#ifndef MEGOHTTP_TLS_STREAM_IMPL_HPP_INCLUDED
#define MEGOHTTP_TLS_STREAM_IMPL_HPP_INCLUDED

// ---------------------------------------------------------------------------
// TLS stream implementation: one pump, two crypto backends.
//
// Why a pump instead of blocking calls
// ------------------------------------
// Neither OpenSSL nor mbedTLS can drive a socket we do not own. OpenSSL solves
// this with memory BIOs: you write network bytes into rbio_ and read network
// bytes out of wbio_. mbedTLS solves it with send/recv callbacks that must
// return WANT_READ / WANT_WRITE when no data is available. Both are the same
// idea, so the state machine below is shared and only the handle wrapper
// differs. That is what keeps the two backends behaviourally identical, which
// task book section 5 requires.
//
// Buffer ownership
// ----------------
//   enc_in_   encrypted bytes read from the underlying stream, not yet fed to
//             the crypto engine.
//   enc_out_  encrypted bytes produced by the engine, not yet handed to the
//             underlying stream.
//   sending_  the exact buffer currently handed to underlying async_write. The
//             AsyncByteStream contract requires the caller to keep that memory
//             alive until the write callback fires, so it is a separate vector:
//             appending new engine output to enc_out_ must never reallocate or
//             mutate what is in flight.
//   plain_    decrypted application bytes waiting for async_read_some.
//
// One outstanding read and one outstanding write on the underlying stream,
// matching TcpStream's contract.
// ---------------------------------------------------------------------------

#include <megohttp/tls_stream.hpp>
#include <megohttp/config.hpp>
#include <megohttp/format.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstring>
#include <cstdio>
#include <vector>

#if MGHTTP_TLS_OPENSSL
#   include <openssl/bio.h>
#   include <openssl/err.h>
#   include <openssl/ssl.h>
#   include <openssl/x509.h>
#   include <openssl/x509_vfy.h>
#elif MGHTTP_TLS_MBEDTLS
#   include <mbedtls/ctr_drbg.h>
#   include <mbedtls/entropy.h>
#   include <mbedtls/error.h>
#   include <mbedtls/error.h>
#   include <mbedtls/pk.h>
#   include <mbedtls/ssl.h>
#   include <mbedtls/x509_crt.h>
#endif

namespace megohttp {


namespace tls_detail {

    // Cheap literal test, used only to decide whether to send SNI: task book
    // 9.1 forbids putting an IP literal into a DNS-type server_name.
    inline bool looks_like_ip_literal(string_view host) noexcept {
        if (host.empty()) return false;
        // memepp::string_view::size_type is signed, so compare against it.
        const string_view::size_type n = host.size();
        // IPv6 must contain ':'
        for (string_view::size_type i = 0; i < n; ++i)
            if (host[i] == ':') return true;
        // IPv4: four dot-separated decimal groups, each <= 255
        int groups = 0;
        string_view::size_type i = 0;
        while (i <= n) {
            const string_view::size_type start = i;
            while (i < n && host[i] >= '0' && host[i] <= '9') ++i;
            if (i == start) return false;
            if (i - start > 3) return false;
            unsigned v = 0;
            auto res = std::from_chars(host.data() + start, host.data() + i, v);
            if (res.ec != std::errc{} || v > 255) return false;
            ++groups;
            if (i == n) break;
            if (host[i] != '.') return false;
            ++i;
        }
        return groups == 4;
    }

} // namespace tls_detail

// ===========================================================================
// Impl
// ===========================================================================
struct TlsStream::Impl {
    enum class State { Handshake, Open, Closing, Closed, Failed };

    std::shared_ptr<AsyncByteStream> underlying_;
    TlsConfig config_;

    // Kept alive by the pump's pending callbacks. Set by start(), cleared when
    // the final callback fires. This is the same pattern TcpStream uses with
    // its Node::self.
    std::shared_ptr<TlsStream> self_;

    State state_{State::Handshake};
    bool handshake_complete_{false};

    // True once start() has initialised the crypto backend. Before that the
    // backend handle is null, so driving it (SSL_do_handshake / SSL_read /
    // mbedtls_* ) would dereference nullptr. Reads and writes must be refused
    // until this is true.
    bool started_{false};

    ErrorPhase handshake_phase_{ErrorPhase::TlsHandshake};
    ErrorPhase protocol_phase_{ErrorPhase::Receive};

    // Callbacks. Each fires at most once.
    ReadyCallback  ready_cb_;
    ReadCallback   read_cb_;
    WriteCallback  write_cb_;
    CloseCallback  close_cb_;

    // Staging buffers (see the ownership note at the top of this file).
    std::vector<uint8_t> enc_in_;
    std::vector<uint8_t> enc_out_;
    std::vector<uint8_t> sending_;
    std::vector<uint8_t> plain_;

    // Plaintext the app still has to be given (async_write input).
    std::vector<uint8_t> plain_in_;
    size_t plain_in_pos_{0};

    bool read_pending_{false};
    bool write_pending_{false};
    bool pumping_{false};
    bool pump_again_{false};
    bool close_requested_{false};
    bool close_notified_{false};

    static constexpr size_t kStage = 17 * 1024;  // > one max TLS record

    Impl(std::shared_ptr<AsyncByteStream> u, TlsConfig c)
        : underlying_(std::move(u)), config_(std::move(c)) {
#if MGHTTP_TLS_MBEDTLS
        // Every mbedTLS context must be initialised before use. Skipping this
        // leaves the structs holding garbage and the first call into them (here
        // mbedtls_ctr_drbg_seed) fails or crashes.
        mbedtls_ssl_init(&ssl_);
        mbedtls_ssl_config_init(&conf_);
        mbedtls_x509_crt_init(&cacert_);
        mbedtls_x509_crt_init(&clicert_);
        mbedtls_pk_init(&pkey_);
        mbedtls_ctr_drbg_init(&ctr_drbg_);
        mbedtls_entropy_init(&entropy_);
#endif
    }

    ~Impl();

    bool init_backend();
    void pump();
    void on_underlying_read(Result<string_view> r);
    void on_underlying_write(Result<size_t> r);
    void finish_ready(VoidResult r);
    void finish_write(Result<size_t> r);
    void finish_read(Result<string_view> r);
    void notify_closed();
    void fail(ErrorCode code, ErrorPhase phase, const char* what);

    // Same mapping as TlsStream::certificate_error(), but callable from inside
    // the pump where we hold Impl* rather than TlsStream*.
    ErrorCode impl_certificate_error() const noexcept;

    // True when the handshake failed because the peer would not agree on a
    // protocol version (e.g. we require TLS 1.3, the server caps at 1.2).
    // Reported as TlsProtocolVersionUnsupported so a caller can tell "the
    // server is too old" apart from a certificate or transport failure.
    bool impl_version_failure() const noexcept;

#if MGHTTP_TLS_OPENSSL
    SSL_CTX* ctx_{nullptr};
    BIO*     rbio_{nullptr};
    BIO*     wbio_{nullptr};
    SSL*     ssl_{nullptr};

    bool init_openssl();
    void drain_wbio();
#elif MGHTTP_TLS_MBEDTLS
    mbedtls_ssl_context      ssl_;
    mbedtls_ssl_config       conf_;
    mbedtls_x509_crt         cacert_;
    mbedtls_x509_crt         clicert_;
    mbedtls_pk_context       pkey_;
    mbedtls_ctr_drbg_context ctr_drbg_;
    mbedtls_entropy_context  entropy_;
    bool                     owns_conf_{false};
    // Last handshake return code. Needed because a version refusal produces no
    // certificate verdict, so the verify result alone cannot classify it.
    int                      last_mbedtls_error_{0};
    // mbedtls_ssl_conf_alpn_protocols stores the POINTER, not a copy, so the
    // null-terminated array must outlive the config. A local vector here made
    // the handshake read freed memory.
    std::vector<const char*> alpn_list_;

    bool init_mbedtls();

    static int send_cb(void* ctx, const unsigned char* buf, size_t len);
    static int recv_cb(void* ctx, unsigned char* buf, size_t len);
    int do_send_cb(const unsigned char* buf, size_t len);
    int do_recv_cb(unsigned char* buf, size_t len);
#endif
};

// ===========================================================================
// OpenSSL backend
// ===========================================================================
#if MGHTTP_TLS_OPENSSL

inline bool TlsStream::Impl::init_openssl() {
    const SSL_METHOD* method = TLS_client_method();
    if (!method) return false;

    ctx_ = SSL_CTX_new(method);
    if (!ctx_) return false;

    // Floor at TLS 1.2 (task book 9.1). SSLv3/TLS1.0/1.1 are never offered.
    SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                              SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    long minv = TLS1_2_VERSION;
    if (config_.min_version == TlsVersion::Tls1_3) minv = TLS1_3_VERSION;
    SSL_CTX_set_min_proto_version(ctx_, static_cast<int>(minv));

    // Verification is on by default. There is no automatic downgrade path: a
    // failure ends the handshake (task book 9.1).
    SSL_CTX_set_verify(ctx_, config_.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       nullptr);

    // Trust material for THIS layer only. An explicitly named but unreadable CA
    // source must not be silently ignored (task book 9.2).
    if (!config_.ca_file.empty() || !config_.ca_path.empty()) {
        if (SSL_CTX_load_verify_locations(
                ctx_,
                config_.ca_file.empty() ? nullptr : config_.ca_file.c_str(),
                config_.ca_path.empty() ? nullptr : config_.ca_path.c_str()) != 1) {
            return false;
        }
    } else if (config_.verify_peer) {
        // No explicit source. Two different kinds of "discovered" exist and they
        // must not be treated the same:
        //
        //   environment (SSL_CERT_FILE / SSL_CERT_DIR)
        //       The caller named this source. If it cannot be read, failing is
        //       the only honest outcome -- silently verifying against something
        //       else is how a typo'd path becomes "trust everything".
        //
        //   platform default (Windows ROOT export, Linux bundle)
        //       We picked it. A Windows ROOT export legitimately contains a few
        //       certificates OpenSSL cannot parse, and one bad entry must not
        //       make the whole system store unusable. Fall back, and only fail
        //       if nothing at all could be loaded.
        const string env_file = tls_trust::env_ca_file();
        if (!env_file.empty()) {
            if (SSL_CTX_load_verify_locations(ctx_, env_file.c_str(), nullptr) != 1) {
                return false;
            }
        } else {
            const string env_dir = tls_trust::env_ca_path();
            if (!env_dir.empty()) {
                if (SSL_CTX_load_verify_locations(ctx_, nullptr, env_dir.c_str()) != 1) {
                    return false;
                }
            } else {
                // Platform default. Try the bundle first, then the hashed
                // directory, then OpenSSL's built-in paths, and accept the first
                // one that loads.
                bool loaded = false;
                const string plat_file = tls_trust::system_ca_bundle_path();
                if (!plat_file.empty()) {
                    loaded = SSL_CTX_load_verify_locations(
                                 ctx_, plat_file.c_str(), nullptr) == 1;
                }
                if (!loaded) {
                    const string plat_dir = tls_trust::system_ca_directory();
                    if (!plat_dir.empty()) {
                        loaded = SSL_CTX_load_verify_locations(
                                     ctx_, nullptr, plat_dir.c_str()) == 1;
                    }
                }
                if (!loaded) {
                    // Treat a total failure as "no trust anchors", which is a
                    // setup error rather than something to discover at handshake
                    // time.
                    if (SSL_CTX_set_default_verify_paths(ctx_) != 1) {
                        return false;
                    }
                }
            }
        }
    }

    // Client certificate for mutual TLS.
    if (!config_.cert_file.empty()) {
        if (SSL_CTX_use_certificate_chain_file(ctx_, config_.cert_file.c_str()) != 1)
            return false;
        if (config_.key_file.empty() ||
            SSL_CTX_use_PrivateKey_file(ctx_, config_.key_file.c_str(),
                                        SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx_) != 1) {
            return false;
        }
    }

    ssl_ = SSL_new(ctx_);
    if (!ssl_) return false;

    const bool is_ip = tls_detail::looks_like_ip_literal(to_view(config_.hostname));

    // SNI: DNS names only. An IP literal must not go into a host_name entry.
    if (!is_ip && !config_.hostname.empty()) {
        if (SSL_set_tlsext_host_name(ssl_, config_.hostname.c_str()) != 1)
            return false;
    }

    // Identity check. SSL_set1_host enables SAN/CN matching and reports
    // X509_V_ERR_HOSTNAME_MISMATCH; set1_ip_asc does the IP-SAN equivalent.
    if (config_.verify_host && !config_.hostname.empty()) {
        X509_VERIFY_PARAM* p = SSL_get0_param(ssl_);
        if (is_ip) {
            if (X509_VERIFY_PARAM_set1_ip_asc(p, config_.hostname.c_str()) != 1)
                return false;
        } else {
            if (X509_VERIFY_PARAM_set1_host(p, config_.hostname.c_str(), 0) != 1)
                return false;
        }
    }

    // ALPN: only protocols this library can actually speak are advertised.
    // SSL_set_alpn_protos sets it on THIS connection. Doing it on the SSL_CTX
    // after SSL_new does nothing, because the client list is copied when the
    // SSL object is created.
    if (!config_.alpn_protocols.empty()) {
        std::vector<uint8_t> wire;
        for (const auto& proto : config_.alpn_protocols) {
            if (proto.empty() || proto.size() > 255) return false;
            wire.push_back(static_cast<uint8_t>(proto.size()));
            wire.insert(wire.end(), proto.begin(), proto.end());
        }
        if (SSL_set_alpn_protos(ssl_, wire.data(),
                                static_cast<unsigned>(wire.size())) != 0) {
            return false;
        }
    }

    // Memory BIOs: the pump owns all network movement.
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    if (!rbio_ || !wbio_) return false;
    BIO_set_mem_eof_return(rbio_, -1);
    BIO_set_mem_eof_return(wbio_, -1);
    SSL_set_bio(ssl_, rbio_, wbio_);   // takes ownership on success
    SSL_set_connect_state(ssl_);

    return true;
}

inline void TlsStream::Impl::drain_wbio() {
    uint8_t stage[kStage];
    for (;;) {
        int n = BIO_read(wbio_, stage, static_cast<int>(sizeof stage));
        if (n <= 0) break;
        enc_out_.insert(enc_out_.end(), stage, stage + n);
    }
}

#endif // MGHTTP_TLS_OPENSSL

// ===========================================================================
// mbedTLS backend
// ===========================================================================
#if MGHTTP_TLS_MBEDTLS

inline int TlsStream::Impl::send_cb(void* ctx, const unsigned char* buf, size_t len) {
    return static_cast<Impl*>(ctx)->do_send_cb(buf, len);
}

inline int TlsStream::Impl::recv_cb(void* ctx, unsigned char* buf, size_t len) {
    return static_cast<Impl*>(ctx)->do_recv_cb(buf, len);
}

inline int TlsStream::Impl::do_send_cb(const unsigned char* buf, size_t len) {
    if (state_ == State::Failed) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (len == 0) return 0;

    // Copy into our own buffer and report the bytes as ACCEPTED. Returning
    // WANT_WRITE after having copied them would make the engine retry the same
    // record, and it would go out twice. We own the ciphertext from here: if the
    // underlying write later fails, the TLS session is dead and we fail the
    // stream, which is correct because TLS has no retransmission.
    enc_out_.insert(enc_out_.end(), buf, buf + len);
    return static_cast<int>(len);
}

inline int TlsStream::Impl::do_recv_cb(unsigned char* buf, size_t len) {
    if (enc_in_.empty()) return MBEDTLS_ERR_SSL_WANT_READ;
    const size_t n = (std::min)(len, enc_in_.size());
    std::memcpy(buf, enc_in_.data(), n);
    enc_in_.erase(enc_in_.begin(), enc_in_.begin() + static_cast<ptrdiff_t>(n));
    return static_cast<int>(n);
}

inline bool TlsStream::Impl::init_mbedtls() {
    const char* pers = "megohttp-tls";
    if (mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                              reinterpret_cast<const unsigned char*>(pers),
                              std::strlen(pers)) != 0) {
        return false;
    }

    if (mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return false;
    }
    owns_conf_ = true;

    mbedtls_ssl_conf_min_tls_version(&conf_,
        config_.min_version == TlsVersion::Tls1_3 ? MBEDTLS_SSL_VERSION_TLS1_3
                                                  : MBEDTLS_SSL_VERSION_TLS1_2);

    mbedtls_ssl_conf_authmode(&conf_, config_.verify_peer
                                        ? MBEDTLS_SSL_VERIFY_REQUIRED
                                        : MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);

    bool any_ca = false;
    if (!config_.ca_file.empty()) {
        // Docs (x509_crt.h): 0 = all parsed, POSITIVE = number of certificates
        // that failed to parse while others succeeded, negative = hard error.
        // The Windows ROOT store export legitimately contains certs mbedTLS
        // cannot parse (legacy algorithms), so rejecting every positive return
        // threw away the entire trust store. Accept partial success as long as
        // something got parsed.
        const int rc = mbedtls_x509_crt_parse_file(&cacert_, config_.ca_file.c_str());
        if (rc < 0) return false;
        any_ca = true;
    }
    if (!config_.ca_path.empty()) {
        const int rc = mbedtls_x509_crt_parse_path(&cacert_, config_.ca_path.c_str());
        if (rc < 0) return false;
        any_ca = true;
    }
    if (!any_ca && config_.verify_peer) {
        // mbedTLS ships no trust store of its own, so without an explicit source
        // it would have nothing to verify against. Two different kinds of
        // "discovered" exist and they must not be treated the same:
        //
        //   environment (SSL_CERT_FILE / SSL_CERT_DIR)
        //       The caller named this source. If it cannot be read, failing is
        //       the only honest outcome.
        //
        //   platform default (Windows ROOT export, Linux bundle)
        //       We picked it. A Windows ROOT export legitimately contains a few
        //       certificates mbedTLS cannot parse, and one bad entry must not
        //       make the whole system store unusable. Fall back, and only fail
        //       if nothing at all could be loaded.
        const string env_file = tls_trust::env_ca_file();
        if (!env_file.empty()) {
            const int rc = mbedtls_x509_crt_parse_file(&cacert_, env_file.c_str());
            if (rc < 0) return false;
            any_ca = true;
        } else {
            const string env_dir = tls_trust::env_ca_path();
            if (!env_dir.empty()) {
                const int rc = mbedtls_x509_crt_parse_path(&cacert_, env_dir.c_str());
                if (rc < 0) return false;
                any_ca = true;
            } else {
                // Platform default. Try the bundle first, then the hashed
                // directory, and accept the first one that loads at least
                // partially.
                const string plat_file = tls_trust::system_ca_bundle_path();
                if (!plat_file.empty()) {
                    const int rc = mbedtls_x509_crt_parse_file(&cacert_, plat_file.c_str());
                    if (rc >= 0) any_ca = true;
                }
                if (!any_ca) {
                    const string plat_dir = tls_trust::system_ca_directory();
                    if (!plat_dir.empty()) {
                        const int rc = mbedtls_x509_crt_parse_path(&cacert_, plat_dir.c_str());
                        if (rc >= 0) any_ca = true;
                    }
                }
            }
        }
    }
    if (any_ca) {
        mbedtls_ssl_conf_ca_chain(&conf_, &cacert_, nullptr);
    } else if (config_.verify_peer) {
        // No trust material from any source: fail loudly rather than hand out
        // an unverified connection (task book 9.2).
        return false;
    }

    if (!config_.cert_file.empty()) {
        if (mbedtls_x509_crt_parse_file(&clicert_, config_.cert_file.c_str()) != 0) {
            return false;
        }
        if (config_.key_file.empty() ||
            mbedtls_pk_parse_keyfile(&pkey_, config_.key_file.c_str(), nullptr,
                                     mbedtls_ctr_drbg_random, &ctr_drbg_) != 0) {
            return false;
        }
        if (mbedtls_ssl_conf_own_cert(&conf_, &clicert_, &pkey_) != 0) return false;
    }

    if (!config_.alpn_protocols.empty()) {
        alpn_list_.reserve(config_.alpn_protocols.size() + 1);
        for (const auto& p : config_.alpn_protocols) {
            if (p.empty()) return false;
            alpn_list_.push_back(p.c_str());
        }
        alpn_list_.push_back(nullptr);
        if (mbedtls_ssl_conf_alpn_protocols(&conf_, alpn_list_.data()) != 0) return false;
    }

    if (mbedtls_ssl_setup(&ssl_, &conf_) != 0) return false;

    // mbedtls_ssl_set_hostname() does BOTH jobs: it fills the server_name TLS
    // extension and it records the identity to check the certificate against.
    // The documented contract (ssl.h) is to ALWAYS call it on a client:
    //   - with the expected name when verification is wanted;
    //   - with NULL when name verification is deliberately not wanted
    //     (MBEDTLS_SSL_VERIFY_REQUIRED otherwise fails with
    //      MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME).
    // Skipping the call entirely is NOT the same as passing NULL.
    const char* identity = (config_.verify_host && !config_.hostname.empty())
                               ? config_.hostname.c_str()
                               : nullptr;
    if (mbedtls_ssl_set_hostname(&ssl_, identity) != 0) {
        return false;
    }

    mbedtls_ssl_set_bio(&ssl_, this, &Impl::send_cb, &Impl::recv_cb, nullptr);
    return true;
}
#endif // MGHTTP_TLS_MBEDTLS

// ===========================================================================
// Shared pump
// ===========================================================================
inline TlsStream::Impl::~Impl() {
#if MGHTTP_TLS_OPENSSL
    if (ssl_) {
        SSL_free(ssl_);
    } else {
        if (rbio_) BIO_free(rbio_);
        if (wbio_) BIO_free(wbio_);
    }
    if (ctx_) SSL_CTX_free(ctx_);
#elif MGHTTP_TLS_MBEDTLS
    // Safe to call on a context that was initialised but never set up.
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&conf_);
    mbedtls_x509_crt_free(&cacert_);
    mbedtls_x509_crt_free(&clicert_);
    mbedtls_pk_free(&pkey_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
#endif
}

inline void TlsStream::Impl::fail(ErrorCode code, ErrorPhase phase, const char* what) {
    if (state_ == State::Failed || state_ == State::Closed) return;
    state_ = State::Failed;
    Error err{code, phase, format("{}", what)};
    if (!handshake_complete_) { finish_ready(VoidResult{err}); return; }

    // A TLS layer allows a read and a write to be outstanding at the same time.
    // Completing only one of them -- which is what this used to do -- leaves the
    // other caller waiting for a callback that never comes.
    if (write_cb_) finish_write(Result<size_t>{err});
    if (read_cb_) finish_read(Result<string_view>{err});
    notify_closed();
}

inline void TlsStream::Impl::finish_ready(VoidResult r) {
    auto cb = std::move(ready_cb_);
    if (cb) cb(std::move(r));
}

inline void TlsStream::Impl::finish_write(Result<size_t> r) {
    auto cb = std::move(write_cb_);
    plain_in_.clear();
    plain_in_pos_ = 0;
    if (cb) cb(std::move(r));
}

inline void TlsStream::Impl::finish_read(Result<string_view> r) {
    auto cb = std::move(read_cb_);
    if (cb) cb(std::move(r));
}

inline ErrorCode TlsStream::Impl::impl_certificate_error() const noexcept {
#if MGHTTP_TLS_OPENSSL
    if (!ssl_) return ErrorCode::Success;
    const long vr = SSL_get_verify_result(ssl_);
    if (vr == X509_V_OK) return ErrorCode::Success;
    switch (vr) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            return ErrorCode::TlsCertificateExpired;
        case X509_V_ERR_HOSTNAME_MISMATCH:
            return ErrorCode::TlsHostnameMismatch;
        default:
            return ErrorCode::TlsCertificateInvalid;
    }
#elif MGHTTP_TLS_MBEDTLS
    const uint32_t f = mbedtls_ssl_get_verify_result(&ssl_);
    // 0xFFFFFFFF is mbedTLS's sentinel for "no certificate verdict exists"
    // (set when the handshake dies before the certificate is examined, e.g. on
    // a protocol-version alert). Treating it as a certificate verdict would
    // report a bogus TlsCertificateInvalid.
    if (f == 0 || f == 0xFFFFFFFFu) return ErrorCode::Success;
    if (f & MBEDTLS_X509_BADCERT_EXPIRED) return ErrorCode::TlsCertificateExpired;
    if (f & MBEDTLS_X509_BADCERT_CN_MISMATCH) return ErrorCode::TlsHostnameMismatch;
    return ErrorCode::TlsCertificateInvalid;
#else
    return ErrorCode::Success;
#endif
}

inline bool TlsStream::Impl::impl_version_failure() const noexcept {
#if MGHTTP_TLS_OPENSSL
    if (!ssl_) return false;
    // SSL_do_handshake returned a non-WANT error: inspect the error queue rather
    // than the verify result, because a version mismatch never produces a
    // certificate verdict. SSL_R_TLSV1_ALERT_PROTOCOL_VERSION is the peer's
    // protocol_version alert; the rest are local version-floor refusals.
    const unsigned long e = ERR_peek_last_error();
    if (e == 0) return false;
    switch (ERR_GET_REASON(e)) {
        case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
        case SSL_R_UNSUPPORTED_PROTOCOL:
        case SSL_R_VERSION_TOO_LOW:
        case SSL_R_VERSION_TOO_HIGH:
        case SSL_R_WRONG_SSL_VERSION:
            return true;
        default:
            return false;
    }
#elif MGHTTP_TLS_MBEDTLS
    // mbedTLS has no public accessor for the peer's alert code, so classify on
    // the pair of facts the two failure modes differ in. Verified by probe
    // (tests/probe_mbedtls_codes.cpp):
    //   version refusal  -> rc = MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
    //                       verify_result = 0xFFFFFFFF (sentinel: no cert verdict
    //                       was ever reached)
    //   certificate refusal -> rc = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
    //                       verify_result = a real bitmask (e.g. 0x8 NOT_TRUSTED)
    // Trusting the sentinel alone keeps a genuine alert from being mislabelled
    // as a certificate error and vice versa.
    if (last_mbedtls_error_ != MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) return false;
    return mbedtls_ssl_get_verify_result(&ssl_) == 0xFFFFFFFFu;
#else
    return false;
#endif
}

inline void TlsStream::Impl::notify_closed() {
    if (close_notified_) return;
    close_notified_ = true;
    auto cb = std::move(close_cb_);
    // Release the self-hold last: the callback may destroy the last external
    // owner, and `this` must stay valid until the callback returns.
    std::shared_ptr<TlsStream> hold = std::move(self_);
    if (cb) cb();
}

inline void TlsStream::Impl::pump() {
    if (pumping_) { pump_again_ = true; return; }
    // Nothing can be driven before the backend exists: state_ is Handshake but
    // ssl_ is null, so SSL_do_handshake / mbedtls_ssl_handshake would crash.
    if (!started_) return;
    pumping_ = true;

    do {
        pump_again_ = false;

        if (state_ == State::Closed || state_ == State::Failed) break;

        if (!write_pending_ && !enc_out_.empty()) {
            sending_.swap(enc_out_);
            enc_out_.clear();
            write_pending_ = true;
            std::weak_ptr<TlsStream> w = self_;
            underlying_->async_write(sending_.data(), sending_.size(),
                [w](Result<size_t> r) {
                    if (auto s = w.lock()) s->impl_->on_underlying_write(std::move(r));
                });
        }

        if (!read_pending_ && state_ != State::Closed) {
            read_pending_ = true;
            std::weak_ptr<TlsStream> w = self_;
            underlying_->async_read_some(
                [w](Result<string_view> r) {
                    if (auto s = w.lock()) s->impl_->on_underlying_read(std::move(r));
                });
        }

        // ---- 2b. hand buffered ciphertext to the engine --------------------
        // OpenSSL reads from its memory BIO, so bytes collected from the
        // underlying stream have to be pushed into rbio_ before the engine is
        // driven. mbedTLS pulls them through recv_cb instead, so this step is
        // OpenSSL-only. Forgetting it looks exactly like a stalled handshake:
        // the peer's reply arrives, sits in enc_in_, and is never seen.
#if MGHTTP_TLS_OPENSSL
        if (!enc_in_.empty() && rbio_) {
            BIO_write(rbio_, enc_in_.data(), static_cast<int>(enc_in_.size()));
            enc_in_.clear();
        }
#endif

        if (state_ == State::Handshake) {
#if MGHTTP_TLS_OPENSSL
            int ret = SSL_do_handshake(ssl_);
            drain_wbio();
            if (ret == 1) {
                state_ = State::Open;
                handshake_complete_ = true;
                finish_ready(VoidResult{});
            } else {
                int e = SSL_get_error(ssl_, ret);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                    const ErrorCode ce = impl_certificate_error();
                    // Order matters: a version refusal leaves the verify result
                    // at X509_V_OK, so it must be checked before falling back to
                    // a generic handshake error.
                    if (ce != ErrorCode::Success)
                        fail(ce, handshake_phase_, "TLS handshake failed");
                    else if (impl_version_failure())
                        fail(ErrorCode::TlsProtocolVersionUnsupported, handshake_phase_,
                             "TLS protocol version not supported by the peer");
                    else
                        fail(ErrorCode::TlsHandshakeFailed, handshake_phase_,
                             "TLS handshake failed");
                }
            }
#elif MGHTTP_TLS_MBEDTLS
            int ret = mbedtls_ssl_handshake(&ssl_);
            if (ret == 0) {
                state_ = State::Open;
                handshake_complete_ = true;
                finish_ready(VoidResult{});
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                       ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                // Record the code before classifying: impl_version_failure()
                // reads it, and the verify result is untouched by a version
                // refusal.
                last_mbedtls_error_ = ret;
                const ErrorCode ce = impl_certificate_error();
                char detail[128] = {0};
                mbedtls_strerror(ret, detail, sizeof detail);
                if (ce != ErrorCode::Success)
                    fail(ce, handshake_phase_, detail);
                else if (impl_version_failure())
                    fail(ErrorCode::TlsProtocolVersionUnsupported, handshake_phase_,
                         detail);
                else
                    fail(ErrorCode::TlsHandshakeFailed, handshake_phase_, detail);
                break;
            }
#endif
        }

        if (state_ == State::Open && !plain_in_.empty() && plain_in_pos_ < plain_in_.size()) {
#if MGHTTP_TLS_OPENSSL
            int n = SSL_write(ssl_, plain_in_.data() + plain_in_pos_,
                              static_cast<int>(plain_in_.size() - plain_in_pos_));
            drain_wbio();
            if (n > 0) {
                plain_in_pos_ += static_cast<size_t>(n);
                if (plain_in_pos_ >= plain_in_.size()) finish_write(Result<size_t>{plain_in_.size()});
            } else {
                int e = SSL_get_error(ssl_, n);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                    fail(ErrorCode::ConnectionReset, protocol_phase_, "TLS write failed");
            }
#elif MGHTTP_TLS_MBEDTLS
            int n = mbedtls_ssl_write(&ssl_, plain_in_.data() + plain_in_pos_,
                                      plain_in_.size() - plain_in_pos_);
            if (n > 0) {
                plain_in_pos_ += static_cast<size_t>(n);
                if (plain_in_pos_ >= plain_in_.size()) finish_write(Result<size_t>{plain_in_.size()});
            } else if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE) {
                fail(ErrorCode::ConnectionReset, protocol_phase_, "TLS write failed");
                break;
            }
#endif
        }

        if (state_ == State::Open && read_cb_ && plain_.empty()) {
            uint8_t stage[kStage];
#if MGHTTP_TLS_OPENSSL
            int n = SSL_read(ssl_, stage, static_cast<int>(sizeof stage));
            if (n > 0) {
                plain_.assign(stage, stage + n);
            } else {
                int e = SSL_get_error(ssl_, n);
                if (e == SSL_ERROR_ZERO_RETURN) {
                    finish_read(Result<string_view>{string_view{}});
                } else if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                    fail(ErrorCode::ConnectionReset, protocol_phase_, "TLS read failed");
                    break;
                }
            }
#elif MGHTTP_TLS_MBEDTLS
            int n = mbedtls_ssl_read(&ssl_, stage, sizeof stage);
            if (n > 0) {
                plain_.assign(stage, stage + n);
            } else if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                finish_read(Result<string_view>{string_view{}});
            } else if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE) {
                fail(ErrorCode::ConnectionReset, protocol_phase_, "TLS read failed");
                break;
            }
#endif
        }

        if (read_cb_ && !plain_.empty()) {
            finish_read(Result<string_view>{
                string_view{reinterpret_cast<const char*>(plain_.data()),
                            static_cast<string_view::size_type>(plain_.size())}});
            plain_.clear();
        }

        if (close_requested_ && state_ != State::Failed) {
            if (!write_pending_ && enc_out_.empty()) {
                state_ = State::Closed;
                std::weak_ptr<TlsStream> w = self_;
                underlying_->async_close([w] {
                    if (auto s = w.lock()) s->impl_->notify_closed();
                });
                break;
            }
        }

        // The engine may have produced ciphertext this pass (step 1 had already
        // run by then), e.g. the ClientHello on the very first call. Without
        // another pass nothing would ever flush it and the peer would wait for
        // us forever. Issuing the write sets write_pending_, so this cannot spin.
        if (state_ != State::Closed && state_ != State::Failed &&
            !write_pending_ && !enc_out_.empty()) {
            pump_again_ = true;
        }

    } while (pump_again_);

    pumping_ = false;
}

inline void TlsStream::Impl::on_underlying_read(Result<string_view> r) {
    read_pending_ = false;
    if (!r) {
        fail(ErrorCode::ConnectionReset, protocol_phase_, "underlying read failed");
        return;
    }
    const string_view v = r.value();
    if (v.empty()) {
        if (state_ == State::Handshake) {
            fail(ErrorCode::ConnectionClosed, handshake_phase_,
                 "connection closed during handshake");
            return;
        }
        state_ = State::Closed;
        if (read_cb_) finish_read(Result<string_view>{string_view{}});
        // A pending write must also reach a terminal state: a clean EOF means
        // the peer is gone, so those bytes were never acknowledged. Leaving the
        // callback unserviced would hang the writer forever -- fail() already
        // covers the error paths, this is the clean-EOF one.
        if (write_cb_) {
            finish_write(Result<size_t>{Error{ErrorCode::ConnectionClosed,
                                              protocol_phase_,
                                              string("connection closed with a write pending")}});
        }
        notify_closed();
        return;
    }
    enc_in_.insert(enc_in_.end(),
                   reinterpret_cast<const uint8_t*>(v.data()),
                   reinterpret_cast<const uint8_t*>(v.data()) + v.size());
    pump();
}

inline void TlsStream::Impl::on_underlying_write(Result<size_t> r) {
    write_pending_ = false;
    if (!r) {
        fail(ErrorCode::ConnectionReset,
             handshake_complete_ ? protocol_phase_ : handshake_phase_,
             "underlying write failed");
        return;
    }
    const size_t n = r.value();
    if (n < sending_.size()) {
        sending_.erase(sending_.begin(), sending_.begin() + static_cast<ptrdiff_t>(n));
        write_pending_ = true;
        std::weak_ptr<TlsStream> w = self_;
        underlying_->async_write(sending_.data(), sending_.size(),
            [w](Result<size_t> r2) {
                if (auto s = w.lock()) s->impl_->on_underlying_write(std::move(r2));
            });
        return;
    }
    sending_.clear();
    pump();
}

// ===========================================================================
// TlsStream public methods
// ===========================================================================
inline TlsStream::TlsStream(std::shared_ptr<AsyncByteStream> underlying,
                            TlsConfig config)
    : impl_(std::make_unique<Impl>(std::move(underlying), std::move(config))) {}

inline TlsStream::~TlsStream() = default;

inline void TlsStream::start(ReadyCallback on_ready) {
    impl_->ready_cb_ = std::move(on_ready);

#if MGHTTP_TLS_NONE
    // Report the missing backend before anything else: with TLS compiled out
    // there is no engine to drive, so "the underlying stream is not connected"
    // would be a misleading diagnosis of a build-configuration problem.
    impl_->state_ = Impl::State::Failed;
    impl_->finish_ready(VoidResult{Error{ErrorCode::TlsNotEnabled, ErrorPhase::None,
                                         string("TLS support was not compiled in")}});
    return;
#else
    if (!impl_->underlying_ || !impl_->underlying_->is_open()) {
        impl_->state_ = Impl::State::Failed;
        impl_->finish_ready(VoidResult{Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                                             string("underlying stream is not connected")}});
        return;
    }

    bool ok = false;
#if MGHTTP_TLS_OPENSSL
    ok = impl_->init_openssl();
#elif MGHTTP_TLS_MBEDTLS
    ok = impl_->init_mbedtls();
#endif

    if (!ok) {
        impl_->state_ = Impl::State::Failed;
        impl_->finish_ready(VoidResult{Error{ErrorCode::TlsHandshakeFailed,
                                             ErrorPhase::TlsHandshake,
                                             string("TLS context initialisation failed")}});
        return;
    }
    // Pending underlying callbacks outlive this call, so the stream must hold
    // itself. Same reason TcpStream's Node keeps a shared_ptr to itself.
    if (!impl_->self_) impl_->self_ = shared_from_this();
    impl_->started_ = true;
    impl_->pump();
#endif // MGHTTP_TLS_NONE
}

inline void TlsStream::async_read_some(ReadCallback cb) {
    if (!impl_->started_) {
        // start() was never called: there is no TLS session to read from, and
        // parking the callback would hang the caller forever.
        cb(Result<string_view>{Error{ErrorCode::InvalidArgument,
                                     impl_->handshake_phase_,
                                     string("TLS stream has not been started")}});
        return;
    }
    if (impl_->state_ == Impl::State::Failed) {
        cb(Result<string_view>{Error{ErrorCode::ConnectionClosed, impl_->protocol_phase_,
                                     string("TLS stream has failed")}});
        return;
    }
    if (impl_->state_ == Impl::State::Closed) {
        cb(Result<string_view>{string_view{}});
        return;
    }
    if (impl_->read_cb_) {
        cb(Result<string_view>{Error{ErrorCode::InvalidArgument, impl_->protocol_phase_,
                                     string("another read is already outstanding")}});
        return;
    }
    impl_->read_cb_ = std::move(cb);
    impl_->pump();
}

inline void TlsStream::async_write(const uint8_t* data, size_t size, WriteCallback cb) {
    if (impl_->state_ != Impl::State::Open) {
        cb(Error{ErrorCode::InvalidArgument, impl_->handshake_complete_
                                                 ? impl_->protocol_phase_
                                                 : impl_->handshake_phase_,
                string("TLS stream is not open")});
        return;
    }
    if (impl_->write_cb_) {
        cb(Error{ErrorCode::InvalidArgument, ErrorPhase::Send,
                string("another write is already outstanding")});
        return;
    }
    impl_->write_cb_ = std::move(cb);
    impl_->plain_in_.assign(data, data + size);
    impl_->plain_in_pos_ = 0;
    impl_->pump();
}

inline void TlsStream::async_close(CloseCallback cb) {
    if (impl_->close_notified_) {
        // Already fully closed. The terminal notification is exactly-once
        // (task book 5.3), so a late caller gets no second callback.
        return;
    }
    if (impl_->close_cb_) {
        // A close is already in progress: the pending callback owns the single
        // terminal notification. A second caller must not add another one.
        return;
    }
    impl_->close_cb_ = std::move(cb);
    impl_->close_requested_ = true;

    // A TlsStream may be constructed over a null underlying stream (the
    // constructor accepts null so a caller can build one and hand it a stream
    // later, and start() reports InvalidArgument in that case). Closing such a
    // stream must complete directly: there is nothing to close underneath, and
    // dereferencing underlying_ would crash.
    const bool no_underlying = !impl_->underlying_;

    if (impl_->state_ == Impl::State::Failed || no_underlying) {
        impl_->state_ = Impl::State::Closed;
        // The callback is delivered even when self_ is empty. A TlsStream that
        // was never start()ed (or whose start failed) has no self-reference, and
        // gating notify_closed() on lock() silently dropped the caller's close
        // completion in exactly that case.
        std::weak_ptr<TlsStream> w = impl_->self_;
        if (no_underlying) {
            impl_->notify_closed();
            return;
        }
        impl_->underlying_->async_close([w] {
            if (auto s = w.lock()) s->impl_->notify_closed();
        });
        if (!w.lock()) impl_->notify_closed();
        return;
    }
    if (impl_->state_ == Impl::State::Handshake) {
        impl_->state_ = Impl::State::Closed;
        std::weak_ptr<TlsStream> w = impl_->self_;
        impl_->underlying_->async_close([w] {
            if (auto s = w.lock()) s->impl_->notify_closed();
        });
        if (!w.lock()) impl_->notify_closed();
        return;
    }

#if MGHTTP_TLS_OPENSSL
    SSL_shutdown(impl_->ssl_);
    impl_->drain_wbio();
#elif MGHTTP_TLS_MBEDTLS
    mbedtls_ssl_close_notify(&impl_->ssl_);
#endif
    impl_->state_ = Impl::State::Closing;
    impl_->pump();
}

inline bool TlsStream::is_open() const noexcept {
    return impl_->state_ == Impl::State::Open;
}

inline string_view TlsStream::tls_protocol() const noexcept {
    if (!impl_->handshake_complete_) return {};
#if MGHTTP_TLS_OPENSSL
    const char* v = SSL_get_version(impl_->ssl_);
    return v ? string_view(v) : string_view{};
#elif MGHTTP_TLS_MBEDTLS
    const char* v = mbedtls_ssl_get_version(&impl_->ssl_);
    return v ? string_view(v) : string_view{};
#else
    return {};
#endif
}

inline bool TlsStream::handshake_complete() const noexcept {
    return impl_->handshake_complete_;
}

inline string TlsStream::negotiated_alpn() const {
    if (!impl_->handshake_complete_) return {};
#if MGHTTP_TLS_OPENSSL
    const unsigned char* p = nullptr;
    unsigned int n = 0;
    SSL_get0_alpn_selected(impl_->ssl_, &p, &n);
    return (p && n) ? string(reinterpret_cast<const char*>(p), n) : string{};
#elif MGHTTP_TLS_MBEDTLS
    const char* p = mbedtls_ssl_get_alpn_protocol(&impl_->ssl_);
    return p ? string(p) : string{};
#else
    return {};
#endif
}

inline void TlsStream::set_error_phase(ErrorPhase handshake_phase,
                                       ErrorPhase protocol_phase) noexcept {
    impl_->handshake_phase_ = handshake_phase;
    impl_->protocol_phase_ = protocol_phase;
}

inline ErrorCode TlsStream::certificate_error() const noexcept {
    return impl_->impl_certificate_error();
}

// ===========================================================================
// Factory
// ===========================================================================
inline std::shared_ptr<TlsStream> make_tls_stream(
    std::shared_ptr<AsyncByteStream> underlying,
    const TlsConfig& config) {
    return std::make_shared<TlsStream>(std::move(underlying), config);
}

} // namespace megohttp

#endif // MEGOHTTP_TLS_STREAM_IMPL_HPP_INCLUDED
