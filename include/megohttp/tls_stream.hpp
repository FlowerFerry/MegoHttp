#ifndef MEGOHTTP_TLS_STREAM_HPP_INCLUDED
#define MEGOHTTP_TLS_STREAM_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Composable TLS stream (task book sections 5, 9).
//
// TLS sits on AsyncByteStream, never on a raw socket, so the same code serves:
//     TCP -> TLS                          direct HTTPS
//     TCP -> TLS -> CONNECT -> TLS        HTTPS proxy to an HTTPS target
//     TCP -> TLS -> CONNECT               HTTPS proxy to an HTTP target
// Section 5 forbids binding TLS only to a raw socket, and section 9.3 requires
// the double-layer path, so composability is fixed here.
//
// One pump state machine is shared by both crypto backends; only the handle
// wrapper differs. Both therefore expose identical read/write/close semantics
// and identical ErrorPhase values, which section 5 requires.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/transport.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace megohttp {

// Explicit version selection. Default = backend default with a TLS 1.2 floor;
// SSLv3/TLS1.0/1.1 are never enabled (section 9.1).
enum class TlsVersion : int {
    Default = 0,
    Tls1_2  = 0x0303,
    Tls1_3  = 0x0304,
};

// TLS settings for ONE layer. Proxy TLS and target TLS each get their own
// TlsConfig: section 6 and 9.3 forbid one object that silently drives both
// identities (proxy certificate must never validate as the target's).
struct TlsConfig {
    // Identity to verify and to offer as SNI. This must stay the TARGET's name
    // even when the socket was opened to a proxy or a bootstrap IP.
    string hostname;

    string ca_file;   // PEM bundle for this layer only
    string ca_path;   // directory of hashed PEM certs for this layer only

    string cert_file; // client certificate (mutual TLS), this layer only
    string key_file;

    bool verify_peer{true};
    bool verify_host{true};

    TlsVersion min_version{TlsVersion::Default};

    // ALPN. Only http/1.1 exists in this library, so that is the only value we
    // may advertise: offering h2 would promise a protocol we cannot speak.
    std::vector<string> alpn_protocols;
};

// ---------------------------------------------------------------------------
// TlsStream
//
// Reads: the delivered view points into storage owned by the stream and is
// valid only for the duration of the callback, matching TcpStream.
// Writes: the buffer must stay valid until the write callback fires; both
// crypto backends may need to retry a partial write.
// ---------------------------------------------------------------------------
class TlsStream final : public AsyncByteStream,
                        public std::enable_shared_from_this<TlsStream> {
public:
    // `underlying` must ALREADY be connected. TlsStream never calls start() on
    // it: re-starting a connected stream would re-issue a connect.
    TlsStream(std::shared_ptr<AsyncByteStream> underlying, TlsConfig config);
    ~TlsStream() override;

    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;

    // One handshake attempt. on_ready fires exactly once: success, or the first
    // handshake/certificate error tagged with this layer's ErrorPhase.
    void start(ReadyCallback on_ready) override;

    void async_read_some(ReadCallback cb) override;
    void async_write(const uint8_t* data, size_t size, WriteCallback cb) override;
    void async_close(CloseCallback cb) override;
    bool is_open() const noexcept override;
    string_view tls_protocol() const noexcept override;

    // Facts about THIS connection only. A caller must not carry them across a
    // reconnect and treat them as still valid (section 12.2).
    bool handshake_complete() const noexcept;
    string negotiated_alpn() const;

    // Which layer this stream is. Picks the ErrorPhase reported on failure, so
    // a proxy TLS error and a target TLS error stay distinguishable (section
    // 6.4 requires exactly that split).
    void set_error_phase(ErrorPhase handshake_phase,
                         ErrorPhase protocol_phase) noexcept;

    // Certificate failure detail, mapped to the specific ErrorCode section 6.4
    // asks for (expired / hostname mismatch / not trusted) instead of one
    // generic handshake error.
    ErrorCode certificate_error() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Build a configured TlsStream without starting the handshake. Never returns
// null; failure to initialise the backend surfaces in start().
std::shared_ptr<TlsStream> make_tls_stream(
    std::shared_ptr<AsyncByteStream> underlying,
    const TlsConfig& config);

// ===========================================================================
// Trust source discovery (task book §9.2)
//
// Order of precedence, and what each source MEANS:
//   1. SSL_CERT_FILE / SSL_CERT_DIR environment variables -- same names OpenSSL
//      uses. An explicit path here REPLACES the platform default; it is not an
//      addition. That is stated so a caller cannot accidentally widen trust.
//   2. An explicit TlsConfig::ca_file / ca_path -- also a replacement.
//   3. Platform default bundle (Linux distro bundle, macOS /etc/ssl/cert.pem,
//      Windows system ROOT store exported to PEM).
//
// "Import the OS root store into the backend" is not identical to native
// platform trust evaluation: revocation checking and platform policy are not
// applied. Section 9.2 requires that difference to be stated, not hidden.
// ===========================================================================
namespace tls_trust {

// Empty result = no bundle found at that source.
string system_ca_bundle_path();
string system_ca_directory();

string env_ca_file();   // SSL_CERT_FILE
string env_ca_path();   // SSL_CERT_DIR

// env > platform default. Either may be empty on a platform with no bundle.
string default_ca_file();
string default_ca_path();

} // namespace tls_trust

} // namespace megohttp

// --- implementation -------------------------------------------------------
// tls_trust declarations are above so the backends below can use them.
#include <megohttp/tls_stream_impl.hpp>

#if defined(_WIN32)
#   include <windows.h>
#   include <wincrypt.h>
#   pragma comment(lib, "crypt32")
#elif defined(__APPLE__)
#   include <TargetConditionals.h>
#   if defined(TARGET_OS_OSX) && TARGET_OS_OSX
#       include <CoreFoundation/CoreFoundation.h>
#       include <Security/Security.h>
#   endif
#   include <cstdio>
#   include <cstdlib>
#else
#   include <cstdio>
#   include <cstdlib>
#endif

namespace megohttp {
namespace tls_trust {

#if defined(_WIN32)

// Windows has no built-in CA bundle file, so export the system ROOT store to a
// PEM file the TLS backend can consume. This is an import, not native trust
// evaluation: revocation checks and platform policy are NOT applied (section
// 9.2 requires that difference to be stated rather than hidden).
static std::string win_export_root_store() {
    HCERTSTORE store = CertOpenSystemStoreA(0, "ROOT");
    if (!store) return {};

    // Pass 1: total PEM size. CryptBinaryToString with a null buffer reports the
    // required size including the terminating NUL, hence the -1 per cert.
    DWORD total = 0;
    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
        DWORD sz = 0;
        if (CryptBinaryToStringA(ctx->pbCertEncoded, ctx->cbCertEncoded,
                                 CRYPT_STRING_BASE64HEADER, nullptr, &sz)) {
            total += sz - 1;
        }
    }
    if (total == 0) { CertCloseStore(store, 0); return {}; }

    std::vector<char> pem(static_cast<size_t>(total) + 1, 0);

    // Pass 2: fill it.
    DWORD off = 0;
    ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
        DWORD sz = total - off;
        if (CryptBinaryToStringA(ctx->pbCertEncoded, ctx->cbCertEncoded,
                                 CRYPT_STRING_BASE64HEADER,
                                 pem.data() + off, &sz)) {
            off += sz - 1;
        }
    }
    CertCloseStore(store, 0);
    pem[off] = '\0';

    char tmp[MAX_PATH] = {0};
    if (GetTempPathA(MAX_PATH, tmp) == 0) return {};
    std::string path = std::string(tmp) + "megohttp_trust_roots.pem";
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return {};
    fwrite(pem.data(), 1, off, f);
    fclose(f);
    return path;
}

static const std::string& win_bundle() {
    // Exported once: walking the root store on every handshake would be slow,
    // and the store rarely changes inside one process.
    static const std::string cached = win_export_root_store();
    return cached;
}

string system_ca_bundle_path() {
    const std::string& p = win_bundle();
    return p.empty() ? string{} : string(p.data(), p.size());
}

string system_ca_directory() { return {}; }   // Windows has no hashed CA dir

#elif defined(__APPLE__)

// macOS does not guarantee a CA bundle file (and /etc/ssl/cert.pem is not the
// Keychain trust store). Export the anchor certificates from the system trust
// store to PEM so the OpenSSL/mbedTLS backends can consume them. As with the
// Windows ROOT export, this is an import, not native platform trust
// evaluation: revocation checks and platform policy are not applied.
#if defined(TARGET_OS_OSX) && TARGET_OS_OSX

static std::string apple_base64_encode(const uint8_t* data, size_t size) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((size + 2) / 3) * 4 + size / 48 + 2);
    size_t column = 0;
    for (size_t i = 0; i < size; i += 3) {
        const uint32_t a = data[i];
        const uint32_t b = (i + 1 < size) ? data[i + 1] : 0;
        const uint32_t c = (i + 2 < size) ? data[i + 2] : 0;
        const uint32_t n = (a << 16) | (b << 8) | c;
        const size_t count = (i + 2 < size) ? 4 : ((i + 1 < size) ? 3 : 2);
        char encoded[4] = {
            table[(n >> 18) & 0x3f],
            table[(n >> 12) & 0x3f],
            count > 2 ? table[(n >> 6) & 0x3f] : '=',
            count > 3 ? table[n & 0x3f] : '=',
        };
        out.append(encoded, count);
        column += count;
        if (column >= 64) {
            out.push_back('\n');
            column = 0;
        }
    }
    if (column != 0) out.push_back('\n');
    return out;
}

static std::string apple_export_anchor_certificates() {
    CFArrayRef anchors = nullptr;
    if (SecTrustCopyAnchorCertificates(&anchors) != errSecSuccess || !anchors) {
        return {};
    }

    std::string pem;
    const CFIndex count = CFArrayGetCount(anchors);
    for (CFIndex i = 0; i < count; ++i) {
        SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(
            const_cast<void*>(CFArrayGetValueAtIndex(anchors, i)));
        if (!cert) continue;
        CFDataRef data = SecCertificateCopyData(cert);
        if (!data) continue;
        const CFIndex length = CFDataGetLength(data);
        if (length > 0) {
            pem.append("-----BEGIN CERTIFICATE-----\n");
            pem.append(apple_base64_encode(
                reinterpret_cast<const uint8_t*>(CFDataGetBytePtr(data)),
                static_cast<size_t>(length)));
            pem.append("-----END CERTIFICATE-----\n");
        }
        CFRelease(data);
    }
    CFRelease(anchors);

    if (pem.empty()) return {};

    const char* tmp = std::getenv("TMPDIR");
    std::string path = (tmp && *tmp) ? tmp : "/tmp";
    if (path.back() != '/') path.push_back('/');
    path.append("megohttp_trust_roots.pem");

    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return {};
    std::fwrite(pem.data(), 1, pem.size(), f);
    std::fclose(f);
    return path;
}

static const std::string& apple_bundle() {
    // Export once: walking the system trust store on every handshake is slow
    // and the trust store rarely changes inside one process.
    static const std::string cached = apple_export_anchor_certificates();
    return cached;
}

string system_ca_bundle_path() {
    const std::string& p = apple_bundle();
    return p.empty() ? string{} : string(p.data(), p.size());
}

string system_ca_directory() { return {}; }   // No hashed PEM directory on macOS

#else

// iOS does not expose the system trust store as a PEM bundle. Callers must
// provide an explicit CA bundle for the OpenSSL/mbedTLS backend, or validate
// with a platform API outside this header-only library.
string system_ca_bundle_path() { return {}; }
string system_ca_directory() { return {}; }

#endif

#elif defined(__linux__)

string system_ca_bundle_path() {
    static const char* candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",                      // Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",                        // Fedora/RHEL
        "/etc/ssl/ca-bundle.pem",                                  // openSUSE
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",       // RHEL 8+
    };
    for (const char* p : candidates) {
        FILE* f = fopen(p, "rb");
        if (f) { fclose(f); return string(p); }
    }
    return {};
}

string system_ca_directory() { return string("/etc/ssl/certs"); }

#else

string system_ca_bundle_path() { return {}; }
string system_ca_directory() { return {}; }

#endif

string env_ca_file() {
    const char* v = std::getenv("SSL_CERT_FILE");
    return (v && *v) ? string(v) : string{};
}

string env_ca_path() {
    const char* v = std::getenv("SSL_CERT_DIR");
    return (v && *v) ? string(v) : string{};
}

string default_ca_file() {
    // An explicit environment path REPLACES the platform default rather than
    // extending it, matching OpenSSL's documented behaviour. State it plainly so
    // nobody assumes the two are combined.
    string v = env_ca_file();
    if (!v.empty()) return v;
    return system_ca_bundle_path();
}

string default_ca_path() {
    string v = env_ca_path();
    if (!v.empty()) return v;
    return system_ca_directory();
}

} // namespace tls_trust
} // namespace megohttp


#endif // MEGOHTTP_TLS_STREAM_HPP_INCLUDED
