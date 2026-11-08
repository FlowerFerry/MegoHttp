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

} // namespace megohttp

// --- implementation -------------------------------------------------------
#include <megohttp/tls_stream_impl.hpp>

#endif // MEGOHTTP_TLS_STREAM_HPP_INCLUDED
