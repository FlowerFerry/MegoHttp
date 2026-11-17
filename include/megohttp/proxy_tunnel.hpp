#ifndef MEGOHTTP_PROXY_TUNNEL_HPP_INCLUDED
#define MEGOHTTP_PROXY_TUNNEL_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Proxy tunnel establishment, decoupled from the HTTP exchange.
//
// The proxy handshake (CONNECT for an HTTP proxy, the RFC 1928 exchange for
// SOCKS5, optionally wrapped in the proxy's own TLS layer) is the same work
// whether what follows is an HTTP request or a WebSocket session. It used to
// live inside Client::Impl where RequestState was the only thing that could
// call it, which is why WebSocket had no proxy support at all: its stream
// provider dialled the origin directly.
//
// Everything here depends on AsyncByteStream and ProxyOptions only. A caller
// supplies a "phase hook" so the HTTP path can still report which stage failed
// (ProxyTls vs ProxyConnectTunnel vs ProxyAuth) without this file knowing what
// those phases mean.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/proxy.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/tls_stream.hpp>
#include <megohttp/transport.hpp>

#include <cstdint>
#include <functional>
#include <memory>

namespace megohttp {
    namespace proxy_tunnel {

        // Reports the stage that is running, so an Error can carry it. Called
        // with an ErrorPhase; a caller that does not care passes nullptr.
        using PhaseHook = std::function<void(ErrorPhase)>;

        // ---------------------------------------------------------------------
        // The stream a tunnel produces. `stream` is the object the next layer
        // must talk to; `leftover` holds bytes the proxy already sent after its
        // own head (the origin may have started speaking immediately). Callers
        // MUST deliver those bytes ahead of anything read from the stream, or
        // the first response/handshake bytes are lost.
        // ---------------------------------------------------------------------
        struct TunnelResult {
            std::shared_ptr<AsyncByteStream> stream;
            byte_buffer leftover;
        };

        using TunnelCallback = std::function<void(Result<TunnelResult>)>;

        // Establish whatever the proxy type requires so that `stream` afterwards
        // carries bytes for `target_host:target_port`.
        //
        //   HTTP proxy  + cleartext target -> nothing to do (absolute-form is
        //                                     the request's job, not the tunnel's)
        //   HTTP proxy  + secure target    -> CONNECT
        //   HTTPS proxy                    -> TLS to the proxy, then as above
        //   SOCKS5                         -> RFC 1928 handshake
        //
        // `stream` is the already-connected socket (or the proxy-TLS-wrapped
        // one). It is replaced in the result when the proxy layer adds TLS.
        void establish(std::shared_ptr<AsyncByteStream> stream,
                       const ProxyOptions& proxy,
                       string_view target_host,
                       uint16_t target_port,
                       string_view user_agent,
                       PhaseHook on_phase,
                       TunnelCallback done);

    } // namespace proxy_tunnel
} // namespace megohttp

#include <megohttp/proxy_tunnel_impl.hpp>

#endif // MEGOHTTP_PROXY_TUNNEL_HPP_INCLUDED
