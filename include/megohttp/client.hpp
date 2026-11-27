#ifndef MEGOHTTP_CLIENT_HPP_INCLUDED
#define MEGOHTTP_CLIENT_HPP_INCLUDED

// Minimal Client: the single-request closure over the transport layer.
//
// Scope of this file (phase 1, spec 1.8): plaintext HTTP/1.1 GET with a callback
// API. Connection pooling, redirects, retries, proxies, TLS, SSE and WebSocket
// come later; nothing here pretends to have them.
#include <megohttp/config.hpp>
#include <megohttp/connection_pool.hpp>
#include <megohttp/content_decoder.hpp>
#include <megohttp/content_type.hpp>
#include <megohttp/multipart_sink.hpp>
#include <megohttp/proxy.hpp>
#include <megohttp/proxy_tunnel.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>

#if MEGOHTTP_HAS_COROUTINES
#include <megohttp/task.hpp>
#endif
#include <megohttp/redirect.hpp>
#include <megohttp/cookie.hpp>
#include <megohttp/request.hpp>
#include <megohttp/retry.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/response.hpp>
#if MEGOHTTP_HAS_SSE
#include <megohttp/sse_session.hpp>
#endif
#include <megohttp/string_adapter.hpp>
#include <megohttp/transport.hpp>
#include <megohttp/tls_stream.hpp>
#if MEGOHTTP_HAS_WEBSOCKET
#include <megohttp/websocket_reconnect.hpp>
#endif

#include <chrono>
#include <future>
#include <functional>
#include <memory>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // ClientOptions
    //
    // Only the settings the minimal Client actually honours are here. Fields for
    // pooling/proxy/TLS are added when those features land, so an option never
    // exists here before it does something.
    // ---------------------------------------------------------------------------
    struct ClientOptions {
        Duration dns_timeout{std::chrono::seconds(30)};
        Duration connect_timeout{std::chrono::seconds(30)};
        Duration send_timeout{std::chrono::seconds(30)};     // 0 = disabled; idle between write progress
        Duration recv_timeout{std::chrono::seconds(30)};     // 0 = disabled; idle between read progress
        Duration total_timeout{std::chrono::seconds(0)};     // 0 = disabled, whole request

        // Send "Expect: 100-continue" for requests that carry a body and hold the
        // body back until the server answers 100 Continue (RFC 7230 5.1.1).
        //
        // Off by default: many servers answer 417 and some never answer at all, so
        // waiting costs a round trip. When on, the wait is bounded by send_timeout
        // and a 4xx/5xx final response cancels the body send.
        bool expect_continue{false};

        // Address-family preference for the connection race (S2.5-03).
        // Unspecified lets the racing logic decide (IPv6 first when present);
        // PreferIPv4 / PreferIPv6 pin which family is attempted first.
        ConnectOptions::FamilyPreference family_preference{ConnectOptions::FamilyPreference::Unspecified};

        // Response body cap for buffered mode. 0 = unlimited.
        uint64_t max_response_body{64ULL * 1024 * 1024};

        // Parser limits applied to every response.
        ParserLimits parser_limits{};

        // Limits for the Content-Encoding decoder chain (gzip / brotli).
        // Kept separate from the parser limits on purpose: the compressed size,
        // the intermediate buffers and the decompressed size are three different
        // things, and only the last one is bounded by max_response_body.
        DecoderLimits decoder_limits{};

        // Request trailer limits (S3.1-11). Counted over the declared names in
        // the `Trailer` header AND the emitted trailer fields together, so a
        // source cannot grow the terminator without bound. 0 = unlimited.
        size_t max_request_trailer_count{32};
        size_t max_request_trailer_bytes{8 * 1024};

        // Connection pool (phase 5, task book 8.1). Defaults reproduce the
        // pre-phase-5 behaviour exactly: no limits and no queueing, so every
        // request opens its own connection. Turning the limits on is what makes
        // connections actually be reused; reuse itself also requires the server
        // to keep the connection alive and the response framing to complete.
        PoolOptions pool{};

        // ------------------------------------------------------------------
        // Proxy routing (phase 5, task book 10.1 / 10.2).
        //
        // Off by default, and reading the environment is off by default inside
        // it: a request must not be routed through whatever the caller's shell
        // happens to export without being asked. Target TLS stays in `tls`;
        // the proxy layer has its own TlsConfig and the two never share one
        // object (task book 9.3 forbids that).
        // ------------------------------------------------------------------
        ProxyOptions proxy{};

        // ------------------------------------------------------------------
        // Redirects (phase 5, task book 8.3).
        //
        // Off by default: following redirects changes which origin sees the
        // request and which credentials it carries, so it must be an explicit
        // opt-in rather than something a caller discovers by surprise.
        // ------------------------------------------------------------------
        struct RedirectPolicy {
            bool follow{false};
            size_t max_redirects{10};
            // An https:// -> http:// hop downgrades transport security. It stays
            // refused unless the caller says otherwise (task book 8.3).
            bool allow_https_to_http{false};
        };
        RedirectPolicy redirects;

        // ------------------------------------------------------------------
        // Automatic retry (phase 5, task book 8.4).
        //
        // Off by default: max_retries = 0. A retry re-sends the request, which
        // can duplicate a side effect the server already performed, so it must
        // never happen unless the caller asked for it.
        // ------------------------------------------------------------------
        RetryPolicy retry;

        // Jitter source. Injected so a test can make retry timing deterministic;
        // left null the Client uses its own seeded generator. This is a test
        // seam, not a required setting.
        std::function<uint32_t()> retry_rng;

        // Inject a resolver (tests, address override). Null = system resolver.
        std::shared_ptr<Resolver> resolver;

        // ------------------------------------------------------------------
        // Cookie jar (phase 5, task book 10.3).
        //
        // Null = cookies are off, which reproduces the pre-phase-5 behaviour
        // exactly: no Cookie header is sent and no Set-Cookie is stored.
        //
        // Shared, not owned by value: the same jar is normally shared across
        // several Clients, and "null means off" is harder to get wrong than a
        // separate enable flag that can disagree with the pointer.
        // ------------------------------------------------------------------
        std::shared_ptr<CookieJar> cookie_jar;

        // External event loop. When set, the Client does NOT own the loop or any
        // driver thread, and the caller must keep running it. When null, the
        // Client creates and owns an internal loop thread.
        std::shared_ptr<Executor> executor;

        string user_agent{"MegoHttp/0.1"};

        // TLS settings for https:// requests. One object only: proxy TLS is a
        // separate concern that arrives with the proxy layer (task book 9.3
        // forbids one object silently driving both identities).
        // Left at its defaults, the backend's platform trust store is used.
        TlsConfig tls;

        // Rejects any duration that cannot be represented as a timer deadline.
        // Called by the Client constructor so a bad option fails immediately
        // instead of producing an overflowing deadline much later (S2.3-03).
        VoidResult validate() const {
            const auto max_d = std::chrono::duration_cast<Duration>(
                std::chrono::hours(24 * 365 * 20));   // 20 years, far beyond any use
            struct Check { const char* name; Duration d; };
            const Check checks[] = {
                {"dns_timeout", dns_timeout},
                {"connect_timeout", connect_timeout},
                {"send_timeout", send_timeout},
                {"recv_timeout", recv_timeout},
                {"total_timeout", total_timeout},
            };
            if (proxy.proxy.is_set()) {
                if (proxy.proxy.host.empty()) {
                    return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                                 string("proxy is enabled but has no host")};
                }
                if (proxy.proxy.port == 0) {
                    return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                                 string("proxy is enabled but has no port")};
                }
            }
            for (const auto& c : checks) {
                if (c.d < Duration::zero()) {
                    return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                                 format("{} must not be negative", c.name)};
                }
                if (c.d > max_d) {
                    return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                                 format("{} exceeds the supported maximum", c.name)};
                }
            }
            return VoidResult{};
        }
    };

    class FutureRequest;

    // ---------------------------------------------------------------------------
    // Client
    // ---------------------------------------------------------------------------
    class Client {
    public:
        using ResponseCallback = std::function<void(Result<Response>)>;

        Client();
        explicit Client(ClientOptions options);
        ~Client();

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
        Client(Client&&) noexcept;
        Client& operator=(Client&&) noexcept;

        // Submit a request. The callback fires exactly once, on the I/O thread,
        // with either a Response or an Error.
        //
        // Returns a cancel handle. Cancelling before completion ends the request
        // with ErrorCode::Cancelled; the callback still fires exactly once, so a
        // caller never has to reason about "did cancelling beat the callback".
        CancelHandle request(const Request& request, ResponseCallback on_complete);

        // Convenience: plaintext GET of an absolute http:// URL.
        CancelHandle get(string_view url, ResponseCallback on_complete);

        // Future-based submission (S2.7-01, S2.7-02). Overload of request()
        // distinguished by arity: no callback means "give me a future instead".
        // Returns an operation object holding both the future and the cancel
        // handle, so a caller can always cancel a request it is blocked on.
        //
        // NOTE: FutureRequest::get() blocks the calling thread. Do not call it
        // from the thread that drives this Client's executor.
        FutureRequest request(const Request& request);

        // Convenience: future-based GET.
        FutureRequest get(string_view url);

        // Synchronous request (S2.7-03). Blocks the calling thread until the
        // response arrives or an error occurs. Internally reuses the async core
        // via request_future().get() — no second state machine.
        //
        // When the Client owns an internal loop and this method is called from
        // the loop thread, it returns an InvalidArgument error instead of
        // deadlocking (S2.7-04). For external executors the deadlock cannot be
        // reliably detected; the caller must ensure the executor is driven from
        // another thread.
        Result<Response> request_sync(const Request& request);

        // Convenience: synchronous GET.
        Result<Response> get_sync(string_view url);

#if MEGOHTTP_HAS_COROUTINES
        // Eager coroutine: the request starts immediately on construction.
        // Cancel before await cancels the in-flight request.
        Task<Result<Response>> request_co(const Request& request);
        Task<Result<Response>> get_co(string_view url);
#endif

#if MEGOHTTP_HAS_SSE
        // SSE session (S6.1). Creates a long-lived event stream with automatic
        // reconnection. The session persists across connection drops and resumes
        // from the last event ID.
        std::shared_ptr<SseSession> request_sse(Request request,
                                                SseReconnectPolicy policy);
#endif

#if MEGOHTTP_HAS_WEBSOCKET
        // WebSocket logical session (S6.2). Establishes the TCP/TLS connection
        // through this Client's options (proxy, timeouts, trust store), then
        // layers the Upgrade handshake and the frame protocol on top. When
        // `policy.enabled` is true the session reconnects on a dropped
        // connection; each reconnect re-runs the whole connect + handshake
        // path, so the security policy is never bypassed.
        std::shared_ptr<ReconnectingWebSocket> open_websocket(
            string_view url,
            WebSocketOptions ws_options,
            WebSocketReconnectPolicy policy);
#endif

        // Stop accepting new work and retire every in-flight request with
        // ErrorCode::Cancelled. Idempotent. The executor is shut down only when
        // the Client created it.
        void shutdown();

        // Same, but invokes `on_drained` once every in-flight request has
        // delivered its terminal callback. Runs immediately (on the calling
        // thread) when nothing is in flight. This is the "shutdown finished"
        // signal (S2.6-04).
        void shutdown(std::function<void()> on_drained);

        const ClientOptions& options() const noexcept;

    private:
        class Impl;
        // shared_ptr, not unique_ptr: shutdown() posts retirement jobs to the
        // executor, and those jobs must keep the implementation alive after the
        // caller's Client handle is gone. With a borrowed executor nothing waits
        // for the queue to drain, so a raw `this` in a posted job is a
        // use-after-free the moment the Client is destroyed while a request is
        // still in flight (found by ASan in test_resolver_doh).
        std::shared_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/client_impl.hpp>
// future.hpp needs the complete Client (for request()), so it comes last.
#include <megohttp/future.hpp>

#endif // MEGOHTTP_CLIENT_HPP_INCLUDED
