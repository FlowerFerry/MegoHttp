#ifndef MEGOHTTP_CLIENT_HPP_INCLUDED
#define MEGOHTTP_CLIENT_HPP_INCLUDED

// Minimal Client: the single-request closure over the transport layer.
//
// Scope of this file (phase 1, spec 1.8): plaintext HTTP/1.1 GET with a callback
// API. Connection pooling, redirects, retries, proxies, TLS, SSE and WebSocket
// come later; nothing here pretends to have them.
#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/request.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/response.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/transport.hpp>

#include <chrono>
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
        Duration send_timeout{std::chrono::seconds(30)};     // 0 = disabled
        Duration recv_timeout{std::chrono::seconds(30)};     // 0 = disabled, whole body
        Duration total_timeout{std::chrono::seconds(0)};     // 0 = disabled, whole request

        // Address-family preference for the connection race (S2.5-03).
        // Unspecified lets the racing logic decide (IPv6 first when present);
        // PreferIPv4 / PreferIPv6 pin which family is attempted first.
        ConnectOptions::FamilyPreference family_preference{ConnectOptions::FamilyPreference::Unspecified};

        // Response body cap for buffered mode. 0 = unlimited.
        uint64_t max_response_body{64ULL * 1024 * 1024};

        // Parser limits applied to every response.
        ParserLimits parser_limits{};

        // Inject a resolver (tests, address override). Null = system resolver.
        std::shared_ptr<Resolver> resolver;

        // External event loop. When set, the Client does NOT own the loop or any
        // driver thread, and the caller must keep running it. When null, the
        // Client creates and owns an internal loop thread.
        std::shared_ptr<Executor> executor;

        string user_agent{"MegoHttp/0.1"};

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
        std::unique_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/client_impl.hpp>
// future.hpp needs the complete Client (for request()), so it comes last.
#include <megohttp/future.hpp>

#endif // MEGOHTTP_CLIENT_HPP_INCLUDED
