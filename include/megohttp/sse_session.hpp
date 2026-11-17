#ifndef MEGOHTTP_SSE_SESSION_HPP_INCLUDED
#define MEGOHTTP_SSE_SESSION_HPP_INCLUDED

// ---------------------------------------------------------------------------
// SSE Session: long-lived event stream with automatic reconnection.
//
// Unlike a regular HTTP request, an SSE session persists across connection
// drops. When the server disconnects (or the network fails), the session
// automatically reconnects using the configured ReconnectPolicy, resuming from
// the last received event ID.
//
// The session object is returned immediately and remains valid until either:
//   - The caller calls cancel()
//   - The server sends a terminal event (204, or a non-2xx status)
//   - The reconnect policy exhausts its budget
//   - The executor is shut down
//
// All callbacks fire on the I/O thread. The session object itself is
// thread-safe: cancel() can be called from any thread.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/request.hpp>
#include <megohttp/reconnect.hpp>
#include <megohttp/sse.hpp>
#include <megohttp/string_adapter.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

namespace megohttp {

    // Forward declaration
    class Response;

    // -------------------------------------------------------------------------
    // SseSession: a long-lived SSE event stream
    // -------------------------------------------------------------------------
    class SseSession : public std::enable_shared_from_this<SseSession> {
    public:
        using EventCallback = std::function<void(const SseEvent&)>;
        using ErrorCallback = std::function<void(const Error&)>;
        using CompleteCallback = std::function<void()>;
        // Function to submit HTTP requests. The session uses this to avoid
        // circular dependencies with Client.
        using RequestSubmitter =
            std::function<void(Request, std::function<void(Result<Response>)>)>;

        SseSession(std::shared_ptr<Executor> executor,
                   RequestSubmitter submitter,
                   Request request,
                   SseReconnectPolicy reconnect_policy);
        ~SseSession();

        // Set callbacks. Must be called before start().
        void on_event(EventCallback cb);
        void on_error(ErrorCallback cb);
        void on_complete(CompleteCallback cb);

        // Start the session. Fires on_event for each event, on_error on fatal
        // errors, and on_complete when the session terminates (either normally
        // or after exhausting the reconnect budget).
        void start();

        // Cancel the session. Idempotent. After cancel(), no further callbacks
        // will fire.
        void cancel();

        // Query state.
        bool is_active() const { return active_.load(); }
        bool is_cancelled() const { return cancelled_.load(); }

        // The last event ID received. Used for reconnection.
        std::optional<string> last_event_id() const;

        // Internal: called by parser bridge to deliver events
        void deliver_event(const SseEvent& event);

    private:
        void attempt_connection();
        void schedule_reconnect(const Error& err);
        void terminate(const Error& err);
        void terminate();

        std::shared_ptr<Executor> executor_;
        RequestSubmitter submitter_;
        Request request_;
        SseReconnectPolicy reconnect_policy_;

        // Callbacks
        EventCallback event_cb_;
        ErrorCallback error_cb_;
        CompleteCallback complete_cb_;

        // State
        std::atomic<bool> active_{false};
        std::atomic<bool> cancelled_{false};
        std::optional<string> last_event_id_;
        // The last server-suggested retry: field, in milliseconds.
        std::optional<int> event_retry_;
        size_t reconnect_attempts_{0};
        TimePoint session_start_;

        // Parser
        std::unique_ptr<SseParser> parser_;
        std::shared_ptr<SseParser::Callbacks> parser_bridge_;

        // Synchronization
        mutable std::mutex mutex_;
    };

} // namespace megohttp

#include <megohttp/sse_session_impl.hpp>

#endif // MEGOHTTP_SSE_SESSION_HPP_INCLUDED
