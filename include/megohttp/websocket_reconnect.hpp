#ifndef MEGOHTTP_WEBSOCKET_RECONNECT_HPP_INCLUDED
#define MEGOHTTP_WEBSOCKET_RECONNECT_HPP_INCLUDED

// ---------------------------------------------------------------------------
// WebSocket auto-reconnect (task book 12.2).
//
// Wraps WebSocketSession in a LOGICAL session that outlives the physical
// connections underneath it. When a connection drops and the reconnect policy
// says "retry", a fresh connect + handshake runs; the old connection and its
// zlib contexts are discarded (RFC 7692 7.1.3 forbids reusing them).
//
// The policy arithmetic lives in reconnect.hpp; this file owns only the loop.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/reconnect.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/transport.hpp>
#include <megohttp/websocket_session.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace megohttp {

    // Produces a connected stream for one physical attempt. Returning null
    // through the error branch ends the session; the caller-visible reason is
    // whatever Error the provider reported.
    using WsStreamProvider =
        std::function<void(string host, string path,
                           std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> on_stream)>;

    // -------------------------------------------------------------------------
    // ReconnectingWebSocket: a logical session over physical connections.
    // -------------------------------------------------------------------------
    class ReconnectingWebSocket
        : public std::enable_shared_from_this<ReconnectingWebSocket> {
    public:
        using OpenCallback = std::function<void(const Error&)>;
        using MessageCallback =
            std::function<void(WsMessageType, const std::vector<uint8_t>&)>;
        using CloseCallback = std::function<void(uint16_t code, const string& reason)>;
        using ErrorCallback = std::function<void(const Error&)>;
        // Session-level terminal, exactly once: user close, budget exhausted,
        // or a non-retryable failure.
        using SessionEndCallback = std::function<void(const Error* reason)>;

        // Fired per PHYSICAL reconnect attempt, so a UI can show "retrying #3".
        struct ReconnectEvents {
            std::function<void(size_t attempt, Duration delay)> on_scheduled;
            std::function<void(size_t attempt, const Error& last_error)> on_attempt_failed;
            std::function<void(size_t attempt, uint64_t generation)> on_succeeded;
            std::function<void(const Error& reason, size_t attempts, bool final)> on_gave_up;
        };

        ReconnectingWebSocket(std::shared_ptr<Executor> executor,
                              WsStreamProvider provider,
                              WebSocketOptions ws_options,
                              WebSocketReconnectPolicy policy);
        ~ReconnectingWebSocket();

        void on_open(OpenCallback cb);
        void on_message(MessageCallback cb);
        void on_close(CloseCallback cb);
        void on_error(ErrorCallback cb);
        void on_session_end(SessionEndCallback cb);
        void set_reconnect_events(ReconnectEvents events);

        // Begin the logical session. Idempotent.
        void start(string host, string path, Headers extra_headers);

        // Send on the CURRENT physical connection. Returns false when there is
        // no open connection: messages are never queued across a disconnect
        // (task book 12.2: "default: reject while disconnected").
        bool send_text(const string& text,
                       std::function<void(const Error&)> on_complete = nullptr);
        bool send_binary(const std::vector<uint8_t>& data,
                         std::function<void(const Error&)> on_complete = nullptr);

        // Graceful close of the logical session: sends a close frame, then
        // stops reconnecting.
        void close(uint16_t code = 1000, const string& reason = {});
        // Hard stop, no close frame, no reconnect.
        void terminate();

        bool is_open() const noexcept;
        bool is_reconnecting() const noexcept { return reconnecting_.load(); }
        size_t reconnect_attempts() const noexcept { return attempts_.load(); }
        uint64_t connection_generation() const noexcept { return generation_.load(); }

    private:
        void attempt_connect();
        void attach(std::shared_ptr<WebSocketSession> session);
        void handle_disconnect(const Error& err);
        void finish_session(const Error& reason);
        void finish_session_clean();

        std::shared_ptr<Executor> executor_;
        WsStreamProvider provider_;
        WebSocketOptions ws_options_;
        WebSocketReconnectPolicy policy_;

        string host_;
        string path_;
        Headers extra_headers_;

        std::shared_ptr<WebSocketSession> session_;   // current physical connection
        mutable std::mutex session_mutex_;

        OpenCallback open_cb_;
        MessageCallback message_cb_;
        CloseCallback close_cb_;
        ErrorCallback error_cb_;
        SessionEndCallback end_cb_;
        ReconnectEvents events_;

        std::atomic<bool> started_{false};
        std::atomic<bool> stopped_{false};      // user closed or session ended
        std::atomic<bool> reconnecting_{false};
        std::atomic<size_t> attempts_{0};
        std::atomic<uint64_t> generation_{0};

        // Stable-connection bookkeeping for the budget reset rule.
        TimePoint connected_at_{};
        // Start of the LOGICAL session; the total-duration budget is measured
        // from here and never refreshed by a reconnect.
        TimePoint session_start_{};
        bool ever_connected_{false};

        mutable std::mutex mutex_;
    };

} // namespace megohttp

#include <megohttp/websocket_reconnect_impl.hpp>

#endif // MEGOHTTP_WEBSOCKET_RECONNECT_HPP_INCLUDED
