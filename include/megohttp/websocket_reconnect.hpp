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

    // -----------------------------------------------------------------------
    // ReconnectingWebSocket: a logical session over physical connections.
    // -----------------------------------------------------------------------
    class ReconnectingWebSocket
        : public std::enable_shared_from_this<ReconnectingWebSocket> {
    public:
        using OpenCallback = std::function<void(const Error&)>;
        using MessageCallback =
            std::function<void(WsMessageType, const std::vector<uint8_t>&)>;
        using MessageBeginCallback = WebSocketSession::MessageBeginCallback;
        using MessageDataCallback = WebSocketSession::MessageDataCallback;
        using MessageEndCallback = WebSocketSession::MessageEndCallback;
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

        // For test injection: the clock the reconnect logic reads, and the
        // scheduler it arms a retry on. Task book 13.7 forbids proving backoff
        // and race behaviour "only with fixed sleeps", so a test needs to drive
        // time itself instead of waiting for it.
        //
        // Both members default to the real thing; an empty function means
        // "use the real one".
        struct TestHooks {
            std::function<TimePoint()> now;
            // Receives the delay and the retry body; a test can run the body
            // immediately (fully deterministic) or record the delay.
            std::function<void(Duration delay, std::function<void()> fn)> schedule_after;
        };

        // Overloads instead of a defaulted nested TestHooks argument; see the
        // AppleClang note in multipart_response.hpp.
        ReconnectingWebSocket(std::shared_ptr<Executor> executor,
                              WsStreamProvider provider,
                              WebSocketOptions ws_options,
                              WebSocketReconnectPolicy policy);
        ReconnectingWebSocket(std::shared_ptr<Executor> executor,
                              WsStreamProvider provider,
                              WebSocketOptions ws_options,
                              WebSocketReconnectPolicy policy,
                              TestHooks test_hooks);
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

        // Incremental send on the CURRENT physical connection. The message is
        // bound to that connection: a disconnect aborts it and the send_end
        // callback fires with the disconnect error. It is never queued or
        // replayed on a reconnect (task book 12.2).
        VoidResult send_begin(WsMessageType type);
        VoidResult send_data(const uint8_t* data, size_t size);
        VoidResult send_data(string_view data);
        VoidResult send_data(const std::vector<uint8_t>& data);
        VoidResult send_end(std::function<void(const Error&)> on_complete = nullptr);
        bool is_sending_message() const noexcept;

        // Incremental receive. Callbacks are stored on the logical session and
        // applied to every new physical connection. A message interrupted by a
        // disconnect does not receive an end callback; the disconnect is
        // reported through on_error/on_close.
        void set_incremental_message_callbacks(MessageBeginCallback begin,
                                               MessageDataCallback data,
                                               MessageEndCallback end);
        void pause_receive();
        void resume_receive();
        bool is_receive_paused() const noexcept;

        // Graceful close of the logical session: sends a close frame, then
        // stops reconnecting.
        void close(uint16_t code = 1000, const string& reason = {});
        // Hard stop, no close frame, no reconnect.
        void terminate();

        bool is_open() const noexcept;
        bool is_reconnecting() const noexcept { return reconnecting_.load(); }
        size_t reconnect_attempts() const noexcept { return attempts_.load(); }
        uint64_t connection_generation() const noexcept { return generation_.load(); }

        // Negotiated permessage-deflate parameters for the CURRENT physical
        // connection. `enabled == false` when no connection is open, or when
        // the server did not accept the extension.
        //
        // Re-read it after a reconnect: every physical connection negotiates
        // independently, so the second connection may agree on different window
        // bits or context-takeover flags than the first (task book 12.2:
        // "重连后查询新的压缩协商结果").
        DeflateNegotiated negotiated_deflate() const {
            std::lock_guard<std::mutex> lock(session_mutex_);
            return session_ ? session_->negotiated_deflate() : DeflateNegotiated{};
        }

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
        TestHooks hooks_;

        // Real time unless a test replaced it.
        TimePoint now() const {
            return hooks_.now ? hooks_.now() : Clock::now();
        }
        void schedule_after(Duration d, std::function<void()> fn) {
            if (hooks_.schedule_after) {
                hooks_.schedule_after(d, std::move(fn));
                return;
            }
            if (executor_) executor_->schedule_after(d, std::move(fn));
        }

        string host_;
        string path_;
        Headers extra_headers_;

        std::shared_ptr<WebSocketSession> session_;   // current physical connection
        mutable std::mutex session_mutex_;

        OpenCallback open_cb_;
        MessageCallback message_cb_;
        MessageBeginCallback inc_message_begin_cb_;
        MessageDataCallback inc_message_data_cb_;
        MessageEndCallback inc_message_end_cb_;
        CloseCallback close_cb_;
        ErrorCallback error_cb_;
        SessionEndCallback end_cb_;
        ReconnectEvents events_;

        std::atomic<bool> receive_paused_{false};

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
