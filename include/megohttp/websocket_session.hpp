#ifndef MEGOHTTP_WEBSOCKET_SESSION_HPP
#define MEGOHTTP_WEBSOCKET_SESSION_HPP

// ---------------------------------------------------------------------------
// WebSocket session (task book 12, phase 6 / S6.2-01).
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/transport.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/websocket_deflate.hpp>

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace megohttp {

    enum class WebSocketState { Connecting, Open, Closing, Closed };

    struct WebSocketOptions {
        std::vector<string> subprotocols;
        std::vector<string> extensions;
        bool require_subprotocol{false};

        // --- Handshake credential refresh (task book 12.2 / 6.5) ---
        // Runs BEFORE each handshake, including the first, and receives the
        // header set that is about to be sent. This is the hook a reconnect
        // uses to attach a fresh token: the old one may have expired while the
        // connection was down, and a handshake that reuses it is rejected.
        //
        // Runs on the I/O thread, so it must NOT block. For a token that has to
        // be fetched over the network use async_prepare_headers instead, which
        // is cancellable and does not stall the loop.
        std::function<void(Headers&)> on_before_handshake;

        // Asynchronous credential preparation. Called once per connect attempt;
        // the completion must be invoked exactly once with either the new
        // headers or an error. A late completion after the attempt was
        // cancelled is ignored.
        //
        //   prepared(prepare_done) where
        //     prepare_done(Result<Headers>, Error) -- headers to use, or the
        //     reason the attempt fails.
        //
        // Passing null means "synchronous only": on_before_handshake runs and
        // the attempt proceeds immediately.
        using HeadersPrepared =
            std::function<void(VoidResult, const Headers&)>;
        std::function<void(std::function<void(VoidResult, const Headers&)>)>
            async_prepare_headers;

        // permessage-deflate (RFC 7692). Off by default; the runtime switch
        // decides whether the extension is OFFERED at all. When the build has no
        // zlib the offer is rejected at start() with WsCompressionNotCompiled,
        // rather than silently sending a proposal we cannot honour.
        bool enable_deflate{false};
        DeflateOptions deflate{};
        size_t max_message_size{16 * 1024 * 1024};
        size_t max_frame_size{1 * 1024 * 1024};
        // Total bytes allowed to sit in the send queue (compressed payload +
        // frame header, i.e. what will actually be written). A send that would
        // exceed it fails with WsSendQueueFull instead of growing without
        // bound: the peer may simply stop reading, and nothing else in the
        // library limits how much a caller can pile up behind that.
        size_t max_send_queue_bytes{8 * 1024 * 1024};
        bool auto_pong{true};
        Duration close_timeout{std::chrono::seconds(5)};
        // Test seam: pins the per-handshake client key. Left empty the library
        // uses the platform RNG. A reconnect must still generate a NEW key, so
        // this only fixes the bytes, not the "same key every time" behaviour.
        ws_detail::KeyRandomSource client_key_rng;
    };

    class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
    public:
        using MessageCallback =
            std::function<void(WsMessageType, const std::vector<uint8_t>&)>;
        using MessageBeginCallback = std::function<void(WsMessageType, bool compressed)>;
        using MessageDataCallback = std::function<bool(const uint8_t* data, size_t size)>;
        using MessageEndCallback = std::function<void()>;
        using ErrorCallback = std::function<void(const Error&)>;
        using CloseCallback = std::function<void(uint16_t code, const string& reason)>;
        using OpenCallback = std::function<void(const Error&)>;

        WebSocketSession(std::shared_ptr<AsyncByteStream> stream,
                         const WebSocketOptions& options,
                         std::shared_ptr<Executor> executor);
        ~WebSocketSession();

        WebSocketSession(const WebSocketSession&) = delete;
        WebSocketSession& operator=(const WebSocketSession&) = delete;

        void start(const string& host, const string& path,
                   const Headers& extra_headers, OpenCallback on_open);

        void send_text(const string& text,
                       std::function<void(const Error&)> on_complete = nullptr);
        void send_binary(const std::vector<uint8_t>& data,
                         std::function<void(const Error&)> on_complete = nullptr);

        // Incremental message sending (task book 6.6 / 12.1A):
        //
        //   send_begin(type) -> send_data(...) 0..n times -> send_end(cb)
        //
        // One logical message is produced; frame boundaries are chosen by the
        // library (max_frame_size) and are invisible to the receiver. Only one
        // incremental message may be open at a time. While it is open,
        // send_text/send_binary and a second send_begin return WsInvalidState;
        // control frames (ping/pong/close) may interleave and are never
        // compressed.
        //
        // The message is bound to THIS physical connection. A close, error or
        // reconnect aborts it: the send_end callback fires once with that
        // error, and the bytes are never replayed on a new connection.
        //
        // send_begin/send_data report synchronous rejection (not open, invalid
        // state, message too large, queue full) through their VoidResult. A
        // send_data rejection leaves the message usable -- no compressed input
        // was consumed -- so the caller may retry that chunk. send_end's
        // callback is the message terminal: success after the last frame is
        // written, or the write/connection error. If send_end itself returns an
        // error, it did not accept the message terminal and the callback is not
        // invoked.
        VoidResult send_begin(WsMessageType type);
        VoidResult send_data(const uint8_t* data, size_t size);
        VoidResult send_data(string_view data);
        VoidResult send_data(const std::vector<uint8_t>& data);
        VoidResult send_end(std::function<void(const Error&)> on_complete = nullptr);

        // True while a send_begin/send_data/send_end message is open.
        bool is_sending_message() const noexcept;
        // Encoded bytes currently sitting in the send queue, including the
        // frame being written. The active message's uncompressed bytes are not
        // included; they are accounted at admission instead.
        size_t pending_send_bytes() const noexcept;
        // Uncompressed input bytes represented by frames still in the send
        // queue, including the frame being written. Compressed frames are
        // attributed back to their original chunks; bytes buffered inside zlib
        // with no emitted frame yet are not included. Control-frame payloads
        // count as raw bytes as well. This is observability only; the queue cap
        // still uses pending_send_bytes() plus the admission-time raw estimate.
        size_t pending_send_raw_bytes() const noexcept;
        void send_ping(const std::vector<uint8_t>& payload = {},
                       std::function<void(const Error&)> on_complete = nullptr);
        void send_pong(const std::vector<uint8_t>& payload = {},
                       std::function<void(const Error&)> on_complete = nullptr);

        void close(uint16_t code = 1000, const string& reason = {});
        void terminate();

        void on_message(MessageCallback cb) { message_cb_ = std::move(cb); }

        // Incremental receive (task book 6.6 / 12.1A). When any of these is
        // non-null, the decoder delivers begin -> data* -> end instead of the
        // whole-message on_message callback; on_message is NOT called in that
        // mode. Set these before start() (or before the first message).
        //
        // - begin: once per message; `compressed` is the first frame's RSV1.
        // - data: one frame payload (uncompressed) or one decompressed chunk
        //   (permessage-deflate). Return false to request a receive pause.
        // - end: once per complete message; not called on disconnect/error.
        //
        // Views are valid only during the call. Control frames may interleave
        // and are never passed to data.
        void set_incremental_message_callbacks(MessageBeginCallback begin,
                                               MessageDataCallback data,
                                               MessageEndCallback end);

        // Receive backpressure. pause_receive() stops before the next data
        // frame; control frames already buffered are still delivered.
        // resume_receive() posts to the executor, replays buffered frames, and
        // resumes socket reads. Both are thread-safe.
        void pause_receive();
        void resume_receive();
        bool is_receive_paused() const noexcept;
        void on_close(CloseCallback cb) { close_cb_ = std::move(cb); }
        void on_error(ErrorCallback cb) { error_cb_ = std::move(cb); }

        WebSocketState state() const noexcept { return state_.load(); }
        const string& negotiated_subprotocol() const noexcept { return subprotocol_; }
        bool is_open() const noexcept { return state() == WebSocketState::Open; }
        bool handshake_complete() const noexcept { return handshake_done_; }

        // --- called by the internal frame-decoder bridge ---
        VoidResult on_frame(const WsFrame& frame);
        VoidResult on_message(WsMessageType type, const byte_buffer& payload,
                              bool compressed);

        // Negotiated permessage-deflate parameters for the CURRENT physical
        // connection. `enabled == false` means the extension was not accepted
        // (keep working uncompressed). There is no separate "valid" flag: the
        // value belongs to this connection and is replaced on the next
        // handshake, because a reconnect renegotiates from scratch.
        DeflateNegotiated negotiated_deflate() const { return deflate_negotiated_; }

    private:
        friend class WsDecoderBridge;

        void do_send_upgrade(const string& host, const string& path,
                             Headers& extra_headers);
        void start_reading();
        void on_read(Result<string_view> r);
        bool parse_handshake_response();
        static size_t find_double_crlf(const byte_buffer& buf);
        void finish_handshake_failure();

        VoidResult handle_control_frame(const WsFrame& frame);

        void send_frame(WsOpcode opcode, const std::vector<uint8_t>& payload,
                        bool fin = true, bool rsv1 = false,
                        std::function<void(const Error&)> on_complete = nullptr);
        void pump_send_queue();
        void pump_send_queue_now();
        void complete_send(bool ok, Result<size_t> r,
                           std::function<void(const Error&)> on_complete);

        // --- locked send helpers (send_mutex_ MUST be held) ---
        VoidResult send_frame_locked(WsOpcode opcode, const uint8_t* payload,
                                     size_t size, bool fin, bool rsv1,
                                     std::function<void(const Error&)> on_complete);
        VoidResult enqueue_payload_locked(WsOpcode first_opcode, const uint8_t* payload,
                                          size_t size, bool fin, bool rsv1,
                                          size_t raw_bytes,
                                          std::function<void(const Error&)> on_complete);
        VoidResult send_text_locked(WsOpcode opcode, const uint8_t* data, size_t size,
                                    std::function<void(const Error&)> on_complete);
        VoidResult send_begin_locked(WsMessageType type);
        VoidResult send_data_locked(const uint8_t* data, size_t size);
        VoidResult send_end_locked(std::function<void(const Error&)> on_complete);
        void complete_incremental_locked(const Error& err);
        void complete_incremental(const Error& err);
        void flush_incremental_completion();
        void terminate_impl(const Error& reason, bool notify);
        bool queue_has_capacity_locked(size_t raw_bytes, size_t wire_bytes) const;
        size_t max_fragment_payload() const;
        bool take_fatal_send_error();

        void transition_to_open();
        void transition_to_closing(uint16_t code, const string& reason);
        void transition_to_closed();
        void report_error(const Error& err);

        // --- incremental receive (called by WsDecoderBridge) ---
        bool has_incremental_receive() const noexcept;
        bool receive_pause_requested() const noexcept;
        VoidResult on_incremental_begin(WsMessageType type, bool compressed);
        VoidResult on_incremental_data(const uint8_t* data, size_t size);
        VoidResult on_incremental_end();
        VoidResult deliver_incremental_plain(const uint8_t* data, size_t size);
        void resume_receive_on_loop();

        std::shared_ptr<AsyncByteStream> stream_;
        WebSocketOptions opts_;
        std::shared_ptr<Executor> executor_;
        std::atomic<WebSocketState> state_{WebSocketState::Connecting};

        string ws_key_;
        string subprotocol_;
        bool handshake_done_{false};
        byte_buffer handshake_buf_;

        // permessage-deflate state for THIS connection. Recreated per handshake
        // because the zlib contexts are bound to the negotiated parameters and
        // RFC 7692 7.1.3 forbids carrying them across connections.
        //
        // deflate_negotiated_ stays unconditional: negotiated_deflate() returns
        // it to callers and the "extension not accepted" result is meaningful in
        // every build. The two context objects exist only when the feature is
        // compiled in, which is exactly when their types exist.
        DeflateNegotiated deflate_negotiated_{};
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
        std::unique_ptr<DeflateCompressor> deflate_out_;
        std::unique_ptr<DeflateDecompressor> deflate_in_;
#endif

        std::unique_ptr<WsFrameDecoder::Callbacks> decoder_cbs_;
        std::unique_ptr<WsFrameDecoder> decoder_;

        struct SendItem {
            std::vector<uint8_t> data;
            size_t raw_bytes{0};
            std::function<void(const Error&)> on_complete;
        };
        std::deque<SendItem> send_queue_;
        // Bytes currently queued (front item included while it is being written).
        size_t send_queue_bytes_{0};
        // Uncompressed input bytes represented by the queued frames above.
        size_t send_queue_raw_bytes_{0};
        bool sending_{false};
        // At most one scheduled pump. For an EXTERNAL io_context
        // is_in_loop_thread() is false by contract (no single driver thread), so
        // a naive "post if not on the loop thread" would post forever. An
        // internal loop answers accurately and runs the pump inline.
        std::atomic<bool> pump_posted_{false};
        mutable std::mutex send_mutex_;

        // --- incremental message state (guarded by send_mutex_) ---
        bool incremental_active_{false};
        WsMessageType incremental_type_{WsMessageType::Text};
        size_t incremental_raw_bytes_{0};
        // Raw chunks already consumed by zlib but not yet represented by an
        // emitted frame. They are moved into the send queue with the next
        // compressed output (or send_end's tail).
        size_t incremental_pending_raw_bytes_{0};
        bool incremental_first_frame_sent_{false};
        bool incremental_compressed_{false};
        std::function<void(const Error&)> incremental_complete_;
        bool incremental_completed_{false};
        // Completion extracted under the lock, invoked after it is released.
        std::function<void(const Error&)> incremental_ready_cb_;
        Error incremental_ready_err_;
        bool incremental_ready_{false};
        // A compression/enqueue failure after zlib consumed input leaves the
        // stream unusable; the public wrapper closes the connection.
        bool fatal_send_error_{false};

        MessageCallback message_cb_;
        ErrorCallback error_cb_;
        CloseCallback close_cb_;

        // --- incremental receive state (I/O thread, except the atomics) ---
        MessageBeginCallback message_begin_cb_;
        MessageDataCallback message_data_cb_;
        MessageEndCallback message_end_cb_;
        std::atomic<bool> incremental_receive_enabled_{false};
        std::atomic<bool> receive_paused_{false};
        std::atomic<bool> receive_resume_posted_{false};
        bool rx_incremental_active_{false};
        WsMessageType rx_type_{WsMessageType::Text};
        bool rx_compressed_{false};
        size_t rx_total_{0};
        WsUtf8Validator rx_validator_;
        OpenCallback open_cb_;

        std::shared_ptr<Timer> close_timeout_timer_;
    };

} // namespace megohttp

#include <megohttp/websocket_session_impl.hpp>

#endif // MEGOHTTP_WEBSOCKET_SESSION_HPP
