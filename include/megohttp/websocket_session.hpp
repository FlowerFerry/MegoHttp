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
        // permessage-deflate (RFC 7692). Off by default; the runtime switch
        // decides whether the extension is OFFERED at all. When the build has no
        // zlib the offer is rejected at start() with WsCompressionNotCompiled,
        // rather than silently sending a proposal we cannot honour.
        bool enable_deflate{false};
        DeflateOptions deflate{};
        size_t max_message_size{16 * 1024 * 1024};
        size_t max_frame_size{1 * 1024 * 1024};
        bool auto_pong{true};
        Duration close_timeout{std::chrono::seconds(5)};
    };

    class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
    public:
        using MessageCallback =
            std::function<void(WsMessageType, const std::vector<uint8_t>&)>;
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
        void send_ping(const std::vector<uint8_t>& payload = {},
                       std::function<void(const Error&)> on_complete = nullptr);
        void send_pong(const std::vector<uint8_t>& payload = {},
                       std::function<void(const Error&)> on_complete = nullptr);

        void close(uint16_t code = 1000, const string& reason = {});
        void terminate();

        void on_message(MessageCallback cb) { message_cb_ = std::move(cb); }
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
        // connection. valid == false when the extension was not accepted, and
        // false again once the connection ends (the parameters belong to that
        // connection, not to the session).
        DeflateNegotiated negotiated_deflate() const { return deflate_negotiated_; }

    private:
        void do_send_upgrade(const string& host, const string& path,
                             const Headers& extra_headers);
        void start_reading();
        void on_read(Result<string_view> r);
        bool parse_handshake_response();
        static size_t find_double_crlf(const byte_buffer& buf);
        void finish_handshake_failure();

        VoidResult handle_control_frame(const WsFrame& frame);
        VoidResult handle_data_frame(const WsFrame& frame);

        void send_frame(WsOpcode opcode, const std::vector<uint8_t>& payload,
                        bool fin = true, bool rsv1 = false,
                        std::function<void(const Error&)> on_complete = nullptr);
        void pump_send_queue();
        void complete_send(bool ok, Result<size_t> r,
                           std::function<void(const Error&)> on_complete);

        void transition_to_open();
        void transition_to_closing(uint16_t code, const string& reason);
        void transition_to_closed();
        void report_error(const Error& err);

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
        DeflateNegotiated deflate_negotiated_{};
        std::unique_ptr<DeflateCompressor> deflate_out_;
        std::unique_ptr<DeflateDecompressor> deflate_in_;

        std::unique_ptr<WsFrameDecoder::Callbacks> decoder_cbs_;
        std::unique_ptr<WsFrameDecoder> decoder_;

        struct SendItem {
            std::vector<uint8_t> data;
            std::function<void(const Error&)> on_complete;
        };
        std::deque<SendItem> send_queue_;
        bool sending_{false};
        mutable std::mutex send_mutex_;

        MessageCallback message_cb_;
        ErrorCallback error_cb_;
        CloseCallback close_cb_;
        OpenCallback open_cb_;

        std::shared_ptr<Timer> close_timeout_timer_;
    };

} // namespace megohttp

#include <megohttp/websocket_session_impl.hpp>

#endif // MEGOHTTP_WEBSOCKET_SESSION_HPP
