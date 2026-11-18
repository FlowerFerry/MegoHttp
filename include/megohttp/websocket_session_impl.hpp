#ifndef MEGOHTTP_WEBSOCKET_SESSION_IMPL_HPP
#define MEGOHTTP_WEBSOCKET_SESSION_IMPL_HPP

#include <megohttp/websocket_session.hpp>

#include <charconv>

namespace megohttp {

    using detail::ascii_iequals;
    using detail::sb_append;
    using detail::sb_release;

    // -----------------------------------------------------------------------
    // Frame-decoder bridge.
    //
    // WsFrameDecoder takes a Callbacks& and holds it for its lifetime, so the
    // bridge must be a separately owned object that outlives decoder_.
    // -----------------------------------------------------------------------
    class WsDecoderBridge : public WsFrameDecoder::Callbacks {
    public:
        explicit WsDecoderBridge(WebSocketSession& s) : session_(s) {}
        VoidResult on_control(const WsFrame& f) override { return session_.on_frame(f); }
        VoidResult on_message(WsMessageType t, const byte_buffer& p,
                              bool compressed) override {
            return session_.on_message(t, p, compressed);
        }
    private:
        WebSocketSession& session_;
    };

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    inline WebSocketSession::WebSocketSession(std::shared_ptr<AsyncByteStream> stream,
                                              const WebSocketOptions& options,
                                              std::shared_ptr<Executor> executor)
        : stream_(std::move(stream)), opts_(options), executor_(std::move(executor)) {
        WsFrameDecoder::Limits lim;
        lim.max_frame_bytes = opts_.max_frame_size;
        lim.max_message_bytes = opts_.max_message_size;

        decoder_cbs_ = std::make_unique<WsDecoderBridge>(*this);
        decoder_ = std::make_unique<WsFrameDecoder>(*decoder_cbs_, lim);
    }

    inline WebSocketSession::~WebSocketSession() {
        terminate();
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------
    inline void WebSocketSession::start(const string& host, const string& path,
                                        const Headers& extra_headers, OpenCallback on_open) {
        if (state() != WebSocketState::Connecting) {
            if (on_open) {
                on_open(Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                              string("WebSocket session already started")});
            }
            return;
        }
        open_cb_ = std::move(on_open);

        // A deflate offer the build cannot honour must fail before the handshake
        // goes out: proposing an extension and then being unable to decode the
        // reply corrupts the connection after it looked healthy.
        //
        // The gate is MEGOHTTP_HAS_WEBSOCKET_DEFLATE, not MEGOHTTP_HAS_ZLIB: the
        // latter only says zlib exists (HTTP gzip needs it too), while the former
        // says WS deflate is actually compiled into this build.
        if (opts_.enable_deflate && !MEGOHTTP_HAS_WEBSOCKET_DEFLATE) {
            auto cb = std::move(open_cb_);
            open_cb_ = nullptr;
            state_.store(WebSocketState::Closed);
            if (cb) {
                cb(Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate requested but the build does not include it")});
            }
            return;
        }

        // A local copy: on_before_handshake and async_prepare_headers mutate the
        // header set for THIS attempt only, and the caller's Headers must not be
        // changed behind its back (a reconnect would then carry the previous
        // attempt's token twice).
        Headers hdrs = extra_headers;

        // Asynchronous credential preparation. It is called on the I/O thread
        // and must complete exactly once; a completion arriving after the
        // session was stopped or moved on is dropped, which is what keeps a
        // slow token fetch from resurrecting a dead attempt.
        if (opts_.async_prepare_headers) {
            auto self = shared_from_this();
            opts_.async_prepare_headers(
                [self, host, path, hdrs](VoidResult r, const Headers& prepared) mutable {
                    // The completion may arrive on ANY thread (an auth service
                    // call is exactly the case this hook exists for), but the
                    // handshake touches the stream, which is loop-confined.
                    auto exec = self->executor_;
                    auto apply = [self, r, prepared, hdrs, host, path]() mutable {
                        if (self->state() != WebSocketState::Connecting) return;
                        if (!r) {
                            auto cb = std::move(self->open_cb_);
                            self->open_cb_ = nullptr;
                            self->state_.store(WebSocketState::Closed);
                            if (cb) {
                                try { cb(r.error()); } catch (...) {}
                            }
                            return;
                        }
                        Headers use = prepared.empty() ? hdrs : prepared;
                        self->do_send_upgrade(host, path, use);
                    };
                    if (exec) {
                        exec->post([apply]() mutable { apply(); });
                    } else {
                        apply();
                    }
                });
            return;
        }

        do_send_upgrade(host, path, hdrs);
    }

    inline void WebSocketSession::terminate() {
        if (state() == WebSocketState::Closed) return;
        state_.store(WebSocketState::Closed);
        if (close_timeout_timer_) { close_timeout_timer_->cancel(); close_timeout_timer_.reset(); }
        if (stream_) stream_->async_close(nullptr);
        std::lock_guard<std::mutex> lk(send_mutex_);
        send_queue_.clear();
        send_queue_bytes_ = 0;
    }

    inline void WebSocketSession::close(uint16_t code, const string& reason) {
        if (state() != WebSocketState::Open) return;
        transition_to_closing(code, reason);

        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(code >> 8));
        payload.push_back(static_cast<uint8_t>(code));
        payload.insert(payload.end(), reason.begin(), reason.end());

        send_frame(WsOpcode::Close, payload, true, false, [](const Error&) {});
    }

    // -----------------------------------------------------------------------
    // Upgrade handshake
    // -----------------------------------------------------------------------
    inline void WebSocketSession::do_send_upgrade(const string& host, const string& path,
                                                  Headers& extra_headers) {
        // Credential refresh runs before the key is generated so the callback
        // can see (and replace) whatever the caller supplied. It runs on every
        // handshake, first one included: a token may already have been rotated.
        if (opts_.on_before_handshake) {
            try { opts_.on_before_handshake(extra_headers); } catch (...) {}
        }

        ws_key_ = ws_detail::make_client_key(opts_.client_key_rng);

        string_builder b;
        sb_append(b, "GET ");
        sb_append(b, path);
        sb_append(b, " HTTP/1.1\r\nHost: ");
        sb_append(b, host);
        sb_append(b, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: ");
        sb_append(b, ws_key_);
        sb_append(b, "\r\nSec-WebSocket-Version: 13\r\n");

        if (!opts_.subprotocols.empty()) {
            sb_append(b, "Sec-WebSocket-Protocol: ");
            for (size_t i = 0; i < opts_.subprotocols.size(); ++i) {
                if (i) sb_append(b, ", ");
                sb_append(b, opts_.subprotocols[i]);
            }
            sb_append(b, "\r\n");
        }
        // The deflate offer is built from DeflateOptions so the four RFC 7692
        // parameters come out in the spelling the peer expects.
        std::vector<string> offers = opts_.extensions;
        if (opts_.enable_deflate) {
            string_builder d;
            sb_append(d, "permessage-deflate");
            if (opts_.deflate.client_no_context_takeover) {
                sb_append(d, "; client_no_context_takeover");
            }
            if (opts_.deflate.server_no_context_takeover) {
                sb_append(d, "; server_no_context_takeover");
            }
            // client_max_window_bits may be offered WITHOUT a value ("you may
            // pick"), which is exactly what nullopt means here.
            if (opts_.deflate.client_max_window_bits > 0 &&
                opts_.deflate.client_max_window_bits < 15) {
                sb_append(d, "; client_max_window_bits=");
                sb_append(d, to_view(format("{}", opts_.deflate.client_max_window_bits)));
            }
            if (opts_.deflate.server_max_window_bits > 0 &&
                opts_.deflate.server_max_window_bits < 15) {
                sb_append(d, "; server_max_window_bits=");
                sb_append(d, to_view(format("{}", opts_.deflate.server_max_window_bits)));
            }
            offers.push_back(sb_release(d));
        }

        if (!offers.empty()) {
            sb_append(b, "Sec-WebSocket-Extensions: ");
            for (size_t i = 0; i < offers.size(); ++i) {
                if (i) sb_append(b, ", ");
                sb_append(b, offers[i]);
            }
            sb_append(b, "\r\n");
        }
        for (const auto& kv : extra_headers) {
            sb_append(b, kv.first);
            sb_append(b, ": ");
            sb_append(b, kv.second);
            sb_append(b, "\r\n");
        }
        sb_append(b, "\r\n");

        // Owned on the heap so it outlives the write callback.
        auto req = std::make_shared<string>(sb_release(b));
        auto self = shared_from_this();
        stream_->async_write(
            reinterpret_cast<const uint8_t*>(req->data()), req->size(),
            [this, self, req](Result<size_t> r) {
                if (!r) { report_error(r.error()); return; }
                start_reading();
            });
    }

    inline void WebSocketSession::start_reading() {
        auto self = shared_from_this();
        stream_->async_read_some([this, self](Result<string_view> r) {
            on_read(std::move(r));
        });
    }

    inline void WebSocketSession::on_read(Result<string_view> r) {
        if (!r) {
            if (state() == WebSocketState::Closing) transition_to_closed();
            else report_error(r.error());
            return;
        }
        const auto data = r.value();
        if (data.empty()) {
            if (state() == WebSocketState::Closing) transition_to_closed();
            else report_error(Error{ErrorCode::ConnectionClosed, ErrorPhase::TargetProtocol,
                                    string("WebSocket connection closed unexpectedly")});
            return;
        }

        if (state() == WebSocketState::Connecting) {
            handshake_buf_.insert(handshake_buf_.end(), data.begin(), data.end());
            if (parse_handshake_response()) return;
            start_reading();
            return;
        }

        auto fr = decoder_->feed(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        if (!fr) { report_error(fr.error()); return; }
        start_reading();
    }

    inline size_t WebSocketSession::find_double_crlf(const byte_buffer& buf) {
        if (buf.size() < 4) return static_cast<size_t>(-1);
        for (size_t i = 0; i + 4 <= buf.size(); ++i) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                return i;
            }
        }
        return static_cast<size_t>(-1);
    }

    inline bool WebSocketSession::parse_handshake_response() {
        const size_t hdr_end = find_double_crlf(handshake_buf_);
        if (hdr_end == static_cast<size_t>(-1)) return false;  // need more bytes

        const char* base = reinterpret_cast<const char*>(handshake_buf_.data());
        const string_view head(base, hdr_end);

        // --- status line ---
        size_t eol = head.find('\n');
        if (eol == string_view::npos) { finish_handshake_failure(); return true; }
        string_view status = head.substr(0, eol);
        if (!status.empty() && status.back() == '\r') status = status.substr(0, status.size() - 1);

        const size_t sp1 = status.find(' ');
        if (sp1 == string_view::npos) { finish_handshake_failure(); return true; }
        size_t sp2 = status.find(' ', sp1 + 1);
        if (sp2 == string_view::npos) sp2 = status.size();
        const string_view code_str = status.substr(sp1 + 1, sp2 - sp1 - 1);

        int code = 0;
        {
            auto fr = std::from_chars(code_str.data(), code_str.data() + code_str.size(), code);
            if (fr.ec != std::errc{} || fr.ptr != code_str.data() + code_str.size()) {
                finish_handshake_failure(); return true;
            }
        }

        // --- headers ---
        Headers headers;
        size_t pos = eol + 1;
        while (pos < head.size()) {
            size_t nl = head.find('\n', pos);
            if (nl == string_view::npos) nl = head.size();
            string_view line = head.substr(pos, nl - pos);
            pos = nl + 1;
            if (!line.empty() && line.back() == '\r') line = line.substr(0, line.size() - 1);
            if (line.empty()) break;

            const size_t colon = line.find(':');
            if (colon == string_view::npos) continue;
            string_view name = line.substr(0, colon);
            string_view value = line.substr(colon + 1);
            if (!value.empty() && value.front() == ' ') value = value.substr(1);
            headers.add(to_string(name), to_string(value));
        }

        // --- validation ---
        if (code != 101) { finish_handshake_failure(); return true; }

        const auto upgrade = headers.get("upgrade");
        if (!upgrade || !ascii_iequals(*upgrade, "websocket")) {
            finish_handshake_failure(); return true;
        }
        const auto conn = headers.get("connection");
        if (!conn || !ws_detail::has_token(*conn, "upgrade")) {
            finish_handshake_failure(); return true;
        }

        const auto accept = headers.get("sec-websocket-accept");
        if (!accept) { finish_handshake_failure(); return true; }
        const string expected = ws_detail::accept_key_for(to_view(ws_key_));
        if (*accept != to_view(expected)) { finish_handshake_failure(); return true; }

        if (const auto proto = headers.get("sec-websocket-protocol")) {
            subprotocol_ = to_string(*proto);
            if (opts_.subprotocols.empty() ||
                !ws_detail::subprotocol_was_offered(opts_.subprotocols, to_view(subprotocol_))) {
                finish_handshake_failure(); return true;
            }
        } else if (opts_.require_subprotocol) {
            finish_handshake_failure(); return true;
        }

        // --- extensions: nothing may be accepted that we did not offer ---
        if (const auto exts = headers.get("sec-websocket-extensions")) {
            std::vector<string> offered = opts_.extensions;
            if (opts_.enable_deflate) offered.push_back(string("permessage-deflate"));
            if (ws_detail::extensions_unsolicited(offered, *exts)) {
                finish_handshake_failure(); return true;
            }
        }

        // --- permessage-deflate result ---
        // Three outcomes must stay distinct (spec 12.1A):
        //   accepted            -> build the contexts
        //   not returned at all -> continue UNCOMPRESSED (legal)
        //   accepted but unusable -> handshake failure
        deflate_negotiated_ = DeflateNegotiated{};
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
        deflate_out_.reset();
        deflate_in_.reset();
        if (opts_.enable_deflate) {
            Headers ext_only;
            if (const auto e = headers.get("sec-websocket-extensions")) {
                ext_only.set("sec-websocket-extensions", *e);
            }
            if (const auto agreed = parse_deflate_offer(ext_only)) {
                deflate_negotiated_.enabled = true;
                deflate_negotiated_.server_window_bits = agreed->server_max_window_bits;
                deflate_negotiated_.client_window_bits = agreed->client_max_window_bits;
                deflate_negotiated_.server_no_context_takeover = agreed->server_no_context_takeover;
                deflate_negotiated_.client_no_context_takeover = agreed->client_no_context_takeover;

                // The server may answer with no_context_takeover even when we did
                // not ask, and RFC 7692 forbids rejecting that. What it must NOT
                // do is answer with a parameter we cannot honour.
                if (deflate_negotiated_.server_window_bits < 8 ||
                    deflate_negotiated_.server_window_bits > 15 ||
                    deflate_negotiated_.client_window_bits < 8 ||
                    deflate_negotiated_.client_window_bits > 15) {
                    deflate_negotiated_ = DeflateNegotiated{};
                    finish_handshake_failure(); return true;
                }

                deflate_out_ = std::make_unique<DeflateCompressor>(deflate_negotiated_);
                deflate_in_ = std::make_unique<DeflateDecompressor>(deflate_negotiated_);
            }
        }
#else
        // enable_deflate was rejected in start(); this branch is unreachable but
        // keeps the surrounding logic single-sourced.
        if (opts_.enable_deflate) { finish_handshake_failure(); return true; }
#endif

        // --- success ---
        handshake_done_ = true;
        transition_to_open();
        if (open_cb_) open_cb_(Error{});

        // Bytes after the head are already frames.
        const size_t consumed = hdr_end + 4;
        if (consumed < handshake_buf_.size()) {
            const size_t n = handshake_buf_.size() - consumed;
            byte_buffer rest(handshake_buf_.begin() + consumed, handshake_buf_.end());
            handshake_buf_.clear();
            auto fr = decoder_->feed(rest.data(), rest.size());
            if (!fr) { report_error(fr.error()); return true; }
        } else {
            handshake_buf_.clear();
        }
        start_reading();
        return true;
    }

    inline void WebSocketSession::finish_handshake_failure() {
        // Read the status line out so the message says what actually happened.
        string msg("WebSocket upgrade failed");
        const size_t hdr_end = find_double_crlf(handshake_buf_);
        if (hdr_end != static_cast<size_t>(-1) && hdr_end > 0) {
            const char* base = reinterpret_cast<const char*>(handshake_buf_.data());
            size_t eol = string_view(base, hdr_end).find('\n');
            if (eol == string_view::npos) eol = hdr_end;
            string_builder b;
            sb_append(b, "WebSocket upgrade failed: ");
            sb_append(b, string_view(base, eol));
            msg = sb_release(b);
        }
        const Error e{ErrorCode::WsHandshakeFailed, ErrorPhase::TargetProtocol, msg};
        // Exactly ONE terminal notification. open_cb_ is the negotiated
        // handshake result, and the connection never opened, so that is the
        // right channel; firing error_cb_ as well made ReconnectingWebSocket
        // see one failure twice (once through its start() callback, once
        // through on_error) and run two reconnect schedules for it.
        ErrorCallback err_cb;
        err_cb = std::move(error_cb_);
        error_cb_ = nullptr;
        if (open_cb_) {
            auto cb = std::move(open_cb_);
            open_cb_ = nullptr;
            try { cb(e); } catch (...) {}
        } else if (err_cb) {
            try { err_cb(e); } catch (...) {}
        }
        state_.store(WebSocketState::Closed);
        if (stream_) stream_->async_close(nullptr);
    }

    // -----------------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------------
    inline void WebSocketSession::send_text(const string& text,
                                            std::function<void(const Error&)> on_complete) {
        std::vector<uint8_t> payload(text.begin(), text.end());
        // Empty text is not compressible and RFC 7692 gives no benefit: send it
        // uncompressed so the peer sees a plain empty frame.
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
        const bool compress = deflate_out_ && deflate_negotiated_.enabled && !payload.empty();
        if (compress) payload = deflate_out_->compress(payload);
#else
        const bool compress = false;
#endif
        send_frame(WsOpcode::Text, payload, true, compress, std::move(on_complete));
    }

    inline void WebSocketSession::send_binary(const std::vector<uint8_t>& data,
                                              std::function<void(const Error&)> on_complete) {
        std::vector<uint8_t> payload = data;
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
        const bool compress = deflate_out_ && deflate_negotiated_.enabled && !payload.empty();
        if (compress) payload = deflate_out_->compress(payload);
#else
        const bool compress = false;
#endif
        send_frame(WsOpcode::Binary, payload, true, compress, std::move(on_complete));
    }

    inline void WebSocketSession::send_ping(const std::vector<uint8_t>& payload,
                                            std::function<void(const Error&)> on_complete) {
        if (payload.size() > 125) {
            if (on_complete) {
                on_complete(Error{ErrorCode::WsProtocolError, ErrorPhase::TargetProtocol,
                                  string("Ping payload must be <= 125 bytes")});
            }
            return;
        }
        send_frame(WsOpcode::Ping, payload, true, false, std::move(on_complete));
    }

    inline void WebSocketSession::send_pong(const std::vector<uint8_t>& payload,
                                            std::function<void(const Error&)> on_complete) {
        if (payload.size() > 125) {
            if (on_complete) {
                on_complete(Error{ErrorCode::WsProtocolError, ErrorPhase::TargetProtocol,
                                  string("Pong payload must be <= 125 bytes")});
            }
            return;
        }
        send_frame(WsOpcode::Pong, payload, true, false, std::move(on_complete));
    }

    inline void WebSocketSession::send_frame(WsOpcode opcode,
                                             const std::vector<uint8_t>& payload,
                                             bool fin, bool rsv1,
                                             std::function<void(const Error&)> on_complete) {
        if (state() != WebSocketState::Open && state() != WebSocketState::Closing) {
            if (on_complete) {
                on_complete(Error{ErrorCode::WsNotOpen, ErrorPhase::TargetProtocol,
                                  string("WebSocket session is not open")});
            }
            return;
        }

        std::vector<uint8_t> frame;
        // RFC 7692 6.1: control frames MUST NOT be compressed and MUST NOT carry
        // RSV1. Guarding here means no future caller can get it wrong.
        const bool allow_rsv1 = rsv1 && !ws_is_control_opcode(opcode);
        ws_encode_frame(frame, opcode, payload.data(), payload.size(), fin, allow_rsv1);

        // Bounded send queue: a frame that would exceed the cap is refused
        // with WsSendQueueFull. The already-in-flight frame is excluded from
        // the counter because it is being written right now and cannot grow.
        // This cap exists alongside per-message / per-frame caps because the
        // peer may simply stop reading, and nothing else limits how much a
        // caller can pile up behind that.
        {
            std::lock_guard<std::mutex> lk(send_mutex_);
            if (opts_.max_send_queue_bytes > 0 &&
                send_queue_bytes_ + frame.size() > opts_.max_send_queue_bytes) {
                if (on_complete) {
                    on_complete(Error{ErrorCode::WsSendQueueFull, ErrorPhase::TargetProtocol,
                                      string("send queue is full")});
                }
                return;
            }
            send_queue_bytes_ += frame.size();
            send_queue_.push_back(SendItem{std::move(frame), std::move(on_complete)});
        }
        pump_send_queue();
    }

    inline void WebSocketSession::pump_send_queue() {
        std::shared_ptr<std::vector<uint8_t>> buf;
        std::function<void(const Error&)> cb;
        {
            std::lock_guard<std::mutex> lk(send_mutex_);
            if (sending_ || send_queue_.empty()) return;
            sending_ = true;
            // Move the frame to the heap: the write callback needs it alive.
            buf = std::make_shared<std::vector<uint8_t>>(std::move(send_queue_.front().data));
            cb = std::move(send_queue_.front().on_complete);
            send_queue_.pop_front();
        }

        auto self = shared_from_this();
        stream_->async_write(
            buf->data(), buf->size(),
            [this, self, buf, cb](Result<size_t> r) mutable {
                {
                    std::lock_guard<std::mutex> lk(send_mutex_);
                    sending_ = false;
                    // The frame left the queue: release its share of the cap.
                    send_queue_bytes_ -= (std::min)(send_queue_bytes_, buf->size());
                }
                if (cb) {
                    if (!r) cb(r.error());
                    else cb(Error{});
                }
                pump_send_queue();
            });
    }

    // -----------------------------------------------------------------------
    // Receiving
    // -----------------------------------------------------------------------
    inline VoidResult WebSocketSession::on_frame(const WsFrame& frame) {
        if (ws_is_control_opcode(frame.opcode)) return handle_control_frame(frame);
        // Data frames reach us through the decoder bridge's on_message (which
        // already reassembled fragments and carries the RSV1 flag); this path
        // exists only so a stray data frame is still handled rather than
        // silently dropped.
        const WsMessageType type = (frame.opcode == WsOpcode::Text)
                                       ? WsMessageType::Text
                                       : WsMessageType::Binary;
        return on_message(type, frame.payload, frame.rsv1);
    }

    inline VoidResult WebSocketSession::on_message(WsMessageType type,
                                                   const byte_buffer& payload,
                                                   bool compressed) {
        if (!compressed) {
            // Uncompressed path: no inflation, but the size and UTF-8 rules are
            // identical, so it goes through the same validators.
            if (payload.size() > opts_.max_message_size) {
                const Error e{ErrorCode::WsMessageTooLarge, ErrorPhase::TargetProtocol,
                              string("message exceeded max_message_size")};
                report_error(e);
                return e;
            }
            if (type == WsMessageType::Text) {
                WsUtf8Validator v;
                if (!v.feed(payload.data(), payload.size()) || !v.complete()) {
                    const Error e{ErrorCode::WsUtf8Invalid, ErrorPhase::TargetProtocol,
                                  string("text message is not valid UTF-8")};
                    report_error(e);
                    return e;
                }
            }
            if (message_cb_) message_cb_(type, payload);
            return VoidResult{};
        }

        // RSV1 was set: the payload is DEFLATE output. It is inflated chunk by
        // chunk, and each chunk is validated and size-checked as it appears, so
        // a bad or oversized message is rejected while it is still being
        // produced rather than after the whole thing has been materialised
        // (task book 12.1A).
#if !MEGOHTTP_HAS_WEBSOCKET_DEFLATE
        // A peer can only send RSV1 if we offered the extension, and start()
        // refuses enable_deflate when the build lacks it. Reaching here means
        // the peer violated the protocol (or a build/config mismatch).
        const Error e{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                      string("compressed frame received but permessage-deflate is not compiled in")};
        report_error(e);
        return e;
#else
        if (!deflate_in_ || !deflate_negotiated_.enabled) {
            const Error e{ErrorCode::WsProtocolError, ErrorPhase::TargetProtocol,
                          string("RSV1 set but permessage-deflate was not negotiated")};
            report_error(e);
            return e;
        }

        byte_buffer plain;
        WsUtf8Validator validator;
        size_t total = 0;
        Error sink_error;
        bool overflow = false;

        auto sink = [&](const uint8_t* data, size_t size) -> bool {
            total += size;
            if (total > opts_.max_message_size) {
                overflow = true;
                return false;
            }
            // Text is validated per output chunk; a multi-byte sequence may be
            // split across chunks, which the validator carries over.
            if (type == WsMessageType::Text && !validator.feed(data, size)) {
                sink_error = Error{ErrorCode::WsUtf8Invalid, ErrorPhase::TargetProtocol,
                                   string("text message is not valid UTF-8")};
                return false;
            }
            plain.insert(plain.end(), data, data + size);
            return true;
        };

        auto r = deflate_in_->decompress_streaming(payload, opts_.max_message_size, sink);
        if (!r) {
            // A sink abort is reported as the caller's own error, not as a
            // compression failure: the bytes were well-formed DEFLATE.
            const Error e = sink_error.code() != ErrorCode::Success
                                ? sink_error
                                : (overflow
                                       ? Error{ErrorCode::WsMessageTooLarge,
                                               ErrorPhase::TargetProtocol,
                                               string("decompressed message exceeded "
                                                      "max_message_size")}
                                       : r.error());
            report_error(e);
            return e;
        }

        // A message may not end mid-code-point.
        if (type == WsMessageType::Text && !validator.complete()) {
            const Error e{ErrorCode::WsUtf8Invalid, ErrorPhase::TargetProtocol,
                          string("text message ends with an incomplete UTF-8 sequence")};
            report_error(e);
            return e;
        }

        if (message_cb_) message_cb_(type, plain);
        return VoidResult{};
#endif // MEGOHTTP_HAS_WEBSOCKET_DEFLATE
    }

    inline VoidResult WebSocketSession::handle_control_frame(const WsFrame& frame) {
        switch (frame.opcode) {
            case WsOpcode::Ping:
                if (opts_.auto_pong) send_pong(frame.payload);
                return VoidResult{};

            case WsOpcode::Pong:
                return VoidResult{};

            case WsOpcode::Close: {
                uint16_t code = 1000;
                string reason;
                if (frame.payload.size() >= 2) {
                    code = static_cast<uint16_t>(
                        (static_cast<uint16_t>(frame.payload[0]) << 8) |
                        static_cast<uint16_t>(frame.payload[1]));
                    if (frame.payload.size() > 2) {
                        reason = to_string(
                            reinterpret_cast<const char*>(frame.payload.data() + 2),
                            frame.payload.size() - 2);
                    }
                }
                if (state() == WebSocketState::Open) {
                    // Peer initiated: echo the close, then finish.
                    transition_to_closing(code, reason);
                    std::vector<uint8_t> echo;
                    echo.push_back(static_cast<uint8_t>(code >> 8));
                    echo.push_back(static_cast<uint8_t>(code));
                    echo.insert(echo.end(), frame.payload.begin() + (frame.payload.size() >= 2 ? 2 : 0),
                                frame.payload.end());
                    send_frame(WsOpcode::Close, echo, true, false, [](const Error&) {});
                    transition_to_closed();
                } else if (state() == WebSocketState::Closing) {
                    transition_to_closed();
                }
                return VoidResult{};
            }

            default:
                return VoidResult{};
        }
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------
    inline void WebSocketSession::transition_to_open() {
        state_.store(WebSocketState::Open);
    }

    inline void WebSocketSession::transition_to_closing(uint16_t code, const string& reason) {
        state_.store(WebSocketState::Closing);
        if (close_cb_) close_cb_(code, reason);

        // The peer may never answer; the timeout is what makes close() terminal.
        if (executor_ && opts_.close_timeout != Duration::zero()) {
            auto self = shared_from_this();
            close_timeout_timer_ = executor_->schedule_after(opts_.close_timeout,
                [this, self]() {
                    if (state() != WebSocketState::Closed) transition_to_closed();
                });
        }
    }

    inline void WebSocketSession::transition_to_closed() {
        if (state() == WebSocketState::Closed) return;
        state_.store(WebSocketState::Closed);
        if (close_timeout_timer_) { close_timeout_timer_->cancel(); close_timeout_timer_.reset(); }
        if (stream_) stream_->async_close(nullptr);
        std::lock_guard<std::mutex> lk(send_mutex_);
        send_queue_.clear();
        send_queue_bytes_ = 0;
    }

    inline void WebSocketSession::report_error(const Error& err) {
        // The error callback is a TERMINAL notification and must fire exactly
        // once. Calling it unconditionally meant a second failure arriving
        // during teardown (a close frame racing a read error, say) reported two
        // terminals for one connection. Clear the callback first so any later
        // report_error in the same connection is a no-op.
        ErrorCallback cb;
        cb = std::move(error_cb_);
        error_cb_ = nullptr;
        if (cb) {
            try { cb(err); } catch (...) {}
        }
        terminate();
    }

} // namespace megohttp

#endif // MEGOHTTP_WEBSOCKET_SESSION_IMPL_HPP
