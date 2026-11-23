#ifndef MEGOHTTP_CLIENT_IMPL_HPP_INCLUDED
#define MEGOHTTP_CLIENT_IMPL_HPP_INCLUDED

// Included at the end of client.hpp. Header-only: every definition is inline.
//
// Minimal request pipeline (phase 1, spec 1.8):
//   parse URL -> resolve -> connect -> write head (+ body) -> parse response
//   -> buffer body (or reject it when too large) -> one terminal callback.
//
// Everything runs on the executor. A request submitted from another thread is
// marshalled with post(), so no state below needs a lock beyond the cancel flag.

#if MGHTTP_BACKEND_LIBUV
#include <megohttp/backend/executor_libuv.hpp>
#elif MGHTTP_BACKEND_ASIO
#include <megohttp/backend/executor_asio.hpp>
#endif

#include <megohttp/content_encoder.hpp>

#include <atomic>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <vector>

namespace megohttp {

    namespace detail {

        // Creates the default executor for the compiled backend.
        inline std::shared_ptr<Executor> make_default_executor() {
#if MGHTTP_BACKEND_LIBUV
            return libuv_backend::UvExecutor::create_internal();
#elif MGHTTP_BACKEND_ASIO
            return asio_backend::AsioExecutor::create_internal();
#else
            return nullptr;
#endif
        }

        inline void shutdown_executor(const std::shared_ptr<Executor>& ex) {
            if (!ex) return;
#if MGHTTP_BACKEND_LIBUV
            if (auto uv_ex = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(ex)) {
                uv_ex->shutdown();
                return;
            }
#endif
#if MGHTTP_BACKEND_ASIO
            if (auto a_ex = std::dynamic_pointer_cast<asio_backend::AsioExecutor>(ex)) {
                a_ex->shutdown();
                return;
            }
#endif
        }

        // Buffered response sink. Enforces the byte cap while the body streams in,
        // so an oversized response is rejected on the byte that crosses the limit
        // rather than after it has all been stored.
        class BufferSink {
        public:
            BufferSink(ResponseHead head, uint64_t cap)
                : head_(std::move(head)), cap_(cap) {}

            // Returns false when the cap is exceeded.
            bool append(const uint8_t* data, size_t size) {
                if (cap_ != 0 && body_.size() + size > cap_) return false;
                body_.insert(body_.end(), data, data + size);
                return true;
            }

            // Trailers arrive after the last body byte and before on_complete, so
            // they are recorded on the head the response will carry.
            void set_trailers(const Headers& tr) { head_.trailers = tr; }

            Response finish() {
                Response r(std::move(head_), std::move(body_));
                return r;
            }

        private:
            ResponseHead head_;
            std::vector<uint8_t> body_;
            uint64_t cap_{0};
        };

        // Per-request state. Self-holding: the request owns it from submission
        // until the terminal callback runs, so a caller that drops the cancel
        // handle does not abort anything.
        //
        // The phase field records which stage of the request lifecycle we are in,
        // so errors carry the correct phase information (S2.1-01, S2.1-02).
        enum class RequestPhase : int32_t {
            Idle = 0,
            UrlParse,
            BuildHead,
            Resolve,
            Connect,
            // Proxy stages (S5.4). Kept separate from their target-side
            // counterparts so a failure report says which hop broke: a proxy
            // that refuses CONNECT must not look like a target TLS failure.
            ProxyResolve,
            ProxyConnect,
            ProxyTls,
            ProxyAuth,
            ProxyConnectTunnel,
            TlsHandshake,
            SendHead,
            SendBody,
            Receive,
            Done,
        };

        struct RequestState : std::enable_shared_from_this<RequestState> {
            std::shared_ptr<Executor> executor;
            std::shared_ptr<Resolver> resolver;
            std::shared_ptr<CookieJar> cookie_jar;
            // The URL this attempt is actually talking to. Differs from the
            // request's text after a redirect, and it is what the cookie jar
            // judges domain / path / Secure against.
            std::optional<Url> current_url;
            ClientOptions options;
            Request request;
            Client::ResponseCallback on_complete;

            std::atomic<bool> finished{false};
            std::shared_ptr<Timer> total_timer;
            std::shared_ptr<Timer> dns_timer;
            CancelHandle dns_cancel;

            // ONE connection-stage deadline covering DNS, TCP, proxy TLS,
            // CONNECT and the target TLS handshake (S5.8-01). Armed once per
            // attempt and never re-armed, so a proxy that accepts TCP and then
            // stalls mid-handshake cannot buy itself a fresh connect_timeout.
            //
            // Errors report the phase that was actually running when it fired,
            // which is what makes "the proxy handshake timed out" distinguishable
            // from "the target handshake timed out".
            std::shared_ptr<Timer> connect_stage_timer;
            bool connect_stage_done{false};
            // Wall point the whole connection stage must be finished by. Kept
            // so sub-stages can be handed the REMAINING time instead of a fresh
            // full budget -- connect_race arms its own timer, and without this
            // TCP would silently get a second connect_timeout after DNS had
            // already spent part of the first one.
            TimePoint connect_stage_deadline{};

            // Milliseconds left in the connection stage. Zero means "no budget"
            // (unlimited), which is also what a disabled connect_timeout means.
            Duration connect_stage_remaining() const {
                if (connect_stage_done) return Duration::zero();
                const auto now = Clock::now();
                if (connect_stage_deadline <= now) return Duration::zero();
                return connect_stage_deadline - now;
            }

            RequestPhase phase{RequestPhase::Idle};

            // True when the request head carried Expect: 100-continue and the body
            // must wait for a 100 answer (S3.1-09).
            bool expect_continue_sent{false};
            // True when the request body is sent chunk-framed (a BodySource with
            // no caller-supplied framing header). The sender wraps every piece.
            bool body_chunked{false};

            // Request body compression (task book 7.3). The body is encoded
            // ONCE in submit(), before the state is registered, so every retry
            // and redirect hop reuses the exact bytes that were already sent.
            // `encoded_body` is only consulted when wire_coding != None.
            Request::Compression wire_coding{Request::Compression::None};
            std::vector<uint8_t> encoded_body;

            // The bytes that actually go on the wire. One accessor for the head
            // builder and both send paths, so a compressed request cannot end up
            // advertising a length that differs from what is written.
            const std::vector<uint8_t>& wire_body() const noexcept {
                return wire_coding == Request::Compression::None
                    ? request.body_bytes() : encoded_body;
            }

            // Held while the exchange is live so the stream outlives its callbacks.
            std::shared_ptr<AsyncByteStream> stream;

            // Holds the TLS layer for https:// requests. Once the handshake
            // completes `stream` points at this same object; on a handshake
            // failure `stream` still refers to the raw TCP stream, which is what
            // the error path needs.
            std::shared_ptr<TlsStream> tls_stream;

            // Self-hold until the terminal callback fires.
            std::shared_ptr<RequestState> self_hold;

            // Called once from finish() so the owning Client can drop this request
            // from its in-flight set and possibly fire a shutdown-drained callback.
            std::function<void()> on_retired;

            // Connection pool plumbing (phase 5). `pool` is null when pooling is
            // disabled, in which case every request opens and closes its own
            // connection exactly as before Phase 5.
            std::shared_ptr<ConnectionPool> pool;
            PoolKey pool_key;
            // Set while this request holds a pooled connection, so finish() can
            // return it exactly once. Null means "not from the pool" (either
            // pool disabled, or the request never got that far).
            std::shared_ptr<AsyncByteStream> pooled_stream;
            bool pooled_clean{false};

            // Proxy routing (S5.4). `proxy` is the decision resolved once in
            // begin() for this hop: an empty ProxyConfig means "connect directly".
            // `proxy_tls_stream` holds the PROXY layer's TLS object, which is a
            // different object from `tls_stream` (the target layer) on purpose:
            // one object must never validate both identities.
            ProxyConfig proxy;
            TlsConfig proxy_tls_config;
            std::shared_ptr<TlsStream> proxy_tls_stream;
            // Bytes the proxy handshake read past what it consumed.
            byte_buffer proxy_leftover;
            // The target's address as raw bytes, used only by SOCKS5 local-DNS
            // mode (remote DNS sends the name instead). Filled from the URL when
            // the target is a literal, or from the resolver when it is a name.
            byte_buffer proxy_target_addr;

            // Redirect bookkeeping (S5.2). `hops_left` counts down from the
            // configured limit; `visited` holds the URLs already requested so a
            // loop is detected instead of burning the whole budget.
            size_t hops_left{0};
            std::vector<string> visited;

            // Continue with the next hop of a redirect. Called from the exchange
            // once it has consumed the 3xx head. This is NOT a terminal event:
            // the request keeps its cancel handle and timers, and the connection
            // returns to the pool through the usual path.
            //
            // The restart lives in Client::Impl, so it arrives as an injected hook
            // rather than a direct call: RequestState is defined before Impl and
            // cannot name its statics.
            std::function<void(int, std::optional<string>)> on_redirect;

            // Retry bookkeeping (S5.3). `attempts_done` counts retries the
            // policy has approved; `retry_timer` waits out the backoff and is
            // cancelled by finish() so a retired request cannot restart itself.
            size_t attempts_done{0};
            std::shared_ptr<Timer> retry_timer;
            // Set when any part of the response head arrived, or any body byte
            // reached the caller: both make a retry unsafe.
            bool response_started{false};
            // Status of the last COMPLETE response head, and its Retry-After
            // resolved to a duration. Both feed the retry decision: a 503 is
            // retryable where a 200 is not, and the server may name its own
            // delay.
            int last_status{0};
            std::optional<Duration> last_retry_after;
            bool body_delivered{false};
            // Restart hook, injected by Impl for the same reason as on_redirect.
            // Returns true when it has started a retry (so the caller must NOT
            // finish), false when the policy declined.
            std::function<bool(Error)> on_retry;

            // Fires the terminal callback exactly once.
            void finish(Result<Response> result) {
                if (finished.exchange(true)) return;
                if (total_timer) total_timer->cancel();
                if (dns_timer) dns_timer->cancel();
                if (connect_stage_timer) { connect_stage_timer->cancel(); connect_stage_timer.reset(); }
                if (retry_timer) { retry_timer->cancel(); retry_timer.reset(); }
                dns_cancel.cancel();   // stop a late DNS answer from firing the callback

                // Return the connection to the pool (or close it) BEFORE the user
                // callback runs, so a callback that immediately submits another
                // request can reuse this connection. `pooled_clean` is only true
                // when the response framing completed AND the server did not ask
                // to close: task book 8.1 forbids pooling anything else, and
                // S2.1-03 forbids pooling a connection whose framing broke.
                if (pooled_stream && pool) {
                    PooledConnection pc;
                    pc.stream = std::move(pooled_stream);
                    pc.key = pool_key;
                    pooled_stream.reset();
                    pool->put(std::move(pc), pooled_clean);
                } else if (pooled_stream) {
                    // Pool went away (Client shutting down): close it ourselves.
                    pooled_stream->async_close(nullptr);
                    pooled_stream.reset();
                }

                auto cb = std::move(on_complete);
                auto retired = std::move(on_retired);
                // Release the hold before the callback so a callback that
                // re-enters does not resurrect this state. The stream is closed
                // separately by async_close() and held alive by its own callback.
                self_hold.reset();
                // Fire the user callback FIRST, then the retirement notice.
                // shutdown(cb) waits for all retired callbacks before firing its
                // drained signal, so the user callback must complete first.
                //
                // Guarded: this runs inside an event-loop handler, and an
                // exception escaping from here would unwind through libuv/Asio
                // and skip the retirement notice below -- leaving shutdown(cb)
                // waiting forever.
                try {
                    if (cb) cb(std::move(result));
                } catch (...) {
                    // A throwing completion callback must not corrupt the loop.
                    // The request is already retired; nothing else to report.
                }
                if (retired) retired();
            }

            // Phase-aware error wrapper: fills in the ErrorPhase from the current
            // request stage when the error did not already carry one.
            void fail(const Error& e) {
                ErrorCode code = e.code();
                string msg = e.message();
                ErrorPhase p = e.phase();
                if (p == ErrorPhase::None) {
                    switch (phase) {
                    case RequestPhase::UrlParse:  p = ErrorPhase::Resolve;   break;
                    case RequestPhase::BuildHead: p = ErrorPhase::Send;      break;
                    case RequestPhase::Resolve:   p = ErrorPhase::Resolve;   break;
                    case RequestPhase::Connect:   p = ErrorPhase::TcpConnect;break;
                    case RequestPhase::TlsHandshake: p = ErrorPhase::TlsHandshake; break;
                    case RequestPhase::SendHead:
                    case RequestPhase::SendBody:  p = ErrorPhase::Send;      break;
                    case RequestPhase::Receive:   p = ErrorPhase::Receive;   break;
                    default: break;
                    }
                }
                // Retry decision comes BEFORE the terminal callback. The hook
                // returns true when it started a retry, in which case this request
                // stays alive and must NOT finish now.
                if (on_retry && on_retry(Error{code, p, msg})) {
                    return;
                }
                finish(Result<Response>(Error{code, p, std::move(msg)}));
            }

        };

        // Bridges MultipartResponseParser to the caller's MultipartSink.
        //
        // A separate class rather than letting Exchange implement both callback
        // interfaces: both declare on_complete(), so one class cannot be both.
        //
        // The two completion conditions stay apart on purpose. The parser's
        // on_complete here only RECORDS that the closing boundary was seen; the
        // sink's on_complete fires later, from the Exchange, once the HTTP
        // message has also completed. A closing boundary says nothing about the
        // epilogue that may follow, and nothing about the framing being intact.
        class MultipartBridge final : public MultipartResponseParser::Callbacks {
        public:
            explicit MultipartBridge(std::shared_ptr<MultipartSink> sink)
                : sink_(std::move(sink)) {}

            VoidResult on_part_start(const Headers& headers) override {
                MultipartPartHead h;
                h.headers = headers;
                h.index = index_++;
                // A throwing sink must not unwind through the parser/loop, and it
                // must become a terminal error rather than a silently skipped part.
                try {
                    sink_->on_part_begin(h);
                } catch (...) {
                    return Error{ErrorCode::Unknown, ErrorPhase::MultipartParse,
                                 string("multipart sink threw from on_part_begin")};
                }
                return VoidResult{};
            }

            bool on_part_data(string_view data) override {
                try {
                    // Any byte that reaches the caller makes a retry unsafe: it
                    // would re-deliver the same part data.
                    if (data.size() > 0) delivered_ = true;
                    const bool keep_going = sink_->on_part_data(
                        reinterpret_cast<const uint8_t*>(data.data()), data.size());
                    if (!keep_going) paused_ = true;
                    return keep_going;
                } catch (...) {
                    threw_ = true;
                    throw_error_ = Error{ErrorCode::Unknown, ErrorPhase::MultipartParse,
                                         string("multipart sink threw from on_part_data")};
                    return false;   // stop the parser; the Exchange re-raises threw()
                }
            }

            VoidResult on_part_end() override {
                try {
                    sink_->on_part_end();
                } catch (...) {
                    return Error{ErrorCode::Unknown, ErrorPhase::MultipartParse,
                                 string("multipart sink threw from on_part_end")};
                }
                return VoidResult{};
            }

            // Closing boundary found. NOT the terminal event the caller receives.
            VoidResult on_complete() override {
                multipart_complete = true;
                return VoidResult{};
            }

            bool threw() const noexcept { return threw_; }
            const Error& throw_error() const noexcept { return throw_error_; }
            void clear_threw() noexcept { threw_ = false; }
            bool paused() const noexcept { return paused_; }
            void clear_paused() noexcept { paused_ = false; }
            bool multipart_complete{false};
            // True once ANY part data reached the sink, so a retry policy knows
            // the caller has seen payload bytes.
            bool delivered() const noexcept { return delivered_; }

        private:
            std::shared_ptr<MultipartSink> sink_;
            size_t index_{0};
            bool threw_{false};
            bool paused_{false};
            bool delivered_{false};
            Error throw_error_{};
        };
        // Drives one response over a connected stream: write the head, then feed
        // every byte to the ResponseParser until on_complete.
        class Exchange final : public ResponseParser::Callbacks,
                               public std::enable_shared_from_this<Exchange> {
        public:
            Exchange(std::shared_ptr<RequestState> state)
                : state_(std::move(state)), parser_(nullptr) {}

            void set_parser(std::unique_ptr<ResponseParser> p) {
                parser_ = std::move(p);
            }

            // send_timeout covers the whole write of head + body: one deadline from
            // the first byte to the last (S2.3-02).
            void arm_send_timer() {
                const auto d = state_->options.send_timeout;
                if (d == Duration::zero()) return;
                auto self = shared_from_this();
                send_timer_ = state_->executor->schedule_after(d, [self] {
                    self->fail(Error{ErrorCode::TimeoutSend, ErrorPhase::Send,
                                     string("request send timed out")});
                });
            }

            void disarm_send_timer() {
                if (send_timer_) { send_timer_->cancel(); send_timer_.reset(); }
            }

            // recv_timeout covers the whole response (head + body), not each read.
            void arm_recv_timer() {
                const auto d = state_->options.recv_timeout;
                if (d == Duration::zero()) return;
                auto self = shared_from_this();
                recv_timer_ = state_->executor->schedule_after(d, [self] {
                    self->fail(Error{ErrorCode::TimeoutRecv, ErrorPhase::Receive,
                                     string("response receive timed out")});
                });
            }

            void disarm_recv_timer() {
                if (recv_timer_) { recv_timer_->cancel(); recv_timer_.reset(); }
            }

            // Start by sending the encoded head.
            //
            // When `hold_body_for_continue` is set the request carries a body and
            // we sent Expect: 100-continue, so the body waits for a 1xx answer
            // (RFC 7231 5.1.1: a client MUST NOT send the body before receiving
            // 100, and MAY send it if the server did not answer within a timeout).
            void start(string head, bool hold_body_for_continue) {
                state_->phase = detail::RequestPhase::SendHead;
                expect_continue_pending_ = hold_body_for_continue;
                arm_send_timer();
                auto self = shared_from_this();
                auto stream = state_->stream;
                stream->async_write(
                    reinterpret_cast<const uint8_t*>(head.data()), head.size(),
                    [self](Result<size_t> w) {
                        if (!w) { self->fail(w.error()); return; }
                        if (self->expect_continue_pending_) {
                            // Head is out; the body waits for 100 Continue. Keep
                            // send_timer_ armed: it bounds the wait, so a server
                            // that never answers fails with TimeoutSend instead of
                            // hanging. Reading is what delivers that answer.
                            self->state_->phase = detail::RequestPhase::Receive;
                            self->read_more();
                            return;
                        }
                        self->send_body();
                    });
            }

            // Send the body after 100 Continue, or after a final status that is not
            // 417 (RFC 7231 lets the client send anyway; the response is already
            // being read, so this is best-effort and its write errors are ignored).
            void send_body_now() {
                if (body_sent_) return;
                body_sent_ = true;
                expect_continue_pending_ = false;

                // Streaming mode: pull from BodySource.
                if (state_->request.body_source()) {
                    send_body_streaming();
                    return;
                }

                // Buffered mode: single write of the whole buffer.
                const auto& body = state_->wire_body();
                if (body.empty()) {
                    // No buffered body: proceed to reading response.
                    disarm_send_timer();
                    arm_recv_timer();
                    read_more();
                    return;
                }
                auto self = shared_from_this();
                auto stream = state_->stream;
                stream->async_write(body.data(), body.size(),
                    [](Result<size_t>) {
                        // The server may already have answered and closed; a failed
                        // body write must not overwrite the response it sent.
                    });
            }

            // Send body if present, then start reading the response.
            // Supports both buffered (body_bytes) and streaming (body_source) modes.
            void send_body() {
                state_->phase = detail::RequestPhase::SendBody;
                body_sent_ = true;
                auto self = shared_from_this();
                auto stream = state_->stream;

                // No body at all: go straight to reading.
                if (!state_->request.has_body()) {
                    disarm_send_timer();
                    arm_recv_timer();
                    read_more();
                    return;
                }

                // Streaming mode: pull from BodySource.
                if (auto& src = state_->request.body_source()) {
                    send_body_streaming();
                    return;
                }

                // Buffered mode: single write of the whole buffer.
                const auto& body = state_->wire_body();
                if (body.empty()) {
                    disarm_send_timer();
                    arm_recv_timer();
                    read_more();
                    return;
                }
                stream->async_write(body.data(), body.size(),
                    [self](Result<size_t> w) {
                        if (!w) { self->fail(w.error()); return; }
                        self->disarm_send_timer();
                        self->arm_recv_timer();
                        self->read_more();
                    });
            }

            // Streaming body: pull chunks from BodySource and write them.
            // Backpressure: empty chunk from Source means "not ready, retry later".
            //
            // When the request is chunk-framed every piece is wrapped:
            //     "<hex size>\r\n<bytes>\r\n"
            // and the terminator is emitted once at EOF. Sending the raw bytes
            // without the wrapper would make the server read them as a new
            // response, which is worse than failing.
            void send_body_streaming() {
                auto& src = *state_->request.body_source();
                Result<std::pair<string_view, bool>> r = Error{
                    ErrorCode::Unknown, ErrorPhase::None, string("body source threw")};
                try {
                    r = src();
                } catch (...) {
                    fail(Error{ErrorCode::Unknown, ErrorPhase::Send,
                               string("request body source threw an exception")});
                    return;
                }
                if (!r) { fail(r.error()); return; }

                auto& [data, eof] = r.value();
                if (data.empty() && !eof) {
                    // Backpressure: Source not ready. Retry shortly.
                    //
                    // The timer is stored on the Exchange so a cancel, timeout
                    // or error can disarm it. Without that, the timer would
                    // outlive the terminal state and call the user's BodySource
                    // after the request was already reported finished -- a
                    // callback after the terminal result, which the contract
                    // forbids, and a write to a retired stream.
                    auto self = shared_from_this();
                    source_retry_timer_ = state_->executor->schedule_after(
                        std::chrono::milliseconds(10),
                        [self]() {
                            self->source_retry_timer_.reset();
                            // Re-check: the terminal may have happened between
                            // the timer firing and this callback running.
                            if (self->state_->finished.load()) return;
                            self->send_body_streaming();
                        });
                    return;
                }

                if (!data.empty()) {
                    auto self = shared_from_this();
                    auto stream = state_->stream;
                    // The wire form is built into an owned buffer that stays
                    // alive until the write completes.
                    auto buf = std::make_shared<string>(
                        state_->body_chunked
                            ? chunked::encode_chunk(
                                  reinterpret_cast<const uint8_t*>(data.data()),
                                  static_cast<size_t>(data.size()))
                            : to_string(data));
                    stream->async_write(
                        reinterpret_cast<const uint8_t*>(buf->data()), buf->size(),
                        [self, buf, eof](Result<size_t> w) {
                            (void)buf; // keep alive
                            if (!w) { self->fail(w.error()); return; }
                            if (eof) {
                                self->finish_body_streaming();
                            } else {
                                self->send_body_streaming();
                            }
                        });
                } else if (eof) {
                    finish_body_streaming();
                }
            }

            // Emits the chunked terminator (when chunk-framed) and moves on to
            // reading the response.
            void finish_body_streaming() {
                if (!state_->body_chunked) {
                    disarm_send_timer();
                    arm_recv_timer();
                    read_more();
                    return;
                }
                auto self = shared_from_this();
                auto stream = state_->stream;
                auto tail = chunked::encode_last_chunk(nullptr);
                if (!tail) { fail(tail.error()); return; }
                auto last = std::make_shared<string>(std::move(tail.value()));
                stream->async_write(
                    reinterpret_cast<const uint8_t*>(last->data()), last->size(),
                    [self, last](Result<size_t> w) {
                        (void)last;
                        if (!w) { self->fail(w.error()); return; }
                        self->disarm_send_timer();
                        self->arm_recv_timer();
                        self->read_more();
                    });
            }

            // --- ResponseParser::Callbacks ---
            // 100 Continue releases the held body (S3.1-09).
            VoidResult on_informational(int status_code) override {
                if (expect_continue_pending_ && status_code == 100) {
                    disarm_send_timer();
                    send_body_now();
                    arm_recv_timer();
                }
                return VoidResult{};
            }

            // Decide whether this 3xx is followable. Returns true when the
            // exchange should treat the response as a redirect-to-be-followed;
            // false means "not followable, handle it as a normal response",
            // which is what a caller wants when the policy is off or the
            // Location is missing/unusable.
            bool handle_redirect(const ParsedResponse& head) {
                // The body of a redirect carries no useful payload, and reading
                // it would keep the connection busy for nothing. The response
                // parser still drives the stream; we simply stop descending into
                // the normal path.
                auto loc = head.headers.get("location");
                if (!loc) return false;

                // Budget.
                if (state_->hops_left == 0) {
                    // Set the flags BEFORE failing: fail() can start a retry, and
                    // a retry re-reads this exchange's state. Writing them after
                    // the call is writing to a request that may already be over.
                    redirect_pending_ = true;
                    redirect_location_.reset();
                    fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                               string("too many redirects")});
                    return true;
                }

                redirect_pending_ = true;
                redirect_status_ = head.status_code;
                redirect_location_ = to_string(*loc);
                return true;
            }

            VoidResult on_head(const ParsedResponse& head) override {
                // Any head at all means the server accepted and answered this
                // request. From here on a retry could duplicate its effect.
                state_->response_started = true;
                state_->last_status = head.status_code;

                // Cookies (S5.5). Stored BEFORE the redirect branch below, so a
                // 3xx that sets a cookie still records it: the next hop's Cookie
                // header is rebuilt from the jar, and losing this would drop a
                // session the server just established.
                //
                // Each Set-Cookie header is applied separately. They cannot be
                // comma-joined: an Expires value contains a comma.
                if (state_->cookie_jar && state_->current_url) {
                    for (const auto& v : head.headers.get_all("set-cookie")) {
                        // A rejected cookie (public suffix, wrong domain, Secure
                        // over http) must not fail the request: the response is
                        // still valid, the cookie is simply not ours to keep.
                        (void)state_->cookie_jar->set_from_header(*state_->current_url, v);
                    }
                }

                // Retry-After is resolved here, while the Date header is still
                // at hand: a date-form value only becomes a delay against the
                // server's own Date, never against the local clock.
                state_->last_retry_after.reset();
                if (auto ra = head.headers.get("retry-after")) {
                    const string_view date_hdr = head.headers.get("date")
                                                     ? *head.headers.get("date")
                                                     : string_view{};
                    state_->last_retry_after = retry_detail::parse_retry_after(
                        *ra, date_hdr);
                }
                // Redirect interception (S5.2). This has to happen before the
                // normal head handling: a 3xx with a usable Location is not a
                // response the caller wants, it is the next request.
                if (redirect_detail::is_redirect_status(head.status_code) &&
                    state_->options.redirects.follow && !redirect_pending_) {
                    if (handle_redirect(head)) return VoidResult{};
                }

                // If we were still holding the body for a 100 answer and the server
                // went straight to a final status: 417 means it refuses the Expect,
                // so do not send; any other status means it may have consumed the
                // request already, so send best-effort.
                if (expect_continue_pending_) {
                    disarm_send_timer();
                    if (head.status_code != 417) send_body_now();
                    else { expect_continue_pending_ = false; body_sent_ = true; }
                }
                ResponseHead rh;
                rh.status_code = head.status_code;
                rh.status_text = head.reason;
                rh.headers = head.headers;
                rh.content_length = (head.framing == ParsedResponse::BodyFraming::ContentLength)
                                        ? std::optional<uint64_t>(head.content_length)
                                        : std::nullopt;
                rh.is_chunked = (head.framing == ParsedResponse::BodyFraming::Chunked);
                rh.connection_close = head.connection_close;
                if (auto ce = head.headers.get("content-encoding")) {
                    rh.content_encoding = to_string(*ce);
                }
                if (auto te = head.headers.get("transfer-encoding")) {
                    rh.transfer_encoding = to_string(*te);
                }
                if (auto ct = head.headers.get("content-type")) {
                    rh.content_type = to_string(*ct);
                }
                rh.informational_status_codes = head.informational;

                // S3.2-02: Choose buffered or streaming mode based on request.
                //
                // Three consumers exist and exactly one is chosen:
                //   sse callback -> bytes go to the SSE parser only
                //   multipart sink -> bytes go to the multipart parser only
                //   body sink      -> bytes go to the caller's sink
                //   neither        -> bytes accumulate in BufferSink
                // Request itself guarantees the sinks are mutually exclusive, so
                // this is a priority chain rather than a validation.
#if MEGOHTTP_HAS_SSE
                if (auto& sse_cb = state_->request.sse_callback()) {
                    // Check the Content-Type BEFORE moving rh into head_:
                    // after the move rh is empty and the check would always fail.
                    //
                    // The media type is compared without its parameters: a
                    // server is free to answer "text/event-stream;charset=utf-8"
                    // (the WHATWG default is UTF-8 and stating it is common), and
                    // an exact whole-value compare would silently fall through to
                    // the buffered path with the caller never learning its SSE
                    // callback was ignored.
                    bool is_sse = false;
                    if (rh.content_type) {
                        const string_view ct = to_view(*rh.content_type);
                        const size_t semi = ct.find(';');
                        is_sse = detail::ascii_iequals(
                            (semi == string_view::npos) ? ct
                                                        : ct.substr(0, semi),
                            "text/event-stream");
                    }
                    head_ = std::move(rh);
                    if (!is_sse) {
                        // The caller asked for SSE and the server sent something
                        // else. Silently buffering the body would make the
                        // callback look like it produced no events; report it.
                        return Error{ErrorCode::SseInvalidContentType, ErrorPhase::Receive,
                                     string("response is not text/event-stream")};
                    }
                    {
                        struct SseBridge : SseParser::Callbacks {
                            std::function<VoidResult(const SseEvent&)> user_cb;
                            std::optional<Error>* err_slot;
                            VoidResult on_event(const SseEvent& e) override {
                                try { return user_cb(e); }
                                catch (...) {
                                    auto err = Error{ErrorCode::Unknown, ErrorPhase::Receive,
                                                     string("SSE callback threw an exception")};
                                    if (err_slot) *err_slot = err;
                                    return err;
                                }
                            }
                            void on_comment(string_view) override {}
                        };
                        auto bridge = std::make_shared<SseBridge>();
                        bridge->user_cb = *sse_cb;
                        bridge->err_slot = &sse_error_;
                        sse_parser_ = std::make_unique<SseParser>(
                            *bridge, state_->request.sse_limits());
                        sse_bridge_ = bridge;
                        return VoidResult{};
                    }
                }
#endif
                if (auto& ms = state_->request.multipart_sink()) {
                    head_ = std::move(rh);
                    // The parser needs the boundary, which may live in the
                    // response Content-Type. Resolving it here means the ordinary
                    // case needs no extra code from the caller.
                    MultipartResponseOptions mopt = state_->request.multipart_options();
                    string boundary = mopt.boundary;
                    if (boundary.empty()) {
                        if (!head_->content_type) {
                            return Error{ErrorCode::MultipartMediaTypeInvalid,
                                         ErrorPhase::Receive,
                                         string("multipart response has no Content-Type")};
                        }
                        std::vector<string> subtypes;
                        if (!mopt.basic_parse_unvalidated) {
                            subtypes.push_back(string("mixed"));
                            subtypes.push_back(string("related"));
                            subtypes.push_back(string("byteranges"));
                            subtypes.push_back(string("x-mixed-replace"));
                        }
                        auto parsed = parse_multipart_boundary(
                            to_view(*head_->content_type), subtypes);
                        if (!parsed) { return parsed.error(); }
                        boundary = std::move(parsed.value());
                    }
                    mopt.limits.allow_continuous_stream = mopt.allow_continuous_stream;

                    multipart_sink_ = ms;
                    multipart_bridge_ = std::make_shared<MultipartBridge>(ms);
                    multipart_parser_ = std::make_unique<MultipartResponseParser>(
                        *multipart_bridge_, to_view(boundary), mopt.limits);

                    // Backpressure, same shape as the BodySink path below:
                    // resume() comes from the caller's thread, so it posts back
                    // onto the executor before touching the stream.
                    multipart_flow_ = state_->request.multipart_flow();
                    if (multipart_flow_) {
                        multipart_paused_ = multipart_flow_->is_paused();
                        std::weak_ptr<Exchange> weak = shared_from_this();
                        auto exec = state_->executor;
                        multipart_flow_->set_wake([weak, exec]() {
                            if (!exec) return;
                            exec->post([weak]() {
                                auto self = weak.lock();
                                if (!self) return;
                                // complete_ may already be true: the HTTP message
                                // can finish while the sink is parked, and the
                                // deferred terminal is exactly what this wake-up
                                // exists to deliver.
                                if (!self->multipart_paused_ && !self->deferred_complete_) return;
                                if (!self->multipart_paused_) return;
                                self->multipart_paused_ = false;
                                if (self->multipart_bridge_) self->multipart_bridge_->clear_paused();
                                // The multipart parser still holds the block it
                                // paused on (paused_skip_ is only cleared by the
                                // next feed). Kick it with an empty feed first:
                                // feed_eof() against a buffer that still has real
                                // payload would report a spurious truncation.
                                if (self->multipart_parser_) {
                                    auto rr = self->multipart_parser_->feed(nullptr, 0);
                                    if (!rr) { self->fail(rr.error()); return; }
                                    if (self->multipart_bridge_->threw()) {
                                        auto e = self->multipart_bridge_->throw_error();
                                        self->multipart_bridge_->clear_threw();
                                        self->fail(e);
                                        return;
                                    }
                                    if (self->multipart_bridge_->paused()) {
                                        // Paused again on the replayed block.
                                        self->multipart_paused_ = true;
                                        self->multipart_flow_->pause();
                                        return;
                                    }
                                }
                                if (self->deferred_complete_) {
                                    self->deferred_complete_ = false;
                                    auto fr = self->finish_complete_side();
                                    if (!fr) self->fail(fr.error());
                                } else {
                                    self->read_more();
                                }
                            });
                        });
                    }
                } else if (auto& bs = state_->request.body_sink()) {
                    body_sink_ = bs;
                    body_sink_complete_ = state_->request.body_sink_complete();
                    // The caller still needs the status line, headers and framing
                    // facts; without this the streamed path returned a default
                    // Response and every one of those vanished.
                    head_ = std::move(rh);

                    // Backpressure plumbing. resume() comes from the caller's
                    // thread, so it posts back onto the executor before touching
                    // the stream.
                    sink_flow_ = state_->request.body_sink_flow();
                    if (sink_flow_) {
                        sink_paused_ = sink_flow_->is_paused() ? true : false;
                        std::weak_ptr<Exchange> weak = shared_from_this();
                        auto exec = state_->executor;
                        sink_flow_->set_wake([weak, exec]() {
                            if (!exec) return;
                            exec->post([weak]() {
                                auto self = weak.lock();
                                if (!self || self->complete_) return;
                                if (self->sink_paused_) {
                                    self->sink_paused_ = false;
                                    self->read_more();
                                }
                            });
                        });
                    }
                } else {
                    buffer_sink_ = std::make_unique<BufferSink>(std::move(rh),
                                                         state_->options.max_response_body);
                }
                // Build the content-decoding chain from the header, in decode
                // order. A response that carries Accept-Encoding-negotiated
                // compression is decoded here so the sink and the buffered body
                // both see plain bytes; the header itself is kept verbatim.
                if (state_->request.decode_response_body()) {
                    if (auto ce = head.headers.get("content-encoding")) {
                        auto encodings = parse_content_encoding_header(*ce);
                        if (!encodings.empty()) {
                            std::optional<Error> chain_err;
                            std::weak_ptr<Exchange> weak_self = shared_from_this();
                            decoder_ = make_content_decoder_chain(
                                encodings,
                                [weak_self](const uint8_t* d, size_t n) -> bool {
                                    auto self = weak_self.lock();
                                    if (!self) return false;
                                    return self->deliver_decoded(d, n);
                                },
                                state_->options.decoder_limits,
                                &chain_err);
                            if (chain_err) { return *chain_err; }
                        }
                    }
                }

                // Framing fact needed later to decide whether this connection may
                // be reused: Connection: close (or HTTP/1.0 without keep-alive)
                // means the server will not carry a second exchange on it.
                head_connection_close_ = head.connection_close;
                return VoidResult{};

            }

            VoidResult on_body_data(const uint8_t* data, size_t size) override {
                // Wire bytes, before any content decoding. Response::
                // wire_body_length() reports this so a caller cannot mistake a
                // compressed length for the decoded one.
                wire_body_bytes_ += size;

                if (decoder_) {
                    // Encoded body: the decoder cascade re-enters through
                    // deliver_decoded(), which is where delivery actually
                    // happens. Nothing below runs for this chunk.
                    auto r = decoder_->feed(data, size);
                    if (!r) return r;
                    if (decoder_error_) {
                        // A downstream sink refused the decoded bytes; the
                        // decoder can only report that through its callback, so
                        // the real error was stashed there.
                        auto e = std::move(*decoder_error_);
                        decoder_error_.reset();
                        return e;
                    }
                    return VoidResult{};
                }
                return deliver_decoded_checked(data, size);
            }

            // Delivers plain (post-decoding) body bytes to whichever consumer is
            // configured. Also the target of the decoder cascade.
            bool deliver_decoded(const uint8_t* data, size_t size) {
                auto r = deliver_decoded_checked(data, size);
                if (!r) {
                    // The decoder callback cannot return an Error, so the
                    // failure is stashed and re-raised by the enclosing feed().
                    decoder_error_ = r.error();
                    return false;
                }
                return true;
            }

            VoidResult deliver_decoded_checked(const uint8_t* data, size_t size) {
                // multipart parsing sits at the END of the pipeline: HTTP framing
                // -> content decoding -> here. Fed after decoding, so a gzipped
                // multipart response is parsed identically to a plain one.
                if (multipart_parser_) {
                    // Data reaching the parser will reach the caller's sink as
                    // parts, so "delivered" becomes true as soon as a part has
                    // bytes -- the same rule that stops a retry re-delivering.
                    auto r = multipart_parser_->feed(data, size);
                    if (!r) return r;
                    if (multipart_bridge_->threw()) {
                        auto e = multipart_bridge_->throw_error();
                        multipart_bridge_->clear_threw();
                        return e;
                    }
                    if (multipart_bridge_->delivered()) state_->body_delivered = true;
                    if (multipart_bridge_->paused()) {
                        // The sink asked to pause. With a flow attached the read
                        // loop stops here and only restarts on resume(); without
                        // one there is no way to signal a resume, so the
                        // historical "keep going" behaviour is the only
                        // non-hanging option.
                        if (multipart_flow_) {
                            multipart_paused_ = true;
                            multipart_flow_->pause();
                        }
                    }
                    return VoidResult{};
                }

                // S6.1-01: SSE
#if MEGOHTTP_HAS_SSE
                if (sse_parser_) {
                    auto r = sse_parser_->feed(data, size);
                    if (!r) return r;
                    if (sse_error_) {
                        auto e = std::move(*sse_error_);
                        sse_error_.reset();
                        return e;
                    }
                    return VoidResult{};
                }
#endif

                // "Delivered" means the CALLER has bytes. In buffered mode the
                // body accumulates internally and the caller sees nothing until
                // finish(), so a retry would not re-deliver anything -- that is
                // what makes retrying a 503 with a body safe. In streaming mode
                // the sink is invoked per chunk, so delivery is immediate.
                if (size > 0 && body_sink_) state_->body_delivered = true;
                if (buffer_sink_) {
                    if (!buffer_sink_->append(data, size)) {
                        return Error{ErrorCode::HttpBodyTooLarge, ErrorPhase::Receive,
                                     string("response body exceeded max_response_body")};
                    }
                    return VoidResult{};
                }
                // S3.2-02: Streaming mode
                if (body_sink_) {
                    auto sv = string_view(reinterpret_cast<const char*>(data), size);
                    // A throwing sink must not unwind through the parser/loop,
                    // and it must not be mistaken for "pause" either: pausing
                    // quietly would let the request continue and report success
                    // after the caller's callback had already blown up. Turn it
                    // into a real terminal error instead.
                    bool keep_going = true;
                    try {
                        keep_going = (*body_sink_)(sv);
                    } catch (...) {
                        return Error{ErrorCode::Unknown, ErrorPhase::Receive,
                                     string("response body sink threw an exception")};
                    }
                    if (!keep_going) {
                        // The sink asked to pause. With a flow attached the read
                        // loop stops here and only restarts on resume(); without
                        // one there is no way to signal a resume, so the
                        // historical "keep going" behaviour is the only
                        // non-hanging option.
                        if (sink_flow_) {
                            sink_paused_ = true;
                            // The flow's own flag must agree, otherwise resume()
                            // sees "was not paused" and never fires the wake-up.
                            sink_flow_->pause();
                        }
                    }
                }
                return VoidResult{};
            }

            // Told to the parser after every body delivery: when the sink has
            // paused, feed() must stop here instead of walking on to further
            // segments in the same buffer. sink_paused_ alone only gated the
            // NEXT read, so a single feed() carrying several body segments kept
            // calling a sink that had already asked to wait.
            // Told to the parser after every body delivery: when the sink has
            // paused, feed() must stop here instead of walking on to further
            // segments in the same buffer. sink_paused_ alone only gated the
            // NEXT read, so a single feed() carrying several body segments kept
            // calling a sink that had already asked to wait.
            //
            // A paused MULTIPART stream is deliberately NOT included. The
            // multipart parser keeps its own buffer and reports its own
            // progress, so rolling the HTTP parser back as well would hand the
            // same bytes to the multipart parser twice. Its pause only gates the
            // socket read (read_more / feed_and_continue).
            bool pause_requested() const override { return sink_paused_; }

            VoidResult on_trailers(const Headers& tr) override {
                if (buffer_sink_) {
                    buffer_sink_->set_trailers(tr);
                } else if (head_) {
                    // Streaming mode: keep them on the saved head so the caller
                    // sees the same ResponseHead a buffered request delivers.
                    // Dropping them silently made trailer delivery depend on
                    // which body mode the caller happened to pick.
                    head_->trailers = tr;
                }
                return VoidResult{};
            }

            VoidResult on_complete() override {
                disarm_recv_timer();

                // The decoder may still hold output (a trailing block, or a
                // truncated stream it only notices now). Flush before reporting
                // completion so a truncated body fails instead of looking short
                // but successful.
                if (decoder_) {
                    auto fr = decoder_->flush();
                    if (!fr) return fr;
                    if (decoder_error_) {
                        auto e = std::move(*decoder_error_);
                        decoder_error_.reset();
                        return e;
                    }
                }

                // A paused multipart stream means the caller has not consumed the
                // last block yet. The HTTP message is complete, but reporting the
                // terminal now would hand the caller a "success" while its own
                // callback is still parked mid-part.
                //
                // This check comes BEFORE the completeness check below, and the
                // order matters: feed_eof() on a parser that is still parked
                // mid-block reports a truncation that does not exist.
                //
                // NOTE: `complete_` must NOT be set here. feed_and_continue()
                // uses it to decide whether to save the unconsumed tail into
                // pending_; setting it early dropped exactly the bytes this
                // pause produced. The deferred path is guarded by
                // deferred_complete_ instead.
                if (multipart_paused_) {
                    deferred_complete_ = true;
                    return VoidResult{};
                }

                return finish_complete_side();
            }

            // Everything on_complete does once the pause question is settled.
            // Split out so a deferred completion can be replayed from the
            // resume path without re-running the decoder flush.
            //
            // Sets complete_ itself: the deferred caller reaches here directly,
            // and without this the Exchange kept reading a message that was
            // already over (the request then hung until the Client was
            // destroyed and answered "client is shutting down").
            VoidResult finish_complete_side() {
                complete_ = true;

                // multipart completeness is INDEPENDENT of HTTP framing
                // completeness. The HTTP message can end while the multipart
                // message never saw its closing boundary (close-delimited framing
                // that stops after a part, or a body truncated at a matching
                // Content-Length). That is a failure, and the connection must not
                // be pooled: the caller would believe it has a complete message.
#if MEGOHTTP_HAS_SSE
                if (sse_parser_) {
                    auto eof = sse_parser_->feed_eof();
                    if (!eof) return eof;
                }
#endif
                if (multipart_parser_ && !multipart_bridge_->multipart_complete) {
                    auto eof = multipart_parser_->feed_eof();
                    if (!eof) return eof;
                }

                if (redirect_pending_) {
                    // The 3xx was consumed; the next hop is the Client's job.
                    // Report through the state so the connection is returned to
                    // the pool the same way a normal completion would be.
                    if (state_->on_redirect) {
                        state_->on_redirect(redirect_status_, std::move(redirect_location_));
                    }
                    return VoidResult{};
                }

                // The response framing reached its end. Whether the connection may
                // be reused is a separate question: the server must not have asked
                // to close, and the message must not have been delimited by close.
                //
                // A multipart message that did not complete already failed in
                // on_complete() above, and every failure goes through fail(), which
                // skips this block entirely. An extra `multipart_ok &&` guard was
                // written and then removed -- it was unreachable, and a guard that
                // cannot run is not a defence.
                if (state_->pooled_stream) {
                    const bool framed_fully = parser_->leftover_offset() == 0;
                    state_->pooled_clean = framed_fully && !head_connection_close_;
                }

                // A retryable STATUS is a completed response, so it arrives here
                // rather than through fail(). The body of a 503 was buffered
                // internally, never handed to the caller, so retrying does not
                // re-deliver anything. Consult the policy before reporting
                // success: a caller who asked for retries does not want a 503
                // handed back while attempts remain.
                if (retry_detail::is_retryable_status(state_->last_status) &&
                    state_->options.retry.retry_on_status &&
                    !state_->body_delivered &&
                    state_->on_retry &&
                    state_->on_retry(Error{ErrorCode::HttpInvalidResponse,
                                           ErrorPhase::Receive,
                                           string("retryable server status")})) {
                    return VoidResult{};
                }

                if (buffer_sink_) {
                    auto response = buffer_sink_->finish();
                    apply_encoding_facts(response);
                    state_->finish(std::move(response));
                } else if (multipart_sink_) {
                    // Both halves are settled: the HTTP message completed and the
                    // multipart message saw its closing boundary (checked above).
                    // Only now is the caller told the whole thing succeeded -- a
                    // part ending says nothing about this.
                    notify_multipart_complete();
                    ResponseHead rh = head_ ? std::move(*head_) : ResponseHead{};
                    Response out(std::move(rh), {});
                    out.set_body_streamed();
                    apply_encoding_facts(out);
                    state_->finish(std::move(out));
                } else if (body_sink_complete_) {
                    // S3.2-02: Streaming mode complete. The caller gets the head
                    // it was promised; the body went to its sink, so body_bytes()
                    // stays empty and body_is_buffered() is false.
                    //
                    // A throwing completion callback must not unwind through the
                    // parser/event loop. The body callback already has the same
                    // protection; this one is the terminal notification, so a throw
                    // here would skip the request's own finish() and strand the
                    // caller. Swallow it and still deliver the response.
                    auto complete = std::move(*body_sink_complete_);
                    body_sink_complete_.reset();
                    try {
                        if (complete) complete(VoidResult{});
                    } catch (...) {
                        // Nothing useful to report: the request itself succeeded.
                    }
                    ResponseHead rh = head_ ? std::move(*head_) : ResponseHead{};
                    Response out(std::move(rh), {});
                    out.set_body_streamed();
                    apply_encoding_facts(out);
                    state_->finish(std::move(out));
                } else {
                    ResponseHead rh = head_ ? std::move(*head_) : ResponseHead{};
                    Response out(std::move(rh), {});
                    apply_encoding_facts(out);
                    state_->finish(std::move(out));
                }
                return VoidResult{};
            }

            // Records whether the body arrived encoded and was decoded, plus the
            // wire length. Without this a caller holding a 40-byte gzip body that
            // decompressed to 4 KB has no way to tell which number it is looking
            // at.
            void apply_encoding_facts(Response& r) {
                const bool decoded = decoder_ != nullptr;
                if (decoded) {
                    r.set_encoding_facts(true, wire_body_bytes_);
                } else if (wire_body_bytes_ != 0) {
                    r.set_encoding_facts(false, wire_body_bytes_);
                }
            }
        private:
            // Feeds bytes to the parser and decides what happens next.
            //
            // The bytes live in a view owned by the stream and are gone the
            // moment this function returns, so anything the parser did NOT
            // consume (leftover_offset() > 0) has to be copied here. The two
            // cases that produce leftover are a paused sink and a message that
            // completed with bytes of the next message behind it.
            void feed_and_continue(string_view sv) {
                auto res = parser_->feed(
                    reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
                if (!res) { fail(res.error()); return; }
                if (complete_) return;

                const size_t left = parser_->leftover_offset();
                if (left > 0) {
                    // Keep the unconsumed tail for the resume path. A paused
                    // sink is the reason it is still there.
                    pending_.assign(
                        reinterpret_cast<const uint8_t*>(sv.data()) + (sv.size() - left),
                        reinterpret_cast<const uint8_t*>(sv.data()) + sv.size());
                }
                if (sink_paused_) return;
                if (multipart_paused_) return;
                read_more();
            }

            void read_more() {
                // A paused sink must be resumed first; feeding more bytes now
                // would deliver them before the caller asked for them.
                if (sink_paused_) return;
                if (multipart_paused_) return;
                // Replay the tail the parser could not consume last time before
                // reading anything new. Without this the CRLF and any following
                // chunk that shared the same socket read were dropped.
                if (!pending_.empty()) {
                    // Raw bytes, not text: keep them in a byte buffer owned by the
                    // posted lambda so the view stays valid until it runs.
                    auto tail = std::make_shared<std::vector<uint8_t>>();
                    tail->swap(pending_);
                    auto self = shared_from_this();
                    state_->executor->post([self, tail]() {
                        if (self->state_->finished.load()) return;
                        self->feed_and_continue(string_view(
                            reinterpret_cast<const char*>(tail->data()), tail->size()));
                    });
                    return;
                }
                auto self = shared_from_this();
                auto stream = state_->stream;
                stream->async_read_some(
                    [self](Result<string_view> r) {
                        if (!r) { self->fail(r.error()); return; }

                        const string_view sv = r.value();
                        if (sv.empty()) {
                            // Transport EOF: the parser decides whether that is a
                            // legal end (until-close framing) or a truncation. On
                            // success it has already fired on_complete().
                            //
                            // Distinguish the two truncation shapes, because they
                            // mean different things to a retry policy:
                            //   no head at all  -> the server hung up before
                            //                      answering: a transport failure,
                            //                      safe to retry
                            //   partial message -> the server answered and then
                            //                      broke off: a protocol problem,
                            //                      NOT retryable
                            const bool no_response_yet = !self->state_->response_started;
                            auto eof = self->parser_->feed_eof();
                            if (!eof) {
                                if (no_response_yet) {
                                    self->fail(Error{ErrorCode::ConnectionClosed,
                                                     ErrorPhase::Receive,
                                                     string("connection closed before the response head arrived")});
                                } else {
                                    self->fail(eof.error());
                                }
                            } else if (!self->complete_) {
                                self->fail(Error{ErrorCode::HttpInvalidResponse,
                                                 ErrorPhase::Receive,
                                                 string("stream ended before the message completed")});
                            }
                            return;
                        }

                        self->state_->phase = detail::RequestPhase::Receive;
                        self->feed_and_continue(sv);
                    });
            }

            void fail(const Error& e) {
                disarm_send_timer();
                disarm_recv_timer();
                // A pending BodySource backpressure retry must not fire after the
                // terminal result: it would call user code post-completion.
                if (source_retry_timer_) { source_retry_timer_->cancel(); source_retry_timer_.reset(); }
                // A streaming caller was promised exactly one completion
                // notification. A cancel, timeout, EOF or parse error used to
                // leave it waiting forever, because only the success path called
                // it.
                notify_sink_failed(e);
                // Same promise for a multipart caller: on_error exactly once,
                // and no part callback after it.
                notify_multipart_failed(e);
                state_->fail(e);
            }

            // Delivers the terminal success/failure to the MultipartSink.
            // Exactly one of on_complete or on_error is delivered.
            void notify_multipart_complete() {
                if (!multipart_sink_) return;
                auto sink = std::move(multipart_sink_);
                multipart_parser_.reset();
                multipart_bridge_.reset();
                try {
                    sink->on_complete();
                } catch (...) {
                    // Request is already terminal; nothing else to report.
                }
            }

            void notify_multipart_failed(const Error& e) {
                if (!multipart_sink_) return;
                auto sink = std::move(multipart_sink_);
                multipart_parser_.reset();
                multipart_bridge_.reset();
                try {
                    sink->on_error(e);
                } catch (...) {
                }
            }

            // Delivers the streaming-mode terminal error, at most once.
            //
            // Guarded the same way as the success path: this runs inside a
            // parser/executor handler, and an exception escaping from here would
            // unwind through libuv/Asio. A user callback that throws must not
            // take the event loop down with it -- the request is already
            // terminal, so there is nothing left to report.
            void notify_sink_failed(const Error& e) {
                if (!body_sink_complete_) return;
                auto cb = std::move(*body_sink_complete_);
                body_sink_complete_.reset();
                if (!cb) return;
                try {
                    cb(VoidResult{e});
                } catch (...) {
                }
            }

            std::shared_ptr<RequestState> state_;
            std::unique_ptr<ResponseParser> parser_;
            std::shared_ptr<Timer> send_timer_;
            std::shared_ptr<Timer> recv_timer_;
            // Backpressure retry for a BodySource that is not ready yet. Owned
            // here so the terminal path can cancel it; an uncancelled timer
            // would call the user's BodySource after the request finished.
            std::shared_ptr<Timer> source_retry_timer_;
            // Content-Encoding decoder. Null when the response is not encoded or
            // the caller asked for raw bytes.
            std::unique_ptr<ContentDecoderChain> decoder_;
            // Wire (compressed) byte count for Response::wire_body_length().
            uint64_t wire_body_bytes_{0};
            std::optional<Error> decoder_error_;
            // Buffered mode: accumulates body into a vector.
            std::unique_ptr<BufferSink> buffer_sink_;
            // Streaming mode: user-provided callbacks. Mutually exclusive with buffer_sink_.
            std::optional<Request::BodySink> body_sink_;
            std::optional<Request::BodySinkComplete> body_sink_complete_;
            // Backpressure: set when the caller asked for flow control. Absent
            // means a `false` from the sink cannot be honoured (nothing could
            // ever resume it), so delivery continues as before.
            std::shared_ptr<Request::BodySinkFlow> sink_flow_;
            bool sink_paused_{false};
            // Bytes a paused feed() could not consume. The stream's read view is
            // only valid for that callback, so the tail is copied here and
            // replayed on resume.
            std::vector<uint8_t> pending_;
            // Head kept for the streaming path, where there is no BufferSink to
            // carry it to the caller.
            std::optional<ResponseHead> head_;
            bool complete_{false};
            // S5.7-01: multipart response. Mutually exclusive with buffer_sink_
            // and body_sink_. When set, decoded body bytes go to the parser
            // instead of being buffered or delivered raw.
            // S6.1-01: SSE streaming parser. Mutually exclusive with
            // buffer_sink_, body_sink_ and multipart_sink_.
#if MEGOHTTP_HAS_SSE
            std::unique_ptr<SseParser> sse_parser_;
            std::shared_ptr<SseParser::Callbacks> sse_bridge_;
            // When the SSE parser hits an error the callback is already inside
            // the parser's feed(), so we stash the error and re-raise in the
            // enclosing deliver_decoded_checked.
            std::optional<Error> sse_error_;
#endif

            std::shared_ptr<MultipartSink> multipart_sink_;
            std::unique_ptr<MultipartResponseParser> multipart_parser_;
            std::shared_ptr<MultipartBridge> multipart_bridge_;
            // Cross-thread pause/resume for the multipart stream. When attached,
            // the sink can return false to pause delivery and a later resume()
            // wakes the I/O thread to continue.
            std::shared_ptr<Request::MultipartSinkFlow> multipart_flow_;
            bool multipart_paused_{false};
            // When on_complete fires while multipart_paused_ is true, the
            // terminal notification must wait for resume().
            bool deferred_complete_{false};
            // Expect: 100-continue bookkeeping (S3.1-09).
            bool expect_continue_pending_{false};
            bool body_sent_{false};
            // Connection-reuse facts captured from the final head. Decided once,
            // when the head arrives, so on_complete() does not need to reach back
            // into the parser.
            bool head_connection_close_{false};
            // Set when this exchange turned out to be a redirect that the
            // Client is going to follow. on_complete must then NOT report a
            // success to the caller.
            bool redirect_pending_{false};
            std::optional<string> redirect_location_;
            int redirect_status_{0};
        };

        // A byte stream that serves a fixed prefix first, then delegates.
        //
        // Needed because a proxy handshake reads MORE bytes than it consumes:
        // the CONNECT response head can arrive in the same read as the first
        // bytes of the target's TLS handshake, and a SOCKS5 reply can arrive
        // with the start of the tunnel payload. Dropping those bytes would break
        // the handshake above this layer in a way that looks like a bad server.
        // Wrapping the raw stream keeps that leftover in front of everything
        // stacked on top of it, including TLS.
        class PrefixedStream final : public AsyncByteStream {
        public:
            PrefixedStream(std::shared_ptr<AsyncByteStream> inner, byte_buffer prefix)
                : inner_(std::move(inner)), prefix_(std::move(prefix)) {}

            void start(ReadyCallback on_ready) override {
                // The underlying stream is already connected: re-starting it
                // would re-issue a connect.
                if (on_ready) on_ready(VoidResult{});
            }

            void async_read_some(ReadCallback cb) override {
                if (!prefix_.empty()) {
                    // Move the prefix out and deliver it in one shot. The moved-out
                    // buffer is not used again, so no clear() is needed.
                    byte_buffer held = std::move(prefix_);
                    if (cb) cb(string_view(reinterpret_cast<const char*>(held.data()),
                                           static_cast<string_view::size_type>(held.size())));
                    return;
                }
                inner_->async_read_some(std::move(cb));
            }

            void async_write(const uint8_t* data, size_t size, WriteCallback cb) override {
                inner_->async_write(data, size, std::move(cb));
            }

            void async_close(CloseCallback cb) override { inner_->async_close(std::move(cb)); }
            bool is_open() const noexcept override { return inner_ && inner_->is_open(); }
            string_view tls_protocol() const noexcept override {
                return inner_ ? inner_->tls_protocol() : string_view();
            }

        private:
            std::shared_ptr<AsyncByteStream> inner_;
            byte_buffer prefix_;
        };

        // Builds the request head for a direct (non-proxy) HTTP request.
        // `expect_continue` adds the Expect header; the caller decides whether the
        // request qualifies (it must actually carry a body) and records the same
        // decision so the exchange holds the body accordingly.
        inline Result<string> build_request_head(const Request& req, const Url& url,
                                                 bool expect_continue, bool pooling,
                                                 bool forward_proxy,
                                                 const ProxyConfig& proxy,
                                                 Request::Compression wire_coding,
                                                 size_t wire_body_size) {
            Headers headers = req.headers();

            // Proxy credentials belong to the proxy hop and to nothing else.
            // Two leaks are possible and both are silent:
            //   - `Proxy-Authorization` reaching the TARGET, which hands the
            //     proxy credential to the origin server;
            //   - the target's `Authorization` reaching the PROXY, which is why
            //     the CONNECT builder never reads the request's headers.
            // Stripping here covers the first, because this head is what the
            // target (through a forward proxy) actually receives.
            headers.remove("proxy-authorization");
            headers.remove("proxy-connection");

            // When relaying through a forward proxy, the proxy hop is the one
            // that needs the credentials. They are built from the proxy config
            // alone: the target's Authorization is never consulted, so a target
            // token can never be mistaken for a proxy credential.
            if (forward_proxy && proxy.has_credentials()) {
                string_builder sb;
                detail::sb_append(sb, "Basic ");
                detail::sb_append(sb, to_view(proxy_detail::basic_auth_value(
                                           to_view(proxy.username),
                                           to_view(proxy.password))));
                headers.set("proxy-authorization", to_view(sb.release()));
            }

            if (!headers.contains("host")) {
                headers.set("host", to_view(url.host_port_header()));
            }
            if (!headers.contains("connection")) {
                // Pooling needs a persistent connection; without a pool the
                // historical "close" keeps the pre-phase-5 behaviour identical
                // (a server that sees "close" hands out no second exchange,
                // which is exactly what makes the no-pool path safe).
                headers.set("connection", pooling ? "keep-alive" : "close");
            }
            // Body framing. Three distinct cases, and conflating them is how a
            // request ends up lying about its own shape:
            //
            //   no body            -> neither header
            //   buffered bytes     -> Content-Length: <exact size>
            //   BodySource (stream)-> Transfer-Encoding: chunked, because the
            //                         length is not known before sending. Writing
            //                         "Content-Length: 0" here (which is what
            //                         body_bytes().size() yields for a stream)
            //                         would tell the server the message ends
            //                         immediately and then send bytes anyway.
            //
            // A caller-supplied Content-Length or Transfer-Encoding wins: it is
            // an explicit assertion about the body and is not second-guessed.
            const bool has_te = headers.contains("transfer-encoding");
            const bool has_cl = headers.contains("content-length");
            // The body coding describes the bytes that follow, so it is added
            // only when an encoded body actually exists. `prepare_request_body`
            // leaves wire_coding at None for a missing/empty body.
            if (wire_coding != Request::Compression::None) {
                const char* coding_name =
                    content_encoding_detail::name_of(wire_coding);
                if (coding_name) {
                    headers.set("content-encoding",
                                string_view(coding_name,
                                    std::char_traits<char>::length(coding_name)));
                }
            }
            if (req.has_body() && !has_cl && !has_te) {
                if (req.body_source().has_value()) {
                    headers.set("transfer-encoding", "chunked");
                } else {
                    // Content-Length describes the ENCODED body. Using
                    // body_bytes().size() here would tell the server to read N
                    // bytes and then write M != N, which truncates or hangs.
                    headers.set("content-length",
                                to_view(format("{}", wire_body_size)));
                }
            }
            if (expect_continue && !headers.contains("expect")) {
                headers.set("expect", "100-continue");
            }
            // A forward proxy (plain http:// target, any proxy type that speaks
            // HTTP) needs the absolute form so it knows where to relay. An
            // https:// target always uses origin-form inside the CONNECT tunnel,
            // because by then the proxy is not reading anything (RFC 7230 5.3.2).
            //
            // Both `absolute_form_target()` and `request_target()` return OWNING
            // strings, so each must be held in a local before taking a view.
            // The old code called `to_view(url.request_target())` directly in
            // the ternary's false branch: the temporary string was destroyed at
            // the end of the full expression, leaving `target` dangling, and the
            // request went out with a corrupted target path (defect #1 of the
            // 2026-11-13 code review).
            string target_str;
            if (forward_proxy) {
                target_str = url.absolute_form_target();
            } else {
                target_str = url.request_target();
            }
            const string_view target = to_view(target_str);
            return encode_request_head(req.method(), req.custom_method(),
                                       target, headers);
        }

    } // namespace detail

    // ---------------------------------------------------------------------------
    // Client::Impl
    // ---------------------------------------------------------------------------
    class Client::Impl {
    public:
        explicit Impl(ClientOptions opts) : options(std::move(opts)) {
            // A bad timeout is a programming error; surface it on the first request
            // instead of letting an overflowing deadline fire at a random time.
            auto valid = options.validate();
            if (!valid) options_error = valid.error();

            executor = options.executor;
            owns_executor = (executor == nullptr);
            if (!executor) executor = detail::make_default_executor();

            resolver = options.resolver;
            if (!resolver && executor) {
                resolver = std::make_shared<SystemResolver>(executor);
            }

            // Phase 5: pooling is ON as soon as any limit or the queue is
            // configured. Leaving every option at 0 keeps the historical
            // one-connection-per-request behaviour, so nothing changes for
            // existing callers who never set these fields.
            const auto& po = options.pool;
            const bool pooling_enabled =
                po.max_total_connections != 0 ||
                po.max_connections_per_origin != 0;
            if (pooling_enabled && executor) {
                pool = std::make_shared<ConnectionPool>(executor, po);
            }
        }

        ~Impl() { shutdown(); }

        void shutdown() {
            bool expected = false;
            if (!stopped.compare_exchange_strong(expected, true)) return;

            // Retire every in-flight request so its terminal callback fires.
            std::vector<std::shared_ptr<detail::RequestState>> live;
            {
                std::lock_guard<std::mutex> lk(m_);
                for (auto& w : in_flight_)
                    if (auto sp = w.lock()) live.push_back(std::move(sp));
                // Do NOT clear in_flight_ here.  Every retirement job calls
                // finish() → retired() → maybe_notify_drained(), which scans
                // in_flight_ to see if anything is still alive.  Clearing it
                // prematurely would make a naturally-completing request see an
                // empty list and fire the drained callback BEFORE the shutdown
                // retirements above have actually run (the drained callback is
                // the caller's promise that all request callbacks have fired).
            }

            // Retire on the I/O thread, not on the caller's. finish() runs the
            // user callback, touches the pool and closes the stream; every one of
            // those belongs to the loop thread, and libuv handle operations are
            // not thread safe.
            //
            // Ordering matters: when this Client owns the executor, stopping the
            // loop is itself posted as the LAST retirement job. Stopping it here
            // and now would abandon every retirement queued ahead of it, and a
            // caller would never see the terminal callbacks shutdown() promises.
            if (!live.empty()) {
                std::shared_ptr<Executor> ex = executor;
                if (ex) {
                    // A latch that fires after the LAST retirement has run, so a
                    // shutdown that owns the loop can wait for those callbacks
                    // before tearing the loop down. Without it, stopping the loop
                    // here would abandon every retirement queued ahead of it.
                    auto done = std::make_shared<std::promise<void>>();
                    auto fut = done->get_future();
                    // Count the retirement jobs.  While they are pending the
                    // drained callback must not fire: a queued job still holds
                    // its RequestState alive, so weak_ptr liveness alone cannot
                    // tell "finished" from "not yet run".
                    retiring.store(static_cast<int>(live.size()));
                    for (size_t idx = 0; idx < live.size(); ++idx) {
                        auto st = std::move(live[idx]);
                        // Do NOT use "this is the last element of the vector":
                        // post() is a queue, and the jobs may run in ANY order.
                        // The last index could run first and then stop the
                        // executor while other retirements are still queued, so
                        // those requests would never get their terminal
                        // callback. The counter reaching zero is the only honest
                        // "all retirements have run" signal.
                        ex->post([this, held = std::move(st), done]() mutable {
                            held->finish(Error{ErrorCode::Cancelled, ErrorPhase::None,
                                               string("client is shutting down")});
                            // finish() ran the user callback and the retirement
                            // notice; this job is done, so open the gate. The
                            // strong reference must go before the liveness scan,
                            // otherwise this very job keeps its state alive and
                            // the request never looks retired.
                            held.reset();
                            if (retiring.fetch_sub(1) == 1) {
                                // Truly last: every posted retirement has run.
                                std::lock_guard<std::mutex> lk(m_);
                                in_flight_.clear();
                                done->set_value();
                            }
                            maybe_notify_drained();
                        });
                    }
                    if (owns_executor && !ex->is_in_loop_thread()) {
                        // Bounded: a handler that blocks forever must not turn a
                        // shutdown into a hang.
                        (void)fut.wait_for(std::chrono::seconds(5));
                    }
                } else {
                    for (auto& st : live) {
                        st->finish(Error{ErrorCode::Cancelled, ErrorPhase::None,
                                         string("client is shutting down")});
                    }
                    // No executor to post to: every retirement above already ran
                    // synchronously on this thread.
                    std::lock_guard<std::mutex> lk(m_);
                    in_flight_.clear();
                }
            }

            // Retire pooled state: waiters get a terminal error, idle
            // connections close. In-flight exchanges close their own connection
            // when they finish.
            if (pool) {
                pool->fail_waiters(ErrorCode::Cancelled, "client is shutting down");
                pool->clear_idle();
            }

            if (owns_executor) detail::shutdown_executor(executor);
            maybe_notify_drained();
        }

        void shutdown(std::function<void()> on_drained) {
            bool was_stopped = false;
            {
                std::lock_guard<std::mutex> lk(m_);
                was_stopped = stopped.load();
                if (!drained_cb) drained_cb = std::move(on_drained);
            }
            if (was_stopped) {
                // shutdown() already ran, so nothing below will call
                // maybe_notify_drained() again. Without this the callback just
                // stored stays in drained_cb forever and a caller waiting for it
                // hangs. Everything is drained at this point (that is what stopped
                // means), so the notification can be delivered straight away.
                maybe_notify_drained();
                return;
            }
            shutdown();
        }

        void submit(const Request& req,
                    Client::ResponseCallback on_complete,
                    const CancelHandle& handle,
                    std::shared_ptr<CancelState> cancel_state,
                    const ClientOptions* opt_override = nullptr) {
            auto st = std::make_shared<detail::RequestState>();
            st->self_hold = st;
            st->executor = executor;
            st->resolver = resolver;
            st->cookie_jar = options.cookie_jar;
            st->options = opt_override ? *opt_override : options;
            st->pool = pool;

            // Request body compression (task book 7.3). Preparation happens
            // before the state is registered: a conflict or a missing encoder is
            // a synchronously rejected submission, and a state that was never
            // accepted must not sit in in_flight_ until shutdown. Encoding runs
            // on the SUBMITTING thread on purpose -- doing it on the I/O thread
            // would block every other connection for the duration.
            auto prepared_body = content_encoding_detail::prepare_request_body(req);
            if (!prepared_body) {
                // Break the self-hold installed above: this state was never
                // registered in in_flight_, so nothing else will ever call
                // finish() to release it. Without this reset the cycle
                // (self_hold -> state -> self_hold) leaks the whole state.
                st->self_hold.reset();
                if (on_complete) on_complete(prepared_body.error());
                return;
            }

            // Redirect budget (S5.2). Only counts when the caller opted in;
            // with the policy off the counter stays 0 and nothing follows.
            st->hops_left = st->options.redirects.follow
                                ? st->options.redirects.max_redirects : 0;
            st->request = req;
            st->wire_coding = prepared_body.value().coding;
            st->encoded_body = std::move(prepared_body.value().bytes);
            st->on_complete = std::move(on_complete);

            // Track in-flight so shutdown() can retire this request (S2.6-02/04).
            //
            // The insert and the `stopped` test happen under one lock: checking
            // `stopped` in the caller and inserting here were separate steps, so a
            // shutdown between them left the request registered against a stopped
            // client and it was never retired -- no terminal callback at all.
            bool retired_here = false;
            {
                std::lock_guard<std::mutex> lk(m_);
                if (stopped.load()) {
                    retired_here = true;
                } else {
                    in_flight_.push_back(st);
                }
            }
            if (retired_here) {
                // Deliver the terminal result without enqueueing work on a
                // stopped executor.
                //
                // DOCUMENTED EXCEPTION to "every callback runs on the I/O
                // context": this one runs on the submitting thread. The executor
                // is already stopped, so posting would enqueue work nothing will
                // ever run, and the caller would get no terminal callback at all.
                // A callback on the wrong thread is recoverable; a missing
                // terminal result is not.
                auto cb = std::move(st->on_complete);
                st->finished.store(true);
                st->self_hold.reset();
                if (cb) {
                    cb(Error{ErrorCode::Cancelled, ErrorPhase::None,
                             string("client is shut down")});
                }
                return;
            }
            st->on_retired = [this] { this->maybe_notify_drained(); };

            if (!executor || !resolver) {
                st->self_hold.reset();
                if (st->on_complete) {
                    st->on_complete(Error{ErrorCode::NotImplemented, ErrorPhase::None,
                                          string("no executor available for this backend")});
                }
                return;
            }

            // Total timeout covers the WHOLE logical request (spec 8.2): pool wait,
            // DNS, connect, TLS, send, receive, every redirect hop and every retry
            // backoff. It is created HERE, in submit(), and nowhere else.
            //
            // begin() and on_redirect/on_retry restart the pipeline, so they must
            // NOT arm it again: a per-hop timeout would let a redirect chain or a
            // retry loop outlive the caller's deadline indefinitely. finish()
            // cancels it.
            if (options.total_timeout != Duration::zero()) {
                std::weak_ptr<detail::RequestState> weak = st;
                st->total_timer = executor->schedule_after(options.total_timeout, [weak] {
                    auto s = weak.lock();
                    if (!s) return;
                    s->finish(Error{ErrorCode::TimeoutTotal, ErrorPhase::None,
                                    string("total request timeout")});
                });
            }

            // Cancellation is observed at the executor: the request is retired on
            // the loop thread, never from the cancelling caller's thread.
            std::weak_ptr<detail::RequestState> weak = st;
            cancel_state->on_cancel([this, weak] {
                auto s = weak.lock();
                if (!s) return;
                executor->post([s] {
                    s->finish(Error{ErrorCode::Cancelled, ErrorPhase::None,
                                    string("request cancelled")});
                });
            });

            // Redirect restart. Runs on the loop thread from the exchange, so it
            // can go straight into begin() with the new URL.
            std::weak_ptr<detail::RequestState> rw = st;
            st->on_redirect = [rw](int status, std::optional<string> location) {
                auto s = rw.lock();
                if (!s || s->finished.load()) return;
                if (!location) return;   // nothing to follow; already failed

                // The URL that produced this response is the base for a relative
                // Location.
                const Url* base = nullptr;
                if (s->request.parsed_url()) base = &*s->request.parsed_url();
                if (!base) {
                    s->fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                  string("redirect without a parsed base URL")});
                    return;
                }

                auto next = redirect_detail::resolve_location(*base, to_view(*location));
                if (!next) { s->fail(next.error()); return; }
                Url next_url = std::move(next.value());

                // Refuse a transport downgrade unless the caller allowed it. This
                // is checked against the URL we are leaving, not the one we are
                // going to, because that is where the security loss happens.
                if (redirect_detail::is_downgrade(*base, next_url) &&
                    !s->options.redirects.allow_https_to_http) {
                    s->fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                  string("refusing to follow a redirect from https to http")});
                    return;
                }

                // Loop detection: a URL we already requested in this same logical
                // request means the server is cycling regardless of budget.
                const string canonical = next_url.origin() + next_url.request_target();
                for (const auto& seen : s->visited) {
                    if (detail::ascii_iequals(to_view(seen), to_view(canonical))) {
                        s->fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                      string("redirect loop detected")});
                        return;
                    }
                }
                s->visited.push_back(canonical);

                if (s->hops_left == 0) {
                    s->fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                  string("too many redirects")});
                    return;
                }
                --s->hops_left;

                // Method and body policy (RFC 7231 + what servers actually expect).
                Request next_req = s->request;
                if (redirect_detail::becomes_get(status, s->request.method())) {
                    next_req.set_method(Method::Get);
                    next_req.clear_body();
                    // The redirect dropped the body, so the encoded copy and
                    // its coding go with it. Leaving either behind would put a
                    // Content-Encoding on a request that carries no body.
                    next_req.set_compress_body(Request::Compression::None);
                    s->wire_coding = Request::Compression::None;
                    s->encoded_body.clear();
                } else if (redirect_detail::preserves_body(status)) {
                    // 307/308 keep the body, which requires it to be replayable:
                    // a BodySource that has already been consumed cannot be re-sent,
                    // and silently sending an empty body would look like success.
                    if (s->request.has_body() && !s->request.is_body_replayable()) {
                        s->fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                      string("cannot follow a 307/308 redirect: the request body is not replayable")});
                        return;
                    }
                }

                // Cross-origin hops must not carry credentials.
                if (!redirect_detail::same_origin(*base, next_url)) {
                    // Headers iterates as a flat sequence of (name, value) pairs,
                    // so filtering is a rebuild rather than a names() walk.
                    Headers kept;
                    for (auto it = next_req.headers().begin();
                         it != next_req.headers().end(); ++it) {
                        if (!redirect_detail::is_origin_bound_header(to_view(it->first))) {
                            kept.add(to_view(it->first), to_view(it->second));
                        }
                    }
                    next_req.headers() = std::move(kept);
                }

                next_req.set_url(to_view(canonical));
                s->request = std::move(next_req);
                s->pooled_clean = false;   // the 3xx body may not have been drained
                s->stream.reset();
                s->tls_stream.reset();
                // A new hop is a new connection stage. The previous one was
                // already disarmed when its exchange started, so re-arm it here
                // or the next connect would be unbounded (S5.8-01).
                //
                // NOTE: total_timeout is deliberately NOT re-armed -- it spans
                // the whole logical request, redirects included (S5.2-04).
                s->connect_stage_done = false;

                // Restart the pipeline for the new URL.
                begin(s);
            };

            // Retry execution. Same shape as on_redirect: the policy decides,
            // this restarts the pipeline, and the request state (not the Client)
            // owns the in-flight bookkeeping.
            st->on_retry = [rw](Error e) -> bool {
                auto s = rw.lock();
                if (!s || s->finished.load()) return false;

                RetryContext ctx;
                ctx.method = s->request.method();
                ctx.body_replayable = s->request.is_body_replayable();
                ctx.response_started = s->response_started;
                ctx.body_delivered = s->body_delivered;
                ctx.status = s->last_status;
                ctx.retry_after = s->last_retry_after;

                const auto delay = retry_detail::next_delay(
                    s->options.retry, ctx, e.code(), s->attempts_done,
                    s->options.retry_rng ? s->options.retry_rng
                                         : std::function<uint32_t()>{});
                if (!delay) return false;   // policy declined: the caller finishes

                ++s->attempts_done;
                s->response_started = false;
                s->body_delivered = false;
                s->last_status = 0;
                s->last_retry_after.reset();
                s->pooled_clean = false;
                s->stream.reset();
                s->tls_stream.reset();
                s->pooled_stream.reset();
                // Same reasoning as the redirect path: a retry reconnects, so it
                // needs its own connection stage. total_timeout still spans the
                // whole logical request (S5.3-02), which is what the cross-retry
                // deadline test asserts.
                s->connect_stage_done = false;

                // Wait out the backoff on the loop thread. The timer lives on the
                // state so finish() can cancel it; without that a request retired
                // during the wait would restart itself after the callback fired.
                std::weak_ptr<detail::RequestState> tw = s;
                s->retry_timer = s->executor->schedule_after(*delay, [tw] {
                    auto st2 = tw.lock();
                    if (!st2 || st2->finished.load()) return;
                    st2->retry_timer.reset();
                    begin(st2);
                });
                return true;
            };

            executor->post([st] { begin(st); });
            (void)handle;
        }

    private:
        // Static: it runs from a posted handler, so it must not depend on `this`
        // staying alive (a Client may be destroyed while a request is in flight).
        static void begin(const std::shared_ptr<detail::RequestState>& st) {
            if (st->finished.load()) return;

            st->phase = detail::RequestPhase::UrlParse;
            auto parsed = parse_url(st->request.url());
            if (!parsed) { st->finish(parsed.error()); return; }
            Url url = std::move(parsed.value());

            if (url.scheme != Scheme::Http && url.scheme != Scheme::Https) {
                st->finish(Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                                 string("only http:// and https:// are supported")});
                return;
            }
#if MGHTTP_TLS_NONE
            if (url.is_secure()) {
                // Built without a TLS backend: report it rather than silently
                // downgrading to plaintext (task book 3.7).
                st->finish(Error{ErrorCode::TlsNotEnabled, ErrorPhase::None,
                                 string("https:// requires a TLS backend")});
                return;
            }
#endif
            st->request.set_parsed_url(url);
            st->current_url = url;

            // Pool key: every fact that affects the security boundary. Proxy
            // and TLS token fields stay empty until those layers land; adding them
            // later to an already-keyed pool would silently reuse across identities.
            if (st->pool) {
                st->pool_key.scheme = url.is_secure() ? string("https") : string("http");
                st->pool_key.host = url.host;
                st->pool_key.port = url.port;
                st->pool_key.tls_verify_peer = st->options.tls.verify_peer;
                if (url.is_secure()) {
                    // Distinguish trust configurations: two TLS sessions with
                    // different CA material are not interchangeable.
                    string_builder tok;
                    detail::sb_append(tok, st->options.tls.ca_file);
                    detail::sb_append(tok, "|");
                    detail::sb_append(tok, st->options.tls.ca_path);
                    detail::sb_append(tok, "|");
                    detail::sb_append(tok, st->options.tls.cert_file);
                    st->pool_key.tls_ca_token = tok.release();
                }
            }
            // Proxy routing (S5.4). Resolved once per hop, before the head is
            // built, because the target form (absolute vs origin) and the set of
            // headers depend on the decision.
            {
                auto decision = proxy_detail::select_proxy(
                    st->options.proxy,
                    [](const char* name) { return std::getenv(name); },
                    to_view(url.host), url.port, url.is_secure());
                if (!decision) { st->finish(decision.error()); return; }
                st->proxy = decision.value().config;

                // Pool key: the PROXY is part of the security boundary. Two
                // connections to the same origin through different proxies are
                // not interchangeable -- neither is one through a proxy with
                // different credentials, nor an HTTPS proxy with different trust
                // material. Leaving these empty keyed every proxied request as if
                // it were direct, so the pool could hand a tunnel built for one
                // proxy (or one target) to a request heading somewhere else.
                //
                // Filled here rather than at the top of begin() because the
                // proxy decision is what makes them knowable.
                if (st->pool) {
                    switch (st->proxy.type) {
                    case ProxyType::Http:   st->pool_key.proxy_type = string("http"); break;
                    case ProxyType::Https:  st->pool_key.proxy_type = string("https"); break;
                    case ProxyType::Socks5: st->pool_key.proxy_type = string("socks5"); break;
                    case ProxyType::None:   st->pool_key.proxy_type = string{}; break;
                    }
                    if (st->proxy.is_set()) {
                        st->pool_key.proxy_host = st->proxy.host;
                        st->pool_key.proxy_port = st->proxy.port;
                        // Credentials as a DIGEST, never the password itself: the
                        // key is compared, hashed and (in tests) printed. Two
                        // different passwords must still produce two different
                        // tokens, and two identical ones must match -- a plain
                        // hash gives both properties without keeping the secret
                        // around in a long-lived object.
                        if (st->proxy.has_credentials()) {
                            std::size_t h = 1469598103934665603ull;
                            auto mix = [&h](string_view v) {
                                for (size_t i = 0; i < v.size(); ++i) {
                                    h ^= static_cast<unsigned char>(v.data()[i]);
                                    h *= 1099511628211ull;
                                }
                            };
                            mix(to_view(st->proxy.username));
                            mix(string_view("\x1f", 1));   // separator, not in a credential
                            mix(to_view(st->proxy.password));
                            st->pool_key.proxy_auth_token = format("{}", h);
                        } else {
                            st->pool_key.proxy_auth_token = string{};
                        }
                    } else {
                        st->pool_key.proxy_host = string{};
                        st->pool_key.proxy_port = 0;
                        st->pool_key.proxy_auth_token = string{};
                    }
                }

#if MGHTTP_TLS_NONE
                if (proxy_detail::uses_proxy_tls(st->proxy.type)) {
                    // Built without a TLS backend: an HTTPS proxy cannot be
                    // used, and silently falling back to a cleartext proxy would
                    // be a downgrade the caller never agreed to.
                    st->finish(Error{ErrorCode::TlsNotEnabled, ErrorPhase::ProxyTls,
                                     string("an https:// proxy requires a TLS backend")});
                    return;
                }
#endif
                if (st->proxy.type == ProxyType::Https) {
                    st->proxy_tls_config = st->options.proxy.tls;
                    // The proxy's own identity drives SNI and the certificate
                    // check; the target's name must never be used here, which
                    // would validate the proxy as if it were the origin.
                    //
                    // An explicitly configured hostname wins: the proxy is very
                    // often reached by address while its certificate names a
                    // host, exactly like an origin behind a load balancer.
                    if (st->proxy_tls_config.hostname.empty()) {
                        st->proxy_tls_config.hostname = st->proxy.host;
                    }

                    // The PROXY layer's trust material is a separate isolation
                    // dimension from the target's (S5.1-05 / task book 9.3). Two
                    // tunnels through the same proxy endpoint but validated
                    // against different CAs, or with different client certs, must
                    // never share a connection: the second would inherit an
                    // identity check it never agreed to.
                    if (st->pool) {
                        string_builder ptok;
                        detail::sb_append(ptok, st->proxy_tls_config.ca_file);
                        detail::sb_append(ptok, "|");
                        detail::sb_append(ptok, st->proxy_tls_config.ca_path);
                        detail::sb_append(ptok, "|");
                        detail::sb_append(ptok, st->proxy_tls_config.cert_file);
                        detail::sb_append(ptok, "|");
                        detail::sb_append(ptok, st->proxy_tls_config.key_file);
                        detail::sb_append(ptok, "|");
                        detail::sb_append(ptok, st->proxy_tls_config.verify_peer ? "1" : "0");
                        detail::sb_append(ptok, "|");
                        detail::sb_append(ptok, st->proxy_tls_config.verify_host ? "1" : "0");
                        st->pool_key.proxy_tls_token = ptok.release();
                    }
                }
            }

            st->phase = detail::RequestPhase::BuildHead;

            // Content coding negotiation (S5.6). Accept-Encoding advertises
            // exactly the codings this build can decode -- promising one we
            // cannot decode would turn every response into a decoding error.
            // A caller who set the header themselves keeps it: they may have a
            // reason to ask for a subset.
            if (st->request.decode_response_body() &&
                !st->request.headers().contains("accept-encoding")) {
                const bool gz = MEGOHTTP_HAS_GZIP != 0;
                const bool br = MEGOHTTP_HAS_BROTLI != 0;
                const char* value = nullptr;
                if (gz && br)      value = "gzip, br";
                else if (gz)       value = "gzip";
                else if (br)       value = "br";
                if (value) {
                    st->request.headers().set(
                        "accept-encoding",
                        string_view(value, std::char_traits<char>::length(value)));
                }
            }

            // Cookies (S5.5). Applied here rather than inside build_request_head
            // because the jar needs the resolved Url and the Request is the thing
            // that carries the headers. The jar decides what to send:
            // domain / path / Secure, all judged against this URL.
            //
            // A jar-configured client rebuilds the header from scratch on every
            // hop, including a same-origin redirect: the path changed, and a
            // cookie scoped to the old path must not follow. A caller-supplied
            // Cookie header (no jar) is left alone -- it was set deliberately.
            if (st->cookie_jar) {
                st->request.headers().remove("cookie");
                const string value = st->cookie_jar->cookie_header(url);
                if (!value.empty()) {
                    st->request.headers().set("cookie", to_view(value));
                }
            }
            // Expect: 100-continue only makes sense when there is a body to hold
            // back. A BodySource counts: its bytes are not in body_bytes(), so
            // testing that alone made Expect never fire for a streamed upload.
            const bool body_carries_bytes =
                st->request.body_source().has_value() ||
                !st->wire_body().empty();
            st->expect_continue_sent = st->options.expect_continue
                                    && st->request.has_body()
                                    && body_carries_bytes;
            // Absolute-form is used only when an HTTP-speaking proxy relays a
            // cleartext target. A secure target goes through CONNECT and then
            // uses origin-form inside the tunnel.
            const bool forward_proxy = proxy_detail::is_forward_proxy(st->proxy.type) &&
                                       !url.is_secure();
            auto head = detail::build_request_head(st->request, url,
                                                   st->expect_continue_sent,
                                                   st->pool != nullptr, forward_proxy,
                                                   st->proxy,
                                                   st->wire_coding,
                                                   st->wire_body().size());
            if (!head) { st->finish(head.error()); return; }
            // Whether the body must be chunk-framed. Same three-case decision the
            // head builder made; recorded on the state so the sender wraps each
            // piece identically. A caller-supplied header was honoured there, so
            // it is honoured here too.
            st->body_chunked = st->request.has_body() &&
                               st->request.body_source().has_value() &&
                               !st->request.headers().contains("content-length") &&
                               !st->request.headers().contains("transfer-encoding");

            std::weak_ptr<detail::RequestState> weak = st;
            const string host = url.host;
            const uint16_t port = url.port;

            // Phase 5: when a pool is configured, try to take a reusable
            // connection first. Pool::acquire always calls back on this thread:
            //   - Found      -> stream already connected, skip DNS and connect
            //   - NotFound   -> the pool reserved a slot; open a new connection
            //   - queued     -> the callback fires later (bounded by max_waiting)
            //   - error      -> surface it (pool exhausted / shutting down)
            if (st->pool) {
                st->pool->acquire(st->pool_key,
                    [weak, head = std::move(head.value())](Result<PooledConnection> conn) mutable {
                        auto s = weak.lock();
                        if (!s || s->finished.load()) {
                            // Request retired while we waited: hand the connection
                            // straight back so it is not leaked.
                            if (conn && conn.value().stream && s && s->pool) {
                                s->pool->put(std::move(conn.value()), true);
                            }
                            return;
                        }
                        if (!conn) {
                            if (conn.error().code() == ErrorCode::NotFound) {
                                // Pool has capacity: open a new connection.
                                start_connect(s, std::move(head));
                            } else {
                                s->fail(conn.error());
                            }
                            return;
                        }
                        // Reused a pooled connection: it is already connected.
                        //
                        // No connection stage to bound here. The stream came out
                        // of the pool already established, so there is no DNS,
                        // TCP, proxy or TLS work left -- arming connect_timeout
                        // would kill a perfectly healthy request on a slow
                        // exchange (S5.8-01).
                        s->connect_stage_done = true;
                        s->stream = conn.value().stream;
                        s->pooled_stream = conn.value().stream;
                        s->pooled_clean = false;  // not clean until framing completes
                        s->phase = detail::RequestPhase::Connect;
                        begin_proxy_stage(s, std::move(head));
                    });
                return;
            }

            start_connect(st, std::move(head.value()));
        }

        // -------------------------------------------------------------------
        // Connection-stage deadline (S5.8-01)
        //
        // DNS + TCP + proxy TLS + CONNECT + SOCKS5 + target TLS share ONE
        // deadline, armed when the connection stage begins and disarmed when the
        // exchange takes over. Without it every proxy sub-stage was unbounded:
        // connect_timeout only reached connect_race, and a proxy that accepted
        // TCP and then stalled mid-TLS would hold the request forever whenever
        // total_timeout was left at its default of 0.
        //
        // The error names the phase that was actually in flight, so "the proxy
        // handshake hung" stays distinguishable from "the target handshake hung".
        // -------------------------------------------------------------------
        static void arm_connect_stage(const std::shared_ptr<detail::RequestState>& st) {
            if (st->connect_stage_done) return;   // already over; never re-arm
            const Duration d = st->options.connect_timeout;
            if (d == Duration::zero()) return;
            st->connect_stage_deadline = Clock::now() + d;
            std::weak_ptr<detail::RequestState> tw = st;
            st->connect_stage_timer = st->executor->schedule_after(d, [tw] {
                auto s = tw.lock();
                if (!s || s->finished.load()) return;
                s->connect_stage_timer.reset();
                const ErrorPhase p = connect_stage_phase(s->phase);
                s->finish(Error{ErrorCode::TimeoutConnect, p,
                                string("connection stage timed out")});
            });
        }

        static void disarm_connect_stage(const std::shared_ptr<detail::RequestState>& st) {
            st->connect_stage_done = true;
            if (st->connect_stage_timer) {
                st->connect_stage_timer->cancel();
                st->connect_stage_timer.reset();
            }
        }

        // Maps the in-flight RequestPhase onto the phase a caller sees. The
        // proxy stages keep their own names on purpose: telling a caller that a
        // proxy handshake timed out as "TcpConnect" would hide which hop broke.
        static ErrorPhase connect_stage_phase(detail::RequestPhase p) {
            switch (p) {
            case detail::RequestPhase::ProxyResolve:       return ErrorPhase::ProxyResolve;
            case detail::RequestPhase::ProxyConnect:       return ErrorPhase::ProxyConnect;
            case detail::RequestPhase::ProxyTls:           return ErrorPhase::ProxyTls;
            case detail::RequestPhase::ProxyAuth:          return ErrorPhase::ProxyAuth;
            case detail::RequestPhase::ProxyConnectTunnel: return ErrorPhase::ProxyConnectTunnel;
            case detail::RequestPhase::TlsHandshake:       return ErrorPhase::TargetTls;
            case detail::RequestPhase::SendHead:
            case detail::RequestPhase::SendBody:           return ErrorPhase::Send;
            case detail::RequestPhase::Receive:            return ErrorPhase::Receive;
            default:                                       return ErrorPhase::TcpConnect;
            }
        }
        // Resolve, race the addresses, then continue to TLS/exchange. Split out so
        // the pooled path can reach the same code after the pool says "open one".
        static void start_connect(const std::shared_ptr<detail::RequestState>& st,
                                  string head) {
            // A real connection is about to be made: DNS, TCP, every proxy
            // handshake and the target TLS all fall under this one deadline.
            // Armed once and never re-armed by the proxy stages below, which is
            // what stops a proxy from buying a fresh budget at each sub-step.
            arm_connect_stage(st);

            std::weak_ptr<detail::RequestState> weak = st;

            // With a proxy in play the TCP connection goes to the PROXY. The
            // target name is handed over later (CONNECT / SOCKS5) and, in the
            // SOCKS5 remote-DNS mode, is never resolved locally at all -- which
            // is the whole point of that mode (task book 9-A.5).
            const bool via_proxy = st->proxy.is_set();
            const bool remote_dns = via_proxy && st->proxy.type == ProxyType::Socks5 &&
                                    st->proxy.socks5_remote_dns;
            const string host = via_proxy ? st->proxy.host
                                          : st->request.parsed_url()->host;
            const uint16_t port = via_proxy ? st->proxy.port
                                            : st->request.parsed_url()->port;
            st->phase = via_proxy ? detail::RequestPhase::ProxyResolve
                                  : detail::RequestPhase::Resolve;

            // A SOCKS5 proxy that has agreed to resolve the name means the local
            // resolver must not see it: the connection goes to the proxy, so only
            // the proxy's address is resolved and the target name is handed over
            // in the CONNECT command.
            //
            // The opposite mode (socks5, local DNS) needs the target's ADDRESS,
            // because the tunnel command carries one. An IP literal already has
            // it; a name has to be resolved here, before the proxy hop, and the
            // result is stashed in proxy_target_addr for the handshake to use.
            const Url& target_url = *st->request.parsed_url();
            if (via_proxy && st->proxy.type == ProxyType::Socks5 && !remote_dns) {
                if (target_url.is_ip_literal) {
                    // The literal is already an address: take its bytes directly
                    // rather than sending the URL's text form, which the wire
                    // format does not accept.
                    const AddressList lits = parse_ip_literal(to_view(target_url.host),
                                                              target_url.port);
                    if (!lits.empty()) st->proxy_target_addr = lits.front().bytes;
                } else {
                    // socks5 (local DNS) with a NAME target needs a local
                    // resolution whose result the tunnel command carries. That
                    // path is not implemented, so it is refused explicitly rather
                    // than sending a tunnel command with an empty address.
                    // socks5h is the supported way to use a name target.
                    st->finish(Error{ErrorCode::NotImplemented, ErrorPhase::ProxyConnectTunnel,
                                     string("SOCKS5 local DNS requires an IP literal target; "
                                            "use socks5h for name targets")});
                    return;
                }
            }

            // DNS timeout: covers ONLY the resolve stage, as a sub-deadline of
            // the connection stage. Cancelling the resolve handle tells the
            // resolver to drop its late answer (S2.3-02).
            //
            // This stays a separate timer from the connection-stage one because
            // it must report TimeoutResolve -- a resolver that never answers is a
            // different failure from a TCP connect that never completes, and the
            // caller may want to retry the two differently.
            if (st->options.dns_timeout != Duration::zero()) {
                std::weak_ptr<detail::RequestState> tw = st;
                st->dns_timer = st->executor->schedule_after(st->options.dns_timeout, [tw] {
                    auto s = tw.lock();
                    if (!s || s->finished.load()) return;
                    s->dns_cancel.cancel();
                    s->finish(Error{ErrorCode::TimeoutResolve,
                                    s->proxy.is_set() ? ErrorPhase::ProxyResolve
                                                      : ErrorPhase::Resolve,
                                    string("DNS resolution timed out")});
                });
            }

            // The connection-stage deadline is armed in start_connect(), not here:
            // a request served out of the pool never reaches that function and has
            // no connect work to bound (S5.8-01).

            auto dns_handle = st->resolver->resolve(host, port, [weak, head = std::move(head)](
                                           Result<AddressList> resolved) mutable {
                auto s = weak.lock();
                if (!s || s->finished.load()) return;
                if (s->dns_timer) { s->dns_timer->cancel(); s->dns_timer.reset(); }

                if (!resolved) { s->fail(resolved.error()); return; }
                if (resolved.value().empty()) {
                    s->finish(Error{ErrorCode::DnsNoData, ErrorPhase::Resolve,
                                    string("resolver returned no address")});
                    return;
                }

                s->phase = s->proxy.is_set() ? detail::RequestPhase::ProxyConnect
                                             : detail::RequestPhase::Connect;
                ConnectOptions copts;
                // The race arms its OWN deadline, so hand it what is LEFT of the
                // connection stage rather than the configured timeout again. A
                // fresh budget here would let DNS + TCP together exceed
                // connect_timeout (S5.8-01).
                copts.connect_timeout = s->options.connect_timeout;
                if (!s->connect_stage_done) {
                    const Duration left = s->connect_stage_remaining();
                    if (left != Duration::zero() && left < copts.connect_timeout) {
                        copts.connect_timeout = left;
                    }
                }
                auto addresses = std::move(resolved.value());

                std::weak_ptr<detail::RequestState> w2 = s;
                connect_race(s->executor, std::move(addresses), copts,
                    [w2, head = std::move(head)](Result<std::shared_ptr<AsyncByteStream>> conn) mutable {
                        auto s2 = w2.lock();
                        if (!s2 || s2->finished.load()) {
                            // Race already retired: close a stream we no longer want.
                            if (conn && conn.value()) conn.value()->async_close(nullptr);
                            return;
                        }
                        if (!conn) { s2->fail(conn.error()); return; }

                        s2->stream = conn.value();
                        // Phase 5: a connection opened while pooling is active must
                        // be handed back when the request finishes, or the pool
                        // would keep reserving a slot for a stream it never sees.
                        if (s2->pool) s2->pooled_stream = conn.value();
                        begin_proxy_stage(s2, std::move(head));
                    });
            });
            st->dns_cancel = dns_handle;
        }

        // -------------------------------------------------------------------
        // Proxy handshake stages (S5.4)
        //
        // Inserted between "TCP connected" and the target's TLS layer, because
        // every proxy mode has to finish talking to the proxy before the target
        // protocol may start:
        //
        //   http/https proxy + https target   CONNECT, then target TLS
        //   http/https proxy + http target    no handshake; absolute-form head
        //   socks5                            binary handshake, then target TLS
        //
        // "CONNECT succeeded" is the only point at which target bytes may be
        // sent: task book 10.2 makes sending them earlier a defect, and a proxy
        // that answers 407 afterwards would have already received the target's
        // TLS ClientHello.
        // -------------------------------------------------------------------

        // Reads exactly `want` bytes (at least) from the stream, keeping any
        // extra bytes in `leftover` so the next layer sees them.
        static void read_proxy_bytes(const std::shared_ptr<detail::RequestState>& st,
                                     size_t want,
                                     std::function<void(Result<byte_buffer>)> done) {
            auto acc = std::make_shared<byte_buffer>();
            auto self = st;
            struct Loop {
                static void run(const std::shared_ptr<detail::RequestState>& s,
                                size_t want,
                                std::shared_ptr<byte_buffer> acc,
                                std::function<void(Result<byte_buffer>)> done) {
                    // Stop conditions that matter: a retired request must not
                    // keep reading, and the buffer must not grow without bound.
                    if (s->finished.load()) return;
                    if (acc->size() >= want) {
                        done(*acc);
                        return;
                    }
                    auto stream = s->stream;
                    stream->async_read_some(
                        [s, want, acc, done](Result<string_view> r) mutable {
                            if (!r) { done(r.error()); return; }
                            const string_view sv = r.value();
                            if (sv.empty()) {
                                done(Error{ErrorCode::ConnectionClosed,
                                           s->proxy.is_set() ? ErrorPhase::ProxyConnectTunnel
                                                             : ErrorPhase::Receive,
                                           string("proxy closed the connection mid-handshake")});
                                return;
                            }
                            acc->insert(acc->end(),
                                        reinterpret_cast<const uint8_t*>(sv.data()),
                                        reinterpret_cast<const uint8_t*>(sv.data()) +
                                            static_cast<size_t>(sv.size()));
                            run(s, want, acc, done);
                        });
                }
            };
            Loop::run(self, want, acc, std::move(done));
        }

        // Reads until the CRLFCRLF that ends a response head, keeping the rest.
        static void read_proxy_head(const std::shared_ptr<detail::RequestState>& st,
                                    size_t max_bytes,
                                    std::function<void(Result<std::string>)> done) {
            auto acc = std::make_shared<std::string>();
            struct Loop {
                static void run(const std::shared_ptr<detail::RequestState>& s,
                                size_t max_bytes,
                                std::shared_ptr<std::string> acc,
                                std::function<void(Result<std::string>)> done) {
                    if (s->finished.load()) return;
                    if (acc->find("\r\n\r\n") != std::string::npos) {
                        done(*acc);
                        return;
                    }
                    if (acc->size() > max_bytes) {
                        done(Error{ErrorCode::ProxyProtocolError,
                                   ErrorPhase::ProxyConnectTunnel,
                                   string("proxy response head is too large")});
                        return;
                    }
                    auto stream = s->stream;
                    stream->async_read_some(
                        [s, max_bytes, acc, done](Result<string_view> r) mutable {
                            if (!r) { done(r.error()); return; }
                            const string_view sv = r.value();
                            if (sv.empty()) {
                                done(Error{ErrorCode::ConnectionClosed,
                                           ErrorPhase::ProxyConnectTunnel,
                                           string("proxy closed before answering")});
                                return;
                            }
                            acc->append(sv.data(), static_cast<size_t>(sv.size()));
                            run(s, max_bytes, acc, done);
                        });
                }
            };
            Loop::run(st, max_bytes, acc, std::move(done));
        }

        // Sends `bytes`, then reads the CONNECT reply head.
        static void send_connect(const std::shared_ptr<detail::RequestState>& st,
                                 string head,
                                 std::function<void(Result<byte_buffer>)> done) {
            st->phase = detail::RequestPhase::ProxyConnectTunnel;
            auto buf = std::make_shared<string>(std::move(head));
            auto stream = st->stream;
            stream->async_write(
                reinterpret_cast<const uint8_t*>(buf->data()), buf->size(),
                [st, buf, done](Result<size_t> w) mutable {
                    (void)buf;
                    if (!w) { done(Error{ErrorCode::ProxyConnectFailed,
                                         ErrorPhase::ProxyConnect,
                                         string("failed to send the CONNECT request")});
                              return; }
                    read_proxy_head(st, 64 * 1024,
                        [st, done](Result<std::string> head) mutable {
                            if (!head) { done(head.error()); return; }
                            const std::string& h = head.value();
                            // The status line is "HTTP/1.x NNN ...".
                            int status = 0;
                            const size_t sp1 = h.find(' ');
                            if (sp1 == std::string::npos) {
                                done(Error{ErrorCode::ProxyProtocolError,
                                           ErrorPhase::ProxyConnectTunnel,
                                           string("CONNECT response has no status line")});
                                return;
                            }
                            const size_t sp2 = h.find(' ', sp1 + 1);
                            const std::string code = h.substr(sp1 + 1, sp2 == std::string::npos
                                                                        ? std::string::npos
                                                                        : sp2 - sp1 - 1);
                            // from_chars, not atoi: atoi has undefined behaviour on
                            // overflow, and the status code comes from an untrusted
                            // proxy. A response of "999999999999" must be rejected,
                            // not produce whatever the platform happens to do.
                            {
                                const char* b = code.data();
                                const char* e = code.data() + code.size();
                                auto fr = std::from_chars(b, e, status);
                                if (fr.ec != std::errc{} || fr.ptr != e ||
                                    status < 100 || status > 999) {
                                    done(Error{ErrorCode::ProxyProtocolError,
                                               ErrorPhase::ProxyConnectTunnel,
                                               string("CONNECT response has invalid status code")});
                                    return;
                                }
                            }

                            const auto outcome = proxy_detail::classify_connect_response(status);
                            if (outcome != proxy_detail::ConnectOutcome::Ok) {
                                done(proxy_detail::connect_outcome_error(outcome, status));
                                return;
                            }
                            // Anything after the head already belongs to the
                            // tunnel; losing it would corrupt the target TLS
                            // handshake that starts next.
                            //
                            // read_proxy_head() only calls back once it has the
                            // terminator, so npos "cannot" happen -- but relying on
                            // a caller's invariant for an offset computation is how
                            // an unsigned wrap becomes a huge read. Checked anyway.
                            byte_buffer leftover;
                            const size_t header_end = h.find("\r\n\r\n");
                            if (header_end == std::string::npos) {
                                done(Error{ErrorCode::ProxyProtocolError,
                                           ErrorPhase::ProxyConnectTunnel,
                                           string("CONNECT response missing header terminator")});
                                return;
                            }
                            for (size_t i = header_end + 4; i < h.size(); ++i) {
                                leftover.push_back(static_cast<uint8_t>(h[i]));
                            }
                            done(std::move(leftover));
                        });
                });
        }

        // The SOCKS5 greeting + optional user/pass, then the CONNECT.
        static void socks5_handshake(const std::shared_ptr<detail::RequestState>& st,
                                     std::function<void(Result<byte_buffer>)> done) {
            using namespace proxy_detail::socks5;
            const bool with_auth = st->proxy.has_credentials();
            auto greeting = std::make_shared<byte_buffer>(
                build_greeting(with_auth));

            st->phase = detail::RequestPhase::ProxyConnectTunnel;
            auto stream = st->stream;
            stream->async_write(
                greeting->data(), greeting->size(),
                [st, greeting, done, with_auth](Result<size_t> w) mutable {
                    (void)greeting;
                    if (!w) { done(Error{ErrorCode::Socks5HandshakeFailed,
                                         ErrorPhase::ProxyConnectTunnel,
                                         string("failed to send the SOCKS5 greeting")});
                              return; }
                    read_proxy_bytes(st, 2, [st, done, with_auth](Result<byte_buffer> r) mutable {
                        if (!r) { done(r.error()); return; }
                        const byte_buffer& sel = r.value();
                        const string_view sv(reinterpret_cast<const char*>(sel.data()),
                                             static_cast<string_view::size_type>(sel.size()));
                        auto method = parse_method_selection(sv);
                        if (!method) { done(method.error()); return; }

                        if (method.value() == kAuthNone) {
                            socks5_send_connect(st, std::move(done));
                            return;
                        }
                        if (method.value() != kAuthUserPass) {
                            done(Error{ErrorCode::Socks5AuthFailed, ErrorPhase::ProxyAuth,
                                       string("SOCKS5 proxy chose an auth method we did not offer")});
                            return;
                        }

                        st->phase = detail::RequestPhase::ProxyAuth;
                        auto creds = std::make_shared<byte_buffer>(
                            build_user_pass(to_view(st->proxy.username),
                                            to_view(st->proxy.password)));
                        auto s2 = st->stream;
                        s2->async_write(
                            creds->data(), creds->size(),
                            [st, creds, done](Result<size_t> wr) mutable {
                                (void)creds;
                                if (!wr) { done(Error{ErrorCode::Socks5AuthFailed,
                                                      ErrorPhase::ProxyAuth,
                                                      string("failed to send the SOCKS5 credentials")});
                                          return; }
                                read_proxy_bytes(st, 2,
                                    [st, done](Result<byte_buffer> rr) mutable {
                                        if (!rr) { done(rr.error()); return; }
                                        const byte_buffer& b = rr.value();
                                        const string_view vs(
                                            reinterpret_cast<const char*>(b.data()),
                                            static_cast<string_view::size_type>(b.size()));
                                        auto ok = parse_user_pass_reply(vs);
                                        if (!ok) { done(ok.error()); return; }
                                        socks5_send_connect(st, std::move(done));
                                    });
                            });
                    });
                });
        }

        // Sends the SOCKS5 CONNECT and validates the reply.
        //
        // The reply length depends on its ATYP, and a domain reply depends on
        // its own name-length byte, so the buffer grows until the parser reports
        // a complete message. Guessing a size either blocks on bytes that will
        // never arrive or swallows the first bytes of the tunnel.
        static void socks5_send_connect(const std::shared_ptr<detail::RequestState>& st,
                                        std::function<void(Result<byte_buffer>)> done) {
            using namespace proxy_detail::socks5;
            const Url& url = *st->request.parsed_url();
            const bool is_literal = url.is_ip_literal;
            // Remote DNS hands the NAME to the proxy, so the local resolver never
            // sees it. An IP literal has no name to hand over and stays a literal
            // in both modes.
            const bool send_name = !is_literal && st->proxy.socks5_remote_dns;

            if (!is_literal && !send_name) {
                // Local-DNS mode needs a resolved address, which this stage does
                // not have. begin() resolves the target first in that mode, so
                // reaching here means the mode was configured inconsistently.
                done(Error{ErrorCode::Socks5HandshakeFailed,
                           ErrorPhase::ProxyConnectTunnel,
                           string("SOCKS5 local-DNS mode needs a resolved target address")});
                return;
            }

            // A literal target that arrived through a redirect/retry may not have
            // gone through the fill in start_connect; parse it here so the frame
            // always carries a real address. A zero-length address produces a
            // malformed CONNECT that the proxy drops, which surfaces as a reset
            // and looks like a proxy bug.
            byte_buffer addr_bytes = st->proxy_target_addr;
            if (!send_name && addr_bytes.empty()) {
                const AddressList lits = parse_ip_literal(to_view(url.host), url.port);
                if (!lits.empty()) addr_bytes = lits.front().bytes;
                if (addr_bytes.empty()) {
                    done(Error{ErrorCode::Socks5HandshakeFailed,
                               ErrorPhase::ProxyConnectTunnel,
                               string("SOCKS5 CONNECT has no target address")});
                    return;
                }
            }

            const uint8_t atyp = send_name
                                     ? kAtypDomain
                                     : (addr_bytes.size() == 16 ? kAtypIpv6 : kAtypIpv4);
            const auto req = build_connect(atyp, to_view(url.host),
                                           addr_bytes.empty() ? nullptr : addr_bytes.data(),
                                           addr_bytes.size(), url.port);

            auto buf = std::make_shared<byte_buffer>(req);
            auto stream = st->stream;
            stream->async_write(
                buf->data(), buf->size(),
                [st, buf, done](Result<size_t> w) mutable {
                    (void)buf;
                    if (!w) {
                        done(Error{ErrorCode::Socks5HandshakeFailed,
                                   ErrorPhase::ProxyConnectTunnel,
                                   string("failed to send the SOCKS5 CONNECT")});
                        return;
                    }
                    read_socks5_reply(st, std::move(done));
                });
        }

        // Collects bytes until the SOCKS5 reply parses as complete.
        static void read_socks5_reply(const std::shared_ptr<detail::RequestState>& st,
                                      std::function<void(Result<byte_buffer>)> done) {
            auto acc = std::make_shared<byte_buffer>();
            struct Loop {
                static void run(const std::shared_ptr<detail::RequestState>& s,
                                std::shared_ptr<byte_buffer> acc,
                                std::function<void(Result<byte_buffer>)> done) {
                    if (s->finished.load()) return;
                    if (acc->size() >= 4) {
                        const string_view sv(
                            reinterpret_cast<const char*>(acc->data()),
                            static_cast<string_view::size_type>(acc->size()));
                        auto probe = proxy_detail::socks5::parse_reply(sv);
                        if (!probe) { done(probe.error()); return; }
                        if (probe.value().complete) {
                            using proxy_detail::socks5::Reply;
                            if (probe.value().code != Reply::Succeeded) {
                                done(proxy_detail::socks5::reply_error(probe.value().code));
                                return;
                            }
                            byte_buffer leftover(
                                acc->begin() + static_cast<std::ptrdiff_t>(
                                                   probe.value().consumed),
                                acc->end());
                            done(std::move(leftover));
                            return;
                        }
                    }
                    if (acc->size() > 512) {
                        done(Error{ErrorCode::Socks5HandshakeFailed,
                                   ErrorPhase::ProxyConnectTunnel,
                                   string("SOCKS5 reply is absurdly long")});
                        return;
                    }
                    auto stream = s->stream;
                    stream->async_read_some(
                        [s, acc, done](Result<string_view> r) mutable {
                            if (!r) { done(r.error()); return; }
                            const string_view v = r.value();
                            if (v.empty()) {
                                done(Error{ErrorCode::Socks5HandshakeFailed,
                                           ErrorPhase::ProxyConnectTunnel,
                                           string("SOCKS5 proxy closed mid-reply")});
                                return;
                            }
                            acc->insert(acc->end(),
                                        reinterpret_cast<const uint8_t*>(v.data()),
                                        reinterpret_cast<const uint8_t*>(v.data()) +
                                            static_cast<size_t>(v.size()));
                            run(s, acc, done);
                        });
                }
            };
            Loop::run(st, acc, std::move(done));
        }

        // Entry point: the stream is connected to the proxy (or to the target
        // when no proxy is configured). Runs the proxy stage then hands over.
        static void begin_proxy_stage(const std::shared_ptr<detail::RequestState>& st,
                                      string head) {
            if (!st->proxy.is_set()) {
                begin_tls_or_exchange(st, std::move(head));
                return;
            }

            const Url& url = *st->request.parsed_url();

            // The head is needed by whichever branch runs, so it is shared rather
            // than moved into the first lambda that mentions it. Moving it into
            // `after_proxy_tls` left the later branches with an empty string and
            // the request went out with no request line at all.
            auto head_ptr = std::make_shared<string>(std::move(head));

            // HTTPS proxy: the connection to the proxy itself is TLS. This layer
            // uses proxy_tls_config, whose hostname is the PROXY's, so the proxy
            // certificate is validated as the proxy and never as the target.
            auto after_proxy_tls = [st, head_ptr](std::function<void()> next) {
                st->phase = detail::RequestPhase::ProxyTls;
                auto tls = make_tls_stream(st->stream, st->proxy_tls_config);
                if (!tls) {
                    st->fail(Error{ErrorCode::TlsHandshakeFailed, ErrorPhase::ProxyTls,
                                   string("failed to create the proxy TLS stream")});
                    return;
                }
                tls->set_error_phase(ErrorPhase::ProxyTls, ErrorPhase::ProxyTls);
                st->proxy_tls_stream = tls;
                std::weak_ptr<detail::RequestState> weak = st;
                tls->start([weak, tls, next](VoidResult r) {
                    auto s = weak.lock();
                    if (!s || s->finished.load()) return;
                    if (!r) { s->fail(r.error()); return; }
                    // Everything above this point now talks through the proxy TLS
                    // stream: CONNECT and, later, the target TLS both sit on it.
                    s->stream = tls;
                    next();
                });
            };

            // Finishes the proxy stage: any leftover bytes are pushed back in
            // front of the stream so the next layer (target TLS or the HTTP
            // exchange) reads them first.
            auto finish_proxy = [st, head_ptr](byte_buffer leftover) {
                if (!leftover.empty()) {
                    st->stream = std::make_shared<detail::PrefixedStream>(
                        st->stream, std::move(leftover));
                }
                begin_tls_or_exchange(st, std::move(*head_ptr));
            };

            // Task book 10.2: a secure target behind an HTTP-speaking proxy needs
            // a CONNECT tunnel; a cleartext target does not (absolute-form).
            if (proxy_detail::needs_connect(st->proxy.type, url.is_secure())) {
                auto do_connect = [st, finish_proxy]() {
                    const Url& u = *st->request.parsed_url();
                    string req = proxy_detail::build_connect_request(
                        to_view(u.host), u.port, st->proxy,
                        to_view(st->options.user_agent));
                    send_connect(st, std::move(req),
                        [st, finish_proxy](Result<byte_buffer> r) {
                            if (!r) { st->fail(r.error()); return; }
                            finish_proxy(std::move(r.value()));
                        });
                };
                if (proxy_detail::uses_proxy_tls(st->proxy.type)) {
                    after_proxy_tls(do_connect);
                } else {
                    do_connect();
                }
                return;
            }

            if (st->proxy.type == ProxyType::Socks5) {
                socks5_handshake(st, [st, finish_proxy](Result<byte_buffer> r) {
                    if (!r) { st->fail(r.error()); return; }
                    finish_proxy(std::move(r.value()));
                });
                return;
            }

            // Forward proxy with a cleartext target: no handshake at all; the
            // head already carries the absolute form.
            if (proxy_detail::uses_proxy_tls(st->proxy.type)) {
                after_proxy_tls([finish_proxy]() { finish_proxy(byte_buffer{}); });
                return;
            }
            begin_tls_or_exchange(st, std::move(*head_ptr));
        }

        // Layered between TCP and the HTTP exchange: when the URL is https://,
        // the connected byte stream is wrapped in a TlsStream first. TLS is
        // built on AsyncByteStream (not on a raw socket), which is what lets the
        // same code serve a proxy CONNECT tunnel later (task book 5).
        static void begin_tls_or_exchange(const std::shared_ptr<detail::RequestState>& st,
                                          string head) {
            if (!st->request.parsed_url() || !st->request.parsed_url()->is_secure()) {
                begin_exchange(st, std::move(head));
                return;
            }

            TlsConfig cfg = st->options.tls;
            // Hostname drives both SNI and the certificate identity check, so it
            // must be the URL host -- never the resolved address.
            cfg.hostname = st->request.parsed_url()->host;

            st->phase = detail::RequestPhase::TlsHandshake;
            auto tls = make_tls_stream(st->stream, cfg);
            if (!tls) {
                st->fail(Error{ErrorCode::TlsHandshakeFailed, ErrorPhase::TlsHandshake,
                               string("failed to create the TLS stream")});
                return;
            }
            // Tag this layer as the TARGET one. Without it a target certificate
            // failure is reported as the generic TlsHandshake phase, so a caller
            // cannot tell a target identity problem from a proxy one -- which is
            // the whole point of the phase split (task book 9.3).
            tls->set_error_phase(ErrorPhase::TargetTls, ErrorPhase::TargetProtocol);
            st->tls_stream = tls;

            std::weak_ptr<detail::RequestState> weak = st;
            tls->start([weak, head = std::move(head)](VoidResult r) mutable {
                auto s = weak.lock();
                if (!s || s->finished.load()) return;
                if (!r) {
                    // The TLS stream already tagged this with ErrorPhase and a
                    // specific certificate code where applicable.
                    s->fail(r.error());
                    return;
                }
                s->stream = s->tls_stream;   // exchange talks TLS from here on
                begin_exchange(s, std::move(head));
            });
        }

        // Free of `this` so it can run from a detached async callback: the
        // request state carries everything the exchange needs.
        static void begin_exchange(const std::shared_ptr<detail::RequestState>& st, string head) {
            // The connection stage is over: DNS, TCP, every proxy handshake and
            // the target TLS are done. From here send_timeout / recv_timeout take
            // over, so the connect deadline must not fire against a healthy
            // exchange (S5.8-01).
            disarm_connect_stage(st);

            // Order matters: the Exchange must exist before the parser (which
            // stores a reference to it), and the Exchange must keep itself alive
            // while the exchange is in flight. It does so via shared_from_this().
            auto exchange = std::make_shared<detail::Exchange>(st);
            auto parser = std::make_unique<ResponseParser>(
                *exchange, st->options.parser_limits);
            // The parser must know the request method: a response to HEAD never
            // carries a body even when it advertises Content-Length (RFC 7230
            // 3.3.3). Without this the parser would wait for bytes that a correct
            // server will never send.
            parser->set_request_method(st->request.method());
            exchange->set_parser(std::move(parser));
            exchange->start(std::move(head), st->expect_continue_sent);
        }

    public:
        ClientOptions options;
        std::optional<Error> options_error;   // set when ClientOptions::validate() failed
        std::shared_ptr<Executor> executor;
        std::shared_ptr<Resolver> resolver;
        bool owns_executor{false};
        std::shared_ptr<ConnectionPool> pool;   // null = pooling disabled
        std::atomic<bool> stopped{false};

        // In-flight request tracking for shutdown(S2.6-02/04).
        std::mutex m_;
        std::vector<std::weak_ptr<detail::RequestState>> in_flight_;
        // Number of shutdown retirement jobs that have been posted but not yet
        // run.  While this is non-zero the drained callback must not fire, even
        // if every RequestState already looks finished.
        std::atomic<int> retiring{0};
        std::function<void()> drained_cb;

        void maybe_notify_drained() {
            std::function<void()> cb;
            {
                std::lock_guard<std::mutex> lk(m_);
                // Only shutdown() arms the drained callback, so a natural
                // completion must not fire it early. Requiring `stopped` makes
                // that intent explicit rather than incidental.
                if (!stopped.load()) return;
                // A retirement job in flight still holds its RequestState alive,
                // and shutdown() itself keeps a strong reference in its local
                // vector while it waits, so weak_ptr liveness cannot answer
                // "have the retirements run yet". The counter is the only honest
                // signal: it reaches zero when the last posted retirement job has
                // executed its finish().
                if (retiring.load() != 0) return;
                if (drained_cb) { cb = std::move(drained_cb); drained_cb = nullptr; }
            }
            if (cb) cb();
        }
    };

    // ---------------------------------------------------------------------------
    // Client
    // ---------------------------------------------------------------------------
    inline Client::Client() : Client(ClientOptions{}) {}

    inline Client::Client(ClientOptions options)
        : impl_(std::make_unique<Impl>(std::move(options))) {}

    inline Client::~Client() = default;

    inline Client::Client(Client&&) noexcept = default;
    inline Client& Client::operator=(Client&&) noexcept = default;

    inline CancelHandle Client::request(const Request& req, ResponseCallback on_complete) {
        auto state = std::make_shared<CancelState>(impl_->executor);
        CancelHandle handle(state);
        // SYNCHRONOUS REJECTION -- this callback runs on the CALLING thread, not
        // on the executor. That is deliberate and allowed by the task book
        // (5.3: "distinguish a synchronously rejected submission from an
        // accepted request"). An accepted request owes exactly one terminal
        // callback on the I/O context; a submission that was never accepted
        // owes the caller an immediate answer, and posting it to an executor
        // that is stopped (or was never usable) would mean it never arrives.
        if (impl_->options_error) {
            if (on_complete) on_complete(Result<Response>(*impl_->options_error));
            return handle;
        }
        if (impl_->stopped.load()) {
            if (on_complete) {
                on_complete(Error{ErrorCode::Cancelled, ErrorPhase::None,
                                  string("client is shut down")});
            }
            return handle;
        }
        impl_->submit(req, std::move(on_complete), handle, state);
        return handle;
    }

    inline CancelHandle Client::get(string_view url, ResponseCallback on_complete) {
        Request req(Method::Get, url);
        return request(req, std::move(on_complete));
    }

    inline void Client::shutdown() { impl_->shutdown(); }

    inline void Client::shutdown(std::function<void()> on_drained) {
        impl_->shutdown(std::move(on_drained));
    }

    inline const ClientOptions& Client::options() const noexcept { return impl_->options; }

#if MEGOHTTP_HAS_SSE
    inline std::shared_ptr<SseSession> Client::request_sse(Request request,
                                                           SseReconnectPolicy policy) {
        auto ex = impl_->executor;
        if (!ex) {
            ex = detail::make_default_executor();
        }
        // The submitter captures the Client by raw pointer. The session is
        // expected to be cancelled before the Client dies (or the Client's
        // shutdown retires it), and a dangling session past that point would be
        // a caller error -- not something a weak_ptr can paper over here,
        // because Client::request is called through impl_.
        Impl* impl = impl_.get();

        // An SSE stream is long-lived by definition. Inheriting the Client's
        // recv_timeout / total_timeout would kill every stream that is simply
        // quiet for a while (heartbeat intervals can exceed 30s), and the task
        // book (11) requires a long-lived SSE connection to be able to disable
        // the total timeout. The connect/DNS budgets are kept: establishing the
        // connection is still bounded work.
        ClientOptions sse_options = impl_->options;
        sse_options.recv_timeout = Duration::zero();
        sse_options.send_timeout = Duration::zero();
        sse_options.total_timeout = Duration::zero();

        auto submitter = [impl, sse_options](Request req,
                                             std::function<void(Result<Response>)> cb) {
            impl->submit(std::move(req), std::move(cb),
                         CancelHandle{}, std::make_shared<CancelState>(impl->executor),
                         &sse_options);
        };
        return std::make_shared<SseSession>(ex, std::move(submitter),
                                            std::move(request), std::move(policy));
    }
#endif

#if MEGOHTTP_HAS_WEBSOCKET
    inline std::shared_ptr<ReconnectingWebSocket> Client::open_websocket(
        string_view url, WebSocketOptions ws_options, WebSocketReconnectPolicy policy) {
        // Parse the ws:// or wss:// URL once, here: the provider below is called
        // once per physical attempt, and re-parsing a fixed URL each time would
        // only add a failure mode.
        auto parsed = parse_url(url);
        if (!parsed) {
            auto bad = std::make_shared<Error>(parsed.error());
            auto provider = [bad](string, string,
                                  std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> done) {
                done(*bad);
            };
            auto fail_session = std::make_shared<ReconnectingWebSocket>(
                impl_->executor, std::move(provider), std::move(ws_options), std::move(policy));
            fail_session->start(string{}, string{}, Headers{});
            return fail_session;
        }

        const Url u = parsed.value();
        string host = to_string(to_view(u.host));
        string path = to_string(to_view(u.request_target()));
        const bool secure = u.is_secure();
        const uint16_t port = (u.port != 0) ? u.port : Url::default_port(u.scheme);

        Impl* impl = impl_.get();
        auto ex = impl_->executor;
        if (!ex) {
            ex = detail::make_default_executor();
            // The provider below runs on a later attempt and reads
            // impl->executor, not this local. Leaving it null made every
            // attempt fail with NotImplemented before it ever resolved a name.
            impl_->executor = ex;
        }
        // Same for the resolver: the provider reads impl->resolver.
        if (!impl_->resolver) {
            impl_->resolver = std::make_shared<SystemResolver>(ex);
        }

        // Proxy routing: when a proxy is configured the TCP connection goes to
        // the PROXY, and the tunnel (CONNECT / SOCKS5, plus the proxy's own TLS
        // layer when it is an HTTPS proxy) is what reaches the target. The
        // target TLS handshake then runs on top of the tunnel, exactly as it
        // does for https:// requests (task book 10.2 / 12.1).
        const ProxyOptions proxy = impl_->options.proxy;
        const bool use_proxy = proxy.proxy.is_set();
        const string dial_host = use_proxy ? proxy.proxy.host : host;
        const uint16_t dial_port = use_proxy ? proxy.proxy.port : port;
        const string user_agent = impl_->options.user_agent;

        // One physical attempt: resolve -> race -> (proxy tunnel) -> (TLS) ->
        // hand the stream back. This intentionally reuses nothing from the HTTP
        // request pipeline: a WebSocket upgrade is not an HTTP exchange after
        // the 101, so sharing the Exchange machinery would fight the frame
        // protocol.
        auto provider = [impl, host, port, secure, u, dial_host, dial_port,
                         use_proxy, proxy, user_agent](
                            string /*h*/, string /*p*/,
                            std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> done) {
            auto exe = impl->executor;
            if (!exe) {
                done(Error{ErrorCode::NotImplemented, ErrorPhase::None,
                           string("no executor available")});
                return;
            }
            auto resolver = impl->resolver;
            if (!resolver) {
                done(Error{ErrorCode::NotImplemented, ErrorPhase::Resolve,
                           string("no resolver available")});
                return;
            }

            resolver->resolve(dial_host, dial_port, [impl, exe, secure, u, done,
                                                     host, port, use_proxy, proxy,
                                                     user_agent](
                                            Result<AddressList> resolved) {
                if (!resolved) {
                    done(resolved.error()); return;
                }
                if (resolved.value().empty()) {
                    done(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                               string("no addresses resolved")});
                    return;
                }
                ConnectOptions copts;
                copts.connect_timeout = impl->options.connect_timeout;
                connect_race(exe, std::move(resolved.value()), copts,
                             [impl, secure, u, done, host, port, use_proxy, proxy,
                              user_agent](
                                 Result<std::shared_ptr<AsyncByteStream>> conn) {
                                 if (!conn) {
                                     done(conn.error()); return;
                                 }
                                 auto stream = conn.value();
                                 if (!stream) {
                                     done(Error{ErrorCode::ConnectFailed,
                                                ErrorPhase::TcpConnect,
                                                string("connect returned no stream")});
                                     return;
                                 }

                                 // Everything after the TCP connection is a
                                 // continuation: tunnel (when proxied), then the
                                 // target TLS handshake, then the session.
                                 auto after_tunnel =
                                     [impl, secure, u, done](
                                         Result<proxy_tunnel::TunnelResult> tr) {
                                         if (!tr) { done(tr.error()); return; }
                                         std::shared_ptr<AsyncByteStream> transport =
                                             tr.value().stream;
                                         byte_buffer leftover = std::move(tr.value().leftover);

                                         // Tunnel bytes the proxy already sent for
                                         // us belong BELOW whatever speaks next --
                                         // for wss that is the TLS record layer, so
                                         // the prefix must wrap the TCP/tunnel
                                         // stream, not the TLS one.
                                         if (!leftover.empty()) {
                                             transport = std::make_shared<detail::PrefixedStream>(
                                                 transport, std::move(leftover));
                                         }

                                         if (!secure) {
                                             done(transport);
                                             return;
                                         }

                                         TlsConfig cfg = impl->options.tls;
                                         if (cfg.hostname.empty()) {
                                             cfg.hostname = to_string(to_view(u.host));
                                         }
                                         auto tls = make_tls_stream(transport, cfg);
                                         if (!tls) {
                                             done(Error{ErrorCode::TlsHandshakeFailed,
                                                        ErrorPhase::TargetTls,
                                                        string("failed to create the target TLS stream")});
                                             return;
                                         }
                                         tls->set_error_phase(ErrorPhase::TargetTls,
                                                              ErrorPhase::TargetProtocol);
                                         tls->start([tls, done](VoidResult r) {
                                             if (!r) { done(r.error()); return; }
                                             done(std::static_pointer_cast<AsyncByteStream>(tls));
                                         });
                                     };

                                 if (!use_proxy) {
                                     after_tunnel(proxy_tunnel::TunnelResult{stream, {}});
                                     return;
                                 }

                                 proxy_tunnel::establish(
                                     stream, proxy, to_view(host), port,
                                     to_view(user_agent),
                                     [impl](ErrorPhase p) { (void)impl; (void)p; },
                                     after_tunnel);
                             });
            });
        };

        auto session = std::make_shared<ReconnectingWebSocket>(
            ex, std::move(provider), std::move(ws_options), std::move(policy));
        session->start(std::move(host), std::move(path), Headers{});
        return session;
    }
#endif

#if MEGOHTTP_HAS_COROUTINES
    inline Task<Result<Response>> Client::request_co(const Request& req) {
        // Publish the request's cancel handle on the promise so
        // Task::cancel() can reach it from any thread, then suspend on the
        // completion callback. Nothing blocks: the executor thread drives the
        // request and resumes this coroutine from the callback.
        auto* p = co_await Task<Result<Response>>::GetPromise{};

        SuspendedOperation<Result<Response>> op;
        // Capture the shared handle slot, not the raw promise pointer: cancel()
        // may copy it from another thread while this body runs.
        auto cancel_slot = p->cancel_;
        op.start = [this, req, cancel_slot](std::function<void(Result<Response>)> done) {
            *cancel_slot = this->request(req, std::move(done));
        };
        co_return co_await op;
    }

    inline Task<Result<Response>> Client::get_co(string_view url) {
        Request req(Method::Get, url);
        co_return co_await request_co(req);
    }
#endif

} // namespace megohttp

#endif // MEGOHTTP_CLIENT_IMPL_HPP_INCLUDED
