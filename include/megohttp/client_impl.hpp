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

#include <atomic>
#include <cstdlib>
#include <mutex>
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
            ClientOptions options;
            Request request;
            Client::ResponseCallback on_complete;

            std::atomic<bool> finished{false};
            std::shared_ptr<Timer> total_timer;
            std::shared_ptr<Timer> dns_timer;
            CancelHandle dns_cancel;

            RequestPhase phase{RequestPhase::Idle};

            // True when the request head carried Expect: 100-continue and the body
            // must wait for a 100 answer (S3.1-09).
            bool expect_continue_sent{false};

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
                if (cb) cb(std::move(result));
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
                const auto& body = state_->request.body_bytes();
                if (body.empty()) return;
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
                const auto& body = state_->request.body_bytes();
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
            void send_body_streaming() {
                auto& src = *state_->request.body_source();
                auto r = src();
                if (!r) { fail(r.error()); return; }

                auto& [data, eof] = r.value();
                if (data.empty() && !eof) {
                    // Backpressure: Source not ready. Retry shortly.
                    auto self = shared_from_this();
                    state_->executor->schedule_after(
                        std::chrono::milliseconds(10),
                        [self]() { self->send_body_streaming(); });
                    return;
                }

                if (!data.empty()) {
                    auto self = shared_from_this();
                    auto stream = state_->stream;
                    // Must keep data alive until async_write completes.
                    auto buf = std::make_shared<string>(to_string(data));
                    stream->async_write(
                        reinterpret_cast<const uint8_t*>(buf->data()), buf->size(),
                        [self, buf, eof](Result<size_t> w) {
                            (void)buf; // keep alive
                            if (!w) { self->fail(w.error()); return; }
                            if (eof) {
                                self->disarm_send_timer();
                                self->arm_recv_timer();
                                self->read_more();
                            } else {
                                self->send_body_streaming();
                            }
                        });
                } else if (eof) {
                    // Empty body with eof.
                    disarm_send_timer();
                    arm_recv_timer();
                    read_more();
                }
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
                    fail(Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                               string("too many redirects")});
                    redirect_pending_ = true;   // stop on_complete from reporting success
                    redirect_location_.reset();
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
                if (auto& bs = state_->request.body_sink()) {
                    body_sink_ = bs;
                    body_sink_complete_ = state_->request.body_sink_complete();
                } else {
                    buffer_sink_ = std::make_unique<BufferSink>(std::move(rh),
                                                         state_->options.max_response_body);
                }
                // Framing fact needed later to decide whether this connection may
                // be reused: Connection: close (or HTTP/1.0 without keep-alive)
                // means the server will not carry a second exchange on it.
                head_connection_close_ = head.connection_close;
                return VoidResult{};

            }

            VoidResult on_body_data(const uint8_t* data, size_t size) override {
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
                    if (!(*body_sink_)(sv)) {
                        // Backpressure: sink asked to pause.
                        // For now we don't pause the parser; we just continue.
                        // Full backpressure would require parser pause/resume.
                    }
                }
                return VoidResult{};
            }

            VoidResult on_trailers(const Headers& tr) override {
                if (buffer_sink_) buffer_sink_->set_trailers(tr);
                // In streaming mode, trailers are dropped (not supported yet).
                return VoidResult{};
            }

            VoidResult on_complete() override {
                complete_ = true;
                disarm_recv_timer();

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
                    state_->finish(std::move(response));
                } else if (body_sink_complete_) {
                    // S3.2-02: Streaming mode complete.
                    (*body_sink_complete_)(VoidResult{});
                    state_->finish(Response{});  // Empty response, data already delivered
                } else {
                    state_->finish(Response{});
                }
                return VoidResult{};
            }
        private:
            void read_more() {
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
                        auto res = self->parser_->feed(
                            reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
                        if (!res) { self->fail(res.error()); return; }
                        if (self->complete_) return;
                        self->read_more();
                    });
            }

            void fail(const Error& e) {
                disarm_send_timer();
                disarm_recv_timer();
                state_->fail(e);
            }

            std::shared_ptr<RequestState> state_;
            std::unique_ptr<ResponseParser> parser_;
            std::shared_ptr<Timer> send_timer_;
            std::shared_ptr<Timer> recv_timer_;
            // Buffered mode: accumulates body into a vector.
            std::unique_ptr<BufferSink> buffer_sink_;
            // Streaming mode: user-provided callbacks. Mutually exclusive with buffer_sink_.
            std::optional<Request::BodySink> body_sink_;
            std::optional<Request::BodySinkComplete> body_sink_complete_;
            bool complete_{false};
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
                    const string_view sv(reinterpret_cast<const char*>(prefix_.data()),
                                         static_cast<string_view::size_type>(prefix_.size()));
                    // Copy out before clearing: the view must stay valid for the
                    // duration of the callback only, which this satisfies.
                    byte_buffer held = std::move(prefix_);
                    prefix_.clear();
                    if (cb) cb(string_view(reinterpret_cast<const char*>(held.data()),
                                           static_cast<string_view::size_type>(held.size())));
                    (void)sv;
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
                                                                                                  const ProxyConfig& proxy) {
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
            if (req.has_body() && !headers.contains("content-length")) {
                headers.set("content-length",
                            to_view(format("{}", req.body_bytes().size())));
            }
            if (expect_continue && !headers.contains("expect")) {
                headers.set("expect", "100-continue");
            }
            // A forward proxy (plain http:// target, any proxy type that speaks
            // HTTP) needs the absolute form so it knows where to relay. An
            // https:// target always uses origin-form inside the CONNECT tunnel,
            // because by then the proxy is not reading anything (RFC 7230 5.3.2).
            //
            // absolute_form_target() returns an OWNING string, so it has to be
            // held in a local: taking to_view() of the temporary left a dangling
            // view that encode_request_head read a moment later, and the request
            // went out with a corrupted target the proxy could not route.
            string absolute;
            if (forward_proxy) absolute = url.absolute_form_target();
            const string_view target = forward_proxy
                                           ? to_view(absolute)
                                           : to_view(url.request_target());
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
                in_flight_.clear();
            }
            for (auto& st : live)
                st->finish(Error{ErrorCode::Cancelled, ErrorPhase::None,
                                 string("client is shutting down")});

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
            {
                std::lock_guard<std::mutex> lk(m_);
                if (!drained_cb) drained_cb = std::move(on_drained);
            }
            shutdown();
        }

        void submit(const Request& req,
                    Client::ResponseCallback on_complete,
                    const CancelHandle& handle,
                    std::shared_ptr<CancelState> cancel_state) {
            auto st = std::make_shared<detail::RequestState>();
            st->self_hold = st;
            st->executor = executor;
            st->resolver = resolver;
            st->options = options;
            st->pool = pool;

            // Redirect budget (S5.2). Only counts when the caller opted in;
            // with the policy off the counter stays 0 and nothing follows.
            st->hops_left = st->options.redirects.follow
                                ? st->options.redirects.max_redirects : 0;
            st->request = req;
            st->on_complete = std::move(on_complete);

            // Track in-flight so shutdown() can retire this request (S2.6-02/04).
            {
                std::lock_guard<std::mutex> lk(m_);
                in_flight_.push_back(st);
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
                }
            }

            st->phase = detail::RequestPhase::BuildHead;
            // Expect: 100-continue only makes sense when there is a body to hold
            // back. Record the decision once so the head and the exchange agree.
            st->expect_continue_sent = st->options.expect_continue
                                    && st->request.has_body()
                                    && !st->request.body_bytes().empty();
            // Absolute-form is used only when an HTTP-speaking proxy relays a
            // cleartext target. A secure target goes through CONNECT and then
            // uses origin-form inside the tunnel.
            const bool forward_proxy = proxy_detail::is_forward_proxy(st->proxy.type) &&
                                       !url.is_secure();
            auto head = detail::build_request_head(st->request, url,
                                                   st->expect_continue_sent,
                                                   st->pool != nullptr, forward_proxy,
                                                   st->proxy);
            if (!head) { st->finish(head.error()); return; }

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

        // Resolve, race the addresses, then continue to TLS/exchange. Split out so
        // the pooled path can reach the same code after the pool says "open one".
        static void start_connect(const std::shared_ptr<detail::RequestState>& st,
                                  string head) {
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

            // DNS timeout: covers the resolve stage only. Cancelling the resolve
            // handle tells the resolver to drop its late answer (S2.3-02).
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
                copts.connect_timeout = s->options.connect_timeout;
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
                            status = std::atoi(code.c_str());

                            const auto outcome = proxy_detail::classify_connect_response(status);
                            if (outcome != proxy_detail::ConnectOutcome::Ok) {
                                done(proxy_detail::connect_outcome_error(outcome, status));
                                return;
                            }
                            // Anything after the head already belongs to the
                            // tunnel; losing it would corrupt the target TLS
                            // handshake that starts next.
                            byte_buffer leftover;
                            const size_t end = h.find("\r\n\r\n") + 4;
                            for (size_t i = end; i < h.size(); ++i) {
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
        std::function<void()> drained_cb;

        void maybe_notify_drained() {
            std::function<void()> cb;
            {
                std::lock_guard<std::mutex> lk(m_);
                bool empty = true;
                for (auto& w : in_flight_) { if (w.lock()) { empty = false; break; } }
                if (empty && drained_cb) { cb = std::move(drained_cb); drained_cb = nullptr; }
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

} // namespace megohttp

#endif // MEGOHTTP_CLIENT_IMPL_HPP_INCLUDED
