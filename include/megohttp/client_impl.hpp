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

            // Self-hold until the terminal callback fires.
            std::shared_ptr<RequestState> self_hold;

            // Called once from finish() so the owning Client can drop this request
            // from its in-flight set and possibly fire a shutdown-drained callback.
            std::function<void()> on_retired;

            // Fires the terminal callback exactly once.
            void finish(Result<Response> result) {
                if (finished.exchange(true)) return;
                if (total_timer) total_timer->cancel();
                if (dns_timer) dns_timer->cancel();
                dns_cancel.cancel();   // stop a late DNS answer from firing the callback
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
                    case RequestPhase::SendHead:
                    case RequestPhase::SendBody:  p = ErrorPhase::Send;      break;
                    case RequestPhase::Receive:   p = ErrorPhase::Receive;   break;
                    default: break;
                    }
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

            VoidResult on_head(const ParsedResponse& head) override {
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
                return VoidResult{};
            }

            VoidResult on_body_data(const uint8_t* data, size_t size) override {
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
                            auto eof = self->parser_->feed_eof();
                            if (!eof) {
                                self->fail(eof.error());
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
        };

        // Builds the request head for a direct (non-proxy) HTTP request.
        // `expect_continue` adds the Expect header; the caller decides whether the
        // request qualifies (it must actually carry a body) and records the same
        // decision so the exchange holds the body accordingly.
        inline Result<string> build_request_head(const Request& req, const Url& url,
                                                 bool expect_continue) {
            Headers headers = req.headers();
            if (!headers.contains("host")) {
                headers.set("host", to_view(url.host_port_header()));
            }
            if (!headers.contains("connection")) {
                headers.set("connection", "close");
            }
            if (req.has_body() && !headers.contains("content-length")) {
                headers.set("content-length",
                            to_view(format("{}", req.body_bytes().size())));
            }
            if (expect_continue && !headers.contains("expect")) {
                headers.set("expect", "100-continue");
            }
            return encode_request_head(req.method(), req.custom_method(),
                                       to_view(url.request_target()), headers);
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

            // Total timeout covers the WHOLE logical request (spec 8.2).
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

            if (url.scheme != Scheme::Http) {
                // Phase 1 has no TLS: refuse rather than silently downgrade.
                st->finish(Error{url.is_secure() ? ErrorCode::TlsNotEnabled
                                                 : ErrorCode::InvalidArgument,
                                 ErrorPhase::None,
                                 string("phase 1 supports plaintext http:// only")});
                return;
            }
            st->request.set_parsed_url(url);

            st->phase = detail::RequestPhase::BuildHead;
            // Expect: 100-continue only makes sense when there is a body to hold
            // back. Record the decision once so the head and the exchange agree.
            st->expect_continue_sent = st->options.expect_continue
                                    && st->request.has_body()
                                    && !st->request.body_bytes().empty();
            auto head = detail::build_request_head(st->request, url,
                                                   st->expect_continue_sent);
            if (!head) { st->finish(head.error()); return; }

            std::weak_ptr<detail::RequestState> weak = st;
            const string host = url.host;
            const uint16_t port = url.port;
            st->phase = detail::RequestPhase::Resolve;

            // DNS timeout: covers the resolve stage only. Cancelling the resolve
            // handle tells the resolver to drop its late answer (S2.3-02).
            if (st->options.dns_timeout != Duration::zero()) {
                std::weak_ptr<detail::RequestState> tw = st;
                st->dns_timer = st->executor->schedule_after(st->options.dns_timeout, [tw] {
                    auto s = tw.lock();
                    if (!s || s->finished.load()) return;
                    s->dns_cancel.cancel();
                    s->finish(Error{ErrorCode::TimeoutResolve, ErrorPhase::Resolve,
                                    string("DNS resolution timed out")});
                });
            }

            auto dns_handle = st->resolver->resolve(host, port, [weak, head = std::move(head.value())](
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

                s->phase = detail::RequestPhase::Connect;
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
                        begin_exchange(s2, std::move(head));
                    });
            });
            st->dns_cancel = dns_handle;
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
