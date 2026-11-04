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

#if defined(MGHTTP_BACKEND_LIBUV)
#include <megohttp/backend/executor_libuv.hpp>
#elif defined(MGHTTP_BACKEND_ASIO)
#include <megohttp/backend/executor_asio.hpp>
#endif

#include <atomic>
#include <mutex>
#include <vector>

namespace MegoHttp {

    namespace Detail {

        // Creates the default executor for the compiled backend.
        inline std::shared_ptr<Executor> make_default_executor() {
#if defined(MGHTTP_BACKEND_LIBUV)
            return libuv_backend::UvExecutor::create_internal();
#elif defined(MGHTTP_BACKEND_ASIO)
            return asio_backend::AsioExecutor::create_internal();
#else
            return nullptr;
#endif
        }

        inline void shutdown_executor(const std::shared_ptr<Executor>& ex) {
            if (!ex) return;
#if defined(MGHTTP_BACKEND_LIBUV)
            if (auto uv_ex = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(ex)) {
                uv_ex->shutdown();
                return;
            }
#endif
#if defined(MGHTTP_BACKEND_ASIO)
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

            RequestPhase phase{RequestPhase::Idle};

            // Held while the exchange is live so the stream outlives its callbacks.
            std::shared_ptr<AsyncByteStream> stream;

            // Self-hold until the terminal callback fires.
            std::shared_ptr<RequestState> self_hold;

            // Fires the terminal callback exactly once.
            void finish(Result<Response> result) {
                if (finished.exchange(true)) return;
                if (total_timer) total_timer->cancel();
                auto cb = std::move(on_complete);
                // Release the hold before the callback so a callback that
                // re-enters does not resurrect this state. The stream is closed
                // separately by async_close() and held alive by its own callback.
                self_hold.reset();
                if (cb) cb(std::move(result));
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

            // Start by sending the encoded head.
            void start(string head) {
                state_->phase = Detail::RequestPhase::SendHead;
                auto self = shared_from_this();
                auto stream = state_->stream;
                stream->async_write(
                    reinterpret_cast<const uint8_t*>(head.data()), head.size(),
                    [self](Result<size_t> w) {
                        if (!w) { self->fail(w.error()); return; }
                        self->send_body();
                    });
            }

            // Send body if present, then start reading the response.
            void send_body() {
                state_->phase = Detail::RequestPhase::SendBody;
                auto self = shared_from_this();
                auto stream = state_->stream;
                if (!state_->request.has_body() || state_->request.body_bytes().empty()) {
                    read_more();
                    return;
                }
                const auto& body = state_->request.body_bytes();
                stream->async_write(body.data(), body.size(),
                    [self](Result<size_t> w) {
                        if (!w) { self->fail(w.error()); return; }
                        self->read_more();
                    });
            }

            // --- ResponseParser::Callbacks ---
            VoidResult on_head(const ParsedResponse& head) override {
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

                sink_ = std::make_unique<BufferSink>(std::move(rh),
                                                     state_->options.max_response_body);
                return VoidResult{};
            }

            VoidResult on_body_data(const uint8_t* data, size_t size) override {
                if (!sink_) {
                    return Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                                 string("body data before response head")};
                }
                if (!sink_->append(data, size)) {
                    return Error{ErrorCode::HttpBodyTooLarge, ErrorPhase::Receive,
                                 string("response body exceeded max_response_body")};
                }
                return VoidResult{};
            }

            VoidResult on_trailers(const Headers&) override { return VoidResult{}; }

            VoidResult on_complete() override {
                complete_ = true;
                auto response = sink_ ? sink_->finish() : Response{};
                state_->finish(std::move(response));
                return VoidResult{};
            }
        private:
            void read_more() {
                auto self = shared_from_this();
                auto stream = state_->stream;
                stream->async_read_some(buf_, sizeof buf_,
                    [self](Result<size_t> r) {
                        if (!r) { self->fail(r.error()); return; }

                        const size_t n = r.value();
                        if (n == 0) {
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

                        self->state_->phase = Detail::RequestPhase::Receive;
                        auto res = self->parser_->feed(self->buf_, n);
                        if (!res) { self->fail(res.error()); return; }
                        if (self->complete_) return;
                        self->read_more();
                    });
            }

            void fail(const Error& e) {
                state_->fail(e);
            }

            std::shared_ptr<RequestState> state_;
            std::unique_ptr<ResponseParser> parser_;
            std::unique_ptr<BufferSink> sink_;
            bool complete_{false};
            uint8_t buf_[16 * 1024] = {0};
        };

        // Builds the request head for a direct (non-proxy) HTTP request.
        inline Result<string> build_request_head(const Request& req, const Url& url) {
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
            return encode_request_head(req.method(), req.custom_method(),
                                       to_view(url.request_target()), headers);
        }

    } // namespace Detail

    // ---------------------------------------------------------------------------
    // Client::Impl
    // ---------------------------------------------------------------------------
    class Client::Impl {
    public:
        explicit Impl(ClientOptions opts) : options(std::move(opts)) {
            executor = options.executor;
            owns_executor = (executor == nullptr);
            if (!executor) executor = Detail::make_default_executor();

            resolver = options.resolver;
            if (!resolver && executor) {
                resolver = std::make_shared<SystemResolver>(executor);
            }
        }

        ~Impl() { shutdown(); }

        void shutdown() {
            bool expected = false;
            if (!stopped.compare_exchange_strong(expected, true)) return;
            if (owns_executor) Detail::shutdown_executor(executor);
        }

        void submit(const Request& req,
                    Client::ResponseCallback on_complete,
                    const CancelHandle& handle,
                    std::shared_ptr<CancelState> cancel_state) {
            auto st = std::make_shared<Detail::RequestState>();
            st->self_hold = st;
            st->executor = executor;
            st->resolver = resolver;
            st->options = options;
            st->request = req;
            st->on_complete = std::move(on_complete);

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
                std::weak_ptr<Detail::RequestState> weak = st;
                st->total_timer = executor->schedule_after(options.total_timeout, [weak] {
                    auto s = weak.lock();
                    if (!s) return;
                    s->finish(Error{ErrorCode::TimeoutTotal, ErrorPhase::None,
                                    string("total request timeout")});
                });
            }

            // Cancellation is observed at the executor: the request is retired on
            // the loop thread, never from the cancelling caller's thread.
            std::weak_ptr<Detail::RequestState> weak = st;
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
        static void begin(const std::shared_ptr<Detail::RequestState>& st) {
            if (st->finished.load()) return;

            st->phase = Detail::RequestPhase::UrlParse;
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

            st->phase = Detail::RequestPhase::BuildHead;
            auto head = Detail::build_request_head(st->request, url);
            if (!head) { st->finish(head.error()); return; }

            std::weak_ptr<Detail::RequestState> weak = st;
            const string host = url.host;
            const uint16_t port = url.port;
            st->phase = Detail::RequestPhase::Resolve;
            st->resolver->resolve(host, port, [weak, head = std::move(head.value())](
                                           Result<AddressList> resolved) mutable {
                auto s = weak.lock();
                if (!s || s->finished.load()) return;

                if (!resolved) { s->finish(resolved.error()); return; }
                if (resolved.value().empty()) {
                    s->finish(Error{ErrorCode::DnsNoData, ErrorPhase::Resolve,
                                    string("resolver returned no address")});
                    return;
                }

                s->phase = Detail::RequestPhase::Connect;
                ConnectOptions copts;
                copts.connect_timeout = s->options.connect_timeout;
                auto addresses = std::move(resolved.value());

                std::weak_ptr<Detail::RequestState> w2 = s;
                connect_race(s->executor, std::move(addresses), copts,
                    [w2, head = std::move(head)](Result<std::shared_ptr<AsyncByteStream>> conn) mutable {
                        auto s2 = w2.lock();
                        if (!s2 || s2->finished.load()) {
                            // Race already retired: close a stream we no longer want.
                            if (conn && conn.value()) conn.value()->async_close(nullptr);
                            return;
                        }
                        if (!conn) { s2->finish(conn.error()); return; }

                        s2->stream = conn.value();
                        begin_exchange(s2, std::move(head));
                    });
            });
        }

        // Free of `this` so it can run from a detached async callback: the
        // request state carries everything the exchange needs.
        static void begin_exchange(const std::shared_ptr<Detail::RequestState>& st, string head) {
            // Order matters: the Exchange must exist before the parser (which
            // stores a reference to it), and the Exchange must keep itself alive
            // while the exchange is in flight. It does so via shared_from_this().
            auto exchange = std::make_shared<Detail::Exchange>(st);
            exchange->set_parser(std::make_unique<ResponseParser>(
                *exchange, st->options.parser_limits));
            exchange->start(std::move(head));
        }

    public:
        ClientOptions options;
        std::shared_ptr<Executor> executor;
        std::shared_ptr<Resolver> resolver;
        bool owns_executor{false};
        std::atomic<bool> stopped{false};
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

    inline const ClientOptions& Client::options() const noexcept { return impl_->options; }

} // namespace MegoHttp

#endif // MEGOHTTP_CLIENT_IMPL_HPP_INCLUDED
