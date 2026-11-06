#ifndef MEGOHTTP_TRANSPORT_LIBUV_IMPL_HPP_INCLUDED
#define MEGOHTTP_TRANSPORT_LIBUV_IMPL_HPP_INCLUDED

// Included from transport.hpp when MGHTTP_BACKEND_LIBUV is defined.

#include <cstring>

#if defined(_WIN32)
#   include <ws2tcpip.h>
#else
#   include <arpa/inet.h>
#endif

namespace megohttp {
namespace detail {

    // Builds a sockaddr from a ResolvedAddress. Returns the initialised size, or 0
    // when the family/byte-count combination is unusable.
    inline int to_sockaddr(const ResolvedAddress& addr, sockaddr_storage* out) {
        std::memset(out, 0, sizeof *out);
        if (addr.family == ResolvedAddress::Family::IPv4 && addr.bytes.size() == 4) {
            auto* v4 = reinterpret_cast<sockaddr_in*>(out);
            v4->sin_family = AF_INET;
            v4->sin_port = htons(addr.port);
            std::memcpy(&v4->sin_addr, addr.bytes.data(), 4);
            return static_cast<int>(sizeof(sockaddr_in));
        }
        if (addr.family == ResolvedAddress::Family::IPv6 && addr.bytes.size() == 16) {
            auto* v6 = reinterpret_cast<sockaddr_in6*>(out);
            v6->sin6_family = AF_INET6;
            v6->sin6_port = htons(addr.port);
            std::memcpy(&v6->sin6_addr, addr.bytes.data(), 16);
            return static_cast<int>(sizeof(sockaddr_in6));
        }
        return 0;
    }

} // namespace detail

    inline TcpStream::TcpStream(std::shared_ptr<Executor> executor,
                                const ResolvedAddress& address,
                                Duration connect_timeout)
        : address_(address) {
        executor_ = std::move(executor);
        auto uv_exec = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(executor_);
        if (uv_exec != nullptr) loop_ = uv_exec->loop();
        (void)connect_timeout;   // enforced by connect_race's shared deadline
    }

    inline TcpStream::~TcpStream() {
        if (loop_ == nullptr) return;
        closing_ = true;
        open_ = false;
        read_cb_ = nullptr;

        auto node = std::move(node_);
        if (!node) return;
        node->owner.reset();
        node->handle.data = node.get();

        auto uv_ex = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(executor_);
        if (uv_ex && !uv_ex->is_in_loop_thread()) {
            // uv_close/uv_read_stop are not thread-safe; hand the close to the
            // loop. The lambda owns the Node so it cannot die in transit.
            uv_ex->post([node = std::move(node)]() mutable {
                do_close(node.get());
                // `node` (and its self-hold) drops here, after do_close returned.
            });
        } else {
            do_close(node.get());
            // If do_close queued an async close, node->self keeps it alive; if the
            // handle was already closing, the Node dies here, which is fine.
        }
    }

    // Runs on the loop thread. Never frees the Node: on_closed owns that.
    inline void TcpStream::do_close(Node* node) {
        if (node == nullptr) return;
        auto* handle = reinterpret_cast<uv_handle_t*>(&node->handle);
        if (uv_is_closing(handle)) return;
        // Stop reading first: uv_close alone does not cancel an outstanding
        // uv_read_start, and libuv would still deliver data through on_read.
        uv_read_stop(reinterpret_cast<uv_stream_t*>(&node->handle));
        node->handle.data = node;
        uv_close(handle, &TcpStream::on_closed);
    }

    inline void TcpStream::close_on_loop(std::shared_ptr<Node> node) {
        if (!node) return;
        do_close(node.get());
    }

    inline void TcpStream::start(ReadyCallback on_ready) {
        ready_cb_ = std::move(on_ready);
        if (loop_ == nullptr) {
            if (auto cb = std::move(ready_cb_)) {
                cb(VoidResult{Error{ErrorCode::NotImplemented, ErrorPhase::TcpConnect,
                                    string("TcpStream requires a libuv executor")}});
            }
            return;
        }

        sockaddr_storage ss{};
        if (detail::to_sockaddr(address_, &ss) == 0) {
            if (auto cb = std::move(ready_cb_)) {
                cb(VoidResult{Error{ErrorCode::InvalidArgument, ErrorPhase::TcpConnect,
                                    string("unusable resolved address")}});
            }
            return;
        }

        node_ = std::make_shared<Node>();
        node_->self = node_;              // keeps the Node alive until on_closed
        node_->owner = weak_from_this();
        node_->handle.data = node_.get();

        uv_tcp_init(loop_, &node_->handle);

        node_->connect_req.data = node_.get();
        connecting_ = true;
        const int rc = uv_tcp_connect(&node_->connect_req, &node_->handle,
                                      reinterpret_cast<const sockaddr*>(&ss),
                                      &TcpStream::on_connect);
        if (rc < 0) {
            connecting_ = false;
            if (auto cb = std::move(ready_cb_)) {
                cb(VoidResult{Error{ErrorCode::ConnectFailed, ErrorPhase::TcpConnect,
                                    format("uv_tcp_connect failed: {}", uv_strerror(rc))}});
            }
        }
    }

    inline void TcpStream::on_connect(uv_connect_t* req, int status) {
        auto* node = static_cast<Node*>(req->data);
        if (node == nullptr) return;
        auto owner = node->owner.lock();
        if (!owner) return;
        owner->connecting_ = false;
        auto cb = std::move(owner->ready_cb_);
        if (!cb) return;   // already consumed: ignore a duplicate callback

        if (status < 0) {
            owner->open_ = false;
            cb(VoidResult{Error{ErrorCode::ConnectFailed, ErrorPhase::TcpConnect,
                                format("connect failed: {}", uv_strerror(status))}});
            return;
        }
        owner->open_ = true;
        cb(VoidResult{});
    }
    inline void TcpStream::async_read_some(ReadCallback cb) {
        if (!open_ || closing_) {
            if (cb) {
                cb(Error{ErrorCode::ConnectionClosed, ErrorPhase::Receive,
                         string("read on a closed stream")});
            }
            return;
        }
        if (read_cb_) {
            if (cb) {
                cb(Error{ErrorCode::InvalidArgument, ErrorPhase::Receive,
                         string("another read is already outstanding")});
            }
            return;
        }
        read_cb_ = std::move(cb);

        // The buffer comes from on_alloc (the Node's staging area), so libuv never
        // touches caller-owned memory.
        uv_read_start(reinterpret_cast<uv_stream_t*>(&node_->handle),
                      &TcpStream::on_alloc, &TcpStream::on_read);
    }

    inline void TcpStream::on_alloc(uv_handle_t* h, size_t, uv_buf_t* buf) {
        auto* node = static_cast<Node*>(h->data);
        if (node == nullptr) {
            buf->base = nullptr;
            buf->len = 0;
            return;
        }
        // Never hand libuv the caller's buffer. libuv fills this inside
        // uv__process_tcp_read_req, which can run after the owner released the
        // caller's destination (or after the owner is gone entirely). Staging in
        // the Node keeps the memory valid for as long as libuv needs it.
        buf->base = reinterpret_cast<char*>(node->read_stage);
        buf->len = static_cast<unsigned int>(sizeof node->read_stage);
    }

    inline void TcpStream::on_read(uv_stream_t* s, ssize_t nread, const uv_buf_t* buf) {
        auto* node = static_cast<Node*>(s->data);
        if (node == nullptr) return;

        uv_read_stop(s);
        auto owner = node->owner.lock();
        if (!owner) {
            // TcpStream is gone; drop the data. The Node still frees itself in
            // on_closed, so nothing leaks and nothing is touched here.
            return;
        }

        auto cb = std::move(owner->read_cb_);
        owner->read_cb_ = nullptr;

        if (nread < 0) {
            owner->open_ = false;
            if (cb) {
                if (nread == UV_EOF) {
                    cb(string_view{});          // empty view = clean EOF
                } else {
                    cb(Error{ErrorCode::ConnectionReset, ErrorPhase::Receive,
                             format("read failed: {}", uv_strerror(static_cast<int>(nread)))});
                }
            }
            return;
        }
        size_t n = static_cast<size_t>(nread);
        if (n > sizeof node->read_stage) n = sizeof node->read_stage;
        // The view points into the Node's staging buffer and is valid only for the
        // duration of this callback.
        if (cb) cb(string_view(reinterpret_cast<const char*>(node->read_stage), n));
    }

    inline void TcpStream::async_write(const uint8_t* data, size_t size, WriteCallback cb) {
        if (!open_ || closing_) {
            if (cb) {
                cb(Error{ErrorCode::ConnectionClosed, ErrorPhase::Send,
                         string("write on a closed stream")});
            }
            return;
        }
        if (write_) {
            if (cb) {
                cb(Error{ErrorCode::InvalidArgument, ErrorPhase::Send,
                         string("another write is already outstanding")});
            }
            return;
        }
        auto pending = std::make_shared<PendingWrite>();
        pending->bytes = std::make_shared<std::vector<uint8_t>>(data, data + size);
        pending->total = size;
        pending->cb = std::move(cb);
        write_ = std::move(pending);
        if (node_) node_->write_req.data = node_.get();
        resume_write();
    }

    inline void TcpStream::resume_write() {
        if (!write_ || !node_) return;
        // Point the uv_buf at the not-yet-written tail so a resumed write continues
        // where the previous one stopped.
        write_->buf = uv_buf_init(
            reinterpret_cast<char*>(write_->bytes->data() + write_->written),
            static_cast<unsigned int>(write_->total - write_->written));
        // The uv_write_t lives in the Node: libuv keeps it until the callback runs,
        // which can be after TcpStream is destroyed.
        const int rc = uv_write(&node_->write_req,
                                reinterpret_cast<uv_stream_t*>(&node_->handle),
                                &write_->buf, 1, &TcpStream::on_write);
        if (rc < 0) {
            auto pending = std::move(write_);
            if (pending && pending->cb) {
                pending->cb(Error{ErrorCode::ConnectionReset, ErrorPhase::Send,
                                  format("uv_write failed: {}", uv_strerror(rc))});
            }
        } else {
            // uv_write succeeded asynchronously; the callback will fire later.
        }
    }

    inline void TcpStream::on_write(uv_write_t* req, int status) {
        auto* node = static_cast<Node*>(req->data);
        if (node == nullptr) return;
        auto owner = node->owner.lock();
        if (!owner) return;
        auto pending = std::move(owner->write_);
        if (!pending) return;
        if (status < 0) {
            if (pending->cb) {
                pending->cb(Error{ErrorCode::ConnectionReset, ErrorPhase::Send,
                                  format("write failed: {}", uv_strerror(status))});
            }
            return;
        }
        if (pending->cb) pending->cb(pending->total);
    }

    inline void TcpStream::async_close(CloseCallback cb) {
        close_cb_ = std::move(cb);
        if (loop_ == nullptr || closing_ || !node_) {
            if (close_cb_) { auto c = std::move(close_cb_); c(); }
            return;
        }
        open_ = false;
        closing_ = true;
        node_->owner = weak_from_this();      // on_closed still needs to notify us
        node_->handle.data = node_.get();

        auto uv_ex = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(executor_);
        if (uv_ex && !uv_ex->is_in_loop_thread()) {
            auto node = node_;
            uv_ex->post([node] { do_close(node.get()); });
        } else {
            do_close(node_.get());
        }
    }

    inline void TcpStream::on_closed(uv_handle_t* h) {
        auto* node = static_cast<Node*>(h->data);
        if (node == nullptr) return;
        h->data = nullptr;

        // Deliver pending read/write/close notifications while the owner can still
        // be reached; libuv already cancelled any outstanding requests.
        if (auto owner = node->owner.lock()) {
            owner->close_notified_ = true;
            if (owner->read_cb_) {
                auto rd = std::move(owner->read_cb_);
                rd(Error{ErrorCode::ConnectionClosed, ErrorPhase::Receive,
                         string("stream closed")});
            }
            if (owner->write_ && owner->write_->cb) {
                auto wr = std::move(owner->write_);
                wr->cb(Error{ErrorCode::ConnectionClosed, ErrorPhase::Send,
                             string("stream closed")});
            }
            if (owner->close_cb_) {
                auto c = std::move(owner->close_cb_);
                c();
            }
        }

        // node->self is the Node's last owner. Moving it into a local defers the
        // destruction until after this frame returns, which is exactly what
        // uv_close requires ("memory can only be released in close_cb or after
        // it has returned").
        auto keep = std::move(node->self);
    }

    inline bool TcpStream::is_open() const noexcept { return open_ && !closing_; }

    inline void TcpStream::set_keep_alive(bool enable, Duration idle) {
        if (loop_ == nullptr || !node_) return;
        const unsigned secs = static_cast<unsigned>(
            std::chrono::duration_cast<std::chrono::seconds>(idle).count());
        uv_tcp_keepalive(&node_->handle, enable ? 1 : 0, secs);
    }

    inline void TcpStream::set_no_delay(bool enable) {
        if (loop_ == nullptr || !node_) return;
        uv_tcp_nodelay(&node_->handle, enable ? 1 : 0);
    }

    // ---------------------------------------------------------------------------
    // connect_race
    //
    // Satisfies spec 5.4.3: more than the first address is tried; the families are
    // raced so an unreachable IPv6 does not block IPv4; one address's failure does
    // not end the race; exactly one connection wins and every loser is closed; the
    // whole race shares ONE deadline; a late success from a loser is closed rather
    // than leaked.
    // ---------------------------------------------------------------------------
    namespace detail {

        struct RaceState {
            std::shared_ptr<Executor> executor;
            AddressList addresses;
            ConnectOptions options;
            std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> on_done;

            std::atomic<bool> finished{false};
            std::atomic<size_t> remaining{0};
            std::shared_ptr<Timer> deadline_timer;

            std::mutex m;
            Error last_error{ErrorCode::ConnectFailed, ErrorPhase::TcpConnect,
                             string("no attempt succeeded")};
            // Losers that connected after the race was decided are parked here so
            // they are not destroyed while a callback still references them.
            std::vector<std::shared_ptr<AsyncByteStream>> losers;

            // Self-hold: every participant (deadline timer, per-address attempt and
            // its connect callback) reaches the state through a weak_ptr, so without
            // this the state would die the moment connect_race() returns and its
            // local shared_ptr goes out of scope. Released in race_finish().
            std::shared_ptr<RaceState> self_hold;
        };

        // Decides the race outcome. Does NOT release the self-hold: attempts that
        // are still in flight must be able to come back through the loser path,
        // and they need `st` to still be alive to do it. The LAST attempt to
        // report (remaining hits 0) releases the hold; see connect_race().
        inline void race_finish(const std::shared_ptr<RaceState>& st,
                                Result<std::shared_ptr<AsyncByteStream>> result) {
            if (st->finished.exchange(true)) {
                // Somebody already won: a live stream reported now is a loser.
                // It really did connect, so its socket must be closed or the
                // peer keeps a half-open connection and we leak a descriptor.
                if (result.has_value() && result.value()) {
                    auto extra = result.value();
                    {
                        std::lock_guard<std::mutex> lk(st->m);
                        st->losers.push_back(extra);
                    }
                    extra->async_close(nullptr);
                }
                return;
            }
            if (st->deadline_timer) st->deadline_timer->cancel();
            auto cb = std::move(st->on_done);
            if (cb) cb(std::move(result));
        }

        // Prefer one family but INTERLEAVE the two: that interleaving is what lets
        // a working IPv4 attempt overtake a broken IPv6 one.
        inline AddressList interleave_by_family(AddressList in,
                                                ConnectOptions::FamilyPreference pref) {
            if (in.size() < 2) return in;
            std::vector<ResolvedAddress> v4, v6;
            for (auto& a : in) {
                if (a.family == ResolvedAddress::Family::IPv6) v6.push_back(std::move(a));
                else v4.push_back(std::move(a));
            }
            const bool v6_first =
                (pref == ConnectOptions::FamilyPreference::PreferIPv6) ||
                (pref == ConnectOptions::FamilyPreference::Unspecified && !v6.empty());

            AddressList out;
            out.reserve(v4.size() + v6.size());
            size_t i = 0, j = 0;
            while (i < v6.size() || j < v4.size()) {
                if (v6_first) {
                    if (i < v6.size()) out.push_back(std::move(v6[i++]));
                    if (j < v4.size()) out.push_back(std::move(v4[j++]));
                } else {
                    if (j < v4.size()) out.push_back(std::move(v4[j++]));
                    if (i < v6.size()) out.push_back(std::move(v6[i++]));
                }
            }
            return out;
        }

    } // namespace detail

    inline void connect_race(
        std::shared_ptr<Executor> executor,
        AddressList addresses,
        const ConnectOptions& options,
        std::function<void(Result<std::shared_ptr<AsyncByteStream>>)> on_done) {

        if (addresses.empty()) {
            if (on_done) {
                on_done(Error{ErrorCode::ConnectFailed, ErrorPhase::TcpConnect,
                              string("no address to connect to")});
            }
            return;
        }

        auto st = std::make_shared<detail::RaceState>();
        st->self_hold = st;        // released in race_finish(); see RaceState
        st->executor = executor;
        st->options = options;
        st->on_done = std::move(on_done);
        st->addresses = detail::interleave_by_family(std::move(addresses), options.preference);
        st->remaining.store(st->addresses.size());

        // ONE deadline for the whole race: the connection phase gets a single
        // budget, not a fresh one per address.
        std::weak_ptr<detail::RaceState> weak = st;
        st->deadline_timer = executor->schedule_after(
            options.connect_timeout,
            [weak] {
                auto s = weak.lock();
                if (!s) return;
                detail::race_finish(s, Error{ErrorCode::ConnectTimeout,
                                             ErrorPhase::TcpConnect,
                                             string("connection race timed out")});
                // A timeout retires the race, but in-flight attempts still have to
                // report. Do not release the hold here; the last one does.
                if (s->remaining.load() == 0) s->self_hold.reset();
            });

        for (size_t i = 0; i < st->addresses.size(); ++i) {
            const ResolvedAddress address = st->addresses[i];
            // attempt_delay * i: the first attempt has NO delay, but
            // schedule_after(0) relies on the timer firing immediately, which some
            // event loops defer. Issue the first one through post() instead so it
            // always runs on the next loop turn.
            const Duration delay = options.attempt_delay * static_cast<int64_t>(i);
            auto attempt = [weak, address] {
                auto s = weak.lock();
                if (!s || s->finished.load()) return;

                auto stream = std::make_shared<TcpStream>(s->executor, address,
                                                          s->options.connect_timeout);
                // The lambda captures `stream` by value, so the stream outlives the
                // attempt and is handed to the winner path intact.
                stream->start([weak, stream](VoidResult ready) mutable {
                    auto s2 = weak.lock();
                    if (!s2) return;

                    if (!ready) {
                        {
                            std::lock_guard<std::mutex> lk(s2->m);
                            s2->last_error = ready.error();
                        }
                        if (s2->remaining.fetch_sub(1) == 1) {
                            Error e;
                            {
                                std::lock_guard<std::mutex> lk(s2->m);
                                e = s2->last_error;
                            }
                            detail::race_finish(s2, e);
                            s2->self_hold.reset();
                        }
                        return;
                    }
                    std::shared_ptr<AsyncByteStream> as_stream = stream;
                    const bool last = (s2->remaining.fetch_sub(1) == 1);
                    detail::race_finish(s2, std::move(as_stream));
                    // Released here, by the last attempt, not inside race_finish:
                    // a late attempt must still find `st` alive to reach the
                    // loser path above.
                    if (last) s2->self_hold.reset();
                });
            };

            if (delay == Duration::zero()) {
                executor->post(attempt);
            } else {
                executor->schedule_after(delay, attempt);
            }
        }
    }

} // namespace megohttp

#endif // MEGOHTTP_TRANSPORT_LIBUV_IMPL_HPP_INCLUDED
