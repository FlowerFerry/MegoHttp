#ifndef MEGOHTTP_BACKEND_TRANSPORT_ASIO_IMPL_HPP_INCLUDED
#define MEGOHTTP_BACKEND_TRANSPORT_ASIO_IMPL_HPP_INCLUDED

// standalone Asio implementation of TcpStream + connect_race.
//
// The same contract as the libuv backend: one outstanding read and one
// outstanding write at a time; every callback fires on the strand (the asio
// analogue of the libuv loop thread); the caller issues stream operations from
// within a post() so no thread-safety assumption is needed at the call site.
#include <megohttp/transport.hpp>
#include <megohttp/backend/executor_asio.hpp>

#if !defined(MGHTTP_BACKEND_ASIO)
#   error "transport_asio_impl.hpp requires MGHTTP_BACKEND_ASIO"
#endif

#include <asio.hpp>
#include <asio/ip/tcp.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

namespace MegoHttp {

    // --- TcpStream ------------------------------------------------------------
    inline TcpStream::TcpStream(std::shared_ptr<Executor> executor,
                                const ResolvedAddress& address,
                                Duration connect_timeout)
        : address_(address) {
        executor_ = std::move(executor);
        auto asio_exec = std::dynamic_pointer_cast<asio_backend::AsioExecutor>(executor_);
        if (asio_exec != nullptr) ioc_ = asio_exec->context();
        (void)connect_timeout;   // enforced by connect_race's shared deadline
    }

    inline TcpStream::~TcpStream() {
        if (ioc_ != nullptr && !closing_ && socket_ && socket_->is_open()) {
            closing_ = true;
            asio::error_code ec;
            socket_->close(ec);
        }
    }

    inline void TcpStream::start(ReadyCallback on_ready) {
        ready_cb_ = std::move(on_ready);
        if (ioc_ == nullptr) {
            if (auto cb = std::move(ready_cb_)) {
                cb(VoidResult{Error{ErrorCode::NotImplemented, ErrorPhase::TcpConnect,
                                    string("TcpStream requires an Asio executor")}});
            }
            return;
        }

        asio::ip::tcp::endpoint ep;
        if (address_.family == ResolvedAddress::Family::IPv4 &&
            address_.bytes.size() == 4) {
            asio::ip::address_v4::bytes_type b{};
            std::memcpy(b.data(), address_.bytes.data(), 4);
            ep = asio::ip::tcp::endpoint(asio::ip::address_v4(b), address_.port);
        } else if (address_.family == ResolvedAddress::Family::IPv6 &&
                   address_.bytes.size() == 16) {
            asio::ip::address_v6::bytes_type b{};
            std::memcpy(b.data(), address_.bytes.data(), 16);
            ep = asio::ip::tcp::endpoint(asio::ip::address_v6(b), address_.port);
        } else {
            if (auto cb = std::move(ready_cb_)) {
                cb(VoidResult{Error{ErrorCode::InvalidArgument, ErrorPhase::TcpConnect,
                                    string("unusable resolved address")}});
            }
            return;
        }

        socket_ = std::make_unique<asio::ip::tcp::socket>(*ioc_);
        socket_->open(ep.protocol());
        socket_->async_connect(ep,
            [self = shared_from_this()](const asio::error_code& ec) {
                on_connect(std::move(self), ec);
            });
    }

    inline void TcpStream::on_connect(std::shared_ptr<TcpStream> self,
                                      const asio::error_code& ec) {
        auto cb = std::move(self->ready_cb_);
        if (!cb) return;

        if (ec) {
            self->open_ = false;
            cb(VoidResult{Error{ErrorCode::ConnectFailed, ErrorPhase::TcpConnect,
                                format("connect failed: {}", ec.message())}});
            return;
        }
        self->open_ = true;
        cb(VoidResult{});
    }

    inline void TcpStream::async_read_some(uint8_t* buf, size_t size, ReadCallback cb) {
        if (!open_ || closing_) {
            if (cb) cb(Error{ErrorCode::ConnectionClosed, ErrorPhase::Receive,
                             string("read on a closed stream")});
            return;
        }
        if (read_cb_) {
            if (cb) cb(Error{ErrorCode::InvalidArgument, ErrorPhase::Receive,
                             string("another read is already outstanding")});
            return;
        }
        read_dst_ = buf;
        read_cap_ = size;
        read_cb_ = std::move(cb);

        // Capture self so the socket outlives the async op.
        asio::mutable_buffer mb(buf, size);
        socket_->async_read_some(mb,
            [self = shared_from_this()](const asio::error_code& ec, size_t n) {
                on_read(std::move(self), ec, n);
            });
    }

    inline void TcpStream::on_read(std::shared_ptr<TcpStream> self,
                                   const asio::error_code& ec, size_t n) {
        self->read_dst_ = nullptr;
        self->read_cap_ = 0;
        auto cb = std::move(self->read_cb_);
        self->read_cb_ = nullptr;

        if (ec) {
            if (ec == asio::error::eof || ec == asio::error::connection_reset) {
                self->open_ = false;
                if (cb) cb(0);   // 0 bytes = clean EOF
            } else {
                self->open_ = false;
                if (cb) {
                    cb(Error{ErrorCode::ConnectionReset, ErrorPhase::Receive,
                             format("read error: {}", ec.message())});
                }
            }
            return;
        }
        if (cb) cb(n);
    }

    inline void TcpStream::async_write(const uint8_t* data, size_t size, WriteCallback cb) {
        if (!open_ || closing_) {
            if (cb) cb(Error{ErrorCode::ConnectionClosed, ErrorPhase::Send,
                             string("write on a closed stream")});
            return;
        }
        if (write_) {
            if (cb) cb(Error{ErrorCode::InvalidArgument, ErrorPhase::Send,
                             string("another write is already outstanding")});
            return;
        }
        auto pw = std::make_shared<PendingWrite>();
        pw->bytes = std::make_shared<std::vector<uint8_t>>(data, data + size);
        pw->total = size;
        pw->cb = std::move(cb);
        write_ = pw;
        resume_write();
    }

    inline void TcpStream::resume_write() {
        if (!write_) return;
        const uint8_t* base = write_->bytes->data() + write_->written;
        size_t remain = write_->total - write_->written;
        asio::const_buffer cb(base, remain);
        asio::async_write(*socket_, cb,
            [self = shared_from_this()](const asio::error_code& ec, size_t n) {
                on_write(std::move(self), ec, n);
            });
    }

    inline void TcpStream::on_write(std::shared_ptr<TcpStream> self,
                                    const asio::error_code& ec, size_t n) {
        auto pw = std::move(self->write_);
        if (!pw) return;

        if (ec) {
            self->open_ = false;
            if (pw->cb) {
                pw->cb(Error{ErrorCode::ConnectionReset, ErrorPhase::Send,
                             format("write error: {}", ec.message())});
            }
            return;
        }
        pw->written += n;
        if (pw->written < pw->total) {
            // Partial write: schedule the remainder.
            self->write_ = std::move(pw);
            self->resume_write();
            return;
        }
        if (pw->cb) pw->cb(pw->total);
    }

    inline void TcpStream::async_close(CloseCallback cb) {
        closing_ = true;
        close_cb_ = std::move(cb);
        if (socket_ && socket_->is_open()) {
            asio::error_code ec;
            socket_->close(ec);
        }
        open_ = false;
        if (close_cb_) close_cb_();
    }

    inline bool TcpStream::is_open() const noexcept { return open_; }

    inline void TcpStream::set_keep_alive(bool enable, Duration) {
        if (ioc_ == nullptr) return;
        asio::error_code ec;
        socket_->set_option(asio::socket_base::keep_alive(enable), ec);
    }

    inline void TcpStream::set_no_delay(bool enable) {
        if (ioc_ == nullptr) return;
        asio::error_code ec;
        socket_->set_option(asio::ip::tcp::no_delay(enable), ec);
    }

    // --- connect_race (same structure as the libuv backend) ------------------
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
            std::vector<std::shared_ptr<AsyncByteStream>> losers;

            // Self-hold: every participant (deadline timer, per-address attempt and
            // its connect callback) reaches the state through a weak_ptr, so without
            // this the state would die the moment connect_race() returns and its
            // local shared_ptr goes out of scope. Released in race_finish().
            std::shared_ptr<RaceState> self_hold;
        };

        inline void race_finish(const std::shared_ptr<RaceState>& st,
                                Result<std::shared_ptr<AsyncByteStream>> result) {
            if (st->finished.exchange(true)) {
                // Somebody already won: a live stream reported now is a loser.
                // It really did connect, so its socket must be closed or the peer
                // keeps a half-open connection and we leak a descriptor.
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
        st->self_hold = st;
        st->executor = executor;
        st->options = options;
        st->on_done = std::move(on_done);
        st->addresses = detail::interleave_by_family(std::move(addresses), options.preference);
        st->remaining.store(st->addresses.size());

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
            const Duration delay = options.attempt_delay * static_cast<int64_t>(i);
            auto attempt = [weak, address] {
                auto s = weak.lock();
                if (!s || s->finished.load()) return;

                auto stream = std::make_shared<TcpStream>(s->executor, address,
                                                          s->options.connect_timeout);
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

} // namespace MegoHttp

#endif
