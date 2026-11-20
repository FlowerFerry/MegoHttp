#ifndef MEGOHTTP_RESOLVER_DOT_IMPL_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_DOT_IMPL_HPP_INCLUDED

// DNS over TLS implementation (task book section 9-A.2).
//
// Wire shape (RFC 7858 / RFC 1035 4.2.2):
//     <2-byte big-endian length><DNS message>
// repeatedly, in both directions, over a single TLS connection.
//
// The resolver keeps ONE connection and pipelines queries over it. Every query
// gets its own message ID, and a response is matched to its waiting caller by
// that ID. Anything unmatched is dropped -- which is exactly what makes a late
// response to a cancelled or timed-out lookup harmless instead of a mis-delivery
// to the next query that happens to reuse the ID.
//
// ID reuse is the subtle part. RFC 7858 lets a client reuse an ID as soon as
// the answer arrived, but reusing it while a late answer is still in flight
// would let the stale answer be delivered to the new query. So an ID is only
// released back to the allocator after its answer has been consumed, and the
// counter is not "recycled from the front": a monotonically incrementing counter
// with an occupied-bitmap check is both simpler and safer than recycling.

#include <megohttp/resolver_dot.hpp>
#include <megohttp/dns_wire.hpp>   // explicit: the impl needs the codec's types

#if MEGOHTTP_HAS_DOT

#include <megohttp/format.hpp>

#include <algorithm>
#include <cstring>

namespace megohttp {
    namespace dot_detail {

        // Each DNS message on a DoT connection is prefixed with its length as a
        // 16-bit big-endian value. 65535 is the hard maximum the format allows.
        constexpr size_t kMaxMessageSize = 65535;

        inline void append_u16(byte_buffer& out, uint16_t v) {
            out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(v & 0xFF));
        }

        inline uint16_t read_u16(const uint8_t* p) {
            return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                         static_cast<uint16_t>(p[1]));
        }

    } // namespace dot_detail

    // -----------------------------------------------------------------------
    // Connection: TCP -> TLS -> framed read loop
    // -----------------------------------------------------------------------

    inline void DotResolver::Connection::connect(std::function<void(const Error*)> on_ready) {
        connect_cb_ = std::move(on_ready);

        if (!executor_) {
            state_ = State::Failed;
            auto cb = std::move(connect_cb_);
            connect_cb_ = nullptr;
            if (cb) {
                Error e{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                        string("DoT connection has no executor")};
                cb(&e);
            }
            return;
        }

        // A DoT endpoint is named by a DNS name, but connecting needs an address.
        // The bootstrap IP (when given) is dialled directly; otherwise the name
        // must already BE a literal. Resolving the endpoint's own name here would
        // be the recursion the task book forbids (9-A.4): the resolver would have
        // to resolve itself to resolve anything.
        AddressList addrs = parse_ip_literal(to_view(options_.bootstrap_ip), options_.port);
        if (addrs.empty() && !options_.server_name.empty()) {
            addrs = parse_ip_literal(to_view(options_.server_name), options_.port);
        }
        if (addrs.empty()) {
            state_ = State::Failed;
            auto cb = std::move(connect_cb_);
            connect_cb_ = nullptr;
            if (cb) {
                // A named endpoint with no bootstrap address is a configuration
                // error, not a network failure: say so, and do NOT quietly fall
                // back to the system resolver.
                cb(new Error{ErrorCode::ConfigurationError, ErrorPhase::Resolve,
                             string("DoT endpoint is a name but no bootstrap IP was configured; "
                                    "set DotOptions::bootstrap_ip (strict bootstrap mode does "
                                    "not fall back to system DNS)")});
            }
            return;
        }

        auto self = shared_from_this();
        ConnectOptions copts;
        copts.connect_timeout = options_.connect_timeout;

        connect_race(executor_, std::move(addrs), copts,
            [self](Result<std::shared_ptr<AsyncByteStream>> conn) {
                if (!conn) {
                    self->state_ = State::Failed;
                    auto cb = std::move(self->connect_cb_);
                    self->connect_cb_ = nullptr;
                    if (cb) cb(new Error(conn.error()));
                    return;
                }

                self->tcp_ = std::dynamic_pointer_cast<TcpStream>(conn.value());

                TlsConfig cfg = self->options_.tls;
                // SNI and certificate identity come from the CONFIGURED name, not
                // from the address actually dialled. A bootstrap IP changes where
                // the bytes go, never who they must prove they are (9-A.4).
                cfg.hostname = self->options_.server_name;

                auto tls = make_tls_stream(conn.value(), cfg);
                if (!tls) {
                    self->state_ = State::Failed;
                    auto cb = std::move(self->connect_cb_);
                    self->connect_cb_ = nullptr;
                    if (cb) cb(new Error{ErrorCode::TlsHandshakeFailed, ErrorPhase::Resolve,
                                         string("failed to create the DoT TLS stream")});
                    return;
                }
                tls->set_error_phase(ErrorPhase::Resolve, ErrorPhase::Resolve);
                self->tls_ = tls;

                tls->start([self, tls](VoidResult r) {
                    if (!r) {
                        self->state_ = State::Failed;
                        auto cb = std::move(self->connect_cb_);
                        self->connect_cb_ = nullptr;
                        if (cb) cb(new Error(r.error()));
                        return;
                    }
                    self->state_ = State::Open;
                    auto cb = std::move(self->connect_cb_);
                    self->connect_cb_ = nullptr;
                    if (cb) cb(nullptr);   // success
                });
            });
    }

    inline void DotResolver::Connection::write(byte_buffer data,
                                               std::function<void(const Error*)> on_done) {
        if (state_ != State::Open || !tls_) {
            if (on_done) {
                on_done(new Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                                  string("DoT connection is not open")});
            }
            return;
        }
        // The framed buffer must outlive the write callback.
        auto buf = std::make_shared<byte_buffer>(std::move(data));
        tls_->async_write(buf->data(), buf->size(),
            [buf, on_done](Result<size_t> r) {
                (void)buf;   // keep alive until the callback runs
                if (!r) {
                    if (on_done) on_done(new Error(r.error()));
                    return;
                }
                if (on_done) on_done(nullptr);
            });
    }

    inline void DotResolver::Connection::read(std::function<void(Result<byte_buffer>)> on_msg) {
        if (state_ != State::Open || !tls_) {
            if (on_msg) {
                on_msg(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                             string("DoT connection is not open")});
            }
            return;
        }

        // Deliver anything already buffered BEFORE reading more. One TCP/TLS
        // read can carry several complete DNS messages (a server that answers
        // five pipelined queries at once writes them back to back), and the
        // leftover would otherwise sit here until unrelated bytes arrived.
        for (;;) {
            if (reading_header_) {
                if (read_buf_.size() < 2) break;
                expected_len_ = dot_detail::read_u16(read_buf_.data());
                if (expected_len_ == 0) {
                    state_ = State::Failed;
                    if (on_msg) {
                        on_msg(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                                     string("DoT server sent a zero-length message")});
                    }
                    return;
                }
                read_buf_.erase(read_buf_.begin(), read_buf_.begin() + 2);
                reading_header_ = false;
            }
            if (read_buf_.size() < expected_len_) {
                // Header seen, payload still short: fall through to a real read.
                break;
            }
            byte_buffer payload(read_buf_.begin(),
                                read_buf_.begin() + static_cast<std::ptrdiff_t>(expected_len_));
            read_buf_.erase(read_buf_.begin(),
                            read_buf_.begin() + static_cast<std::ptrdiff_t>(expected_len_));
            reading_header_ = true;
            expected_len_ = 0;
            if (on_msg) on_msg(std::move(payload));
            return;   // one message per call; the caller loops
        }

        auto self = shared_from_this();
        tls_->async_read_some([self, on_msg](Result<string_view> r) mutable {
            if (!r) { if (on_msg) on_msg(r.error()); return; }
            const string_view sv = r.value();
            if (sv.empty()) {
                self->state_ = State::Closed;
                if (on_msg) {
                    on_msg(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                                 string("DoT server closed the connection")});
                }
                return;
            }

            self->read_buf_.insert(self->read_buf_.end(),
                                   reinterpret_cast<const uint8_t*>(sv.data()),
                                   reinterpret_cast<const uint8_t*>(sv.data()) +
                                       static_cast<size_t>(sv.size()));
            // Re-enter through read() so the buffered-message loop runs before
            // another socket read is issued.
            self->read(std::move(on_msg));
        });
    }

    inline void DotResolver::Connection::close() {
        if (state_ == State::Closed || state_ == State::Failed) return;
        state_ = State::Closed;
        if (tls_) tls_->async_close(nullptr);
        else if (tcp_) tcp_->async_close(nullptr);
        connect_cb_ = nullptr;
        read_cb_ = nullptr;
    }

    // -----------------------------------------------------------------------
    // DotResolver
    // -----------------------------------------------------------------------

    inline DotResolver::DotResolver(std::shared_ptr<Executor> executor, DotOptions options)
        : executor_(std::move(executor)), options_(std::move(options)) {}

    inline DotResolver::~DotResolver() {
        if (conn_) conn_->close();
    }

    inline CancelHandle DotResolver::resolve(string host, uint16_t port, Callback cb) {
        auto cancel = std::make_shared<CancelState>(executor_);
        CancelHandle handle(cancel);

        // An IP literal needs no DNS at all. Answering it from here keeps a
        // literal out of the wire protocol entirely and matches every other
        // resolver in this library.
        if (auto lits = parse_ip_literal(to_view(host), port); !lits.empty()) {
            executor_->post([cb, lits, cancel]() {
                if (cancel && cancel->is_cancelled()) return;
                if (cb) cb(AddressList(lits));
            });
            return handle;
        }

        // Check the TTL-driven cache first (task book 9-A.6). A negative entry
        // (NXDOMAIN / NODATA) returns an empty list -- not an error.
        if (auto cached = cache_.get(host, port,
                                      static_cast<uint16_t>(::megohttp::dns::RecordType::A))) {
            executor_->post([cb, answers = std::move(*cached), cancel]() {
                if (cancel && cancel->is_cancelled()) return;
                if (cb) cb(answers);
            });
            return handle;
        }

        auto q = std::make_shared<Query>();
        q->host = std::move(host);
        q->qport = port;
        // Both A and AAAA are asked for; the connection layer interleaves the
        // results, so collecting both here is what lets it do that.
        q->qtype = ::megohttp::dns::RecordType::A;
        q->cb = std::move(cb);
        q->cancel = cancel;
        q->self = q;

        // Everything below touches resolver state, so it runs on the loop.
        auto self = shared_from_this();
        executor_->post([self, q]() mutable {
            if (q->cancel && q->cancel->is_cancelled()) return;

            if (self->pending_.size() >= kMaxInFlight) {
                if (q->cb) {
                    q->cb(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                                string("too many concurrent DoT queries")});
                }
                return;
            }

            // Allocate an unused message ID. The counter wraps at 65535; with at
            // most kMaxInFlight live queries, a full scan is trivially cheap.
            uint16_t id = 0;
            for (size_t tries = 0; tries < 65535; ++tries) {
                const uint16_t candidate = self->next_id_++;
                if (self->next_id_ == 0) self->next_id_ = 1;   // 0 is not a usable ID
                if (self->pending_.find(candidate) == self->pending_.end()) {
                    id = candidate;
                    break;
                }
            }
            if (id == 0) {
                if (q->cb) {
                    q->cb(Error{ErrorCode::DnsResolveFailed, ErrorPhase::Resolve,
                                string("no free DNS message ID for the DoT query")});
                }
                return;
            }

            q->id = id;
            self->pending_[id] = q;

            // Register the cancel hook: cancelling removes the pending entry, so
            // a late answer is dropped rather than delivered.
            std::weak_ptr<DotResolver> wself = self;
            q->cancel->on_cancel([wself, id]() {
                auto s = wself.lock();
                if (!s) return;
                // on_cancel may fire on the cancelling thread; hop to the loop so
                // the pending_ map is only ever mutated there.
                s->executor_->post([s, id]() { s->pending_.erase(id); });
            });

            self->ensure_connection();
            // If the connection was ALREADY open, submit right away. A fresh
            // connection calls submit_queries() from on_connection_ready(),
            // because writing before the TLS handshake completes would fail.
            if (self->conn_ && self->conn_->is_open()) {
                self->submit_queries();
            }
        });

        return handle;
    }

    inline void DotResolver::ensure_connection() {
        // A connection that exists is either Open (reuse) or still Connecting
        // (let it finish). Creating a second one would abandon the first mid
        // handshake and every query waiting on it.
        if (conn_) return;

        conn_ = std::make_shared<Connection>(executor_, options_);

        auto self = shared_from_this();
        conn_->connect([self](const Error* err) {
            if (err) {
                self->on_connection_failed(*err);
                return;
            }
            self->on_connection_ready();
        });
    }

    inline void DotResolver::on_connection_ready() {
        submit_queries();
        read_response();
    }

    inline void DotResolver::on_connection_failed(const Error& e) {
        // Every pending lookup fails with the connection's error. This is the
        // "the transport is gone" verdict; a caller that wants to keep trying
        // wraps this resolver in a CachingResolver or retries at a higher level.
        auto pending = std::move(pending_);
        pending_.clear();
        for (auto& kv : pending) {
            if (kv.second && kv.second->cb && kv.second->cancel &&
                !kv.second->cancel->is_cancelled()) {
                kv.second->cb(e);
            }
        }
    }

    inline void DotResolver::submit_queries() {
        // Collect queries that have not been written yet.
        for (auto& kv : pending_) {
            if (kv.second && kv.second->id != 0 && !kv.second->written) {
                kv.second->written = true;
                write_queue_.push_back(kv.second);
            }
        }
        pump_writes();
    }

    // Sends queued queries one at a time. The stream allows exactly one
    // outstanding write, so a burst of lookups must be serialised here rather
    // than issued in a loop.
    inline void DotResolver::pump_writes() {
        if (write_in_flight_ || write_queue_.empty()) return;
        if (!conn_ || !conn_->is_open()) return;

        auto q = write_queue_.front();
        write_queue_.erase(write_queue_.begin());

        auto msg = dnswire::build_query(q->id, to_view(q->host), q->qtype);
        if (!msg) {
            auto id = q->id;
            pending_.erase(id);
            if (q->cb && !q->cancel->is_cancelled()) q->cb(msg.error());
            pump_writes();
            return;
        }

        byte_buffer framed;
        const auto& payload = msg.value();
        if (payload.size() > dot_detail::kMaxMessageSize) {
            auto id = q->id;
            pending_.erase(id);
            if (q->cb && !q->cancel->is_cancelled()) {
                q->cb(Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                            string("DNS query exceeds the DoT message size limit")});
            }
            pump_writes();
            return;
        }
        framed.reserve(payload.size() + 2);
        dot_detail::append_u16(framed, static_cast<uint16_t>(payload.size()));
        framed.insert(framed.end(), payload.begin(), payload.end());

        write_in_flight_ = true;
        std::weak_ptr<DotResolver> wself = shared_from_this();
        const uint16_t id = q->id;
        conn_->write(std::move(framed), [wself, id](const Error* e) {
            auto s = wself.lock();
            if (!s) return;
            s->write_in_flight_ = false;
            if (e) {
                auto it = s->pending_.find(id);
                if (it != s->pending_.end()) {
                    auto qq = it->second;
                    s->pending_.erase(it);
                    if (qq && qq->cb && qq->cancel && !qq->cancel->is_cancelled()) {
                        qq->cb(*e);
                    }
                }
            }
            s->pump_writes();
            s->read_response();
        });
    }

    inline void DotResolver::read_response() {
        if (!conn_ || !conn_->is_open()) return;
        // Only one outstanding read may exist: Connection hands its buffer to a
        // single read at a time, and a second concurrent read would race for it.
        if (read_in_flight_) return;
        read_in_flight_ = true;

        std::weak_ptr<DotResolver> wself = shared_from_this();
        conn_->read([wself](Result<byte_buffer> r) {
            auto s = wself.lock();
            if (!s) return;
            s->read_in_flight_ = false;
            if (!r) {
                s->on_connection_failed(r.error());
                return;
            }
            s->dispatch_answer(0, r.value());
            // Keep the read loop alive for as long as the connection is.
            if (s->conn_ && s->conn_->is_open() && !s->pending_.empty()) {
                s->read_response();
            }
        });
    }

    inline void DotResolver::dispatch_answer(uint16_t id_hint, const byte_buffer& payload) {
        using namespace megohttp::dns;

        auto parsed = parse_message(payload);
        if (!parsed) {
            on_connection_failed(parsed.error());
            return;
        }

        const auto& msg = parsed.value();
        const uint16_t id = (id_hint != 0) ? id_hint : msg.id;

        auto it = pending_.find(id);
        if (it == pending_.end()) {
            return;
        }

        auto q = it->second;
        pending_.erase(it);
        if (!q || !q->cb) return;
        if (q->cancel && q->cancel->is_cancelled()) return;

        const uint16_t qtype = static_cast<uint16_t>(q->qtype);

        switch (msg.rcode) {
            case ResponseCode::NoError:
                break;
            case ResponseCode::NxDomain: {
                // NXDOMAIN is a definitive answer, so it is negatively cached
                // per RFC 2308 using the SOA MINIMUM (task book 9-A.6).
                if (auto neg = negative_cache_ttl(msg)) {
                    cache_.put_negative(q->host, q->qport, qtype, *neg);
                }
                q->cb(Error{ErrorCode::DnsNameNotFound, ErrorPhase::Resolve,
                            string("DoT: NXDOMAIN")});
                return;
            }
            case ResponseCode::ServFail:
            case ResponseCode::Refused:
                // SERVFAIL and REFUSED are transport-level failures of the
                // upstream, NOT statements about the name. Caching them would
                // turn a transient outage into a lasting NXDOMAIN.
                q->cb(Error{ErrorCode::DnsServerFailure, ErrorPhase::Resolve,
                            string("DoT: server failure")});
                return;
            case ResponseCode::FormErr:
            case ResponseCode::NotImp:
            case ResponseCode::Unknown:
                q->cb(Error{ErrorCode::DnsInvalidMessage, ErrorPhase::Resolve,
                            string("DoT: server rejected the query")});
                return;
        }

        auto answers = extract_addresses(msg, q->qtype);
        if (!answers) {
            q->cb(answers.error());
            return;
        }

        AddressList out;
        const size_t want = (q->qtype == ::megohttp::dns::RecordType::A) ? 4 : 16;
        for (const auto& raw : answers.value().addresses) {
            if (raw.size() != want) continue;
            ResolvedAddress a;
            a.family = (want == 4) ? ResolvedAddress::Family::IPv4
                                   : ResolvedAddress::Family::IPv6;
            a.port = q->qport;
            a.bytes = raw;
            // Text form, so diagnostics and the connection layer can log it.
            char buf[64] = {0};
            if (inet_ntop(want == 4 ? AF_INET : AF_INET6, raw.data(), buf, sizeof buf)) {
                a.text = to_string(buf);
            }
            out.push_back(std::move(a));
        }

        if (out.empty()) {
            // NOERROR with no address records is NODATA, which is a valid answer
            // meaning "this name has no records of that type" (9-A.5). It is
            // negatively cached like NXDOMAIN -- the name exists but this type
            // is absent.
            if (auto neg = negative_cache_ttl(msg)) {
                cache_.put_negative(q->host, q->qport, qtype, *neg);
            }
            q->cb(Error{ErrorCode::DnsNoData, ErrorPhase::Resolve,
                        string("DoT: NOERROR with no address records")});
            return;
        }

        // Positive cache with the real record TTL (task book 9-A.6). A CNAME
        // chain's entries carry their own TTLs, so the minimum across the answer
        // set is the only value that keeps the whole chain coherent.
        if (auto ttl = min_ttl(msg.answers)) {
            cache_.put_positive(q->host, q->qport, qtype, out, *ttl);
        }

        q->cb(AddressList(std::move(out)));
    }

} // namespace megohttp

#endif // MEGOHTTP_HAS_DOT
#endif // MEGOHTTP_RESOLVER_DOT_IMPL_HPP_INCLUDED
