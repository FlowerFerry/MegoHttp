#ifndef MEGOHTTP_CONNECTION_POOL_IMPL_HPP_INCLUDED
#define MEGOHTTP_CONNECTION_POOL_IMPL_HPP_INCLUDED

// Implementation of the connection pool. All of it is inline: the library is
// header-only, so every non-template definition carries `inline`.

#include <megohttp/connection_pool.hpp>
#include <megohttp/format.hpp>

#include <string>

namespace megohttp {

    // ---------------------------------------------------------------------
    // PoolKey
    // ---------------------------------------------------------------------

    inline string PoolKey::describe() const {
        string_builder b;
        detail::sb_append(b, scheme);
        detail::sb_append(b, "://");
        detail::sb_append(b, host);
        detail::sb_append(b, ":");
        detail::sb_append(b, format("{}", port));
        if (!proxy_type.empty()) {
            detail::sb_append(b, " via ");
            detail::sb_append(b, proxy_type);
            detail::sb_append(b, "://");
            detail::sb_append(b, proxy_host);
            detail::sb_append(b, ":");
            detail::sb_append(b, format("{}", proxy_port));
        }
        return b.release();
    }

    inline std::size_t PoolKeyHash::operator()(const PoolKey& k) const noexcept {
        std::size_t h = 1469598103934665603ull;
        auto mix = [&h](std::size_t v) {
            h ^= v;
            h *= 1099511628211ull;
        };
        mix(std::hash<std::string>{}(std::string(k.scheme.data(), k.scheme.size())));
        mix(std::hash<std::string>{}(std::string(k.host.data(), k.host.size())));
        mix(k.port);
        mix(std::hash<std::string>{}(std::string(k.proxy_type.data(), k.proxy_type.size())));
        mix(std::hash<std::string>{}(std::string(k.proxy_host.data(), k.proxy_host.size())));
        mix(k.proxy_port);
        mix(std::hash<std::string>{}(std::string(k.proxy_auth_token.data(), k.proxy_auth_token.size())));
        mix(std::hash<std::string>{}(std::string(k.tls_ca_token.data(), k.tls_ca_token.size())));
        mix(std::hash<std::string>{}(std::string(k.tls_client_cert_token.data(), k.tls_client_cert_token.size())));
        mix(k.tls_verify_peer ? 1u : 0u);
        return h;
    }

    // ---------------------------------------------------------------------
    // ConnectionPool
    // ---------------------------------------------------------------------

    inline ConnectionPool::ConnectionPool(std::shared_ptr<Executor> executor,
                                          PoolOptions options)
        : executor_(std::move(executor)), options_(options) {}

    // Reserve a slot for the caller to either use an idle connection or open
    // a new one. Returns false when a limit would be exceeded.
    inline bool ConnectionPool::try_reserve(const PoolKey& key) {
        if (options_.max_total_connections != 0) {
            // Idle connections hold slots too: they own a socket and count
            // against the ceiling. Comparing only busy_total_ let a pool sit at
            // max_total_connections in idle connections and still hand out more,
            // so the real limit became max_total_connections + idle.
            // (2026-11-13 code review, defect #7.)
            size_t total = busy_total_;
            for (const auto& kv : idle_) total += kv.second.size();
            if (total >= options_.max_total_connections) return false;
        }
        if (options_.max_connections_per_origin != 0) {
            auto it = busy_per_key_.find(key);
            const size_t in_use = (it == busy_per_key_.end()) ? 0 : it->second;
            size_t idle_for_key = 0;
            auto ii = idle_.find(key);
            if (ii != idle_.end()) idle_for_key = ii->second.size();
            if (in_use + idle_for_key >= options_.max_connections_per_origin) {
                return false;
            }
        }
        ++busy_total_;
        ++busy_per_key_[key];
        return true;
    }

    inline void ConnectionPool::release_slot(const PoolKey& key) {
        auto it = busy_per_key_.find(key);
        if (it != busy_per_key_.end()) {
            if (it->second > 0) --it->second;
            if (it->second == 0) busy_per_key_.erase(it);
        }
        if (busy_total_ > 0) --busy_total_;
        serve_waiters();
    }

    inline void ConnectionPool::acquire(const PoolKey& key, AcquireCallback on_result) {
        // 1. An idle connection for this exact key, still open.
        auto it = idle_.find(key);
        while (it != idle_.end() && !it->second.empty()) {
            PooledConnection conn = std::move(it->second.front());
            it->second.pop_front();
            if (it->second.empty()) idle_.erase(it);
            if (conn.usable()) {
                ++conn.generation;
                // The connection moves from idle to busy: increment counters.
                ++busy_total_;
                ++busy_per_key_[key];
                if (on_result) on_result(Result<PooledConnection>{std::move(conn)});
                return;
            }
            // Dead on arrival: close and free the slot it occupied.
            if (conn.stream) conn.stream->async_close(nullptr);
            release_slot(key);
            // Continue looking for another idle connection for this key.
            it = idle_.find(key);
        }

        // 2. Capacity remains: tell the caller to open a new connection.
        if (try_reserve(key)) {
            if (on_result) {
                on_result(Result<PooledConnection>{Error{
                    ErrorCode::NotFound, ErrorPhase::None,
                    string("no idle connection; open a new one")}});
            }
            return;
        }

        // 3. Neither: queue, bounded by max_waiting.
        if (options_.max_waiting == 0 || waiters_.size() >= options_.max_waiting) {
            if (on_result) {
                on_result(Result<PooledConnection>{Error{
                    ErrorCode::PoolExhausted, ErrorPhase::None,
                    string("connection pool is full and the wait queue is full")}});
            }
            return;
        }
        waiters_.push_back(Waiter{key, std::move(on_result)});
    }

    inline void ConnectionPool::serve_waiters() {
        size_t tried = 0;
        size_t total = waiters_.size();
        while (tried < total && !waiters_.empty()) {
            Waiter w = std::move(waiters_.front());
            waiters_.pop_front();
            ++tried;

            auto it = idle_.find(w.key);
            if (it != idle_.end() && !it->second.empty()) {
                PooledConnection conn = std::move(it->second.front());
                it->second.pop_front();
                if (it->second.empty()) idle_.erase(it);
                if (conn.usable()) {
                    ++conn.generation;
                    ++busy_total_;
                    ++busy_per_key_[w.key];
                    if (w.callback) {
                        w.callback(Result<PooledConnection>{std::move(conn)});
                    }
                    continue;
                }
                // Dead: close and try to give this waiter a new slot.
                if (conn.stream) conn.stream->async_close(nullptr);
                if (try_reserve(w.key)) {
                    if (w.callback) {
                        w.callback(Result<PooledConnection>{Error{
                            ErrorCode::NotFound, ErrorPhase::None,
                            string("no idle connection; open a new one")}});
                    }
                    continue;
                }
                waiters_.push_back(std::move(w));
                continue;
            }
            if (try_reserve(w.key)) {
                if (w.callback) {
                    w.callback(Result<PooledConnection>{Error{
                        ErrorCode::NotFound, ErrorPhase::None,
                        string("no idle connection; open a new one")}});
                }
                continue;
            }
            waiters_.push_back(std::move(w));
        }
    }

    inline void ConnectionPool::put(PooledConnection conn, bool finished_cleanly) {
        const PoolKey key = conn.key;

        if (!finished_cleanly || !conn.usable()) {
            if (conn.stream) conn.stream->async_close(nullptr);
            release_slot(key);
            return;
        }

        conn.idle_since = std::chrono::steady_clock::now();
        idle_[key].push_back(std::move(conn));
        // The connection moves from busy to idle: decrement busy counters.
        // It still occupies a slot against the limits (tracked by busy + idle).
        auto it = busy_per_key_.find(key);
        if (it != busy_per_key_.end()) {
            if (it->second > 0) --it->second;
            if (it->second == 0) busy_per_key_.erase(it);
        }
        if (busy_total_ > 0) --busy_total_;
        serve_waiters();
    }

    inline void ConnectionPool::clear_idle() {
        for (auto& kv : idle_) {
            for (auto& c : kv.second) {
                if (c.stream) c.stream->async_close(nullptr);
            }
        }
        idle_.clear();
        serve_waiters();
    }

    inline size_t ConnectionPool::sweep_idle(std::chrono::steady_clock::time_point now) {
        size_t closed = 0;
        for (auto it = idle_.begin(); it != idle_.end();) {
            auto& dq = it->second;
            for (auto c = dq.begin(); c != dq.end();) {
                const bool too_old =
                    options_.idle_timeout != Duration::zero() &&
                    (now - c->idle_since) >= options_.idle_timeout;
                if (too_old || !c->usable()) {
                    if (c->stream) c->stream->async_close(nullptr);
                    const PoolKey closed_key = it->first;
                    c = dq.erase(c);
                    ++closed;
                    // Free the slot this idle connection occupied.
                    if (busy_per_key_[closed_key] > 0) --busy_per_key_[closed_key];
                    if (busy_per_key_[closed_key] == 0) busy_per_key_.erase(closed_key);
                    if (busy_total_ > 0) --busy_total_;
                } else {
                    ++c;
                }
            }
            if (dq.empty()) {
                it = idle_.erase(it);
            } else {
                ++it;
            }
        }
        if (closed) serve_waiters();
        return closed;
    }

    inline size_t ConnectionPool::idle_count() const noexcept {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        size_t n = 0;
        for (const auto& kv : idle_) n += kv.second.size();
        return n;
    }

    inline size_t ConnectionPool::busy_count() const noexcept {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        return busy_total_;
    }

    inline size_t ConnectionPool::waiting_count() const noexcept {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        return waiters_.size();
    }

    inline void ConnectionPool::fail_waiters(ErrorCode code, const char* message) {
        std::deque<Waiter> pending = std::move(waiters_);
        waiters_.clear();
        for (auto& w : pending) {
            if (w.callback) {
                w.callback(Result<PooledConnection>{
                    Error{code, ErrorPhase::None, format("{}", message)}});
            }
        }
    }

} // namespace megohttp

#endif // MEGOHTTP_CONNECTION_POOL_IMPL_HPP_INCLUDED
