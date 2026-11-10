#ifndef MEGOHTTP_RESOLVER_CACHING_HPP_INCLUDED
#define MEGOHTTP_RESOLVER_CACHING_HPP_INCLUDED

// CachingResolver: wraps any Resolver and adds three things the spec asks for
// (S2.4-03 concurrency cap, S2.4-04 request coalescing) plus an answer cache.
//
// Deliberately thin: it owns no threads and no timers. Cache expiry is checked
// on lookup, so no sweep task is needed.

#include <megohttp/resolver.hpp>
#include <megohttp/string_adapter.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace megohttp {

    class CachingResolver final : public Resolver,
                                  public std::enable_shared_from_this<CachingResolver> {
    public:
        struct Options {
            // How long a successful answer stays valid. Duration::zero() disables
            // caching entirely.
            Duration cache_ttl{std::chrono::minutes(5)};
            // Maximum number of DISTINCT lookups allowed to be outstanding
            // upstream at once. Further distinct lookups queue in arrival order.
            // 0 = unlimited.
            size_t max_in_flight{0};
        };

        CachingResolver(std::shared_ptr<Executor> executor,
                        std::shared_ptr<Resolver> upstream)
            : executor_(std::move(executor))
            , upstream_(std::move(upstream)) {}

        CachingResolver(std::shared_ptr<Executor> executor,
                        std::shared_ptr<Resolver> upstream,
                        Options options)
            : executor_(std::move(executor))
            , upstream_(std::move(upstream))
            , options_(options) {}

        CancelHandle resolve(string host, uint16_t port, Callback cb) override {
            const std::string key = cache_key(host, port);

            // A per-caller cancel state. Cancelling it removes this caller's
            // waiter without disturbing other coalesced callers.
            auto cancel = std::make_shared<CancelState>(executor_);

            {
                std::lock_guard<std::mutex> lk(m_);

                // 1. Fresh cache hit: answer without touching the upstream. The
                //    callback is still posted so it runs on the loop thread, as
                //    the Resolver contract requires.
                if (options_.cache_ttl != Duration::zero()) {
                    auto it = cache_.find(key);
                    if (it != cache_.end()) {
                        auto exp = cache_expiry_.find(key);
                        if (exp != cache_expiry_.end() && Clock::now() < exp->second) {
                            AddressList answers = it->second;
                            for (auto& a : answers) a.port = port;
                            auto ready_cb = cb;
                            auto cancel_state_for_hit = cancel;
                            executor_->post([ready_cb, answers, cancel_state_for_hit]() {
                                // A cancelled lookup must not deliver, even from
                                // the cache: "no callback after cancel" is the
                                // Resolver contract, and a cache hit is still a
                                // callback.
                                if (cancel_state_for_hit &&
                                    cancel_state_for_hit->is_cancelled()) {
                                    return;
                                }
                                if (ready_cb) ready_cb(Result<AddressList>(answers));
                            });
                            return CancelHandle(cancel);
                        }
                        cache_.erase(it);
                        cache_expiry_.erase(exp);
                    }
                }

                Waiter w;
                w.cb = std::move(cb);
                w.cancel = cancel;

                // 2. Coalesce: an identical lookup is already upstream.
                auto inf = in_flight_.find(key);
                if (inf != in_flight_.end()) {
                    inf->second.waiters.push_back(std::move(w));
                    return CancelHandle(cancel);
                }

                // 3. Concurrency cap: queue when the upstream is saturated.
                if (options_.max_in_flight != 0 && in_flight_.size() >= options_.max_in_flight) {
                    Queued q;
                    q.key = key;
                    q.host = host;
                    q.port = port;
                    q.waiters.push_back(std::move(w));
                    queue_.push_back(std::move(q));
                    return CancelHandle(cancel);
                }

                // Nothing else in flight for this key: reserve the slot now so a
                // concurrent caller coalesces onto it instead of racing.
                in_flight_[key].waiters.push_back(std::move(w));
            }

            start_lookup(key, host, port);
            return CancelHandle(cancel);
        }

        const char* name() const noexcept override { return "caching"; }

        // Test seam: number of distinct lookups currently outstanding upstream.
        size_t in_flight_count() const {
            std::lock_guard<std::mutex> lk(m_);
            return in_flight_.size();
        }

        // Test seam: number of lookups waiting for a concurrency slot.
        size_t queued_count() const {
            std::lock_guard<std::mutex> lk(m_);
            return queue_.size();
        }

    private:
        struct Waiter {
            Callback cb;
            std::shared_ptr<CancelState> cancel;
        };

        struct InFlight {
            std::vector<Waiter> waiters;
            CancelHandle upstream_handle;
        };

        struct Queued {
            std::string key;
            string host;
            uint16_t port{0};
            std::vector<Waiter> waiters;
        };

        using Clock = std::chrono::steady_clock;

        std::shared_ptr<Executor> executor_;
        std::shared_ptr<Resolver> upstream_;
        Options options_;

        mutable std::mutex m_;
        std::unordered_map<std::string, AddressList> cache_;
        std::unordered_map<std::string, Clock::time_point> cache_expiry_;
        std::unordered_map<std::string, InFlight> in_flight_;
        std::vector<Queued> queue_;

        // Cache key: lower-cased host + ':' + port. A DNS name is
        // case-insensitive, so "Example.COM" and "example.com" share a slot.
        static std::string cache_key(const string& host, uint16_t port) {
            std::string k(host.data(), host.size());
            std::transform(k.begin(), k.end(), k.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            k += ':';
            k += std::to_string(static_cast<unsigned>(port));
            return k;
        }

        void start_lookup(const std::string& key, const string& host, uint16_t port) {

            // Capture a weak_ptr, never `this`: the CachingResolver may be
            // destroyed while the upstream lookup is still outstanding.
            std::weak_ptr<CachingResolver> weak = shared_from_this();
            std::string k = key;

            CancelHandle h = upstream_->resolve(host, port,
                [weak, k](Result<AddressList> r) {
                    if (auto self = weak.lock()) self->on_lookup_done(k, std::move(r));
                });

            std::lock_guard<std::mutex> lk(m_);
            auto it = in_flight_.find(key);
            if (it != in_flight_.end()) it->second.upstream_handle = std::move(h);
        }

        void on_lookup_done(const std::string& key, Result<AddressList> result) {
            std::vector<Waiter> waiters;
            {
                std::lock_guard<std::mutex> lk(m_);
                auto it = in_flight_.find(key);
                if (it == in_flight_.end()) return;
                waiters = std::move(it->second.waiters);
                in_flight_.erase(it);

                if (result && options_.cache_ttl != Duration::zero()) {
                    cache_[key] = result.value();
                    cache_expiry_[key] = Clock::now() + options_.cache_ttl;
                }
            }

            for (auto& w : waiters) {
                if (w.cancel && w.cancel->is_cancelled()) continue;
                if (w.cb) w.cb(result);
            }

            drain_queue();
        }

        void drain_queue() {
            std::vector<Queued> to_start;
            {
                std::lock_guard<std::mutex> lk(m_);
                while (!queue_.empty()) {
                    if (options_.max_in_flight != 0 &&
                        in_flight_.size() >= options_.max_in_flight) break;

                    auto q = std::move(queue_.front());
                    queue_.erase(queue_.begin());

                    // Drop waiters that were cancelled while queued.
                    q.waiters.erase(
                        std::remove_if(q.waiters.begin(), q.waiters.end(),
                                       [](const Waiter& w) {
                                           return w.cancel && w.cancel->is_cancelled();
                                       }),
                        q.waiters.end());
                    if (q.waiters.empty()) continue;

                    // Another request may have started this key meanwhile.
                    auto inf = in_flight_.find(q.key);
                    if (inf != in_flight_.end()) {
                        for (auto& w : q.waiters) inf->second.waiters.push_back(std::move(w));
                        continue;
                    }
                    for (auto& w : q.waiters) in_flight_[q.key].waiters.push_back(std::move(w));
                    to_start.push_back(std::move(q));
                }
            }
            for (auto& q : to_start) {
                start_lookup(q.key, q.host, q.port);
            }
        }
    };

} // namespace megohttp

#endif // MEGOHTTP_RESOLVER_CACHING_HPP_INCLUDED
