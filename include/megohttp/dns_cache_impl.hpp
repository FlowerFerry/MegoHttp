#ifndef MEGOHTTP_DNS_CACHE_IMPL_HPP_INCLUDED
#define MEGOHTTP_DNS_CACHE_IMPL_HPP_INCLUDED

#include <megohttp/dns_cache.hpp>

namespace megohttp {

    inline DnsCache::DnsCache(DnsCacheOptions options)
        : options_(options) {}

    inline std::string DnsCache::key(const string& host, uint16_t port,
                                      uint16_t qtype) {
        // A DNS name is case-insensitive, so the key is lower-cased. The port
        // is part of the key because the caller's AddressList carries a port
        // and a lookup for a different port must not reuse the answer's list
        // without rewriting it (it is rewritten, but keying on it also keeps
        // two ports in flight independently).
        std::string k(host.data(), host.size());
        std::transform(k.begin(), k.end(), k.begin(),
                       [](unsigned char c) {
                           return static_cast<char>(std::tolower(c));
                       });
        k += ':';
        k += std::to_string(static_cast<unsigned>(qtype));
        k += ':';
        k += std::to_string(static_cast<unsigned>(port));
        return k;
    }

    inline std::optional<AddressList>
    DnsCache::get(const string& host, uint16_t port, uint16_t qtype) {
        if (!options_.enabled) return std::nullopt;

        const std::string k = key(host, port, qtype);
        std::shared_lock<std::shared_mutex> lk(mutex_);

        auto it = entries_.find(k);
        if (it == entries_.end()) return std::nullopt;

        if (Clock::now() >= it->second.expires) {
            // Expired: report a miss. The entry itself is removed lazily on the
            // next write (a read lock cannot erase).
            return std::nullopt;
        }

        // A negative entry is a definitive "no records of this type", which
        // callers see as an empty list -- not an error.
        if (it->second.negative) return AddressList{};

        AddressList answers = it->second.answers;
        for (auto& a : answers) a.port = port;
        return answers;
    }

    inline void DnsCache::put_positive(const string& host, uint16_t port,
                                        uint16_t qtype,
                                        const AddressList& answers,
                                        uint32_t ttl_seconds) {
        if (!options_.enabled) return;
        // A TTL of zero means "do not cache" (task book 9-A.6).
        if (ttl_seconds == 0) return;
        if (answers.empty()) return;   // NODATA goes through put_negative

        Duration ttl = std::chrono::seconds(ttl_seconds);
        if (ttl > options_.max_ttl) ttl = options_.max_ttl;

        const std::string k = key(host, port, qtype);
        std::unique_lock<std::shared_mutex> lk(mutex_);

        Entry& e = entries_[k];
        e.answers = answers;
        e.expires = Clock::now() + ttl;
        e.negative = false;
        touch_locked(k);
    }

    inline void DnsCache::put_negative(const string& host, uint16_t port,
                                        uint16_t qtype, uint32_t neg_ttl) {
        if (!options_.enabled || !options_.negative_enabled) return;
        if (neg_ttl == 0) return;

        Duration ttl = std::chrono::seconds(neg_ttl);
        if (ttl > options_.max_ttl) ttl = options_.max_ttl;

        const std::string k = key(host, port, qtype);
        std::unique_lock<std::shared_mutex> lk(mutex_);

        Entry& e = entries_[k];
        e.answers.clear();
        e.expires = Clock::now() + ttl;
        e.negative = true;
        touch_locked(k);
    }

    inline void DnsCache::evict(const string& host, uint16_t port,
                                 uint16_t qtype) {
        const std::string k = key(host, port, qtype);
        std::unique_lock<std::shared_mutex> lk(mutex_);
        entries_.erase(k);
        order_.erase(std::remove(order_.begin(), order_.end(), k), order_.end());
    }

    inline void DnsCache::clear() noexcept {
        std::unique_lock<std::shared_mutex> lk(mutex_);
        entries_.clear();
        order_.clear();
    }

    inline size_t DnsCache::size() const {
        std::shared_lock<std::shared_mutex> lk(mutex_);
        // Counting expired entries as present would overstate the cache; the
        // caller only cares about usable entries.
        size_t live = 0;
        const auto now = Clock::now();
        for (const auto& kv : entries_) {
            if (now < kv.second.expires) ++live;
        }
        return live;
    }

    inline void DnsCache::disable() noexcept {
        std::unique_lock<std::shared_mutex> lk(mutex_);
        options_.enabled = false;
        entries_.clear();
        order_.clear();
    }

    inline void DnsCache::touch_locked(const std::string& k) {
        // Move `k` to the end (most recently used).
        auto it = std::remove(order_.begin(), order_.end(), k);
        if (it != order_.end()) order_.erase(it, order_.end());
        order_.push_back(k);

        // Evict the oldest entries while over the limit. This also reaps expired
        // entries as a side effect, so no background sweep is needed.
        while (order_.size() > options_.max_entries) {
            const std::string oldest = order_.front();
            order_.pop_front();
            entries_.erase(oldest);
        }
    }

} // namespace megohttp

#endif // MEGOHTTP_DNS_CACHE_IMPL_HPP_INCLUDED
