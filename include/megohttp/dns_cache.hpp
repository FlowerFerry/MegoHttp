#ifndef MEGOHTTP_DNS_CACHE_HPP_INCLUDED
#define MEGOHTTP_DNS_CACHE_HPP_INCLUDED

// A small, bounded cache for DNS answer records, keyed by (host, port, record
// type).  Entries expire on their real DNS TTL (positive cache) or the SOA
// MINIMUM capped by the SOA TTL (negative cache, RFC 2308).
//
// Thread-safe, no internal timers: expiry is checked on access, so stale
// entries are evicted lazily without a background task.
//
// The cache does NOT store SERVFAIL, network errors, or cancelled lookups
// (task book 9-A.6).  NXDOMAIN and NODATA are stored as negative entries
// with a TTL derived from the SOA record.

#include <megohttp/error.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/string_adapter.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace megohttp {

    struct DnsCacheOptions {
        bool    enabled{true};
        size_t  max_entries{1024};
        // Hard ceiling on any positive TTL, regardless of what the wire says.
        // Prevents a single record with a huge TTL from poisoning the cache
        // for days.
        Duration max_ttl{std::chrono::hours(24)};
        // Negative cache (NXDOMAIN/NODATA) per RFC 2308.
        bool    negative_enabled{true};
    };

    // Cache entry: either a list of resolved addresses (positive) or a sentinel
    // indicating that the name has no records of the queried type (negative).
    class DnsCache {
    public:
        explicit DnsCache(DnsCacheOptions options = {});

        // Look up a cached answer. Returns nullopt when there is no entry,
        // the entry expired, or the cache is disabled.
        // The returned list already carries the caller's `port`.
        std::optional<AddressList> get(const string& host, uint16_t port,
                                       uint16_t qtype);

        // Store a positive answer with its TTLs. `ttl_seconds` is the minimum
        // TTL across the answer records.
        void put_positive(const string& host, uint16_t port, uint16_t qtype,
                          const AddressList& answers, uint32_t ttl_seconds);

        // Store a negative answer (NXDOMAIN or NODATA). `neg_ttl` comes from
        // dns::negative_cache_ttl (RFC 2308).
        void put_negative(const string& host, uint16_t port, uint16_t qtype,
                          uint32_t neg_ttl);

        // Remove a single entry.
        void evict(const string& host, uint16_t port, uint16_t qtype);

        // Remove all entries.
        void clear() noexcept;

        // Current number of live (non-expired) entries.  Acquires a read lock.
        size_t size() const;

        // Disable the cache: `get` always returns nullopt, `put_*` are no-ops.
        void disable() noexcept;

    private:
        using Clock = std::chrono::steady_clock;

        struct Entry {
            AddressList answers;
            Clock::time_point expires;
            bool negative{false};   // true = NXDOMAIN/NODATA sentinel
        };

        static std::string key(const string& host, uint16_t port, uint16_t qtype);

        // Record `k` as most recently used and evict the oldest entries when the
        // cache is over its limit. Caller holds the exclusive lock.
        void touch_locked(const std::string& k);

        DnsCacheOptions options_;
        mutable std::shared_mutex mutex_;
        std::unordered_map<std::string, Entry> entries_;
        // Insertion order for LRU eviction when max_entries is hit.
        std::deque<std::string> order_;
    };

} // namespace megohttp

#include <megohttp/dns_cache_impl.hpp>

#endif // MEGOHTTP_DNS_CACHE_HPP_INCLUDED
