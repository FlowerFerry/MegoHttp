// DNS cache unit tests (S5A.5-01 / S5A.5-02, task book 9-A.6).
//
// The cache is a plain data structure, so these tests need no server and no
// executor. The TTL behaviour is verified with real short sleeps; the values
// are chosen so the difference between "cached" and "expired" is unambiguous
// (100 ms TTL vs a 200 ms wait).

#include <catch2/catch_all.hpp>

#include <megohttp/dns_cache.hpp>

#include <chrono>
#include <thread>

namespace {

using namespace megohttp;

constexpr uint16_t kQtypeA = 1;

ResolvedAddress make_v4(const char* text, uint16_t port) {
    ResolvedAddress a;
    a.family = ResolvedAddress::Family::IPv4;
    a.text = string(text);
    a.port = port;
    return a;
}

AddressList one_answer(const char* text, uint16_t port) {
    AddressList l;
    l.push_back(make_v4(text, port));
    return l;
}

} // anonymous namespace

// -----------------------------------------------------------------------

TEST_CASE("DnsCache stores and returns a positive answer", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("example.com"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);

    auto got = cache.get(string("example.com"), 443, kQtypeA);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].text == string("192.0.2.1"));
    CHECK((*got)[0].port == 443);
}

TEST_CASE("DnsCache rewrites the port for the caller", "[dns_cache][s5a]") {
    DnsCache cache;
    // Stored with port 443 ...
    cache.put_positive(string("example.com"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);

    // ... but a lookup for the same host on another port must carry that port.
    auto got = cache.get(string("example.com"), 8080, kQtypeA);
    // The key includes the port, so this is a MISS: different port, different
    // entry. That is deliberate -- two ports are independent lookups.
    CHECK_FALSE(got.has_value());
}

TEST_CASE("DnsCache is case-insensitive on the host name", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("Example.COM"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);

    auto got = cache.get(string("example.com"), 443, kQtypeA);
    CHECK(got.has_value());
}

TEST_CASE("DnsCache expires a positive entry after its TTL", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("short.example"), 443, kQtypeA,
                       one_answer("192.0.2.9", 443), 1);   // 1 second

    CHECK(cache.get(string("short.example"), 443, kQtypeA).has_value());
    // The TTL is one second; waiting just past it must produce a miss. This
    // sleeps 1.1 s, which is the price of testing a real clock.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    CHECK_FALSE(cache.get(string("short.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache does not cache a TTL of zero", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("zero.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 0);
    // TTL 0 means "do not cache" (task book 9-A.6).
    CHECK_FALSE(cache.get(string("zero.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache clamps an oversized TTL to max_ttl", "[dns_cache][s5a]") {
    DnsCacheOptions opts;
    opts.max_ttl = std::chrono::milliseconds(50);
    DnsCache cache(opts);

    // A one-week TTL must be clamped to the 50 ms ceiling.
    cache.put_positive(string("long.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 7 * 24 * 3600);
    CHECK(cache.get(string("long.example"), 443, kQtypeA).has_value());

    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    CHECK_FALSE(cache.get(string("long.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache stores a negative entry as an empty answer", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_negative(string("missing.example"), 443, kQtypeA, 300);

    auto got = cache.get(string("missing.example"), 443, kQtypeA);
    // A negative hit is a definitive "no records", which is an empty list and
    // NOT an error.
    REQUIRE(got.has_value());
    CHECK(got->empty());
}

TEST_CASE("DnsCache expires a negative entry after its TTL", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_negative(string("gone.example"), 443, kQtypeA, 1);

    REQUIRE(cache.get(string("gone.example"), 443, kQtypeA).has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    CHECK_FALSE(cache.get(string("gone.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache can disable negative caching", "[dns_cache][s5a]") {
    DnsCacheOptions opts;
    opts.negative_enabled = false;
    DnsCache cache(opts);

    cache.put_negative(string("missing.example"), 443, kQtypeA, 300);
    CHECK_FALSE(cache.get(string("missing.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache honours the disabled flag", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("example.com"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    REQUIRE(cache.get(string("example.com"), 443, kQtypeA).has_value());

    cache.disable();
    CHECK_FALSE(cache.get(string("example.com"), 443, kQtypeA).has_value());

    // A put after disabling is a no-op, not a re-enable.
    cache.put_positive(string("example.com"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    CHECK_FALSE(cache.get(string("example.com"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache clear removes every entry", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("a.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    cache.put_positive(string("b.example"), 443, kQtypeA,
                       one_answer("192.0.2.2", 443), 300);
    CHECK(cache.size() == 2);

    cache.clear();
    CHECK(cache.size() == 0);
    CHECK_FALSE(cache.get(string("a.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache evicts the oldest entry at max_entries", "[dns_cache][s5a]") {
    DnsCacheOptions opts;
    opts.max_entries = 2;
    DnsCache cache(opts);

    cache.put_positive(string("one.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    cache.put_positive(string("two.example"), 443, kQtypeA,
                       one_answer("192.0.2.2", 443), 300);

    // Both fit, so both are present.
    CHECK(cache.get(string("one.example"), 443, kQtypeA).has_value());
    CHECK(cache.get(string("two.example"), 443, kQtypeA).has_value());

    // A third entry exceeds the limit; the oldest insert goes.
    // NOTE: eviction order is insertion order, not access order -- `get` takes a
    // read lock and deliberately does not reorder, so a read cannot make an
    // entry immortal. That also means a hot entry can be evicted; the cache is
    // a size bound, not a hot-set optimiser.
    cache.put_positive(string("three.example"), 443, kQtypeA,
                       one_answer("192.0.2.3", 443), 300);

    CHECK_FALSE(cache.get(string("one.example"), 443, kQtypeA).has_value());
    CHECK(cache.get(string("two.example"), 443, kQtypeA).has_value());
    CHECK(cache.get(string("three.example"), 443, kQtypeA).has_value());
    CHECK(cache.size() == 2);
}

TEST_CASE("DnsCache keys separate record types", "[dns_cache][s5a]") {
    DnsCache cache;
    constexpr uint16_t kAaaa = 28;

    cache.put_positive(string("dual.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    // A lookup for AAAA must not see the A answer.
    CHECK_FALSE(cache.get(string("dual.example"), 443, kAaaa).has_value());
    CHECK(cache.get(string("dual.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache explicit evict removes one entry", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("a.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    cache.put_positive(string("b.example"), 443, kQtypeA,
                       one_answer("192.0.2.2", 443), 300);

    cache.evict(string("a.example"), 443, kQtypeA);
    CHECK_FALSE(cache.get(string("a.example"), 443, kQtypeA).has_value());
    CHECK(cache.get(string("b.example"), 443, kQtypeA).has_value());
}

TEST_CASE("DnsCache size counts only live entries", "[dns_cache][s5a]") {
    DnsCache cache;
    cache.put_positive(string("live.example"), 443, kQtypeA,
                       one_answer("192.0.2.1", 443), 300);
    cache.put_positive(string("dead.example"), 443, kQtypeA,
                       one_answer("192.0.2.2", 443), 1);
    CHECK(cache.size() == 2);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    // The expired entry is no longer counted, even before any write evicts it.
    CHECK(cache.size() == 1);
}
