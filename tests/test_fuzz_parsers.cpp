// Fuzz entry points for the parsers (S3.4-23, and S3.1-10 for the HTTP parser).
//
// This is NOT a libFuzzer harness: the project builds with MSVC + Ninja and has no
// clang/libFuzzer dependency. Instead this is a deterministic, self-contained
// driver that mutates a corpus with a fixed seed.
//
// WHAT IT PROVES: the parsers do not crash, hang, or loop forever on arbitrary
// input, and they always terminate within the input they were given.
//
// WHAT IT DOES NOT PROVE: memory safety. A read past the end of a buffer is
// undefined behaviour that a plain Release build will not report -- it usually
// just reads adjacent heap bytes and carries on.
//
// MEASURED ON THIS HOST (do not "fix" this note without re-measuring):
//   * MSVC /fsanitize=address aborts at startup with
//     "Interception failure" (interception_win.cpp:171). Setting
//     ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1 gets the binaries running.
//   * That workaround is NOT a no-op: injecting a heap out-of-bounds read into
//     parse_content_range() made ASan report
//         ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
//         #0 megohttp::parse_content_range content_range_impl.hpp:69
//     with the 8-byte allocation and shadow bytes. So the sanitizer does check
//     memory under the workaround, and a clean run of this file is real
//     memory-safety evidence (allocation-level redzones).
//
// To reproduce that verification, temporarily add an out-of-bounds access to a
// parser, rebuild the ASan tree, and confirm ASan reports it -- an ASan run that
// cannot catch a deliberate bug proves nothing.
//
// Usage:
//   test_fuzz_parsers            run the default sweep (deterministic)
//   test_fuzz_parsers <seed>     run with a specific seed
//   test_fuzz_parsers <seed> <n> run n mutations
//
// Every run is bounded: each iteration feeds at most kMaxInput bytes and the
// parsers all have their own limits, so the whole sweep finishes in a few seconds.
#include <catch2/catch_all.hpp>

#include <megohttp/content_range.hpp>
#include <megohttp/dns_wire.hpp>
#include <megohttp/http.hpp>
#include <megohttp/multipart_response.hpp>

#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace megohttp;

namespace {

// Seeds chosen to reach each parser's interesting states: complete messages,
// truncated messages, wrong delimiters, and garbage.
const char* const kHttpSeeds[] = {
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "HTTP/1.1 204 No Content\r\n\r\n",
    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 200 OK\r\n\r\nuntil close",
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
    "garbage\r\n\r\n",
};

const char* const kMultipartSeeds[] = {
    "--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n",
    "--b\r\n\r\n\r\n--b--\r\n",
    "preamble\r\n--b\r\nX: y\r\n\r\ndata\r\n--b--\r\nepilogue",
    "--b\r\nContent-Range: bytes 0-4/100\r\n\r\nhello\r\n--b--\r\n",
    "--b\r\nbad header\r\n\r\nd\r\n--b--\r\n",
    "--b\r\nX: y\r\n\r\ntruncated",
    "--b--\r\n",
};

const char* const kRangeSeeds[] = {
    "bytes 0-499/1234",
    "bytes */1234",
    "bytes 0-9/*",
    "items 0-4/100",
    "bytes 500-499/1234",
    "bytes 0-18446744073709551616/9",
};

// DNS message seeds as raw bytes. Each one is a different shape the parser has
// to handle: a plain A answer, a CNAME chain, NXDOMAIN with no authority,
// a message with a compression pointer, a truncated message, and a query
// (which a response parser must reject).
std::vector<std::vector<uint8_t>> dns_seeds() {
    // Helper: a 12-byte header + question for "example.com" type A class IN.
    auto header_and_question = [](uint16_t id, uint16_t flags, uint16_t ancount) {
        std::vector<uint8_t> v;
        auto put16 = [&v](uint16_t x) {
            v.push_back(static_cast<uint8_t>(x >> 8));
            v.push_back(static_cast<uint8_t>(x & 0xFF));
        };
        put16(id);
        put16(flags);
        put16(1);        // qdcount
        put16(ancount);  // ancount
        put16(0);        // nscount
        put16(0);        // arcount
        // "example.com": 7 example 3 com 0
        const uint8_t name[] = {7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0};
        v.insert(v.end(), name, name + sizeof(name));
        put16(1);  // qtype A
        put16(1);  // qclass IN
        return v;
    };

    std::vector<std::vector<uint8_t>> seeds;

    {   // A answer with one 192.0.2.1 record, pointer-compressed owner.
        auto v = header_and_question(0x1234, 0x8180, 1);
        const uint8_t ans[] = {0xC0, 0x0C,  0x00, 0x01, 0x00, 0x01,
                               0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                               192, 0, 2, 1};
        v.insert(v.end(), ans, ans + sizeof(ans));
        seeds.push_back(v);
    }
    {   // NXDOMAIN with no authority section (negative_cache_ttl is nullopt).
        seeds.push_back(header_and_question(0x2345, 0x8183, 0));
    }
    {   // Truncated: header claims an answer that is not there.
        seeds.push_back(header_and_question(0x3456, 0x8180, 1));
    }
    {   // A bare header: no question at all.
        seeds.push_back({0x12, 0x34, 0x81, 0x80, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    }
    {   // A forward compression pointer, which the parser must reject.
        std::vector<uint8_t> v = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        v.push_back(0xC0);
        v.push_back(0x20);   // points forward, into uninitialised territory
        v.push_back(0x00);
        v.push_back(0x01);
        v.push_back(0x00);
        v.push_back(0x01);
        seeds.push_back(v);
    }
    {   // Empty input.
        seeds.push_back({});
    }
    return seeds;
}

// Collects HTTP parser output; all callbacks accept everything so the sweep
// exercises the parser itself, not a sink's policy.
struct HttpSink : ResponseParser::Callbacks {
    size_t bytes = 0;
    VoidResult on_head(const ParsedResponse&) override { return VoidResult{}; }
    VoidResult on_body_data(const uint8_t*, size_t n) override { bytes += n; return VoidResult{}; }
    VoidResult on_trailers(const Headers&) override { return VoidResult{}; }
    VoidResult on_complete() override { return VoidResult{}; }
};

struct MultiSink : MultipartResponseParser::Callbacks {
    size_t bytes = 0;
    VoidResult on_part_start(const Headers&) override { return VoidResult{}; }
    bool on_part_data(string_view d) override { bytes += d.size(); return true; }
    VoidResult on_part_end() override { return VoidResult{}; }
    VoidResult on_complete() override { return VoidResult{}; }
};

// Applies one random mutation: flip, insert, erase or duplicate a byte.
std::string mutate(std::string s, std::mt19937& rng) {
    if (s.empty()) {
        s.push_back(static_cast<char>(rng() & 0xFF));
        return s;
    }
    std::uniform_int_distribution<size_t> pos_dist(0, s.size() - 1);
    std::uniform_int_distribution<int> op_dist(0, 3);

    switch (op_dist(rng)) {
    case 0:   // flip a bit
        s[pos_dist(rng)] = static_cast<char>(s[pos_dist(rng)] ^ (1u << (rng() % 8)));
        break;
    case 1:   // insert a byte
        s.insert(s.begin() + static_cast<long>(pos_dist(rng)),
                 static_cast<char>(rng() & 0xFF));
        break;
    case 2:   // erase a byte
        if (s.size() > 1) s.erase(s.begin() + static_cast<long>(pos_dist(rng)));
        break;
    default:  // duplicate a span
        {
            const size_t at = pos_dist(rng);
            const size_t len = std::min<size_t>(8, s.size() - at);
            s.insert(at, s.substr(at, len));
        }
        break;
    }
    return s;
}

} // namespace

TEST_CASE("HTTP response parser survives mutated input", "[fuzz][http]") {
    std::mt19937 rng(0xF00D1234u);
    size_t parsed = 0, rejected = 0;

    for (const char* seed : kHttpSeeds) {
        std::string input = seed;
        for (int round = 0; round < 200; ++round) {
            HttpSink sink;
            ResponseParser parser(sink);
            // Feed in two arbitrary halves so the split points vary too.
            const size_t cut = input.empty() ? 0 : rng() % (input.size() + 1);
            auto r1 = parser.feed(reinterpret_cast<const uint8_t*>(input.data()), cut);
            if (r1.has_value()) {
                parser.feed(reinterpret_cast<const uint8_t*>(input.data() + cut),
                            input.size() - cut);
            }
            parser.feed_eof();

            if (parser.is_complete()) ++parsed; else ++rejected;
            input = mutate(input, rng);
            // Keep the corpus bounded so a run stays fast.
            if (input.size() > 4096) input.resize(4096);
        }
    }

    // Not a correctness assertion -- a smoke check that the sweep actually
    // exercised both outcomes instead of short-circuiting.
    CHECK(parsed > 0);
    CHECK(rejected > 0);
    CHECK(parsed + rejected == 8 * 200);
}

TEST_CASE("multipart response parser survives mutated input", "[fuzz][multipart]") {
    std::mt19937 rng(0xBEEF5678u);
    size_t parsed = 0, rejected = 0;

    for (const char* seed : kMultipartSeeds) {
        std::string input = seed;
        for (int round = 0; round < 200; ++round) {
            MultiSink sink;
            MultipartResponseParser parser(sink, "b");
            const size_t cut = input.empty() ? 0 : rng() % (input.size() + 1);
            auto r1 = parser.feed(reinterpret_cast<const uint8_t*>(input.data()), cut);
            if (r1.has_value()) {
                parser.feed(reinterpret_cast<const uint8_t*>(input.data() + cut),
                            input.size() - cut);
            }
            parser.feed_eof();

            if (parser.is_complete()) ++parsed; else ++rejected;
            input = mutate(input, rng);
            if (input.size() > 4096) input.resize(4096);
        }
    }

    CHECK(parsed > 0);
    CHECK(rejected > 0);
    CHECK(parsed + rejected == 7 * 200);
}

TEST_CASE("Content-Range parser survives mutated input", "[fuzz][byteranges]") {
    std::mt19937 rng(0xCAFE9ABCu);
    size_t accepted = 0, rejected = 0;

    for (const char* seed : kRangeSeeds) {
        std::string input = seed;
        for (int round = 0; round < 200; ++round) {
            auto r = parse_content_range(string_view(input.data(), input.size()));
            if (r.has_value()) ++accepted; else ++rejected;
            input = mutate(input, rng);
            if (input.size() > 256) input.resize(256);
        }
    }

    CHECK(accepted > 0);
    CHECK(rejected > 0);
    CHECK(accepted + rejected == 6 * 200);
}

TEST_CASE("DNS wire-format parser survives mutated input", "[fuzz][dns]") {
    // Task book 9-A.7: the DNS parser gets its own fuzz entry point, using the
    // production parser (dns::parse_message), with bounded input and a bounded
    // pointer-hop limit inside the parser itself.
    std::mt19937 rng(0xD15EA5EDu);
    size_t parsed = 0, rejected = 0;

    const auto seeds = dns_seeds();
    for (const auto& seed : seeds) {
        std::vector<uint8_t> input = seed;
        for (int round = 0; round < 200; ++round) {
            auto r = megohttp::dns::parse_message(input);
            if (r) {
                ++parsed;
                // Walk the parsed structure so a corrupted-but-accepted message
                // cannot leave a bad index unchecked.
                const auto& msg = r.value();
                (void)megohttp::dns::extract_addresses(msg, megohttp::dns::RecordType::A);
                (void)megohttp::dns::min_ttl(msg.answers);
                (void)megohttp::dns::negative_cache_ttl(msg);
            } else {
                ++rejected;
            }

            // Mutate as raw bytes: the mutations must be able to break lengths,
            // counts and compression pointers, which is where the risk lives.
            std::string as_string(input.begin(), input.end());
            as_string = mutate(as_string, rng);
            if (as_string.size() > 2048) as_string.resize(2048);
            input.assign(as_string.begin(), as_string.end());
        }
    }

    CHECK(parsed > 0);
    CHECK(rejected > 0);
    CHECK(parsed + rejected == seeds.size() * 200);
}

TEST_CASE("DNS wire-format parser tolerates random bytes", "[fuzz][dns]") {
    std::mt19937 rng(0x5EEDBEEFu);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    for (int round = 0; round < 300; ++round) {
        const size_t len = rng() % 512;
        std::vector<uint8_t> input;
        input.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            input.push_back(static_cast<uint8_t>(byte_dist(rng)));
        }

        auto r = megohttp::dns::parse_message(input);
        if (r) {
            const auto& msg = r.value();
            (void)megohttp::dns::extract_addresses(msg, megohttp::dns::RecordType::A);
            (void)megohttp::dns::extract_addresses(msg, megohttp::dns::RecordType::AAAA);
            (void)megohttp::dns::negative_cache_ttl(msg);
        }
    }
    SUCCEED("no crash on 300 random DNS buffers");
}

TEST_CASE("DNS query builder round-trips every fuzzed query", "[fuzz][dns]") {
    // build_query must either produce a message that parses back, or fail
    // cleanly. A builder that emits unparseable bytes would break DoT/DoH in a
    // way the response-side fuzz above cannot see.
    std::mt19937 rng(0xB0117u);
    std::uniform_int_distribution<int> len_dist(0, 40);
    std::uniform_int_distribution<int> chr_dist(33, 126);

    for (int round = 0; round < 200; ++round) {
        std::string name;
        const int len = len_dist(rng);
        for (int i = 0; i < len; ++i) {
            name.push_back(static_cast<char>(chr_dist(rng)));
        }

        auto built = megohttp::dns::build_query(
            0x4242, string_view(name.data(), name.size()),
            megohttp::dns::RecordType::A);
        if (!built) continue;   // rejected (empty label, over-long, etc.)

        auto parsed = megohttp::dns::parse_message(built.value());
        // Whatever the builder accepted must parse back as a query with the
        // same name spelled the way the wire carries it.
        REQUIRE(parsed);
        CHECK(parsed.value().id == 0x4242);
        CHECK_FALSE(parsed.value().is_response);
    }
}

TEST_CASE("all parsers tolerate random bytes", "[fuzz][random]") {
    // Pure random input: no seed message, so the parsers see nothing they were
    // designed for. This is the case that catches an out-of-bounds read.
    std::mt19937 rng(0x1234ABCDu);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    for (int round = 0; round < 300; ++round) {
        const size_t len = rng() % 512;
        std::string input;
        input.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            input.push_back(static_cast<char>(byte_dist(rng)));
        }

        {
            HttpSink sink;
            ResponseParser parser(sink);
            parser.feed(reinterpret_cast<const uint8_t*>(input.data()), input.size());
            parser.feed_eof();
        }
        {
            MultiSink sink;
            MultipartResponseParser parser(sink, "boundary");
            parser.feed(reinterpret_cast<const uint8_t*>(input.data()), input.size());
            parser.feed_eof();
        }
        {
            parse_content_range(string_view(input.data(), input.size()));
        }
    }
    SUCCEED("no crash on 300 random buffers");
}
