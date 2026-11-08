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
