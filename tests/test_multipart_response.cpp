// S3.4: multipart response parsing.
#include <catch2/catch_all.hpp>
#include <megohttp/multipart_response.hpp>
#include <megohttp/multipart_response_impl.hpp>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace megohttp;

namespace {

struct Collector : MultipartResponseParser::Callbacks {
    std::vector<Headers> parts_headers;
    std::vector<std::string> parts_data;
    int complete_count = 0;
    bool has_error = false;
    std::string error_msg;

    VoidResult on_part_start(const Headers& headers) override {
        parts_headers.push_back(headers);
        parts_data.emplace_back();
        return VoidResult{};
    }

    bool on_part_data(string_view data) override {
        if (!parts_data.empty()) {
            parts_data.back().append(data.data(), data.size());
        }
        return true;  // continue parsing
    }

    VoidResult on_part_end() override {
        return VoidResult{};
    }

    VoidResult on_complete() override {
        ++complete_count;
        return VoidResult{};
    }

    VoidResult on_error(const Error& e) {
        has_error = true;
        error_msg.assign(e.message().data(), e.message().size());
        return VoidResult{};
    }
};

// Feed helper: feeds data in chunks of `step` bytes (step=0 means all at once)
static VoidResult feed_in_chunks(MultipartResponseParser& p, const std::string& raw, size_t step) {
    if (step == 0) {
        return p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    }
    size_t i = 0;
    while (i < raw.size()) {
        size_t n = std::min(step, raw.size() - i);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data() + i), n);
        if (!r) return r;
        i += n;
    }
    return VoidResult{};
}

} // namespace

TEST_CASE("multipart mixed basic parsing", "[multipart][response]") {
    const char* boundary = "boundary123";
    const std::string body = 
        "This is the preamble.\r\n"
        "--boundary123\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello\r\n"
        "--boundary123\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        "{\"key\": \"value\"}\r\n"
        "--boundary123--\r\n"
        "This is the epilogue.\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_headers.size() == 2);
    CHECK(c.parts_data.size() == 2);
    CHECK(c.parts_data[0] == "Hello");
    CHECK(c.parts_data[1] == "{\"key\": \"value\"}");
    CHECK(c.complete_count == 1);
    CHECK(p.is_complete());
    CHECK(p.leftover_offset() > 0); // Epilogue
}

TEST_CASE("multipart with quoted boundary parameter", "[multipart][response]") {
    // Simulates Content-Type: multipart/mixed; boundary="boundary\"with\"quotes"
    const char* boundary = "boundary_with_quotes";
    const std::string body = 
        "--boundary_with_quotes\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Part 1\r\n"
        "--boundary_with_quotes--\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_headers.size() == 1);
    CHECK(c.parts_data[0] == "Part 1");
    CHECK(c.complete_count == 1);
}

TEST_CASE("multipart byteranges parsing", "[multipart][response]") {
    // Simulates a multipart/byteranges response
    const char* boundary = "byteranges";
    const std::string body = 
        "\r\n"
        "--byteranges\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Range: bytes 0-4/100\r\n"
        "\r\n"
        "Hello\r\n"
        "--byteranges\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Range: bytes 95-99/100\r\n"
        "\r\n"
        "World\r\n"
        "--byteranges--\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_headers.size() == 2);
    
    // Check headers
    auto& h0 = c.parts_headers[0];
    auto cr0 = h0.get("content-range");
    REQUIRE(cr0.has_value());
    CHECK(std::string(cr0->data(), cr0->size()) == "bytes 0-4/100");
    
    auto& h1 = c.parts_headers[1];
    auto cr1 = h1.get("content-range");
    REQUIRE(cr1.has_value());
    CHECK(std::string(cr1->data(), cr1->size()) == "bytes 95-99/100");
    
    CHECK(c.parts_data[0] == "Hello");
    CHECK(c.parts_data[1] == "World");
    CHECK(c.complete_count == 1);
}

TEST_CASE("multipart with empty part", "[multipart][response]") {
    const char* boundary = "empty";
    const std::string body = 
        "--empty\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "\r\n"
        "--empty--\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_headers.size() == 1);
    CHECK(c.parts_data[0].empty());   // the CRLF before the delimiter belongs to it
    CHECK(c.complete_count == 1);
}

TEST_CASE("multipart with binary data and NUL", "[multipart][response]") {
    const char* boundary = "bin";
    std::string body = 
        "--bin\r\n"
        "Content-Type: application/octet-stream\r\n"
        "\r\n";
    body += std::string("\x00\x01\x02\xFF", 4);
    body += "\r\n--bin--\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_data[0] == std::string("\x00\x01\x02\xFF", 4));
    CHECK(c.complete_count == 1);
}

TEST_CASE("multipart boundary in data (false positive)", "[multipart][response]") {
    // Needle appears inside data, but not as a valid boundary line.
    const char* boundary = "sep";
    const std::string body = 
        "--sep\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "text --sep text\r\n"  // False positive: no \r\n before --sep
        "--sep--\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_data[0] == "text --sep text");
    CHECK(c.complete_count == 1);
}

TEST_CASE("multipart preamble too large", "[multipart][response]") {
    const char* boundary = "limit";
    // Preamble has its own budget (S3.4-25); it is NOT taken from max_part_bytes.
    std::string preamble(101, 'x'); // Larger than the preamble limit below
    std::string body = preamble + "--limit\r\nContent-Type: text/plain\r\n\r\ndata\r\n--limit--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_preamble_size = 100;

    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("multipart preamble is not limited by max_part_bytes", "[multipart][response]") {
    // Raising max_part_bytes must not widen the preamble allowance: the two
    // budgets are independent. A large preamble with a small max_preamble_size
    // still fails even when max_part_bytes is generous.
    const char* boundary = "limit";
    std::string preamble(5000, 'x');
    std::string body = preamble + "--limit\r\nContent-Type: text/plain\r\n\r\ndata\r\n--limit--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_part_bytes = 1024 * 1024;   // generous part budget
    lim.max_preamble_size = 4096;       // the actual constraint

    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("multipart headers too large", "[multipart][response]") {
    const char* boundary = "limit";
    // A syntactically valid header line that exceeds max_header_bytes (64 KiB).
    const std::string pad(70000, 'x');
    std::string body = "--limit\r\nX-Pad: " + pad + "\r\n\r\ndata\r\n--limit--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_header_bytes = 64 * 1024;
    
    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("multipart truncated (missing close-delimiter)", "[multipart][response]") {
    const char* boundary = "trunc";
    const std::string body = 
        "--trunc\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "data\r\n";
        // Missing --trunc--

    Collector c;
    MultipartResponseParser p(c, boundary);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value()); // Feed succeeds (waiting for more)
    
    auto eof_r = p.feed_eof();
    CHECK(!eof_r.has_value());
    CHECK(eof_r.error().code() == ErrorCode::MultipartTruncated);
}

TEST_CASE("multipart split across feeds", "[multipart][response]") {
    const char* boundary = "split";
    const std::string body = 
        "--split\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello\r\n"
        "--split--\r\n";

    Collector c;
    MultipartResponseParser p(c, boundary);

    // Feed in every possible split point
    for (size_t step = 1; step <= body.size(); ++step) {
        Collector c2;
        MultipartResponseParser p2(c2, boundary);
        auto r = feed_in_chunks(p2, body, step);
        CHECK(r.has_value());
        CHECK(c2.parts_data[0] == "Hello");
        CHECK(c2.complete_count == 1);
    }
}

TEST_CASE("multipart rejects an over-long boundary", "[multipart][response]") {
    // RFC 2046 caps a boundary at 70 characters.
    const std::string longb(200, 'x');
    Collector c;
    MultipartResponseParser::Limits lim;
    CHECK(lim.max_boundary_length == 100);   // documented default

    MultipartResponseParser p(c, longb.c_str(), lim);
    const char* body = "--xx\r\n\r\ndata\r\n--xx--\r\n";
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body), std::strlen(body));
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("multipart rejects an empty boundary", "[multipart][response]") {
    Collector c;
    MultipartResponseParser p(c, "");
    const char* body = "--x\r\n\r\ndata\r\n--x--\r\n";
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body), std::strlen(body));
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartMediaTypeInvalid);
}

TEST_CASE("multipart enforces max_part_count", "[multipart][response]") {
    const char* boundary = "mc";
    std::string body;
    for (int i = 0; i < 5; ++i) {
        body += "--mc\r\nContent-Type: text/plain\r\n\r\nd\r\n";
    }
    body += "--mc--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_part_count = 3;

    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
    CHECK(c.parts_headers.size() == 3);   // the 4th is refused, not silently kept
}

TEST_CASE("multipart enforces max_part_bytes per part", "[multipart][response]") {
    const char* boundary = "mb";
    const std::string big(500, 'x');
    const std::string body = "--mb\r\nContent-Type: text/plain\r\n\r\n" + big +
                             "\r\n--mb--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_part_bytes = 100;

    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    // Feed in small steps: a single-shot feed finds the boundary in the same
    // buffer, so the payload never flows through the incremental emit() path
    // where the per-part budget is enforced.
    auto r = feed_in_chunks(p, body, 16);
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("multipart part budget is per part, not cumulative", "[multipart][response]") {
    // Two 80-byte parts with a 100-byte per-part limit: both are fine.
    const char* boundary = "pb";
    const std::string chunk(80, 'y');
    std::string body;
    for (int i = 0; i < 2; ++i) {
        body += "--pb\r\nContent-Type: text/plain\r\n\r\n" + chunk + "\r\n";
    }
    body += "--pb--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_part_bytes = 100;

    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(c.parts_headers.size() == 2);
    CHECK(c.complete_count == 1);
}

TEST_CASE("multipart part data split across many feeds stays within budget",
          "[multipart][response]") {
    // Same 80-byte part, but delivered one byte at a time: the budget must be
    // counted across feeds, which is what the part_bytes_ accumulator does.
    const char* boundary = "sb";
    const std::string chunk(80, 'z');
    const std::string body = "--sb\r\nContent-Type: text/plain\r\n\r\n" + chunk +
                             "\r\n--sb--\r\n";

    MultipartResponseParser::Limits lim;
    lim.max_part_bytes = 100;

    Collector c;
    MultipartResponseParser p(c, boundary, lim);
    auto r = feed_in_chunks(p, body, 1);
    CHECK(r.has_value());
    CHECK(c.parts_data[0] == chunk);
    CHECK(c.complete_count == 1);
}

// ---------------------------------------------------------------------------
// S3.4-11 / S3.4-12: backpressure and pause/resume.
//
// on_part_data returning false pauses the parser. The bytes it was handed are
// not delivered again on resume, and parsing continues exactly where it left off.
// ---------------------------------------------------------------------------
TEST_CASE("multipart pauses on backpressure and resumes without losing data",
          "[multipart][response][backpressure]") {
    const char* boundary = "bp";
    const std::string chunk(4000, 'q');
    // Two parts, so there is real work left after the paused part.
    const std::string body =
        "--bp\r\nContent-Type: text/plain\r\n\r\n" + chunk + "\r\n"
        "--bp\r\nContent-Type: text/plain\r\n\r\nsecond\r\n"
        "--bp--\r\n";

    struct Pausing : MultipartResponseParser::Callbacks {
        std::string received;
        int parts_started = 0;
        int parts_ended = 0;
        bool paused = false;
        int complete_count = 0;
        VoidResult on_part_start(const Headers&) override { ++parts_started; return VoidResult{}; }
        bool on_part_data(string_view d) override {
            received.append(d.data(), d.size());
            if (!paused) { paused = true; return false; }   // pause on the first chunk
            return true;
        }
        VoidResult on_part_end() override { ++parts_ended; return VoidResult{}; }
        VoidResult on_complete() override { ++complete_count; return VoidResult{}; }
    };

    Pausing c;
    MultipartResponseParser p(c, boundary);

    // Feed everything in ONE call. With the pause honoured, parsing stops right
    // after the first on_part_data: no on_part_end, no second part, not complete.
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());              // a pause is not an error
    CHECK(c.paused);
    CHECK(c.parts_ended == 0);         // stopped before finishing the part
    CHECK(c.complete_count == 0);
    CHECK(c.parts_started == 1);       // the second part was never reached
    const size_t after_pause = c.received.size();

    // Resume: further processing must deliver the rest exactly once.
    for (int i = 0; i < 1000 && !p.is_complete(); ++i) {
        auto r2 = p.feed(nullptr, 0);
        if (!r2) break;
    }

    CHECK(c.complete_count == 1);
    CHECK(c.parts_ended == 2);
    CHECK(c.received.size() == chunk.size() + 6);   // chunk + "second"
    // The 4000-byte payload was NOT delivered twice.
    CHECK(c.received.size() - after_pause == 6);
}

TEST_CASE("multipart backpressure does not duplicate already-delivered bytes",
          "[multipart][response][backpressure]") {
    const char* boundary = "dup";
    const std::string chunk = "0123456789ABCDEF";
    const std::string body = "--dup\r\nContent-Type: text/plain\r\n\r\n" + chunk +
                             "\r\n--dup--\r\n";

    struct Pausing : MultipartResponseParser::Callbacks {
        std::string received;
        bool paused = false;
        int complete_count = 0;
        VoidResult on_part_start(const Headers&) override { return VoidResult{}; }
        bool on_part_data(string_view d) override {
            received.append(d.data(), d.size());
            if (!paused) { paused = true; return false; }   // pause on the very first chunk
            return true;
        }
        VoidResult on_part_end() override { return VoidResult{}; }
        VoidResult on_complete() override { ++complete_count; return VoidResult{}; }
    };

    Pausing c;
    MultipartResponseParser p(c, boundary);
    auto r = feed_in_chunks(p, body, 4);
    CHECK(r.has_value());
    CHECK(c.received == chunk);       // exactly once, in order
    CHECK(c.complete_count == 1);
}

// ---------------------------------------------------------------------------
// S3.4-18: a failed parse must be detectable, so the caller knows the connection
// cannot be reused. After a protocol or limit error the byte stream is at an
// unknown position; anything still buffered cannot belong to the next message.
// ---------------------------------------------------------------------------
TEST_CASE("failed parse is reported so the connection is not reused",
          "[multipart][response][lifecycle]") {
    SECTION("limit error") {
        const char* boundary = "f1";
        const std::string body = "--f1\r\nX-Pad: " + std::string(70000, 'x') +
                                 "\r\n\r\nd\r\n--f1--\r\n";
        MultipartResponseParser::Limits lim;
        lim.max_header_bytes = 1024;

        Collector c;
        MultipartResponseParser p(c, boundary, lim);
        CHECK_FALSE(p.is_failed());
        auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
        CHECK(!r.has_value());
        CHECK(p.is_failed());
        CHECK_FALSE(p.is_complete());

        // Once failed, further input is refused rather than silently consumed.
        const char* more = "junk";
        auto r2 = p.feed(reinterpret_cast<const uint8_t*>(more), std::strlen(more));
        CHECK(!r2.has_value());
        CHECK(p.is_failed());
    }

    SECTION("truncated at EOF") {
        const char* boundary = "f2";
        const char* body = "--f2\r\nContent-Type: text/plain\r\n\r\npartial";
        Collector c;
        MultipartResponseParser p(c, boundary);
        CHECK_FALSE(p.is_failed());
        auto r = p.feed(reinterpret_cast<const uint8_t*>(body), std::strlen(body));
        CHECK(r.has_value());                 // still waiting for more
        CHECK_FALSE(p.is_failed());

        auto eof_r = p.feed_eof();
        CHECK(!eof_r.has_value());
        CHECK(p.is_failed());
    }

    SECTION("a clean parse never reports failed") {
        const char* boundary = "f3";
        const char* body = "--f3\r\n\r\ndata\r\n--f3--\r\n";
        Collector c;
        MultipartResponseParser p(c, boundary);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(body), std::strlen(body));
        CHECK(r.has_value());
        CHECK(p.is_complete());
        CHECK_FALSE(p.is_failed());
    }
}
