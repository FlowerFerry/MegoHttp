#include <megohttp/config.hpp>
#include <megohttp/multipart_response.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <string>
#include <optional>
#include <vector>

namespace megohttp {
namespace {

// Simple callback collector
struct MCollector : MultipartResponseParser::Callbacks {
    std::vector<Headers> parts_headers;
    std::vector<std::string> parts_data;
    int part_end_count{0};
    int complete_count{0};
    std::optional<Error> error;

    VoidResult on_part_start(const Headers& headers) override {
        parts_headers.push_back(headers);
        return VoidResult{};
    }
    bool on_part_data(string_view data) override {
        parts_data.emplace_back(data.data(), data.size());
        return true;
    }
    VoidResult on_part_end() override {
        ++part_end_count;
        return VoidResult{};
    }
    VoidResult on_complete() override {
        ++complete_count;
        return VoidResult{};
    }
};



TEST_CASE("continuous stream: EOF without close-delimiter completes normally", "[multipart][continuous]") {
    // No closing boundary, so feed_eof should succeed with allow_continuous_stream
    const std::string body =
        "preamble\r\n"
        "--boundary\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Part data\r\n"
        "--boundary\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Part 2\r\n";

    MCollector c;
    MultipartResponseParser::Limits lim;
    lim.allow_continuous_stream = true;
    MultipartResponseParser p(c, "boundary", lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(!p.is_complete()); // no closing boundary yet
    CHECK(!p.is_failed());

    // EOF simulates the connection ending
    r = p.feed_eof();
    CHECK(r.has_value());
    CHECK(p.is_complete());
    CHECK(!p.is_failed());
    CHECK(c.parts_data.size() == 2);
    CHECK(c.parts_data[0] == "Part data");
    CHECK(c.parts_data[1] == "Part 2");
    CHECK(c.part_end_count == 2);
    CHECK(c.complete_count == 1);
}

TEST_CASE("continuous stream: no parts, only preamble, EOF completes", "[multipart][continuous]") {
    const std::string body = "just preamble\r\n";

    MCollector c;
    MultipartResponseParser::Limits lim;
    lim.allow_continuous_stream = true;
    MultipartResponseParser p(c, "boundary", lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());

    r = p.feed_eof();
    CHECK(r.has_value());
    CHECK(p.is_complete());
    CHECK(c.complete_count == 1);
    CHECK(c.parts_data.empty());
}

TEST_CASE("finite stream: EOF without close-delimiter still fails", "[multipart][continuous]") {
    // allow_continuous_stream is OFF by default
    const std::string body =
        "--boundary\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Part data\r\n";

    MCollector c;
    MultipartResponseParser p(c, "boundary");
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());

    r = p.feed_eof();
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartTruncated);
    CHECK(!p.is_complete());
    CHECK(p.is_failed());
}

TEST_CASE("preamble has independent size limit", "[multipart][limits]") {
    MCollector c;
    MultipartResponseParser::Limits lim;
    lim.max_preamble_size = 10;

    MultipartResponseParser p(c, "boundary", lim);
    // Preamble: 20 bytes before first boundary
    std::string body = "1234567890123456789\r\n--boundary\r\nContent-Type: t\r\n\r\nX--boundary--\r\n";
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("epilogue has independent size limit", "[multipart][limits]") {
    MCollector c;
    MultipartResponseParser::Limits lim;
    lim.max_epilogue_size = 5;

    std::string body = "--boundary\r\nContent-Type: t\r\n\r\nHi\r\n--boundary--\r\n1234567890";
    MultipartResponseParser p(c, "boundary", lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    // The close-delimiter is found, but the epilogue that follows exceeds the cap
    CHECK(!r.has_value());
    CHECK(r.error().code() == ErrorCode::MultipartLimitExceeded);
}

TEST_CASE("epilogue within limit succeeds", "[multipart][limits]") {
    MCollector c;
    MultipartResponseParser::Limits lim;
    lim.max_epilogue_size = 100;

    std::string body = "--boundary\r\nContent-Type: t\r\n\r\nHi\r\n--boundary--\r\ntrailer";
    MultipartResponseParser p(c, "boundary", lim);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    CHECK(r.has_value());
    CHECK(p.is_complete());
    CHECK(p.leftover_offset() > 0);
}

} // namespace
} // namespace megohttp
