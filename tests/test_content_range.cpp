// S3.5: multipart/byteranges Content-Range parsing.
#include <catch2/catch_all.hpp>

#include <megohttp/content_range.hpp>

#include <string>

using namespace megohttp;

TEST_CASE("Content-Range parses a satisfied range", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes 0-499/1234");
    REQUIRE(r.has_value());
    const auto& cr = r.value();
    CHECK(cr.kind == ContentRange::Kind::Bytes);
    CHECK_FALSE(cr.unsatisfied);
    REQUIRE(cr.first.has_value());
    REQUIRE(cr.last.has_value());
    REQUIRE(cr.total.has_value());
    CHECK(cr.first.value() == 0);
    CHECK(cr.last.value() == 499);
    CHECK(cr.total.value() == 1234);
    CHECK(cr.length().value() == 500);
    CHECK(cr.is_known_length());
}

TEST_CASE("Content-Range parses an unsatisfied range", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes */1234");
    REQUIRE(r.has_value());
    const auto& cr = r.value();
    CHECK(cr.unsatisfied);
    CHECK_FALSE(cr.first.has_value());
    CHECK(cr.total.value() == 1234);
    // The resource length is known, but the PART carries no bytes -- that is what
    // is_known_length() reports, so it must be false here.
    CHECK_FALSE(cr.is_known_length());
    CHECK_FALSE(cr.length().has_value());
}

TEST_CASE("Content-Range accepts an unknown total", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes 0-9/*");
    REQUIRE(r.has_value());
    CHECK_FALSE(r.value().total.has_value());
    CHECK(r.value().length().value() == 10);
    CHECK_FALSE(r.value().is_known_length());
}

TEST_CASE("Content-Range is case-insensitive on the unit", "[byteranges][content-range]") {
    auto r = parse_content_range("BYTES 0-0/1");
    REQUIRE(r.has_value());
    CHECK(r.value().kind == ContentRange::Kind::Bytes);
}

TEST_CASE("Content-Range tolerates surrounding OWS", "[byteranges][content-range]") {
    auto r = parse_content_range("  bytes   0-4 / 100  ");
    REQUIRE(r.has_value());
    CHECK(r.value().first.value() == 0);
    CHECK(r.value().last.value() == 4);
    CHECK(r.value().total.value() == 100);
}

TEST_CASE("Content-Range reports an unsupported unit without failing", "[byteranges][content-range]") {
    auto r = parse_content_range("items 0-4/100");
    REQUIRE(r.has_value());
    CHECK(r.value().kind == ContentRange::Kind::Unsupported);
    // No numbers are interpreted for a unit we do not implement.
    CHECK_FALSE(r.value().first.has_value());
}

TEST_CASE("Content-Range rejects malformed values", "[byteranges][content-range]") {
    // empty
    CHECK(!parse_content_range("").has_value());
    // no separator
    CHECK(!parse_content_range("bytes 0-499").has_value());
    // no unit
    CHECK(!parse_content_range("0-499/1234").has_value());
    // reversed span
    CHECK(!parse_content_range("bytes 500-499/1234").has_value());
    // non-decimal
    CHECK(!parse_content_range("bytes 0-x/1234").has_value());
    // last outside the resource
    CHECK(!parse_content_range("bytes 0-1234/1234").has_value());
    // empty total
    CHECK(!parse_content_range("bytes 0-499/").has_value());
    // garbage after '*'
    CHECK(!parse_content_range("bytes *x/1234").has_value());
    CHECK(!parse_content_range("bytes */12x4").has_value());
    // empty range
    CHECK(!parse_content_range("bytes /1234").has_value());
}

TEST_CASE("Content-Range rejects overflow", "[byteranges][content-range]") {
    // 2^64 = 18446744073709551616, one past uint64 max
    CHECK(!parse_content_range("bytes 0-18446744073709551616/99999999999999999999").has_value());
    CHECK(!parse_content_range("bytes 0-9/18446744073709551616").has_value());
}

TEST_CASE("Content-Range accepts the uint64 boundary", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes 0-18446744073709551614/18446744073709551615");
    REQUIRE(r.has_value());
    CHECK(r.value().last.value() == 18446744073709551614ULL);
    CHECK(r.value().total.value() == 18446744073709551615ULL);
}

TEST_CASE("validate_content_range checks the part byte count", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes 0-4/100");
    REQUIRE(r.has_value());
    const auto& cr = r.value();

    // 0..4 inclusive is 5 bytes.
    CHECK(validate_content_range(cr, 5).has_value());
    // Any other count is a protocol error.
    CHECK(!validate_content_range(cr, 4).has_value());
    CHECK(!validate_content_range(cr, 6).has_value());
}

TEST_CASE("validate_content_range rejects data in an unsatisfied range", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes */100");
    REQUIRE(r.has_value());
    CHECK(validate_content_range(r.value(), 0).has_value());
    CHECK(!validate_content_range(r.value(), 1).has_value());
}

TEST_CASE("validate_content_range cross-checks the total", "[byteranges][content-range]") {
    auto r = parse_content_range("bytes 0-4/100");
    REQUIRE(r.has_value());

    // Matches the declared resource length.
    CHECK(validate_content_range(r.value(), 5, std::optional<uint64_t>(100)).has_value());
    // Disagrees: the response said 200 total, the part says 100.
    CHECK(!validate_content_range(r.value(), 5, std::optional<uint64_t>(200)).has_value());
}

TEST_CASE("validate_content_range skips an unsupported unit", "[byteranges][content-range]") {
    auto r = parse_content_range("items 0-4/100");
    REQUIRE(r.has_value());
    // Nothing to validate for a unit we do not implement.
    CHECK(validate_content_range(r.value(), 12345).has_value());
}
