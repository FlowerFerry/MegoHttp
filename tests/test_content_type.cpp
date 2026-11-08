// S3.4-24: Content-Type media-type and boundary extraction tests.
#include <megohttp/config.hpp>
#include <megohttp/content_type.hpp>
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace megohttp;

// ---------------------------------------------------------------------------
// parse_media_type: valid inputs
// ---------------------------------------------------------------------------

TEST_CASE("parse_media_type handles plain type/subtype", "[content_type]") {
    auto r = parse_media_type("text/plain");
    REQUIRE(r.has_value());
    CHECK(r.value().type == string("text"));
    CHECK(r.value().subtype == string("plain"));
    CHECK(!r.value().is_multipart());
}

TEST_CASE("parse_media_type handles parameters", "[content_type]") {
    auto r = parse_media_type("text/html; charset=UTF-8");
    REQUIRE(r.has_value());
    REQUIRE(r.value().parameter("charset"));
    CHECK(r.value().parameter("charset").value() == string_view("UTF-8"));
}

TEST_CASE("parse_media_type handles quoted parameter values", "[content_type]") {
    // Content-Type: multipart/mixed; boundary="--boundary"; charset=UTF-8
    const char* ct = "multipart/mixed; boundary=\"--boundary\"; charset=UTF-8";
    auto r = parse_media_type(ct);
    REQUIRE(r.has_value());
    REQUIRE(r.value().parameter("boundary"));
    CHECK(r.value().parameter("boundary").value() == string_view("--boundary"));
}

TEST_CASE("parse_media_type unescapes quoted-pair in a quoted value", "[content_type]") {
    // RFC 2045 quoted-pair: \" inside a quoted string yields a literal quote.
    const char* ct = "multipart/mixed; boundary=\"a\\\"b\"";
    auto r = parse_media_type(ct);
    REQUIRE(r.has_value());
    REQUIRE(r.value().parameter("boundary"));
    CHECK(r.value().parameter("boundary").value() == string_view("a\"b"));
}

TEST_CASE("parse_media_type handles OWS around semicolons", "[content_type]") {
    auto r = parse_media_type("text/html  ;  charset = \"UTF-8\"  ;  lang = en");
    REQUIRE(r.has_value());
    REQUIRE(r.value().parameter("charset"));
    REQUIRE(r.value().parameter("lang"));
    CHECK(r.value().parameter("lang").value() == string_view("en"));
}

TEST_CASE("parse_media_type lowercases type and subtype", "[content_type]") {
    auto r = parse_media_type("TEXT/PLAIN");
    REQUIRE(r.has_value());
    CHECK(r.value().type == string("text"));
    CHECK(r.value().subtype == string("plain"));
}

// ---------------------------------------------------------------------------
// parse_media_type: rejections
// ---------------------------------------------------------------------------

TEST_CASE("parse_media_type rejects empty value", "[content_type]") {
    CHECK(!parse_media_type("").has_value());
}

TEST_CASE("parse_media_type rejects missing subtype", "[content_type]") {
    CHECK(!parse_media_type("text").has_value());
}

TEST_CASE("parse_media_type rejects empty parameter name", "[content_type]") {
    CHECK(!parse_media_type("text/html; =value").has_value());
}

TEST_CASE("parse_media_type rejects parameter without equals", "[content_type]") {
    CHECK(!parse_media_type("text/html; charset").has_value());
}

TEST_CASE("parse_media_type rejects unterminated quoted string", "[content_type]") {
    CHECK(!parse_media_type("text/html; charset=\"UTF-8").has_value());
}

TEST_CASE("parse_media_type rejects duplicate conflicting parameter", "[content_type]") {
    CHECK(!parse_media_type("text/html; charset=UTF-8; charset=ASCII").has_value());
}

TEST_CASE("parse_media_type accepts identical duplicate parameter", "[content_type]") {
    auto r = parse_media_type("text/html; charset=UTF-8; charset=UTF-8");
    REQUIRE(r.has_value());
    REQUIRE(r.value().parameter("charset"));
    CHECK(r.value().parameter("charset").value() == string_view("UTF-8"));
}

// ---------------------------------------------------------------------------
// parse_multipart_boundary
// ---------------------------------------------------------------------------

TEST_CASE("parse_multipart_boundary extracts simple boundary", "[content_type]") {
    auto r = parse_multipart_boundary("multipart/mixed; boundary=myboundary");
    REQUIRE(r.has_value());
    CHECK(r.value() == string("myboundary"));
}

TEST_CASE("parse_multipart_boundary extracts quoted boundary", "[content_type]") {
    auto r = parse_multipart_boundary("multipart/mixed; boundary=\"my-boundary_123\"");
    REQUIRE(r.has_value());
    CHECK(r.value() == string("my-boundary_123"));
}

TEST_CASE("parse_multipart_boundary rejects non-multipart type", "[content_type]") {
    CHECK(!parse_multipart_boundary("text/plain; boundary=x").has_value());
}

TEST_CASE("parse_multipart_boundary rejects empty boundary", "[content_type]") {
    CHECK(!parse_multipart_boundary("multipart/mixed; boundary=").has_value());
}

TEST_CASE("parse_multipart_boundary rejects boundary over 70 chars", "[content_type]") {
    std::string longb(71, 'a');
    std::string ct = "multipart/mixed; boundary=" + longb;
    CHECK(!parse_multipart_boundary(string_view(ct.data(), ct.size())).has_value());
}

TEST_CASE("parse_multipart_boundary rejects illegal characters in boundary", "[content_type]") {
    CHECK(!parse_multipart_boundary("multipart/mixed; boundary=\"abc def\"").has_value());
}

TEST_CASE("parse_multipart_boundary rejects trailing space", "[content_type]") {
    CHECK(!parse_multipart_boundary("multipart/mixed; boundary=\"abc \"").has_value());
}

TEST_CASE("parse_multipart_boundary rejects conflicting duplicate boundary params", "[content_type]") {
    CHECK(!parse_multipart_boundary("multipart/mixed; boundary=a; boundary=b").has_value());
}

TEST_CASE("parse_multipart_boundary accepts identical duplicate boundary", "[content_type]") {
    auto r = parse_multipart_boundary("multipart/mixed; boundary=a; boundary=a");
    REQUIRE(r.has_value());
    CHECK(r.value() == string("a"));
}

TEST_CASE("parse_multipart_boundary validates subtype against whitelist", "[content_type]") {
    std::vector<string> allowed;
    allowed.push_back(string("mixed"));
    allowed.push_back(string("related"));

    auto r1 = parse_multipart_boundary("multipart/mixed; boundary=x", allowed);
    REQUIRE(r1.has_value());

    auto r2 = parse_multipart_boundary("multipart/byteranges; boundary=x", allowed);
    CHECK(!r2.has_value());
}

TEST_CASE("parse_multipart_boundary accepts any subtype when list is empty", "[content_type]") {
    auto r = parse_multipart_boundary("multipart/x-my-custom; boundary=x");
    REQUIRE(r.has_value());
    CHECK(r.value() == string("x"));
}

TEST_CASE("parse_multipart_boundary handles leading and trailing OWS", "[content_type]") {
    auto r = parse_multipart_boundary("  multipart/mixed ; boundary=bb  ");
    REQUIRE(r.has_value());
    CHECK(r.value() == string("bb"));
}

TEST_CASE("parse_multipart_boundary rejects missing boundary parameter", "[content_type]") {
    CHECK(!parse_multipart_boundary("multipart/mixed; charset=utf-8").has_value());
}
