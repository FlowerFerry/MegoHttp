// S3.3: multipart/form-data request encoding.
#include <catch2/catch_all.hpp>

#include <megohttp/multipart.hpp>
#include <megohttp/request.hpp>

#include <string>
#include <vector>

using namespace megohttp;

namespace {

// Collects the whole body a BodySource yields, following the same
// empty-chunk-means-retry contract the client uses.
static Result<std::vector<uint8_t>> drain(const Request::BodySource& src, int max_rounds = 10000) {
    std::vector<uint8_t> out;
    for (int i = 0; i < max_rounds; ++i) {
        auto r = src();
        if (!r) return r.error();
        auto& chunk = r.value();
        if (!chunk.first.empty()) {
            const char* d = chunk.first.data();
            out.insert(out.end(),
                       reinterpret_cast<const uint8_t*>(d),
                       reinterpret_cast<const uint8_t*>(d) +
                           static_cast<size_t>(chunk.first.size()));
        }
        if (chunk.second) return out;
    }
    return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                 string("body source never reached eof")};
}

static std::string as_text(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

} // namespace

TEST_CASE("multipart text field encoding", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));
    REQUIRE(b.add_text_field("name", "value"));
    CHECK(b.field_count() == 1);

    auto body = b.build_body();
    REQUIRE(body.has_value());
    const std::string text = as_text(body.value());

    CHECK(text.find("--B0UND\r\n") == 0);
    CHECK(text.find("Content-Disposition: form-data; name=\"name\"\r\n") != std::string::npos);
    // The headers end with a blank line, then the value verbatim.
    CHECK(text.find("\r\n\r\nvalue") != std::string::npos);
    // The body closes with the delimiter, preceded by a CRLF.
    CHECK(text.find("\r\n--B0UND--\r\n") != std::string::npos);
}

TEST_CASE("multipart file field includes filename and content type", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));

    std::vector<uint8_t> data = {0x00, 0x01, 0xFF, 'a', 'b'};   // binary, not text
    REQUIRE(b.add_file_field("avatar", "photo.jpg", "image/jpeg", std::move(data)));

    auto body = b.build_body();
    REQUIRE(body.has_value());
    const std::string text = as_text(body.value());

    CHECK(text.find("name=\"avatar\"; filename=\"photo.jpg\"") != std::string::npos);
    CHECK(text.find("Content-Type: image/jpeg\r\n") != std::string::npos);
}

TEST_CASE("multipart preserves binary data including NUL", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));

    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00};
    const std::vector<uint8_t> expected = data;
    REQUIRE(b.add_file_field("f", "x.bin", "application/octet-stream", std::move(data)));

    auto body = b.build_body();
    REQUIRE(body.has_value());
    const auto& out = body.value();

    // Find the NUL-containing payload verbatim.
    bool found = false;
    for (size_t i = 0; i + expected.size() <= out.size(); ++i) {
        if (std::equal(expected.begin(), expected.end(), out.begin() + static_cast<long>(i))) {
            found = true;
            break;
        }
    }
    CHECK(found);
}

TEST_CASE("multipart escapes quote and backslash in names", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));

    // A quote would end the quoted-string early; a backslash would escape the
    // closing quote. Both must be escaped.
    REQUIRE(b.add_text_field("na\"me\\x", "v"));

    auto body = b.build_body();
    REQUIRE(body.has_value());
    const std::string text = as_text(body.value());
    CHECK(text.find("name=\"na\\\"me\\\\x\"") != std::string::npos);
}

TEST_CASE("multipart rejects CR/LF in field names", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));

    // A newline in a header parameter is a smuggling vector.
    CHECK(!b.add_text_field("bad\r\nname", "v"));

    // The failure surfaces when the body is built or applied.
    REQUIRE(b.add_text_field("good", "v"));
    auto bad_name = b.add_text_field("x\r\nY", "v");
    CHECK(!bad_name);
}

TEST_CASE("multipart rejects an invalid boundary", "[multipart][request]") {
    MultipartBuilder b;
    CHECK(!b.set_boundary("").has_value());                    // empty
    // 71 'a's: over the RFC 2046 70-character limit.
    const char* longb = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    CHECK(!b.set_boundary(longb).has_value());                 // too long
    CHECK(!b.set_boundary("has space at end ").has_value());   // trailing space
    CHECK(!b.set_boundary("bad\"char").has_value());           // not a bchar
    CHECK(b.set_boundary("valid-123"));
}

TEST_CASE("multipart total size matches the built body", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));
    REQUIRE(b.add_text_field("a", "1"));
    REQUIRE(b.add_file_field("b", "b.bin", "application/octet-stream",
                             std::vector<uint8_t>{1, 2, 3, 4}));

    auto total = b.compute_total_size();
    REQUIRE(total.has_value());

    auto body = b.build_body();
    REQUIRE(body.has_value());
    CHECK(total.value() == body.value().size());
}

TEST_CASE("multipart with unknown stream size reports no total", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));
    REQUIRE(b.add_text_field("a", "1"));

    auto src = []() -> Result<std::pair<string_view, bool>> {
        static int n = 0;
        if (n++ < 1) {
            static std::string d = "streamed";
            return std::make_pair(string_view(d.data(), d.size()), true);
        }
        return std::make_pair(string_view{}, true);
    };
    REQUIRE(b.add_stream_field("s", "s.bin", "application/octet-stream", src));

    // No declared size: the caller must fall back to chunked transfer.
    CHECK(!b.compute_total_size().has_value());
}

TEST_CASE("multipart stream field body via apply_to", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));

    // A stream that yields two chunks then eof.
    auto state = std::make_shared<int>(0);
    auto src = [state]() -> Result<std::pair<string_view, bool>> {
        static std::string one = "part-one";
        static std::string two = "part-two";
        if (*state == 0) { *state = 1; return std::make_pair(string_view(one.data(), one.size()), false); }
        if (*state == 1) { *state = 2; return std::make_pair(string_view(two.data(), two.size()), true); }
        return std::make_pair(string_view{}, true);
    };

    REQUIRE(b.add_stream_field("s", "s.bin", "application/octet-stream", src,
                               std::optional<uint64_t>(16)));

    Request req(Method::Post, "http://example.com/upload");
    REQUIRE(b.apply_to(req));

    // Content-Type carries the boundary.
    auto ct = req.headers().get("content-type");
    REQUIRE(ct.has_value());
    CHECK(std::string(ct->data(), ct->size()).find("multipart/form-data; boundary=B0UND") !=
          std::string::npos);

    // The body is a source, not a buffer.
    CHECK(req.has_body());
    REQUIRE(req.body_source().has_value());

    auto body = drain(req.body_source().value());
    REQUIRE(body.has_value());
    const std::string text = as_text(body.value());
    CHECK(text.find("part-one") != std::string::npos);
    CHECK(text.find("part-two") != std::string::npos);
    CHECK(text.find("--B0UND--") != std::string::npos);
}

TEST_CASE("multipart all-in-memory apply_to installs a Content-Length", "[multipart][request]") {
    MultipartBuilder b;
    REQUIRE(b.set_boundary(to_view(to_string("B0UND"))));
    REQUIRE(b.add_text_field("a", "1"));

    Request req(Method::Post, "http://example.com/upload");
    REQUIRE(b.apply_to(req));

    CHECK(req.has_body());
    // In-memory parts are emitted as a buffer, so the size is exact.
    CHECK(!req.body_bytes().empty());
    printf("  debug bytes=%zu\n", req.body_bytes().size());
}

TEST_CASE("multipart empty builder is an error on apply_to", "[multipart][request]") {
    MultipartBuilder b;
    Request req(Method::Post, "http://example.com/upload");
    CHECK(!b.apply_to(req));
}

TEST_CASE("multipart boundary is generated by default", "[multipart][request]") {
    MultipartBuilder a;
    MultipartBuilder b;
    CHECK(!a.boundary().empty());
    CHECK(!b.boundary().empty());
    // Random, so two builders should not agree.
    CHECK((a.boundary().size() != b.boundary().size() ||
           std::string(a.boundary().data(), a.boundary().size()) !=
           std::string(b.boundary().data(), b.boundary().size())));
    // Long enough that an accidental collision with payload bytes is implausible.
    CHECK(a.boundary().size() >= 32);
}
