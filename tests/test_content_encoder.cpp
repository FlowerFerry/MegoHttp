// Request body encoder unit tests (task book 7.3).
//
// These cover the codecs and the prepare/validate policy. The end-to-end wiring
// through Client lives in test_request_compression.cpp.

#include <catch2/catch_all.hpp>

#include <megohttp/content_decoder.hpp>
#include <megohttp/content_encoder.hpp>

#include <string>
#include <optional>
#include <vector>

using namespace megohttp;

namespace {

std::vector<uint8_t> bytes_of(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Decodes with the production decoder chain. The encoder and decoder are
// independent directions even when they share zlib, so this checks the output
// is a valid stream rather than merely non-empty.
bool decode_all(const char* coding, const std::vector<uint8_t>& wire,
                std::vector<uint8_t>& out) {
    std::optional<Error> err;
    std::vector<string> encodings;
    encodings.push_back(string(coding));
    auto chain = make_content_decoder_chain(
        encodings,
        [&out](const uint8_t* d, size_t n) {
            out.insert(out.end(), d, d + n);
            return true;
        },
        DecoderLimits{},
        &err);
    if (err || !chain) return false;
    auto fed = chain->feed(wire.data(), wire.size());
    if (!fed) return false;
    auto flushed = chain->flush();
    return static_cast<bool>(flushed);
}

const std::string kText =
    "request body compression: the quick brown fox jumps over the lazy dog. "
    "request body compression: the quick brown fox jumps over the lazy dog.";

} // namespace

TEST_CASE("gzip request encoding produces a decodable gzip stream",
          "[content][encoder][gzip]") {
#if MEGOHTTP_HAS_GZIP
    const auto input = bytes_of(kText);
    auto enc = content_encoding_detail::encode_request_body(
        Request::Compression::Gzip, input.data(), input.size());
    REQUIRE(enc);
    const auto& wire = enc.value();
    REQUIRE(wire.size() > 2);
    CHECK(wire[0] == 0x1f);
    CHECK(wire[1] == 0x8b);

    std::vector<uint8_t> back;
    REQUIRE(decode_all("gzip", wire, back));
    CHECK(back == input);
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("deflate request encoding uses the zlib wrapper",
          "[content][encoder][deflate]") {
#if MEGOHTTP_HAS_ZLIB
    const auto input = bytes_of(kText);
    auto enc = content_encoding_detail::encode_request_body(
        Request::Compression::Deflate, input.data(), input.size());
    REQUIRE(enc);
    const auto& wire = enc.value();
    REQUIRE(wire.size() > 2);
    // RFC 1950: CMF/FLG. The low nibble of CMF is 8 (deflate) for a zlib stream.
    CHECK((wire[0] & 0x0f) == 8);
    CHECK(((static_cast<unsigned>(wire[0]) << 8) | wire[1]) % 31 == 0);

    std::vector<uint8_t> back;
    REQUIRE(decode_all("deflate", wire, back));
    CHECK(back == input);
#else
    SUCCEED("zlib not compiled in");
#endif
}

TEST_CASE("brotli request encoding produces a decodable br stream",
          "[content][encoder][brotli]") {
#if MEGOHTTP_HAS_BROTLI && MEGOHTTP_HAS_BROTLI_ENCODER
    const auto input = bytes_of(kText);
    auto enc = content_encoding_detail::encode_request_body(
        Request::Compression::Brotli, input.data(), input.size());
    REQUIRE(enc);
    CHECK(!enc.value().empty());

    std::vector<uint8_t> back;
    REQUIRE(decode_all("br", enc.value(), back));
    CHECK(back == input);
#else
    SUCCEED("brotli encoder not compiled in");
#endif
}

TEST_CASE("a request with no coding is left untouched",
          "[content][encoder]") {
    Request req(Method::Post, "http://example.com/upload");
    req.set_body("hello");
    auto prepared = content_encoding_detail::prepare_request_body(req);
    REQUIRE(prepared);
    CHECK(prepared.value().coding == Request::Compression::None);
    CHECK(prepared.value().bytes.empty());
}

TEST_CASE("a request without a body is not given a Content-Encoding",
          "[content][encoder]") {
    Request req(Method::Get, "http://example.com/");
    req.set_compress_body(Request::Compression::Gzip);
    auto prepared = content_encoding_detail::prepare_request_body(req);
    REQUIRE(prepared);
    CHECK(prepared.value().coding == Request::Compression::None);
}

TEST_CASE("an explicitly empty body is not compressed",
          "[content][encoder]") {
    Request req(Method::Post, "http://example.com/upload");
    req.set_body("");
    req.set_compress_body(Request::Compression::Gzip);
    auto prepared = content_encoding_detail::prepare_request_body(req);
    REQUIRE(prepared);
    CHECK(prepared.value().coding == Request::Compression::None);
}

TEST_CASE("a streaming body cannot be compressed",
          "[content][encoder]") {
    Request req(Method::Post, "http://example.com/upload");
    req.set_body_source([]() -> Result<std::pair<string_view, bool>> {
        return std::make_pair(string_view{}, true);
    });
    req.set_compress_body(Request::Compression::Gzip);
    auto prepared = content_encoding_detail::prepare_request_body(req);
    REQUIRE(!prepared);
    CHECK(prepared.error().code() == ErrorCode::NotImplemented);
    CHECK(prepared.error().phase() == ErrorPhase::Send);
}

TEST_CASE("caller-supplied framing headers conflict with compression",
          "[content][encoder]") {
    struct Case { const char* name; const char* value; };
    const Case cases[] = {
        {"content-length", "7"},
        {"transfer-encoding", "chunked"},
        {"content-encoding", "identity"},
    };

    for (const auto& c : cases) {
        Request req(Method::Post, "http://example.com/upload");
        req.set_body("payload");
        req.set_compress_body(Request::Compression::Gzip);
        req.headers().set(c.name, c.value);

        auto prepared = content_encoding_detail::prepare_request_body(req);
        REQUIRE(!prepared);
        CHECK(prepared.error().code() == ErrorCode::InvalidArgument);
        CHECK(prepared.error().phase() == ErrorPhase::Send);
    }
}

TEST_CASE("a coding that is not compiled in is reported, not silently skipped",
          "[content][encoder]") {
    const uint8_t data[] = {'a', 'b', 'c'};

#if !MEGOHTTP_HAS_GZIP
    auto gz = content_encoding_detail::encode_request_body(
        Request::Compression::Gzip, data, sizeof data);
    REQUIRE(!gz);
    CHECK(gz.error().code() == ErrorCode::ContentEncodingUnsupported);
#endif

#if !MEGOHTTP_HAS_ZLIB
    auto df = content_encoding_detail::encode_request_body(
        Request::Compression::Deflate, data, sizeof data);
    REQUIRE(!df);
    CHECK(df.error().code() == ErrorCode::ContentEncodingUnsupported);
#endif

#if !(MEGOHTTP_HAS_BROTLI && MEGOHTTP_HAS_BROTLI_ENCODER)
    auto br = content_encoding_detail::encode_request_body(
        Request::Compression::Brotli, data, sizeof data);
    REQUIRE(!br);
    CHECK(br.error().code() == ErrorCode::ContentEncodingUnsupported);
#endif
}
