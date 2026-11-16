// Content-Encoding decoder tests (S5.6): gzip, brotli, deflate, multi-layer
// chains, truncation, corruption and the wire/decoded length bookkeeping.
//
// The compressed fixtures are built here with zlib/brotli's own encoders so the
// test never depends on a pre-made blob nobody can regenerate.

#include <catch2/catch_all.hpp>

#include <megohttp/content_decoder.hpp>

#include <zlib.h>
#if MEGOHTTP_HAS_BROTLI
#include <brotli/encode.h>
#endif

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace megohttp;

namespace {

// --- encoders used only to build fixtures -------------------------------

std::vector<uint8_t> gzip_compress(const std::string& in) {
    z_stream s{};
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return {};
    }
    std::vector<uint8_t> out(deflateBound(&s, static_cast<uLong>(in.size())) + 64);
    s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    s.avail_in = static_cast<uInt>(in.size());
    s.next_out = out.data();
    s.avail_out = static_cast<uInt>(out.size());
    const int rc = deflate(&s, Z_FINISH);
    const size_t produced = out.size() - s.avail_out;
    deflateEnd(&s);
    if (rc != Z_STREAM_END) return {};
    out.resize(produced);
    return out;
}

std::vector<uint8_t> deflate_compress(const std::string& in) {
    z_stream s{};
    if (deflateInit(&s, Z_DEFAULT_COMPRESSION) != Z_OK) return {};
    std::vector<uint8_t> out(deflateBound(&s, static_cast<uLong>(in.size())) + 64);
    s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    s.avail_in = static_cast<uInt>(in.size());
    s.next_out = out.data();
    s.avail_out = static_cast<uInt>(out.size());
    const int rc = deflate(&s, Z_FINISH);
    const size_t produced = out.size() - s.avail_out;
    deflateEnd(&s);
    if (rc != Z_STREAM_END) return {};
    out.resize(produced);
    return out;
}

#if MEGOHTTP_HAS_BROTLI
std::vector<uint8_t> brotli_compress(const std::string& in) {
    size_t cap = BrotliEncoderMaxCompressedSize(in.size());
    if (cap == 0) cap = in.size() + 1024;
    std::vector<uint8_t> out(cap);
    size_t out_size = cap;
    if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                              BROTLI_MODE_GENERIC, in.size(),
                              reinterpret_cast<const uint8_t*>(in.data()),
                              &out_size, out.data())) {
        return {};
    }
    out.resize(out_size);
    return out;
}
#endif

// Runs a chain over `data` and collects what it produces.
struct DecodeOutcome {
    std::string out;
    std::optional<Error> err;
    bool sink_refused{false};
    int sink_calls{0};
};

DecodeOutcome run_chain(const std::vector<string>& encodings,
                        const std::vector<uint8_t>& wire,
                        DecoderLimits limits = DecoderLimits{},
                        size_t chunk = 0,          // 0 = one feed
                        size_t refuse_after = SIZE_MAX) {
    DecodeOutcome oc;
    std::optional<Error> chain_err;
    auto chain = make_content_decoder_chain(
        encodings,
        [&oc, refuse_after](const uint8_t* d, size_t n) -> bool {
            ++oc.sink_calls;
            if (static_cast<size_t>(oc.sink_calls) > refuse_after) {
                oc.sink_refused = true;
                return false;
            }
            oc.out.append(reinterpret_cast<const char*>(d), n);
            return true;
        },
        limits, &chain_err);
    if (chain_err) { oc.err = chain_err; return oc; }
    if (!chain) return oc;   // identity

    if (chunk == 0) {
        auto r = chain->feed(wire.data(), wire.size());
        if (!r) { oc.err = r.error(); return oc; }
    } else {
        size_t i = 0;
        while (i < wire.size()) {
            const size_t n = std::min(chunk, wire.size() - i);
            auto r = chain->feed(wire.data() + i, n);
            if (!r) { oc.err = r.error(); return oc; }
            i += n;
        }
    }
    auto fr = chain->flush();
    if (!fr) { oc.err = fr.error(); return oc; }
    return oc;
}

const std::string kPayload = "the quick brown fox jumps over the lazy dog, "
                             "repeat repeat repeat repeat repeat";

} // namespace

// ---------------------------------------------------------------------------

TEST_CASE("content encoding header is parsed in wire order", "[content][decode]") {
    auto v = parse_content_encoding_header("gzip, br");
    REQUIRE(v.size() == 2);
    CHECK(v[0] == "gzip");
    CHECK(v[1] == "br");

    // Whitespace, case and the identity coding.
    auto v2 = parse_content_encoding_header("  GZIP ,\tidentity , BR ");
    REQUIRE(v2.size() == 2);
    CHECK(v2[0] == "gzip");
    CHECK(v2[1] == "br");

    CHECK(parse_content_encoding_header("").empty());
    CHECK(parse_content_encoding_header("identity").empty());
    CHECK(parse_content_encoding_header("   ").empty());
}

TEST_CASE("gzip round trip decodes to the original bytes", "[content][decode][gzip]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = gzip_compress(kPayload);
    REQUIRE(!wire.empty());
    auto oc = run_chain({"gzip"}, wire);
    REQUIRE(!oc.err);
    CHECK(oc.out == kPayload);
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("gzip decoding is incremental across arbitrary feed sizes",
          "[content][decode][gzip]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = gzip_compress(kPayload);
    REQUIRE(!wire.empty());
    // Every split point must produce identical output: the decoder must not
    // assume a whole frame per feed.
    for (size_t step : {size_t(1), size_t(2), size_t(3), size_t(7), size_t(13)}) {
        auto oc = run_chain({"gzip"}, wire, DecoderLimits{}, step);
        REQUIRE(!oc.err);
        CHECK(oc.out == kPayload);
    }
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("truncated gzip is a decoding failure, not a short body",
          "[content][decode][gzip]") {
#if MEGOHTTP_HAS_GZIP
    auto wire = gzip_compress(kPayload);
    REQUIRE(wire.size() > 8);
    wire.resize(wire.size() / 2);          // cut mid-stream
    auto oc = run_chain({"gzip"}, wire);
    REQUIRE(oc.err.has_value());
    CHECK(oc.err->code() == ErrorCode::ContentDecodingFailed);
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("corrupt gzip is reported as ContentDecodingFailed",
          "[content][decode][gzip]") {
#if MEGOHTTP_HAS_GZIP
    auto wire = gzip_compress(kPayload);
    REQUIRE(wire.size() > 20);
    // Damage the deflate payload past the 10-byte gzip header.
    for (size_t i = 12; i < 20 && i < wire.size(); ++i) wire[i] ^= 0xFF;
    auto oc = run_chain({"gzip"}, wire);
    REQUIRE(oc.err.has_value());
    CHECK(oc.err->code() == ErrorCode::ContentDecodingFailed);
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("deflate (zlib wrapper) round trip", "[content][decode][deflate]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = deflate_compress(kPayload);
    REQUIRE(!wire.empty());
    auto oc = run_chain({"deflate"}, wire);
    REQUIRE(!oc.err);
    CHECK(oc.out == kPayload);
#else
    SUCCEED("deflate not compiled in");
#endif
}

TEST_CASE("gzip data is not accepted as deflate",
          "[content][decode][deflate]") {
#if MEGOHTTP_HAS_GZIP
    // The two are different container formats; feeding one to the other must
    // fail rather than silently produce garbage.
    const auto gz = gzip_compress(kPayload);
    auto oc = run_chain({"deflate"}, gz);
    REQUIRE(oc.err.has_value());
#else
    SUCCEED("deflate not compiled in");
#endif
}

#if MEGOHTTP_HAS_BROTLI

TEST_CASE("brotli round trip decodes to the original bytes", "[content][decode][br]") {
    const auto wire = brotli_compress(kPayload);
    REQUIRE(!wire.empty());
    auto oc = run_chain({"br"}, wire);
    REQUIRE(!oc.err);
    CHECK(oc.out == kPayload);
}

TEST_CASE("brotli decoding is incremental across arbitrary feed sizes",
          "[content][decode][br]") {
    const auto wire = brotli_compress(kPayload);
    REQUIRE(!wire.empty());
    for (size_t step : {size_t(1), size_t(3), size_t(11)}) {
        auto oc = run_chain({"br"}, wire, DecoderLimits{}, step);
        REQUIRE(!oc.err);
        CHECK(oc.out == kPayload);
    }
}

TEST_CASE("truncated brotli is reported", "[content][decode][br]") {
    auto wire = brotli_compress(kPayload);
    REQUIRE(wire.size() > 4);
    wire.resize(wire.size() / 2);
    auto oc = run_chain({"br"}, wire);
    REQUIRE(oc.err.has_value());
    CHECK(oc.err->code() == ErrorCode::ContentDecodingFailed);
}

TEST_CASE("a two-layer gzip+br chain decodes in reverse order",
          "[content][decode][multi]") {
    // Wire order "gzip, br" means: original -> gzip -> br.
    const auto inner = gzip_compress(kPayload);
    REQUIRE(!inner.empty());
    const std::string inner_str(reinterpret_cast<const char*>(inner.data()), inner.size());
    const auto wire = brotli_compress(inner_str);
    REQUIRE(!wire.empty());

    auto oc = run_chain({"gzip", "br"}, wire);
    REQUIRE(!oc.err);
    CHECK(oc.out == kPayload);
}

#else

TEST_CASE("brotli is reported unsupported when not compiled in",
          "[content][decode][br]") {
    std::optional<Error> err;
    auto chain = make_content_decoder_chain(
        {"br"}, [](const uint8_t*, size_t) { return true; },
        DecoderLimits{}, &err);
    REQUIRE(!chain);
    REQUIRE(err.has_value());
    CHECK(err->code() == ErrorCode::ContentEncodingUnsupported);
}

#endif

TEST_CASE("an unknown coding is rejected rather than guessed",
          "[content][decode]") {
    std::optional<Error> err;
    auto chain = make_content_decoder_chain(
        {"compress"}, [](const uint8_t*, size_t) { return true; },
        DecoderLimits{}, &err);
    REQUIRE(!chain);
    REQUIRE(err.has_value());
    CHECK(err->code() == ErrorCode::ContentEncodingUnsupported);
}

TEST_CASE("the decoded-bytes limit stops an expansion bomb",
          "[content][decode][limits]") {
#if MEGOHTTP_HAS_GZIP
    // 1 MiB of zeros compresses to almost nothing and expands huge: exactly the
    // shape a decoder limit exists for.
    const std::string bomb(1024 * 1024, '\0');
    const auto wire = gzip_compress(bomb);
    REQUIRE(!wire.empty());

    DecoderLimits lim;
    lim.max_decoded_bytes = 4096;
    auto oc = run_chain({"gzip"}, wire, lim);
    // The budget is checked BEFORE the caller's sink sees the chunk, so the sink
    // is not the party that refuses: the chain reports the limit itself.
    CHECK(oc.out.size() <= 4096);
    REQUIRE(oc.err.has_value());
    CHECK(oc.err->code() == ErrorCode::ContentDecodingResourceExceeded);
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("the wire-bytes limit is enforced before decoding",
          "[content][decode][limits]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = gzip_compress(kPayload);
    REQUIRE(!wire.empty());
    DecoderLimits lim;
    lim.max_wire_bytes = wire.size() - 1;   // one byte short
    auto oc = run_chain({"gzip"}, wire, lim);
    REQUIRE(oc.err.has_value());
    CHECK(oc.err->code() == ErrorCode::ContentDecodingResourceExceeded);
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("identity data passes through untouched when there is no chain",
          "[content][decode]") {
    // make_content_decoder_chain returns null for an empty encoding list, which
    // is what the Client uses to mean "no decoding".
    std::optional<Error> err;
    auto chain = make_content_decoder_chain(
        {}, [](const uint8_t*, size_t) { return true; }, DecoderLimits{}, &err);
    CHECK(!chain);
    CHECK(!err.has_value());
}
