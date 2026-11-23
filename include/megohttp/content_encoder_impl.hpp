#ifndef MEGOHTTP_CONTENT_ENCODER_IMPL_HPP_INCLUDED
#define MEGOHTTP_CONTENT_ENCODER_IMPL_HPP_INCLUDED

#if !defined(MEGOHTTP_CONTENT_ENCODER_HPP_INCLUDED)
#error "Include content_encoder.hpp, not content_encoder_impl.hpp"
#endif

#include <megohttp/string_adapter.hpp>

// gzip/deflate need zlib; "br" needs Brotli's ENCODER. Both includes are gated
// so a build with neither keeps them out of the translation unit (task book 3.21).
#if MEGOHTTP_HAS_ZLIB
#include <zlib.h>
#endif

#if MEGOHTTP_HAS_BROTLI && MEGOHTTP_HAS_BROTLI_ENCODER
#include <brotli/encode.h>
#endif

#include <algorithm>
#include <limits>
#include <utility>

namespace megohttp {
namespace content_encoding_detail {

    inline const char* name_of(Request::Compression coding) noexcept {
        switch (coding) {
            case Request::Compression::Gzip:    return "gzip";
            case Request::Compression::Deflate: return "deflate";
            case Request::Compression::Brotli:  return "br";
            case Request::Compression::None:    break;
        }
        return nullptr;
    }

    inline bool request_coding_available(Request::Compression coding) noexcept {
        switch (coding) {
            case Request::Compression::None:
                return true;
            case Request::Compression::Gzip:
                // MEGOHTTP_HAS_GZIP already implies zlib was found and the HTTP
                // gzip feature was enabled; do not use HAS_ZLIB here or a build
                // with gzip disabled would still advertise/accept the coding.
                return MEGOHTTP_HAS_GZIP != 0;
            case Request::Compression::Deflate:
                // The decoder side is gated on zlib availability alone, so the
                // encoder follows the same rule: RFC 1950 zlib-wrapped DEFLATE.
                return MEGOHTTP_HAS_ZLIB != 0;
            case Request::Compression::Brotli:
                return MEGOHTTP_HAS_BROTLI != 0 && MEGOHTTP_HAS_BROTLI_ENCODER != 0;
        }
        return false;
    }

#if MEGOHTTP_HAS_ZLIB
    // Window bits: 31 = gzip wrapper (RFC 1952), 15 = zlib wrapper (RFC 1950).
    // Raw DEFLATE (-15) belongs to permessage-deflate and is NOT used here.
    inline Result<std::vector<uint8_t>> zlib_encode(const uint8_t* data,
                                                    size_t size,
                                                    int window_bits) {
        z_stream zs{};
        zs.zalloc = Z_NULL;
        zs.zfree = Z_NULL;
        zs.opaque = Z_NULL;
        int rc = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                              window_bits, 8, Z_DEFAULT_STRATEGY);
        if (rc == Z_MEM_ERROR) {
            return Error{ErrorCode::OutOfMemory, ErrorPhase::Send,
                         string("out of memory during request body compression")};
        }
        if (rc != Z_OK) {
            return Error{ErrorCode::ContentEncodingFailed, ErrorPhase::Send,
                         string("deflateInit2 failed for request body compression")};
        }

        // RAII: every return path must end the zlib stream.
        struct EndGuard {
            z_stream* s;
            ~EndGuard() { if (s->state) deflateEnd(s); }
        } guard{&zs};

        std::vector<uint8_t> out;
        constexpr size_t kOutChunk = 32768;
        size_t offset = 0;

        for (;;) {
            // `avail_in` is a uInt, which is 32-bit even on 64-bit Windows:
            // feed the input in chunks or a >4 GiB body would be truncated.
            if (zs.avail_in == 0 && offset < size) {
                const size_t remaining = size - offset;
                const size_t take = (std::min)(remaining,
                    static_cast<size_t>((std::numeric_limits<uInt>::max)()));
                zs.next_in = const_cast<Bytef*>(data + offset);
                zs.avail_in = static_cast<uInt>(take);
                offset += take;
            }

            const bool final_input = (offset >= size && zs.avail_in == 0);
            const size_t produced_at = out.size();
            out.resize(produced_at + kOutChunk);
            zs.next_out = out.data() + produced_at;
            zs.avail_out = static_cast<uInt>(kOutChunk);

            rc = deflate(&zs, final_input ? Z_FINISH : Z_NO_FLUSH);
            const size_t produced = kOutChunk - static_cast<size_t>(zs.avail_out);
            out.resize(produced_at + produced);

            if (rc == Z_STREAM_END) return out;
            if (rc == Z_MEM_ERROR) {
                return Error{ErrorCode::OutOfMemory, ErrorPhase::Send,
                             string("out of memory while compressing request body")};
            }
            if (rc != Z_OK && !(rc == Z_BUF_ERROR && produced > 0)) {
                return Error{ErrorCode::ContentEncodingFailed, ErrorPhase::Send,
                             string("unexpected deflate return code")};
            }
            // Z_BUF_ERROR with no progress and no input left cannot resolve;
            // fail instead of spinning forever.
            if (rc == Z_BUF_ERROR && produced == 0 && final_input) {
                return Error{ErrorCode::ContentEncodingFailed, ErrorPhase::Send,
                             string("deflate made no progress at end of input")};
            }
        }
    }
#endif // MEGOHTTP_HAS_ZLIB

#if MEGOHTTP_HAS_BROTLI && MEGOHTTP_HAS_BROTLI_ENCODER
    inline Result<std::vector<uint8_t>> brotli_encode(const uint8_t* data,
                                                      size_t size) {
        size_t capacity = BrotliEncoderMaxCompressedSize(size);
        if (capacity == 0) {
            return Error{ErrorCode::ContentEncodingFailed, ErrorPhase::Send,
                         string("brotli encoder could not size the output buffer")};
        }
        std::vector<uint8_t> out(capacity);
        size_t encoded_size = capacity;
        // Fixed policy for this iteration: quality 5 is the usual speed/size
        // balance, lgwin 22 is the Brotli default window. Not caller-tunable yet.
        const BROTLI_BOOL ok = BrotliEncoderCompress(
            5, 22, BROTLI_MODE_GENERIC, size, data, &encoded_size, out.data());
        if (!ok) {
            return Error{ErrorCode::ContentEncodingFailed, ErrorPhase::Send,
                         string("brotli encoder failed")};
        }
        out.resize(encoded_size);
        return out;
    }
#endif

    inline Result<std::vector<uint8_t>> encode_request_body(
            Request::Compression coding, const uint8_t* data, size_t size) {
        if (coding == Request::Compression::None || size == 0) {
            return std::vector<uint8_t>{};
        }
        if (!request_coding_available(coding)) {
            return Error{ErrorCode::ContentEncodingUnsupported, ErrorPhase::Send,
                         string("request body content encoding is not compiled in")};
        }

        switch (coding) {
            case Request::Compression::Gzip:
#if MEGOHTTP_HAS_GZIP && MEGOHTTP_HAS_ZLIB
                return zlib_encode(data, size, 31);
#else
                break;
#endif
            case Request::Compression::Deflate:
#if MEGOHTTP_HAS_ZLIB
                return zlib_encode(data, size, 15);
#else
                break;
#endif
            case Request::Compression::Brotli:
#if MEGOHTTP_HAS_BROTLI && MEGOHTTP_HAS_BROTLI_ENCODER
                return brotli_encode(data, size);
#else
                break;
#endif
            case Request::Compression::None:
                break;
        }
        return Error{ErrorCode::ContentEncodingUnsupported, ErrorPhase::Send,
                     string("request body content encoding is not compiled in")};
    }

    inline Result<PreparedRequestBody> prepare_request_body(const Request& request) {
        PreparedRequestBody prepared;
        const Request::Compression coding = request.compress_body();
        if (coding == Request::Compression::None) return prepared;

        // Nothing to encode. An explicitly empty body is still sent exactly as
        // before (Content-Length: 0 for a buffered body); wrapping zero bytes in
        // a gzip stream would change the request's wire meaning.
        if (!request.has_body()) return prepared;

        // The source check must come BEFORE the empty-buffer check: a BodySource
        // leaves body_bytes() empty, so testing that first would classify every
        // streaming upload as "nothing to do" and silently send it uncompressed.
        if (request.body_source().has_value()) {
            return Error{
                ErrorCode::NotImplemented, ErrorPhase::Send,
                string("streaming request body compression is not implemented; "
                       "use set_body (buffered) for compressed uploads")};
        }
        if (request.body_bytes().empty()) return prepared;

        // The head builder honours caller-supplied framing headers ("caller
        // wins"). Compressing around them would make the request lie about its
        // own length or apply the coding twice, so reject the combination.
        const Headers& headers = request.headers();
        if (headers.contains("content-encoding")) {
            return Error{
                ErrorCode::InvalidArgument, ErrorPhase::Send,
                string("set_compress_body conflicts with a caller-supplied "
                       "Content-Encoding header")};
        }
        if (headers.contains("content-length")) {
            return Error{
                ErrorCode::InvalidArgument, ErrorPhase::Send,
                string("set_compress_body conflicts with a caller-supplied "
                       "Content-Length header")};
        }
        if (headers.contains("transfer-encoding")) {
            return Error{
                ErrorCode::InvalidArgument, ErrorPhase::Send,
                string("set_compress_body conflicts with a caller-supplied "
                       "Transfer-Encoding header")};
        }

        auto bytes = encode_request_body(
            coding, request.body_bytes().data(), request.body_bytes().size());
        if (!bytes) return bytes.error();

        prepared.coding = coding;
        prepared.bytes = std::move(bytes.value());
        return prepared;
    }

} // namespace content_encoding_detail
} // namespace megohttp

#endif // MEGOHTTP_CONTENT_ENCODER_IMPL_HPP_INCLUDED
