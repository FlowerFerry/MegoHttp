#ifndef MEGOHTTP_CONTENT_ENCODER_HPP_INCLUDED
#define MEGOHTTP_CONTENT_ENCODER_HPP_INCLUDED

// Request body content encoder (task book 7.3): the SENDING counterpart of
// content_decoder.hpp.
//
// Compression is opt-in per request (`Request::set_compress_body`). The default
// is None, which leaves the request byte-for-byte identical to a build without
// this feature. Only a buffered body is compressed; a BodySource is rejected
// explicitly at submission rather than sent as plaintext under a
// Content-Encoding header.
//
// Availability is per coding, not per library:
//   gzip    -> MEGOHTTP_HAS_GZIP                 (HTTP gzip feature enabled)
//   deflate -> MEGOHTTP_HAS_ZLIB                 (zlib; RFC 1950 wrapper)
//   br      -> MEGOHTTP_HAS_BROTLI &&
//              MEGOHTTP_HAS_BROTLI_ENCODER       (encoder library present)
// Asking for a coding this build cannot produce returns
// ContentEncodingUnsupported instead of silently sending uncompressed bytes.

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/request.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace megohttp {
namespace content_encoding_detail {

    // Wire name for a coding: "gzip" / "deflate" / "br". Null for None.
    const char* name_of(Request::Compression coding) noexcept;

    // Whether this build can PRODUCE the coding (not merely decode it).
    bool request_coding_available(Request::Compression coding) noexcept;

    // Encodes `size` bytes at `data`. Returns an empty vector for None or for
    // zero-length input (the caller sends no Content-Encoding in that case).
    Result<std::vector<uint8_t>> encode_request_body(Request::Compression coding,
                                                     const uint8_t* data,
                                                     size_t size);

    struct PreparedRequestBody {
        Request::Compression coding{Request::Compression::None};
        std::vector<uint8_t> bytes;
    };

    // Validates the request's body/header combination and encodes it when a
    // coding is requested. This is the policy layer: it rejects
    //   - caller-supplied Content-Encoding / Content-Length / Transfer-Encoding
    //     combined with compression (the head would lie about the body),
    //   - a BodySource (streaming compression is not implemented).
    // A request without a body, or with an explicitly empty buffered body, is
    // left untouched: there are no bytes to encode, and turning a zero-length
    // body into a compressed empty stream would change its wire meaning.
    Result<PreparedRequestBody> prepare_request_body(const Request& request);

} // namespace content_encoding_detail
} // namespace megohttp

#include <megohttp/content_encoder_impl.hpp>

#endif // MEGOHTTP_CONTENT_ENCODER_HPP_INCLUDED
