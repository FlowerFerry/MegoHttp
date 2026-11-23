#ifndef MEGOHTTP_CONTENT_DECODER_HPP_INCLUDED
#define MEGOHTTP_CONTENT_DECODER_HPP_INCLUDED

// Pluggable content decoder: a chain of decoders (gzip, brotli, ...)
// wired between the ResponseParser and the BodySink.
//
// The chain is built in REVERSE order of the Content-Encoding header,
// so the last encoder applied by the server is the first to be decoded.

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace megohttp {

    // Limits for the decoder chain, independent of the parser's limits.
    struct DecoderLimits {
        // Maximum compressed bytes consumed across ALL layers.
        // 0 = unlimited.
        uint64_t max_wire_bytes{256ULL * 1024 * 1024};

        // Maximum decompressed bytes produced across ALL layers.
        // 0 = unlimited.
        uint64_t max_decoded_bytes{256ULL * 1024 * 1024};

        // Maximum intermediate buffer for a single layer (prevents
        // unbounded caching when a downstream sink is paused).
        size_t max_intermediate_buffer{8 * 1024 * 1024};
    };

    // --- Abstract decoder interface ---------------------------------------

    class ContentDecoder {
    public:
        virtual ~ContentDecoder() = default;

        // Feeds compressed data. The decoder may emit zero or more output
        // chunks by calling the on_output callback.
        //
        // Returns:
        //   VoidResult{}          -- accepted more input
        //   Error (any code)      -- decoding error, chain must abort
        //
        // The decoder may return successfully while outputting nothing
        // (e.g. it has not yet accumulated a complete output frame).
        virtual VoidResult feed(const uint8_t* data, size_t size) = 0;

        // Flush: no more input. Decoder must emit all remaining buffered
        // output and reach the terminal state.
        //
        // Returns:
        //   VoidResult{}          -- finished cleanly
        //   Error                 -- truncated or invalid encoding
        virtual VoidResult flush() = 0;

        // Whether the decoder has finished (flush called and all output emitted).
        virtual bool is_finished() const noexcept = false;
    };

    // --- Chain -----------------------------------------------------------

    // A ContentDecoderChain wraps a series of decoders. Each decoder's
    // output is fed as input to the next one in the chain. The chain
    // exposes a single feed/flush interface.
    //
    // Construction order = decode order = reverse of the Content-Encoding header.
    // "Content-Encoding: gzip, br" means the data was original -> gzip -> br,
    // so decoding runs br first and then gzip: the wire-facing decoder
    // (decoders_.front()) is br, and its output feeds gzip.
    class ContentDecoderChain final : public ContentDecoder {
    public:
        using OutputCallback = std::function<bool(const uint8_t* data, size_t size)>;

        ContentDecoderChain(DecoderLimits limits, OutputCallback on_output);

        // Push a decoder onto the end of the chain. The chain takes ownership.
        void push(std::unique_ptr<ContentDecoder> decoder);

        // Returns whether the chain contains any decoders.
        bool empty() const noexcept;

        // ContentDecoder interface
        VoidResult feed(const uint8_t* data, size_t size) override;
        VoidResult flush() override;
        bool is_finished() const noexcept override;

    private:
        friend std::unique_ptr<ContentDecoderChain>
        make_content_decoder_chain(const std::vector<string>&,
                                   OutputCallback, DecoderLimits,
                                   std::optional<Error>*);
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    // --- Factory functions (backend-specific) ----------------------------
    // Each factory returns nullopt when the encoding is not compiled in.

    // "gzip" (RFC 1952, wbits=31). Returns ContentEncodingUnsupported if
    // gzip is not compiled in.
    std::unique_ptr<ContentDecoder> make_gzip_decoder();

    // "br" (RFC 7932, Brotli). Returns ContentEncodingUnsupported if
    // brotli is not compiled in.
    std::unique_ptr<ContentDecoder> make_brotli_decoder();

    // "deflate" (RFC 1950/1951 zlib-wrapped DEFLATE, wbits=15).
    // Note: this is NOT the same as the DEFLATE used by permessage-deflate
    // (which is raw DEFLATE, wbits=-15).
    std::unique_ptr<ContentDecoder> make_deflate_decoder();

    // "identity" is a no-op. The chain should not contain one.

    // --- Content-Encoding header parsing ----------------------------------
    // Returns the list of encoding names in wire order (e.g. {"gzip","br"}).
    // Empty = identity.
    std::vector<string> parse_content_encoding_header(string_view value);

} // namespace megohttp

#include <megohttp/content_decoder_impl.hpp>

#endif // MEGOHTTP_CONTENT_DECODER_HPP_INCLUDED
