#ifndef MEGOHTTP_CONTENT_DECODER_IMPL_HPP_INCLUDED
#define MEGOHTTP_CONTENT_DECODER_IMPL_HPP_INCLUDED

#if !defined(MEGOHTTP_CONTENT_DECODER_HPP_INCLUDED)
#error "Include content_decoder.hpp, not content_decoder_impl.hpp"
#endif

#include <megohttp/string_adapter.hpp>

// gzip / deflate need zlib; "br" needs Brotli. When NEITHER is available the
// chain cannot decode anything, so this implementation is not compiled at all
// and content_decoder.hpp skips including it. That keeps a build with both
// features off free of the zlib/brotli headers (task book 3.21).
#if MEGOHTTP_HAS_ZLIB
#include <zlib.h>
#endif

#if MGHTTP_HAS_FEATURE_BROTLI
#include <brotli/decode.h>
#endif

#include <algorithm>
#include <string>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>

namespace megohttp {

    // ======================================================================
    // Individual decoders (each constructed with an OutputCallback)
    // ======================================================================

    // --- Gzip decoder (zlib, wbits=31) -----------------------------------

#if MEGOHTTP_HAS_ZLIB
    class GzipDecoder final : public ContentDecoder {
    public:
        explicit GzipDecoder(ContentDecoderChain::OutputCallback on_output)
            : on_output_(std::move(on_output)) {
            memset(&stream_, 0, sizeof(stream_));
            stream_.zalloc = Z_NULL;
            stream_.zfree = Z_NULL;
            stream_.opaque = Z_NULL;
            int rc = inflateInit2(&stream_, 31);  // gzip format
            if (rc != Z_OK) { inflateEnd(&stream_); stream_.state = nullptr; }
        }

        ~GzipDecoder() override {
            if (stream_.state) inflateEnd(&stream_);
        }

        VoidResult feed(const uint8_t* data, size_t size) override {
            if (size == 0) return VoidResult{};
            stream_.next_in = const_cast<uint8_t*>(data);
            stream_.avail_in = static_cast<uInt>(size);

            uint8_t out_buf[32768];
            while (stream_.avail_in > 0) {
                stream_.next_out = out_buf;
                stream_.avail_out = sizeof(out_buf);

                int rc = inflate(&stream_, Z_NO_FLUSH);
                size_t produced = sizeof(out_buf) - stream_.avail_out;
                if (produced > 0 && !on_output_(out_buf, produced)) {
                    return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive,
                                 string("sink rejected decompressed output")};
                }
                if (rc == Z_STREAM_END) { finished_ = true; return VoidResult{}; }
                if (rc == Z_BUF_ERROR) break;
                if (rc == Z_DATA_ERROR) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("corrupt gzip data")};
                if (rc == Z_MEM_ERROR) return Error{ErrorCode::OutOfMemory, ErrorPhase::Receive, string("out of memory during inflate")};
                if (rc != Z_OK) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("unexpected inflate return code")};
                if (stream_.avail_out == 0) continue;
                break;
            }
            return VoidResult{};
        }

        VoidResult flush() override {
            uint8_t out_buf[32768];
            for (;;) {
                stream_.next_out = out_buf;
                stream_.avail_out = sizeof(out_buf);
                int rc = inflate(&stream_, Z_FINISH);
                size_t produced = sizeof(out_buf) - stream_.avail_out;
                if (produced > 0 && !on_output_(out_buf, produced)) {
                    return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive, string("output rejected")};
                }
                if (rc == Z_STREAM_END) { finished_ = true; return VoidResult{}; }
                if (rc == Z_DATA_ERROR || rc == Z_MEM_ERROR) {
                    return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive,
                                 string("truncated or corrupt gzip data")};
                }
                // Z_BUF_ERROR here means the stream ended without the gzip
                // trailer: the deflate side saw no more input but never reached
                // Z_STREAM_END. Reporting success would turn a truncated body
                // into a silently short-but-valid one.
                if (rc == Z_BUF_ERROR) {
                    return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive,
                                 string("truncated gzip data: stream ended early")};
                }
                if (rc != Z_OK) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("unexpected inflate code")};
            }
        }

        bool is_finished() const noexcept override { return finished_; }

    private:
        ContentDecoderChain::OutputCallback on_output_;
        z_stream stream_{};
        bool finished_{false};
    };
#endif // MEGOHTTP_HAS_ZLIB

    // --- Brotli decoder --------------------------------------------------

#if MEGOHTTP_HAS_BROTLI
    class BrotliDecoderImpl final : public ContentDecoder {
    public:
        explicit BrotliDecoderImpl(ContentDecoderChain::OutputCallback on_output)
            : on_output_(std::move(on_output)) {
            state_ = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        }

        ~BrotliDecoderImpl() override {
            if (state_) BrotliDecoderDestroyInstance(state_);
        }

        VoidResult feed(const uint8_t* data, size_t size) override {
            if (size == 0) return VoidResult{};
            const uint8_t* next_in = data;
            size_t avail_in = size;
            uint8_t out_buf[32768];

            // Loop until the decoder either needs more input or finishes. The
            // output buffer filling up (avail_out == 0) means more output is
            // pending, so the loop must continue; only NEEDS_MORE_INPUT or
            // SUCCESS ends it. Returning on a full buffer dropped output.
            for (;;) {
                uint8_t* next_out = out_buf;
                size_t avail_out = sizeof(out_buf);

                BrotliDecoderResult result = BrotliDecoderDecompressStream(
                    state_, &avail_in, &next_in, &avail_out, &next_out, nullptr);

                size_t produced = sizeof(out_buf) - avail_out;
                if (produced > 0 && !on_output_(out_buf, produced)) {
                    return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive, string("output rejected")};
                }
                if (result == BROTLI_DECODER_RESULT_SUCCESS) { finished_ = true; return VoidResult{}; }
                if (result == BROTLI_DECODER_RESULT_ERROR) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("brotli decompression error")};
                if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) return VoidResult{};
                // NEEDS_MORE_OUTPUT: keep going, the decoder still has data.
            }
        }

        VoidResult flush() override {
            if (finished_) return VoidResult{};
            uint8_t out_buf[32768];
            for (;;) {
                uint8_t* next_out = out_buf;
                size_t avail_out = sizeof(out_buf);
                size_t avail_in = 0;
                const uint8_t* next_in = nullptr;
                BrotliDecoderResult result = BrotliDecoderDecompressStream(
                    state_, &avail_in, &next_in, &avail_out, &next_out, nullptr);
                size_t produced = sizeof(out_buf) - avail_out;
                if (produced > 0 && !on_output_(out_buf, produced)) return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive, string("output rejected")};
                if (result == BROTLI_DECODER_RESULT_SUCCESS) { finished_ = true; return VoidResult{}; }
                if (result == BROTLI_DECODER_RESULT_ERROR) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("truncated brotli data")};
                if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
                    // No more input will come; the stream never reached its end.
                    return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("truncated brotli data")};
                }
                // NEEDS_MORE_OUTPUT: drain the rest.
            }
        }

        bool is_finished() const noexcept override { return finished_; }

    private:
        ContentDecoderChain::OutputCallback on_output_;
        BrotliDecoderState* state_{nullptr};
        bool finished_{false};
    };
#endif

    // --- Deflate decoder (zlib wrapper, wbits=15) ------------------------

#if MEGOHTTP_HAS_ZLIB
    class DeflateDecoderImpl final : public ContentDecoder {
    public:
        explicit DeflateDecoderImpl(ContentDecoderChain::OutputCallback on_output)
            : on_output_(std::move(on_output)) {
            memset(&stream_, 0, sizeof(stream_));
            stream_.zalloc = Z_NULL;
            stream_.zfree = Z_NULL;
            stream_.opaque = Z_NULL;
            inflateInit(&stream_);  // wbits=15 = zlib wrapper
        }

        ~DeflateDecoderImpl() override {
            if (stream_.state) inflateEnd(&stream_);
        }

        VoidResult feed(const uint8_t* data, size_t size) override {
            if (size == 0) return VoidResult{};
            stream_.next_in = const_cast<uint8_t*>(data);
            stream_.avail_in = static_cast<uInt>(size);
            uint8_t out_buf[32768];
            while (stream_.avail_in > 0) {
                stream_.next_out = out_buf; stream_.avail_out = sizeof(out_buf);
                int rc = inflate(&stream_, Z_NO_FLUSH);
                size_t produced = sizeof(out_buf) - stream_.avail_out;
                if (produced > 0 && !on_output_(out_buf, produced)) return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive, string("output rejected")};
                if (rc == Z_STREAM_END) { finished_ = true; return VoidResult{}; }
                if (rc == Z_BUF_ERROR) break;
                if (rc == Z_DATA_ERROR) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("corrupt deflate")};
                if (rc == Z_MEM_ERROR) return Error{ErrorCode::OutOfMemory, ErrorPhase::Receive, string("out of memory")};
                if (rc != Z_OK) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("unexpected inflate")};
            }
            return VoidResult{};
        }

        VoidResult flush() override {
            uint8_t out_buf[32768];
            for (;;) {
                stream_.next_out = out_buf; stream_.avail_out = sizeof(out_buf);
                int rc = inflate(&stream_, Z_FINISH);
                size_t produced = sizeof(out_buf) - stream_.avail_out;
                if (produced > 0 && !on_output_(out_buf, produced)) return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive, string("output rejected")};
                if (rc == Z_STREAM_END) { finished_ = true; return VoidResult{}; }
                if (rc == Z_DATA_ERROR || rc == Z_MEM_ERROR) {
                    return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive,
                                 string("truncated or corrupt deflate data")};
                }
                if (rc == Z_BUF_ERROR) {
                    return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive,
                                 string("truncated deflate data: stream ended early")};
                }
                if (rc != Z_OK) return Error{ErrorCode::ContentDecodingFailed, ErrorPhase::Receive, string("unexpected inflate code")};
            }
        }

        bool is_finished() const noexcept override { return finished_; }

    private:
        ContentDecoderChain::OutputCallback on_output_;
        z_stream stream_{};
        bool finished_{false};
    };
#endif // MEGOHTTP_HAS_ZLIB

    // --- Stub factories (the real wiring is in the chain factory below) ---

    inline std::unique_ptr<ContentDecoder> make_gzip_decoder() {
#if MEGOHTTP_HAS_GZIP
        return nullptr;  // Use the constructor directly in the chain factory.
#else
        return nullptr;
#endif
    }

    inline std::unique_ptr<ContentDecoder> make_brotli_decoder() {
        return nullptr;
    }

    inline std::unique_ptr<ContentDecoder> make_deflate_decoder() {
        return nullptr;
    }

    // ======================================================================
    // ContentDecoderChain implementation
    // ======================================================================

    class ContentDecoderChain::Impl {
    public:
        Impl(DecoderLimits limits, OutputCallback on_output)
            : limits_(std::move(limits)), final_output_(std::move(on_output)) {}

        DecoderLimits limits_;
        OutputCallback final_output_;
        std::vector<std::shared_ptr<ContentDecoder>> decoders_;
        uint64_t wire_bytes_{0};
        uint64_t decoded_bytes_{0};
    };

    ContentDecoderChain::ContentDecoderChain(DecoderLimits limits, OutputCallback on_output)
        : impl_(std::make_unique<Impl>(std::move(limits), std::move(on_output))) {}

    void ContentDecoderChain::push(std::unique_ptr<ContentDecoder> decoder) {
        impl_->decoders_.push_back(std::shared_ptr<ContentDecoder>(decoder.release()));
    }

    bool ContentDecoderChain::empty() const noexcept {
        return impl_->decoders_.empty();
    }

    VoidResult ContentDecoderChain::feed(const uint8_t* data, size_t size) {
        if (impl_->decoders_.empty()) {
            return impl_->final_output_(data, size)
                ? VoidResult{}
                : Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive,
                        string("sink rejected pass-through bytes")};
        }
        impl_->wire_bytes_ += size;
        if (impl_->limits_.max_wire_bytes != 0 &&
            impl_->wire_bytes_ > impl_->limits_.max_wire_bytes) {
            return Error{ErrorCode::ContentDecodingResourceExceeded, ErrorPhase::Receive,
                         string("compressed wire bytes exceed limit")};
        }
        return impl_->decoders_.front()->feed(data, size);
    }

    VoidResult ContentDecoderChain::flush() {
        if (impl_->decoders_.empty()) return VoidResult{};
        return impl_->decoders_.front()->flush();
    }

    bool ContentDecoderChain::is_finished() const noexcept {
        if (impl_->decoders_.empty()) return true;
        return impl_->decoders_.front()->is_finished();
    }

    // --- Helper callbacks -------------------------------------------------

    using SharedError = std::shared_ptr<std::optional<Error>>;

    // The counter must be SHARED, not a raw pointer into a local shared_ptr:
    // the chain outlives the factory, and a dangling counter made the decoded
    // byte budget fire after one byte (observed as out=1/N).
    static inline ContentDecoderChain::OutputCallback
    make_next_decoder_cb(ContentDecoder* next_decoder, SharedError err_slot,
                         std::shared_ptr<uint64_t> decoded_bytes, uint64_t max_decoded_bytes) {
        return [next_decoder, err_slot, decoded_bytes, max_decoded_bytes]
               (const uint8_t* data, size_t size) -> bool {
            *decoded_bytes += size;
            if (max_decoded_bytes != 0 && *decoded_bytes > max_decoded_bytes) {
                *err_slot = Error{ErrorCode::ContentDecodingResourceExceeded,
                                  ErrorPhase::Receive, string("decoded bytes exceed limit")};
                return false;
            }
            auto r = next_decoder->feed(data, size);
            if (!r) {
                *err_slot = r.error();
                return false;
            }
            return true;
        };
    }

    // The budget failure has to be RECORDED, not just refused: the callback can
    // only return bool, and without an error in the slot the caller would see a
    // plain "sink said no" and the real cause would be lost.
    static inline ContentDecoderChain::OutputCallback
    make_final_cb(ContentDecoderChain::OutputCallback final_cb, SharedError err_slot,
                  std::shared_ptr<uint64_t> decoded_bytes, uint64_t max_decoded_bytes) {
        return [final_cb, err_slot, decoded_bytes, max_decoded_bytes]
               (const uint8_t* data, size_t size) -> bool {
            *decoded_bytes += size;
            if (max_decoded_bytes != 0 && *decoded_bytes > max_decoded_bytes) {
                *err_slot = Error{ErrorCode::ContentDecodingResourceExceeded,
                                  ErrorPhase::Receive,
                                  string("decoded bytes exceed limit")};
                return false;
            }
            return final_cb(data, size);
        };
    }

    // --- Chain factory ----------------------------------------------------

    inline std::unique_ptr<ContentDecoderChain>
    make_content_decoder_chain(const std::vector<string>& encodings,
                               ContentDecoderChain::OutputCallback final_cb,
                               DecoderLimits limits,
                               std::optional<Error>* err_slot) {
        if (encodings.empty()) return nullptr;

        // Decode order = reverse of wire order.
        // "gzip, br" means data was: original -> gzip -> br -> wire
        // Decode: br first, then gzip.
        std::vector<string> decode_order(encodings.rbegin(), encodings.rend());

        SharedError shared_err = std::make_shared<std::optional<Error>>();
        auto decoded = std::make_shared<uint64_t>(0);

        // Build innermost first: the decoder closest to the OUTPUT is the one
        // that undoes the FIRST applied encoding, and its output goes straight
        // to the final callback. Each earlier-created decoder's output feeds the
        // one created before it. `decode_order` is [last encoding ... first
        // encoding], so iterating it BACKWARDS builds exactly that order.
        ContentDecoderChain::OutputCallback current_cb =
            make_final_cb(final_cb, shared_err, decoded, limits.max_decoded_bytes);

        std::vector<std::shared_ptr<ContentDecoder>> built;   // output -> input

        for (auto it = decode_order.rbegin(); it != decode_order.rend(); ++it) {
            const string& enc = *it;
            std::shared_ptr<ContentDecoder> decoder;

            if (enc == "gzip") {
#if MEGOHTTP_HAS_ZLIB
                decoder = std::make_shared<GzipDecoder>(current_cb);
#else
                *err_slot = Error{ErrorCode::ContentEncodingUnsupported, ErrorPhase::Receive,
                                  string("gzip content encoding is not compiled in")};
                return nullptr;
#endif
            } else if (enc == "br") {
#if MEGOHTTP_HAS_BROTLI
                decoder = std::make_shared<BrotliDecoderImpl>(current_cb);
#else
                *err_slot = Error{ErrorCode::ContentEncodingUnsupported, ErrorPhase::Receive,
                                  string("brotli content encoding is not compiled in")};
                return nullptr;
#endif
            } else if (enc == "deflate") {
#if MEGOHTTP_HAS_ZLIB
                decoder = std::make_shared<DeflateDecoderImpl>(current_cb);
#else
                *err_slot = Error{ErrorCode::ContentEncodingUnsupported, ErrorPhase::Receive,
                                  string("deflate content encoding is not compiled in")};
                return nullptr;
#endif
            } else {
                string_builder mb;
                detail::sb_append(mb, to_view(string("unsupported content encoding: ")));
                detail::sb_append(mb, to_view(enc));
                *err_slot = Error{ErrorCode::ContentEncodingUnsupported, ErrorPhase::Receive,
                                  mb.release()};
                return nullptr;
            }

            built.push_back(decoder);
            current_cb = make_next_decoder_cb(decoder.get(), shared_err, decoded, limits.max_decoded_bytes);
        }

        // `built` runs output -> input, so the chain order (wire -> output) is
        // its reverse. The chain owns every decoder; the callbacks capture raw
        // pointers, which stay valid because the chain outlives them.
        auto chain = std::make_unique<ContentDecoderChain>(limits, final_cb);
        for (auto it = built.rbegin(); it != built.rend(); ++it) {
            chain->impl_->decoders_.push_back(*it);
        }

        return chain;
    }

    // --- Content-Encoding header parsing ----------------------------------

    inline std::vector<string> parse_content_encoding_header(string_view value) {
        if (value.empty()) return {};
        std::vector<string> encodings;
        size_t start = 0;
        while (start <= value.size()) {
            size_t comma = value.find(',', start);
            if (comma == string_view::npos) comma = value.size();
            size_t b = start;
            while (b < comma && (value[b] == ' ' || value[b] == '\t')) ++b;
            size_t e = comma;
            while (e > b && (value[e-1] == ' ' || value[e-1] == '\t')) --e;
            if (b < e) {
                // Lowercase the whole token in one owned buffer, then append it
                // once. Appending one character at a time through a view of a
                // loop-local char is not safe: the builder keeps the text it was
                // given, and reusing that slot produced the last character
                // repeated ("gzip" came out as "pppp").
                std::string lower;
                lower.reserve(e - b);
                for (size_t i = b; i < e; ++i) {
                    lower.push_back(static_cast<char>(
                        std::tolower(static_cast<unsigned char>(value[i]))));
                }
                string_builder tb;
                detail::sb_append(tb, string_view(lower.data(), lower.size()));
                string tok = tb.release();
                if (tok != "identity") encodings.push_back(std::move(tok));
            }
            start = comma + 1;
        }
        return encodings;
    }

} // namespace megohttp

#endif // MEGOHTTP_CONTENT_DECODER_IMPL_HPP_INCLUDED
