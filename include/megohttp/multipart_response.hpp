#ifndef MEGOHTTP_MULTIPART_RESPONSE_HPP_INCLUDED
#define MEGOHTTP_MULTIPART_RESPONSE_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // MultipartResponseParser
    // ---------------------------------------------------------------------------
    // Parses a multipart MIME body (e.g. multipart/mixed, multipart/byteranges).
    // Designed to be fed by the Response body stream.
    class MultipartResponseParser {
    public:
        // Limits
        struct Limits {
            size_t max_boundary_length{100};
            size_t max_header_bytes{64 * 1024};
            size_t max_header_count{100};
            size_t max_part_count{100};
            uint64_t max_part_bytes{64ULL * 1024 * 1024};
            // Preamble and epilogue have their own budgets. Sharing max_part_bytes
            // would let raising the part cap silently widen the preamble allowance
            // (S3.4-25). Neither is buffered: the preamble is discarded as it
            // streams past, the epilogue is only counted.
            size_t max_preamble_size{8 * 1024};
            size_t max_epilogue_size{8 * 1024};

            // Continuous streams (multipart/x-mixed-replace) never send a closing
            // boundary: the body ends when the connection ends. With this set,
            // EOF without a close-delimiter ends the current part normally instead
            // of reporting MultipartTruncated. It MUST stay off for finite bodies,
            // where a missing close-delimiter is a truncation (RFC 2046 / spec
            // 7.2A).
            bool allow_continuous_stream{false};
        };

        // Callbacks
        struct Callbacks {
            virtual ~Callbacks() = default;
            // Called when headers for a new part are ready.
            virtual VoidResult on_part_start(const Headers& headers) = 0;
            // Called with part body data. View is valid only for the call duration.
            // Return `false` to pause (backpressure); `feed()` will return `VoidResult{}`
            // and resume from the same position on the next call.
            virtual bool on_part_data(string_view data) = 0;
            // Called when a part finishes.
            virtual VoidResult on_part_end() = 0;
            // Called when the whole message is done (closing boundary found).
            virtual VoidResult on_complete() = 0;
        };

        MultipartResponseParser(Callbacks& cbs, string_view boundary, Limits limits = {});
        ~MultipartResponseParser();

        MultipartResponseParser(const MultipartResponseParser&) = delete;
        MultipartResponseParser& operator=(const MultipartResponseParser&) = delete;
        MultipartResponseParser(MultipartResponseParser&&) noexcept;
        MultipartResponseParser& operator=(MultipartResponseParser&&) noexcept;

        // Feed body bytes. Can be called multiple times.
        // Returns error on protocol violation (malformed multipart, limits exceeded).
        VoidResult feed(const uint8_t* data, size_t size);
        
        // Signal end of stream.
        VoidResult feed_eof();

        // True if the closing boundary was found.
        bool is_complete() const noexcept;

        // True once the parser has hit a protocol or limit error. A failed parser
        // must be discarded and its connection must NOT be reused (S3.4-18): the
        // byte stream is in an unknown position, so anything left in the socket
        // cannot be attributed to the next message.
        bool is_failed() const noexcept;

        // Bytes of input that belong to the epilogue (after the closing boundary).
        size_t leftover_offset() const noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/multipart_response_impl.hpp>

#endif // MEGOHTTP_MULTIPART_RESPONSE_HPP_INCLUDED
