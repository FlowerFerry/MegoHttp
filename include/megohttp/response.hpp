#ifndef MEGOHTTP_RESPONSE_HPP_INCLUDED
#define MEGOHTTP_RESPONSE_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // ResponseHead
    //
    // All text is owning: this is handed to the caller and must not alias the
    // parser's buffer. The parsed fields record header facts verbatim; a caller
    // never has to re-parse them.
    // ---------------------------------------------------------------------------
    struct ResponseHead {
        int status_code{0};
        string status_text;              // reason phrase as received
        Headers headers;                 // owning copies, duplicates preserved

        std::optional<uint64_t> content_length;
        bool is_chunked{false};
        bool connection_close{false};
        std::optional<string> content_encoding;   // verbatim, NOT decoded
        std::optional<string> transfer_encoding;  // verbatim
        std::optional<string> content_type;

        // 1xx codes received before the final response. The head itself describes
        // the FINAL response.
        std::vector<int> informational_status_codes;

        // Chunked trailers, delivered after the body. Empty when the response was
        // not chunked or carried no trailers.
        Headers trailers;
    };

    // ---------------------------------------------------------------------------
    // Response
    //
    // Buffered mode only for now: a request that used a BodySink reports
    // body_is_buffered() == false and empty body containers, rather than silently
    // accumulating a second copy of data the caller already consumed.
    // ---------------------------------------------------------------------------
    class Response {
    public:
        Response();
        Response(ResponseHead head, std::vector<uint8_t> body);
        Response(const Response&);
        Response& operator=(const Response&);
        Response(Response&&) noexcept;
        Response& operator=(Response&&) noexcept;
        ~Response();

        const ResponseHead& head() const noexcept;

        // --- Buffered body ---
        const std::vector<uint8_t>& body_bytes() const noexcept;
        string_view body_text() const noexcept;
        bool body_is_buffered() const noexcept;

        // --- Streaming body (S3.2-02) ---
        // Called for each chunk of response body as it arrives.
        // Return true to continue, false to pause (backpressure).
        // The callback runs on the I/O thread; copy data if you need it later.
        using BodySink = std::function<bool(string_view chunk)>;
        // Called once when the body is complete (eof) or on error.
        using BodySinkComplete = std::function<void(VoidResult)>;

        // --- Encoding bookkeeping ---
        // body_bytes() is already Content-Decoded. These record the wire facts so a
        // caller cannot mistake a compressed length for an uncompressed one.
        bool body_decoded() const noexcept;
        std::optional<uint64_t> wire_body_length() const noexcept;
        uint64_t decoded_body_length() const noexcept;

        // Records that the body arrived Content-Encoded and was decoded.
        void set_encoding_facts(bool decoded,
                                std::optional<uint64_t> wire_length) noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/response_impl.hpp>

#endif // MEGOHTTP_RESPONSE_HPP_INCLUDED
