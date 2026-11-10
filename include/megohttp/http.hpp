#ifndef MEGOHTTP_HTTP_HPP_INCLUDED
#define MEGOHTTP_HTTP_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <vector>
#include <memory>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/url.hpp>

#include <cstdint>
#include <optional>

namespace megohttp {

    enum class Method {
        Get, Head, Post, Put, Delete, Patch, Options, Trace, Connect,
        Custom,   // name held in Request::custom_method
    };

    const char* to_string(Method m) noexcept;
    Method method_from_string(string_view name) noexcept;

    // Encode a request head (status line + headers + CRLF). The body is NOT included.
    // Rejects header names/values that would allow request splitting.
    Result<string> encode_request_head(Method method,
                                       string_view custom_method,
                                       string_view request_target,
                                       const Headers& headers);

    // Response head: status line + headers.
    Result<string> encode_response_head(int status_code,
                                        string_view reason,
                                        const Headers& headers);

    // ---------------------------------------------------------------------------
    // Parser limits. Every one is configurable because the spec requires bounded
    // resources; the defaults are deliberately conservative but not tiny.
    // ---------------------------------------------------------------------------
    struct ParserLimits {
        size_t max_start_line_length{8 * 1024};
        size_t max_header_field_size{16 * 1024};   // one name+value line
        size_t max_header_count{200};
        size_t max_header_bytes{64 * 1024};        // whole head
        size_t max_chunk_line_length{1 * 1024};
        size_t max_trailer_bytes{16 * 1024};
        size_t max_trailer_count{64};
        uint64_t max_body_bytes{64ULL * 1024 * 1024};   // 0 = unlimited
    };

    // Parsed response head plus the framing decision the body reader must follow.
    struct ParsedResponse {
        int status_code{0};
        string reason;                 // owning
        Headers headers;               // owning
        int http_major{1};
        int http_minor{1};

        // Framing, resolved from the headers. Exactly one of these is the answer:
        enum class BodyFraming {
            None,          // no body at all (HEAD, 204, 304, 1xx)
            ContentLength,
            Chunked,       // Transfer-Encoding: chunked
            UntilClose,    // no CL, no chunked: body ends when the connection closes
        };
        BodyFraming framing{BodyFraming::UntilClose};
        uint64_t content_length{0};    // valid when framing == ContentLength

        bool connection_close{false};  // Connection: close present, or HTTP/1.0 without keep-alive
        bool has_trailers{false};      // "Trailer" header present
        bool keep_alive{false};

        // Informational 1xx status codes seen before the final response.
        std::vector<int> informational;

        // Wire size of the head, for accounting.
        size_t head_bytes{0};
    };

    // Streaming HTTP/1.1 response parser.
    //
    // Feed it arbitrary byte chunks in any split; it reports progress through a
    // small callback interface, mirroring the feed/poll shape that both network
    // backends can drive without copying buffers.
    //
    // Correctness contracts enforced here:
    //   • A conflicting Content-Length, or a Transfer-Encoding that is not exactly
    //     "chunked" (or ends with it in a legal multi-TE form), is rejected rather
    //     than guessed at.
    //   • Content-Length is parsed overflow-checked.
    //   • Chunk sizes are hex, overflow-checked; a chunk-extension is ignored but
    //     must be syntactically legal enough not to swallow the CRLF.
    //   • Trailers are parsed but bounded, and never merged into the head headers.
    //   • 1xx responses are consumed as informational, not delivered as final.
    //   • HEAD / 204 / 304 produce no body regardless of a Content-Length header.
    class ResponseParser {
    public:
        struct Callbacks {
            virtual ~Callbacks() = default;

            // Called once when the final head is complete and framing is resolved.
            // Returning an error aborts parsing.
            virtual VoidResult on_head(const ParsedResponse& head) = 0;

            // Called for each informational (1xx) response received before the
            // final one, in arrival order. Default: ignore. A client that sent
            // Expect: 100-continue uses this to learn it may send the body.
            virtual VoidResult on_informational(int status_code) {
                (void)status_code;
                return VoidResult{};
            }

            // Body bytes, already de-chunked when applicable. The pointer is valid
            // only for the duration of the call.
            virtual VoidResult on_body_data(const uint8_t* data, size_t size) = 0;

            // Trailers, delivered once after the last body byte (chunked only).
            virtual VoidResult on_trailers(const Headers& trailers) = 0;

            // Exactly once, when the message is complete by framing rules.
            virtual VoidResult on_complete() = 0;
        };

        // Callbacks are required: the parser owns no storage for the body, so it
        // must hand every byte to the sink as it arrives. The caller keeps the
        // callbacks alive for the lifetime of the parser.
        ResponseParser(Callbacks& callbacks, ParserLimits limits = {});
        ~ResponseParser();

        ResponseParser(const ResponseParser&) = delete;
        ResponseParser& operator=(const ResponseParser&) = delete;
        ResponseParser(ResponseParser&&) noexcept;
        ResponseParser& operator=(ResponseParser&&) noexcept;

        // Examine the request method before feeding, so HEAD framing is correct.
        void set_request_method(Method m) noexcept;

        // Signal transport EOF. Required for "connection close" framing; returns
        // HttpProtocolViolation if the message was incomplete under any other
        // framing.
        VoidResult feed_eof();

        // Feed bytes. Returns an error on protocol violation; the parser must then
        // be discarded (a polluted connection must never be reused).
        VoidResult feed(const uint8_t* data, size_t size);

        // True once the whole message has been consumed.
        bool is_complete() const noexcept;

        // Bytes of the current feed() buffer that belong to the NEXT message
        // (pipelining is not supported, but a server may send the next response
        //  early; the caller must not lose them).
        size_t leftover_offset() const noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    // ---------------------------------------------------------------------------
    // chunked encoding, used for both request bodies and response bodies
    // ---------------------------------------------------------------------------
    namespace chunked {

        // "1a\r\n<26 bytes>\r\n"
        string encode_chunk(const uint8_t* data, size_t size);

        // Terminating chunk: "0\r\n" + optional trailers + "\r\n"
        //
        // Returns an error when a trailer name or value could not be written as
        // a header line. Trailer values are attacker-influenced in the same way
        // header values are, so an unchecked CR/LF there splits the chunked body
        // exactly like it splits a head.
        Result<string> encode_last_chunk(const Headers* trailers = nullptr);

        // Parsed chunk size line: hex digits with optional ;ext
        Result<uint64_t> parse_chunk_size(string_view line);

    } // namespace chunked

    // ---------------------------------------------------------------------------
    // Header value helpers used across the HTTP layer
    // ---------------------------------------------------------------------------
    namespace http_detail {

        // Token-list membership, comma separated, whitespace tolerated,
        // case-insensitive, e.g. "keep-alive, Upgrade" contains "upgrade".
        bool header_has_token(string_view value, string_view token) noexcept;

        // Splits a comma-separated list into trimmed elements (borrowed views into
        // `value`; copy before storing).
        std::vector<string_view> split_list(string_view value);

        // Trim OWS (SP / HTAB) from both ends.
        string_view trim_ows(string_view v) noexcept;

        // Reason phrase for a status code; empty for unknown codes (we never invent).
        string_view status_reason(int status_code) noexcept;

    } // namespace http_detail

} // namespace megohttp

#include <megohttp/http_impl.hpp>

#endif // MEGOHTTP_HTTP_HPP_INCLUDED
