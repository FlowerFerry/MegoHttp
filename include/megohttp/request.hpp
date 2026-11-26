#ifndef MEGOHTTP_REQUEST_HPP_INCLUDED
#define MEGOHTTP_REQUEST_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/http.hpp>
#include <megohttp/multipart_sink.hpp>
#include <megohttp/response.hpp>
#if MEGOHTTP_HAS_SSE
#include <megohttp/sse.hpp>
#endif
#include <megohttp/string_adapter.hpp>
#include <megohttp/url.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace megohttp {

    class BodySource;

    // ---------------------------------------------------------------------------
    // Request
    //
    // Everything here is owning: a Request outlives the call that created it and
    // is read on the I/O thread, so no string_view may survive submission.
    // ---------------------------------------------------------------------------
    class Request {
    public:
        Request();
        Request(Method method, string_view url);
        Request(const Request&);
        Request& operator=(const Request&);
        Request(Request&&) noexcept;
        Request& operator=(Request&&) noexcept;
        ~Request();

        // --- Method ---
        Method method() const noexcept;
        void set_method(Method method);
        // Only meaningful when method() == Method::Custom.
        string_view custom_method() const noexcept;
        void set_custom_method(string_view name);

        // --- URL ---
        // The URL is stored as given; it is parsed on submission so a malformed
        // URL is reported as an error rather than thrown at construction.
        string_view url() const noexcept;
        void set_url(string_view url);
        // Parsed form, available after a successful parse or after set_parsed_url.
        const std::optional<Url>& parsed_url() const noexcept;
        VoidResult set_parsed_url(Url url);

        // --- Headers ---
        Headers& headers() noexcept;
        const Headers& headers() const noexcept;

        // --- Body ---
        // Copy the bytes. Replayable.
        void set_body(string_view data);
        // Take the bytes. Replayable.
        void set_body(std::vector<uint8_t> data);

        // Body source: stream the request body piece by piece.
        // Called repeatedly until it returns eof or an error.
        // Returning an empty view means "not ready now, ask again later" (backpressure).
        using BodySource = std::function<Result<std::pair<string_view, bool>>()>;
        void set_body_source(BodySource src);

        bool has_body() const noexcept;
        void clear_body();

        // Only a byte body is replayable. There is no resettable-stream
        // interface, so a streamed body is never replayable -- that is what
        // keeps redirect/retry from silently re-sending it.
        bool is_body_replayable() const noexcept;

        // Body bytes when the body is a byte buffer; empty otherwise.
        const std::vector<uint8_t>& body_bytes() const noexcept;

        // Body source for streaming upload; nullopt if using buffer mode.
        const std::optional<BodySource>& body_source() const noexcept;

        // --- Request trailers (S3.1-11; task book 7 "trailer 的读取及受控发送") ---
        // Sent in the terminating chunk of a CHUNKED request body. A buffered
        // body is Content-Length framed, where trailers cannot be sent, so
        // setting a trailer without a BodySource is rejected at submission.
        // OFF by default.
        //
        // Static trailers are known at submission. A TrailerSource runs at EOF
        // on the I/O thread for values computed over the body (checksums,
        // signatures); both may be set and the source's fields are appended
        // after the static ones.
        //
        // Every emitted name must be declared, either by a static trailer or by
        // the caller's `Trailer` header. The library merges those into the
        // declaration it sends and rejects an undeclared dynamic name at EOF.
        // Fields RFC 7230 forbids in a trailer (Content-Length,
        // Transfer-Encoding, Host, Trailer, ...) are rejected. Declared names
        // and emitted fields are bounded by
        // ClientOptions::max_request_trailer_count / _bytes.
        using TrailerSource = std::function<Result<Headers>()>;
        void set_trailers(Headers trailers);
        const Headers& trailers() const noexcept;
        void set_trailer_source(TrailerSource src);
        const std::optional<TrailerSource>& trailer_source() const noexcept;

        // Body sink for streaming download; nullopt if using buffer mode (default).
        // When set, body_bytes() will be empty and body_is_buffered() false.
        //
        // Returning false means PAUSE delivery. A BodySink requires an attached
        // BodySinkFlow; without one a submit is rejected synchronously with
        // InvalidArgument, because there would be no way to resume. Delivery
        // resumes when the caller signals the attached flow.
        using BodySink = std::function<bool(string_view chunk)>;
        using BodySinkComplete = std::function<void(VoidResult)>;

        // Cross-thread pause/resume for a streaming download. Copyable; every
        // copy refers to the same state.
        class BodySinkFlow {
        public:
            BodySinkFlow();
            // Ask delivery to pause. Idempotent.
            void pause();
            // Resume after a pause. Safe to call from any thread.
            void resume();
            bool is_paused() const noexcept;

            // Installed by the Client when the exchange starts. Not part of the
            // caller-facing contract; `wake` is invoked on resume().
            void set_wake(std::function<void()> wake);

        private:
            std::shared_ptr<struct BodySinkFlowState> state_;
        };

        // Kept for source compatibility, but a request using this overload is
        // rejected at submit with InvalidArgument: false cannot pause without a
        // resume channel.
        void set_body_sink(BodySink sink, BodySinkComplete complete);
        // Streaming download with proper pause/resume. Use this overload.
        void set_body_sink(BodySink sink, BodySinkComplete complete,
                           std::shared_ptr<BodySinkFlow> flow);
        const std::optional<BodySink>& body_sink() const noexcept;
        const std::optional<BodySinkComplete>& body_sink_complete() const noexcept;
        const std::shared_ptr<BodySinkFlow>& body_sink_flow() const noexcept;

        // --- Response head callback (S1.7-05; task book 6.4 / 7.1) ---
        // Invoked on the I/O execution context as soon as the FINAL response
        // head is complete, before any body byte reaches a BodySink,
        // MultipartSink or SSE parser, and before the terminal callback. This
        // is what lets a streaming caller inspect status / Content-Type /
        // Content-Length and decide whether the body is worth consuming.
        //
        // Contract:
        //   - once per attempt that produces a final head; zero times when the
        //     request fails before one (DNS, connect, TLS, proxy, cancel);
        //   - not called for informational 1xx responses (their codes are in
        //     ResponseHead::informational_status_codes). 101 is a final
        //     protocol-switch head and DOES call it;
        //   - not called for a 3xx that this Client follows; a 3xx that is NOT
        //     followed is a final response and DOES call it;
        //   - with retries enabled it can fire once per attempt (e.g. 503 then
        //     200); the terminal callback still fires exactly once;
        //   - ResponseHead::trailers is empty here: trailers arrive after the
        //     body. Copy the head if you need to keep it; the reference is valid
        //     only for the duration of the call;
        //   - a callback that throws terminates the request with
        //     ErrorCode::Unknown (ErrorPhase::Receive), the same policy as a
        //     throwing BodySink.
        using HeadCallback = std::function<void(const ResponseHead&)>;
        void set_head_callback(HeadCallback cb);
        const std::optional<HeadCallback>& head_callback() const noexcept;

        // Pause/resume handle for a streaming multipart download. Same state
        // machine as BodySinkFlow -- an alias rather than a second class, because
        // a copy of the mechanics would only be a place for the two to drift.
        using MultipartSinkFlow = BodySinkFlow;

        // --- multipart response (S5.7-01) ---
        // Attach a streaming multipart parser for the response body. The body is
        // then parsed instead of delivered raw: Content-Encoding is still decoded
        // first (HTTP framing -> decoding -> multipart), so a gzipped multipart
        // response works unchanged.
        //
        // Mutually exclusive with BodySink: a request delivers body bytes to
        // exactly one consumer, and setting one clears the other. Silently
        // delivering the same bytes twice would duplicate part data.
        //
        // Pass a flow to get real backpressure: `on_part_data` returning false
        // then stops the socket read until the flow is resumed. Without one the
        // return value cannot be acted on (nothing could ever resume it) and the
        // parser's internal buffer keeps absorbing data up to its byte caps.
        void set_multipart_sink(std::shared_ptr<MultipartSink> sink,
                                MultipartResponseOptions options = {},
                                std::shared_ptr<MultipartSinkFlow> flow = nullptr);
        const std::shared_ptr<MultipartSink>& multipart_sink() const noexcept;
        const MultipartResponseOptions& multipart_options() const noexcept;
        const std::shared_ptr<MultipartSinkFlow>& multipart_flow() const noexcept;

#if MEGOHTTP_HAS_SSE
        // --- SSE (S6.1-01) ---
        // Attach a callback for streaming SSE events. Response body is parsed
        // as text/event-stream instead of delivered raw; Content-Encoding is
        // still decoded first (HTTP framing -> decoding -> SSE).
        // Mutually exclusive with BodySink and MultipartSink.
        //
        // Optional flow: pause_receive-equivalent backpressure. When attached,
        // calling flow->pause() (from the callback or any thread) stops the
        // parser after the current line and stops socket reads; flow->resume()
        // replays the retained bytes. Without a flow the parser still bounds
        // its buffers but the caller has no way to ask for a pause.
        using SseCallback = std::function<VoidResult(const SseEvent&)>;
        using SseFlow = BodySinkFlow;
        void set_sse_callback(SseCallback cb, SseParser::Limits limits = {},
                              std::shared_ptr<SseFlow> flow = nullptr);
        const std::optional<SseCallback>& sse_callback() const noexcept;
        const SseParser::Limits& sse_limits() const noexcept;
        const std::shared_ptr<SseFlow>& sse_flow() const noexcept;
#endif

        // --- Content coding ---
        // Request body compression. OFF by default: compressing an upload
        // spends CPU the caller never asked for, and a server that does not
        // understand the coding answers 415.
        //
        // Current implementation (task book 7.3):
        //   - a buffered body (set_body) is encoded once at submission; the
        //     request carries Content-Encoding and Content-Length describes the
        //     ENCODED bytes. Redirects/retries reuse the same encoded buffer.
        //   - a BodySource is rejected with NotImplemented: streaming
        //     compression is not implemented, and sending plaintext under a
        //     Content-Encoding header would be worse than failing.
        //   - no body, or an explicitly empty buffered body, is left untouched
        //     (there is nothing to encode; a zero-length body keeps its normal
        //     framing).
        //   - a caller-supplied Content-Encoding / Content-Length /
        //     Transfer-Encoding combined with compression is rejected with
        //     InvalidArgument, because the head would contradict the body.
        //   - a coding this build cannot produce (gzip disabled, brotli encoder
        //     missing) is rejected with ContentEncodingUnsupported.
        // Encoding runs on the submitting thread, before the request is
        // accepted; a failure is therefore a synchronous rejection (the same
        // documented exception as invalid options).
        enum class Compression {
            None,       // no Content-Encoding (default)
            Gzip,       // Content-Encoding: gzip (RFC 1952)
            Deflate,    // Content-Encoding: deflate (RFC 1950 zlib wrapper)
            Brotli,     // Content-Encoding: br (RFC 7932)
        };
        void set_compress_body(Compression coding);
        Compression compress_body() const noexcept;

        // Response decoding. ON by default: a server that sends gzip because it
        // saw our Accept-Encoding owes us the decoded bytes.
        //
        // Setting this false delivers the raw compressed bytes (the caller
        // handles the coding itself). The Content-Encoding header is preserved
        // either way, and Response::body_decoded() says which happened.
        void set_decode_response_body(bool decode);
        bool decode_response_body() const noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/request_impl.hpp>

#endif // MEGOHTTP_REQUEST_HPP_INCLUDED
