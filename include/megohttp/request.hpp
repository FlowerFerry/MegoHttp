#ifndef MEGOHTTP_REQUEST_HPP_INCLUDED
#define MEGOHTTP_REQUEST_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/http.hpp>
#include <megohttp/multipart_sink.hpp>
#include <megohttp/sse.hpp>
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

        // Only a byte body is replayable. A BodySource is replayable iff it
        // reports is_resettable(); a streamed body is never assumed replayable,
        // which is what keeps redirect/retry from silently re-sending it.
        bool is_body_replayable() const noexcept;

        // Body bytes when the body is a byte buffer; empty otherwise.
        const std::vector<uint8_t>& body_bytes() const noexcept;

        // Body source for streaming upload; nullopt if using buffer mode.
        const std::optional<BodySource>& body_source() const noexcept;

        // Body sink for streaming download; nullopt if using buffer mode (default).
        // When set, body_bytes() will be empty and body_is_buffered() false.
        //
        // Returning false asks the client to PAUSE delivery. Pausing stops the
        // reads, so a slow consumer actually stops the socket instead of the
        // library buffering everything it cannot deliver. Delivery resumes when
        // the caller signals the attached BodySinkFlow; without one attached the
        // return value cannot be acted on and delivery continues (the historical
        // behaviour, kept so existing callers are not broken silently).
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

        void set_body_sink(BodySink sink, BodySinkComplete complete);
        // Same, with backpressure control.
        void set_body_sink(BodySink sink, BodySinkComplete complete,
                           std::shared_ptr<BodySinkFlow> flow);
        const std::optional<BodySink>& body_sink() const noexcept;
        const std::optional<BodySinkComplete>& body_sink_complete() const noexcept;
        const std::shared_ptr<BodySinkFlow>& body_sink_flow() const noexcept;

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

        // --- SSE (S6.1-01) ---
        // Attach a callback for streaming SSE events. Response body is parsed
        // as text/event-stream instead of delivered raw; Content-Encoding is
        // still decoded first (HTTP framing -> decoding -> SSE).
        // Mutually exclusive with BodySink and MultipartSink.
        using SseCallback = std::function<VoidResult(const SseEvent&)>;
        void set_sse_callback(SseCallback cb, SseParser::Limits limits = {});
        const std::optional<SseCallback>& sse_callback() const noexcept;
        const SseParser::Limits& sse_limits() const noexcept;

        // --- Content coding ---
        // Request body compression. OFF by default: compressing an upload
        // spends CPU the caller never asked for, and a server that does not
        // understand the coding answers 415.
        enum class Compression {
            None,       // no Content-Encoding (default)
            Gzip,       // Content-Encoding: gzip
            Deflate,    // Content-Encoding: deflate (zlib wrapper)
            Brotli,     // Content-Encoding: br
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
