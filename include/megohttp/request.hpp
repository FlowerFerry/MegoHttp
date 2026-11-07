#ifndef MEGOHTTP_REQUEST_HPP_INCLUDED
#define MEGOHTTP_REQUEST_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/http.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/url.hpp>

#include <cstdint>
#include <functional>
#include <memory>
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
        using BodySink = std::function<bool(string_view chunk)>;
        using BodySinkComplete = std::function<void(VoidResult)>;
        void set_body_sink(BodySink sink, BodySinkComplete complete);
        const std::optional<BodySink>& body_sink() const noexcept;
        const std::optional<BodySinkComplete>& body_sink_complete() const noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/request_impl.hpp>

#endif // MEGOHTTP_REQUEST_HPP_INCLUDED
