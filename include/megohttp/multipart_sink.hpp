#ifndef MEGOHTTP_MULTIPART_SINK_HPP_INCLUDED
#define MEGOHTTP_MULTIPART_SINK_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/multipart_response.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <memory>

namespace megohttp {

    // ---------------------------------------------------------------------------
    // Client-level multipart response delivery (S5.7-01 / spec 7.2A).
    //
    // The byte-level state machine lives in MultipartResponseParser. This
    // header only describes what a CALLER receives: a part head, part data,
    // a part end, and exactly one terminal event for the whole message.
    //
    // Why a separate sink rather than reusing BodySink: the HTTP message and
    // the multipart message have INDEPENDENT completion conditions. A closing
    // boundary does not complete the HTTP message (an epilogue may follow), and
    // a completed HTTP framing does not prove the multipart message ended. The
    // Client checks both before it reports success or reuses the connection.
    // ---------------------------------------------------------------------------

    struct MultipartPartHead {
        // Owning copies, duplicates and order preserved. Views from get() are
        // borrowed from this object and die with it.
        Headers headers;

        // 0-based, in wire order. Deliberately NOT related to the order of any
        // Range the caller requested: a server may answer in any order.
        size_t index{0};
    };

    class MultipartSink {
    public:
        virtual ~MultipartSink() = default;

        // Called once per part, before any of its data.
        virtual void on_part_begin(const MultipartPartHead& head) = 0;

        // Part payload. The view is valid ONLY for the duration of the call.
        //
        // Returning false asks for a pause. With a `MultipartSinkFlow` attached to
        // the request the read loop stops here and only restarts when the caller
        // resumes it from another thread. Without a flow the return value is
        // ignored — pausing without a way back would hang the transfer forever,
        // so the historical "keep going" behaviour is the only non-hanging option.
        virtual bool on_part_data(const uint8_t* data, size_t size) = 0;

        // Called when a part finishes. Says nothing about the request: the HTTP
        // message may still be truncated afterwards.
        virtual void on_part_end() = 0;

        // Called exactly once, when BOTH the HTTP message and the multipart
        // message are complete.
        virtual void on_complete() = 0;

        // Called exactly once on failure (protocol error, truncation, resource
        // limit, cancellation, timeout). Mutually exclusive with on_complete,
        // and no further callback of any kind follows it.
        virtual void on_error(const Error& error) = 0;
    };

    // ---------------------------------------------------------------------------
    // MultipartResponseOptions
    //
    // Limits are reused verbatim from the parser rather than duplicated here:
    // two copies of the same ten defaults would drift apart.
    // ---------------------------------------------------------------------------
    struct MultipartResponseOptions {
        // Empty means "take the boundary from the response Content-Type".
        // A non-empty value overrides it (the caller parses the header itself,
        // e.g. from a stream of responses that share one boundary).
        string boundary;

        // Only for endless multipart/x-mixed-replace streams: EOF without a
        // closing boundary ends the message normally instead of reporting
        // MultipartTruncated. It MUST stay off for finite bodies.
        bool allow_continuous_stream{false};

        // Also accept multipart subtypes outside
        // mixed / related / byteranges / x-mixed-replace.
        bool basic_parse_unvalidated{false};

        MultipartResponseParser::Limits limits{};
    };

} // namespace megohttp

#endif // MEGOHTTP_MULTIPART_SINK_HPP_INCLUDED
