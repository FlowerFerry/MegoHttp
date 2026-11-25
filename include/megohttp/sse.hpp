#ifndef MEGOHTTP_SSE_HPP_INCLUDED
#define MEGOHTTP_SSE_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Server-Sent Events parsing (task book 11, phase 6).
//
// This is the PARSER only. It consumes response-body bytes and emits events;
// it never opens a socket. That is deliberate: task book 11 requires SSE to be
// built on the shared HTTP streaming path, so the Client feeds this parser from
// the same BodySink plumbing multipart and plain streaming already use. A
// parser that owned a connection would be a second network client.
//
// Wire format (WHATWG HTML "server-sent events"):
//   - lines end with LF, CRLF or a lone CR
//   - a UTF-8 BOM at the very start is ignored
//   - ":" starts a comment line, ignored
//   - "field: value" -- one optional space after the colon is stripped
//   - fields: data, event, id, retry; anything else is ignored
//   - blank line dispatches the buffered event
//   - an "id:" containing NUL is ignored (WHATWG)
//   - EOF does not dispatch a trailing event that never saw its blank line
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace megohttp {

    // One dispatched event. All text is owning: an event outlives the parser's
    // buffer and callers are allowed to keep it.
    struct SseEvent {
        // Multi-line data joined with '\n', no trailing newline.
        string data;
        // "message" when the stream carried no event field.
        string event_type;
        // nullopt = this event carried no id field.
        std::optional<string> id;
        // Server-suggested reconnect delay, in milliseconds.
        std::optional<int> retry_ms;
        // What a reconnect after THIS event must send as Last-Event-ID.
        // Copied, not a view: the parser's notion of "last" can move on.
        string last_event_id_at_dispatch;
    };

    class SseParser {
    public:
        struct Limits {
            // A single line longer than this is a stream error, not a silent
            // truncation: an attacker must not be able to grow the line buffer
            // without bound.
            size_t max_line_length{64 * 1024};
            // Total bytes of one event's accumulated data + id + type.
            size_t max_event_bytes{1024 * 1024};
            // Bytes accepted while the parser is paused. The Client stops
            // reading once a pause is requested, but one already-decoded or
            // already-read chunk can still be handed over; this caps that
            // hand-over instead of buffering without bound. 0 = unlimited.
            size_t max_paused_buffer_bytes{4 * 1024 * 1024};
        };

        struct Callbacks {
            virtual ~Callbacks() = default;
            // Called once per dispatched event (blank line seen).
            virtual VoidResult on_event(const SseEvent& event) = 0;
            // Called for a comment line. Not an error to ignore.
            virtual void on_comment(string_view comment) {}
            // Checked after every complete line. Returning true stops parsing
            // at that line boundary; the remaining input is retained by the
            // parser until resume() is called. This is event/line granularity,
            // not mid-line granularity.
            virtual bool pause_requested() const { return false; }
        };

        SseParser(Callbacks& cbs, Limits limits = {});
        ~SseParser();

        SseParser(const SseParser&) = delete;
        SseParser& operator=(const SseParser&) = delete;
        SseParser(SseParser&&) noexcept;
        SseParser& operator=(SseParser&&) noexcept;

        // Feed body bytes. Safe to call with any split, including one byte at a
        // time: field names, values and line endings may all straddle a call.
        // If the parser is paused, bytes are retained (bounded by
        // Limits::max_paused_buffer_bytes) and consumed by resume().
        VoidResult feed(const uint8_t* data, size_t size);

        // Signal end of stream. A partially accumulated event is discarded:
        // WHATWG says a stream that ends mid-event never dispatches it.
        VoidResult feed_eof();

        // True when a callback asked for a pause and feed() stopped at a line
        // boundary. Callers must stop reading the response until resume().
        bool is_paused() const noexcept;

        // Start paused before any byte is fed. Used when a flow is already
        // paused when the response head arrives; subsequent feed() input is
        // retained until resume().
        void pause() noexcept;

        // Resume parsing bytes retained by the pause and clear the paused
        // state. Must run on the same thread that calls feed().
        VoidResult resume();

        // Id to send as Last-Event-ID on a reconnect, empty when none was seen.
        const string& last_event_id() const noexcept;

        // True once a line or event exceeded its budget. A failed parser must be
        // discarded along with the connection.
        bool is_failed() const noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace megohttp

#include <megohttp/sse_impl.hpp>

#endif // MEGOHTTP_SSE_HPP_INCLUDED
