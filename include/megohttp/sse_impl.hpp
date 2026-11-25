#ifndef MEGOHTTP_SSE_IMPL_HPP_INCLUDED
#define MEGOHTTP_SSE_IMPL_HPP_INCLUDED

#include <megohttp/sse.hpp>
#include <megohttp/string_adapter.hpp>

#include <charconv>

namespace megohttp {

    using detail::ascii_iequals;
    using detail::sb_append;

    class SseParser::Impl {
    public:
        explicit Impl(Callbacks& cbs, Limits limits)
            : limits_(limits), cbs_(cbs) {}

        // --- line assembly ---
        // The line is RAW BYTES, not text: a field value may legitimately carry
        // a NUL (an "id:" with NUL is ignored per WHATWG, which is only
        // implementable if the byte survives). MemeString's builder drops
        // embedded NULs, so line assembly stays on byte_buffer and only the
        // final field value is converted to a string.
        byte_buffer line_;
        size_t line_len_{0};
        // A CR may be the first half of a CRLF pair, so the line ending is only
        // committed once the next byte is known not to be LF.
        bool pending_cr_{false};
        // A BOM is valid only at byte 0 of the stream.
        bool first_feed_{true};

        // --- event assembly ---
        // Accumulated event data. memepp::string is immutable, so appends go
        // through a fresh builder seeded with the existing content.
        string data_;
        size_t data_len_{0};
        bool data_started_{false};
        std::optional<string> event_type_;
        std::optional<string> event_id_;
        std::optional<int> event_retry_;
        // Last id seen; survives a dispatch, because WHATWG says an event with
        // no id field leaves the previous id in force for the next reconnect.
        string last_event_id_;
        bool has_event_field_{false};

        // --- bookkeeping ---
        Limits limits_;
        Callbacks& cbs_;
        bool failed_{false};
        // Set when a line-boundary pause was requested. Input arriving while
        // paused is retained here, not discarded, because the owner of the
        // current buffer is about to invalidate it.
        bool paused_{false};
        byte_buffer paused_bytes_;

        VoidResult fail(ErrorCode code, const char* msg) {
            failed_ = true;
            return Error{code, ErrorPhase::Receive, string(msg)};
        }

        void reset_event_state() {
            data_ = string{};
            data_len_ = 0;
            data_started_ = false;
            event_type_.reset();
            event_id_.reset();
            event_retry_.reset();
            has_event_field_ = false;
        }

        VoidResult dispatch_event() {
            // A blank line with nothing buffered dispatches nothing.
            if (!has_event_field_ && !data_started_) {
                reset_event_state();
                return VoidResult{};
            }

            SseEvent evt;
            // data_ is an owning string, not a builder: just move it into the event.
            evt.data = std::move(data_);
            data_len_ = 0;
            evt.event_type = event_type_ ? *event_type_ : string("message");
            evt.id = event_id_;
            evt.retry_ms = event_retry_;
            if (event_id_) last_event_id_ = *event_id_;
            evt.last_event_id_at_dispatch = last_event_id_;

            event_type_.reset();
            event_id_.reset();
            event_retry_.reset();
            has_event_field_ = false;
            data_started_ = false;
            return cbs_.on_event(evt);
        }

        VoidResult process_line(const string_view& raw_line) {
            if (!raw_line.empty() && raw_line.front() == ':') {
                const string_view rest =
                    raw_line.size() > 1 ? raw_line.substr(1) : string_view{};
                cbs_.on_comment(rest);
                return VoidResult{};
            }

            const size_t colon = raw_line.find(':');
            string_view field, value;
            if (colon == string_view::npos) {
                field = raw_line;
                value = string_view{};
            } else {
                field = raw_line.substr(0, colon);
                // Exactly ONE optional space after the colon is stripped;
                // any further spaces belong to the value (WHATWG).
                value = (colon + 1 < raw_line.size() && raw_line[colon + 1] == ' ')
                            ? raw_line.substr(colon + 2)
                            : raw_line.substr(colon + 1);
            }

            if (field.empty()) return dispatch_event();

            has_event_field_ = true;

            // The budget is checked before the field is accepted, so an
            // oversized event is rejected rather than silently truncated.
            if (limits_.max_event_bytes > 0) {
                size_t current = data_len_ + value.size();
                if (event_id_) current += event_id_->size();
                if (event_type_) current += event_type_->size();
                if (current > limits_.max_event_bytes) {
                    return fail(ErrorCode::SseEventTooLarge,
                                "SSE event exceeded max_event_bytes");
                }
            }

            if (ascii_iequals(field, "data")) {
                // Every data line after the first contributes a newline
                // separator, including an empty one: data:a / data: / data:b
                // is "a\n\nb".
                string_builder b;
                sb_append(b, data_);
                if (data_started_) {
                    sb_append(b, '\n');
                    ++data_len_;
                }
                sb_append(b, value);
                data_len_ += value.size();
                data_ = b.release();
                data_started_ = true;
                return VoidResult{};
            }
            if (ascii_iequals(field, "event")) {
                event_type_ = to_string(value);
                return VoidResult{};
            }
            if (ascii_iequals(field, "id")) {
                // WHATWG: an id field containing NUL is ignored entirely.
                // Scanned byte by byte: a NUL-aware search on a borrowed view
                // is not something to depend on across both string modes.
                bool has_nul = false;
                for (size_t i = 0; i < value.size(); ++i) {
                    if (value[i] == '\0') { has_nul = true; break; }
                }
                if (has_nul) return VoidResult{};
                event_id_ = to_string(value);
                return VoidResult{};
            }
            if (ascii_iequals(field, "retry")) {
                int64_t ms = 0;
                bool ok = !value.empty();
                if (ok) {
                    const char* b = value.data();
                    const char* e = b + value.size();
                    auto fr = std::from_chars(b, e, ms);
                    ok = (fr.ec == std::errc{} && fr.ptr == e && ms >= 0 &&
                          ms <= 86400000);
                }
                if (ok) event_retry_ = static_cast<int>(ms);
                return VoidResult{};
            }
            // Unknown field: ignored, per WHATWG.
            return VoidResult{};
        }

        VoidResult finish_line() {
            // Move the byte-buffer into a string so that the NUL byte, if any,
            // survives.
            string line = to_string(reinterpret_cast<const char*>(line_.data()),
                                    line_.size());
            line_.clear();
            line_len_ = 0;
            return process_line(to_view(line));
        }

        VoidResult feed(const uint8_t* data, size_t size) {
            if (failed_) {
                return Error{ErrorCode::SseEventTooLarge, ErrorPhase::Receive,
                             string("SSE parser already failed")};
            }
            if (paused_) {
                return append_paused(data, size);
            }
            return feed_unpaused(data, size);
        }

        VoidResult append_paused(const uint8_t* data, size_t size) {
            if (size == 0) return VoidResult{};
            if (limits_.max_paused_buffer_bytes != 0 &&
                paused_bytes_.size() + size > limits_.max_paused_buffer_bytes) {
                return fail(ErrorCode::SseEventTooLarge,
                            "SSE paused buffer exceeded max_paused_buffer_bytes");
            }
            paused_bytes_.insert(paused_bytes_.end(), data, data + size);
            return VoidResult{};
        }

        VoidResult feed_unpaused(const uint8_t* data, size_t size) {
            // A UTF-8 BOM is ignored, but only at byte 0 of the stream.
            if (first_feed_) {
                first_feed_ = false;
                if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB &&
                    data[2] == 0xBF) {
                    data += 3;
                    size -= 3;
                }
            }

            for (size_t i = 0; i < size; ++i) {
                const char c = static_cast<char>(data[i]);

                // A CR already ended the previous line. If an LF follows, it is
                // the second half of that same line ending and is swallowed;
                // otherwise this byte simply starts the next line.
                if (pending_cr_) {
                    pending_cr_ = false;
                    if (c == '\n') continue;
                }

                if (c == '\r') {
                    auto r = finish_line();
                    if (!r) return r;
                    pending_cr_ = true;
                    if (cbs_.pause_requested()) {
                        paused_ = true;
                        if (i + 1 < size) {
                            auto a = append_paused(data + i + 1, size - i - 1);
                            if (!a) return a;
                        }
                        return VoidResult{};
                    }
                    continue;
                }
                if (c == '\n') {
                    auto r = finish_line();
                    if (!r) return r;
                    if (cbs_.pause_requested()) {
                        paused_ = true;
                        if (i + 1 < size) {
                            auto a = append_paused(data + i + 1, size - i - 1);
                            if (!a) return a;
                        }
                        return VoidResult{};
                    }
                    continue;
                }

                if (limits_.max_line_length > 0 &&
                    line_len_ >= limits_.max_line_length) {
                    return fail(ErrorCode::SseLineTooLong,
                                "SSE line exceeded max_line_length");
                }
                {
                    line_.push_back(static_cast<uint8_t>(c));
                }
                ++line_len_;
            }
            return VoidResult{};
        }

        VoidResult resume() {
            if (failed_) {
                return Error{ErrorCode::SseEventTooLarge, ErrorPhase::Receive,
                             string("SSE parser already failed")};
            }
            if (!paused_) return VoidResult{};
            paused_ = false;
            if (paused_bytes_.empty()) return VoidResult{};
            // Keep the buffer alive for the duration of the call; feed_unpaused
            // may pause again and append its own remainder to paused_bytes_.
            byte_buffer pending;
            pending.swap(paused_bytes_);
            return feed_unpaused(pending.data(), pending.size());
        }

        VoidResult feed_eof() {
            if (failed_) return VoidResult{};
            // The owner must resume() first: a paused parser still holds bytes
            // (and possibly a complete event) that EOF must not discard.
            if (paused_) return VoidResult{};
            // A trailing CR is a complete line ending on its own.
            if (pending_cr_) {
                pending_cr_ = false;
                auto r = finish_line();
                if (!r) return r;
            }
            // WHATWG: a stream that ends mid-event never dispatches it. Drop
            // the accumulated fields rather than emitting a partial event.
            reset_event_state();
            return VoidResult{};
        }
    };

    // -----------------------------------------------------------------------
    // SseParser public API
    // -----------------------------------------------------------------------

    inline SseParser::SseParser(Callbacks& cbs, Limits limits)
        : impl_(std::make_unique<Impl>(cbs, limits)) {}

    inline SseParser::~SseParser() = default;

    inline SseParser::SseParser(SseParser&&) noexcept = default;
    inline SseParser& SseParser::operator=(SseParser&&) noexcept = default;

    inline VoidResult SseParser::feed(const uint8_t* data, size_t size) {
        return impl_->feed(data, size);
    }

    inline VoidResult SseParser::feed_eof() {
        return impl_->feed_eof();
    }

    inline bool SseParser::is_paused() const noexcept {
        return impl_->paused_;
    }

    inline void SseParser::pause() noexcept {
        impl_->paused_ = true;
    }

    inline VoidResult SseParser::resume() {
        return impl_->resume();
    }

    inline const string& SseParser::last_event_id() const noexcept {
        return impl_->last_event_id_;
    }

    inline bool SseParser::is_failed() const noexcept {
        return impl_->failed_;
    }

} // namespace megohttp

#endif // MEGOHTTP_SSE_IMPL_HPP_INCLUDED
