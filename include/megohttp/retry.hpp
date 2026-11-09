#ifndef MEGOHTTP_RETRY_HPP_INCLUDED
#define MEGOHTTP_RETRY_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Automatic retry policy (task book 8.4, phase 5 item S5.3-*).
//
// The whole design is "safety first". A retry re-sends a request, so it can
// duplicate a side effect the server already performed. The rules below exist
// because every one of them has a known failure mode when skipped:
//
//   • Only idempotent/safe methods by default. Re-sending a POST after the
//     connection died is how you create two orders.
//   • Two ways for a request to fail "retryably", and they are separate:
//       - the transport died before any response byte arrived;
//       - the server answered with a status that MEANS "try again"
//         (429, 502, 503, 504).
//     Everything else is final. Protocol violations, TLS failures and other
//     4xx/5xx are answers, and the answer is the answer.
//   • Never retry after any part of the response body was handed to the caller.
//   • A body that cannot be replayed cannot be retried, no matter the method.
//   • The backoff wait is cancellable and shares the request's total deadline,
//     so retrying cannot extend the logical request past its own timeout.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/http.hpp>
#include <megohttp/string_adapter.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>

namespace megohttp {

    // ---------------------------------------------------------------------
    // RetryPolicy
    // ---------------------------------------------------------------------
    struct RetryPolicy {
        // 0 disables retrying entirely, which is the default: a caller who never
        // asked for retries must not have requests silently re-sent.
        size_t max_retries{0};

        Duration base_delay{std::chrono::milliseconds(200)};
        Duration max_delay{std::chrono::seconds(30)};
        // Exponential growth factor. 1.0 means "constant delay".
        double multiplier{2.0};
        // Random spread applied to each delay, in [0.5, 1.5) of the value. The
        // point is to keep a fleet of clients from retrying in lockstep after a
        // shared failure.
        bool jitter{true};

        // Allow retrying methods that are not idempotent. Off by default and
        // documented as dangerous: the caller is asserting that repeating the
        // request is acceptable for its semantics.
        bool retry_non_idempotent{false};

        // Retry when the server answers with a status that means "try again"
        // (429, 502, 503, 504). On by default: honouring the server's own
        // backpressure signal is the point of those statuses. Still subject to
        // every other rule (method, replayable body, nothing delivered).
        bool retry_on_status{true};
    };

    // ---------------------------------------------------------------------
    // RetryContext
    //
    // The facts the decision needs. Passed explicitly rather than read from
    // internal state, which keeps the decision a pure function and therefore
    // testable without a socket.
    // ---------------------------------------------------------------------
    struct RetryContext {
        Method method{Method::Get};
        bool body_replayable{true};

        // Status code of a COMPLETE response head, or 0 when no head arrived.
        // This is what distinguishes "the server said 503" from "the socket
        // died", and the two follow different rules.
        int status{0};

        // True once ANY byte of a response arrived. With status == 0 this means
        // the head was truncated: the server started answering, so a retry could
        // hit a request it already saw.
        bool response_started{false};

        // True once ANY body byte was handed to the CALLER. Buffering the body
        // of a 503 internally does not count: the caller has not seen it.
        bool body_delivered{false};

        // A server-supplied delay from Retry-After, already resolved to a
        // duration. Only meaningful with a status.
        std::optional<Duration> retry_after;
    };

    namespace retry_detail {

        // Idempotent by HTTP semantics (RFC 7231 4.2.2) plus OPTIONS/TRACE.
        // POST is deliberately absent; PATCH is absent because it is not
        // idempotent by definition.
        inline bool is_idempotent(Method m) noexcept {
            switch (m) {
            case Method::Get:
            case Method::Head:
            case Method::Put:
            case Method::Delete:
            case Method::Options:
            case Method::Trace:
                return true;
            case Method::Post:
            case Method::Patch:
            case Method::Connect:
            case Method::Custom:
                return false;
            }
            return false;
        }

        // Errors that prove the request never reached the server, or that the
        // connection died in a way a fresh attempt can recover from.
        //
        // Everything NOT listed is treated as final. That asymmetry is on
        // purpose: an unknown error is more likely to be a real answer than a
        // transient one, and guessing "transient" risks duplicating work.
        inline bool is_transient_failure(ErrorCode c) noexcept {
            switch (c) {
            case ErrorCode::ConnectFailed:
            case ErrorCode::ConnectTimeout:
            case ErrorCode::ConnectionReset:
            case ErrorCode::ConnectionClosed:
            case ErrorCode::TimeoutConnect:
                return true;
            default:
                return false;
            }
        }

        // Statuses that mean "the server could not serve this now, come back".
        //
        // Deliberately narrow. 500 is NOT here: an unhandled server error is
        // usually deterministic, so retrying just costs another failure. 501,
        // 505 and the whole 4xx range other than 429 are permanent by nature.
        inline bool is_retryable_status(int status) noexcept {
            switch (status) {
            case 429:   // Too Many Requests
            case 502:   // Bad Gateway
            case 503:   // Service Unavailable
            case 504:   // Gateway Timeout
                return true;
            default:
                return false;
            }
        }

        // ------------------------------------------------------------------
        // HTTP-date parsing
        //
        // RFC 7231 7.1.1.1 requires recipients to accept three formats:
        //   IMF-fixdate   Sun, 06 Nov 1994 08:49:37 GMT
        //   RFC 850       Sunday, 06-Nov-94 08:49:37 GMT
        //   asctime       Sun Nov  6 08:49:37 1994
        //
        // Parsed to seconds since the Unix epoch, so the difference between two
        // dates is exact integer arithmetic. No local clock is involved:
        // Retry-After and Date come from the same response, so their difference
        // is the server's intended delay regardless of what this host's clock
        // says or whether it is even set correctly.
        // ------------------------------------------------------------------

        // Days since 1970-01-01 for a proleptic Gregorian date (Howard
        // Hinnant's civil-days algorithm: exact, no tables, no floating point).
        inline int64_t days_from_civil(int64_t y, unsigned m, unsigned d) noexcept {
            y -= (m <= 2) ? 1 : 0;
            const int64_t era = (y >= 0 ? y : y - 399) / 400;
            const unsigned yoe = static_cast<unsigned>(y - era * 400);
            const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
            const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
            return era * 146097 + static_cast<int64_t>(doe) - 719468;
        }

        // Small hand-written scanner. Three formats differ enough in punctuation
        // and field width that a shared cursor with a few helpers is clearer
        // than three strptime-style formats -- and it avoids depending on the
        // C library's locale-sensitive time parsing.
        class DateScanner {
        public:
            DateScanner(const char* p, size_t n) : p_(p), n_(n) {}

            bool eof() const noexcept { return i_ >= n_; }
            void rewind() noexcept { i_ = 0; }

            void spaces() noexcept {
                while (i_ < n_ && (p_[i_] == ' ' || p_[i_] == '\t')) ++i_;
            }
            bool expect(char c) noexcept {
                if (i_ < n_ && p_[i_] == c) { ++i_; return true; }
                return false;
            }
            bool digits(int count, int* out) noexcept {
                if (i_ + static_cast<size_t>(count) > n_) return false;
                int v = 0;
                for (int k = 0; k < count; ++k) {
                    const char c = p_[i_ + static_cast<size_t>(k)];
                    if (c < '0' || c > '9') return false;
                    v = v * 10 + (c - '0');
                }
                i_ += static_cast<size_t>(count);
                if (out) *out = v;
                return true;
            }
            // One or two digits: asctime right-aligns the day ("Nov  6").
            bool digits12(int* out) noexcept {
                if (i_ >= n_) return false;
                int v = 0, count = 0;
                while (i_ < n_ && count < 2 && p_[i_] >= '0' && p_[i_] <= '9') {
                    v = v * 10 + (p_[i_] - '0');
                    ++i_; ++count;
                }
                if (count == 0) return false;
                if (out) *out = v;
                return true;
            }
            // Case-insensitive three-letter token from a packed lowercase list.
            int name3(const char* packed, int count) noexcept {
                if (i_ + 3 > n_) return -1;
                char a[3];
                for (int k = 0; k < 3; ++k) {
                    char c = p_[i_ + static_cast<size_t>(k)];
                    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                    a[k] = c;
                }
                for (int s = 0; s < count; ++s) {
                    const char* w = packed + s * 3;
                    if (a[0] == w[0] && a[1] == w[1] && a[2] == w[2]) {
                        i_ += 3;
                        return s;
                    }
                }
                return -1;
            }
            void alpha_run() noexcept {
                while (i_ < n_ && ((p_[i_] >= 'A' && p_[i_] <= 'Z') ||
                                   (p_[i_] >= 'a' && p_[i_] <= 'z'))) ++i_;
            }
            bool time_hms(int* h, int* mi, int* s) noexcept {
                return digits(2, h) && expect(':') && digits(2, mi) &&
                       expect(':') && digits(2, s);
            }
            bool lit(const char* word) noexcept {
                size_t k = 0;
                while (word[k]) {
                    if (i_ + k >= n_) return false;
                    char c = p_[i_ + k];
                    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                    char w = word[k];
                    if (w >= 'A' && w <= 'Z') w = static_cast<char>(w - 'A' + 'a');
                    if (c != w) return false;
                    ++k;
                }
                i_ += k;
                return true;
            }

        private:
            const char* p_;
            size_t n_;
            size_t i_{0};
        };

        inline int64_t compose_epoch(int year, int month, int day,
                                     int h, int mi, int s) noexcept {
            const int64_t days = days_from_civil(static_cast<int64_t>(year),
                                                 static_cast<unsigned>(month),
                                                 static_cast<unsigned>(day));
            return days * 86400 + static_cast<int64_t>(h) * 3600 +
                   static_cast<int64_t>(mi) * 60 + s;
        }

        // "Sun, 06 Nov 1994 08:49:37 GMT"
        inline bool scan_imf_fixdate(DateScanner& c, int64_t* out) noexcept {
            static const char kDays[] = "sunmontuewedthufrisat";
            static const char kMonths[] = "janfebmaraprmayjunjulaugsepoctnovdec";
            int day = 0, year = 0, h = 0, mi = 0, s = 0;
            if (c.name3(kDays, 7) < 0) return false;
            if (!c.expect(',')) return false;
            c.spaces();
            if (!c.digits(2, &day)) return false;
            c.spaces();
            const int mon = c.name3(kMonths, 12);
            if (mon < 0) return false;
            c.spaces();
            if (!c.digits(4, &year)) return false;
            c.spaces();
            if (!c.time_hms(&h, &mi, &s)) return false;
            c.spaces();
            if (!c.lit("GMT")) return false;
            if (!c.eof()) return false;
            *out = compose_epoch(year, mon + 1, day, h, mi, s);
            return true;
        }

        // "Sunday, 06-Nov-94 08:49:37 GMT"
        inline bool scan_rfc850(DateScanner& c, int64_t* out) noexcept {
            static const char kMonths[] = "janfebmaraprmayjunjulaugsepoctnovdec";
            int day = 0, yy = 0, h = 0, mi = 0, s = 0;
            c.alpha_run();                 // full weekday name, any spelling
            if (!c.expect(',')) return false;
            c.spaces();
            if (!c.digits(2, &day)) return false;
            if (!c.expect('-')) return false;
            const int mon = c.name3(kMonths, 12);
            if (mon < 0) return false;
            if (!c.expect('-')) return false;
            if (!c.digits(2, &yy)) return false;
            c.spaces();
            if (!c.time_hms(&h, &mi, &s)) return false;
            c.spaces();
            if (!c.lit("GMT")) return false;
            if (!c.eof()) return false;
            // Two-digit year: without a clock the standard reading is the
            // 1970..2069 window, which is what every other HTTP implementation
            // uses and what RFC 7231 describes.
            const int year = (yy < 70) ? 2000 + yy : 1900 + yy;
            *out = compose_epoch(year, mon + 1, day, h, mi, s);
            return true;
        }

        // "Sun Nov  6 08:49:37 1994"
        inline bool scan_asctime(DateScanner& c, int64_t* out) noexcept {
            static const char kDays[] = "sunmontuewedthufrisat";
            static const char kMonths[] = "janfebmaraprmayjunjulaugsepoctnovdec";
            int day = 0, h = 0, mi = 0, s = 0, year = 0;
            if (c.name3(kDays, 7) < 0) return false;
            c.spaces();
            const int mon = c.name3(kMonths, 12);
            if (mon < 0) return false;
            c.spaces();
            if (!c.digits12(&day)) return false;
            c.spaces();
            if (!c.time_hms(&h, &mi, &s)) return false;
            c.spaces();
            if (!c.digits(4, &year)) return false;
            if (!c.eof()) return false;
            *out = compose_epoch(year, mon + 1, day, h, mi, s);
            return true;
        }

        // Seconds since the Unix epoch, or nullopt when the value is not a valid
        // HTTP-date in any of the three accepted formats.
        inline std::optional<int64_t> parse_http_date(string_view value) {
            size_t b = 0, e = static_cast<size_t>(value.size());
            while (b < e && (value.data()[b] == ' ' || value.data()[b] == '\t')) ++b;
            while (e > b && (value.data()[e - 1] == ' ' || value.data()[e - 1] == '\t')) --e;
            if (b == e) return std::nullopt;

            int64_t out = 0;
            DateScanner c(value.data() + b, e - b);
            if (scan_imf_fixdate(c, &out)) return out;
            c.rewind();
            if (scan_rfc850(c, &out)) return out;
            c.rewind();
            if (scan_asctime(c, &out)) return out;
            return std::nullopt;
        }

        // ------------------------------------------------------------------
        // Retry-After
        //
        // Two forms:
        //   delay-seconds   "120"
        //   HTTP-date       "Wed, 21 Oct 2015 07:28:00 GMT"
        //
        // The date form is a wall-clock instant, so it only becomes a delay when
        // a reference instant is available. That reference is the `Date` header
        // of the SAME response: both values come from the server, so their
        // difference is the server's intended delay and owes nothing to this
        // host's clock being correct, set, or in the right timezone.
        //
        // Without a usable Date the function returns nullopt and the caller
        // falls back to its own backoff. That is honest: deriving a delay from a
        // local clock we do not otherwise trust would be worse than backing off
        // normally.
        // ------------------------------------------------------------------
        inline std::optional<Duration> parse_retry_after(string_view value,
                                                         string_view server_date = {}) {
            size_t b = 0, e = static_cast<size_t>(value.size());
            while (b < e && (value.data()[b] == ' ' || value.data()[b] == '\t')) ++b;
            while (e > b && (value.data()[e - 1] == ' ' || value.data()[e - 1] == '\t')) --e;
            if (b == e) return std::nullopt;

            // delay-seconds: all digits.
            bool all_digits = true;
            for (size_t i = b; i < e; ++i) {
                const char c = value.data()[i];
                if (c < '0' || c > '9') { all_digits = false; break; }
            }
            if (all_digits) {
                uint64_t seconds = 0;
                for (size_t i = b; i < e; ++i) {
                    // Overflow guard: beyond ~584 billion years is nonsense and
                    // would overflow the conversion below.
                    if (seconds > (UINT64_MAX / 10)) return std::nullopt;
                    seconds = seconds * 10 + static_cast<uint64_t>(value.data()[i] - '0');
                }
                return std::chrono::duration_cast<Duration>(std::chrono::seconds(seconds));
            }

            // HTTP-date: becomes a delay only against the response's own Date.
            const auto target = parse_http_date(string_view(value.data() + b, e - b));
            if (!target) return std::nullopt;
            if (static_cast<size_t>(server_date.size()) == 0) return std::nullopt;
            const auto ref = parse_http_date(server_date);
            if (!ref) return std::nullopt;

            int64_t delta = *target - *ref;
            // A date in the past means "now": clamp rather than produce a
            // negative delay that would read as "already expired".
            if (delta < 0) delta = 0;
            return std::chrono::duration_cast<Duration>(std::chrono::seconds(delta));
        }

        // Exponential backoff for attempt N (0-based), clamped to max_delay.
        inline Duration backoff_delay(const RetryPolicy& p, size_t attempt) noexcept {
            Duration d = p.base_delay;
            for (size_t i = 0; i < attempt; ++i) {
                const auto scaled = std::chrono::duration_cast<Duration>(
                    std::chrono::duration<double, Duration::period>(
                        static_cast<double>(d.count()) * p.multiplier));
                if (scaled <= d && p.multiplier > 1.0) {
                    // Overflow or saturation: stop growing and let the clamp
                    // below handle it. Without this a large attempt count would
                    // overflow the duration.
                    d = p.max_delay;
                    break;
                }
                d = scaled;
                if (d >= p.max_delay) { d = p.max_delay; break; }
            }
            if (d > p.max_delay) d = p.max_delay;
            return d;
        }

        // Applies jitter in [0.5, 1.5) of the delay. The source is injected so a
        // test can make the timing deterministic.
        inline Duration apply_jitter(const RetryPolicy& p, Duration d,
                                     const std::function<uint32_t()>& rng) noexcept {
            if (!p.jitter || !rng) return d;
            const uint32_t r = rng() % 1000u;
            const double scale = 0.5 + static_cast<double>(r) / 1000.0;
            return std::chrono::duration_cast<Duration>(
                std::chrono::duration<double, Duration::period>(
                    static_cast<double>(d.count()) * scale));
        }

        // The decision. Returns the delay to wait, or nullopt when the request
        // must NOT be retried.
        //
        // `attempt` is the number of retries already performed (0 on the first
        // failure). Pure: same inputs, same output.
        inline std::optional<Duration> next_delay(const RetryPolicy& p,
                                                  const RetryContext& ctx,
                                                  ErrorCode error,
                                                  size_t attempt,
                                                  const std::function<uint32_t()>& rng) {
            if (p.max_retries == 0) return std::nullopt;
            if (attempt >= p.max_retries) return std::nullopt;

            // Body fidelity: a one-shot source cannot be re-sent.
            if (!ctx.body_replayable) return std::nullopt;

            // Method safety. A non-idempotent method is only retried when the
            // caller explicitly accepted the duplicate risk. A retryable status
            // does not weaken this: a 503 on a POST may still have been acted on.
            if (!p.retry_non_idempotent && !is_idempotent(ctx.method)) {
                return std::nullopt;
            }

            // Once the caller has body bytes, a retry would deliver them twice.
            if (ctx.body_delivered) return std::nullopt;

            // Two separate routes, because they carry different evidence.
            if (ctx.status != 0) {
                // A complete response head arrived. Only a status that itself
                // means "try again" is retryable; every other answer is final.
                if (!p.retry_on_status) return std::nullopt;
                if (!is_retryable_status(ctx.status)) return std::nullopt;
            } else if (ctx.response_started) {
                // Bytes arrived but no complete head: the head was truncated.
                // The server started answering, so it may already have acted.
                return std::nullopt;
            } else {
                // Nothing arrived. Only a transport failure that proves the
                // request did not complete qualifies.
                if (!is_transient_failure(error)) return std::nullopt;
            }

            // A server-supplied delay wins over our own backoff, but is still
            // bounded by max_delay: a broken or hostile `Retry-After: 99999`
            // must not park the request indefinitely.
            Duration d = ctx.retry_after ? *ctx.retry_after : backoff_delay(p, attempt);
            if (d > p.max_delay) d = p.max_delay;
            if (!ctx.retry_after) d = apply_jitter(p, d, rng);
            return d;
        }

    } // namespace retry_detail
} // namespace megohttp

#endif // MEGOHTTP_RETRY_HPP_INCLUDED
