#ifndef MEGOHTTP_RECONNECT_HPP
#define MEGOHTTP_RECONNECT_HPP

// ---------------------------------------------------------------------------
// Reconnect policy for long-lived streams (task book 11 SSE reconnect, 12.2
// WebSocket auto-reconnect).
//
// SSE and WebSocket each have their own reconnect policy and the two must never
// be stacked with the general HTTP retry policy: a retry re-sends a request,
// whereas a reconnect re-establishes a session. Sharing one counter between
// them is how you get an unbounded, unexplainable number of attempts.
//
// This file holds only the decision arithmetic — no sockets, no timers — so
// every rule below is testable without a network.
// ---------------------------------------------------------------------------

#include <megohttp/error.hpp>
#include <megohttp/executor.hpp>   // Duration / Clock

#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <optional>

namespace megohttp {

    // Shared shape for SSE and WebSocket reconnect policies. The two protocols
    // differ in what counts as retryable and in budget-reset rules, both of
    // which live in their own structures below.
    struct ReconnectBackoff {
        Duration initial_delay{std::chrono::seconds(1)};
        Duration max_delay{std::chrono::seconds(30)};
        double multiplier{2.0};
        // Fraction of the delay to jitter by, applied as +/- this ratio.
        // 0 = no jitter.
        double jitter_ratio{0.2};
        // 0 = unlimited attempts.
        size_t max_attempts{0};
        // 0 = unlimited total duration.
        Duration max_total_duration{Duration::zero()};
    };

    namespace reconnect_detail {

        // Delay before attempt number `attempt` (1-based), with jitter applied.
        //
        // The multiplier is clamped BEFORE the jitter so a huge attempt count
        // cannot overflow the duration: `initial * multiplier^attempt` is
        // computed by repeated saturation, not by pow().
        inline Duration backoff_delay(const ReconnectBackoff& p, size_t attempt,
                                      uint32_t jitter_seed) {
            if (attempt == 0) attempt = 1;

            Duration d = p.initial_delay;
            for (size_t i = 1; i < attempt; ++i) {
                if (p.multiplier <= 1.0) break;
                // Saturate at max_delay instead of letting it overflow.
                const auto next = std::chrono::duration_cast<Duration>(
                    std::chrono::duration<double, Duration::period>(
                        static_cast<double>(d.count()) * p.multiplier));
                if (next >= p.max_delay) { d = p.max_delay; break; }
                d = next;
            }
            if (d > p.max_delay) d = p.max_delay;

            if (p.jitter_ratio > 0.0) {
                // Deterministic pseudo-random in [0,1): the caller passes a seed
                // it controls, so tests pin the value instead of sleeping.
                const double unit = static_cast<double>(jitter_seed % 10000u) / 10000.0;
                // Map to [-ratio, +ratio].
                const double factor = 1.0 + (unit * 2.0 - 1.0) * p.jitter_ratio;
                const auto jittered = std::chrono::duration_cast<Duration>(
                    std::chrono::duration<double, Duration::period>(
                        static_cast<double>(d.count()) * factor));
                d = jittered > Duration::zero() ? jittered : Duration::zero();
                if (d > p.max_delay) d = p.max_delay;
            }
            return d;
        }

        // Attempts/time exhausted?
        inline bool budget_exhausted(const ReconnectBackoff& p, size_t attempts_done,
                                     Duration elapsed) {
            if (p.max_attempts != 0 && attempts_done >= p.max_attempts) return true;
            if (p.max_total_duration != Duration::zero() && elapsed >= p.max_total_duration) {
                return true;
            }
            return false;
        }

    } // namespace reconnect_detail

    // -----------------------------------------------------------------------
    // SSE reconnect (task book 11)
    //
    // A disconnect that will be retried is NOT the session's terminal state; the
    // terminal notification fires once when the stream is genuinely over.
    // -----------------------------------------------------------------------
    struct SseReconnectPolicy {
        // Runtime default OFF, like every other "changes who sees what" switch.
        bool auto_reconnect{false};

        ReconnectBackoff backoff;

        // Send Last-Event-ID on reconnect, taken from the last received id.
        bool send_last_event_id{true};

        // A server `retry:` field overrides the backoff seed for later attempts;
        // max_delay still caps it.
        bool honor_server_retry{true};

        // Stop conditions required by the WHATWG spec / task book 11:
        //   204 No Content  -> stop, the server has nothing more to send
        //   2xx other       -> stop (a normal response, not a reconnectable drop)
        //   other 4xx/5xx   -> stop unless the caller decides otherwise
        // A redirect is not followed by default for the same reason as HTTP.
        bool stop_on_http_error{true};
    };

    // -----------------------------------------------------------------------
    // WebSocket reconnect (task book 12.2)
    // -----------------------------------------------------------------------
    struct WebSocketReconnectPolicy {
        bool enabled{false};   // runtime default OFF

        ReconnectBackoff backoff;

        // Does the FIRST connect failure count against the retry budget?
        bool retry_initial_connect_failure{true};

        // Budget reset is deliberately NOT "any successful connect resets
        // everything": a flapping short-lived connection would retry forever.
        // The connection must stay open this long before the failure counter
        // decays.
        Duration minimum_stable_connection_duration{std::chrono::seconds(30)};
        // Failures cleared by one stable connection. 0 = clear all.
        size_t stable_connection_success_decay{0};

        // Optional per-outcome override. Return nullopt to use the default table.
        // The library refuses a policy that would retry a failed TLS identity
        // check, so this cannot be used to weaken security.
        std::function<std::optional<bool>(const Error&)> classify_error;
    };

    namespace ws_reconnect_detail {

        // Default classification (task book 12.2). Anything not listed here is
        // NOT retried: an unknown error is more likely a real answer than a
        // transient fault, and guessing "transient" is what makes a reconnect
        // loop repeat a protocol violation forever.
        inline bool is_retryable_by_default(const Error& e) {
            switch (e.code()) {
                case ErrorCode::ConnectFailed:
                case ErrorCode::ConnectTimeout:
                case ErrorCode::ConnectionReset:
                case ErrorCode::ConnectionClosed:
                case ErrorCode::TimeoutConnect:
                case ErrorCode::TimeoutRecv:
                case ErrorCode::DnsResolveFailed:
                case ErrorCode::DnsTimeout:
                case ErrorCode::ProxyConnectFailed:
                    return true;

                // Never retry a failed identity check: the peer is not who it
                // claims to be, and a new TCP connection does not change that.
                case ErrorCode::TlsCertificateInvalid:
                case ErrorCode::TlsCertificateExpired:
                case ErrorCode::TlsHostnameMismatch:
                    return false;

                // Protocol-level failures are deterministic.
                case ErrorCode::WsHandshakeFailed:
                case ErrorCode::WsProtocolError:
                case ErrorCode::WsUtf8Invalid:
                case ErrorCode::WsCompressionNegotiationFailed:
                case ErrorCode::WsCompressionMalformedData:
                    return false;

                // Retrying would re-receive the same oversized message.
                case ErrorCode::WsCompressionResourceExceeded:
                    return false;

                // Permanent unless the credentials changed.
                case ErrorCode::ProxyAuthFailed:
                    return false;

                // The caller or the Client asked for this.
                case ErrorCode::Cancelled:
                    return false;

                default:
                    return false;
            }
        }

        // Close-code driven answers (RFC 6455 7.4.1).
        //   1000 normal / 1001 going away -> the session ended on purpose
        //   1008 policy / 1003 unsupported data -> retrying repeats the mistake
        //   anything else -> transient
        inline bool is_retryable_close_code(uint16_t code) {
            switch (code) {
                case 1000:  // normal closure
                case 1001:  // going away
                case 1008:  // policy violation
                case 1003:  // unsupported data
                    return false;
                default:
                    return true;
            }
        }

        // The classification actually used: the caller's override first, then
        // the default table.
        inline bool should_retry(const WebSocketReconnectPolicy& p, const Error& e) {
            if (p.classify_error) {
                if (const auto verdict = p.classify_error(e)) return *verdict;
            }
            return is_retryable_by_default(e);
        }

        // Whether a connection that just ended was stable enough to decay the
        // failure counter.
        inline bool was_stable(const WebSocketReconnectPolicy& p, Duration connection_lifetime) {
            return connection_lifetime >= p.minimum_stable_connection_duration;
        }

        // New failure count after a stable connection.
        inline size_t decay_failures(const WebSocketReconnectPolicy& p, size_t failures) {
            if (p.stable_connection_success_decay == 0) return 0;
            return (failures > p.stable_connection_success_decay)
                       ? failures - p.stable_connection_success_decay
                       : 0;
        }

    } // namespace ws_reconnect_detail

} // namespace megohttp

#endif // MEGOHTTP_RECONNECT_HPP
