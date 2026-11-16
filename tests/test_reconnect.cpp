// Reconnect policy tests (task book 11 SSE reconnect, 12.2 WebSocket reconnect).
//
// Pure decision arithmetic: no sockets, no timers, no sleeps. Every rule the
// policy encodes is asserted directly, which is the only way to prove a retry
// classification table without waiting for real network faults.

#include <megohttp/reconnect.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace megohttp;

namespace {

    Duration ms(int n) { return std::chrono::milliseconds(n); }

    Error err(ErrorCode c) { return Error{c, ErrorPhase::None, string{}}; }

} // namespace

TEST_CASE("reconnect backoff grows exponentially and clamps", "[reconnect]") {
    ReconnectBackoff p;
    p.initial_delay = ms(100);
    p.max_delay = ms(1000);
    p.multiplier = 2.0;
    p.jitter_ratio = 0.0;

    CHECK(reconnect_detail::backoff_delay(p, 1, 0) == ms(100));
    CHECK(reconnect_detail::backoff_delay(p, 2, 0) == ms(200));
    CHECK(reconnect_detail::backoff_delay(p, 3, 0) == ms(400));
    CHECK(reconnect_detail::backoff_delay(p, 4, 0) == ms(800));
    // Clamped, not grown past max_delay.
    CHECK(reconnect_detail::backoff_delay(p, 5, 0) == ms(1000));
    CHECK(reconnect_detail::backoff_delay(p, 50, 0) == ms(1000));
}

TEST_CASE("reconnect attempt 0 is treated as the first attempt", "[reconnect]") {
    ReconnectBackoff p;
    p.initial_delay = ms(250);
    p.jitter_ratio = 0.0;
    CHECK(reconnect_detail::backoff_delay(p, 0, 0) == ms(250));
}

TEST_CASE("reconnect jitter stays inside the configured band", "[reconnect]") {
    ReconnectBackoff p;
    p.initial_delay = ms(1000);
    p.max_delay = ms(10000);
    p.jitter_ratio = 0.5;

    // Sweep the seed space: every result must land in [0.5x, 1.5x].
    for (uint32_t seed = 0; seed < 500; ++seed) {
        const auto d = reconnect_detail::backoff_delay(p, 1, seed * 37u);
        CHECK(d >= ms(500));
        CHECK(d <= ms(1500));
    }
}

TEST_CASE("reconnect with zero jitter is deterministic", "[reconnect]") {
    ReconnectBackoff p;
    p.initial_delay = ms(300);
    p.jitter_ratio = 0.0;
    CHECK(reconnect_detail::backoff_delay(p, 1, 1) ==
          reconnect_detail::backoff_delay(p, 1, 9999));
}

TEST_CASE("reconnect jitter is capped by max_delay", "[reconnect]") {
    ReconnectBackoff p;
    p.initial_delay = ms(1000);
    p.max_delay = ms(1000);
    p.jitter_ratio = 0.5;
    for (uint32_t seed = 0; seed < 200; ++seed) {
        CHECK(reconnect_detail::backoff_delay(p, 1, seed * 13u) <= ms(1000));
    }
}

TEST_CASE("reconnect budget exhaustion counts attempts", "[reconnect]") {
    ReconnectBackoff p;
    p.max_attempts = 3;
    CHECK(!reconnect_detail::budget_exhausted(p, 0, Duration::zero()));
    CHECK(!reconnect_detail::budget_exhausted(p, 2, Duration::zero()));
    CHECK(reconnect_detail::budget_exhausted(p, 3, Duration::zero()));
    CHECK(reconnect_detail::budget_exhausted(p, 4, Duration::zero()));
}

TEST_CASE("reconnect budget exhaustion counts time", "[reconnect]") {
    ReconnectBackoff p;
    p.max_total_duration = ms(5000);
    CHECK(!reconnect_detail::budget_exhausted(p, 0, ms(4999)));
    CHECK(reconnect_detail::budget_exhausted(p, 0, ms(5000)));
    CHECK(reconnect_detail::budget_exhausted(p, 0, ms(9000)));
}

TEST_CASE("reconnect budget of zero means unlimited", "[reconnect]") {
    ReconnectBackoff p;   // max_attempts 0, max_total_duration 0
    CHECK(!reconnect_detail::budget_exhausted(p, 1000, ms(999999)));
}

TEST_CASE("ws reconnect retries transport failures", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    // These prove the request never completed, so re-establishing is safe.
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::ConnectFailed)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::ConnectTimeout)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::ConnectionReset)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::ConnectionClosed)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::TimeoutConnect)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::TimeoutRecv)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::DnsResolveFailed)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::DnsTimeout)));
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::ProxyConnectFailed)));
}

TEST_CASE("ws reconnect never retries a failed identity check", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    // A new TCP connection does not change who the peer is.
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::TlsCertificateInvalid)));
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::TlsCertificateExpired)));
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::TlsHostnameMismatch)));
}

TEST_CASE("ws reconnect never retries protocol errors", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::WsHandshakeFailed)));
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::WsProtocolError)));
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::WsUtf8Invalid)));
    CHECK(!ws_reconnect_detail::should_retry(
        p, err(ErrorCode::WsCompressionNegotiationFailed)));
    CHECK(!ws_reconnect_detail::should_retry(
        p, err(ErrorCode::WsCompressionMalformedData)));
}

TEST_CASE("ws reconnect does not loop on an oversized message", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    // Reconnecting would re-receive the same message and hit the same limit.
    CHECK(!ws_reconnect_detail::should_retry(
        p, err(ErrorCode::WsCompressionResourceExceeded)));
}

TEST_CASE("ws reconnect does not retry a cancellation", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    // The caller asked for this; reconnecting would ignore their intent.
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::Cancelled)));
}

TEST_CASE("ws reconnect does not retry a permanent auth failure", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::ProxyAuthFailed)));
}

TEST_CASE("ws reconnect caller override wins over the default table", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    // Force retry of an error that is not retryable by default.
    p.classify_error = [](const Error& e) -> std::optional<bool> {
        if (e.code() == ErrorCode::WsProtocolError) return true;
        return std::nullopt;
    };
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::WsProtocolError)));

    // nullopt falls back to the default table.
    CHECK(ws_reconnect_detail::should_retry(p, err(ErrorCode::ConnectFailed)));
    CHECK(!ws_reconnect_detail::should_retry(p, err(ErrorCode::Cancelled)));
}

TEST_CASE("ws reconnect close-code classification", "[reconnect][websocket]") {
    using namespace ws_reconnect_detail;
    // Purposeful shutdowns.
    CHECK(!is_retryable_close_code(1000));
    CHECK(!is_retryable_close_code(1001));
    // Policy / unsupported data: retrying repeats the mistake.
    CHECK(!is_retryable_close_code(1008));
    CHECK(!is_retryable_close_code(1003));
    // Anything else is treated as transient.
    CHECK(is_retryable_close_code(1006));   // abnormal closure
    CHECK(is_retryable_close_code(1011));   // internal error
    CHECK(is_retryable_close_code(4000));
}

TEST_CASE("ws reconnect budget decays only after a stable connection", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    p.minimum_stable_connection_duration = ms(1000);
    p.stable_connection_success_decay = 0;   // clear all

    // A short-lived connection must NOT reset the budget: that is how a flapping
    // server would retry forever.
    CHECK(!ws_reconnect_detail::was_stable(p, ms(999)));
    CHECK(ws_reconnect_detail::was_stable(p, ms(1000)));
    CHECK(ws_reconnect_detail::was_stable(p, ms(5000)));
}

TEST_CASE("ws reconnect gradual decay clears only part of the count", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    p.stable_connection_success_decay = 0;
    CHECK(ws_reconnect_detail::decay_failures(p, 5) == 0);

    p.stable_connection_success_decay = 2;
    CHECK(ws_reconnect_detail::decay_failures(p, 5) == 3);
    CHECK(ws_reconnect_detail::decay_failures(p, 2) == 0);
    CHECK(ws_reconnect_detail::decay_failures(p, 1) == 0);
    CHECK(ws_reconnect_detail::decay_failures(p, 0) == 0);
}

TEST_CASE("sse reconnect policy defaults to off", "[reconnect][sse]") {
    SseReconnectPolicy p;
    CHECK(!p.auto_reconnect);
    CHECK(p.send_last_event_id);
    CHECK(p.honor_server_retry);
    CHECK(p.stop_on_http_error);
}

TEST_CASE("ws reconnect policy defaults to off", "[reconnect][websocket]") {
    WebSocketReconnectPolicy p;
    CHECK(!p.enabled);
    CHECK(p.retry_initial_connect_failure);
}
