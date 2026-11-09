// Phase 5 S5.3: retry policy decision table.
//
// The decision is a pure function of (policy, context, error, attempt), so it is
// tested without a socket. That separation is deliberate: a retry policy proven
// only through integration tests cannot show WHICH rule refused a retry, and the
// rules are the whole point.
//
// Every "must not retry" case has a "must retry" counterpart, so a policy that
// simply refused everything would fail.
#include <megohttp/config.hpp>

#include <catch2/catch_test_macros.hpp>
#include <megohttp/retry.hpp>

#include <cstdint>

using namespace megohttp;

namespace {

// Deterministic "random" source: the middle of the jitter range, so a delay
// assertion is exact.
std::function<uint32_t()> fixed_rng(uint32_t v) {
    return [v] { return v; };
}

bool retries(const RetryPolicy& p, const RetryContext& ctx, ErrorCode e, size_t attempt = 0) {
    return retry_detail::next_delay(p, ctx, e, attempt, fixed_rng(500)).has_value();
}

RetryPolicy basic_policy(size_t max_retries = 3) {
    RetryPolicy p;
    p.max_retries = max_retries;
    p.jitter = false;
    return p;
}

RetryContext get_ctx() {
    RetryContext c;
    c.method = Method::Get;
    c.body_replayable = true;
    return c;
}

} // namespace

// ---------------------------------------------------------------------------
// Method safety
// ---------------------------------------------------------------------------

TEST_CASE("an idempotent method is retried on a transient failure", "[retry]") {
    // The positive control: without this, every "must not retry" test below
    // would also pass with a policy that never retries anything.
    CHECK(retries(basic_policy(), get_ctx(), ErrorCode::ConnectFailed));
}

TEST_CASE("POST is not retried by default", "[retry]") {
    RetryContext c = get_ctx();
    c.method = Method::Post;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::ConnectionReset));
}

TEST_CASE("POST is retried when the caller accepts the duplicate risk", "[retry]") {
    RetryPolicy p = basic_policy();
    p.retry_non_idempotent = true;
    RetryContext c = get_ctx();
    c.method = Method::Post;
    CHECK(retries(p, c, ErrorCode::ConnectionReset));
}

TEST_CASE("PATCH is treated as non-idempotent", "[retry]") {
    RetryContext c = get_ctx();
    c.method = Method::Patch;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::ConnectionReset));
}

TEST_CASE("the idempotent set matches RFC 7231", "[retry]") {
    using retry_detail::is_idempotent;
    CHECK(is_idempotent(Method::Get));
    CHECK(is_idempotent(Method::Head));
    CHECK(is_idempotent(Method::Put));
    CHECK(is_idempotent(Method::Delete));
    CHECK(is_idempotent(Method::Options));
    CHECK(is_idempotent(Method::Trace));
    CHECK_FALSE(is_idempotent(Method::Post));
    CHECK_FALSE(is_idempotent(Method::Patch));
    CHECK_FALSE(is_idempotent(Method::Custom));
}

// ---------------------------------------------------------------------------
// Body replay
// ---------------------------------------------------------------------------

TEST_CASE("an unreplayable body blocks the retry regardless of method", "[retry]") {
    RetryContext c = get_ctx();   // GET, but with a one-shot body
    c.body_replayable = false;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::ConnectFailed));
}

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

TEST_CASE("only transport failures that prove no answer was received are transient",
          "[retry]") {
    using retry_detail::is_transient_failure;
    CHECK(is_transient_failure(ErrorCode::ConnectFailed));
    CHECK(is_transient_failure(ErrorCode::ConnectTimeout));
    CHECK(is_transient_failure(ErrorCode::ConnectionReset));
    CHECK(is_transient_failure(ErrorCode::ConnectionClosed));

    // These mean the server answered or the config is wrong. Retrying either
    // would duplicate work or loop pointlessly.
    CHECK_FALSE(is_transient_failure(ErrorCode::HttpInvalidResponse));
    CHECK_FALSE(is_transient_failure(ErrorCode::HttpProtocolViolation));
    CHECK_FALSE(is_transient_failure(ErrorCode::TlsCertificateInvalid));
    CHECK_FALSE(is_transient_failure(ErrorCode::TlsHandshakeFailed));
    CHECK_FALSE(is_transient_failure(ErrorCode::Cancelled));
    CHECK_FALSE(is_transient_failure(ErrorCode::TimeoutTotal));
    CHECK_FALSE(is_transient_failure(ErrorCode::DnsNameNotFound));
    CHECK_FALSE(is_transient_failure(ErrorCode::InvalidArgument));
}

TEST_CASE("a TLS failure is never retried", "[retry]") {
    CHECK_FALSE(retries(basic_policy(), get_ctx(), ErrorCode::TlsCertificateInvalid));
}

TEST_CASE("a DNS NXDOMAIN is never retried", "[retry]") {
    // The name does not exist; asking again will not change that.
    CHECK_FALSE(retries(basic_policy(), get_ctx(), ErrorCode::DnsNameNotFound));
}

TEST_CASE("cancellation is never retried", "[retry]") {
    CHECK_FALSE(retries(basic_policy(), get_ctx(), ErrorCode::Cancelled));
}

// ---------------------------------------------------------------------------
// Delivery state
// ---------------------------------------------------------------------------

TEST_CASE("a retry is refused once the response has started", "[retry]") {
    // The server answered. Whatever it decided may already have happened.
    RetryContext c = get_ctx();
    c.response_started = true;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::ConnectionReset));
}

TEST_CASE("a retry is refused once body bytes reached the caller", "[retry]") {
    // The caller has data. A retry would deliver it twice.
    RetryContext c = get_ctx();
    c.body_delivered = true;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::ConnectionReset));
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

TEST_CASE("the retry budget is respected", "[retry]") {
    RetryPolicy p = basic_policy(2);
    const auto c = get_ctx();
    CHECK(retries(p, c, ErrorCode::ConnectFailed, 0));   // first retry
    CHECK(retries(p, c, ErrorCode::ConnectFailed, 1));   // second retry
    CHECK_FALSE(retries(p, c, ErrorCode::ConnectFailed, 2));  // budget spent
}

TEST_CASE("max_retries = 0 disables retrying entirely", "[retry]") {
    RetryPolicy p;
    p.max_retries = 0;
    CHECK_FALSE(retries(p, get_ctx(), ErrorCode::ConnectFailed));
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

TEST_CASE("backoff grows exponentially and is clamped", "[retry]") {
    RetryPolicy p;
    p.base_delay = std::chrono::milliseconds(100);
    p.max_delay = std::chrono::milliseconds(1000);
    p.multiplier = 2.0;

    using namespace std::chrono;
    CHECK(retry_detail::backoff_delay(p, 0) == milliseconds(100));
    CHECK(retry_detail::backoff_delay(p, 1) == milliseconds(200));
    CHECK(retry_detail::backoff_delay(p, 2) == milliseconds(400));
    CHECK(retry_detail::backoff_delay(p, 3) == milliseconds(800));
    // Clamped rather than 1600.
    CHECK(retry_detail::backoff_delay(p, 4) == milliseconds(1000));
    // A large attempt count must not overflow; it saturates at max_delay.
    CHECK(retry_detail::backoff_delay(p, 500) == milliseconds(1000));
}

TEST_CASE("multiplier 1.0 gives a constant delay", "[retry]") {
    RetryPolicy p;
    p.base_delay = std::chrono::milliseconds(50);
    p.max_delay = std::chrono::milliseconds(1000);
    p.multiplier = 1.0;
    using namespace std::chrono;
    CHECK(retry_detail::backoff_delay(p, 0) == milliseconds(50));
    CHECK(retry_detail::backoff_delay(p, 5) == milliseconds(50));
}

TEST_CASE("jitter stays within the documented band", "[retry]") {
    // The band is [0.5, 1.5) of the base delay. A bounded, non-zero result is
    // what matters: it decorrelates clients without unbounded drift.
    RetryPolicy p;
    p.base_delay = std::chrono::milliseconds(1000);
    p.max_delay = std::chrono::seconds(60);
    p.jitter = true;
    using namespace std::chrono;

    CHECK(retry_detail::apply_jitter(p, milliseconds(1000), fixed_rng(0)) == milliseconds(500));
    CHECK(retry_detail::apply_jitter(p, milliseconds(1000), fixed_rng(999)) ==
          duration_cast<milliseconds>(duration<double, std::milli>(1000.0 * 1.499)));
    // Midpoint is ~1.0x.
    const auto mid = retry_detail::apply_jitter(p, milliseconds(1000), fixed_rng(500));
    CHECK(mid >= milliseconds(999));
    CHECK(mid <= milliseconds(1001));
}

TEST_CASE("jitter off returns the input delay unchanged", "[retry]") {
    RetryPolicy p;
    p.jitter = false;
    using namespace std::chrono;
    CHECK(retry_detail::apply_jitter(p, milliseconds(750), fixed_rng(0)) == milliseconds(750));
}

// ---------------------------------------------------------------------------
// Retry-After
// ---------------------------------------------------------------------------

TEST_CASE("Retry-After in seconds is honoured", "[retry]") {
    using namespace std::chrono;
    const auto d = retry_detail::parse_retry_after(string_view("120"));
    REQUIRE(d.has_value());
    CHECK(*d == seconds(120));
}

TEST_CASE("Retry-After tolerates surrounding whitespace", "[retry]") {
    using namespace std::chrono;
    const auto d = retry_detail::parse_retry_after(string_view("  7\t"));
    REQUIRE(d.has_value());
    CHECK(*d == seconds(7));
}

TEST_CASE("Retry-After in HTTP-date form is not interpreted", "[retry]") {
    // The library uses a monotonic clock and has no calendar, so a date cannot
    // be converted to a delay without the wall clock. Returning nullopt makes
    // the caller fall back to its own backoff, which is honest.
    CHECK_FALSE(retry_detail::parse_retry_after(
        string_view("Wed, 21 Oct 2015 07:28:00 GMT")).has_value());
}

TEST_CASE("a malformed Retry-After is rejected rather than guessed", "[retry]") {
    CHECK_FALSE(retry_detail::parse_retry_after(string_view("")).has_value());
    CHECK_FALSE(retry_detail::parse_retry_after(string_view("abc")).has_value());
    CHECK_FALSE(retry_detail::parse_retry_after(string_view("-5")).has_value());
    // Overflow guard.
    CHECK_FALSE(retry_detail::parse_retry_after(
        string_view("99999999999999999999999999")).has_value());
}

TEST_CASE("a huge Retry-After is clamped to max_delay", "[retry]") {
    // A broken or hostile server must not park the request for a day.
    RetryPolicy p = basic_policy();
    p.max_delay = std::chrono::seconds(5);
    RetryContext c = get_ctx();
    c.retry_after = std::chrono::seconds(999999);

    const auto d = retry_detail::next_delay(p, c, ErrorCode::ConnectionReset, 0,
                                            fixed_rng(500));
    REQUIRE(d.has_value());
    CHECK(*d == std::chrono::seconds(5));
}

TEST_CASE("Retry-After is used instead of the computed backoff", "[retry]") {
    RetryPolicy p = basic_policy();
    p.base_delay = std::chrono::milliseconds(100);
    p.max_delay = std::chrono::seconds(30);
    RetryContext c = get_ctx();
    c.retry_after = std::chrono::seconds(3);

    const auto d = retry_detail::next_delay(p, c, ErrorCode::ConnectionReset, 0,
                                            fixed_rng(500));
    REQUIRE(d.has_value());
    // Exactly the server's value: no jitter is applied to an explicit hint.
    CHECK(*d == std::chrono::seconds(3));
}

TEST_CASE("without Retry-After the computed backoff is used", "[retry]") {
    RetryPolicy p = basic_policy();
    p.base_delay = std::chrono::milliseconds(200);
    p.max_delay = std::chrono::seconds(30);
    p.jitter = false;

    const auto d = retry_detail::next_delay(p, get_ctx(), ErrorCode::ConnectionReset, 1,
                                            fixed_rng(500));
    REQUIRE(d.has_value());
    CHECK(*d == std::chrono::milliseconds(400));   // 200 * 2^1
}

// ---------------------------------------------------------------------------
// HTTP-date parsing (three formats RFC 7231 requires)
// ---------------------------------------------------------------------------

TEST_CASE("IMF-fixdate parses to the Unix epoch", "[retry][date]") {
    // The reference instant from RFC 7231's own example.
    const auto t = retry_detail::parse_http_date(
        string_view("Sun, 06 Nov 1994 08:49:37 GMT"));
    REQUIRE(t.has_value());
    CHECK(*t == 784111777);
}

TEST_CASE("RFC 850 date parses to the same instant", "[retry][date]") {
    // Same instant, obsolete format: a recipient must accept both.
    const auto t = retry_detail::parse_http_date(
        string_view("Sunday, 06-Nov-94 08:49:37 GMT"));
    REQUIRE(t.has_value());
    CHECK(*t == 784111777);
}

TEST_CASE("asctime date parses to the same instant", "[retry][date]") {
    // asctime right-aligns the day, so this has two spaces before the 6.
    const auto t = retry_detail::parse_http_date(
        string_view("Sun Nov  6 08:49:37 1994"));
    REQUIRE(t.has_value());
    CHECK(*t == 784111777);
}

TEST_CASE("the epoch itself round-trips", "[retry][date]") {
    const auto t = retry_detail::parse_http_date(
        string_view("Thu, 01 Jan 1970 00:00:00 GMT"));
    REQUIRE(t.has_value());
    CHECK(*t == 0);
}

TEST_CASE("a leap day parses correctly", "[retry][date]") {
    // 2024-02-29: catching an off-by-one in the civil-days conversion.
    const auto t = retry_detail::parse_http_date(
        string_view("Thu, 29 Feb 2024 00:00:00 GMT"));
    REQUIRE(t.has_value());
    const auto t_prev = retry_detail::parse_http_date(
        string_view("Wed, 28 Feb 2024 00:00:00 GMT"));
    REQUIRE(t_prev.has_value());
    CHECK(*t - *t_prev == 86400);
}

TEST_CASE("a date in a non-GMT zone is rejected, not guessed", "[retry][date]") {
    // HTTP-date is always GMT. Accepting a local zone would make the value
    // depend on the sender's timezone, which is not what the header means.
    CHECK_FALSE(retry_detail::parse_http_date(
        string_view("Sun, 06 Nov 1994 08:49:37 PST")).has_value());
}

TEST_CASE("malformed dates are rejected", "[retry][date]") {
    CHECK_FALSE(retry_detail::parse_http_date(string_view("")).has_value());
    CHECK_FALSE(retry_detail::parse_http_date(string_view("not a date")).has_value());
    CHECK_FALSE(retry_detail::parse_http_date(
        string_view("Sun, 06 Xxx 1994 08:49:37 GMT")).has_value());
    CHECK_FALSE(retry_detail::parse_http_date(
        string_view("Sun, 06 Nov 1994 08:49 GMT")).has_value());   // no seconds
    CHECK_FALSE(retry_detail::parse_http_date(
        string_view("Sun, 06 Nov 1994 08:49:37 GMT extra")).has_value());
}

// ---------------------------------------------------------------------------
// Retry-After, date form, resolved against the response's own Date
// ---------------------------------------------------------------------------

TEST_CASE("a date-form Retry-After becomes a delay against the server Date",
          "[retry][retry_after]") {
    using namespace std::chrono;
    // Retry-After is 30 s after Date -> 30 s delay, with no clock of ours
    // involved anywhere.
    const auto d = retry_detail::parse_retry_after(
        string_view("Sun, 06 Nov 1994 08:50:07 GMT"),
        string_view("Sun, 06 Nov 1994 08:49:37 GMT"));
    REQUIRE(d.has_value());
    CHECK(*d == seconds(30));
}

TEST_CASE("a date-form Retry-After in the past clamps to zero",
          "[retry][retry_after]") {
    using namespace std::chrono;
    // The server already named a time that has passed: retry immediately rather
    // than produce a negative delay.
    const auto d = retry_detail::parse_retry_after(
        string_view("Sun, 06 Nov 1994 08:49:00 GMT"),
        string_view("Sun, 06 Nov 1994 08:49:37 GMT"));
    REQUIRE(d.has_value());
    CHECK(*d == Duration::zero());
}

TEST_CASE("a date-form Retry-After without a Date header is not guessed",
          "[retry][retry_after]") {
    // No reference instant means no delay. Falling back to the computed backoff
    // is honest; inventing one from the local clock would not be.
    CHECK_FALSE(retry_detail::parse_retry_after(
        string_view("Sun, 06 Nov 1994 08:50:07 GMT")).has_value());
}

TEST_CASE("a date-form Retry-After with an unparseable Date is not guessed",
          "[retry][retry_after]") {
    CHECK_FALSE(retry_detail::parse_retry_after(
        string_view("Sun, 06 Nov 1994 08:50:07 GMT"),
        string_view("garbage")).has_value());
}

TEST_CASE("delay-seconds keeps working alongside the date form",
          "[retry][retry_after]") {
    using namespace std::chrono;
    // The seconds form needs no reference instant at all.
    const auto d = retry_detail::parse_retry_after(string_view("90"));
    REQUIRE(d.has_value());
    CHECK(*d == seconds(90));
}

// ---------------------------------------------------------------------------
// Retryable statuses
// ---------------------------------------------------------------------------

TEST_CASE("only the come-back-later statuses are retryable", "[retry]") {
    using retry_detail::is_retryable_status;
    CHECK(is_retryable_status(429));
    CHECK(is_retryable_status(502));
    CHECK(is_retryable_status(503));
    CHECK(is_retryable_status(504));

    // 500 is a deterministic server bug: retrying just costs another failure.
    CHECK_FALSE(is_retryable_status(500));
    CHECK_FALSE(is_retryable_status(501));
    CHECK_FALSE(is_retryable_status(404));
    CHECK_FALSE(is_retryable_status(400));
    CHECK_FALSE(is_retryable_status(200));
    CHECK_FALSE(is_retryable_status(301));
}

TEST_CASE("a 503 is retried", "[retry]") {
    RetryContext c = get_ctx();
    c.status = 503;
    c.response_started = true;
    CHECK(retries(basic_policy(), c, ErrorCode::HttpInvalidResponse));
}

TEST_CASE("a 500 is not retried", "[retry]") {
    RetryContext c = get_ctx();
    c.status = 500;
    c.response_started = true;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::HttpInvalidResponse));
}

TEST_CASE("retry_on_status = false disables status-based retrying", "[retry]") {
    RetryPolicy p = basic_policy();
    p.retry_on_status = false;
    RetryContext c = get_ctx();
    c.status = 503;
    c.response_started = true;
    CHECK_FALSE(retries(p, c, ErrorCode::HttpInvalidResponse));
    // The transport path still works.
    CHECK(retries(p, get_ctx(), ErrorCode::ConnectFailed));
}

TEST_CASE("a truncated head is still not retried", "[retry]") {
    // response_started with status == 0 means the head was truncated: the server
    // began answering, so it may already have acted on the request.
    RetryContext c = get_ctx();
    c.status = 0;
    c.response_started = true;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::ConnectionReset));
}

TEST_CASE("a retryable status does not override the method rule", "[retry]") {
    // A 503 on a POST may still have been acted on. The method rule is not
    // weakened by the status being retryable.
    RetryContext c;
    c.method = Method::Post;
    c.body_replayable = true;
    c.status = 503;
    c.response_started = true;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::HttpInvalidResponse));

    RetryPolicy p = basic_policy();
    p.retry_non_idempotent = true;
    CHECK(retries(p, c, ErrorCode::HttpInvalidResponse));
}

TEST_CASE("a retryable status does not override the delivered-body rule",
          "[retry]") {
    RetryContext c = get_ctx();
    c.status = 503;
    c.response_started = true;
    c.body_delivered = true;
    CHECK_FALSE(retries(basic_policy(), c, ErrorCode::HttpInvalidResponse));
}

TEST_CASE("Retry-After from a 503 is honoured", "[retry]") {
    using namespace std::chrono;
    RetryPolicy p = basic_policy();
    p.max_delay = seconds(60);
    RetryContext c = get_ctx();
    c.status = 503;
    c.response_started = true;
    c.retry_after = seconds(7);

    const auto d = retry_detail::next_delay(p, c, ErrorCode::HttpInvalidResponse, 0,
                                            fixed_rng(500));
    REQUIRE(d.has_value());
    CHECK(*d == seconds(7));
}
