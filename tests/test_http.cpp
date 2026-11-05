// ResponseParser tests: framing, chunked, trailers, 1xx, limits, byte-splitting.
#include <catch2/catch_all.hpp>

#include <megohttp/http.hpp>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace megohttp;


// Collects everything the parser reports.
struct Collector : ResponseParser::Callbacks {
    bool got_head{false};
    ParsedResponse head;
    std::string body;
    Headers trailers;
    bool got_trailers{false};
    int complete_count{0};
    int body_calls{0};

    VoidResult on_head(const ParsedResponse& h) override {
        got_head = true; head = h; return VoidResult{};
    }
    VoidResult on_body_data(const uint8_t* d, size_t n) override {
        ++body_calls;
        body.append(reinterpret_cast<const char*>(d), n);
        return VoidResult{};
    }
    VoidResult on_trailers(const Headers& t) override {
        got_trailers = true; trailers = t; return VoidResult{};
    }
    VoidResult on_complete() override { ++complete_count; return VoidResult{}; }
};

// Feeds `raw` in chunks of `step` bytes (step==0 means one shot).
static VoidResult feed_split(ResponseParser& p, const std::string& raw, size_t step) {
    if (step == 0) {
        return p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    }
    size_t i = 0;
    while (i < raw.size()) {
        const size_t n = std::min(step, raw.size() - i);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data() + i), n);
        if (!r) return r;
        i += n;
    }
    return VoidResult{};
}

static const std::string RESP_CL =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 11\r\n"
    "\r\n"
    "hello world";

static const std::string RESP_CHUNKED =
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5\r\nhello\r\n"
    "6\r\n world\r\n"
    "0\r\n"
    "\r\n";

static const std::string RESP_CHUNKED_TRAILER =
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Trailer: X-Sum\r\n"
    "\r\n"
    "5\r\nhello\r\n"
    "0\r\n"
    "X-Sum: 42\r\n"
    "\r\n";

TEST_CASE("content length", "[http]") {
    // Whole message in one feed
    {
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(RESP_CL.data()), RESP_CL.size());
        CHECK(r.has_value());
        CHECK(c.got_head);
        CHECK(c.head.status_code == 200);
        CHECK(c.head.framing == ParsedResponse::BodyFraming::ContentLength);
        CHECK(c.head.content_length == 11);
        CHECK(c.body == "hello world");
        CHECK(c.complete_count == 1);
        CHECK(p.is_complete());
        CHECK(!c.head.connection_close);
        CHECK(c.head.keep_alive);
    }
    // Every possible split point must produce the same result
    for (size_t step = 1; step <= RESP_CL.size(); ++step) {
        Collector c; ResponseParser p(c);
        auto r = feed_split(p, RESP_CL, step);
        const bool ok = r.has_value() && c.body == "hello world" && c.complete_count == 1
                        && c.head.content_length == 11;
        if (!ok) {
            std::printf("FAIL split step=%zu body=[%s] complete=%d\n",
                        step, c.body.c_str(), c.complete_count);
        }
        CHECK(ok);
    }
}

TEST_CASE("chunked", "[http]") {
    {
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(RESP_CHUNKED.data()),
                        RESP_CHUNKED.size());
        CHECK(r.has_value());
        CHECK(c.head.framing == ParsedResponse::BodyFraming::Chunked);
        CHECK(c.body == "hello world");
        CHECK(c.complete_count == 1);
        CHECK(!c.got_trailers);
    }
    for (size_t step = 1; step <= RESP_CHUNKED.size(); ++step) {
        Collector c; ResponseParser p(c);
        auto r = feed_split(p, RESP_CHUNKED, step);
        const bool ok = r.has_value() && c.body == "hello world" && c.complete_count == 1;
        if (!ok) {
            std::printf("FAIL chunked split step=%zu body=[%s] complete=%d err=%s\n",
                        step, c.body.c_str(), c.complete_count,
                        r.has_error() ? to_string(r.error().code()) : "-");
        }
        CHECK(ok);
    }
}

TEST_CASE("trailers", "[http]") {
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(RESP_CHUNKED_TRAILER.data()),
                    RESP_CHUNKED_TRAILER.size());
    CHECK(r.has_value());
    CHECK(c.body == "hello");
    CHECK(c.got_trailers);
    auto v = c.trailers.get("x-sum");
    CHECK(v.has_value());
    // Trailers must NOT be merged into the head headers.
    CHECK(!c.head.headers.contains("X-Sum"));
    CHECK(c.complete_count == 1);
}

TEST_CASE("no body semantics", "[http]") {
    // 204 must not have a body even with Content-Length present
    {
        const std::string raw =
            "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_value());
        CHECK(c.head.framing == ParsedResponse::BodyFraming::None);
        CHECK(c.body.empty());
        CHECK(c.complete_count == 1);
    }
    // 304 same
    {
        const std::string raw =
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_value());
        CHECK(c.head.framing == ParsedResponse::BodyFraming::None);
        CHECK(c.complete_count == 1);
    }
    // HEAD response: Content-Length describes what a GET would return, no body sent
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        Collector c; ResponseParser p(c);
        p.set_request_method(Method::Head);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_value());
        CHECK(c.head.framing == ParsedResponse::BodyFraming::None);
        CHECK(c.body.empty());
        CHECK(c.complete_count == 1);
    }
}

TEST_CASE("informational", "[http]") {
    const std::string raw =
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    CHECK(r.has_value());
    CHECK(c.got_head);
    CHECK(c.head.status_code == 200);
    CHECK(c.head.informational.size() == 1);
    CHECK(c.head.informational[0] == 100);
    CHECK(c.body == "ok");
    CHECK(c.complete_count == 1);
}

TEST_CASE("until close", "[http]") {
    // No CL, no chunked -> body runs to EOF
    const std::string raw = "HTTP/1.1 200 OK\r\n\r\nstreamed until close";
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    CHECK(r.has_value());
    CHECK(c.head.framing == ParsedResponse::BodyFraming::UntilClose);
    CHECK(c.head.connection_close);
    CHECK(c.complete_count == 0);   // not complete until EOF
    auto e = p.feed_eof();
    CHECK(e.has_value());
    CHECK(c.body == "streamed until close");
    CHECK(c.complete_count == 1);
}

TEST_CASE("ambiguous framing", "[http]") {
    // Both TE and CL: smuggling signal, must reject
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpAmbiguousFraming);
    }
    // Conflicting duplicate Content-Length
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpAmbiguousFraming);
    }
    // Identical duplicate Content-Length is legal
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_value());
        CHECK(c.body == "hello");
    }
    // TE that does not end with chunked
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpAmbiguousFraming);
    }
    // chunked listed twice
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
    }
}

TEST_CASE("content length overflow", "[http]") {
    const std::string raw =
        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n";
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    CHECK(r.has_error());
    if (r) return;
    CHECK(r.error().code() == ErrorCode::HttpInvalidResponse);
}

TEST_CASE("chunk size overflow", "[http]") {
    const std::string raw =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "FFFFFFFFFFFFFFFFF\r\nx\r\n";
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    CHECK(r.has_error());
    if (r) return;
    CHECK(r.error().code() == ErrorCode::HttpChunkError);
}

TEST_CASE("bad chunk terminator", "[http]") {
    // chunk data not followed by CRLF
    const std::string raw =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhelloXX0\r\n\r\n";
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    CHECK(r.has_error());
    if (r) return;
    CHECK(r.error().code() == ErrorCode::HttpChunkError);
}

TEST_CASE("limits", "[http]") {
    // header block too large
    {
        ParserLimits lim; lim.max_header_bytes = 100;
        std::string raw = "HTTP/1.1 200 OK\r\n";
        raw += "X-Big: ";
        raw.append(200, 'a');
        raw += "\r\n\r\n";
        Collector c; ResponseParser p(c, lim);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpHeaderTooLarge);
    }
    // too many headers
    {
        ParserLimits lim; lim.max_header_count = 2;
        std::string raw = "HTTP/1.1 200 OK\r\n";
        for (int i = 0; i < 5; ++i) { raw += "X-A: 1\r\n"; }
        raw += "\r\n";
        Collector c; ResponseParser p(c, lim);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpHeaderCountExceeded);
    }
    // body larger than allowed
    {
        ParserLimits lim; lim.max_body_bytes = 4;
        const std::string raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        Collector c; ResponseParser p(c, lim);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpBodyTooLarge);
    }
}

TEST_CASE("malformed head", "[http]") {
    // Not HTTP
    {
        const std::string raw = "FOO/1.1 200 OK\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
    }
    // Bad status code digits
    {
        const std::string raw = "HTTP/1.1 2x0 OK\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
    }
    // Header with no colon
    {
        const std::string raw = "HTTP/1.1 200 OK\r\nNoColonHere\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpInvalidResponse);
    }
    // Obs-fold must be rejected
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nX-A: 1\r\n  continued\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
        if (r) return;
        CHECK(r.error().code() == ErrorCode::HttpProtocolViolation);
    }
    // Space before the colon in a header name (smuggling vector)
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nX-A : 1\r\n\r\n";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_error());
    }
}

TEST_CASE("leftover", "[http]") {
    // Two responses in one buffer: the parser must report the second as leftover.
    const std::string raw = RESP_CL + RESP_CL;
    Collector c; ResponseParser p(c);
    auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    CHECK(r.has_value());
    CHECK(c.complete_count == 1);
    CHECK(c.head.content_length == 11);
    // The second head is not consumed; leftover_offset is where it starts.
    CHECK(p.leftover_offset() > 0);
    CHECK(p.leftover_offset() <= raw.size());
}

TEST_CASE("eof errors", "[http]") {
    // EOF in the middle of the head
    {
        const std::string raw = "HTTP/1.1 200 OK\r\nContent-Le";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_value());
        auto e = p.feed_eof();
        CHECK(e.has_error());
    }
    // EOF before Content-Length satisfied
    {
        const std::string raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        Collector c; ResponseParser p(c);
        auto r = p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        CHECK(r.has_value());
        auto e = p.feed_eof();
        CHECK(e.has_error());
        if (!e) CHECK(e.error().code() == ErrorCode::HttpProtocolViolation);
    }
}

TEST_CASE("request encoding", "[http]") {
    Headers h;
    h.add("Host", "example.com");
    h.add("Accept", "*/*");
    auto r = encode_request_head(Method::Get, {}, "/path?q=1", h);
    CHECK(r.has_value());
    if (!r) return;
    const std::string got(r->data(), r->size());
    CHECK(got == "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n");

    // Custom method
    auto r2 = encode_request_head(Method::Custom, "PURGE", "/x", h);
    CHECK(r2.has_value());
    const std::string got2(r2->data(), r2->size());
    CHECK(got2.find("PURGE /x HTTP/1.1") == 0);

    // CRLF injection in a header value must be rejected
    Headers evil;
    evil.add("Host", "a\r\nX-Injected: 1");
    CHECK(encode_request_head(Method::Get, {}, "/", evil).has_error());

    // CRLF injection in the target must be rejected
    CHECK(encode_request_head(Method::Get, {}, "/a\r\nX: 1", h).has_error());
}

TEST_CASE("chunk encode", "[http]") {
    const char* payload = "hello";
    auto c = chunked::encode_chunk(reinterpret_cast<const uint8_t*>(payload), 5);
    const std::string got(c.data(), c.size());
    CHECK(got == "5\r\nhello\r\n");

    auto last = chunked::encode_last_chunk(nullptr);
    const std::string got2(last.data(), last.size());
    CHECK(got2 == "0\r\n\r\n");

    Headers tr; tr.add("X-Sum", "42");
    auto last2 = chunked::encode_last_chunk(&tr);
    const std::string got3(last2.data(), last2.size());
    CHECK(got3 == "0\r\nX-Sum: 42\r\n\r\n");

    // parse_chunk_size
    auto s1 = chunked::parse_chunk_size("1a");
    CHECK((s1.has_value() && s1.value() == 26));
    auto s2 = chunked::parse_chunk_size("FF");
    CHECK((s2.has_value() && s2.value() == 255));
    auto s3 = chunked::parse_chunk_size("5;ext=1");
    CHECK((s3.has_value() && s3.value() == 5));
    CHECK(chunked::parse_chunk_size("").has_error());
    CHECK(chunked::parse_chunk_size("zz").has_error());
    CHECK(chunked::parse_chunk_size("5\r").has_error());
}

TEST_CASE("token helpers", "[http]") {
    CHECK(http_detail::header_has_token("keep-alive, Upgrade", "upgrade"));
    CHECK(http_detail::header_has_token("Upgrade", "UPGRADE"));
    CHECK(http_detail::header_has_token("a , b ,close", "close"));
    CHECK(!http_detail::header_has_token("keep-alive", "close"));
    CHECK(!http_detail::header_has_token("", "close"));

    auto parts = http_detail::split_list("gzip, br ,  identity");
    CHECK(parts.size() == 3);

    auto t = http_detail::trim_ows("  x  ");
    CHECK((detail::to_size(t) == 1 && t.data()[0] == 'x'));

    CHECK(!http_detail::status_reason(200).empty());
    CHECK(http_detail::status_reason(299).empty());   // never invent a phrase
}
