// Unit tests for the SSE parser (task book 11, phase 6).
//
// Parser only: no socket, no Client. The parser is the piece with real protocol
// rules (line endings, field rules, budget), and it is the piece that the
// Client-level tests would otherwise never exercise directly.

#include <megohttp/sse.hpp>
#include <megohttp/string_adapter.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace megohttp;

namespace {

    struct Recorder : SseParser::Callbacks {
        std::vector<SseEvent> events;
        std::vector<std::string> comments;
        bool paused = false;

        VoidResult on_event(const SseEvent& e) override {
            events.push_back(e);
            return VoidResult{};
        }
        void on_comment(string_view c) override {
            comments.emplace_back(c.data(), c.size());
        }
    };

    std::string str(const string& s) { return std::string(s.data(), s.size()); }

    // Feed a whole buffer through the parser, reporting the first error.
    VoidResult feed_all(SseParser& p, const std::string& s) {
        return p.feed(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    // Feed one byte at a time, which is the split that exposes every
    // straddling-CRLF and straddling-field bug.
    VoidResult feed_byte_by_byte(SseParser& p, const std::string& s) {
        for (char c : s) {
            auto r = p.feed(reinterpret_cast<const uint8_t*>(&c), 1);
            if (!r) return r;
        }
        return VoidResult{};
    }

} // namespace

TEST_CASE("sse parses a simple event", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "data: hello\n\n"));

    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "hello");
    CHECK(str(rec.events[0].event_type) == "message");
    CHECK(!rec.events[0].id.has_value());
    CHECK(!rec.events[0].retry_ms.has_value());
}

TEST_CASE("sse strips exactly one space after the colon", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "data:  two spaces\n\n"));
    REQUIRE(rec.events.size() == 1);
    // One space stripped, the second belongs to the value.
    CHECK(str(rec.events[0].data) == " two spaces");
}

TEST_CASE("sse joins multiple data lines with newline", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "data: a\ndata: b\ndata: c\n\n"));
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "a\nb\nc");
}

TEST_CASE("sse keeps an empty data line as a blank line in the payload", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "data: a\ndata:\ndata: b\n\n"));
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "a\n\nb");
}

TEST_CASE("sse honours the event field", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "event: ping\ndata: x\n\n"));
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].event_type) == "ping");
}

TEST_CASE("sse accepts LF, CRLF and CR line endings", "[sse]") {
    for (const char* sep : {"\n", "\r\n", "\r"}) {
        Recorder rec;
        SseParser p(rec);
        std::string body;
        body += "data: hello";
        body += sep;
        body += sep;
        REQUIRE(feed_all(p, body));
        INFO("separator is " << (sep[0] == '\r' ? "CR-ish" : "LF"));
        CHECK(rec.events.size() == 1);
        if (!rec.events.empty()) CHECK(str(rec.events[0].data) == "hello");
    }
}

TEST_CASE("sse survives a CRLF split across two feeds", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    // The CR ends write 1, the LF opens write 2: a parser that treats CR as a
    // full line ending here would dispatch an extra empty event.
    REQUIRE(feed_all(p, "data: hello\r"));
    REQUIRE(rec.events.empty());

    REQUIRE(feed_all(p, "\n\r\n"));
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "hello");
}

TEST_CASE("sse ignores comments", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, ":keepalive\ndata: x\n\n"));
    REQUIRE(rec.comments.size() == 1);
    CHECK(rec.comments[0] == "keepalive");
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "x");
}

TEST_CASE("sse ignores an unknown field", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "bogus: whatever\ndata: x\n\n"));
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "x");
}

TEST_CASE("sse tracks the id and reports it on dispatch", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "id: 42\ndata: first\n\n"));
    REQUIRE(rec.events.size() == 1);
    REQUIRE(rec.events[0].id.has_value());
    CHECK(str(*rec.events[0].id) == "42");
    CHECK(str(rec.events[0].last_event_id_at_dispatch) == "42");

    // An event with no id field inherits the previous id.
    REQUIRE(feed_all(p, "data: second\n\n"));
    REQUIRE(rec.events.size() == 2);
    CHECK(!rec.events[1].id.has_value());
    CHECK(str(rec.events[1].last_event_id_at_dispatch) == "42");
    CHECK(str(p.last_event_id()) == "42");
}

TEST_CASE("sse ignores an id field containing NUL", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    std::string body = "id: 7\ndata: first\n\n";
    REQUIRE(feed_all(p, body));

    // An id with an embedded NUL must be dropped entirely, leaving id 7 in force.
    std::string with_nul = "id: 8";
    with_nul.push_back('\0');
    with_nul += "9\ndata: second\n\n";
    REQUIRE(feed_all(p, with_nul));

    REQUIRE(rec.events.size() == 2);
    CHECK(!rec.events[1].id.has_value());
    CHECK(str(rec.events[1].last_event_id_at_dispatch) == "7");
}

TEST_CASE("sse parses the retry field", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "retry: 2500\ndata: x\n\n"));
    REQUIRE(rec.events.size() == 1);
    REQUIRE(rec.events[0].retry_ms.has_value());
    CHECK(*rec.events[0].retry_ms == 2500);
}

TEST_CASE("sse rejects a non-numeric retry without failing the stream", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "retry: soon\ndata: x\n\n"));
    REQUIRE(rec.events.size() == 1);
    CHECK(!rec.events[0].retry_ms.has_value());
    CHECK(!p.is_failed());
}

TEST_CASE("sse skips a UTF-8 BOM at the start only", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    std::string body = "\xEF\xBB\xBF";
    body += "data: hello\n\n";
    REQUIRE(feed_all(p, body));
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "hello");
}

TEST_CASE("sse does not dispatch a partial trailing event at EOF", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    // No blank line: WHATWG says this event is never dispatched.
    REQUIRE(feed_all(p, "data: incomplete\n"));
    REQUIRE(rec.events.empty());

    REQUIRE(p.feed_eof());
    CHECK(rec.events.empty());
}

TEST_CASE("sse dispatches the event that a trailing blank line completes", "[sse]") {
    Recorder rec;
    SseParser p(rec);

    REQUIRE(feed_all(p, "data: last\n\n"));
    REQUIRE(p.feed_eof());
    REQUIRE(rec.events.size() == 1);
    CHECK(str(rec.events[0].data) == "last");
}

TEST_CASE("sse produces the same events one byte at a time", "[sse]") {
    // Every field name, value and line ending straddles a feed boundary here.
    const std::string body =
        ":comment\r\nevent: update\r\nid: 9\r\ndata: line one\r\n"
        "data: line two\r\nretry: 1000\r\n\r\n"
        "data: second\n\n";

    Recorder whole;
    SseParser p1(whole);
    REQUIRE(feed_all(p1, body));

    Recorder split;
    SseParser p2(split);
    REQUIRE(feed_byte_by_byte(p2, body));

    REQUIRE(whole.events.size() == 2);
    REQUIRE(split.events.size() == whole.events.size());

    for (size_t i = 0; i < whole.events.size(); ++i) {
        CHECK(str(split.events[i].data) == str(whole.events[i].data));
        CHECK(str(split.events[i].event_type) == str(whole.events[i].event_type));
        CHECK(str(split.events[i].last_event_id_at_dispatch) ==
              str(whole.events[i].last_event_id_at_dispatch));
        CHECK(split.events[i].retry_ms == whole.events[i].retry_ms);
    }
    CHECK(split.comments == whole.comments);
}

TEST_CASE("sse rejects an over-long line", "[sse]") {
    Recorder rec;
    SseParser::Limits lim;
    lim.max_line_length = 16;
    SseParser p(rec, lim);

    const std::string body = "data: " + std::string(100, 'x') + "\n\n";
    auto r = feed_all(p, body);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::SseLineTooLong);
    CHECK(p.is_failed());
}

TEST_CASE("sse rejects an over-large event", "[sse]") {
    Recorder rec;
    SseParser::Limits lim;
    lim.max_event_bytes = 32;
    SseParser p(rec, lim);

    std::string body;
    for (int i = 0; i < 10; ++i) body += "data: 0123456789\n";
    body += "\n";

    auto r = feed_all(p, body);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::SseEventTooLarge);
    CHECK(p.is_failed());
}
