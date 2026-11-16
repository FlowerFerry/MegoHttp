// Unit tests for the WebSocket protocol layer (task book 12.1, phase 6).
//
// Handshake accept value, extension/subprotocol validation, and the frame codec.
// No socket: every rule here is checkable from bytes, and the framing rules are
// where RFC 6455 actually has teeth.

#include <megohttp/websocket.hpp>
#include <megohttp/string_adapter.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace megohttp;

namespace {

    std::string str(const string& s) { return std::string(s.data(), s.size()); }

    struct Collector : WsFrameDecoder::Callbacks {
        struct Control {
            WsOpcode op;
            std::vector<uint8_t> payload;
        };
        struct Message {
            WsMessageType type;
            std::vector<uint8_t> payload;
            bool compressed;
        };
        std::vector<Control> controls;
        std::vector<Message> messages;

        VoidResult on_control(const WsFrame& f) override {
            controls.push_back({f.opcode, f.payload});
            return VoidResult{};
        }
        VoidResult on_message(WsMessageType t, const byte_buffer& p,
                              bool compressed) override {
            messages.push_back({t, p, compressed});
            return VoidResult{};
        }
    };

    // A server->client frame: never masked.
    std::vector<uint8_t> server_frame(WsOpcode op, const std::string& payload,
                                      bool fin = true, bool rsv1 = false) {
        std::vector<uint8_t> out;
        uint8_t b0 = static_cast<uint8_t>(op);
        if (fin) b0 |= 0x80;
        if (rsv1) b0 |= 0x40;
        out.push_back(b0);
        const size_t n = payload.size();
        if (n < 126) {
            out.push_back(static_cast<uint8_t>(n));
        } else if (n <= 0xFFFF) {
            out.push_back(126);
            out.push_back(static_cast<uint8_t>(n >> 8));
            out.push_back(static_cast<uint8_t>(n));
        } else {
            out.push_back(127);
            for (int i = 7; i >= 0; --i)
                out.push_back(static_cast<uint8_t>(n >> (i * 8)));
        }
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    VoidResult feed(WsFrameDecoder& d, const std::vector<uint8_t>& v) {
        return d.feed(v.data(), v.size());
    }

} // namespace

TEST_CASE("ws accept key matches the RFC 6455 example", "[websocket]") {
    // RFC 6455 1.3 worked example. Any SHA-1 or base64 bug shows up here.
    CHECK(str(ws_detail::accept_key_for("dGhlIHNhbXBsZSBub25jZQ==")) ==
          "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST_CASE("ws client key is 16 random bytes in base64", "[websocket]") {
    const string k1 = ws_detail::make_client_key();
    // 16 bytes -> 24 base64 chars with one '=' pad.
    CHECK(k1.size() == 24);
    CHECK(k1[k1.size() - 1] == '=');

    // Two keys must not collide (random_device, not a fixed table).
    const string k2 = ws_detail::make_client_key();
    CHECK(k1 != k2);
}

TEST_CASE("ws header token matching is case-insensitive and comma-aware", "[websocket]") {
    CHECK(ws_detail::has_token("Upgrade", "upgrade"));
    CHECK(ws_detail::has_token("keep-alive, Upgrade", "Upgrade"));
    CHECK(ws_detail::has_token("Upgrade, keep-alive", "upgrade"));
    CHECK(ws_detail::has_token(" keep-alive , Upgrade ", "UPGRADE"));
    CHECK(!ws_detail::has_token("keep-alive", "upgrade"));
    // A prefix of a longer token must not match.
    CHECK(!ws_detail::has_token("upgraded", "upgrade"));
}

TEST_CASE("ws rejects a subprotocol it never offered", "[websocket]") {
    const std::vector<string> offered = {string("chat"), string("superchat")};
    CHECK(ws_detail::subprotocol_was_offered(offered, "chat"));
    CHECK(ws_detail::subprotocol_was_offered(offered, "CHAT"));
    CHECK(!ws_detail::subprotocol_was_offered(offered, "other"));
}

TEST_CASE("ws rejects an unsolicited extension", "[websocket]") {
    const std::vector<string> requested = {string("permessage-deflate")};
    CHECK(!ws_detail::extensions_unsolicited(requested, ""));
    CHECK(!ws_detail::extensions_unsolicited(
        requested, "permessage-deflate; server_no_context_takeover"));
    CHECK(!ws_detail::extensions_unsolicited(requested,
                                             "permessage-deflate"));
    // A different extension nobody asked for.
    CHECK(ws_detail::extensions_unsolicited(requested, "permessage-bzip2"));
    // Two entries, one of them unsolicited.
    CHECK(ws_detail::extensions_unsolicited(
        requested, "permessage-deflate, permessage-bzip2"));
}

TEST_CASE("ws encodes a small masked frame", "[websocket]") {
    byte_buffer out;
    const std::string payload = "Hello";
    ws_encode_frame(out, WsOpcode::Text,
                    reinterpret_cast<const uint8_t*>(payload.data()),
                    payload.size(), true, false, 0x12345678u);

    REQUIRE(out.size() == 2 + 4 + 5);
    CHECK(out[0] == 0x81);                 // FIN + text
    CHECK(out[1] == (0x80 | 5));           // masked + length 5
    CHECK(out[2] == 0x12);
    CHECK(out[3] == 0x34);
    CHECK(out[4] == 0x56);
    CHECK(out[5] == 0x78);

    // The payload must be XORed with the mask, not copied.
    static const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
    for (size_t i = 0; i < payload.size(); ++i) {
        CHECK(out[6 + i] ==
              static_cast<uint8_t>(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]));
    }
}

TEST_CASE("ws encodes the three length forms", "[websocket]") {
    byte_buffer out;
    const uint32_t mask = 0x01020304u;

    ws_encode_frame(out, WsOpcode::Binary, nullptr, 0, true, false, mask);
    CHECK(out[1] == 0x80);  // masked, 7-bit length 0

    std::vector<uint8_t> small(125, 'a');
    ws_encode_frame(out, WsOpcode::Binary, small.data(), small.size(), true,
                    false, mask);
    CHECK(out[1] == (0x80 | 125));

    std::vector<uint8_t> medium(126, 'a');
    ws_encode_frame(out, WsOpcode::Binary, medium.data(), medium.size(), true,
                    false, mask);
    CHECK(out[1] == (0x80 | 126));
    CHECK(out[2] == 0x00);
    CHECK(out[3] == 126);

    std::vector<uint8_t> large(70000, 'a');
    ws_encode_frame(out, WsOpcode::Binary, large.data(), large.size(), true,
                    false, mask);
    CHECK(out[1] == (0x80 | 127));
    CHECK(out[2] == 0x00);
    CHECK(out[9] == static_cast<uint8_t>(70000 & 0xFF));
}

TEST_CASE("ws decodes a text frame", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    REQUIRE(feed(d, server_frame(WsOpcode::Text, "hello")));
    REQUIRE(col.messages.size() == 1);
    CHECK(col.messages[0].type == WsMessageType::Text);
    CHECK(std::string(col.messages[0].payload.begin(), col.messages[0].payload.end()) ==
          "hello");
}

TEST_CASE("ws decodes binary with an embedded NUL", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    std::string payload("a\0b", 3);
    REQUIRE(feed(d, server_frame(WsOpcode::Binary, payload)));
    REQUIRE(col.messages.size() == 1);
    CHECK(col.messages[0].type == WsMessageType::Binary);
    CHECK(col.messages[0].payload.size() == 3);
    CHECK(col.messages[0].payload[1] == 0);
}

TEST_CASE("ws reassembles a fragmented message", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    std::vector<uint8_t> stream;
    const auto f1 = server_frame(WsOpcode::Text, "frag", false);
    const auto f2 = server_frame(WsOpcode::Continuation, "ment", false);
    const auto f3 = server_frame(WsOpcode::Continuation, "ed", true);
    stream.insert(stream.end(), f1.begin(), f1.end());
    stream.insert(stream.end(), f2.begin(), f2.end());
    stream.insert(stream.end(), f3.begin(), f3.end());

    REQUIRE(feed(d, stream));
    REQUIRE(col.messages.size() == 1);
    CHECK(std::string(col.messages[0].payload.begin(), col.messages[0].payload.end()) ==
          "fragmented");
}

TEST_CASE("ws surfaces a control frame interleaved in a fragmented message", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    std::vector<uint8_t> stream;
    const auto f1 = server_frame(WsOpcode::Text, "part1", false);
    const auto ping = server_frame(WsOpcode::Ping, "p");
    const auto f2 = server_frame(WsOpcode::Continuation, "part2", true);
    stream.insert(stream.end(), f1.begin(), f1.end());
    stream.insert(stream.end(), ping.begin(), ping.end());
    stream.insert(stream.end(), f2.begin(), f2.end());

    REQUIRE(feed(d, stream));
    // The ping must not be swallowed by the open message.
    REQUIRE(col.controls.size() == 1);
    CHECK(col.controls[0].op == WsOpcode::Ping);
    REQUIRE(col.messages.size() == 1);
    CHECK(std::string(col.messages[0].payload.begin(), col.messages[0].payload.end()) ==
          "part1part2");
}

TEST_CASE("ws rejects a masked server frame", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    // Build a frame with the mask bit set: a server must never send one.
    std::vector<uint8_t> f = server_frame(WsOpcode::Text, "x");
    f[1] |= 0x80;

    auto r = feed(d, f);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsProtocolError);
    CHECK(d.is_failed());
}

TEST_CASE("ws rejects a fragmented control frame", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    auto r = feed(d, server_frame(WsOpcode::Ping, "x", /*fin=*/false));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsProtocolError);
}

TEST_CASE("ws rejects an over-long control frame", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    auto r = feed(d, server_frame(WsOpcode::Ping, std::string(126, 'x')));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsProtocolError);
}

TEST_CASE("ws rejects an unknown opcode", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    std::vector<uint8_t> f = {0x83, 0x00};  // FIN + opcode 3 (reserved)
    auto r = feed(d, f);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsProtocolError);
}

TEST_CASE("ws rejects RSV2 and RSV3", "[websocket]") {
    for (uint8_t bit : {0x20, 0x10}) {
        Collector col;
        WsFrameDecoder d(col);
        std::vector<uint8_t> f = server_frame(WsOpcode::Text, "x");
        f[0] |= bit;
        auto r = feed(d, f);
        REQUIRE(!r);
        CHECK(r.error().code() == ErrorCode::WsProtocolError);
    }
}

TEST_CASE("ws rejects a continuation without an open message", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    auto r = feed(d, server_frame(WsOpcode::Continuation, "x"));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsProtocolError);
}

TEST_CASE("ws rejects a new data frame while a message is open", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    std::vector<uint8_t> stream;
    const auto f1 = server_frame(WsOpcode::Text, "a", false);
    const auto f2 = server_frame(WsOpcode::Text, "b", true);
    stream.insert(stream.end(), f1.begin(), f1.end());
    stream.insert(stream.end(), f2.begin(), f2.end());

    auto r = feed(d, stream);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsProtocolError);
}

TEST_CASE("ws rejects invalid UTF-8 in a text message", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    // 0xFF is never a legal UTF-8 byte.
    std::string bad;
    bad.push_back(static_cast<char>(0xFF));
    auto r = feed(d, server_frame(WsOpcode::Text, bad));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsUtf8Invalid);
}

TEST_CASE("ws validates UTF-8 across a fragment boundary", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    // U+00E9 (é) is C3 A9. Split it across two frames: validating each frame
    // alone would falsely reject both halves.
    std::string first;
    first.push_back(static_cast<char>(0xC3));
    std::string second;
    second.push_back(static_cast<char>(0xA9));

    std::vector<uint8_t> stream;
    const auto f1 = server_frame(WsOpcode::Text, first, false);
    const auto f2 = server_frame(WsOpcode::Continuation, second, true);
    stream.insert(stream.end(), f1.begin(), f1.end());
    stream.insert(stream.end(), f2.begin(), f2.end());

    auto r = feed(d, stream);
    REQUIRE(r);
    REQUIRE(col.messages.size() == 1);
    CHECK(col.messages[0].payload.size() == 2);
}

TEST_CASE("ws survives a frame split across feeds", "[websocket]") {
    Collector col;
    WsFrameDecoder d(col);

    const auto f = server_frame(WsOpcode::Text, "split me");
    for (size_t i = 0; i < f.size(); ++i) {
        REQUIRE(d.feed(&f[i], 1));
    }
    REQUIRE(col.messages.size() == 1);
    CHECK(std::string(col.messages[0].payload.begin(), col.messages[0].payload.end()) ==
          "split me");
}

TEST_CASE("ws decodes the 16-bit and 64-bit length forms", "[websocket]") {
    {
        Collector col;
        WsFrameDecoder d(col);
        const std::string payload(300, 'x');
        REQUIRE(feed(d, server_frame(WsOpcode::Binary, payload)));
        REQUIRE(col.messages.size() == 1);
        CHECK(col.messages[0].payload.size() == 300);
    }
    {
        Collector col;
        WsFrameDecoder::Limits lim;
        lim.max_frame_bytes = 100000;
        WsFrameDecoder d(col, lim);
        const std::string payload(70000, 'x');
        REQUIRE(feed(d, server_frame(WsOpcode::Binary, payload)));
        REQUIRE(col.messages.size() == 1);
        CHECK(col.messages[0].payload.size() == 70000);
    }
}

TEST_CASE("ws enforces max_frame_bytes", "[websocket]") {
    Collector col;
    WsFrameDecoder::Limits lim;
    lim.max_frame_bytes = 8;
    WsFrameDecoder d(col, lim);

    auto r = feed(d, server_frame(WsOpcode::Binary, std::string(100, 'x')));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsFrameTooLarge);
}

TEST_CASE("ws enforces max_message_bytes across fragments", "[websocket]") {
    Collector col;
    WsFrameDecoder::Limits lim;
    lim.max_message_bytes = 8;
    WsFrameDecoder d(col, lim);

    std::vector<uint8_t> stream;
    const auto f1 = server_frame(WsOpcode::Binary, std::string(6, 'x'), false);
    const auto f2 = server_frame(WsOpcode::Continuation, std::string(6, 'x'), true);
    stream.insert(stream.end(), f1.begin(), f1.end());
    stream.insert(stream.end(), f2.begin(), f2.end());

    auto r = feed(d, stream);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::WsMessageTooLarge);
}

TEST_CASE("ws utf8 validator rejects overlong and surrogate forms", "[websocket]") {
    // Overlong 2-byte encoding of '/' (0x2F).
    const uint8_t overlong2[] = {0xC0, 0xAF};
    CHECK(!ws_is_valid_utf8(overlong2, sizeof overlong2));

    // Overlong 3-byte encoding.
    const uint8_t overlong3[] = {0xE0, 0x80, 0xAF};
    CHECK(!ws_is_valid_utf8(overlong3, sizeof overlong3));

    // UTF-16 surrogate U+D800.
    const uint8_t surrogate[] = {0xED, 0xA0, 0x80};
    CHECK(!ws_is_valid_utf8(surrogate, sizeof surrogate));

    // Above U+10FFFF.
    const uint8_t too_high[] = {0xF4, 0x90, 0x80, 0x80};
    CHECK(!ws_is_valid_utf8(too_high, sizeof too_high));

    // Legal maximum: U+10FFFF.
    const uint8_t max_cp[] = {0xF4, 0x8F, 0xBF, 0xBF};
    CHECK(ws_is_valid_utf8(max_cp, sizeof max_cp));

    // Plain ASCII and a 3-byte form.
    const uint8_t mixed[] = {'a', 0xE2, 0x82, 0xAC, 'b'};
    CHECK(ws_is_valid_utf8(mixed, sizeof mixed));
}

TEST_CASE("ws utf8 incomplete tail reports the partial sequence", "[websocket]") {
    // A lone lead byte of a 2-byte sequence.
    const uint8_t one[] = {0xC3};
    CHECK(ws_utf8_incomplete_tail(one, sizeof one) == 1);

    // Lead plus one continuation byte of a 3-byte sequence.
    const uint8_t two[] = {0xE2, 0x82};
    CHECK(ws_utf8_incomplete_tail(two, sizeof two) == 2);

    // A complete sequence has no incomplete tail.
    const uint8_t done[] = {0xE2, 0x82, 0xAC};
    CHECK(ws_utf8_incomplete_tail(done, sizeof done) == 0);

    // Plain ASCII has none either.
    const uint8_t ascii[] = {'a', 'b'};
    CHECK(ws_utf8_incomplete_tail(ascii, sizeof ascii) == 0);
}
