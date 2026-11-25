#include <catch2/catch_test_macros.hpp>
#include <megohttp/websocket_deflate.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/headers.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace megohttp;

TEST_CASE("WebSocket deflate: parse offer", "[websocket][deflate]") {
    SECTION("no extension header") {
        Headers h;
        auto result = parse_deflate_offer(h);
        REQUIRE(!result.has_value());
    }

    SECTION("simple offer") {
        Headers h;
        h.set("Sec-WebSocket-Extensions", "permessage-deflate");
        auto result = parse_deflate_offer(h);
        REQUIRE(result.has_value());
        REQUIRE(result->enabled);
        REQUIRE(result->server_max_window_bits == 15);
        REQUIRE(result->client_max_window_bits == 15);
        REQUIRE(!result->server_no_context_takeover);
        REQUIRE(!result->client_no_context_takeover);
    }

    SECTION("offer with parameters") {
        Headers h;
        h.set("Sec-WebSocket-Extensions",
              "permessage-deflate; server_max_window_bits=12; client_max_window_bits=10; "
              "server_no_context_takeover; client_no_context_takeover");
        auto result = parse_deflate_offer(h);
        REQUIRE(result.has_value());
        REQUIRE(result->enabled);
        REQUIRE(result->server_max_window_bits == 12);
        REQUIRE(result->client_max_window_bits == 10);
        REQUIRE(result->server_no_context_takeover);
        REQUIRE(result->client_no_context_takeover);
    }

    SECTION("offer with other extensions") {
        Headers h;
        h.set("Sec-WebSocket-Extensions",
              "some-other-extension, permessage-deflate; server_max_window_bits=11");
        auto result = parse_deflate_offer(h);
        REQUIRE(result.has_value());
        REQUIRE(result->enabled);
        REQUIRE(result->server_max_window_bits == 11);
    }
}

TEST_CASE("WebSocket deflate: build response", "[websocket][deflate]") {
    SECTION("disabled") {
        DeflateNegotiated params;
        params.enabled = false;
        auto result = build_deflate_response(params);
        REQUIRE(result.empty());
    }

    SECTION("default parameters") {
        DeflateNegotiated params;
        params.enabled = true;
        auto result = build_deflate_response(params);
        REQUIRE(result == "permessage-deflate");
    }

    SECTION("custom window bits") {
        DeflateNegotiated params;
        params.enabled = true;
        params.server_window_bits = 12;
        params.client_window_bits = 10;
        auto result = build_deflate_response(params);
        REQUIRE(result == "permessage-deflate; server_max_window_bits=12; client_max_window_bits=10");
    }

    SECTION("no context takeover") {
        DeflateNegotiated params;
        params.enabled = true;
        params.server_no_context_takeover = true;
        params.client_no_context_takeover = true;
        auto result = build_deflate_response(params);
        REQUIRE(result == "permessage-deflate; server_no_context_takeover; client_no_context_takeover");
    }
}

TEST_CASE("WebSocket deflate: compress and decompress", "[websocket][deflate]") {
    DeflateNegotiated params;
    params.enabled = true;
    params.server_window_bits = 15;
    params.client_window_bits = 15;
    params.server_no_context_takeover = false;
    params.client_no_context_takeover = false;

    DeflateCompressor compressor(params);
    DeflateDecompressor decompressor(params);

    SECTION("simple text") {
        std::string text = "Hello, WebSocket compression!";
        std::vector<uint8_t> input(text.begin(), text.end());

        auto compressed = compressor.compress(input);
        REQUIRE(!compressed.empty());

        auto decompressed = decompressor.decompress(compressed, 16 * 1024 * 1024);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }

    SECTION("empty message") {
        std::vector<uint8_t> input;
        auto compressed = compressor.compress(input);
        auto decompressed = decompressor.decompress(compressed, 16 * 1024 * 1024);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }

    SECTION("large message") {
        std::string text(10000, 'A');
        std::vector<uint8_t> input(text.begin(), text.end());

        auto compressed = compressor.compress(input);
        REQUIRE(compressed.size() < input.size()); // Should compress well

        auto decompressed = decompressor.decompress(compressed, 16 * 1024 * 1024);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }

    SECTION("binary data") {
        std::vector<uint8_t> input;
        for (int i = 0; i < 1000; ++i) {
            input.push_back(static_cast<uint8_t>(i % 256));
        }

        auto compressed = compressor.compress(input);
        auto decompressed = decompressor.decompress(compressed, 16 * 1024 * 1024);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }
}

TEST_CASE("WebSocket deflate: no context takeover", "[websocket][deflate]") {
    DeflateNegotiated params;
    params.enabled = true;
    params.server_window_bits = 15;
    params.client_window_bits = 15;
    params.server_no_context_takeover = true;
    params.client_no_context_takeover = true;

    DeflateCompressor compressor(params);
    DeflateDecompressor decompressor(params);

    std::string text1 = "First message";
    std::string text2 = "Second message";
    std::vector<uint8_t> input1(text1.begin(), text1.end());
    std::vector<uint8_t> input2(text2.begin(), text2.end());

    // Compress and decompress first message
    auto compressed1 = compressor.compress(input1);
    auto decompressed1 = decompressor.decompress(compressed1, 16 * 1024 * 1024);
    REQUIRE(decompressed1.has_value());
    REQUIRE(*decompressed1 == input1);

    // Compress and decompress second message (context should be reset)
    auto compressed2 = compressor.compress(input2);
    auto decompressed2 = decompressor.decompress(compressed2, 16 * 1024 * 1024);
    REQUIRE(decompressed2.has_value());
    REQUIRE(*decompressed2 == input2);
}

TEST_CASE("WebSocket deflate: context preservation", "[websocket][deflate]") {
    DeflateNegotiated params;
    params.enabled = true;
    params.server_window_bits = 15;
    params.client_window_bits = 15;
    params.server_no_context_takeover = false;
    params.client_no_context_takeover = false;

    DeflateCompressor compressor(params);
    DeflateDecompressor decompressor(params);

    // Send similar messages - should compress better with context
    std::string text1 = "Hello, World! This is a test message.";
    std::string text2 = "Hello, World! This is another test message.";
    std::vector<uint8_t> input1(text1.begin(), text1.end());
    std::vector<uint8_t> input2(text2.begin(), text2.end());

    auto compressed1 = compressor.compress(input1);
    auto compressed2 = compressor.compress(input2);

    // Second message should be smaller due to shared context
    REQUIRE(compressed2.size() < compressed1.size());

    // Both should decompress correctly
    auto decompressed1 = decompressor.decompress(compressed1, 16 * 1024 * 1024);
    auto decompressed2 = decompressor.decompress(compressed2, 16 * 1024 * 1024);
    REQUIRE(decompressed1.has_value());
    REQUIRE(decompressed2.has_value());
    REQUIRE(*decompressed1 == input1);
    REQUIRE(*decompressed2 == input2);
}

TEST_CASE("deflate decompressor enforces output limit (bomb protection)", "[websocket][deflate]") {
    DeflateNegotiated params;
    params.enabled = true;
    DeflateCompressor compressor(params);

    // Create 10KB of highly compressible data (all zeros)
    std::vector<uint8_t> input(10000, 0);
    auto compressed = compressor.compress(input);
    REQUIRE(compressed.size() < input.size());

    SECTION("a tiny output cap fails instead of materialising the message") {
        DeflateDecompressor decompressor(params);
        auto r = decompressor.decompress(compressed, 10);
        REQUIRE(!r);
        REQUIRE(r.error().code() == ErrorCode::WsCompressionResourceExceeded);
    }

    SECTION("a generous cap decompresses normally") {
        // A fresh decompressor: the capped attempt above drove the zlib stream
        // part-way, and context takeover means that state belongs to that
        // attempt, not to this one.
        DeflateDecompressor decompressor(params);
        auto r = decompressor.decompress(compressed, 16 * 1024 * 1024);
        REQUIRE(r.has_value());
        REQUIRE(r.value() == input);
    }
}

TEST_CASE("deflate streaming decompression delivers chunks as they are produced",
          "[websocket][deflate]") {
    // D10: the streaming path exists so a caller can validate and limit while
    // inflating. It must deliver exactly the same bytes as the buffered path,
    // split into one or more chunks and never a trailing empty one.
    DeflateNegotiated params;
    params.enabled = true;
    DeflateCompressor compressor(params);

    std::string text;
    for (int i = 0; i < 500; ++i) text += "streaming chunk boundary test ";
    std::vector<uint8_t> input(text.begin(), text.end());
    auto compressed = compressor.compress(input);
    REQUIRE(!compressed.empty());

    SECTION("chunks reassemble to the original payload") {
        DeflateDecompressor d(params);
        std::vector<uint8_t> got;
        int chunks = 0;
        auto r = d.decompress_streaming(compressed, 16 * 1024 * 1024,
            [&](const uint8_t* data, size_t size) {
                ++chunks;
                CHECK(size > 0);          // never a zero-length chunk
                got.insert(got.end(), data, data + size);
                return true;
            });
        REQUIRE(r);
        CHECK(chunks >= 1);
        CHECK(got == input);
    }

    SECTION("the sink can abort, and the abort is reported as a limit breach") {
        DeflateDecompressor d(params);
        size_t seen = 0;
        auto r = d.decompress_streaming(compressed, 16 * 1024 * 1024,
            [&](const uint8_t*, size_t size) {
                seen += size;
                return seen < 100;        // stop early
            });
        REQUIRE(!r);
        CHECK(r.error().code() == ErrorCode::WsCompressionResourceExceeded);
        CHECK(seen < input.size());
    }

    SECTION("the output cap is still enforced on the streaming path") {
        DeflateDecompressor d(params);
        auto r = d.decompress_streaming(compressed, 50,
            [](const uint8_t*, size_t) { return true; });
        REQUIRE(!r);
        CHECK(r.error().code() == ErrorCode::WsCompressionResourceExceeded);
    }
}

TEST_CASE("deflate streaming compression reassembles to the same message",
          "[websocket][deflate]") {
    DeflateNegotiated params;
    params.enabled = true;
    params.server_window_bits = 15;
    params.client_window_bits = 15;

    auto make_input = [] {
        std::string text;
        for (int i = 0; i < 400; ++i) text += "incremental compression chunk ";
        return std::vector<uint8_t>(text.begin(), text.end());
    };

    SECTION("arbitrary chunk splits produce one valid compressed message") {
        const auto input = make_input();
        DeflateCompressor c(params);
        REQUIRE(c.begin_message());
        CHECK(c.message_open());

        std::vector<uint8_t> wire;
        const size_t splits[] = {1, 7, 64, 1024, input.size()};
        size_t offset = 0;
        for (size_t take : splits) {
            if (offset >= input.size()) break;
            take = (std::min)(take, input.size() - offset);
            auto r = c.compress_chunk(input.data() + offset, take);
            REQUIRE(r);
            wire.insert(wire.end(), r.value().begin(), r.value().end());
            offset += take;
        }
        REQUIRE(offset == input.size());
        auto tail = c.end_message();
        REQUIRE(tail);
        CHECK(!c.message_open());
        wire.insert(wire.end(), tail.value().begin(), tail.value().end());

        DeflateDecompressor d(params);
        auto got = d.decompress(wire, 16 * 1024 * 1024);
        REQUIRE(got);
        CHECK(got.value() == input);
    }

    SECTION("empty message still produces a decodable message") {
        DeflateCompressor c(params);
        REQUIRE(c.begin_message());
        auto tail = c.end_message();
        REQUIRE(tail);
        DeflateDecompressor d(params);
        auto got = d.decompress(tail.value(), 16 * 1024 * 1024);
        REQUIRE(got);
        CHECK(got.value().empty());
    }

    SECTION("context takeover survives across two messages") {
        DeflateCompressor c(params);
        DeflateDecompressor d(params);
        const auto first = make_input();
        const auto second = make_input();

        REQUIRE(c.begin_message());
        auto c1 = c.compress_chunk(first.data(), first.size());
        REQUIRE(c1);
        auto t1 = c.end_message();
        REQUIRE(t1);
        std::vector<uint8_t> w1 = c1.value();
        w1.insert(w1.end(), t1.value().begin(), t1.value().end());

        REQUIRE(c.begin_message());
        auto c2 = c.compress_chunk(second.data(), second.size());
        REQUIRE(c2);
        auto t2 = c.end_message();
        REQUIRE(t2);
        std::vector<uint8_t> w2 = c2.value();
        w2.insert(w2.end(), t2.value().begin(), t2.value().end());

        auto g1 = d.decompress(w1, 16 * 1024 * 1024);
        auto g2 = d.decompress(w2, 16 * 1024 * 1024);
        REQUIRE(g1);
        REQUIRE(g2);
        CHECK(g1.value() == first);
        CHECK(g2.value() == second);
    }

    SECTION("no_context_takeover resets between messages") {
        params.client_no_context_takeover = true;
        params.server_no_context_takeover = true;
        DeflateCompressor c(params);
        const auto input = make_input();

        REQUIRE(c.begin_message());
        auto x = c.compress_chunk(input.data(), input.size());
        REQUIRE(x);
        auto tx = c.end_message();
        REQUIRE(tx);

        REQUIRE(c.begin_message());
        auto y = c.compress_chunk(input.data(), input.size());
        REQUIRE(y);
        auto ty = c.end_message();
        REQUIRE(ty);

        DeflateDecompressor d(params);
        std::vector<uint8_t> wx = x.value();
        wx.insert(wx.end(), tx.value().begin(), tx.value().end());
        std::vector<uint8_t> wy = y.value();
        wy.insert(wy.end(), ty.value().begin(), ty.value().end());
        auto gx = d.decompress(wx, 16 * 1024 * 1024);
        auto gy = d.decompress(wy, 16 * 1024 * 1024);
        REQUIRE(gx);
        REQUIRE(gy);
        CHECK(gx.value() == input);
        CHECK(gy.value() == input);
    }

    SECTION("misuse is rejected instead of corrupting the stream") {
        DeflateCompressor c(params);
        CHECK(!c.compress_chunk(nullptr, 0));
        CHECK(!c.end_message());
        REQUIRE(c.begin_message());
        auto a = c.compress_chunk(nullptr, 0);
        CHECK(a);
        CHECK(!c.begin_message());          // already open
        auto t = c.end_message();
        REQUIRE(t);
        CHECK(!c.end_message());            // already closed
    }
}

TEST_CASE("deflate streaming receive decompresses frame-sized chunks",
          "[websocket][deflate]") {
    DeflateNegotiated params;
    params.enabled = true;
    params.server_window_bits = 15;
    params.client_window_bits = 15;

    auto make_input = [] {
        std::string text;
        for (int i = 0; i < 300; ++i) text += "incremental receive chunk ";
        return std::vector<uint8_t>(text.begin(), text.end());
    };

    SECTION("chunked input matches the original") {
        const auto input = make_input();
        DeflateCompressor c(params);
        REQUIRE(c.begin_message());
        auto first = c.compress_chunk(input.data(), input.size() / 2);
        REQUIRE(first);
        auto second = c.compress_chunk(input.data() + input.size() / 2,
                                       input.size() - input.size() / 2);
        REQUIRE(second);
        auto tail = c.end_message();
        REQUIRE(tail);
        std::vector<uint8_t> wire = first.value();
        wire.insert(wire.end(), second.value().begin(), second.value().end());
        wire.insert(wire.end(), tail.value().begin(), tail.value().end());

        DeflateDecompressor d(params);
        REQUIRE(d.begin_message());
        CHECK(d.message_open());
        std::vector<uint8_t> got;
        const size_t splits[] = {1, 5, 64, 4096, wire.size()};
        size_t offset = 0;
        for (size_t take : splits) {
            if (offset >= wire.size()) break;
            take = (std::min)(take, wire.size() - offset);
            auto out = d.decompress_chunk(wire.data() + offset, take, 16 * 1024 * 1024);
            REQUIRE(out);
            got.insert(got.end(), out.value().begin(), out.value().end());
            offset += take;
        }
        REQUIRE(offset == wire.size());
        auto final_out = d.end_message(16 * 1024 * 1024);
        REQUIRE(final_out);
        CHECK(!d.message_open());
        got.insert(got.end(), final_out.value().begin(), final_out.value().end());
        CHECK(got == input);
    }

    SECTION("context takeover survives across two received messages") {
        const auto input = make_input();
        DeflateCompressor c(params);
        DeflateDecompressor d(params);

        auto compress_one = [&] {
            REQUIRE(c.begin_message());
            auto x = c.compress_chunk(input.data(), input.size());
            REQUIRE(x);
            auto t = c.end_message();
            REQUIRE(t);
            std::vector<uint8_t> w = x.value();
            w.insert(w.end(), t.value().begin(), t.value().end());
            return w;
        };
        const auto w1 = compress_one();
        const auto w2 = compress_one();

        auto receive_one = [&](const std::vector<uint8_t>& w) {
            REQUIRE(d.begin_message());
            auto out = d.decompress_chunk(w.data(), w.size(), 16 * 1024 * 1024);
            REQUIRE(out);
            auto tail = d.end_message(16 * 1024 * 1024);
            REQUIRE(tail);
            std::vector<uint8_t> got = out.value();
            got.insert(got.end(), tail.value().begin(), tail.value().end());
            return got;
        };
        CHECK(receive_one(w1) == input);
        CHECK(receive_one(w2) == input);
    }

    SECTION("empty message and output cap") {
        DeflateCompressor c(params);
        REQUIRE(c.begin_message());
        auto t = c.end_message();
        REQUIRE(t);
        std::vector<uint8_t> w = t.value();

        DeflateDecompressor d(params);
        REQUIRE(d.begin_message());
        auto out = d.decompress_chunk(w.data(), w.size(), 16 * 1024 * 1024);
        REQUIRE(out);
        auto tail = d.end_message(16 * 1024 * 1024);
        REQUIRE(tail);
        CHECK(out.value().empty());
        CHECK(tail.value().empty());

        const auto input = make_input();
        REQUIRE(c.begin_message());
        auto x = c.compress_chunk(input.data(), input.size());
        REQUIRE(x);
        auto tx = c.end_message();
        REQUIRE(tx);
        std::vector<uint8_t> wire = x.value();
        wire.insert(wire.end(), tx.value().begin(), tx.value().end());
        REQUIRE(d.begin_message());
        auto capped = d.decompress_chunk(wire.data(), wire.size(), 16);
        CHECK(!capped);
        if (!capped) {
            CHECK(capped.error().code() == ErrorCode::WsCompressionResourceExceeded);
        }
    }
}

TEST_CASE("deflate streaming output can be UTF-8 validated per chunk",
          "[websocket][deflate]") {
    // The whole point of D10: validation happens on chunks whose boundaries do
    // not respect code-point boundaries. A multi-byte character split across
    // two inflate outputs must still validate.
    DeflateNegotiated params;
    params.enabled = true;
    DeflateCompressor compressor(params);

    std::string text;
    for (int i = 0; i < 200; ++i) text += "\xE2\x82\xAC";   // euro, 3 bytes each
    std::vector<uint8_t> input(text.begin(), text.end());
    auto compressed = compressor.compress(input);

    DeflateDecompressor d(params);
    WsUtf8Validator v;
    bool utf8_ok = true;
    size_t bytes = 0;
    auto r = d.decompress_streaming(compressed, 16 * 1024 * 1024,
        [&](const uint8_t* data, size_t size) {
            bytes += size;
            if (!v.feed(data, size)) { utf8_ok = false; return false; }
            return true;
        });
    REQUIRE(r);
    CHECK(utf8_ok);
    CHECK(v.complete());
    CHECK(bytes == input.size());
}
