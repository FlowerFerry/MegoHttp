#include <catch2/catch_test_macros.hpp>
#include <megohttp/websocket_deflate.hpp>
#include <megohttp/headers.hpp>

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

        auto decompressed = decompressor.decompress(compressed);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }

    SECTION("empty message") {
        std::vector<uint8_t> input;
        auto compressed = compressor.compress(input);
        auto decompressed = decompressor.decompress(compressed);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }

    SECTION("large message") {
        std::string text(10000, 'A');
        std::vector<uint8_t> input(text.begin(), text.end());

        auto compressed = compressor.compress(input);
        REQUIRE(compressed.size() < input.size()); // Should compress well

        auto decompressed = decompressor.decompress(compressed);
        REQUIRE(decompressed.has_value());
        REQUIRE(*decompressed == input);
    }

    SECTION("binary data") {
        std::vector<uint8_t> input;
        for (int i = 0; i < 1000; ++i) {
            input.push_back(static_cast<uint8_t>(i % 256));
        }

        auto compressed = compressor.compress(input);
        auto decompressed = decompressor.decompress(compressed);
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
    auto decompressed1 = decompressor.decompress(compressed1);
    REQUIRE(decompressed1.has_value());
    REQUIRE(*decompressed1 == input1);

    // Compress and decompress second message (context should be reset)
    auto compressed2 = compressor.compress(input2);
    auto decompressed2 = decompressor.decompress(compressed2);
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
    auto decompressed1 = decompressor.decompress(compressed1);
    auto decompressed2 = decompressor.decompress(compressed2);
    REQUIRE(decompressed1.has_value());
    REQUIRE(decompressed2.has_value());
    REQUIRE(*decompressed1 == input1);
    REQUIRE(*decompressed2 == input2);
}
