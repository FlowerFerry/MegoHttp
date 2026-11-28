// Example 13 — WebSocket permessage-deflate: negotiate, then query the result.
//
// Compression is opt-in twice: the build must have it
// (MGHTTP_ENABLE_WEBSOCKET_DEFLATE) and the caller must ask for it
// (WebSocketOptions::enable_deflate). Only then is `permessage-deflate` offered
// in the Upgrade handshake.
//
// The server may accept the extension with different parameters, or refuse it.
// `negotiated_deflate()` reports what THIS connection agreed on:
//   • enabled                  — the extension was accepted at all;
//   • server/client_window_bits — LZ77 window the two sides may use;
//   • *_no_context_takeover     — whether the deflate context resets per message.
// A refused offer is not an error: the session simply runs uncompressed.
//
// max_message_size is the limit on the DECOMPRESSED size. That is the number
// that bounds memory: a 2 KiB frame can expand to megabytes, so the compressed
// frame length is the wrong thing to bound.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_WEBSOCKET=ON \
//              -DMGHTTP_ENABLE_WEBSOCKET_DEFLATE=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/ws_server.py 8087
//         megohttp_example_ws_deflate_negotiation ws://127.0.0.1:8087/chat
//
// Exit code: 0 when the echo arrived (compressed or not), 1 otherwise.

#include <megohttp/client.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/websocket_deflate.hpp>
#include <megohttp/websocket_reconnect.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "ws://127.0.0.1:8087/chat";

    megohttp::Client client;
    megohttp::string url(target);

    megohttp::WebSocketOptions ws_options;
    ws_options.enable_deflate = true;
    ws_options.deflate.server_no_context_takeover = false;
    ws_options.deflate.client_no_context_takeover = false;
    ws_options.max_message_size = 1024 * 1024;   // decompressed bytes, not wire

    megohttp::WebSocketReconnectPolicy policy;   // disabled: one connection

    auto ws = client.open_websocket(megohttp::to_view(url), ws_options, policy);
    if (!ws) {
        std::printf("open_websocket returned no session\n");
        return 1;
    }

    std::atomic<bool> done{false};
    int status = 1;

    ws->on_open([&](const megohttp::Error& error) {
        if (error) {
            std::printf("handshake failed: %.*s\n",
                        static_cast<int>(error.message().size()), error.message().data());
            done.store(true);
            return;
        }
        const megohttp::DeflateNegotiated neg = ws->negotiated_deflate();
        std::printf("open: deflate=%s\n", neg.enabled ? "accepted" : "not negotiated");
        if (neg.enabled) {
            std::printf("  server_window_bits=%d client_window_bits=%d "
                        "server_no_context_takeover=%d client_no_context_takeover=%d\n",
                        neg.server_window_bits, neg.client_window_bits,
                        neg.server_no_context_takeover ? 1 : 0,
                        neg.client_no_context_takeover ? 1 : 0);
        }
        std::printf("  max_message_size (decompressed) = %zu bytes\n",
                    ws_options.max_message_size);
        ws->send_text(megohttp::string("compressible compressible compressible"));
    });

    ws->on_message([&](megohttp::WsMessageType type, const std::vector<uint8_t>& payload) {
        std::printf("echo: type=%s bytes=%zu text=%.*s\n",
                    type == megohttp::WsMessageType::Text ? "text" : "binary",
                    payload.size(), static_cast<int>(payload.size()),
                    reinterpret_cast<const char*>(payload.data()));
        status = 0;
        ws->close(1000, megohttp::string("done"));
    });

    ws->on_close([&](uint16_t code, const megohttp::string& reason) {
        std::printf("closed code=%u reason=%.*s\n", static_cast<unsigned>(code),
                    static_cast<int>(reason.size()), reason.data());
        done.store(true);
    });

    ws->on_error([&](const megohttp::Error& error) {
        std::printf("session error: %.*s\n",
                    static_cast<int>(error.message().size()), error.message().data());
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!done.load()) {
        std::printf("timed out\n");
        return 1;
    }
    return status;
}
