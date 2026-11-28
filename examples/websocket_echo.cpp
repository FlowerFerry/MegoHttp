// Example 12 — WebSocket basic communication.
//
// Client::open_websocket() parses the ws:// URL once, runs the connect +
// Upgrade handshake through this Client's options (proxy, timeouts, trust
// store), and returns a session that is already started. Callbacks are installed
// right after it returns; the handshake cannot complete before that because it
// needs at least one I/O round trip.
//
// This is the plain request/response shape: open, send one text message, print
// the echo, close. Reconnection, permessage-deflate, streaming sends and
// token refresh are separate examples.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_WEBSOCKET=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/ws_echo_server.py 8080
//         megohttp_example_websocket_echo ws://127.0.0.1:8080/chat
//
// The server is local and needs no network. Exit code: 0 when the echoed text
// came back and the close handshake finished, 1 otherwise.

#include <megohttp/client.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/websocket_reconnect.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "ws://127.0.0.1:8080/chat";

    megohttp::Client client;
    megohttp::string url(target);

    megohttp::WebSocketOptions ws_options;   // no subprotocol, no extensions
    megohttp::WebSocketReconnectPolicy policy;   // enabled = false: one connection

    auto ws = client.open_websocket(megohttp::to_view(url), ws_options, policy);
    if (!ws) {
        std::printf("open_websocket returned no session\n");
        return 1;
    }

    std::atomic<bool> done{false};
    std::atomic<bool> echoed{false};

    ws->on_open([&](const megohttp::Error& error) {
        if (error) {
            std::printf("handshake failed: %.*s\n",
                        static_cast<int>(error.message().size()), error.message().data());
            done.store(true);
            return;
        }
        std::printf("open\n");
        ws->send_text(megohttp::string("hello from megohttp"),
                      [](const megohttp::Error& send_error) {
                          if (send_error) {
                              std::printf("send failed: %.*s\n",
                                          static_cast<int>(send_error.message().size()),
                                          send_error.message().data());
                          }
                      });
    });

    ws->on_message([&](megohttp::WsMessageType type, const std::vector<uint8_t>& payload) {
        std::printf("message type=%s bytes=%zu text=%.*s\n",
                    type == megohttp::WsMessageType::Text ? "text" : "binary",
                    payload.size(),
                    static_cast<int>(payload.size()),
                    reinterpret_cast<const char*>(payload.data()));
        echoed.store(true);
        ws->close(1000, megohttp::string("bye"));
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
    return echoed.load() ? 0 : 1;
}
