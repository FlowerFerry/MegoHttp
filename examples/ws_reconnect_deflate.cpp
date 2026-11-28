// Example 16 — WebSocket: re-query the compression negotiation after a reconnect.
//
// Each physical connection negotiates permessage-deflate independently — the
// server may accept different window bits, or refuse the extension on the second
// connection. So the negotiated result from the first connection must NOT be
// cached by the caller: `negotiated_deflate()` reports the CURRENT connection,
// and a reconnect is exactly when it can change.
//
// The demo server is started with --vary-negotiation, so the first connection
// agrees on a 15-bit window and every later one on 9 bits with
// server_no_context_takeover. The two printouts below therefore differ, which is
// the behavior this example exists to demonstrate.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_WEBSOCKET=ON \
//              -DMGHTTP_ENABLE_WEBSOCKET_DEFLATE=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/ws_server.py 8087 --vary-negotiation --drop-after 1
//         megohttp_example_ws_reconnect_deflate ws://127.0.0.1:8087/chat
//
// Exit code: 0 when two connections were established and the second reported a
// different negotiation than the first.

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
    ws_options.max_message_size = 4 * 1024 * 1024;

    megohttp::WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(100);
    policy.backoff.max_delay = std::chrono::seconds(1);
    policy.backoff.jitter_ratio = 0.0;
    policy.backoff.max_attempts = 4;
    policy.minimum_stable_connection_duration = std::chrono::milliseconds(50);

    auto ws = client.open_websocket(megohttp::to_view(url), ws_options, policy);
    if (!ws) {
        std::printf("open_websocket returned no session\n");
        return 1;
    }

    std::atomic<bool> done{false};
    std::atomic<uint64_t> connections{0};
    megohttp::DeflateNegotiated first{};
    megohttp::DeflateNegotiated second{};
    std::atomic<bool> have_first{false};

    auto describe = [](const char* label, const megohttp::DeflateNegotiated& neg) {
        std::printf("%s: enabled=%d server_window_bits=%d client_window_bits=%d "
                    "server_no_context_takeover=%d client_no_context_takeover=%d\n",
                    label, neg.enabled ? 1 : 0, neg.server_window_bits,
                    neg.client_window_bits, neg.server_no_context_takeover ? 1 : 0,
                    neg.client_no_context_takeover ? 1 : 0);
    };

    // on_open fires once for the logical session; a successful reconnect is
    // reported through ReconnectEvents::on_succeeded, which is where the second
    // negotiation has to be read.
    ws->on_open([&](const megohttp::Error& error) {
        if (error) {
            std::printf("handshake failed: %.*s\n",
                        static_cast<int>(error.message().size()), error.message().data());
            return;
        }
        const auto neg = ws->negotiated_deflate();
        first = neg;
        have_first.store(true);
        connections.fetch_add(1);
        describe("connection 1 negotiation", first);
        // One message makes the server drop the connection, which is what forces
        // the reconnect this example is about.
        ws->send_text(megohttp::string("trigger the drop"));
    });

    megohttp::ReconnectingWebSocket::ReconnectEvents events;
    events.on_succeeded = [&](size_t attempt, uint64_t generation) {
        second = ws->negotiated_deflate();
        connections.fetch_add(1);
        describe("connection 2 negotiation", second);
        std::printf("generation=%llu attempt=%zu, same as connection 1: %d\n",
                    static_cast<unsigned long long>(generation), attempt,
                    (second.enabled == first.enabled &&
                     second.server_window_bits == first.server_window_bits &&
                     second.server_no_context_takeover == first.server_no_context_takeover)
                        ? 1
                        : 0);
        ws->close(1000, megohttp::string("done"));
    };
    ws->set_reconnect_events(std::move(events));

    ws->on_close([&](uint16_t code, const megohttp::string& reason) {
        std::printf("close frame: code=%u reason=%.*s\n", static_cast<unsigned>(code),
                    static_cast<int>(reason.size()), reason.data());
    });

    ws->on_session_end([&](const megohttp::Error* reason) {
        if (reason) {
            std::printf("session ended with error: %.*s\n",
                        static_cast<int>(reason->message().size()),
                        reason->message().data());
        }
        done.store(true);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    const bool changed = connections.load() >= 2 && have_first.load() &&
                         (second.server_window_bits != first.server_window_bits ||
                          second.server_no_context_takeover != first.server_no_context_takeover);
    std::printf("summary: connections=%llu negotiation_changed=%d\n",
                static_cast<unsigned long long>(connections.load()), changed ? 1 : 0);
    return changed ? 0 : 1;
}
