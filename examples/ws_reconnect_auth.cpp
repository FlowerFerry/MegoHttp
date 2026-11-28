// Example 15 — WebSocket auto-reconnect, credential refresh and explicit stop.
//
// Three behaviors that only make sense together on a long-lived session:
//
//   auto-reconnect  — WebSocketReconnectPolicy::enabled; each dropped connection
//                     is retried with backoff. Every attempt re-runs the WHOLE
//                     connect + handshake path, so the security policy is never
//                     bypassed. Messages are NOT queued across a disconnect: a
//                     send on a dead connection fails instead of being replayed.
//
//   credential refresh — WebSocketOptions::on_before_handshake runs before every
//                     handshake, including the first, and receives the header set
//                     about to be sent. That is where a fresh token goes: the one
//                     used on the first connection is usually expired by the time
//                     a reconnect happens. The demo server accepts any
//                     "Bearer demo-*" and prints the value it saw, so the log
//                     proves the header changed between attempts.
//
//   explicit stop   — close() sends a close frame and stops reconnecting;
//                     terminate() is the hard stop with no close frame.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_WEBSOCKET=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/ws_server.py 8087 --require-token-prefix "Bearer demo-" \
//                 --drop-after 1
//         megohttp_example_ws_reconnect_auth ws://127.0.0.1:8087/chat
//
// Exit code: 0 when at least two connections were established and the session
// was stopped explicitly.

#include <megohttp/client.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/websocket_reconnect.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "ws://127.0.0.1:8087/chat";

    megohttp::Client client;
    megohttp::string url(target);

    // The token a reconnect should use. Guarded because on_before_handshake runs
    // on the I/O thread while the value is written from the reconnect-event
    // callback; the two happen to be the same thread today, but the example
    // should not depend on that.
    std::mutex token_mutex;
    std::string token = "demo-1";
    std::atomic<int> refreshes{0};

    megohttp::WebSocketOptions ws_options;
    ws_options.on_before_handshake = [&](megohttp::Headers& headers) {
        std::lock_guard<std::mutex> lock(token_mutex);
        headers.set("Authorization", megohttp::string(("Bearer " + token).c_str()));
        std::printf("handshake: Authorization=%s\n", ("Bearer " + token).c_str());
    };

    megohttp::WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(100);
    policy.backoff.max_delay = std::chrono::seconds(1);
    policy.backoff.jitter_ratio = 0.0;              // keep the log readable
    policy.backoff.max_attempts = 5;
    policy.minimum_stable_connection_duration = std::chrono::milliseconds(50);

    auto ws = client.open_websocket(megohttp::to_view(url), ws_options, policy);
    if (!ws) {
        std::printf("open_websocket returned no session\n");
        return 1;
    }

    std::atomic<bool> done{false};
    std::atomic<uint64_t> last_generation{0};

    // Fires per physical reconnect attempt, BEFORE the handshake: the only place
    // where "the old token is now expired" translates into a new header.
    megohttp::ReconnectingWebSocket::ReconnectEvents events;
    events.on_scheduled = [&](size_t attempt, megohttp::Duration delay) {
        std::lock_guard<std::mutex> lock(token_mutex);
        token = "demo-" + std::to_string(attempt + 1);
        refreshes.fetch_add(1);
        std::printf("reconnect #%zu scheduled in %lld ms, token refreshed to %s\n",
                    attempt,
                    static_cast<long long>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(delay).count()),
                    token.c_str());
    };
    // on_open fires once for the logical session; later physical connections are
    // reported here, with the generation of the new connection.
    events.on_succeeded = [&](size_t attempt, uint64_t generation) {
        last_generation.store(generation);
        std::printf("reconnected: generation=%llu attempts=%zu\n",
                    static_cast<unsigned long long>(generation), attempt);
        ws->send_text(megohttp::string("ping-after-reconnect"));
    };
    events.on_gave_up = [&](const megohttp::Error& reason, size_t attempts, bool final) {
        std::printf("gave up after %zu attempts (final=%d): %.*s\n", attempts,
                    final ? 1 : 0, static_cast<int>(reason.message().size()),
                    reason.message().data());
    };
    ws->set_reconnect_events(std::move(events));

    ws->on_open([&](const megohttp::Error& error) {
        if (error) {
            std::printf("handshake failed: %.*s\n",
                        static_cast<int>(error.message().size()), error.message().data());
            return;
        }
        const uint64_t generation = ws->connection_generation();
        last_generation.store(generation);
        std::printf("open: generation=%llu attempts=%zu\n",
                    static_cast<unsigned long long>(generation),
                    ws->reconnect_attempts());
        ws->send_text(megohttp::string("ping"));
    });

    ws->on_message([&](megohttp::WsMessageType, const std::vector<uint8_t>& payload) {
        std::printf("echo: %.*s\n", static_cast<int>(payload.size()),
                    reinterpret_cast<const char*>(payload.data()));
    });

    ws->on_close([&](uint16_t code, const megohttp::string& reason) {
        std::printf("close frame: code=%u reason=%.*s\n", static_cast<unsigned>(code),
                    static_cast<int>(reason.size()), reason.data());
    });

    ws->on_session_end([&](const megohttp::Error* reason) {
        if (reason) {
            std::printf("session ended with error: %.*s\n",
                        static_cast<int>(reason->message().size()),
                        reason->message().data());
        } else {
            std::printf("session ended cleanly\n");
        }
        done.store(true);
    });

    // Wait for two physical connections, then stop explicitly. Without the
    // explicit close the session would keep reconnecting after the server drops
    // it, which is exactly the behavior a caller must be able to end.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        if (last_generation.load() >= 2) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::printf("stopping explicitly after generation=%llu (refreshes=%d)\n",
                static_cast<unsigned long long>(last_generation.load()), refreshes.load());
    ws->close(1000, megohttp::string("example done"));

    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return (last_generation.load() >= 2) ? 0 : 1;
}
