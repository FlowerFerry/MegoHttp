// Example 11 — Server-Sent Events (SSE).
//
// A normal GET whose response body is an event stream. The session handles the
// framing, the reconnect policy and the Last-Event-ID bookkeeping, so the
// callbacks only see decoded events.
//
// Reconnection is opt-in: SseReconnectPolicy::auto_reconnect defaults to false.
// This example turns it on with a short backoff so a dropped connection (the
// bundled demo server drops after five events) visibly resumes from the last id.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_SSE=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/sse_server.py 8080
//         megohttp_example_sse_client http://127.0.0.1:8080/events [max-events]
//
// The server is local and needs no network. Exit code: 0 once max-events
// arrived (default 6), 1 on a fatal error or timeout.

#include <megohttp/client.hpp>
#include <megohttp/sse_session.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/events";
    const size_t want = (argc > 2) ? static_cast<size_t>(std::atoi(argv[2])) : 6u;

    megohttp::string url(target);
    megohttp::Request request(megohttp::Method::Get, megohttp::to_view(url));
    request.headers().set("Accept", "text/event-stream");

    megohttp::Client client;

    megohttp::SseReconnectPolicy policy;
    policy.auto_reconnect = true;      // off by default; this example wants it
    policy.send_last_event_id = true;  // resume, do not replay from zero
    policy.backoff.initial_delay = std::chrono::milliseconds(200);
    policy.backoff.max_delay = std::chrono::seconds(2);
    policy.backoff.jitter_ratio = 0.0; // keep the demo output deterministic
    policy.backoff.max_attempts = 5;

    auto session = client.request_sse(request, policy);

    std::atomic<size_t> received{0};
    std::atomic<bool> done{false};

    session->on_event([&](const megohttp::SseEvent& event) {
        std::printf("event #%zu type=%.*s id=%s data=%.*s\n",
                    received.load() + 1,
                    static_cast<int>(event.event_type.size()), event.event_type.data(),
                    event.id ? event.id->c_str() : "(none)",
                    static_cast<int>(event.data.size()), event.data.data());
        if (received.fetch_add(1) + 1 >= want) session->cancel();
    });
    session->on_error([&](const megohttp::Error& error) {
        std::printf("stream error: %.*s\n",
                    static_cast<int>(error.message().size()), error.message().data());
    });
    session->on_complete([&] {
        std::printf("stream complete, last event id: %s\n",
                    session->last_event_id() ? session->last_event_id()->c_str() : "(none)");
        done.store(true);
    });

    session->start();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!done.load()) {
        session->cancel();
        std::printf("timed out after %zu events\n", received.load());
        return 1;
    }
    return received.load() >= want ? 0 : 1;
}
