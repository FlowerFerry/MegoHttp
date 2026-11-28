// Example 2 — callback request and cross-thread cancellation.
//
// Client::request()/get() takes a completion callback and returns a CancelHandle.
// The callback fires exactly once, on the I/O thread, with either a Response or
// an Error — there is no "did cancel beat the callback?" race for the caller to
// reason about.
//
// cancel() is thread-safe and may be called from any thread, which is the whole
// point of the handle being separate from the callback: a UI thread, a signal
// handler or a timeout thread can stop a request it no longer wants. The request
// then completes with ErrorCode::Cancelled.
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python examples/servers/slow_server.py 8084 2000   # answers after 2 s
//         megohttp_example_callback_cancel http://127.0.0.1:8084/ 200
//
// The second argument is the delay before the cancelling thread fires, so the
// default run cancels long before the server answers.
//
// Exit code: 0 when a response arrived, 2 when the cancel won, 1 on any other
// error or timeout.

#include <megohttp/client.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8084/";
    const int cancel_after_ms = (argc > 2) ? std::atoi(argv[2]) : 200;

    megohttp::Client client;
    megohttp::string url(target);

    std::atomic<bool> done{false};
    int outcome = 1;   // 0 = response, 2 = cancelled, 1 = other error

    const megohttp::CancelHandle handle = client.get(
        megohttp::to_view(url), [&](megohttp::Result<megohttp::Response> result) {
            if (!result) {
                const auto& error = result.error();
                std::printf("request failed: code=%d %.*s\n",
                            static_cast<int>(error.code()),
                            static_cast<int>(error.message().size()),
                            error.message().data());
                outcome = (error.code() == megohttp::ErrorCode::Cancelled) ? 2 : 1;
            } else {
                std::printf("status %d, %zu body bytes\n",
                            result.value().head().status_code,
                            static_cast<size_t>(result.value().body_bytes().size()));
                outcome = 0;
            }
            done.store(true);
        });

    if (cancel_after_ms >= 0) {
        // Any thread may cancel: the handle is a value type with shared state.
        std::thread canceller([handle, cancel_after_ms]() mutable {
            std::this_thread::sleep_for(std::chrono::milliseconds(cancel_after_ms));
            std::printf("cancelling from another thread\n");
            handle.cancel();
        });
        canceller.detach();
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!done.load()) {
        handle.cancel();
        std::printf("timed out waiting for the terminal callback\n");
        return 1;
    }
    return outcome;
}
