// Example 3 — future-based request.
//
// Client::get(url) returns a FutureRequest: the operation object that carries
// BOTH the std::future and the cancel handle. The request starts immediately;
// the future becomes ready when the terminal callback fires.
//
// Two things this example shows on purpose:
//   • wait_for() lets the caller keep doing work (here: print a progress tick)
//     instead of blocking indefinitely;
//   • cancel() is thread-safe and still makes the future ready, with
//     ErrorCode::Cancelled, so "cancel" never leaves a caller waiting forever.
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python -m http.server 8080
//         megohttp_example_future_get http://127.0.0.1:8080/ [cancel-after-ms]
//
// With a second argument the example cancels the request after that many
// milliseconds, which prints a Cancelled error instead of a response.
//
// Exit code: 0 when a response arrived, 2 when it was cancelled on purpose,
// 1 on any other error.

#include <megohttp/client.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/";
    const int cancel_after_ms = (argc > 2) ? std::atoi(argv[2]) : 0;

    megohttp::Client client;
    megohttp::string url(target);

    // Starts the request right away; nothing blocks here.
    megohttp::FutureRequest op = client.get(megohttp::to_view(url));

    if (cancel_after_ms > 0) {
        std::thread canceller([&op, cancel_after_ms] {
            std::this_thread::sleep_for(std::chrono::milliseconds(cancel_after_ms));
            op.cancel();   // thread-safe, may race the completion callback
        });
        canceller.detach();
    }

    // Poll with a bounded wait so the caller keeps control: this is the whole
    // point of the future API over get_sync().
    std::optional<megohttp::Result<megohttp::Response>> maybe;
    for (int i = 0; i < 300 && !maybe; ++i) {         // 300 * 100 ms = 30 s cap
        maybe = op.wait_for(std::chrono::milliseconds(100));
        if (!maybe) std::printf("waiting... (%d)\n", i + 1);
    }

    if (!maybe) {
        op.cancel();
        std::printf("timed out waiting for the request\n");
        return 1;
    }

    const auto& result = *maybe;
    if (!result) {
        const auto& err = result.error();
        std::printf("request failed: code=%d %.*s\n",
                    static_cast<int>(err.code()),
                    static_cast<int>(err.message().size()),
                    err.message().data());
        return err.code() == megohttp::ErrorCode::Cancelled ? 2 : 1;
    }

    std::printf("status %d, %zu body bytes\n",
                result.value().head().status_code,
                static_cast<size_t>(result.value().body_bytes().size()));
    return 0;
}
