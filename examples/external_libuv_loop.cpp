// Example 4 — external libuv loop.
//
// When ClientOptions::executor is set, the Client does NOT own a loop and does
// NOT start a driver thread: the caller creates the loop, runs it, and closes
// it. This is the integration shape an application with its own uv_loop_t wants.
//
// The teardown order below is the contract, not decoration:
//   1. initialize_external_wake_handle() from the thread that runs the loop.
//      libuv has no "am I on this loop's thread" query, so the executor cannot
//      install its own wake handle; without it, posts stay queued by design.
//   2. Client::shutdown(), then run the loop until the retirement jobs it
//      posted have run. Closing the executor first drops them.
//   3. Destroy the Client: the transport/timer handles it created are closed
//      there, asynchronously.
//   4. Executor::shutdown() closes only the executor's own handle.
//   5. Run the loop until nothing is active, then uv_loop_close(). Skipping 2/3
//      leaves it reporting "resource busy".
//
// Build:  cmake -S . -B build -DMGHTTP_BACKEND_LIBUV=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python -m http.server 8080
//         megohttp_example_external_libuv_loop http://127.0.0.1:8080/
//
// Exit code: 0 on a 200 response, 1 on error, 2 on timeout.

#include <megohttp/backend/executor_libuv.hpp>
#include <megohttp/client.hpp>

#include <uv.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/";

    uv_loop_t loop;
    if (uv_loop_init(&loop) != 0) {
        std::printf("uv_loop_init failed\n");
        return 1;
    }

    auto executor = megohttp::libuv_backend::UvExecutor::create_external(&loop);
    if (!executor) {
        std::printf("create_external failed\n");
        uv_loop_close(&loop);
        return 1;
    }
    executor->initialize_external_wake_handle();   // we are the driver thread

    std::atomic<bool> done{false};
    int status = 0;

    // The Client is destroyed before the loop is closed: a borrowed-loop Client
    // closes the transport and timer handles it created, and those closes are
    // asynchronous, so the loop has to run once more afterwards. Keeping the
    // Client alive until main() returns is what leaves uv_loop_close() with
    // "resource busy" — the handles are still there when the loop is closed.
    {
        megohttp::ClientOptions options;
        options.executor = executor;                   // borrowed, not owned
        options.connect_timeout = std::chrono::seconds(10);
        options.total_timeout = std::chrono::seconds(30);
        megohttp::Client client(std::move(options));

        megohttp::string url(target);

        client.get(megohttp::to_view(url), [&](megohttp::Result<megohttp::Response> result) {
            if (!result) {
                std::printf("request failed: %.*s\n",
                            static_cast<int>(result.error().message().size()),
                            result.error().message().data());
                status = 1;
            } else {
                std::printf("status %d, %zu body bytes\n",
                            result.value().head().status_code,
                            static_cast<size_t>(result.value().body_bytes().size()));
                status = (result.value().head().status_code == 200) ? 0 : 1;
            }
            done.store(true);
        });

        // Drive the caller-owned loop. UV_RUN_NOWAIT + a short sleep is used
        // instead of UV_RUN_ONCE so the example cannot block forever if the
        // timer set is empty; a real application would call UV_RUN_DEFAULT.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(35);
        while (!done.load() && std::chrono::steady_clock::now() < deadline) {
            uv_run(&loop, UV_RUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        client.shutdown();
        // shutdown() posts retirement work to the executor: run the loop until
        // that queue is empty, otherwise the posted jobs (and everything they
        // keep alive) are dropped when the executor closes its wake handle.
        for (int i = 0; i < 50; ++i) {
            uv_run(&loop, UV_RUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    // ~Client: runs here, and its own closes are queued on the loop as well.
    for (int i = 0; i < 50; ++i) {
        uv_run(&loop, UV_RUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    executor->shutdown();

    // uv_close is asynchronous: the executor's handles are only really gone
    // after the loop has run again, and uv_loop_close() refuses while any
    // handle is still active. Running with UV_RUN_NOWAIT keeps a stuck handle
    // visible as an error instead of hanging the example forever.
    for (int i = 0; i < 500 && uv_loop_alive(&loop); ++i) {
        uv_run(&loop, UV_RUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    const int rc = uv_loop_close(&loop);
    if (rc != 0) {
        std::printf("uv_loop_close: %s\n", uv_strerror(rc));
        return 1;
    }
    return done.load() ? 0 : 2;
}
