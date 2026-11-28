// Example 5 — external Asio io_context.
//
// The Asio counterpart of the libuv external-loop example: the caller owns the
// io_context, runs it, and stops it. The Client borrows the executor and never
// calls io_context::stop() on somebody else's context.
//
// The completion callback runs ON the io_context thread, so the example finishes
// the loop from inside the callback (io_context::stop()) exactly where a real
// application would hand the result to its own state machine.
//
// Build:  cmake -S . -B build -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python -m http.server 8080
//         megohttp_example_external_asio_loop http://127.0.0.1:8080/
//
// Exit code: 0 on a 200 response, 1 on error.

#include <megohttp/backend/executor_asio.hpp>
#include <megohttp/client.hpp>

#include <asio.hpp>

#include <chrono>
#include <cstdio>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/";

    asio::io_context ioc;
    auto executor = megohttp::asio_backend::AsioExecutor::create_external(ioc);
    if (!executor) {
        std::printf("create_external failed\n");
        return 1;
    }

    megohttp::ClientOptions options;
    options.executor = executor;                  // borrowed, not owned
    options.connect_timeout = std::chrono::seconds(10);
    options.total_timeout = std::chrono::seconds(30);
    megohttp::Client client(std::move(options));

    int status = 0;
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
        ioc.stop();   // our loop, our decision to stop it
    });

    ioc.run();

    client.shutdown();
    executor->shutdown();   // releases the executor's work guard; does not stop ioc
    return status;
}
