// Example 1 — synchronous GET.
//
// The smallest useful request: build a Client, ask for a URL, get a Response or
// an Error. get_sync() blocks the calling thread until the terminal callback
// fires, so it must not be called from the thread that drives this Client's
// executor (an internal-loop Client creates that thread itself, so from main()
// the call is always safe).
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python -m http.server 8080
//         megohttp_example_sync_get http://127.0.0.1:8080/
//
// Exit code: 0 when the status is 200, 1 on error or any other status.

#include <megohttp/client.hpp>

#include <cstdio>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/";

    megohttp::Client client;   // owns its own loop thread
    megohttp::string url(target);

    const auto result = client.get_sync(megohttp::to_view(url));
    if (!result) {
        std::printf("request failed: %.*s\n",
                    static_cast<int>(result.error().message().size()),
                    result.error().message().data());
        return 1;
    }

    const megohttp::Response& response = result.value();
    std::printf("status %d %.*s\n",
                response.head().status_code,
                static_cast<int>(response.head().status_text.size()),
                response.head().status_text.data());

    if (!response.body_is_buffered()) {
        std::printf("body was streamed away by a sink; nothing buffered\n");
    } else {
        const auto body = response.body_text();
        std::printf("body %zu bytes:\n%.*s\n", body.size(),
                    static_cast<int>(body.size()), body.data());
    }
    return response.head().status_code == 200 ? 0 : 1;
}
