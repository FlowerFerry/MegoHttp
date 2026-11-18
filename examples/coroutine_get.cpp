// C++20 coroutine example (stage 7).
//
// Build:
//   cmake -S . -B build_cxx20 -DCMAKE_CXX_STANDARD=20 -DMGHTTP_BUILD_TESTS=OFF
//   cmake --build build_cxx20
//
// Run against any local HTTP server, e.g.:
//   python -m http.server 8080
//   coroutine_get http://127.0.0.1:8080/
//
// The Task is EAGER: constructing it starts the request immediately. The
// coroutine suspends at co_await until the completion callback runs on the
// Client's executor thread, then resumes there. Nothing blocks and no thread
// is created per request.

#include <megohttp/client.hpp>

#if !MEGOHTTP_HAS_COROUTINES
#error "This example requires MGHTTP_ENABLE_COROUTINES (C++20)"
#endif

#include <cstdio>
#include <utility>

namespace {

// A coroutine that performs one GET and reports the status.
megohttp::Task<int> fetch(megohttp::Client& client, megohttp::string url) {
    megohttp::Request req(megohttp::Method::Get, url);
    auto result = co_await client.request_co(req);
    if (!result) {
        std::printf("request failed: %s\n", result.error().message().c_str());
        co_return -1;
    }
    std::printf("status %d, %zu body bytes\n",
                result.value().head().status_code,
                static_cast<size_t>(result.value().body_bytes().size()));
    co_return result.value().head().status_code;
}

} // namespace

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/";

    megohttp::Client client;
    auto task = fetch(client, megohttp::string(target));

    // The task already started. Cancel from here if the work is unwanted:
    //   task.cancel();
    const int status = task.await_resume();
    return (status == 200) ? 0 : 1;
}
