// uvw availability test: the C++ wrapper over libuv must actually compile and
// run against the same libuv the raw backend uses. A build-time flag is not
// evidence; this schedules real work on a uvw loop.
#include <catch_amalgamated.hpp>

#include <megohttp/config.hpp>

#if !defined(MGHTTP_USE_UVW)
TEST_CASE("feature disabled", "[uvw]") {
    SKIP("uvw not enabled in this configuration");
}
#else

#include <uvw.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>


template<typename F>
static bool wait_until(F pred, int max_ms = 3000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return pred();
}

TEST_CASE("timer", "[uvw]") {
    auto loop = uvw::loop::get_default();
    CHECK(loop != nullptr);
    if (!loop) return;

    std::atomic<int> fired{0};
    std::atomic<bool> too_early{false};
    const auto start = std::chrono::steady_clock::now();

    auto timer = loop->resource<uvw::timer_handle>();
    CHECK(timer != nullptr);
    timer->on<uvw::timer_event>([&](const uvw::timer_event&, uvw::timer_handle& h) {
        const auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed < std::chrono::milliseconds(20)) too_early.store(true);
        fired.fetch_add(1);
        h.stop();
        loop->stop();
    });
    timer->start(std::chrono::milliseconds(30), std::chrono::milliseconds(0));
    loop->run();

    CHECK(fired.load() == 1);
    CHECK(!too_early.load());
    timer->close();
    loop->run();
}

TEST_CASE("async across threads", "[uvw]") {
    // uvw's async handle is the same wake-up mechanism the executor uses.
    auto loop = uvw::loop::get_default();
    CHECK(loop != nullptr);
    if (!loop) return;

    std::atomic<int> delivered{0};
    std::atomic<bool> poster_done{false};
    auto async = loop->resource<uvw::async_handle>();
    CHECK(async != nullptr);

    async->on<uvw::async_event>([&](const uvw::async_event&, uvw::async_handle&) {
        delivered.fetch_add(1);
        // Stop only after every send has been observed, so the loop cannot return
        // before the last one is delivered.
        if (poster_done.load() && delivered.load() >= 3) loop->stop();
    });

    std::thread poster([&] {
        // Posts from a non-loop thread, exactly like Executor::post().
        for (int i = 0; i < 3; ++i) {
            async->send();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        poster_done.store(true);
        async->send();   // one extra, to wake a loop already blocked
    });

    // Drive the loop until our handler stops it. uvw's async handle wakes the
    // loop from another thread, which is precisely what is under test.
    loop->run();
    poster.join();

    CHECK(delivered.load() >= 3);
    async->close();
    loop->run();
}

#endif
