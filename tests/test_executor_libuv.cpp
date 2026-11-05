// libuv executor tests: cross-thread post, timers, cancel, internal/external loop.
#include <catch_amalgamated.hpp>

#include <megohttp/backend/executor_libuv.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace megohttp;
using namespace megohttp::libuv_backend;


// Waits for a predicate with a bounded timeout, so a hang fails instead of hanging.
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

TEST_CASE("internal post from other thread", "[executor]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<int> count{0};
    std::atomic<std::thread::id> ran_on{};

    // Post from a thread that is NOT the loop thread.
    std::thread t([&] {
        for (int i = 0; i < 100; ++i) {
            ex->post([&] {
                ran_on.store(std::this_thread::get_id());
                count.fetch_add(1);
            });
        }
    });
    t.join();

    CHECK(wait_until([&] { return count.load() == 100; }));
    // Handlers must run on the loop thread, not the posting thread.
    CHECK(ran_on.load() != std::this_thread::get_id());
    CHECK(ex->is_in_loop_thread() == false);   // we are on the test thread

    ex->shutdown();
}

TEST_CASE("post from loop thread", "[executor]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<int> count{0};
    std::atomic<bool> was_in_loop{false};

    ex->post([&] {
        was_in_loop.store(ex->is_in_loop_thread());
        // A post from inside the loop must also be dispatched, not run inline.
        ex->post([&] { count.fetch_add(1); });
        count.fetch_add(1);
    });

    CHECK(wait_until([&] { return count.load() == 2; }));
    CHECK(was_in_loop.load());
    ex->shutdown();
}

TEST_CASE("timer", "[executor]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<int> fired{0};
    std::atomic<bool> too_early{false};
    const auto start = std::chrono::steady_clock::now();

    ex->post([&] {
        auto t = ex->schedule_after(std::chrono::milliseconds(50), [&] {
            const auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed < std::chrono::milliseconds(40)) too_early.store(true);
            fired.fetch_add(1);
        });
        CHECK(t != nullptr);
    });

    CHECK(wait_until([&] { return fired.load() == 1; }));
    CHECK(!too_early.load());
    // One-shot: must not fire again.
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    CHECK(fired.load() == 1);
    ex->shutdown();
}

TEST_CASE("timer cancel", "[executor]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<int> fired{0};
    std::atomic<bool> armed{false};
    std::shared_ptr<Timer> held;

    ex->post([&] {
        held = ex->schedule_after(std::chrono::milliseconds(120), [&] {
            fired.fetch_add(1);
        });
        armed.store(true);
    });
    CHECK(wait_until([&] { return armed.load(); }));

    if (held) held->cancel();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(fired.load() == 0);

    ex->shutdown();
}

TEST_CASE("external loop", "[executor]") {
    // The caller owns and drives the loop; the executor must never stop it.
    uv_loop_t loop;
    CHECK(uv_loop_init(&loop) == 0);

    auto ex = UvExecutor::create_external(&loop);
    CHECK(ex != nullptr);
    if (!ex) { uv_loop_close(&loop); return; }

    // Contract: the caller installs the wake handle from the driver thread.
    // Without it, posts stay queued by design (nothing is silently dropped).
    ex->initialize_external_wake_handle();

    std::atomic<int> count{0};
    ex->post([&] { count.fetch_add(1); });

    // Drive the loop by hand until the handler ran.
    bool ok = wait_until([&] {
        uv_run(&loop, UV_RUN_NOWAIT);
        return count.load() == 1;
    });

    CHECK(ok);
    CHECK(ex->is_in_loop_thread() == false);   // external mode never claims a thread

    ex->shutdown();      // the loop itself is untouched; only our handle closes
    // uv_close is async: the caller's loop must run for the close callback to fire,
    // otherwise uv_loop_close reports EBUSY. This IS the documented contract.
    int rc = UV_EBUSY;
    for (int i = 0; i < 100; ++i) {
        rc = uv_loop_close(&loop);
        if (rc != UV_EBUSY) break;
        uv_run(&loop, UV_RUN_NOWAIT);
    }
    CHECK(rc == 0);      // still closable by the caller
}

TEST_CASE("cancel state", "[executor]") {
    auto st = std::make_shared<CancelState>();
    CancelHandle h(st);

    CHECK(!h.is_cancelled());
    std::atomic<int> handlers{0};
    st->on_cancel([&] { handlers.fetch_add(1); });
    CHECK(handlers.load() == 0);

    h.cancel();
    CHECK(h.is_cancelled());
    CHECK(handlers.load() == 1);

    // Cancelling twice must not re-run handlers.
    h.cancel();
    CHECK(handlers.load() == 1);

    // Registering after cancellation runs immediately.
    std::atomic<int> late{0};
    st->on_cancel([&] { late.fetch_add(1); });
    CHECK(late.load() == 1);

    // A default-constructed handle is inert, not a crash.
    CancelHandle empty;
    empty.cancel();
    CHECK(!empty.is_cancelled());
    CHECK(!empty.valid());
}

TEST_CASE("shutdown is safe", "[executor]") {
    // shutdown() twice, and after destruction of posted work.
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;
    ex->post([] {});
    ex->shutdown();
    ex->shutdown();
    CHECK(true);   // reaching here without a crash is the assertion
}
