// Phase 5: connection pool tests.
//
// The pool is a data-structure + slot accounting with no network. We use a
// tiny AsyncByteStream that always reports "open" so tests focus on the pool
// logic, not the transport.
#include <megohttp/config.hpp>

#include <catch2/catch_test_macros.hpp>
#include <megohttp/connection_pool.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace megohttp;

namespace {

struct DummyStream : AsyncByteStream {
    void start(ReadyCallback cb) override { if (cb) cb(VoidResult{}); }
    void async_read_some(ReadCallback cb) override {
        if (cb) cb(Result<string_view>{string_view{}});
    }
    void async_write(const uint8_t*, size_t, WriteCallback cb) override {
        if (cb) cb(Result<size_t>{0});
    }
    void async_close(CloseCallback cb) override { open_ = false; if (cb) cb(); }
    bool is_open() const noexcept override { return open_; }
    bool open_{true};
};

struct AcquireResult {
    bool called{false};
    bool ok{false};
    ErrorCode code{ErrorCode::Success};
    uint64_t generation{0};
    std::shared_ptr<AsyncByteStream> stream;
};

AcquireResult acquire_sync(ConnectionPool& pool, const PoolKey& k) {
    AcquireResult out;
    pool.acquire(k, [&out](Result<PooledConnection> r) {
        out.called = true;
        out.ok = static_cast<bool>(r);
        if (!r) out.code = r.error().code();
        else { out.generation = r.value().generation; out.stream = r.value().stream; }
    });
    return out;
}

PoolKey key_for(const char* host, uint16_t port) {
    PoolKey k;
    k.scheme = string("http");
    k.host = string(host);
    k.port = port;
    return k;
}

class NullExecutor : public Executor {
public:
    void post(std::function<void()>) override {}
    std::shared_ptr<Timer> schedule_after(Duration, std::function<void()>) override { return {}; }
    bool is_in_loop_thread() const noexcept override { return true; }
    TimePoint now() const noexcept override { return TimePoint::clock::now(); }
};

} // namespace

// ---- Basic acquire: capacity exists, no idle connection -> NotFound --------

TEST_CASE("acquire with no idle connection and capacity returns NotFound",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 4;
    po.max_connections_per_origin = 2;
    ConnectionPool pool(ex, po);

    auto r = acquire_sync(pool, key_for("example.com", 80));
    REQUIRE(r.called);
    REQUIRE(!r.ok);
    CHECK(r.code == ErrorCode::NotFound);
    // The slot was reserved for the caller to open a new connection.
    CHECK(pool.busy_count() == 1);
}

// ---- Put and re-acquire: a cleanly returned connection is handed out again -

TEST_CASE("returned connection is handed back on next acquire",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 4;
    po.max_connections_per_origin = 2;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto stream = std::make_shared<DummyStream>();
    PooledConnection pc;
    pc.stream = stream;
    pc.key = k;

    pool.put(std::move(pc), true);
    CHECK(pool.idle_count() == 1);
    // The connection occupies a slot but is not "busy" (no exchange owns it).
    CHECK(pool.busy_count() == 0);

    auto r = acquire_sync(pool, k);
    REQUIRE(r.called);
    REQUIRE(r.ok);
    CHECK(r.generation == 1);
    CHECK(r.stream.get() == stream.get());
    CHECK(pool.idle_count() == 0);
    // The idle connection was handed out: it is now busy.
    CHECK(pool.busy_count() == 1);
}

// ---- S2.1-03: a dirty connection must not be pooled ------------------------

TEST_CASE("put with finished_cleanly=false closes the connection",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 4;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto stream = std::make_shared<DummyStream>();
    PooledConnection pc;
    pc.stream = stream;
    pc.key = k;

    pool.put(std::move(pc), false);
    CHECK(pool.idle_count() == 0);
    CHECK(!stream->is_open());
}

// ---- Per-origin limit -------------------------------------------------------

TEST_CASE("per-origin limit prevents extra connections to the same host",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_connections_per_origin = 1;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);

    // First acquire takes the slot.
    auto r1 = acquire_sync(pool, k);
    REQUIRE(r1.called);
    REQUIRE(!r1.ok);
    CHECK(r1.code == ErrorCode::NotFound);
    CHECK(pool.busy_count() == 1);

    // Second acquire to the same key cannot take a slot -> queues.
    auto r2 = acquire_sync(pool, k);
    CHECK(!r2.called);
    CHECK(pool.waiting_count() == 1);

    // Simulate the caller returning the connection they just opened.
    PooledConnection pc;
    pc.key = k;
    pc.stream = std::make_shared<DummyStream>();
    pool.put(std::move(pc), true);

    // serve_waiters runs synchronously inside put(): the waiter is served.
    CHECK(pool.waiting_count() == 0);
    // The waiter got the newly-returned slot (NotFound: open a new one).
    // busy_count is still 1 because the new put took the slot that the first
    // acquire had reserved.
    CHECK(pool.busy_count() == 1);
}

// ---- Total limit ------------------------------------------------------------

TEST_CASE("total limit prevents new connections when max_total_connections is hit",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 2;
    po.max_connections_per_origin = 10;
    ConnectionPool pool(ex, po);

    auto k1 = key_for("a.com", 80);
    auto k2 = key_for("b.com", 80);
    auto k3 = key_for("c.com", 80);

    auto r1 = acquire_sync(pool, k1);
    auto r2 = acquire_sync(pool, k2);
    auto r3 = acquire_sync(pool, k3);

    REQUIRE(r1.called); CHECK(!r1.ok);
    REQUIRE(r2.called); CHECK(!r2.ok);
    // Third acquire: total limit hit (2/2) -> queues.
    CHECK(!r3.called);
    CHECK(pool.waiting_count() == 1);
    CHECK(pool.busy_count() == 2);

    // Release one slot by returning a connection.
    PooledConnection pc;
    pc.key = k1;
    pc.stream = std::make_shared<DummyStream>();
    pool.put(std::move(pc), true);

    // The waiter is served synchronously inside put().
    CHECK(pool.waiting_count() == 0);
    CHECK(pool.busy_count() == 2);  // still 2: one slot freed, one reserved for k3
}

// ---- Wait queue is bounded --------------------------------------------------

TEST_CASE("wait queue is bounded by max_waiting", "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 1;
    po.max_waiting = 2;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto r1 = acquire_sync(pool, k);
    REQUIRE(r1.called);
    CHECK(pool.busy_count() == 1);

    // Second and third acquire queue.
    AcquireResult r2, r3, r4;
    pool.acquire(k, [&r2](Result<PooledConnection> r) {
        r2.called = true; r2.ok = static_cast<bool>(r);
        if (!r) r2.code = r.error().code();
    });
    pool.acquire(k, [&r3](Result<PooledConnection> r) {
        r3.called = true; r3.ok = static_cast<bool>(r);
        if (!r) r3.code = r.error().code();
    });
    // Fourth acquire: queue full -> fail immediately.
    pool.acquire(k, [&r4](Result<PooledConnection> r) {
        r4.called = true; r4.ok = static_cast<bool>(r);
        if (!r) r4.code = r.error().code();
    });

    CHECK(!r2.called);
    CHECK(!r3.called);
    REQUIRE(r4.called);
    REQUIRE(!r4.ok);
    CHECK(r4.code == ErrorCode::PoolExhausted);
    CHECK(pool.waiting_count() == 2);
}

// ---- Idle sweep -------------------------------------------------------------

TEST_CASE("idle connections are swept when they exceed idle_timeout",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.idle_timeout = std::chrono::seconds(10);
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto stream = std::make_shared<DummyStream>();
    PooledConnection pc;
    pc.stream = stream;
    pc.key = k;
    pool.put(std::move(pc), true);
    CHECK(pool.idle_count() == 1);

    // Brand new (put() sets idle_since to now).
    auto now = std::chrono::steady_clock::now();
    CHECK(pool.sweep_idle(now) == 0);

    // Simulate the server closing it while idle.
    stream->async_close(nullptr);
    // Sweep should find the dead one via the !usable() check.
    now = std::chrono::steady_clock::now();
    CHECK(pool.sweep_idle(now) == 1);
    CHECK(pool.idle_count() == 0);
}

// ---- Dead idle connections removed on acquire -------------------------------

TEST_CASE("dead idle connections are removed on acquire", "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 4;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto stream = std::make_shared<DummyStream>();
    PooledConnection pc;
    pc.stream = stream;
    pc.key = k;
    pool.put(std::move(pc), true);

    stream->async_close(nullptr);
    CHECK(pool.idle_count() == 1);

    auto r = acquire_sync(pool, k);
    REQUIRE(r.called);
    REQUIRE(!r.ok);
    CHECK(r.code == ErrorCode::NotFound);
    CHECK(pool.idle_count() == 0);
}

// ---- clear_idle -------------------------------------------------------------

TEST_CASE("clear_idle closes everything", "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    ConnectionPool pool(ex, po);

    std::vector<std::shared_ptr<DummyStream>> streams;
    for (int i = 0; i < 3; ++i) {
        auto k = key_for("example.com", 80 + i);
        auto s = std::make_shared<DummyStream>();
        streams.push_back(s);
        PooledConnection pc;
        pc.stream = s;
        pc.key = k;
        pool.put(std::move(pc), true);
    }
    CHECK(pool.idle_count() == 3);

    pool.clear_idle();
    CHECK(pool.idle_count() == 0);
    for (auto& s : streams) CHECK(!s->is_open());
}

// ---- Key isolation ----------------------------------------------------------

TEST_CASE("different keys are isolated from each other", "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 10;
    ConnectionPool pool(ex, po);

    auto k1 = key_for("a.com", 80);
    auto k2 = key_for("b.com", 443);

    auto s1 = std::make_shared<DummyStream>();
    PooledConnection pc1;
    pc1.stream = s1;
    pc1.key = k1;
    pool.put(std::move(pc1), true);

    auto r = acquire_sync(pool, k2);
    REQUIRE(r.called);
    // k2 must NOT get k1's connection.
    REQUIRE(!r.ok);
    CHECK(r.code == ErrorCode::NotFound);
    CHECK(pool.idle_count() == 1);
}

TEST_CASE("pool key distinguishes http vs https", "[connection_pool]") {
    PoolKey k1 = key_for("example.com", 80);
    k1.scheme = string("http");
    PoolKey k2 = key_for("example.com", 443);
    k2.scheme = string("https");
    CHECK(k1 != k2);
    CHECK(k1.describe() != k2.describe());
}

// ---- fail_waiters -----------------------------------------------------------

TEST_CASE("fail_waiters retires every queued request", "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 1;
    po.max_waiting = 10;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto r1 = acquire_sync(pool, k);
    REQUIRE(r1.called);

    std::vector<AcquireResult> results(5);
    for (int i = 0; i < 5; ++i) {
        auto* p = &results[i];
        pool.acquire(k, [p](Result<PooledConnection> r) {
            p->called = true;
            p->ok = static_cast<bool>(r);
            if (!r) p->code = r.error().code();
        });
    }
    for (int i = 0; i < 5; ++i) CHECK(!results[i].called);

    pool.fail_waiters(ErrorCode::Cancelled, "shutting down");

    for (int i = 0; i < 5; ++i) {
        CHECK(results[i].called);
        REQUIRE(!results[i].ok);
        CHECK(results[i].code == ErrorCode::Cancelled);
    }
    CHECK(pool.waiting_count() == 0);
}

// ---- Serving waiters on put -------------------------------------------------

TEST_CASE("putting a connection back serves the next waiter",
          "[connection_pool]") {
    auto ex = std::make_shared<NullExecutor>();
    PoolOptions po;
    po.max_total_connections = 1;
    po.max_waiting = 10;
    ConnectionPool pool(ex, po);

    auto k = key_for("example.com", 80);
    auto r1 = acquire_sync(pool, k);
    REQUIRE(r1.called);

    // Second acquire queues.
    AcquireResult r2;
    pool.acquire(k, [&r2](Result<PooledConnection> r) {
        r2.called = true;
        r2.ok = static_cast<bool>(r);
        if (!r) r2.code = r.error().code();
        else { r2.generation = r.value().generation; r2.stream = r.value().stream; }
    });
    CHECK(!r2.called);
    CHECK(pool.waiting_count() == 1);

    // Return a connection.
    PooledConnection pc;
    pc.key = k;
    pc.stream = std::make_shared<DummyStream>();
    pool.put(std::move(pc), true);

    // The waiter was served synchronously inside put(). It gets the idle
    // connection we just put back, with the generation bumped from 0 to 1.
    CHECK(r2.called);
    REQUIRE(r2.ok);
    CHECK(r2.generation == 1);
    CHECK(pool.waiting_count() == 0);
}
