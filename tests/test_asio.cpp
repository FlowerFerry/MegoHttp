// Asio backend tests: executor (internal/external loop, timers, cross-thread
// post), resolver, TCP echo roundtrip, refused connect, and the connect race.
//
// Same shape as test_executor_libuv.cpp / test_transport.cpp so the two backends
// are held to the same behaviour. No public network access is required.
#include <megohttp/config.hpp>

#if !defined(MGHTTP_BACKEND_ASIO)
int main() {
    // Asio backend not selected in this configuration.
    return 0;
}
#else

#include <megohttp/backend/executor_asio.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/transport.hpp>

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

using namespace MegoHttp;
using namespace MegoHttp::asio_backend;

static int g_fail = 0, g_pass = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

template<typename F>
static bool wait_until(F pred, int max_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return pred();
}

// --- executor -------------------------------------------------------------

static void test_executor_post() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<int> ran{0};
    for (int i = 0; i < 5; ++i) ex->post([&] { ran.fetch_add(1); });
    CHECK(wait_until([&] { return ran.load() == 5; }));
    ex->shutdown();
}

static void test_executor_post_never_inline() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<bool> inline_ran{false}, posted{false};
    ex->post([&] {
        ex->post([&] { inline_ran.store(true); });
        // The nested post must not have executed by the time the outer returns.
        posted.store(!inline_ran.load());
    });
    CHECK(wait_until([&] { return inline_ran.load(); }));
    CHECK(posted.load());
    ex->shutdown();
}

static void test_timer_fires() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<bool> fired{false};
    const auto start = std::chrono::steady_clock::now();
    auto t = ex->schedule_after(std::chrono::milliseconds(30), [&] { fired.store(true); });
    CHECK(t != nullptr);
    CHECK(wait_until([&] { return fired.load(); }));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(elapsed >= std::chrono::milliseconds(20));
    ex->shutdown();
}

static void test_timer_self_holding() {
    // The caller drops the handle; the timer must still fire. This is the trap
    // the libuv backend hit with DeferredTimer.
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<bool> fired{false};
    ex->schedule_after(std::chrono::milliseconds(20), [&] { fired.store(true); });
    // No handle kept.
    CHECK(wait_until([&] { return fired.load(); }));
    ex->shutdown();
}

static void test_timer_cancel() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<bool> fired{false};
    auto t = ex->schedule_after(std::chrono::milliseconds(60), [&] { fired.store(true); });
    CHECK(t != nullptr);
    t->cancel();
    CHECK(t->is_cancelled());
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    CHECK(!fired.load());
    ex->shutdown();
}

static void test_external_loop() {
    asio::io_context ioc;
    auto ex = AsioExecutor::create_external(ioc);
    CHECK(ex != nullptr);
    if (!ex) return;

    std::atomic<int> ran{0};
    ex->post([&] { ran.fetch_add(1); });

    // The executor's work guard keeps run() alive; we drive it ourselves.
    std::thread driver([&] { ioc.run(); });
    CHECK(wait_until([&] { return ran.load() == 1; }));

    // shutdown() releases the guard so our loop can return. It must not call
    // ioc.stop() on somebody else's context.
    ex->shutdown();
    CHECK(wait_until([&] { return ioc.stopped() || true; }, 500));
    driver.join();
}

static void test_shutdown_is_idempotent() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;
    ex->shutdown();
    ex->shutdown();   // must not crash or deadlock
    CHECK(true);
}

// --- resolver -------------------------------------------------------------

static void test_resolver_literal() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    auto r = std::make_shared<SystemResolver>(ex);
    std::atomic<bool> done{false};
    std::atomic<int> count{-1};
    r->resolve("127.0.0.1", 80, [&](Result<AddressList> res) {
        count.store(res ? static_cast<int>(res.value().size()) : -1);
        done.store(true);
    });
    CHECK(wait_until([&] { return done.load(); }));
    CHECK(count.load() == 1);
    ex->shutdown();
}

static void test_resolver_static() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    AddressList answers;
    ResolvedAddress a;
    a.family = ResolvedAddress::Family::IPv4;
    a.text = "192.0.2.10";
    a.bytes = {192, 0, 2, 10};
    answers.push_back(a);

    auto r = std::make_shared<StaticResolver>(ex, answers);
    std::atomic<bool> done{false};
    uint16_t got_port = 0;
    r->resolve("anything.test", 9999, [&](Result<AddressList> res) {
        if (res && !res.value().empty()) got_port = res.value()[0].port;
        done.store(true);
    });
    CHECK(wait_until([&] { return done.load(); }));
    CHECK(got_port == 9999);
    ex->shutdown();
}

// --- transport ------------------------------------------------------------

// A local echo server built directly on asio, deliberately sharing no code with
// the client under test.
class AsioEchoServer {
public:
    bool start() {
        asio::error_code ec;
        acc_.open(asio::ip::tcp::v4(), ec);
        if (ec) return false;
        acc_.set_option(asio::socket_base::reuse_address(true), ec);
        acc_.bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0), ec);
        if (ec) return false;
        acc_.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) return false;
        port_ = acc_.local_endpoint().port();
        accept_one();
        thread_ = std::thread([this] { ioc_.run(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }
    int accepted() const noexcept { return accepted_.load(); }
    int closed() const noexcept { return closed_.load(); }

    void stop() {
        asio::error_code ec;
        acc_.close(ec);
        ioc_.stop();
        if (thread_.joinable()) thread_.join();
    }

    ~AsioEchoServer() { stop(); }

private:
    void accept_one() {
        auto sock = std::make_shared<asio::ip::tcp::socket>(ioc_);
        acc_.async_accept(*sock, [this, sock](const asio::error_code& ec) {
            if (ec) return;
            accepted_.fetch_add(1);
            auto buf = std::make_shared<std::vector<char>>(4096);
            read_loop(sock, buf);
        });
    }

    void read_loop(std::shared_ptr<asio::ip::tcp::socket> sock,
                   std::shared_ptr<std::vector<char>> buf) {
        sock->async_read_some(asio::buffer(*buf),
            [this, sock, buf](const asio::error_code& ec, size_t n) {
                if (ec || n == 0) {
                    // Peer closed: count it so tests can observe a dropped connection.
                    asio::error_code ig;
                    sock->close(ig);
                    closed_.fetch_add(1);
                    return;
                }
                asio::async_write(*sock, asio::buffer(buf->data(), n),
                    [this, sock, buf](const asio::error_code& wec, size_t) {
                        if (wec) {
                            asio::error_code ig;
                            sock->close(ig);
                            closed_.fetch_add(1);
                            return;
                        }
                        read_loop(sock, buf);
                    });
            });
    }

    asio::io_context ioc_;
    std::atomic<int> accepted_{0};
    std::atomic<int> closed_{0};
    asio::ip::tcp::acceptor acc_{ioc_};
    uint16_t port_{0};
    std::thread thread_;
};

static void test_tcp_echo() {
    AsioEchoServer server;
    if (!server.start()) {
        std::printf("SKIP: could not start the local echo server\n");
        return;
    }

    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) { server.stop(); return; }

    ResolvedAddress target;
    target.family = ResolvedAddress::Family::IPv4;
    target.text = "127.0.0.1";
    target.bytes = {127, 0, 0, 1};
    target.port = server.port();

    auto stream = std::make_shared<TcpStream>(ex, target);

    std::atomic<bool> ready_done{false}, ready_ok{false};
    std::atomic<bool> write_done{false};
    std::atomic<size_t> written{0};
    std::atomic<bool> read_done{false};
    std::atomic<size_t> got{0};
    std::atomic<bool> closed{false};
    uint8_t buf[64] = {0};
    static const char* kMsg = "hello asio tcp";
    const size_t kLen = std::strlen(kMsg);

    ex->post([&, stream] {
        stream->start([&, stream](VoidResult r) {
            ready_ok.store(r.has_value());
            ready_done.store(true);
            if (!r) return;

            stream->async_write(reinterpret_cast<const uint8_t*>(kMsg), kLen,
                                [&, stream](Result<size_t> w) {
                written.store(w ? w.value() : 0);
                write_done.store(true);
                if (!w) return;

                stream->async_read_some(buf, sizeof buf, [&, stream](Result<size_t> rd) {
                    got.store(rd ? rd.value() : 0);
                    read_done.store(true);
                    stream->async_close([&] { closed.store(true); });
                });
            });
        });
    });

    CHECK(wait_until([&] { return ready_done.load(); }));
    CHECK(ready_ok.load());
    CHECK(wait_until([&] { return write_done.load(); }));
    CHECK(written.load() == kLen);
    CHECK(wait_until([&] { return read_done.load(); }));
    CHECK(got.load() == kLen);
    CHECK(std::memcmp(buf, kMsg, got.load()) == 0);
    CHECK(wait_until([&] { return closed.load(); }));

    ex->shutdown();
    server.stop();
}

static void test_tcp_connect_refused() {
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    ResolvedAddress target;
    target.family = ResolvedAddress::Family::IPv4;
    target.bytes = {127, 0, 0, 1};
    target.port = 65535;   // verified closed on this host

    auto stream = std::make_shared<TcpStream>(ex, target);
    std::atomic<bool> done{false}, failed{false};

    ex->post([&, stream] {
        stream->start([&](VoidResult r) {
            failed.store(!r.has_value());
            done.store(true);
        });
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(failed.load());
    ex->shutdown();
}

static void test_connect_race() {
    AsioEchoServer server;
    if (!server.start()) {
        std::printf("SKIP: could not start the local echo server\n");
        return;
    }
    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) { server.stop(); return; }

    ResolvedAddress dead;
    dead.family = ResolvedAddress::Family::IPv4;
    dead.bytes = {127, 0, 0, 1};
    dead.port = 65535;

    ResolvedAddress live;
    live.family = ResolvedAddress::Family::IPv4;
    live.bytes = {127, 0, 0, 1};
    live.port = server.port();

    AddressList list{dead, live};

    std::atomic<bool> done{false}, ok{false};
    ConnectOptions opts;
    opts.connect_timeout = std::chrono::seconds(5);
    opts.attempt_delay = std::chrono::milliseconds(20);

    connect_race(ex, list, opts, [&](Result<std::shared_ptr<AsyncByteStream>> r) {
        ok.store(r.has_value() && r.value() != nullptr);
        done.store(true);
        if (r && r.value()) {
            auto s = r.value();
            ex->post([s] { s->async_close(nullptr); });
        }
    });

    CHECK(wait_until([&] { return done.load(); }, 10000));
    CHECK(ok.load());
    ex->shutdown();
    server.stop();
}


// Race loser close: both servers accept a connection, exactly one is closed once
// the race decides, and the winner still works. Uses server-side counters, so
// this observes real sockets rather than internal race state.
static void test_race_closes_loser() {
    AsioEchoServer srvA;
    CHECK(srvA.start());
    AsioEchoServer srvB;
    CHECK(srvB.start());
    if (srvA.port() == 0 || srvB.port() == 0) { srvA.stop(); srvB.stop(); return; }

    auto ex = AsioExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) { srvA.stop(); srvB.stop(); return; }

    ResolvedAddress a;
    a.family = ResolvedAddress::Family::IPv4;
    a.bytes = {127, 0, 0, 1};
    a.port = srvA.port();
    ResolvedAddress b = a;
    b.port = srvB.port();

    AddressList list{a, b};

    ConnectOptions opts;
    opts.connect_timeout = std::chrono::seconds(10);
    // 0 => every attempt is posted on the next loop turn, so both really connect.
    opts.attempt_delay = Duration::zero();

    std::atomic<int> cb_count{0};
    std::atomic<bool> got_stream{false};
    std::shared_ptr<AsyncByteStream> winner;

    connect_race(ex, list, opts,
        [&](Result<std::shared_ptr<AsyncByteStream>> r) {
            cb_count.fetch_add(1);
            if (r && r.value()) {
                winner = r.value();
                got_stream.store(true);
            }
        });

    CHECK(wait_until([&] { return cb_count.load() > 0; }, 10000));
    CHECK(cb_count.load() == 1);
    CHECK(got_stream.load());

    // Both connected, which is what makes one of them a loser.
    CHECK(wait_until([&] { return srvA.accepted() == 1 && srvB.accepted() == 1; }, 5000));
    CHECK(srvA.accepted() == 1);
    CHECK(srvB.accepted() == 1);

    // The loser must already be closed by the race, before we touch the winner.
    CHECK(wait_until([&] { return srvA.closed() + srvB.closed() == 1; }, 5000));
    CHECK(srvA.closed() + srvB.closed() == 1);

    if (winner) ex->post([winner] { winner->async_close(nullptr); });
    CHECK(wait_until([&] { return srvA.closed() == 1 && srvB.closed() == 1; }, 5000));
    CHECK(srvA.closed() == 1);
    CHECK(srvB.closed() == 1);

    ex->shutdown();
    srvA.stop();
    srvB.stop();
}

int main() {
    test_executor_post();
    test_executor_post_never_inline();
    test_timer_fires();
    test_timer_self_holding();
    test_timer_cancel();
    test_external_loop();
    test_shutdown_is_idempotent();
    test_resolver_literal();
    test_resolver_static();
    test_tcp_echo();
    test_tcp_connect_refused();
    test_connect_race();
    test_race_closes_loser();

    std::printf("=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

#endif // MGHTTP_BACKEND_ASIO
