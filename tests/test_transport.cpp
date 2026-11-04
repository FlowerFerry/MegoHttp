// TcpStream / resolver tests against a local, self-hosted TCP echo server.
// No public network access is required or assumed.
//
// Threading contract exercised here: AsyncByteStream is NOT thread-safe, so every
// stream call is issued from the loop thread (the documented pattern for the
// higher layers too).
#include <catch_amalgamated.hpp>

#include <megohttp/config.hpp>
#include <megohttp/format.hpp>
#include <megohttp/resolver.hpp>
#include <megohttp/transport.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#if defined(_WIN32)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#else
#   include <arpa/inet.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#   include <unistd.h>
#endif

using namespace MegoHttp;
using namespace MegoHttp::libuv_backend;


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

// A tiny blocking TCP echo server, sharing no code with the client under test so a
// bug on one side cannot mask a bug on the other.
class EchoServer {
public:
    bool start() {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ == INVALID_SOCKET) return false;
        int one = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&one), sizeof one);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;   // OS picks the port, so tests never collide
        if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) return false;
        if (::listen(sock_, 8) != 0) return false;

        socklen_t len = sizeof addr;
        if (::getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return false;
        port_ = ntohs(addr.sin_port);

        thread_ = std::thread([this] { serve(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }
    int accepted() const noexcept { return accepted_.load(); }
    int closed() const noexcept { return closed_.load(); }

    void stop() {
        stop_.store(true);
        if (sock_ != INVALID_SOCKET) {
            ::shutdown(sock_, 2);
#if defined(_WIN32)
            closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~EchoServer() { stop(); }

private:
    void serve() {
        for (;;) {
            if (stop_.load()) return;
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            accepted_.fetch_add(1);
            char buf[4096];
            for (;;) {
                const int n = ::recv(c, buf, sizeof buf, 0);
                if (n <= 0) break;
                int sent = 0;
                while (sent < n) {
                    const int w = ::send(c, buf + sent, n - sent, 0);
                    if (w <= 0) break;
                    sent += w;
                }
            }
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
            closed_.fetch_add(1);
            if (stop_.load()) return;
        }
    }

    std::atomic<int> accepted_{0};
    std::atomic<int> closed_{0};

#if defined(_WIN32)
    SOCKET sock_{INVALID_SOCKET};
#else
    int sock_{-1};
#endif
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

TEST_CASE("resolve literal", "[transport]") {
    auto v4 = parse_ip_literal("127.0.0.1", 8080);
    CHECK(v4.size() == 1);
    if (!v4.empty()) {
        CHECK(v4[0].family == ResolvedAddress::Family::IPv4);
        CHECK(v4[0].port == 8080);
        CHECK(v4[0].bytes.size() == 4);
    }
    auto v6 = parse_ip_literal("::1", 443);
    CHECK(v6.size() == 1);
    if (!v6.empty()) {
        CHECK(v6[0].family == ResolvedAddress::Family::IPv6);
        CHECK(v6[0].bytes.size() == 16);
    }
    CHECK(parse_ip_literal("[::1]", 443).size() == 1);
    CHECK(parse_ip_literal("example.com", 80).empty());
}

TEST_CASE("static resolver", "[transport]") {
    auto ex = UvExecutor::create_internal();
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
    std::atomic<bool> ok{false};
    uint16_t got_port = 0;

    r->resolve("anything.test", 9999, [&](Result<AddressList> res) {
        ok.store(res.has_value());
        if (res && !res.value().empty()) got_port = res.value()[0].port;
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(ok.load());
    CHECK(got_port == 9999);
    ex->shutdown();
}

TEST_CASE("system resolver literal fast path", "[transport]") {
    auto ex = UvExecutor::create_internal();
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

TEST_CASE("chained resolver", "[transport]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    // First link answers nothing, second answers: the chain must use the second
    // rather than reporting the first link's failure.
    auto empty = std::make_shared<StaticResolver>(ex, AddressList{});
    AddressList answers;
    ResolvedAddress a;
    a.family = ResolvedAddress::Family::IPv4;
    a.text = "198.51.100.7";
    a.bytes = {198, 51, 100, 7};
    answers.push_back(a);
    auto good = std::make_shared<StaticResolver>(ex, answers);

    auto chain = std::make_shared<ChainedResolver>(
        std::vector<std::shared_ptr<Resolver>>{empty, good});

    std::atomic<bool> done{false};
    std::atomic<int> count{-1};
    chain->resolve("x.test", 80, [&](Result<AddressList> res) {
        count.store(res ? static_cast<int>(res.value().size()) : -1);
        done.store(true);
    });
    CHECK(wait_until([&] { return done.load(); }));
    CHECK(count.load() == 1);
    ex->shutdown();
}

TEST_CASE("tcp connect and echo", "[transport]") {
    EchoServer server;
    if (!server.start()) {
        std::printf("SKIP: could not start the local echo server\n");
        return;
    }

    auto ex = UvExecutor::create_internal();
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
    static const char* kMsg = "hello tcp";
    const size_t kLen = std::strlen(kMsg);

    // Every stream call is issued from the loop thread, chained through callbacks.
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

TEST_CASE("tcp connect refused", "[transport]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    // A fixed high port that nothing listens on. A "just released" port is NOT a
    // reliable choice: the socket can still be in TIME_WAIT and accept the connect.
    constexpr uint16_t kDeadPort = 65535;

    ResolvedAddress target;
    target.family = ResolvedAddress::Family::IPv4;
    target.bytes = {127, 0, 0, 1};
    target.port = kDeadPort;

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

TEST_CASE("connect race", "[transport]") {
    EchoServer server;
    if (!server.start()) {
        std::printf("SKIP: could not start the local echo server\n");
        return;
    }
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) { server.stop(); return; }

    // First entry is dead, second is the live server: the race must not stop at the
    // first failure.
    ResolvedAddress dead;
    dead.family = ResolvedAddress::Family::IPv4;
    dead.bytes = {127, 0, 0, 1};
    dead.port = 65535;   // verified closed on this host

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
        if (r && r.value()) r.value()->async_close(nullptr);
    });

    CHECK(wait_until([&] { return done.load(); }, 10000));
    CHECK(ok.load());
    ex->shutdown();
    server.stop();
}

// ---------------------------------------------------------------------------
// Race terminal semantics.
//
// What connect_race can actually be held to, observable from outside:
//   • exactly one terminal callback, whether attempts succeed or all fail
//   • no callback after the terminal one
//   • the winner stream is usable (an echo actually round-trips)
//
// The loser-close path lives inside race_finish and is not observable from here;
// what IS observable is that a late attempt never produces a second terminal.
// ---------------------------------------------------------------------------

// Both addresses reach a live server. Only one terminal callback, and the
// returned stream must be usable for real I/O.
TEST_CASE("race one winner usable", "[transport]") {
    EchoServer srvA;
    CHECK(srvA.start());
    EchoServer srvB;
    CHECK(srvB.start());
    if (srvA.port() == 0 || srvB.port() == 0) { srvA.stop(); srvB.stop(); return; }

    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) { srvA.stop(); srvB.stop(); return; }

    ResolvedAddress first;
    first.family = ResolvedAddress::Family::IPv4;
    first.bytes = {127, 0, 0, 1};
    first.port = srvA.port();
    ResolvedAddress second = first;
    second.port = srvB.port();

    AddressList list{first, second};

    ConnectOptions opts;
    opts.connect_timeout = std::chrono::seconds(10);
    opts.attempt_delay = std::chrono::milliseconds(300);   // real gap

    std::atomic<int> cb_count{0};
    std::atomic<bool> winner_ok{false};
    std::atomic<bool> echo_ok{false};
    static const char* kMsg = "race";
    const size_t kLen = std::strlen(kMsg);
    uint8_t buf[32] = {0};

    connect_race(ex, list, opts,
        [&](Result<std::shared_ptr<AsyncByteStream>> r) {
            cb_count.fetch_add(1);
            if (!r || !r.value()) return;
            auto s = r.value();
            winner_ok.store(s->is_open());
            s->async_write(reinterpret_cast<const uint8_t*>(kMsg), kLen,
                [&, s](Result<size_t> w) {
                    if (!w) return;
                    s->async_read_some(buf, sizeof buf, [&, s](Result<size_t> rd) {
                        if (rd && rd.value() == kLen &&
                            std::memcmp(buf, kMsg, kLen) == 0) {
                            echo_ok.store(true);
                        }
                        s->async_close(nullptr);
                    });
                });
        });

    CHECK(wait_until([&] { return cb_count.load() > 0; }, 10000));
    CHECK(winner_ok.load());

    // A late second attempt must never produce another terminal callback.
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    CHECK(cb_count.load() == 1);

    CHECK(wait_until([&] { return echo_ok.load(); }, 5000));

    ex->shutdown();
    srvA.stop();
    srvB.stop();
}

// Every address fails: exactly one error terminal, and no second callback.
TEST_CASE("race single terminal error", "[transport]") {
    auto ex = UvExecutor::create_internal();
    CHECK(ex != nullptr);
    if (!ex) return;

    ResolvedAddress a;
    a.family = ResolvedAddress::Family::IPv4;
    a.bytes = {127, 0, 0, 1};
    a.port = 65534;      // verified closed on this host
    ResolvedAddress b = a;
    b.port = 65535;

    AddressList list{a, b};

    ConnectOptions opts;
    opts.connect_timeout = std::chrono::seconds(5);
    opts.attempt_delay = std::chrono::milliseconds(50);

    std::atomic<int> cb_count{0};
    std::atomic<bool> had_error{false};

    connect_race(ex, list, opts,
        [&](Result<std::shared_ptr<AsyncByteStream>> r) {
            cb_count.fetch_add(1);
            had_error.store(!r.has_value());
        });

    CHECK(wait_until([&] { return cb_count.load() > 0; }, 10000));
    CHECK(had_error.load());
    // Any further callback would be a duplicate terminal.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK(cb_count.load() == 1);

    ex->shutdown();
}


// ---------------------------------------------------------------------------
// Race loser close.
//
// To reach race_finish's loser branch both attempts must be IN FLIGHT at the
// same time and BOTH must connect: the first to report wins, the second must be
// closed. With attempt_delay == 0 every attempt is posted on the next loop turn,
// so both really do connect.
//
// Observable from outside, without touching library internals:
//   • each server counts how many connections it accepted and how many it saw
//     close
//   • exactly one terminal callback
//   • after the race ends, the LOSER server must observe its connection closed
// ---------------------------------------------------------------------------
TEST_CASE("race closes loser", "[transport]") {
    EchoServer srvA;
    CHECK(srvA.start());
    EchoServer srvB;
    CHECK(srvB.start());
    if (srvA.port() == 0 || srvB.port() == 0) { srvA.stop(); srvB.stop(); return; }

    auto ex = UvExecutor::create_internal();
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
    // 0 => every attempt is posted on the next loop turn, so both connect.
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

    // Both servers must have accepted a connection: that is what makes one of
    // them the loser rather than "an attempt that never happened".
    CHECK((wait_until([&] { return srvA.accepted() == 1 && srvB.accepted() == 1; }, 5000)));
    CHECK(srvA.accepted() == 1);
    CHECK(srvB.accepted() == 1);

    // The loser is closed by race_finish, so exactly ONE server should see its
    // connection drop BEFORE we close the winner ourselves.
    const bool one_closed =
        wait_until([&] { return srvA.closed() + srvB.closed() == 1; }, 5000);
    CHECK(one_closed);
    CHECK(srvA.closed() + srvB.closed() == 1);

    // Now close the winner; the second server should observe its close too.
    if (winner) ex->post([winner] { winner->async_close(nullptr); });
    CHECK((wait_until([&] { return srvA.closed() == 1 && srvB.closed() == 1; }, 5000)));
    CHECK(srvA.closed() == 1);
    CHECK(srvB.closed() == 1);

    ex->shutdown();
    srvA.stop();
    srvB.stop();
}
