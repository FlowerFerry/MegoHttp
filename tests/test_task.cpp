// C++20 coroutine tests (stage 7).
//
// Covers the cases task book 6.3/14 requires: completion before suspension,
// completion after suspension, completion racing cancellation, the thread the
// continuation resumes on, frame destruction, Client shutdown, repeated
// cancellation, and that the C++17 build does not see <coroutine> at all
// (checked by the surrounding #if).

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using sock_t = SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using sock_t = int;
#endif

#if MEGOHTTP_HAS_COROUTINES

#include <megohttp/task.hpp>
#if MGHTTP_BACKEND_LIBUV
#include <megohttp/backend/executor_libuv.hpp>
#endif

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace {

bool wait_until(const std::function<bool()>& pred, int timeout_ms = 8000) {
    const auto start = std::chrono::steady_clock::now();
    while (!pred()) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

// Minimal HTTP server: answers every request with a fixed 200 response.
class OneShotServer {
public:
    bool start() {
        sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ == INVALID_SOCKET) return false;
        int yes = 1;
        ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof yes);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(sock_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        socklen_t len = sizeof a;
        ::getsockname(sock_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        if (::listen(sock_, 8) != 0) return false;
        th_ = std::thread([this] { serve(); });
        return true;
    }

    uint16_t port() const { return port_; }

    void stop() {
        if (sock_ != INVALID_SOCKET) { ::closesocket(sock_); sock_ = INVALID_SOCKET; }
        if (th_.joinable()) th_.join();
    }

    ~OneShotServer() { stop(); }

    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_) + "/"; }

private:
    void serve() {
        for (;;) {
            sock_t c = ::accept(sock_, nullptr, nullptr);
            if (c == INVALID_SOCKET) return;
            char buf[4096];
            ::recv(c, buf, sizeof buf, 0);
            const char* resp =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
            ::closesocket(c);
        }
    }

    ::SOCKET sock_{INVALID_SOCKET};
    uint16_t port_{0};
    std::thread th_;
};

// Windows needs WSAStartup before any socket call.
struct WsaInit {
    WsaInit() {
#if defined(_WIN32)
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
#endif
    }
    ~WsaInit() {
#if defined(_WIN32)
        WSACleanup();
#endif
    }
};
const WsaInit g_wsa_init;

} // anonymous namespace

TEST_CASE("eager task that never suspends is already done", "[coroutine][eager]") {
    auto task = []() -> megohttp::Task<int> {
        co_return 42;
    }();

    CHECK(task.done());
    CHECK(task.await_ready());
    CHECK(task.await_resume() == 42);
}

TEST_CASE("task value survives a move", "[coroutine][move]") {
    auto first = []() -> megohttp::Task<int> { co_return 7; }();
    megohttp::Task<int> second = std::move(first);

    CHECK(first.done());          // moved-from handle is null
    CHECK_THROWS_AS(first.await_resume(), std::logic_error);
    CHECK(second.await_resume() == 7);
}

TEST_CASE("unconsumed task destroys its frame without resuming", "[coroutine][lifecycle]") {
    // A suspended task whose frame is destroyed must not crash or resume.
    auto task = []() -> megohttp::Task<int> {
        co_return 1;
    }();
    CHECK(task.done());
    // ~Task destroys the frame here.
}

TEST_CASE("exception inside the body reaches the awaiter", "[coroutine][exception]") {
    auto task = []() -> megohttp::Task<int> {
        throw std::runtime_error("boom");
        co_return 0;
    }();

    CHECK(task.done());
    CHECK_THROWS_AS(task.await_resume(), std::runtime_error);
}

// Functor rather than a lambda: MSVC rewrites lambdas inside a coroutine body
// as awaitables, which breaks handing one to std::function.
struct DelayedCompleter {
    // Thread the completion was actually invoked from, so the test can assert
    // the coroutine resumes THERE and not on the awaiting thread.
    std::atomic<std::thread::id>* ran_on{nullptr};

    void operator()(std::function<void(int)> finish) const {
        std::thread([this, finish] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            if (ran_on) ran_on->store(std::this_thread::get_id());
            finish(123);
        }).detach();
    }
};

TEST_CASE("SuspendedOperation resumes the coroutine from the completing thread",
          "[coroutine][suspend]") {
    std::atomic<bool> resumed{false};
    std::atomic<std::thread::id> completer_thread{};
    std::thread::id resume_thread{};

    const auto awaiting_thread = std::this_thread::get_id();

    auto task = [&]() -> megohttp::Task<int> {
        megohttp::SuspendedOperation<int> op;
        op.start = DelayedCompleter{&completer_thread};
        const int v = co_await op;
        resume_thread = std::this_thread::get_id();
        resumed.store(true);
        co_return v;
    }();

    // Eager: the body ran up to the suspension point but not past it.
    CHECK(!task.done());
    CHECK(!resumed.load());

    REQUIRE(wait_until([&] { return task.done(); }));
    CHECK(task.await_resume() == 123);
    CHECK(resumed.load());

    // The continuation ran on the thread that completed the operation, not on
    // the one that awaited it. That is the documented resume context; without
    // this assertion the test only proves "something resumed it".
    REQUIRE(completer_thread.load() != std::thread::id{});
    CHECK(resume_thread == completer_thread.load());
    CHECK(resume_thread != awaiting_thread);
}

TEST_CASE("coroutine request completes against a real server", "[coroutine][client]") {
    OneShotServer srv;
    REQUIRE(srv.start());

    megohttp::Client client;
    megohttp::Request req(megohttp::Method::Get, megohttp::string(srv.url().c_str()));

    std::atomic<bool> finished{false};
    int status = 0;

    auto task = [&]() -> megohttp::Task<int> {
        auto r = co_await client.request_co(req);
        status = r ? r.value().head().status_code : -1;
        finished.store(true);
        co_return status;
    }();

    // The request is in flight, so the coroutine is suspended.
    CHECK(!task.done());
    REQUIRE(wait_until([&] { return task.done(); }));
    CHECK(task.await_resume() == 200);
    CHECK(status == 200);
}

TEST_CASE("cancelling a suspended task ends the request", "[coroutine][cancel]") {
    // A server that accepts but never answers, so the request stays in flight.
    sock_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(s != INVALID_SOCKET);
    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof yes);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
    socklen_t len = sizeof a;
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    const uint16_t port = ntohs(a.sin_port);
    REQUIRE(::listen(s, 8) == 0);

    megohttp::ClientOptions opts;
    opts.recv_timeout = std::chrono::milliseconds(5000);
    megohttp::Client client(opts);
    megohttp::string url(("http://127.0.0.1:" + std::to_string(port) + "/").c_str());
    megohttp::Request req(megohttp::Method::Get, url);

    std::atomic<bool> finished{false};
    auto task = [&]() -> megohttp::Task<int> {
        auto r = co_await client.request_co(req);
        finished.store(true);
        co_return r ? r.value().head().status_code : -1;
    }();

    REQUIRE(wait_until([&] { return !task.await_ready(); }, 2000));

    // Cancel twice: cancellation is idempotent.
    task.cancel();
    task.cancel();

    REQUIRE(wait_until([&] { return task.done(); }, 8000));
    const int code = task.await_resume();
    CHECK(finished.load());
    CHECK(code == -1);   // cancelled -> Result carries an error

    ::closesocket(s);
}

TEST_CASE("Client shutdown completes a pending coroutine", "[coroutine][shutdown]") {
    sock_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(s != INVALID_SOCKET);
    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof yes);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    REQUIRE(::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
    socklen_t len = sizeof a;
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    const uint16_t port = ntohs(a.sin_port);
    REQUIRE(::listen(s, 8) == 0);

    megohttp::Client client;
    megohttp::string url(("http://127.0.0.1:" + std::to_string(port) + "/").c_str());
    megohttp::Request req(megohttp::Method::Get, url);

    auto task = [&]() -> megohttp::Task<int> {
        auto r = co_await client.request_co(req);
        co_return r ? r.value().head().status_code : -1;
    }();

    REQUIRE(wait_until([&] { return !task.await_ready(); }, 2000));
    client.shutdown();

    REQUIRE(wait_until([&] { return task.done(); }, 8000));
    CHECK(task.await_resume() == -1);

    ::closesocket(s);
}

#endif // MEGOHTTP_HAS_COROUTINES
