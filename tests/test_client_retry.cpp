// Phase 5 S5.3: retry through the public Client.
//
// test_retry proves the decision table. This proves the decision is actually
// wired to the request pipeline: that a retry really re-sends, that the backoff
// really waits, and that the cases which must NOT retry never re-send.
//
// The load-bearing evidence is the SERVER's request count. Asserting only on the
// final Result would pass equally well for a client that retried and one that
// did not, whenever the second attempt also succeeded.
#include <megohttp/config.hpp>
#include <megohttp/client.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#else
#   include <arpa/inet.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#   include <unistd.h>
#endif

using namespace megohttp;

namespace {

// Scripted server that can either answer or drop the connection, so "the
// transport failed" and "the server answered" are both reproducible.
class ScriptServer {
public:
    enum class Action {
        Respond,        // 200 with a short body
        DropBeforeReply // close immediately, no bytes
        ,
        Respond503,     // 503 + Retry-After, so the status path is exercised
        Respond503NoRA  // 503 with no Retry-After
    };

    bool start(std::vector<Action> script) {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        script_ = std::move(script);
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!valid(listen_)) return false;
        int on = 1;
        ::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&on), sizeof on);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::bind(listen_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        if (::listen(listen_, 16) != 0) return false;
        sockaddr_in got{};
        socklen_t glen = sizeof got;
        ::getsockname(listen_, reinterpret_cast<sockaddr*>(&got), &glen);
        port_ = ntohs(got.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }
    int connections() const { return connections_.load(); }

    ~ScriptServer() { stop(); }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (valid(listen_)) { closesock(listen_); listen_ = invalid(); }
        if (thread_.joinable()) thread_.join();
    }

private:
#if defined(_WIN32)
    using sock_t = SOCKET;
    static sock_t invalid() { return INVALID_SOCKET; }
    static bool valid(sock_t s) { return s != INVALID_SOCKET; }
    static void closesock(sock_t s) { ::closesocket(s); }
#else
    using sock_t = int;
    static sock_t invalid() { return -1; }
    static bool valid(sock_t s) { return s >= 0; }
    static void closesock(sock_t s) { ::close(s); }
#endif

    void run() {
        while (!stopped_.load()) {
            sock_t c = ::accept(listen_, nullptr, nullptr);
            if (!valid(c)) return;
            const int idx = connections_.fetch_add(1);
            Action act = Action::Respond;
            {
                std::lock_guard<std::mutex> lk(m_);
                if (idx < static_cast<int>(script_.size())) act = script_[static_cast<size_t>(idx)];
            }
            std::thread([this, c, act] { serve(c, act); }).detach();
        }
    }

    void serve(sock_t c, Action act) {
        // Read the request head so the client's write completes before we act.
        std::string head;
        char ch = 0;
        while (head.size() < 32 * 1024) {
            int n = static_cast<int>(::recv(c, &ch, 1, 0));
            if (n <= 0) break;
            head += ch;
            if (head.size() >= 4 && head.compare(head.size() - 4, 4, "\r\n\r\n") == 0) break;
        }
        // Drain the request body before answering. A client still writing a POST
        // body would otherwise see a reset when this socket closes, and the test
        // would then measure that write race instead of the retry decision.
        // Field names are matched case-insensitively (RFC 7230 3.2): the client
        // sends them lowercase, so a case-sensitive lookup silently finds nothing.
        {
            size_t cl = 0;
            size_t line = 0;
            while (line < head.size()) {
                size_t eol = head.find("\r\n", line);
                if (eol == std::string::npos) eol = head.size();
                size_t colon = head.find(':', line);
                if (colon != std::string::npos && colon < eol) {
                    std::string name = head.substr(line, colon - line);
                    for (char& x : name) {
                        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x + 32);
                    }
                    if (name == "content-length") {
                        cl = static_cast<size_t>(strtoull(head.c_str() + colon + 1, nullptr, 10));
                    }
                }
                line = eol + 2;
            }
            size_t got = 0;
            char buf[4096];
            while (got < cl) {
                size_t want = cl - got < sizeof buf ? cl - got : sizeof buf;
                int n = static_cast<int>(::recv(c, buf, static_cast<int>(want), 0));
                if (n <= 0) break;
                got += static_cast<size_t>(n);
            }
        }

        if (act == Action::DropBeforeReply) {
            // Abrupt close: the client sees a reset with no response head.
            closesock(c);
            return;
        }

        if (act == Action::Respond503 || act == Action::Respond503NoRA) {
            const std::string resp =
                std::string("HTTP/1.1 503 Service Unavailable\r\n") +
                (act == Action::Respond503 ? "Retry-After: 1\r\n" : "") +
                "Content-Length: 4\r\nConnection: close\r\n\r\nbusy";
            ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
            closesock(c);
            return;
        }
        const char* body = "ok";
        const std::string resp = std::string("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n") +
                                 "Connection: close\r\n\r\n" + body;
        ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
        closesock(c);
    }

    sock_t listen_{invalid()};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    std::atomic<int> connections_{0};
    std::vector<Action> script_;
    std::mutex m_;
    std::thread thread_;
};

// Returns the library's own string type: Request takes a string_view and the
// alias differs per build mode, so building it here keeps call sites readable.
string url_on(uint16_t port) {
    const std::string s = "http://127.0.0.1:" + std::to_string(port) + "/";
    return string(s.data(), s.size());
}

bool wait_for(std::function<bool()> pred, int max_ms = 8000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

ClientOptions retrying(size_t max_retries, bool jitter = false) {
    ClientOptions o;
    o.retry.max_retries = max_retries;
    o.retry.base_delay = std::chrono::milliseconds(30);
    o.retry.max_delay = std::chrono::milliseconds(120);
    o.retry.jitter = jitter;
    o.retry.retry_non_idempotent = false;
    return o;
}

} // namespace

TEST_CASE("a dropped connection is retried and the request succeeds",
          "[retry][client]") {
    // First connection drops before replying, second answers. The retry must
    // actually happen: 2 connections from the server is the evidence.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c(retrying(2));
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));

    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(wait_for([&] { return srv.connections() >= 2; }));
    CHECK(srv.connections() == 2);
}

TEST_CASE("without a retry policy the same failure is final", "[retry][client]") {
    // The counterweight: identical failure, but max_retries = 0 (default).
    // Exactly one connection, and the caller gets the error.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c;   // defaults: no retries
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));

    REQUIRE(!r);
    CHECK(srv.connections() == 1);
}

TEST_CASE("the retry budget is finite", "[retry][client]") {
    // Every connection drops. With max_retries = 1 the server must see exactly
    // 2 connections: the original plus one retry, then give up.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c(retrying(1));
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));

    REQUIRE(!r);
    CHECK(wait_for([&] { return srv.connections() >= 2; }));
    CHECK(srv.connections() == 2);
}

TEST_CASE("POST is not retried by default", "[retry][client]") {
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c(retrying(3));
    Request req(Method::Post, url_on(srv.port()));
    req.set_body("payload");

    auto r = c.request_sync(req);
    REQUIRE(!r);
    // One attempt only: re-sending a POST could duplicate a side effect.
    CHECK(srv.connections() == 1);
}

TEST_CASE("POST is retried when the caller explicitly accepts the risk",
          "[retry][client]") {
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    ClientOptions o = retrying(2);
    o.retry.retry_non_idempotent = true;
    Client c(o);

    Request req(Method::Post, url_on(srv.port()));
    req.set_body("payload");

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(wait_for([&] { return srv.connections() >= 2; }));
}

TEST_CASE("PUT is retried because it is idempotent", "[retry][client]") {
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c(retrying(2));
    Request req(Method::Put, url_on(srv.port()));
    req.set_body("payload");

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(wait_for([&] { return srv.connections() >= 2; }));
}

TEST_CASE("a body from a one-shot source blocks the retry", "[retry][client]") {
    // A BodySource cannot be replayed, so even a GET (idempotent, retryable)
    // must not be re-sent when it carries one.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c(retrying(3));
    Request req(Method::Get, url_on(srv.port()));
    req.set_body_source([] {
        return Result<std::pair<string_view, bool>>{
            std::make_pair(string_view("x"), true)};
    });

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(srv.connections() == 1);
}

TEST_CASE("the backoff actually waits before re-sending", "[retry][client]") {
    // base_delay is 30ms; a retry that fires instantly would report a total wall
    // time below it. This asserts the timer is used rather than a synchronous
    // immediate retry (which would also spin the loop).
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    Client c(retrying(2));
    const auto t0 = std::chrono::steady_clock::now();
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    REQUIRE(r);
    CHECK(elapsed >= std::chrono::milliseconds(25));
}

TEST_CASE("cancelling while waiting for the backoff ends the request",
          "[retry][client][cancel]") {
    // The backoff wait must be cancellable: a request parked in a 5 s delay has
    // to stop promptly when the caller cancels.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    ClientOptions o;
    o.retry.max_retries = 3;
    o.retry.base_delay = std::chrono::milliseconds(5000);   // long enough to observe
    o.retry.max_delay = std::chrono::milliseconds(5000);
    o.retry.jitter = false;
    Client c(o);

    std::atomic<bool> done{false};
    ErrorCode code = ErrorCode::Success;
    auto handle = c.request(Request(Method::Get, url_on(srv.port())),
                            [&](Result<Response> r) {
        if (!r) code = r.error().code();
        done.store(true);
    });

    // Wait until the failure has happened and the backoff started.
    REQUIRE(wait_for([&] { return srv.connections() >= 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    handle.cancel();

    REQUIRE(wait_for([&] { return done.load(); }, 3000));
    CHECK(code == ErrorCode::Cancelled);
    // No second connection: the retry never fired.
    CHECK(srv.connections() == 1);
}

// ---------------------------------------------------------------------------
// Retryable statuses (429 / 502 / 503 / 504) through the real client
// ---------------------------------------------------------------------------

TEST_CASE("a 503 response is retried and then succeeds", "[retry][client][status]") {
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::Respond503,
                       ScriptServer::Action::Respond}));

    Client c(retrying(2));
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));

    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(wait_for([&] { return srv.connections() >= 2; }));
    CHECK(srv.connections() == 2);
}

TEST_CASE("a 503 with retry_on_status off is handed to the caller",
          "[retry][client][status]") {
    // The counterweight: same server, retries enabled, but status-retrying off.
    // The caller must see the 503 rather than a silent second attempt.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::Respond503,
                       ScriptServer::Action::Respond}));

    ClientOptions o = retrying(2);
    o.retry.retry_on_status = false;
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 503);
    CHECK(srv.connections() == 1);
}

TEST_CASE("a 503 on POST is not retried by default", "[retry][client][status]") {
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::Respond503,
                       ScriptServer::Action::Respond}));

    Client c(retrying(3));
    Request req(Method::Post, url_on(srv.port()));
    req.set_body("payload");

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 503);
    CHECK(srv.connections() == 1);
}

TEST_CASE("a 503 with Retry-After waits for the server's own delay",
          "[retry][client][status]") {
    // Retry-After: 1 second. With base_delay at 30 ms, a client that ignored the
    // header would retry far sooner than 1 s.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::Respond503,
                       ScriptServer::Action::Respond}));

    ClientOptions o = retrying(2);
    o.retry.max_delay = std::chrono::seconds(5);
    Client c(o);

    const auto t0 = std::chrono::steady_clock::now();
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    // At least the server-named second, not our 30 ms backoff.
    CHECK(elapsed >= std::chrono::milliseconds(950));
}

// ---------------------------------------------------------------------------
// The retry backoff counts against the total deadline (S5.3-02)
// ---------------------------------------------------------------------------

TEST_CASE("the total deadline covers the retry backoff", "[retry][client][timeout]") {
    // Every attempt is dropped before replying. base_delay is 300 ms and the
    // total budget is 400 ms, so the request must die inside the FIRST backoff
    // (~400 ms) with TimeoutTotal. A client that restarted the clock per attempt
    // would run all five and take several seconds.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply}));

    ClientOptions o;
    o.retry.max_retries = 5;
    o.retry.base_delay = std::chrono::milliseconds(300);
    o.retry.max_delay = std::chrono::milliseconds(300);
    o.retry.jitter = false;
    o.total_timeout = std::chrono::milliseconds(400);
    Client c(o);

    const auto t0 = std::chrono::steady_clock::now();
    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::TimeoutTotal);
    // Died in the first backoff, not after running the whole retry budget.
    CHECK(elapsed < std::chrono::milliseconds(1200));
    CHECK(srv.connections() <= 2);
}

TEST_CASE("a budget large enough lets every retry happen",
          "[retry][client][timeout]") {
    // Counterweight: same server shape, budget generous. Then the retries do run
    // and the final attempt succeeds.
    ScriptServer srv;
    REQUIRE(srv.start({ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::DropBeforeReply,
                       ScriptServer::Action::Respond}));

    ClientOptions o;
    o.retry.max_retries = 3;
    o.retry.base_delay = std::chrono::milliseconds(20);
    o.retry.max_delay = std::chrono::milliseconds(50);
    o.retry.jitter = false;
    o.total_timeout = std::chrono::milliseconds(5000);
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, url_on(srv.port())));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(srv.connections() == 3);
}
