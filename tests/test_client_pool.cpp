// Phase 5 S5.1-03: real connection reuse through the public Client.
//
// The pool's own unit tests (test_connection_pool) prove the accounting. This
// file proves the thing that actually matters and that only a real client run
// can show: a second request on the same origin travels over the SAME TCP
// connection, observed from the server side by counting accepts.
//
// A pool test that only inspected data structures would pass even if Client
// never consulted the pool at all, so the accept counter is the load-bearing
// assertion here.
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

using namespace megohttp;

namespace {

// A keep-alive-aware HTTP/1.1 server that counts how many TCP connections it
// accepted and how many requests it served on each. That pair is the evidence:
// N requests over 1 accept means reuse really happened.
class CountingServer {
public:
    bool start() {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!is_valid(listen_)) return false;
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
    int accepts() const noexcept { return accepts_.load(); }
    int requests() const noexcept { return requests_.load(); }

    ~CountingServer() { stop(); }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (is_valid(listen_)) {
            closesock(listen_);
            listen_ = invalid_sock();
        }
        if (thread_.joinable()) thread_.join();
    }

private:
#if defined(_WIN32)
    using sock_t = SOCKET;
    static sock_t invalid_sock() { return INVALID_SOCKET; }
    static bool is_valid(sock_t s) { return s != INVALID_SOCKET; }
    static void closesock(sock_t s) { ::closesocket(s); }
#else
    using sock_t = int;
    static sock_t invalid_sock() { return -1; }
    static bool is_valid(sock_t s) { return s >= 0; }
    static void closesock(sock_t s) { ::close(s); }
#endif

    void run() {
        while (!stopped_.load()) {
            sock_t c = ::accept(listen_, nullptr, nullptr);
            if (!is_valid(c)) return;
            ++accepts_;
            // Serve every request on this connection until the client closes it
            // or sends Connection: close.
            std::thread([this, c] { serve(c); }).detach();
        }
    }

    static std::string read_request_head(sock_t c) {
        std::string head;
        char ch = 0;
        while (head.size() < 64 * 1024) {
            int n = static_cast<int>(::recv(c, &ch, 1, 0));
            if (n <= 0) return {};
            head += ch;
            if (head.size() >= 4 && head.compare(head.size() - 4, 4, "\r\n\r\n") == 0) break;
        }
        return head;
    }

    void serve(sock_t c) {
        while (!stopped_.load()) {
            const std::string head = read_request_head(c);
            if (head.empty()) break;   // client closed
            ++requests_;

            std::string lower = head;
            for (auto& ch : lower) ch = static_cast<char>(::tolower(static_cast<unsigned char>(ch)));
            const bool client_wants_close =
                lower.find("connection: close") != std::string::npos;

            const char* body = "ok";
            const std::string resp =
                std::string("HTTP/1.1 200 OK\r\n") +
                "Content-Length: 2\r\n" +
                // Echo the close intent: a real server says "close" when it is
                // about to close. Claiming keep-alive and then hanging up would
                // make the client pool a connection it cannot use, which would be
                // a fixture bug rather than a library behaviour to test.
                (client_wants_close ? "Connection: close\r\n"
                                    : "Connection: keep-alive\r\n") +
                "\r\n" + body;
            if (::send(c, resp.data(), static_cast<int>(resp.size()), 0) <= 0) break;

            if (client_wants_close) break;
        }
        closesock(c);
    }

    sock_t listen_{invalid_sock()};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    std::atomic<int> accepts_{0};
    std::atomic<int> requests_{0};
    std::thread thread_;
};

std::string to_std(const string& s) { return std::string(s.data(), s.size()); }

// The accept counter is incremented on the server's own thread, so a test that
// reads it immediately after request_sync can observe the connection before the
// accept for it was recorded. Wait for a condition instead of assuming ordering.
bool wait_for(std::function<bool()> pred, int max_ms = 3000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

// Give the server thread a chance to record any accept it is about to, so a
// negative assertion ("no second connection was opened") is not a race.
void settle(int ms = 150) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

ClientOptions pooling_options(size_t max_per_origin) {
    ClientOptions opt;
    opt.pool.max_connections_per_origin = max_per_origin;
    opt.pool.max_total_connections = max_per_origin;
    opt.pool.max_waiting = 16;
    return opt;
}

} // namespace

TEST_CASE("two sequential requests reuse one pooled connection", "[pool][client]") {
    CountingServer srv;
    REQUIRE(srv.start());

    Client c(pooling_options(2));
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/";

    auto r1 = c.request_sync(Request(Method::Get, string(url.data(), url.size())));
    if (!r1) { WARN("r1 error: " << static_cast<int>(r1.error().code()) << " " << to_std(r1.error().message())); }
    REQUIRE(r1);
    CHECK(r1.value().head().status_code == 200);

    auto r2 = c.request_sync(Request(Method::Get, string(url.data(), url.size())));
    REQUIRE(r2);
    CHECK(r2.value().head().status_code == 200);

    // The load-bearing assertion: two requests, ONE TCP connection.
    settle();   // give a (wrong) second accept time to appear
    CHECK(srv.accepts() == 1);
    CHECK(wait_for([&] { return srv.requests() >= 2; }));
}

TEST_CASE("without a pool each request opens its own connection",
          "[pool][client]") {
    // The counterweight: if the pool were always on, the test above would pass
    // for the wrong reason. With every limit at 0 (the historical default) two
    // requests must produce two accepts.
    CountingServer srv;
    REQUIRE(srv.start());

    Client c;   // default options: no pooling
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/";

    auto r1 = c.request_sync(Request(Method::Get, string(url.data(), url.size())));
    REQUIRE(r1);
    auto r2 = c.request_sync(Request(Method::Get, string(url.data(), url.size())));
    REQUIRE(r2);

    CHECK(wait_for([&] { return srv.accepts() >= 2; }));
    CHECK(wait_for([&] { return srv.requests() >= 2; }));
}

TEST_CASE("a server that answers Connection: close is never reused",
          "[pool][client]") {
    // Framing rule S5.1-04: a connection the server intends to close must not go
    // back into the pool. The next request has to open a fresh one.
    //
    // Implemented with a one-shot server: it closes after each response, so the
    // pool's reuse attempt would find a dead socket. Whether the pool detects
    // that at put() time (Connection: close) or at acquire() time (dead stream),
    // the observable result is the same: two accepts.
    CountingServer srv;
    REQUIRE(srv.start());

    Client c(pooling_options(2));
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/";

    // Send "Connection: close" explicitly so the server closes after replying.
    Request req(Method::Get, string(url.data(), url.size()));
    req.headers().set("connection", "close");
    auto r1 = c.request_sync(req);
    REQUIRE(r1);
    CHECK(r1.value().head().status_code == 200);
    CHECK(r1.value().head().connection_close);

    Request req2(Method::Get, string(url.data(), url.size()));
    req2.headers().set("connection", "close");
    auto r2 = c.request_sync(req2);
    if (!r2) {
        WARN("r2 error: " << static_cast<int>(r2.error().code()) << " "
                          << to_std(r2.error().message()));
    }
    REQUIRE(r2);

    CHECK(wait_for([&] { return srv.accepts() >= 2; }));
}

TEST_CASE("per-origin limit caps concurrent connections", "[pool][client]") {
    // With a limit of 1 and two requests in flight the second must wait, not
    // open a second connection. Both eventually succeed; the accept count proves
    // the limit held.
    CountingServer srv;
    REQUIRE(srv.start());

    Client c(pooling_options(1));
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/";

    std::atomic<int> done{0};
    std::atomic<int> ok_count{0};
    for (int i = 0; i < 2; ++i) {
        c.request(Request(Method::Get, string(url.data(), url.size())),
                  [&](Result<Response> r) {
                      if (r && r.value().head().status_code == 200) ++ok_count;
                      ++done;
                  });
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (done.load() < 2 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    REQUIRE(done.load() == 2);
    CHECK(ok_count.load() == 2);
    // Both requests completed; the connection count must not exceed the limit.
    CHECK(srv.accepts() <= 1);
}
