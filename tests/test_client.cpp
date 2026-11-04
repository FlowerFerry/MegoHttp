// Client tests: end-to-end HTTP request with the minimal Client.
// Uses a local HTTP server on the same executor so no public network is needed.
// The server is deliberately NOT built from any MegoHttp code.
#include <megohttp/client.hpp>
#include <megohttp/transport.hpp>

#if defined(MGHTTP_BACKEND_LIBUV)
#include <megohttp/backend/executor_libuv.hpp>
#endif
#if defined(MGHTTP_BACKEND_ASIO)
#include <megohttp/backend/executor_asio.hpp>
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
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

// A tiny blocking HTTP/1.1 server that always returns a 200 with a known body.
class TinyHttpServer {
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
        addr.sin_port = 0;
        if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) return false;
        if (::listen(sock_, 8) != 0) return false;
        socklen_t len = sizeof addr;
        if (::getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return false;
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { serve(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }

    void stop() {
        if (stop_.exchange(true)) return;
        if (sock_ != INVALID_SOCKET) {
            // Close the listening socket: the blocked accept() then returns
            // INVALID_SOCKET and the thread exits. Do NOT accept() here to wake it
            // -- the server is already blocked in accept() and a second call would
            // wait for a connection that never comes.
#if defined(_WIN32)
            ::closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TinyHttpServer() { stop(); }

private:
    void serve() {
        for (;;) {
            if (stop_.load()) return;
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            // Read the request line.
            char buf[4096];
            const int n = ::recv(c, buf, sizeof buf - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                // Respond with a 200 OK.
                const char* resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "Hello from TinyHttpServer";
                ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
            }
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
            if (stop_.load()) return;
        }
    }

#if defined(_WIN32)
    SOCKET sock_{INVALID_SOCKET};
#else
    int sock_{-1};
#endif
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

// --- tests ---

static void test_get_ok() {
    TinyHttpServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local HTTP server\n");
        return;
    }

    ClientOptions opts;
    opts.executor = nullptr;   // internal loop
    Client client(opts);

    std::atomic<bool> done{false}, ok{false};
    int status = 0;
    string body;

    string url_str = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";
    client.get(url_str, [&](Result<Response> r) {
        if (r) {
            ok.store(true);
            status = r.value().head().status_code;
            body = to_string(r.value().body_text());
        }
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(ok.load());
    CHECK(status == 200);
    CHECK(body == "Hello from TinyHttpServer");

    client.shutdown();
    srv.stop();
}

static void test_get_cancel() {
    TinyHttpServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local HTTP server\n");
        return;
    }

    ClientOptions opts;
    Client client(opts);

    std::atomic<bool> done{false}, cancelled{false};
    string url_str = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";
    auto h = client.get(url_str, [&](Result<Response> r) {
        if (!r && r.error().code() == ErrorCode::Cancelled) cancelled.store(true);
        done.store(true);
    });
    // Cancel immediately.
    h.cancel();

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(cancelled.load());

    client.shutdown();
    srv.stop();
}

static void test_get_invalid_scheme() {
    Client client;
    std::atomic<bool> done{false}, failed{false};
    // The server is never contacted — this tests URL parse rejection.
    client.get("https://127.0.0.1:1/test", [&](Result<Response> r) {
        failed.store(!r.has_value());
        done.store(true);
    });
    CHECK(wait_until([&] { return done.load(); }));
    CHECK(failed.load());
    client.shutdown();
}

static void test_client_shutdown() {
    Client client;
    std::atomic<bool> done{false};
    client.shutdown();
    // Request after shutdown should get Cancelled.
    client.get("http://127.0.0.1:1/", [&](Result<Response>) {
        done.store(true);
    });
    CHECK(wait_until([&] { return done.load(); }));
}

int main() {
    test_get_ok();
    test_get_cancel();
    test_get_invalid_scheme();
    test_client_shutdown();

    std::printf("=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
