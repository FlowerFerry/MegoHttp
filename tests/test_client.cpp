// Client tests: end-to-end HTTP request with the minimal Client.
// Uses a local HTTP server on the same executor so no public network is needed.
// The server is deliberately NOT built from any MegoHttp code.
#include <catch_amalgamated.hpp>

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
            // Read the request head, then Content-Length bytes of body. Record what
            // actually arrived so a test can assert the body was sent.
            char buf[8192];
            std::string accum;
            size_t content_length = 0;
            bool head_complete = false;
            while (accum.size() < sizeof buf) {
                int n = ::recv(c, buf, sizeof buf, 0);
                if (n <= 0) break;
                accum.append(buf, n);
                if (!head_complete) {
                    size_t he = accum.find("\r\n\r\n");
                    if (he != std::string::npos) {
                        head_complete = true;
                        size_t cl = accum.find("Content-Length:");
                        if (cl != std::string::npos && cl < he) {
                            const char* p = accum.data() + cl + 15;
                            while (*p == ' ' || *p == '\t') ++p;
                            content_length = strtoull(p, nullptr, 10);
                        }
                    }
                }
                if (head_complete) {
                    size_t need = accum.find("\r\n\r\n") + 4 + content_length;
                    if (accum.size() >= need) break;
                }
            }
            {
                const size_t he = accum.find("\r\n\r\n");
                if (he != std::string::npos) {
                    body_seen_.store(accum.size() - (he + 4));
                }
            }
            const char* resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 25\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Hello from TinyHttpServer";
            ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
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
    std::atomic<size_t> body_seen_{0};

public:
    size_t body_seen() const noexcept { return body_seen_.load(); }
};

// --- tests ---

TEST_CASE("get ok", "[client]") {
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

TEST_CASE("get cancel", "[client]") {
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

TEST_CASE("get invalid scheme", "[client]") {
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

TEST_CASE("client shutdown", "[client]") {
    Client client;
    std::atomic<bool> done{false};
    client.shutdown();
    // Request after shutdown should get Cancelled.
    client.get("http://127.0.0.1:1/", [&](Result<Response>) {
        done.store(true);
    });
    CHECK(wait_until([&] { return done.load(); }));
}

TEST_CASE("post sends body", "[client]") {
    TinyHttpServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local HTTP server\n");
        return;
    }

    ClientOptions opts;
    Client client(opts);

    std::atomic<bool> done{false}, ok{false};
    int status = 0;

    string url_str = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";
    Request req(Method::Post, url_str);
    string payload = to_string("hello-body-12345");
    req.set_body(payload);

    client.request(req, [&](Result<Response> r) {
        if (r) {
            ok.store(true);
            status = r.value().head().status_code;
        }
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(ok.load());
    REQUIRE(status == 200);
    REQUIRE(srv.body_seen() == 16);

    client.shutdown();
    srv.stop();
}
