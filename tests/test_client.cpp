// Client tests: end-to-end HTTP request with the minimal Client.
// Uses a local HTTP server on the same executor so no public network is needed.
// The server is deliberately NOT built from any MegoHttp code.
#include <catch2/catch_all.hpp>

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
#include <functional>
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
                        // Header names are case-insensitive: the client may emit
                        // any casing, so fold before searching.
                        std::string lower;
                        lower.reserve(he);
                        for (size_t k = 0; k < he; ++k) {
                            lower.push_back(static_cast<char>(
                                std::tolower(static_cast<unsigned char>(accum[k]))));
                        }
                        size_t cl = lower.find("content-length:");
                        if (cl != std::string::npos) {
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

// Accepts a connection then never writes anything, so only a receive timeout
// can end the request.
class TinysilentServer {
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
#if defined(_WIN32)
            ::closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TinysilentServer() { stop(); }

private:
    void serve() {
        for (;;) {
            if (stop_.load()) return;
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            // Read the request so the client's send completes, then stay silent
            // until the client gives up and closes.
            char buf[4096];
            ::recv(c, buf, sizeof buf, 0);
            while (!stop_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
            return;
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

// Connection handle type for the raw-socket test servers in this file.
#if defined(_WIN32)
using probe_conn_t = SOCKET;
#else
using probe_conn_t = int;
#endif

// Expect: 100-continue server (S3.1-09).
//
// mode 0: answer 100 Continue, then read the body, then answer 200.
// mode 1: answer 417 Expectation Failed immediately, never reading the body.
//
// It records whether the body arrived in the SAME recv as the request head. A
// client that correctly holds the body back cannot have sent it yet, so that
// flag must be false; a client that ignores Expect would pipeline head+body and
// make it true. That is the observable difference this test relies on.
class TinyExpectServer {
public:
    // mode 0: answer 100 Continue, take the body, answer 200.
    // mode 1: answer 417 immediately, never take the body.
    bool start(int mode) {
        mode_ = mode;
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
    bool saw_expect_header() const { return expect_header_.load(); }
    bool body_in_first_recv() const { return body_in_first_recv_.load(); }
    bool got_body() const { return got_body_.load(); }
    std::string body() const { return body_; }

    void stop() {
        if (stop_.exchange(true)) return;
        if (sock_ != INVALID_SOCKET) {
#if defined(_WIN32)
            ::closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TinyExpectServer() { stop(); }

private:
    static void set_recv_timeout(probe_conn_t c, int ms) {
#if defined(_WIN32)
        DWORD t = static_cast<DWORD>(ms);
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&t), sizeof t);
#else
        timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof tv);
#endif
    }

    void serve() {
        for (;;) {
            if (stop_.load()) return;
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            // Every recv on this connection is bounded, so the thread can never
            // block past stop()/join().
            set_recv_timeout(c, 2000);

            char buf[8192];
            const int n = ::recv(c, buf, sizeof buf, 0);
            if (n <= 0) {
#if defined(_WIN32)
                closesocket(c);
#else
                ::close(c);
#endif
                return;
            }
            std::string head(buf, static_cast<size_t>(n));
            size_t content_length = 0;
            const size_t he = head.find("\r\n\r\n");
            if (he != std::string::npos) {
                std::string lower;
                lower.reserve(he);
                for (size_t k = 0; k < he; ++k) {
                    lower.push_back(static_cast<char>(
                        std::tolower(static_cast<unsigned char>(head[k]))));
                }
                expect_header_.store(lower.find("expect: 100-continue") != std::string::npos);
                body_in_first_recv_.store(head.size() > he + 4);
                size_t cl = lower.find("content-length:");
                if (cl != std::string::npos) {
                    const char* q = lower.data() + cl + 15;
                    while (*q == ' ' || *q == '\t') ++q;
                    content_length = static_cast<size_t>(strtoul(q, nullptr, 10));
                }
            }
            std::string body = (he == std::string::npos)
                                   ? std::string()
                                   : head.substr(he + 4);

            if (mode_ == 1) {
                const char* resp =
                    "HTTP/1.1 417 Expectation Failed\r\n"
                    "Content-Length: 3\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "no!";
                ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
            } else {
                const char* cont = "HTTP/1.1 100 Continue\r\n\r\n";
                ::send(c, cont, static_cast<int>(std::strlen(cont)), 0);
                // Only read again if the body has not already arrived: a client
                // that did not send Expect pipelines head+body into one read.
                while (body.size() < content_length) {
                    const int m = ::recv(c, buf, sizeof buf, 0);
                    if (m <= 0) break;
                    body.append(buf, static_cast<size_t>(m));
                }
                if (!body.empty()) {
                    body_ = body;
                    got_body_.store(true);
                }
                const char* resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 2\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "ok";
                ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
            }
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
            return;
        }
    }

#if defined(_WIN32)
    SOCKET sock_{INVALID_SOCKET};
#else
    int sock_{-1};
#endif
    uint16_t port_{0};
    int mode_{0};
    std::atomic<bool> stop_{false};
    std::thread thread_;
    std::atomic<bool> expect_header_{false};
    std::atomic<bool> body_in_first_recv_{false};
    std::atomic<bool> got_body_{false};
    std::string body_;
};

class TinyHeadServer {
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
    std::string request_line() const { return request_line_; }

    void stop() {
        if (stop_.exchange(true)) return;
        if (sock_ != INVALID_SOCKET) {
#if defined(_WIN32)
            ::closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TinyHeadServer() { stop(); }

private:
    void serve() {
        for (;;) {
            if (stop_.load()) return;
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            char buf[4096] = {0};
            const int n = ::recv(c, buf, sizeof buf - 1, 0);
            if (n > 0) {
                std::string req(buf, static_cast<size_t>(n));
                const size_t eol = req.find("\r\n");
                request_line_ = (eol == std::string::npos) ? req : req.substr(0, eol);
            }
            // Content-Length advertises 5 bytes; no body follows. Correct for HEAD.
            const char* resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n";
            ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
            return;
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
    std::string request_line_;
};

// Serves a chunked response with two trailers, so the test can assert the
// trailers survive the parser and reach the caller.
class TinyChunkedServer {
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
#if defined(_WIN32)
            ::closesocket(sock_);
#else
            ::close(sock_);
#endif
            sock_ = INVALID_SOCKET;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TinyChunkedServer() { stop(); }

private:
    void serve() {
        for (;;) {
            if (stop_.load()) return;
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            char buf[4096];
            ::recv(c, buf, sizeof buf, 0);
            const char* resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "2\r\nab\r\n"
                "0\r\n"
                "X-Checksum: abc123\r\n"
                "X-Parts: 1\r\n"
                "\r\n";
            ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
            return;
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

    ErrorCode err_code = ErrorCode::Unknown;
    std::string err_msg;
    client.request(req, [&](Result<Response> r) {
        if (r) {
            ok.store(true);
            status = r.value().head().status_code;
        } else {
            err_code = r.error().code();
            err_msg = std::string(r.error().describe().data(), r.error().describe().size());
        }
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!ok.load()) {
        std::printf("post FAILED: code=%d msg=%s\n",
                    static_cast<int>(err_code), err_msg.c_str());
    }
    REQUIRE(ok.load());
    REQUIRE(status == 200);
    REQUIRE(srv.body_seen() == 16);

    client.shutdown();
    srv.stop();
}


TEST_CASE("options validate rejects bad timeouts", "[client][timeout]") {
    SECTION("negative dns_timeout") {
        ClientOptions o;
        o.dns_timeout = -std::chrono::seconds(1);
        REQUIRE_FALSE(o.validate());
        REQUIRE(o.validate().error().code() == ErrorCode::InvalidArgument);
    }
    SECTION("negative send_timeout") {
        ClientOptions o;
        o.send_timeout = -std::chrono::milliseconds(5);
        REQUIRE_FALSE(o.validate());
    }
    SECTION("absurdly large total_timeout") {
        ClientOptions o;
        o.total_timeout = std::chrono::hours(24 * 365 * 100);   // 100 years
        REQUIRE_FALSE(o.validate());
    }
    SECTION("defaults are valid") {
        ClientOptions o;
        REQUIRE(o.validate());
    }
}

TEST_CASE("invalid options fail the request instead of running", "[client][timeout]") {
    ClientOptions o;
    o.dns_timeout = -std::chrono::seconds(1);
    Client client(o);

    std::atomic<bool> done{false};
    ErrorCode code = ErrorCode::Unknown;
    // The URL is never touched: option validation rejects first.
    client.get("http://127.0.0.1:1/", [&](Result<Response> r) {
        if (!r) code = r.error().code();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(code == ErrorCode::InvalidArgument);
    client.shutdown();
}

TEST_CASE("dns timeout fails with TimeoutResolve and phase Resolve", "[client][timeout]") {
    // A resolver that never calls back: only the DNS timer can end the request.
    class StuckResolver final : public Resolver {
    public:
        const char* name() const noexcept override { return "stuck"; }
        CancelHandle resolve(string, uint16_t, Callback) override {
            return CancelHandle{};   // never invoked
        }
    };

    ClientOptions o;
    o.resolver = std::make_shared<StuckResolver>();
    o.dns_timeout = std::chrono::milliseconds(120);
    Client client(o);

    std::atomic<bool> done{false};
    ErrorCode code = ErrorCode::Unknown;
    ErrorPhase phase = ErrorPhase::None;
    client.get("http://127.0.0.1:1/", [&](Result<Response> r) {
        if (!r) { code = r.error().code(); phase = r.error().phase(); }
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(code == ErrorCode::TimeoutResolve);
    REQUIRE(phase == ErrorPhase::Resolve);
    client.shutdown();
}

TEST_CASE("recv timeout fires when the server never responds", "[client][timeout]") {
    // Server accepts and then stays silent, so only recv_timeout can end it.
    TinysilentServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the silent server\n");
        return;
    }

    ClientOptions o;
    o.recv_timeout = std::chrono::milliseconds(150);
    o.total_timeout = Duration::zero();
    Client client(o);

    std::atomic<bool> done{false};
    ErrorCode code = ErrorCode::Unknown;
    ErrorPhase phase = ErrorPhase::None;
    client.get(string("http://127.0.0.1:") + format("{}", srv.port()) + "/",
               [&](Result<Response> r) {
        if (!r) { code = r.error().code(); phase = r.error().phase(); }
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 5000));
    REQUIRE(code == ErrorCode::TimeoutRecv);
    REQUIRE(phase == ErrorPhase::Receive);
    client.shutdown();
    srv.stop();
}


// ---------------------------------------------------------------------------
// Cancellation (S2.2-03, S2.2-04)
// ---------------------------------------------------------------------------

// Resolver that records every request and lets the test decide when (and
// whether) each one completes. Used to prove that cancelling one request has
// no effect on the others.
class ControlledResolver final : public Resolver {
public:
    const char* name() const noexcept override { return "controlled"; }

    CancelHandle resolve(string host, uint16_t port, Callback cb) override {
        std::lock_guard<std::mutex> lk(m_);
        auto state = std::make_shared<CancelState>();
        Pending p;
        p.host = std::string(host.data(), host.size());
        p.port = port;
        p.cb = std::move(cb);
        p.state = state;
        pending_.push_back(std::move(p));
        return CancelHandle(state);
    }

    size_t count() const {
        std::lock_guard<std::mutex> lk(m_);
        return pending_.size();
    }

    // Deliver a successful answer to request `i`, unless it was cancelled.
    void complete(size_t i, std::vector<uint8_t> ip, uint16_t fallback_port) {
        Callback cb;
        bool cancelled = false;
        {
            std::lock_guard<std::mutex> lk(m_);
            if (i >= pending_.size()) return;
            cancelled = pending_[i].state && pending_[i].state->is_cancelled();
            cb = pending_[i].cb;
        }
        if (cancelled || !cb) return;   // honour the "do not call back" contract

        AddressList list;
        ResolvedAddress a;
        a.family = ResolvedAddress::Family::IPv4;
        a.bytes = std::move(ip);
        a.port = pending_[i].port ? pending_[i].port : fallback_port;
        list.push_back(a);
        cb(Result<AddressList>(std::move(list)));
    }

private:
    struct Pending {
        std::string host;
        uint16_t port{0};
        Callback cb;
        std::shared_ptr<CancelState> state;
    };
    mutable std::mutex m_;
    std::vector<Pending> pending_;
};

TEST_CASE("cancelling one request does not affect another", "[client][cancel]") {
    TinyHttpServer srv;
    REQUIRE(srv.start());

    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    std::atomic<int> done_a{0}, done_b{0};
    ErrorCode code_a = ErrorCode::Unknown;
    bool ok_b = false;

    const string url = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";

    auto ha = client.get(url, [&](Result<Response> r) {
        if (!r) code_a = r.error().code();
        done_a.fetch_add(1);
    });
    auto hb = client.get(url, [&](Result<Response> r) {
        ok_b = static_cast<bool>(r);
        done_b.fetch_add(1);
    });

    // Both requests reach the resolver.
    REQUIRE(wait_until([&] { return res->count() == 2; }));

    // Cancel only A.
    ha.cancel();
    REQUIRE(wait_until([&] { return done_a.load() == 1; }));
    REQUIRE(code_a == ErrorCode::Cancelled);

    // B is untouched: still pending, callback has not run.
    REQUIRE(done_b.load() == 0);

    // Now let B complete; it must succeed.
    res->complete(1, {127, 0, 0, 1}, srv.port());
    REQUIRE(wait_until([&] { return done_b.load() == 1; }, 5000));
    REQUIRE(ok_b);

    // Each callback fired exactly once.
    REQUIRE(done_a.load() == 1);
    REQUIRE(done_b.load() == 1);

    client.shutdown();
    srv.stop();
}

TEST_CASE("a late DNS answer after cancel is dropped", "[client][cancel]") {
    TinyHttpServer srv;
    REQUIRE(srv.start());

    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    std::atomic<int> fired{0};
    ErrorCode code = ErrorCode::Unknown;

    const string url = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";
    auto h = client.get(url, [&](Result<Response> r) {
        if (!r) code = r.error().code();
        fired.fetch_add(1);
    });

    REQUIRE(wait_until([&] { return res->count() == 1; }));

    h.cancel();
    REQUIRE(wait_until([&] { return fired.load() == 1; }));
    REQUIRE(code == ErrorCode::Cancelled);

    // Deliver the answer only now: the resolver contract says a cancelled
    // request must not be called back, so this must produce no second terminal.
    res->complete(0, {127, 0, 0, 1}, srv.port());
    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    REQUIRE(fired.load() == 1);

    client.shutdown();
    srv.stop();
}


// ---------------------------------------------------------------------------
// Client shutdown (S2.6-02, S2.6-04)
// ---------------------------------------------------------------------------

TEST_CASE("shutdown retires in-flight requests with Cancelled", "[client][shutdown]") {
    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    std::atomic<int> done{0};
    ErrorCode code = ErrorCode::Unknown;

    const string url = "http://example.test/";
    auto h = client.get(url, [&](Result<Response> r) {
        if (!r) code = r.error().code();
        done.fetch_add(1);
    });

    REQUIRE(wait_until([&] { return res->count() == 1; }));

    client.shutdown();

    REQUIRE(wait_until([&] { return done.load() == 1; }, 5000));
    REQUIRE(code == ErrorCode::Cancelled);
}

TEST_CASE("shutdown(cb) orders the drained signal after the request callback", "[client][shutdown]") {
    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    // Record the observable order: the request's terminal callback must have
    // run before the drained signal, and both must have run by the time
    // shutdown() returns for a single pending request.
    std::atomic<int> seq{0};
    int request_cb_seq = 0;
    int drained_seq = 0;

    client.get("http://example.test/", [&](Result<Response> r) {
        REQUIRE(!r);                       // cancelled, not a success
        request_cb_seq = seq.fetch_add(1) + 1;
    });
    REQUIRE(wait_until([&] { return res->count() == 1; }));

    client.shutdown([&] { drained_seq = seq.fetch_add(1) + 1; });

    REQUIRE(request_cb_seq == 1);          // request callback ran first
    REQUIRE(drained_seq == 2);             // drained signal ran second
    REQUIRE(seq.load() == 2);              // each ran exactly once
}

TEST_CASE("shutdown(cb) fires immediately when nothing is in flight", "[client][shutdown]") {
    Client client;
    std::atomic<bool> cb_called{false};
    client.shutdown([&] { cb_called.store(true); });
    REQUIRE(cb_called.load());
}

TEST_CASE("shutdown is idempotent", "[client][shutdown]") {
    Client client;
    client.shutdown();
    client.shutdown();   // must not crash
    client.shutdown();
    REQUIRE(true);
}

TEST_CASE("destructing the Client cancels in-flight requests", "[client][shutdown]") {
    auto res = std::make_shared<ControlledResolver>();
    std::atomic<int> done{0};
    ErrorCode code = ErrorCode::Unknown;

    {
        ClientOptions o;
        o.resolver = res;
        Client client(o);
        client.get("http://example.test/", [&](Result<Response> r) {
            if (!r) code = r.error().code();
            done.fetch_add(1);
        });
        REQUIRE(wait_until([&] { return res->count() == 1; }));
    }  // Client destructed here; request must be cancelled

    REQUIRE(wait_until([&] { return done.load() == 1; }, 5000));
    REQUIRE(code == ErrorCode::Cancelled);
}
TEST_CASE("ClientOptions carries the family preference through", "[client][family]") {
    ClientOptions o;
    REQUIRE(o.family_preference == ConnectOptions::FamilyPreference::Unspecified);
    o.family_preference = ConnectOptions::FamilyPreference::PreferIPv4;
    REQUIRE(o.family_preference == ConnectOptions::FamilyPreference::PreferIPv4);
    REQUIRE(o.validate());
}


// ---------------------------------------------------------------------------
// Future API (S2.7-01, S2.7-02)
// ---------------------------------------------------------------------------

TEST_CASE("future request returns the response", "[client][future]") {
    TinyHttpServer srv;
    REQUIRE(srv.start());

    Client client;
    const string url = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";

    auto op = client.request(Request(Method::Get, url));
    REQUIRE(op.valid());

    // The client owns an internal loop thread, so blocking here is safe.
    auto result = op.get();
    REQUIRE(result.has_value());
    REQUIRE(result.value().head().status_code == 200);
    REQUIRE(to_string(result.value().body_text()) == "Hello from TinyHttpServer");

    client.shutdown();
    srv.stop();
}

TEST_CASE("future request can be cancelled", "[client][future]") {
    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    auto op = client.request(Request(Method::Get, "http://example.test/"));
    REQUIRE(wait_until([&] { return res->count() == 1; }));

    op.cancel();

    auto result = op.get();          // must still become ready
    REQUIRE(!result.has_value());
    REQUIRE(result.error().code() == ErrorCode::Cancelled);

    client.shutdown();
}

TEST_CASE("future wait_for reports not-ready then ready", "[client][future]") {
    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    auto op = client.request(Request(Method::Get, "http://example.test/"));
    REQUIRE(wait_until([&] { return res->count() == 1; }));

    // Nothing has completed yet: the lookup is parked in the resolver.
    REQUIRE_FALSE(op.is_ready());
    REQUIRE_FALSE(op.wait_for(std::chrono::milliseconds(30)).has_value());

    // shutdown() retires the in-flight request, so the future must become ready
    // with a Cancelled error.
    client.shutdown();

    auto got = op.wait_for(std::chrono::seconds(5));
    REQUIRE(got.has_value());
    REQUIRE(!(*got).has_value());
    REQUIRE((*got).error().code() == ErrorCode::Cancelled);
}




// ---------------------------------------------------------------------------
// Synchronous API (S2.7-03, S2.7-04)
// ---------------------------------------------------------------------------

TEST_CASE("sync request returns the response", "[client][sync]") {
    TinyHttpServer srv;
    REQUIRE(srv.start());

    Client client;
    const string url = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";

    auto result = client.get_sync(url);
    REQUIRE(result.has_value());
    REQUIRE(result.value().head().status_code == 200);
    REQUIRE(to_string(result.value().body_text()) == "Hello from TinyHttpServer");

    client.shutdown();
    srv.stop();
}

TEST_CASE("sync request reports errors synchronously", "[client][sync]") {
    Client client;
    // Nothing listens on port 1; connect must fail.
    auto result = client.get_sync("http://127.0.0.1:1/");
    REQUIRE(!result.has_value());
    client.shutdown();
}

TEST_CASE("sync request_sync rejects an invalid URL", "[client][sync]") {
    Client client;
    auto result = client.get_sync("ftp://example.com/");
    REQUIRE(!result.has_value());
    REQUIRE(result.error().code() == ErrorCode::InvalidArgument);
    client.shutdown();
}

TEST_CASE("sync request can be interrupted by shutdown from another thread",
          "[client][sync]") {
    auto res = std::make_shared<ControlledResolver>();
    ClientOptions o;
    o.resolver = res;
    Client client(o);

    std::atomic<bool> returned{false};
    ErrorCode code = ErrorCode::Unknown;

    // The resolver never answers, so only shutdown can end this request.
    std::thread waiter([&] {
        auto r = client.get_sync("http://never-answers.test/");
        if (!r) code = r.error().code();
        returned.store(true);
    });

    REQUIRE(wait_until([&] { return res->count() == 1; }));

    client.shutdown();          // retires the in-flight request from this thread

    REQUIRE(wait_until([&] { return returned.load(); }, 5000));
    REQUIRE(code == ErrorCode::Cancelled);

    waiter.join();
}


// ---------------------------------------------------------------------------
// State-machine phase correctness (S2.1-02)
//
// Each failing stage must report the ErrorPhase that matches where it failed,
// so a caller can tell a DNS problem from a refused TCP connection.
// ---------------------------------------------------------------------------

namespace {

// Resolver that always fails, so the request dies in the Resolve stage.
class FailingResolver final : public Resolver {
public:
    explicit FailingResolver(ErrorCode code) : code_(code) {}
    const char* name() const noexcept override { return "failing"; }
    CancelHandle resolve(string, uint16_t, Callback cb) override {
        auto ex = std::make_shared<CancelState>();
        auto fn = cb;
        // Deliver asynchronously, the way a real resolver would.
        std::thread([fn, code = code_] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            if (fn) fn(Result<AddressList>(Error{code, ErrorPhase::Resolve,
                                                 string("resolver failed")}));
        }).detach();
        return CancelHandle(ex);
    }
private:
    ErrorCode code_;
};

} // namespace

TEST_CASE("DNS failure reports phase Resolve", "[client][phase]") {
    ClientOptions o;
    o.resolver = std::make_shared<FailingResolver>(ErrorCode::DnsNameNotFound);
    Client client(o);

    std::atomic<bool> done{false};
    ErrorCode code = ErrorCode::Unknown;
    ErrorPhase phase = ErrorPhase::None;

    client.get("http://does-not-exist.test/", [&](Result<Response> r) {
        if (!r) { code = r.error().code(); phase = r.error().phase(); }
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 5000));
    REQUIRE(code == ErrorCode::DnsNameNotFound);
    REQUIRE(phase == ErrorPhase::Resolve);

    client.shutdown();
}

TEST_CASE("connection refusal reports phase TcpConnect", "[client][phase]") {
    // Port 1 is not listening here (verified: connect() returns WSAECONNREFUSED).
    ClientOptions o;
    o.connect_timeout = std::chrono::seconds(3);
    Client client(o);

    std::atomic<bool> done{false};
    ErrorCode code = ErrorCode::Unknown;
    ErrorPhase phase = ErrorPhase::None;

    client.get("http://127.0.0.1:1/", [&](Result<Response> r) {
        if (!r) { code = r.error().code(); phase = r.error().phase(); }
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 10000));
    REQUIRE(code == ErrorCode::ConnectFailed);
    REQUIRE(phase == ErrorPhase::TcpConnect);

    client.shutdown();
}

TEST_CASE("truncated response reports phase Receive", "[client][phase]") {
    // Server promises 100 bytes but sends 5 and closes: the parser sees a
    // truncation during the receive stage.
    class TruncatingServer {
    public:
        bool start() {
#if defined(_WIN32)
            WSADATA wsa{}; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
            sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (sock_ == INVALID_SOCKET) return false;
            int one = 1;
            setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&one), sizeof one);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = 0;
            if (::bind(sock_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
            if (::listen(sock_, 4) != 0) return false;
            socklen_t len = sizeof a;
            if (::getsockname(sock_, reinterpret_cast<sockaddr*>(&a), &len) != 0) return false;
            port_ = ntohs(a.sin_port);
            thread_ = std::thread([this] { serve(); });
            return true;
        }
        uint16_t port() const noexcept { return port_; }
        void stop() {
            if (stop_.exchange(true)) return;
            if (sock_ != INVALID_SOCKET) {
#if defined(_WIN32)
                ::closesocket(sock_);
#else
                ::close(sock_);
#endif
                sock_ = INVALID_SOCKET;
            }
            if (thread_.joinable()) thread_.join();
        }
        ~TruncatingServer() { stop(); }
    private:
        void serve() {
            sockaddr_in peer{};
            socklen_t plen = sizeof peer;
            auto c = ::accept(sock_, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c == INVALID_SOCKET) return;
            char buf[2048];
            ::recv(c, buf, sizeof buf, 0);
            const char* resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 100\r\n"
                "Connection: close\r\n"
                "\r\n"
                "short";                     // 5 bytes, CL says 100
            ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
#if defined(_WIN32)
            closesocket(c);
#else
            ::close(c);
#endif
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

    TruncatingServer srv;
    REQUIRE(srv.start());

    Client client;
    std::atomic<bool> done{false};
    ErrorPhase phase = ErrorPhase::None;
    bool failed = false;

    client.get(string("http://127.0.0.1:") + format("{}", srv.port()) + "/",
        [&](Result<Response> r) {
            if (!r) { failed = true; phase = r.error().phase(); }
            done.store(true);
        });

    REQUIRE(wait_until([&] { return done.load(); }, 5000));
    REQUIRE(failed);
    REQUIRE(phase == ErrorPhase::Receive);

    client.shutdown();
    srv.stop();
}

// ---------------------------------------------------------------------------
// Destructor safety (S2.6-02): no callback after the Client is gone
// ---------------------------------------------------------------------------

TEST_CASE("no request callback fires after the Client is destroyed", "[client][shutdown]") {
    std::atomic<int> fired{0};
    std::shared_ptr<ControlledResolver> res;

    {
        res = std::make_shared<ControlledResolver>();
        ClientOptions o;
        o.resolver = res;
        Client client(o);

        client.get("http://pending.test/", [&](Result<Response>) {
            fired.fetch_add(1);
        });
        REQUIRE(wait_until([&] { return res->count() == 1; }));

        // The destructor retires the request, so exactly one callback fires
        // during destruction...
    }

    REQUIRE(wait_until([&] { return fired.load() == 1; }, 5000));

    // ...and delivering the resolver's answer NOW must not produce a second one.
    res->complete(0, {127, 0, 0, 1}, 80);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    REQUIRE(fired.load() == 1);
}

// ---------------------------------------------------------------------------
// Client on a CALLER-OWNED event loop (ClientOptions::executor injection).
//
// The executor layer has external-loop tests, but the Client layer had none:
// the injected-executor path was declared in ClientOptions and never exercised.
// These cover it, and assert the ownership contract -- the Client must never
// stop or close somebody else's loop, and must not shut down an executor it
// did not create.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// S3.1-02: a response to HEAD must not be waited on for a body, even when it
// advertises Content-Length (RFC 7230 3.3.3). This needs the Client to tell the
// parser which method it sent; ResponseParser defaults to Get.
// ---------------------------------------------------------------------------
TEST_CASE("HEAD response with Content-Length completes without a body",
          "[client][method]") {
    TinyHeadServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local HEAD server\n");
        return;
    }

    // A short recv timeout: if the Client waited for the advertised 5 bytes this
    // test would end in TimeoutReceive rather than a response.
    ClientOptions o;
    o.recv_timeout = std::chrono::seconds(5);
    Client client(o);

    Request req;
    req.set_method(Method::Head);
    req.set_url(string("http://127.0.0.1:") + format("{}", srv.port()) + "/");

    std::atomic<bool> done{false};
    bool ok = false;
    int status = 0;
    size_t body_len = 999;
    std::string err;

    client.request(req, [&](Result<Response> r) {
        if (r) {
            ok = true;
            status = r.value().head().status_code;
            body_len = r.value().body_bytes().size();
        } else {
            err = to_string(r.error().code());
        }
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(ok);
    CHECK(status == 200);
    CHECK(body_len == 0);
    CHECK(err.empty());

    // The server must actually have seen a HEAD, not a GET.
    CHECK(wait_until([&] { return !srv.request_line().empty(); }));
    CHECK(srv.request_line().compare(0, 5, "HEAD ") == 0);

    client.shutdown();
    srv.stop();
}

// ---------------------------------------------------------------------------
// S3.1-08: chunked trailers are parsed AND surfaced to the caller. The parser
// always parsed them; the Client used to drop them on the floor.
// ---------------------------------------------------------------------------
TEST_CASE("chunked trailers reach the caller", "[client][trailer]") {
    TinyChunkedServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local chunked server\n");
        return;
    }

    Client client;
    std::atomic<bool> done{false};
    bool ok = false;
    std::string body;
    size_t trailer_count = 0;
    std::string trailer_value;
    std::string err;

    client.get(string("http://127.0.0.1:") + format("{}", srv.port()) + "/",
               [&](Result<Response> r) {
        if (r) {
            ok = true;
            const ResponseHead& h = r.value().head();
            body.assign(r.value().body_text().data(), r.value().body_text().size());
            trailer_count = h.trailers.size();
            if (auto v = h.trailers.get("x-checksum")) {
                trailer_value.assign(v->data(), v->size());
            }
        } else {
            err = to_string(r.error().code());
        }
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(ok);
    CHECK(body == "ab");
    CHECK(err.empty());
    CHECK(trailer_count == 2);
    CHECK(trailer_value == "abc123");

    client.shutdown();
    srv.stop();
}

// ---------------------------------------------------------------------------
// S3.1-09: Expect: 100-continue. The body must be held back until the server
// answers 100, and a 417 must stop the body from being sent at all.
// ---------------------------------------------------------------------------
TEST_CASE("expect continue holds the body until 100 Continue", "[client][expect]") {
    TinyExpectServer srv;
    if (!srv.start(0)) {
        std::printf("SKIP: could not start the local expect server\n");
        return;
    }

    ClientOptions o;
    o.expect_continue = true;
    Client client(o);

    Request req;
    req.set_method(Method::Post);
    req.set_url(string("http://127.0.0.1:") + format("{}", srv.port()) + "/upload");
    req.set_body(to_string("payload-12345"));

    std::atomic<bool> done{false};
    bool ok = false;
    int status = 0;
    std::string err;
    client.request(req, [&](Result<Response> r) {
        if (r) { ok = true; status = r.value().head().status_code; }
        else err = to_string(r.error().code());
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(err.empty());
    CHECK(ok);
    CHECK(status == 200);

    // The header must have been sent...
    CHECK(srv.saw_expect_header());
    // ...and the body must NOT have been pipelined with the head.
    CHECK(!srv.body_in_first_recv());
    // ...and it must have arrived only after the 100 answer.
    CHECK(wait_until([&] { return srv.got_body(); }));
    CHECK(srv.body() == "payload-12345");

    client.shutdown();
    srv.stop();
}

TEST_CASE("expect continue with 417 does not send the body", "[client][expect]") {
    TinyExpectServer srv;
    if (!srv.start(1)) {
        std::printf("SKIP: could not start the local expect server\n");
        return;
    }

    ClientOptions o;
    o.expect_continue = true;
    Client client(o);

    Request req;
    req.set_method(Method::Post);
    req.set_url(string("http://127.0.0.1:") + format("{}", srv.port()) + "/upload");
    req.set_body(to_string("payload-12345"));

    std::atomic<bool> done{false};
    bool ok = false;
    int status = 0;
    std::string body;
    std::string err;
    client.request(req, [&](Result<Response> r) {
        if (r) {
            ok = true;
            status = r.value().head().status_code;
            body.assign(r.value().body_text().data(), r.value().body_text().size());
        } else err = to_string(r.error().code());
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    // 417 is a valid HTTP response, not a transport failure.
    CHECK(err.empty());
    CHECK(ok);
    CHECK(status == 417);
    CHECK(body == "no!");
    CHECK(srv.saw_expect_header());
    CHECK(!srv.body_in_first_recv());
    CHECK(!srv.got_body());

    client.shutdown();
    srv.stop();
}

// Default off: a body-carrying request must not gain an Expect header.
TEST_CASE("expect continue is off by default", "[client][expect]") {
    TinyExpectServer srv;
    if (!srv.start(0)) {
        std::printf("SKIP: could not start the local expect server\n");
        return;
    }

    Client client;                       // default options
    Request req;
    req.set_method(Method::Post);
    req.set_url(string("http://127.0.0.1:") + format("{}", srv.port()) + "/upload");
    req.set_body(to_string("payload-12345"));

    std::atomic<bool> done{false};
    bool ok = false;
    client.request(req, [&](Result<Response> r) {
        ok = static_cast<bool>(r);
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(ok);
    CHECK(!srv.saw_expect_header());
    // Deliberately NOT asserting body_in_first_recv() here. The client writes the
    // head and the body as two separate operations, and TCP is free to deliver
    // them in one recv() or two -- nothing in the protocol promises coalescing.
    // Asserting it made this case fail whenever the segments happened to split,
    // which says nothing about whether Expect was (correctly) left off.
    CHECK(srv.body() == "payload-12345");

    client.shutdown();
    srv.stop();
}

#if defined(MGHTTP_BACKEND_LIBUV)
TEST_CASE("client runs on a caller-owned libuv loop", "[client][external]") {
    TinyHttpServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local HTTP server\n");
        return;
    }

    // The caller owns the loop and drives it by hand, so the Client can never
    // be the one that stops it.
    uv_loop_t loop;
    REQUIRE(uv_loop_init(&loop) == 0);

    auto ex = libuv_backend::UvExecutor::create_external(&loop);
    REQUIRE(ex != nullptr);

    // Contract: the wake handle is installed by the caller, on the driving
    // thread. Until it exists, posts stay queued rather than being dropped.
    ex->initialize_external_wake_handle();

    // Pump helper: NOWAIT drains whatever is pending, then checks the predicate.
    auto pump_until = [&](const std::function<bool()>& pred) {
        for (int i = 0; i < 2500; ++i) {
            uv_run(&loop, UV_RUN_NOWAIT);
            if (pred()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        uv_run(&loop, UV_RUN_NOWAIT);
        return pred();
    };

    ClientOptions o;
    o.executor = ex;                 // injected: the Client must not own it
    Client client(o);

    std::atomic<bool> done{false}, ok{false};
    int status = 0;

    const string url = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";
    client.get(url, [&](Result<Response> r) {
        if (r) { ok.store(true); status = r.value().head().status_code; }
        done.store(true);
    });

    CHECK(pump_until([&] { return done.load(); }));
    CHECK(ok.load());
    CHECK(status == 200);

    // External mode never claims to know which thread drives the loop.
    CHECK(ex->is_in_loop_thread() == false);

    // Every handle the request created (DNS timer, send timer, recv timer, the
    // TCP stream) must be released once the request reaches its terminal state.
    // In external mode the executor never drains the loop itself, so the caller
    // pumping is what lets the asynchronous uv_close callbacks run.
    // Regression guard: DeferredTimer used to hold a strong self-reference inside
    // the UvTimer's on_fired callback, forming a cycle that kept the timer -- and
    // therefore its uv_timer_t -- alive forever, so the caller's loop could never
    // be closed (uv_loop_close returned UV_EBUSY indefinitely).
    auto count_handles = [](uv_loop_t* l) {
        int total = 0;
        uv_walk(l, [](uv_handle_t* h, void* arg) { (*static_cast<int*>(arg))++; }, &total);
        return total;
    };

    for (int i = 0; i < 50; ++i) uv_run(&loop, UV_RUN_NOWAIT);
    CHECK(count_handles(&loop) == 1);   // only the executor's own wake handle

    client.shutdown();
    for (int i = 0; i < 50; ++i) uv_run(&loop, UV_RUN_NOWAIT);
    CHECK(count_handles(&loop) == 1);   // shutdown must not leak either

    // The caller closes what the caller opened: the executor releases its own
    // handle, then the caller's loop must become closable.
    ex->shutdown();
    for (int i = 0; i < 50; ++i) uv_run(&loop, UV_RUN_NOWAIT);
    CHECK(count_handles(&loop) == 0);

    int rc = UV_EBUSY;
    for (int i = 0; i < 200; ++i) {
        rc = uv_loop_close(&loop);
        if (rc != UV_EBUSY) break;
        uv_run(&loop, UV_RUN_NOWAIT);
    }
    CHECK(rc == 0);

    srv.stop();
}
#endif

#if defined(MGHTTP_BACKEND_ASIO)
TEST_CASE("client runs on a caller-owned io_context", "[client][external][asio]") {
    TinyHttpServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start the local HTTP server\n");
        return;
    }

    asio::io_context ioc;
    auto ex = asio_backend::AsioExecutor::create_external(ioc);
    REQUIRE(ex != nullptr);

    // The executor's work guard keeps run() from returning while work is
    // outstanding; the caller owns the driving thread.
    std::thread driver([&] { ioc.run(); });

    ClientOptions o;
    o.executor = ex;                 // injected: the Client must not own it
    Client client(o);

    std::atomic<bool> done{false}, ok{false};
    int status = 0;

    const string url = string("http://127.0.0.1:") + format("{}", srv.port()) + "/";
    client.get(url, [&](Result<Response> r) {
        if (r) { ok.store(true); status = r.value().head().status_code; }
        done.store(true);
    });

    CHECK(wait_until([&] { return done.load(); }));
    CHECK(ok.load());
    CHECK(status == 200);

    // External mode cannot honestly answer "am I the loop thread", so it says no.
    CHECK(ex->is_in_loop_thread() == false);

    client.shutdown();

    // The Client must not stop somebody else's io_context.
    CHECK(ioc.stopped() == false);

    std::atomic<int> after{0};
    ex->post([&] { after.fetch_add(1); });
    CHECK(wait_until([&] { return after.load() == 1; }));   // context still live

    // Releasing the guard is what lets the caller's run() return.
    ex->shutdown();
    CHECK(wait_until([&] { return ioc.stopped(); }, 2000));
    driver.join();

    srv.stop();
}
#endif

