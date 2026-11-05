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
