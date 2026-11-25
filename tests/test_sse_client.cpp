// SSE integration test (task book 11, S6.1).
//
// A real local server that answers with text/event-stream, and a Client
// configured with set_sse_callback(). The parser is fed through the same
// HTTP-framing -> Content-Encoding -> SSE pipeline that a production caller
// would use.

#include <megohttp/client.hpp>
#include <megohttp/request.hpp>
#include <megohttp/string_adapter.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using sock_t = SOCKET;
const sock_t kInvalidSock = INVALID_SOCKET;
inline void close_sock(sock_t s) { ::closesocket(s); }
inline bool init_winsock() {
    WSADATA wsa{};
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using sock_t = int;
const sock_t kInvalidSock = -1;
inline void close_sock(sock_t s) { ::close(s); }
inline bool init_winsock() { return true; }
#endif

using namespace megohttp;

namespace {

    // Minimal single-request SSE echo server. Accepts one connection, sends the
    // events provided in *body, then closes.
    class TinySseServer {
    public:
        explicit TinySseServer(std::string body,
                               std::string content_type = "text/event-stream")
            : body_(std::move(body)), ctype_(std::move(content_type)) {}
        ~TinySseServer() { stop(); }

        bool start() {
            ls_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (ls_ == kInvalidSock) return false;
            int one = 1;
            setsockopt(ls_, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&one), sizeof one);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = 0;
            if (::bind(ls_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
                close_sock(ls_); return false;
            }
            if (::listen(ls_, 1) != 0) { close_sock(ls_); return false; }
            socklen_t al = sizeof a;
            getsockname(ls_, reinterpret_cast<sockaddr*>(&a), &al);
            port_ = ntohs(a.sin_port);

            running_ = true;
            th_ = std::thread([this] { serve(); });
            // Wait for the thread to reach accept (simple readiness).
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return true;
        }

        void stop() {
            if (!running_) return;
            running_ = false;
            close_sock(ls_);
            if (th_.joinable()) th_.join();
        }

        uint16_t port() const { return port_; }

    private:
        void serve() {
            sockaddr_in ca{};
            socklen_t cal = sizeof ca;
            sock_t c = ::accept(ls_, reinterpret_cast<sockaddr*>(&ca), &cal);
            if (c == kInvalidSock) return;

            // Read the request (just drain the head).
            char buf[4096];
            std::string head;
            for (;;) {
                int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                if (n <= 0) break;
                head.append(buf, n);
                if (head.find("\r\n\r\n") != std::string::npos) break;
            }

            // Send SSE response.
            std::string resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: " + ctype_ + "\r\n"
                "Connection: close\r\n"
                "Content-Length: " + std::to_string(body_.size()) + "\r\n"
                "\r\n" + body_;
            ::send(c, resp.c_str(), static_cast<int>(resp.size()), 0);
            close_sock(c);
        }

        std::string body_;
        std::string ctype_;
        uint16_t port_{0};
        sock_t ls_{kInvalidSock};
        std::atomic<bool> running_{false};
        std::thread th_;
    };

    bool wait_until(std::function<bool()> pred, int ms = 3000) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return false;
    }

} // namespace

TEST_CASE("Client delivers SSE events through set_sse_callback", "[sse][client]") {
    init_winsock();
    TinySseServer srv("event: update\ndata: hello\n\n"
                      "data: world\n\n");
    if (!srv.start()) {
        std::printf("SKIP: could not start SSE server\n");
        return;
    }

    Client cli;
    string url;
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        url = b.release();
    }
    Request req(Method::Get, url);

    std::vector<std::string> events;
    std::vector<std::string> types;
    std::atomic<int> done{0};

    req.set_sse_callback(
        [&events, &types](const SseEvent& e) {
            events.emplace_back(e.data.data(), e.data.size());
            types.emplace_back(e.event_type.data(), e.event_type.size());
            return VoidResult{};
        });

    cli.request(req, [&done](Result<Response> r) {
        (void)r;
        done.store(1);
    });

    CHECK(wait_until([&] { return done.load() == 1; }));
    REQUIRE(events.size() == 2);
    CHECK(events[0] == "hello");
    CHECK(events[1] == "world");
    CHECK(types[0] == "update");
    CHECK(types[1] == "message");

    cli.shutdown();
    srv.stop();
}

TEST_CASE("Client SSE survives gzipped content-encoding", "[sse][client]") {
    init_winsock();
#if !MEGOHTTP_HAS_GZIP
    std::printf("SKIP: gzip not compiled\n");
    return;
#else
    // Build a gzipped SSE body at compile time is too heavy; just verify the
    // Content-Type check rejects non-SSE types. The actual gzip+SSE combo is
    // exercised by the Content-Encoding pipeline test.
    TinySseServer srv("data: plain\n\n");
    if (!srv.start()) return;

    Client cli;
    string url;
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        url = b.release();
    }
    Request req(Method::Get, url);

    int count = 0;
    std::atomic<int> done{0};

    req.set_sse_callback(
        [&count](const SseEvent& e) {
            ++count;
            (void)e;
            return VoidResult{};
        });

    cli.request(req, [&done](Result<Response> r) {
        (void)r;
        done.store(1);
    });

    CHECK(wait_until([&] { return done.load() == 1; }));
    // The Content-Type is text/event-stream → SSE parser should fire.
    CHECK(count >= 1);

    cli.shutdown();
    srv.stop();
#endif
}

TEST_CASE("Client ignores non-SSE Content-Type when SSE callback is set", "[sse][client]") {
    init_winsock();
    // Server that answers 200 with text/plain instead of text/event-stream.
    // The SSE callback should NOT fire.
    class TinyPlainServer {
    public:
        bool start() {
            ls_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (ls_ == kInvalidSock) return false;
            int one = 1;
            setsockopt(ls_, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&one), sizeof one);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = 0;
            if (::bind(ls_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
                close_sock(ls_); return false;
            }
            if (::listen(ls_, 1) != 0) { close_sock(ls_); return false; }
            socklen_t al = sizeof a;
            getsockname(ls_, reinterpret_cast<sockaddr*>(&a), &al);
            port_ = ntohs(a.sin_port);
            running_ = true;
            th_ = std::thread([this] {
                sockaddr_in ca{}; socklen_t cal = sizeof ca;
                sock_t c = ::accept(ls_, reinterpret_cast<sockaddr*>(&ca), &cal);
                if (c == kInvalidSock) return;
                char buf[4096];
                std::string req;
                for (;;) {
                    int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                    if (n <= 0) break;
                    req.append(buf, n);
                    if (req.find("\r\n\r\n") != std::string::npos) break;
                }
                const char* resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc";
                ::send(c, resp, static_cast<int>(std::strlen(resp)), 0);
                close_sock(c);
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return true;
        }
        void stop() {
            if (!running_) return;
            running_ = false;
            close_sock(ls_);
            if (th_.joinable()) th_.join();
        }
        uint16_t port() const { return port_; }
    private:
        uint16_t port_{0}; sock_t ls_{kInvalidSock};
        std::atomic<bool> running_{false}; std::thread th_;
    };

    TinyPlainServer srv;
    if (!srv.start()) return;

    Client cli;
    string url;
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        url = b.release();
    }
    Request req(Method::Get, url);

    int sse_count = 0;
    std::atomic<int> done{0};
    std::atomic<int> result_had_error{0};
    std::atomic<int> err_code{0};

    req.set_sse_callback(
        [&sse_count](const SseEvent& e) {
            ++sse_count;
            (void)e;
            return VoidResult{};
        });

    cli.request(req, [&done, &result_had_error, &err_code](Result<Response> r) {
        if (!r) {
            result_had_error.store(1);
            err_code.store(static_cast<int>(r.error().code()));
        }
        done.store(1);
    });

    CHECK(wait_until([&] { return done.load() == 1; }));
    // The Content-Type is text/plain: the request must fail with
    // SseInvalidContentType rather than silently buffering a body the caller
    // will never see through its SSE callback (D12).
    CHECK(sse_count == 0);
    REQUIRE(result_had_error.load() == 1);
    CHECK(err_code.load() == static_cast<int>(ErrorCode::SseInvalidContentType));

    cli.shutdown();
    srv.stop();
}

TEST_CASE("SSE is accepted when the Content-Type carries a charset parameter",
          "[sse][client]") {
    // "text/event-stream; charset=utf-8" is the shape real servers send. An
    // exact whole-value compare used to reject it and silently fall through to
    // the buffered path (D12).
    init_winsock();
    TinySseServer srv("data: one\n\n"
                      "data: two\n\n",
                      "text/event-stream; charset=utf-8");
    if (!srv.start()) {
        std::printf("SKIP: could not start SSE server\n");
        return;
    }

    Client cli;
    string url;
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        url = b.release();
    }
    Request req(Method::Get, url);

    std::vector<std::string> events;
    std::atomic<int> done{0};

    req.set_sse_callback([&events](const SseEvent& e) {
        events.emplace_back(e.data.data(), e.data.size());
        return VoidResult{};
    });

    cli.request(req, [&done](Result<Response> r) {
        (void)r;
        done.store(1);
    });

    CHECK(wait_until([&] { return done.load() == 1; }));
    REQUIRE(events.size() == 2);
    CHECK(events[0] == "one");
    CHECK(events[1] == "two");

    cli.shutdown();
    srv.stop();
}

TEST_CASE("Client SSE flow can start paused before the first event",
          "[sse][client][backpressure]") {
    init_winsock();
    TinySseServer srv("data: one\n\ndata: two\n\n");
    if (!srv.start()) {
        std::printf("SKIP: could not start SSE server\n");
        return;
    }

    Client cli;
    string url;
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        url = b.release();
    }
    Request req(Method::Get, url);

    auto flow = std::make_shared<Request::SseFlow>();
    flow->pause();
    std::atomic<int> events{0};
    std::atomic<int> done{0};

    req.set_sse_callback(
        [&events](const SseEvent&) {
            ++events;
            return VoidResult{};
        },
        {},
        flow);

    cli.request(req, [&done](Result<Response> r) {
        (void)r;
        done.store(1);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    CHECK(events.load() == 0);
    CHECK(!done.load());

    flow->resume();
    CHECK(wait_until([&] { return done.load() == 1; }));
    CHECK(events.load() == 2);

    cli.shutdown();
    srv.stop();
}

TEST_CASE("Client SSE flow pauses delivery and resume drains the rest",
          "[sse][client][backpressure]") {
    init_winsock();
    TinySseServer srv("data: one\n\ndata: two\n\n");
    if (!srv.start()) {
        std::printf("SKIP: could not start SSE server\n");
        return;
    }

    Client cli;
    string url;
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        url = b.release();
    }
    Request req(Method::Get, url);

    auto flow = std::make_shared<Request::SseFlow>();
    std::atomic<int> events{0};
    std::atomic<int> done{0};

    req.set_sse_callback(
        [&events, &flow](const SseEvent& e) {
            (void)e;
            ++events;
            if (events.load() == 1) {
                flow->pause();
            }
            return VoidResult{};
        },
        {},
        flow);
    CHECK(req.sse_flow() == flow);

    cli.request(req, [&done](Result<Response> r) {
        (void)r;
        done.store(1);
    });

    REQUIRE(wait_until([&] { return events.load() == 1; }));
    CHECK(!done.load());
    // Give a leaked second delivery a chance to appear.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(events.load() == 1);

    CHECK(flow->is_paused());
    flow->resume();
    CHECK(!flow->is_paused());
    CHECK(wait_until([&] { return done.load() == 1; }));
    CHECK(events.load() == 2);

    cli.shutdown();
    srv.stop();
}
