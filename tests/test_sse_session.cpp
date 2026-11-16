// SSE session integration test (task book 11, S6.1 reconnect).
//
// A local server that sends events, then drops the connection. The session must
// reconnect, send Last-Event-ID, and keep delivering.

#include <megohttp/client.hpp>
#include <megohttp/sse_session.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using sock_t = SOCKET;
const sock_t kBadSock = INVALID_SOCKET;
inline void sock_close(sock_t s) { ::closesocket(s); }
inline bool sock_init() {
    static bool once = [] {
        WSADATA w{};
        return WSAStartup(MAKEWORD(2, 2), &w) == 0;
    }();
    return once;
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using sock_t = int;
const sock_t kBadSock = -1;
inline void sock_close(sock_t s) { ::close(s); }
inline bool sock_init() { return true; }
#endif

using namespace megohttp;
using namespace std::chrono_literals;

namespace {

    bool wait_until(const std::function<bool()>& pred, int ms = 4000) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            std::this_thread::sleep_for(5ms);
        }
        return false;
    }

    std::string lower(std::string s) {
        for (char& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    std::string header_value(const std::string& head, const std::string& name) {
        const std::string lh = lower(head);
        const std::string needle = lower(name) + ":";
        size_t pos = lh.find(needle);
        if (pos == std::string::npos) return {};
        size_t vs = pos + needle.size();
        size_t ve = head.find("\r\n", vs);
        if (ve == std::string::npos) return {};
        while (vs < ve && (head[vs] == ' ' || head[vs] == '\t')) ++vs;
        return head.substr(vs, ve - vs);
    }

    // Serves N sequential SSE connections. The first one sends its events then
    // closes; a reconnect must arrive with Last-Event-ID set.
    class SseDroppingServer {
    public:
        struct Reply {
            std::string status_line{"HTTP/1.1 200 OK"};
            std::string body;
            bool close_after{true};
            std::vector<std::string> extra_headers;
        };

        ~SseDroppingServer() { stop(); }

        bool start(std::vector<Reply> replies) {
            replies_ = std::move(replies);
            ls_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (ls_ == kBadSock) return false;
            int one = 1;
            setsockopt(ls_, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&one), sizeof one);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = 0;
            if (::bind(ls_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
                sock_close(ls_); ls_ = kBadSock; return false;
            }
            if (::listen(ls_, 8) != 0) { sock_close(ls_); ls_ = kBadSock; return false; }
            socklen_t al = sizeof a;
            getsockname(ls_, reinterpret_cast<sockaddr*>(&a), &al);
            port_ = ntohs(a.sin_port);
            running_ = true;
            th_ = std::thread([this] { serve(); });
            std::this_thread::sleep_for(50ms);
            return true;
        }

        void stop() {
            running_ = false;
            if (ls_ != kBadSock) { sock_close(ls_); ls_ = kBadSock; }
            if (th_.joinable()) th_.join();
        }

        uint16_t port() const { return port_; }
        size_t connections() const { return connections_; }
        std::vector<std::string> request_heads() const { return heads_; }

    private:
        void serve() {
            size_t idx = 0;
            while (running_) {
                sockaddr_in ca{};
                socklen_t cl = sizeof ca;
                sock_t c = ::accept(ls_, reinterpret_cast<sockaddr*>(&ca), &cl);
                if (c == kBadSock) return;
                ++connections_;

                std::string head;
                char buf[4096];
                while (head.find("\r\n\r\n") == std::string::npos) {
                    int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                    if (n <= 0) break;
                    head.append(buf, static_cast<size_t>(n));
                }
                heads_.push_back(head);

                const Reply& r = replies_[idx < replies_.size() ? idx : replies_.size() - 1];
                ++idx;

                std::string resp = r.status_line + "\r\n";
                resp += "Content-Type: text/event-stream\r\n";
                for (const auto& h : r.extra_headers) resp += h + "\r\n";
                if (!r.close_after) {
                    resp += "Connection: keep-alive\r\n";
                } else {
                    resp += "Connection: close\r\n";
                }
                resp += "Content-Length: " + std::to_string(r.body.size()) + "\r\n\r\n";
                resp += r.body;
                ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
                sock_close(c);

                if (idx >= replies_.size() && running_) {
                    // Keep the accept loop alive so a late reconnect is recorded
                    // rather than refused (which would look like a network error).
                    std::this_thread::sleep_for(20ms);
                }
            }
        }

        sock_t ls_{kBadSock};
        uint16_t port_{0};
        std::atomic<bool> running_{false};
        std::thread th_;
        std::vector<Reply> replies_;
        std::atomic<size_t> connections_{0};
        std::vector<std::string> heads_;
    };

} // namespace

TEST_CASE("sse session delivers events from one connection", "[sse][session]") {
    sock_init();
    SseDroppingServer srv;
    SseDroppingServer::Reply r;
    r.status_line = "HTTP/1.1 200 OK";
    r.body = "id: 1\ndata: first\n\nid: 2\ndata: second\n\n";
    REQUIRE(srv.start({r}));

    Client client;
    Request req(Method::Get, string("http://127.0.0.1"));
    // Port is only known after start(), so rebuild the URL.
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        detail::sb_append(b, "/events");
        req.set_url(to_view(b.release()));
    }

    SseReconnectPolicy policy;
    policy.auto_reconnect = false;   // one shot

    auto session = client.request_sse(req, policy);

    std::vector<std::string> events;
    std::atomic<int> completed{0};
    Error err;
    std::mutex m;

    session->on_event([&](const SseEvent& e) {
        std::lock_guard<std::mutex> lk(m);
        events.emplace_back(e.data.data(), e.data.size());
    });
    session->on_error([&](const Error& e) { std::lock_guard<std::mutex> lk(m); err = e; });
    session->on_complete([&] { completed.fetch_add(1); });

    session->start();

    CHECK(wait_until([&] { return completed.load() > 0; }));
    {
        std::lock_guard<std::mutex> lk(m);
        REQUIRE(events.size() == 2);
        CHECK(events[0] == "first");
        CHECK(events[1] == "second");
    }
    // The session ended by EOF without a reconnect policy, so no error.
    CHECK(srv.connections() == 1);

    session->cancel();
    client.shutdown();
    srv.stop();
}

TEST_CASE("sse session reconnects and sends Last-Event-ID", "[sse][session]") {
    sock_init();
    SseDroppingServer srv;

    SseDroppingServer::Reply first;
    first.body = "id: 7\ndata: one\n\nid: 9\ndata: two\n\n";

    SseDroppingServer::Reply second;
    second.body = "id: 10\ndata: three\n\n";

    REQUIRE(srv.start({first, second}));

    Client client;
    Request req(Method::Get, string("http://127.0.0.1"));
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        detail::sb_append(b, "/events");
        req.set_url(to_view(b.release()));
    }

    SseReconnectPolicy policy;
    policy.auto_reconnect = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(20);
    policy.backoff.max_delay = std::chrono::milliseconds(50);
    policy.backoff.max_attempts = 3;
    policy.backoff.jitter_ratio = 0.0;

    auto session = client.request_sse(req, policy);

    std::atomic<size_t> count{0};
    std::atomic<int> completed{0};
    session->on_event([&](const SseEvent&) { count.fetch_add(1); });
    session->on_complete([&] { completed.fetch_add(1); });

    session->start();

    // Two connections must happen, and the second must carry Last-Event-ID: 9.
    CHECK(wait_until([&] { return srv.connections() >= 2; }, 5000));

    const auto heads = srv.request_heads();
    REQUIRE(heads.size() >= 2);
    // First connection has no Last-Event-ID.
    CHECK(header_value(heads[0], "Last-Event-ID").empty());
    // Second reconnects from the last seen id.
    CHECK(header_value(heads[1], "Last-Event-ID") == "9");

    session->cancel();
    client.shutdown();
    srv.stop();
}

TEST_CASE("sse session stops on 204", "[sse][session]") {
    sock_init();
    SseDroppingServer srv;
    SseDroppingServer::Reply r;
    r.status_line = "HTTP/1.1 204 No Content";
    REQUIRE(srv.start({r}));

    Client client;
    Request req(Method::Get, string("http://127.0.0.1"));
    {
        string_builder b;
        detail::sb_append(b, "http://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", srv.port())));
        req.set_url(to_view(b.release()));
    }

    SseReconnectPolicy policy;
    policy.auto_reconnect = true;   // must NOT reconnect after 204

    auto session = client.request_sse(req, policy);
    std::atomic<int> completed{0};
    session->on_complete([&] { completed.fetch_add(1); });
    session->start();

    CHECK(wait_until([&] { return completed.load() > 0; }));
    // Give a reconnect a chance to happen if it were going to.
    std::this_thread::sleep_for(150ms);
    CHECK(srv.connections() == 1);

    session->cancel();
    client.shutdown();
    srv.stop();
}
