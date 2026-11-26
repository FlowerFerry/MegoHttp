// Response head callback tests (S1.7-05; task book 6.4 / 7.1).
//
// A local server sends the response head immediately and the body after a
// delay, so "the head arrived before the body" is observable rather than
// inferred. The callback must also stay out of the body consumers' way and
// respect redirect/retry semantics.

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace megohttp;

namespace {

#if defined(_WIN32)
using sock_t = SOCKET;
constexpr sock_t kInvalid = INVALID_SOCKET;
inline void closesock(sock_t s) { ::closesocket(s); }
inline void ensure_wsa() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA w{};
        WSAStartup(MAKEWORD(2, 2), &w);
    });
}
#else
using sock_t = int;
constexpr sock_t kInvalid = -1;
inline void closesock(sock_t s) { ::close(s); }
inline void ensure_wsa() {}
#endif

std::string lowercase(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim(const std::string& s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(b, e - b);
}

std::string header_value(const std::string& head, const std::string& name) {
    const std::string lower_head = lowercase(head);
    const std::string needle = "\r\n" + lowercase(name) + ":";
    size_t p = lower_head.find(needle);
    if (p == std::string::npos) return {};
    p += needle.size();
    size_t e = lower_head.find("\r\n", p);
    if (e == std::string::npos) e = head.size();
    return head.substr(p, e - p);
}

// Sends the head, waits delay_ms, then sends the body. One reply per
// connection; replies are consumed in order.
class DelayedServer {
public:
    struct Reply {
        std::string head;
        std::string body;
        int delay_ms{0};
    };

    ~DelayedServer() { stop(); }

    bool start() {
        ensure_wsa();
        s_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s_ == kInvalid) return false;
        int yes = 1;
        ::setsockopt(s_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&yes), sizeof yes);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(s_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        socklen_t len = sizeof a;
        ::getsockname(s_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        if (::listen(s_, 8) != 0) return false;
        th_ = std::thread([this] { serve(); });
        return true;
    }

    void stop() {
        if (stop_.exchange(true)) return;
        if (s_ != kInvalid) {
            closesock(s_);
            s_ = kInvalid;
        }
        if (th_.joinable()) th_.join();
    }

    uint16_t port() const { return port_; }

    void push(Reply r) {
        std::lock_guard<std::mutex> g(mu_);
        replies_.push_back(std::move(r));
    }

    size_t accepts() const { return accepts_.load(); }

private:
    static bool send_all(sock_t c, const std::string& data) {
        size_t off = 0;
        while (off < data.size()) {
            const int n = static_cast<int>(
                ::send(c, data.data() + off,
                       static_cast<int>(data.size() - off), 0));
            if (n <= 0) return false;
            off += static_cast<size_t>(n);
        }
        return true;
    }

    void serve() {
        while (!stop_.load()) {
            sock_t c = ::accept(s_, nullptr, nullptr);
            if (c == kInvalid) break;
            ++accepts_;
            handle(c);
        }
    }

    void handle(sock_t c) {
        std::string raw;
        char buf[4096];
        size_t head_end = std::string::npos;
        while ((head_end = raw.find("\r\n\r\n")) == std::string::npos) {
            const int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
            if (n <= 0) { closesock(c); return; }
            raw.append(buf, static_cast<size_t>(n));
            if (raw.size() > 1024 * 1024) { closesock(c); return; }
        }

        const std::string head = raw.substr(0, head_end);
        size_t body_have = raw.size() - (head_end + 4);

        const std::string cl = trim(header_value(head, "content-length"));
        size_t want = 0;
        if (!cl.empty()) {
            want = static_cast<size_t>(std::strtoull(cl.c_str(), nullptr, 10));
        }
        while (body_have < want) {
            const int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
            if (n <= 0) break;
            body_have += static_cast<size_t>(n);
        }

        Reply reply = pop_reply();
        (void)send_all(c, reply.head);
        if (reply.delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(reply.delay_ms));
        }
        if (!reply.body.empty()) (void)send_all(c, reply.body);
        closesock(c);
    }

    Reply pop_reply() {
        std::lock_guard<std::mutex> g(mu_);
        if (!replies_.empty()) {
            Reply r = std::move(replies_.front());
            replies_.pop_front();
            return r;
        }
        return Reply{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                     "Connection: close\r\n\r\n", "ok", 0};
    }

    sock_t s_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<size_t> accepts_{0};
    std::thread th_;
    mutable std::mutex mu_;
    std::deque<Reply> replies_;
};

string to_owning(const std::string& s) { return string(s.c_str(), s.size()); }

std::string url_for(uint16_t port, const char* path = "/head") {
    return "http://127.0.0.1:" + std::to_string(port) + path;
}

std::string ok_head(int length = 5) {
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(length) + "\r\n"
           "Connection: close\r\n\r\n";
}

} // namespace

TEST_CASE("the head callback fires before the streaming body starts",
          "[head-callback][client][streaming]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({ok_head(5), "hello", 200});

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    std::atomic<bool> head_seen{false};
    std::atomic<bool> body_seen{false};
    std::atomic<bool> complete_seen{false};
    std::atomic<bool> head_before_body{false};
    std::atomic<bool> head_before_complete{false};
    std::atomic<int> status{0};
    std::atomic<uint64_t> content_length{0};

    req.set_head_callback([&](const ResponseHead& h) {
        head_before_body = !body_seen.load();
        head_before_complete = !complete_seen.load();
        status = h.status_code;
        if (h.content_length) content_length = *h.content_length;
        head_seen = true;
    });
    auto flow = std::make_shared<Request::BodySinkFlow>();
    req.set_body_sink(
        [&](string_view) {
            body_seen = true;
            return true;
        },
        [&](VoidResult) { complete_seen = true; },
        flow);

    auto r = c.request_sync(req);
    REQUIRE(r);

    CHECK(head_seen.load());
    CHECK(body_seen.load());
    CHECK(complete_seen.load());
    CHECK(head_before_body.load());
    CHECK(head_before_complete.load());
    CHECK(status.load() == 200);
    CHECK(content_length.load() == 5);
    // Streaming mode still delivers the head at terminal too.
    CHECK(r.value().head().status_code == 200);
    CHECK(r.value().head().content_type.has_value());
    CHECK(*r.value().head().content_type == "text/plain");

    c.shutdown();
    srv.stop();
}

TEST_CASE("the head callback fires before a buffered response completes",
          "[head-callback][client][buffered]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({ok_head(5), "hello", 250});

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    std::mutex m;
    std::condition_variable cv;
    bool head_seen = false;
    bool done = false;
    bool ok = false;
    int status = 0;
    std::chrono::steady_clock::time_point head_at;
    std::chrono::steady_clock::time_point done_at;

    req.set_head_callback([&](const ResponseHead& h) {
        std::lock_guard<std::mutex> g(m);
        head_seen = true;
        status = h.status_code;
        head_at = std::chrono::steady_clock::now();
        cv.notify_all();
    });

    CancelHandle handle = c.request(req, [&](Result<Response> r) {
        std::lock_guard<std::mutex> g(m);
        done = true;
        ok = static_cast<bool>(r);
        done_at = std::chrono::steady_clock::now();
        cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lk(m);
        REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return head_seen; }));
        // The body is delayed by 250 ms, so the head cannot have waited for it.
        CHECK(!done);
        CHECK(status == 200);
    }
    {
        std::unique_lock<std::mutex> lk(m);
        REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return done; }));
        CHECK(ok);
        const auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(
            done_at - head_at);
        CHECK(gap.count() >= 100);
    }

    (void)handle;
    c.shutdown();
    srv.stop();
}

TEST_CASE("a followed redirect does not surface its intermediate head",
          "[head-callback][client][redirect]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({"HTTP/1.1 307 Temporary Redirect\r\n"
              "Location: " + url_for(srv.port(), "/next") + "\r\n"
              "Content-Length: 0\r\n"
              "Connection: close\r\n\r\n",
              "", 0});
    srv.push({ok_head(2), "ok", 0});

    ClientOptions opts;
    opts.redirects.follow = true;
    Client c(opts);

    std::mutex m;
    std::vector<int> seen;
    Request req(Method::Get, to_owning(url_for(srv.port())));
    req.set_head_callback([&](const ResponseHead& h) {
        std::lock_guard<std::mutex> g(m);
        seen.push_back(h.status_code);
    });

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    std::lock_guard<std::mutex> g(m);
    REQUIRE(seen.size() == 1);
    CHECK(seen[0] == 200);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a redirect that is not followed is a final head",
          "[head-callback][client][redirect]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({"HTTP/1.1 302 Found\r\n"
              "Location: " + url_for(srv.port(), "/other") + "\r\n"
              "Content-Length: 5\r\n"
              "Connection: close\r\n\r\n",
              "redir", 0});

    Client c;   // follow defaults to false
    std::atomic<int> calls{0};
    std::atomic<int> status{0};
    Request req(Method::Get, to_owning(url_for(srv.port())));
    req.set_head_callback([&](const ResponseHead& h) {
        ++calls;
        status = h.status_code;
    });

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 302);
    CHECK(calls.load() == 1);
    CHECK(status.load() == 302);

    c.shutdown();
    srv.stop();
}

TEST_CASE("each retry attempt delivers its own head",
          "[head-callback][client][retry]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({"HTTP/1.1 503 Service Unavailable\r\n"
              "Content-Length: 0\r\n"
              "Retry-After: 0\r\n"
              "Connection: close\r\n\r\n",
              "", 0});
    srv.push({ok_head(2), "ok", 0});

    ClientOptions opts;
    opts.retry.max_retries = 1;
    opts.retry.base_delay = std::chrono::milliseconds(1);
    opts.retry.max_delay = std::chrono::milliseconds(1);
    opts.retry.jitter = false;
    Client c(opts);

    std::mutex m;
    std::vector<int> seen;
    Request req(Method::Get, to_owning(url_for(srv.port())));
    req.set_head_callback([&](const ResponseHead& h) {
        std::lock_guard<std::mutex> g(m);
        seen.push_back(h.status_code);
    });

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    std::lock_guard<std::mutex> g(m);
    REQUIRE(seen.size() == 2);
    CHECK(seen[0] == 503);
    CHECK(seen[1] == 200);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a failure before any head produces no head callback",
          "[head-callback][client][error]") {
    Client c;
    std::atomic<int> calls{0};
    Request req(Method::Get, to_owning("http://127.0.0.1:65535/"));
    req.set_head_callback([&](const ResponseHead&) { ++calls; });

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(calls.load() == 0);

    c.shutdown();
}

TEST_CASE("the head callback runs on the client I/O thread",
          "[head-callback][client][thread]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({ok_head(2), "ok", 100});

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    std::mutex m;
    std::condition_variable cv;
    bool head_seen = false;
    bool done = false;
    bool ok = false;
    std::thread::id head_thread;
    std::thread::id done_thread;
    const auto caller_thread = std::this_thread::get_id();

    req.set_head_callback([&](const ResponseHead&) {
        std::lock_guard<std::mutex> g(m);
        head_thread = std::this_thread::get_id();
        head_seen = true;
        cv.notify_all();
    });

    CancelHandle handle = c.request(req, [&](Result<Response> r) {
        std::lock_guard<std::mutex> g(m);
        done_thread = std::this_thread::get_id();
        done = true;
        ok = static_cast<bool>(r);
        cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lk(m);
        REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return head_seen && done; }));
        CHECK(ok);
        CHECK(head_thread == done_thread);
        CHECK(head_thread != caller_thread);
    }

    (void)handle;
    c.shutdown();
    srv.stop();
}

TEST_CASE("a throwing head callback fails the request before any body",
          "[head-callback][client][error]") {
    DelayedServer srv;
    REQUIRE(srv.start());
    srv.push({ok_head(5), "hello", 150});

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    std::atomic<bool> body_seen{false};
    req.set_head_callback([](const ResponseHead&) {
        throw std::runtime_error("head callback failure");
    });
    auto flow = std::make_shared<Request::BodySinkFlow>();
    req.set_body_sink(
        [&](string_view) {
            body_seen = true;
            return true;
        },
        [](VoidResult) {},
        flow);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::Unknown);
    CHECK(r.error().phase() == ErrorPhase::Receive);
    CHECK(!body_seen.load());

    c.shutdown();
    srv.stop();
}
