// WebSocket auto-reconnect tests (task book 12.2, phase 6).
//
// A local server that serves N sequential WebSocket connections. The logical
// session must reconnect per the policy, report each physical attempt, and
// refuse sends while disconnected.

#include <megohttp/client.hpp>
#include <megohttp/websocket_reconnect.hpp>

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

    bool wait_until(const std::function<bool()>& pred, int ms = 5000) {
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

    // Handshake then immediately close, `times` times. After that, hold the
    // connection open so the session shows as connected.
    class WsHandshakeServer {
    public:
        ~WsHandshakeServer() { stop(); }

        bool start(size_t drop_count) {
            drop_ = drop_count;
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
        size_t connections() const { return connections_.load(); }
        std::vector<std::string> heads() const { return heads_; }

    private:
        void serve() {
            while (running_) {
                sockaddr_in ca{};
                socklen_t cl = sizeof ca;
                sock_t c = ::accept(ls_, reinterpret_cast<sockaddr*>(&ca), &cl);
                if (c == kBadSock) return;
                const size_t n = connections_.fetch_add(1) + 1;

                std::string head;
                char buf[4096];
                while (head.find("\r\n\r\n") == std::string::npos) {
                    int r = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                    if (r <= 0) break;
                    head.append(buf, static_cast<size_t>(r));
                }
                heads_.push_back(head);

                const std::string key = header_value(head, "Sec-WebSocket-Key");
                const string acc = ws_detail::accept_key_for(
                    to_view(string(key.c_str())));

                std::string resp;
                resp += "HTTP/1.1 101 Switching Protocols\r\n";
                resp += "Upgrade: websocket\r\n";
                resp += "Connection: Upgrade\r\n";
                resp += "Sec-WebSocket-Accept: ";
                resp.append(acc.data(), acc.size());
                resp += "\r\n\r\n";
                ::send(c, resp.data(), static_cast<int>(resp.size()), 0);

                if (n <= drop_) {
                    // Deliberate drop: the client must see this as a disconnect.
                    sock_close(c);
                    continue;
                }
                // Hold it open so the session stays "open" for the assertion.
                while (running_) {
                    int r = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                    if (r <= 0) break;
                }
                sock_close(c);
            }
        }

        sock_t ls_{kBadSock};
        uint16_t port_{0};
        std::atomic<bool> running_{false};
        size_t drop_{0};
        std::thread th_;
        std::atomic<size_t> connections_{0};
        std::vector<std::string> heads_;
    };

} // namespace

TEST_CASE("ws reconnect retries a dropped connection", "[websocket][reconnect]") {
    sock_init();
    WsHandshakeServer srv;
    REQUIRE(srv.start(/*drop_count=*/1));

    Client client;
    auto url = string("ws://127.0.0.1");

    WebSocketOptions wopt;
    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(20);
    policy.backoff.max_delay = std::chrono::milliseconds(60);
    policy.backoff.max_attempts = 5;
    policy.backoff.jitter_ratio = 0.0;

    std::atomic<size_t> succeeded{0};
    std::atomic<size_t> failed_attempts{0};
    std::atomic<size_t> gave_up{0};

    // Build the URL with the real port.
    string_builder ub;
    detail::sb_append(ub, "ws://127.0.0.1:");
    detail::sb_append(ub, to_view(format("{}", srv.port())));
    detail::sb_append(ub, "/ws");
    url = ub.release();

    auto ws = client.open_websocket(to_view(url), wopt, policy);
    ws->set_reconnect_events({
        nullptr,
        [&](size_t, const Error&) { failed_attempts.fetch_add(1); },
        [&](size_t, uint64_t) { succeeded.fetch_add(1); },
        [&](const Error&, size_t, bool) { gave_up.fetch_add(1); },
    });

    // The first connection is dropped, so a reconnect must follow.
    CHECK(wait_until([&] { return srv.connections() >= 2; }, 6000));
    CHECK(wait_until([&] { return ws->is_open(); }, 6000));
    CHECK(succeeded.load() >= 1);
    CHECK(failed_attempts.load() >= 1);
    CHECK(gave_up.load() == 0);

    ws->terminate();
    client.shutdown();
    srv.stop();
}

TEST_CASE("ws reconnect gives up after the budget", "[websocket][reconnect]") {
    sock_init();
    // Every connection drops: the budget must eventually stop the loop.
    WsHandshakeServer srv;
    REQUIRE(srv.start(/*drop_count=*/1000));

    Client client;
    WebSocketOptions wopt;
    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(10);
    policy.backoff.max_delay = std::chrono::milliseconds(20);
    policy.backoff.max_attempts = 3;
    policy.backoff.jitter_ratio = 0.0;

    string_builder ub;
    detail::sb_append(ub, "ws://127.0.0.1:");
    detail::sb_append(ub, to_view(format("{}", srv.port())));
    detail::sb_append(ub, "/ws");
    const string url = ub.release();

    std::atomic<size_t> gave_up{0};
    std::atomic<bool> ended{false};

    auto ws = client.open_websocket(to_view(url), wopt, policy);
    ws->set_reconnect_events({
        nullptr, nullptr, nullptr,
        [&](const Error&, size_t, bool final) {
            if (final) gave_up.fetch_add(1);
        },
    });
    ws->on_session_end([&](const Error*) { ended.store(true); });

    CHECK(wait_until([&] { return ended.load(); }, 8000));
    CHECK(gave_up.load() == 1);
    // Bounded: the loop did not run away.
    CHECK(srv.connections() <= 8);

    client.shutdown();
    srv.stop();
}

TEST_CASE("ws reconnect refuses sends while disconnected", "[websocket][reconnect]") {
    sock_init();
    WsHandshakeServer srv;
    // Drop the first connection and use a long backoff, so the session spends
    // measurable time disconnected.
    REQUIRE(srv.start(/*drop_count=*/1));

    Client client;
    WebSocketOptions wopt;
    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(300);
    policy.backoff.max_delay = std::chrono::milliseconds(300);
    policy.backoff.max_attempts = 3;
    policy.backoff.jitter_ratio = 0.0;

    string_builder ub;
    detail::sb_append(ub, "ws://127.0.0.1:");
    detail::sb_append(ub, to_view(format("{}", srv.port())));
    detail::sb_append(ub, "/ws");
    const string url = ub.release();

    auto ws = client.open_websocket(to_view(url), wopt, policy);

    // Wait until the first connection was dropped and the backoff started.
    CHECK(wait_until([&] { return ws->is_reconnecting(); }, 3000));

    bool sent = true;
    Error send_err;
    sent = ws->send_text(string("dropped"), [&](const Error& e) { send_err = e; });

    // No queueing across a disconnect: the send must be refused, not buffered.
    CHECK(!sent);
    CHECK(send_err.code() == ErrorCode::WsNotOpen);

    ws->terminate();
    client.shutdown();
    srv.stop();
}

TEST_CASE("ws reconnect stops after a local close", "[websocket][reconnect]") {
    sock_init();
    WsHandshakeServer srv;
    REQUIRE(srv.start(/*drop_count=*/1));

    Client client;
    WebSocketOptions wopt;
    WebSocketReconnectPolicy policy;
    policy.enabled = true;
    policy.backoff.initial_delay = std::chrono::milliseconds(20);
    policy.backoff.max_delay = std::chrono::milliseconds(40);
    policy.backoff.max_attempts = 20;   // generous: the close must stop it
    policy.backoff.jitter_ratio = 0.0;

    string_builder ub;
    detail::sb_append(ub, "ws://127.0.0.1:");
    detail::sb_append(ub, to_view(format("{}", srv.port())));
    detail::sb_append(ub, "/ws");
    const string url = ub.release();

    auto ws = client.open_websocket(to_view(url), wopt, policy);
    REQUIRE(wait_until([&] { return ws->is_open(); }, 6000));

    ws->close(1000, "done");
    CHECK(!ws->is_reconnecting());

    const size_t before = srv.connections();
    std::this_thread::sleep_for(200ms);
    // No further physical connection may be attempted after a local close,
    // even though the budget would have allowed many.
    CHECK(srv.connections() == before);

    client.shutdown();
    srv.stop();
}
