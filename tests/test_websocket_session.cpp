// WebSocket session integration tests (task book 12, phase 6 / S6.2-01).
//
// A real local server that performs the Upgrade handshake and echoes frames.
// The accept value is computed from the key the CLIENT actually sent, which is
// the only way to test the handshake without pinning the client's random key.

#include <megohttp/websocket_session.hpp>
#include <megohttp/backend/executor_libuv.hpp>
#include <megohttp/transport.hpp>
#include <megohttp/resolver.hpp>

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

    bool wait_until(const std::function<bool()>& pred, int ms = 3000) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            std::this_thread::sleep_for(5ms);
        }
        return false;
    }

    // Pull one header value out of a raw request head.
    std::string header_value(const std::string& head, const std::string& name) {
        std::string lower_head, lower_name;
        for (char c : head) lower_head.push_back(static_cast<char>(::tolower(c)));
        for (char c : name) lower_name.push_back(static_cast<char>(::tolower(c)));
        const std::string needle = lower_name + ":";
        size_t pos = lower_head.find(needle);
        if (pos == std::string::npos) return {};
        size_t vstart = pos + needle.size();
        size_t vend = head.find("\r\n", vstart);
        if (vend == std::string::npos) return {};
        while (vstart < vend && (head[vstart] == ' ' || head[vstart] == '\t')) ++vstart;
        return head.substr(vstart, vend - vstart);
    }

    // A single-connection WebSocket server: handshake, then echo data frames.
    class WsEchoServer {
    public:
        ~WsEchoServer() { stop(); }

        bool start() {
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
            if (::listen(ls_, 1) != 0) { sock_close(ls_); ls_ = kBadSock; return false; }

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
        std::string request_head() const { return request_head_; }
        // Bytes the client sent after the head (i.e. its frames).
        std::vector<uint8_t> client_frames() const { return client_frames_; }

        // Inject a server->client frame right after the handshake.
        void set_greeting(std::vector<uint8_t> f) { greeting_ = std::move(f); }
        // Answer the upgrade with this instead of 101 (for the failure test).
        void set_reject_status(const std::string& s) { reject_ = s; }
        // Accept permessage-deflate (echoing the header back) — the server does
        // NOT actually compress; the tests only assert negotiation and whether
        // the client sets RSV1 on the frames it writes.
        void accept_deflate(std::string response_value = "permessage-deflate") {
            accept_ext_ = std::move(response_value);
        }

    private:
        void serve() {
            sockaddr_in ca{};
            socklen_t cl = sizeof ca;
            sock_t c = ::accept(ls_, reinterpret_cast<sockaddr*>(&ca), &cl);
            if (c == kBadSock) return;

            // --- read the request head ---
            std::string head;
            char buf[4096];
            while (head.find("\r\n\r\n") == std::string::npos) {
                int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                if (n <= 0) { sock_close(c); return; }
                head.append(buf, static_cast<size_t>(n));
            }
            request_head_ = head;

            if (!reject_.empty()) {
                ::send(c, reject_.data(), static_cast<int>(reject_.size()), 0);
                sock_close(c);
                return;
            }

            // --- handshake, computing accept from the CLIENT's key ---
            const std::string key = header_value(head, "Sec-WebSocket-Key");
            const string acc = ws_detail::accept_key_for(to_view(string(key.c_str())));

            std::string resp;
            resp += "HTTP/1.1 101 Switching Protocols\r\n";
            resp += "Upgrade: websocket\r\n";
            resp += "Connection: Upgrade\r\n";
            resp += "Sec-WebSocket-Accept: ";
            resp.append(acc.data(), acc.size());
            resp += "\r\n";
            if (!accept_ext_.empty()) {
                resp += "Sec-WebSocket-Extensions: " + accept_ext_ + "\r\n";
            }
            resp += "\r\n";
            if (::send(c, resp.data(), static_cast<int>(resp.size()), 0) <= 0) {
                sock_close(c); return;
            }

            if (!greeting_.empty()) {
                ::send(c, reinterpret_cast<const char*>(greeting_.data()),
                       static_cast<int>(greeting_.size()), 0);
            }

            // --- echo any frames the client sends ---
            for (;;) {
                int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                if (n <= 0) break;
                client_frames_.insert(client_frames_.end(), buf, buf + n);
                // Echo the raw bytes back (a masked client frame unmasked would
                // be wrong for a real server, so unmask then re-frame).
                auto echo = unmask_and_reframe(buf, static_cast<size_t>(n));
                if (!echo.empty()) {
                    ::send(c, reinterpret_cast<const char*>(echo.data()),
                           static_cast<int>(echo.size()), 0);
                }
            }
            sock_close(c);
        }

        // Client frames are masked; a server echoes the payload unmasked.
        static std::vector<uint8_t> unmask_and_reframe(const char* data, size_t size) {
            std::vector<uint8_t> out;
            size_t i = 0;
            while (i + 2 <= size) {
                const uint8_t b0 = static_cast<uint8_t>(data[i]);
                const uint8_t b1 = static_cast<uint8_t>(data[i + 1]);
                const bool masked = (b1 & 0x80) != 0;
                size_t len = b1 & 0x7F;
                size_t hdr = 2;
                if (len == 126) {
                    if (i + 4 > size) break;
                    len = (static_cast<size_t>(static_cast<uint8_t>(data[i + 2])) << 8) |
                          static_cast<size_t>(static_cast<uint8_t>(data[i + 3]));
                    hdr = 4;
                } else if (len == 127) {
                    break;  // not needed for these tests
                }
                size_t need = hdr + (masked ? 4 : 0) + len;
                if (i + need > size) break;

                std::vector<uint8_t> payload(data + i + hdr + (masked ? 4 : 0),
                                             data + i + need);
                if (masked) {
                    const uint8_t* m = reinterpret_cast<const uint8_t*>(data + i + hdr);
                    for (size_t k = 0; k < payload.size(); ++k) {
                        payload[k] = static_cast<uint8_t>(payload[k] ^ m[k % 4]);
                    }
                }
                // Server->client: unmasked.
                out.push_back(b0);
                if (payload.size() < 126) {
                    out.push_back(static_cast<uint8_t>(payload.size()));
                } else {
                    out.push_back(126);
                    out.push_back(static_cast<uint8_t>(payload.size() >> 8));
                    out.push_back(static_cast<uint8_t>(payload.size()));
                }
                out.insert(out.end(), payload.begin(), payload.end());
                i += need;
            }
            return out;
        }

        sock_t ls_{kBadSock};
        uint16_t port_{0};
        std::atomic<bool> running_{false};
        std::thread th_;
        std::string request_head_;
        std::vector<uint8_t> client_frames_;
        std::vector<uint8_t> greeting_;
        std::string reject_;
        std::string accept_ext_;
    };

    // RAII wiring for one session over a real TCP connection.
    using megohttp::libuv_backend::UvExecutor;

    struct SessionFixture {
        std::shared_ptr<UvExecutor> exec;
        std::shared_ptr<TcpStream> stream;
        std::shared_ptr<WebSocketSession> session;

        bool connect(uint16_t port) {
            exec = UvExecutor::create_internal();
            if (!exec) return false;

            ResolvedAddress target;
            target.family = ResolvedAddress::Family::IPv4;
            target.text = "127.0.0.1";
            target.bytes = {127, 0, 0, 1};
            target.port = port;

            stream = std::make_shared<TcpStream>(exec, target);
            std::atomic<bool> done{false};
            std::atomic<bool> ok{false};
            // AsyncByteStream is not thread-safe: every call must be made from
            // the loop thread.
            exec->post([&] {
                stream->start([&](VoidResult r) {
                    ok.store(static_cast<bool>(r));
                    done.store(true);
                });
            });
            return wait_until([&] { return done.load(); }) && ok.load();
        }

        // Run `fn` on the executor's loop thread and wait for it to finish.
        void on_loop(std::function<void()> fn) {
            std::atomic<bool> done{false};
            exec->post([&] { fn(); done.store(true); });
            wait_until([&] { return done.load(); });
        }

        ~SessionFixture() {
            if (session) session->terminate();
            if (exec) exec->shutdown();
        }
    };

} // namespace

TEST_CASE("ws session performs the upgrade handshake", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    Error open_err;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/chat"), Headers{},
                          [&](const Error& e) {
                              open_err = e;
                              opened.store(true);
                          });
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    CHECK(!open_err);
    CHECK(fx.session->handshake_complete());
    CHECK(fx.session->state() == WebSocketState::Open);

    // The request the server saw must be a legal Upgrade.
    const std::string head = srv.request_head();
    CHECK(head.rfind("GET /chat HTTP/1.1", 0) == 0);
    CHECK(header_value(head, "Upgrade") == "websocket");
    CHECK(header_value(head, "Sec-WebSocket-Version") == "13");
    CHECK(!header_value(head, "Sec-WebSocket-Key").empty());
}

TEST_CASE("ws on_before_handshake refreshes credentials before the upgrade",
          "[websocket][session]") {
    // D6: the hook is what lets a reconnect attach a token that was rotated
    // while the connection was down. It must run BEFORE the request is written
    // and must be able to both add and replace headers.
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    WebSocketOptions opt;
    int calls = 0;
    opt.on_before_handshake = [&calls](Headers& h) {
        ++calls;
        h.set("Authorization", "Bearer fresh-token");
        h.set("X-Attempt", "1");
    };

    std::atomic<bool> opened{false};
    Error open_err;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opt, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/chat"), Headers{},
                          [&](const Error& e) {
                              open_err = e;
                              opened.store(true);
                          });
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    CHECK(!open_err);
    CHECK(calls == 1);

    const std::string head = srv.request_head();
    CHECK(header_value(head, "Authorization") == "Bearer fresh-token");
    CHECK(header_value(head, "X-Attempt") == "1");
}

TEST_CASE("ws async_prepare_headers runs before the upgrade and can add a token",
          "[websocket][session]") {
    // The asynchronous form exists so a caller never has to block the I/O
    // thread fetching a token. The attempt must wait for the completion.
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    WebSocketOptions opt;
    std::atomic<bool> prepared{false};
    opt.async_prepare_headers = [&prepared](std::function<void(VoidResult, const Headers&)> done) {
        // Simulate an out-of-band fetch completing on another thread.
        std::thread([&prepared, done]() {
            Headers h;
            h.set("Authorization", "Bearer async-token");
            prepared.store(true);
            done(VoidResult{}, h);
        }).detach();
    };

    std::atomic<bool> opened{false};
    Error open_err;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opt, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/chat"), Headers{},
                          [&](const Error& e) {
                              open_err = e;
                              opened.store(true);
                          });
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    CHECK(prepared.load());
    CHECK(!open_err);
    CHECK(header_value(srv.request_head(), "Authorization") == "Bearer async-token");
}

TEST_CASE("ws async_prepare_headers failure aborts the attempt", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    WebSocketOptions opt;
    opt.async_prepare_headers = [](std::function<void(VoidResult, const Headers&)> done) {
        done(Error{ErrorCode::Cancelled, ErrorPhase::None, string("token fetch cancelled")},
             Headers{});
    };

    std::atomic<bool> opened{false};
    Error open_err;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opt, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/chat"), Headers{},
                          [&](const Error& e) {
                              open_err = e;
                              opened.store(true);
                          });
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    CHECK(open_err.code() == ErrorCode::Cancelled);
    // The request never went out.
    CHECK(srv.request_head().empty());
}

TEST_CASE("ws session rejects a non-101 upgrade response", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.set_reject_status("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    Error open_err;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error& e) {
                              open_err = e;
                              opened.store(true);
                          });
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    CHECK(static_cast<bool>(open_err));
    CHECK(open_err.code() == ErrorCode::WsHandshakeFailed);
    CHECK(fx.session->state() == WebSocketState::Closed);
}

TEST_CASE("ws session sends a masked text frame", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    std::atomic<bool> sent{false};
    fx.on_loop([&] {
        fx.session->send_text(string("hello-小明"), [&](const Error& e) {
            CHECK(!e);
            sent.store(true);
        });
    });
    REQUIRE(wait_until([&] { return sent.load(); }));

    // The server keeps whatever the client wrote after the head.
    REQUIRE(wait_until([&] { return !srv.client_frames().empty(); }));
    const auto frames = srv.client_frames();
    REQUIRE(frames.size() >= 2);
    CHECK(frames[0] == 0x81);              // FIN + text
    CHECK((frames[1] & 0x80) != 0);        // MASK bit set: a client frame
    // Payload length from the 7-bit field, then 4 mask bytes, then data.
    const size_t len = frames[1] & 0x7F;
    CHECK(frames.size() >= 2 + 4 + len);
}

TEST_CASE("ws session receives a text message", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    // Greeting: server->client unmasked text frame sent right after the 101.
    const std::string msg = "from-server";
    std::vector<uint8_t> frame;
    frame.push_back(0x81);                                  // FIN + text
    frame.push_back(static_cast<uint8_t>(msg.size()));      // unmasked
    frame.insert(frame.end(), msg.begin(), msg.end());
    srv.set_greeting(frame);

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> got{false};
    std::string received;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.session->on_message([&](WsMessageType type, const std::vector<uint8_t>& data) {
        if (type == WsMessageType::Text) {
            received.assign(data.begin(), data.end());
            got.store(true);
        }
    });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(wait_until([&] { return got.load(); }));
    CHECK(received == msg);
}

TEST_CASE("ws session answers a ping with a pong", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    const std::string payload = "ka";
    std::vector<uint8_t> ping;
    ping.push_back(0x89);                                            // FIN + ping
    ping.push_back(static_cast<uint8_t>(payload.size()));
    ping.insert(ping.end(), payload.begin(), payload.end());
    srv.set_greeting(ping);

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    // auto_pong is on by default, so the client must write a Pong back.
    auto is_pong = [&] {
        const auto f = srv.client_frames();
        return !f.empty() && (f[0] & 0x0F) == 0x0A;
    };
    REQUIRE(wait_until(is_pong));
    const auto f = srv.client_frames();
    CHECK((f[0] & 0x80) != 0);   // FIN
    CHECK((f[0] & 0x0F) == 0x0A);  // pong opcode
    CHECK((f[1] & 0x80) != 0);   // masked, as a client frame must be
}

TEST_CASE("ws session closes with a close frame", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> closed_cb{false};
    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.session->on_close([&](uint16_t, const string&) { closed_cb.store(true); });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    fx.on_loop([&] { fx.session->close(1000, "bye"); });
    CHECK(closed_cb.load());

    auto is_close = [&] {
        const auto f = srv.client_frames();
        return !f.empty() && (f[0] & 0x0F) == 0x08;
    };
    REQUIRE(wait_until(is_close));
    CHECK(fx.session->state() != WebSocketState::Open);
}

TEST_CASE("ws session negotiates permessage-deflate and sets RSV1", "[websocket][session][deflate]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    Error open_err;
    WebSocketOptions opts;
    opts.enable_deflate = true;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error& e) { open_err = e; opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(!open_err);

    // The negotiation result must be queryable, and the offer must have gone out.
    CHECK(fx.session->negotiated_deflate().enabled);
    const std::string head = srv.request_head();
    CHECK(head.find("Sec-WebSocket-Extensions: permessage-deflate") != std::string::npos);

    // A compressed message: the first frame's RSV1 bit must be set.
    std::atomic<bool> sent{false};
    fx.on_loop([&] {
        fx.session->send_text(string("compressible compressible compressible"),
                              [&](const Error& e) { sent.store(true); (void)e; });
    });
    REQUIRE(wait_until([&] { return sent.load(); }));
    REQUIRE(wait_until([&] { return !srv.client_frames().empty(); }));

    const auto f = srv.client_frames();
    REQUIRE(f.size() >= 2);
    // FIN (0x80) + RSV1 (0x40) + text opcode (0x01) = 0xC1.
    CHECK(f[0] == 0xC1);
    CHECK((f[0] & 0x40) != 0);     // RSV1 set: the payload is compressed
    CHECK((f[1] & 0x80) != 0);     // masked, as a client frame must be
}

TEST_CASE("ws session continues uncompressed when the server declines deflate",
          "[websocket][session][deflate]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    // No Sec-WebSocket-Extensions in the response at all: legal per RFC 7692.

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    WebSocketOptions opts;
    opts.enable_deflate = true;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    // Declined extension is not a failure, and no compression is in effect.
    CHECK(!fx.session->negotiated_deflate().enabled);

    std::atomic<bool> sent{false};
    fx.on_loop([&] {
        fx.session->send_text(string("plain text"), [&](const Error&) { sent.store(true); });
    });
    REQUIRE(wait_until([&] { return sent.load(); }));
    REQUIRE(wait_until([&] { return !srv.client_frames().empty(); }));

    const auto f = srv.client_frames();
    REQUIRE(f.size() >= 2);
    CHECK((f[0] & 0x40) == 0);  // RSV1 must stay clear
}

TEST_CASE("ws session rejects a compressed frame without negotiation",
          "[websocket][session][deflate]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    // Server never accepted the extension, yet sends RSV1: a protocol error.

    std::vector<uint8_t> frame;
    frame.push_back(0xC1);  // FIN + RSV1 + text
    const std::string payload = "not-really-deflate";
    frame.push_back(static_cast<uint8_t>(payload.size()));
    frame.insert(frame.end(), payload.begin(), payload.end());
    srv.set_greeting(frame);

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> errored{false};
    Error seen;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.session->on_error([&](const Error& e) { seen = e; errored.store(true); });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(wait_until([&] { return errored.load(); }));
    CHECK(seen.code() == ErrorCode::WsProtocolError);
}
