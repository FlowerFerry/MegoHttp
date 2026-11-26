// WebSocket session integration tests (task book 12, phase 6 / S6.2-01).
//
// A real local server that performs the Upgrade handshake and echoes frames.
// The accept value is computed from the key the CLIENT actually sent, which is
// the only way to test the handshake without pinning the client's random key.

#include <megohttp/websocket_session.hpp>
#include <megohttp/transport.hpp>
#include <megohttp/resolver.hpp>
#if MGHTTP_BACKEND_LIBUV
#include <megohttp/backend/executor_libuv.hpp>
#else
#include <megohttp/backend/executor_asio.hpp>
#endif

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
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

    struct ParsedClientFrame {
        bool fin{false};
        bool rsv1{false};
        uint8_t opcode{0};
        std::vector<uint8_t> payload;
    };

    // Parse as many complete CLIENT frames as the captured byte stream holds.
    // Incomplete trailing bytes are ignored: the server records whatever recv
    // returned, which may end mid-frame.
    std::vector<ParsedClientFrame> parse_client_frames(const std::vector<uint8_t>& bytes) {
        std::vector<ParsedClientFrame> out;
        size_t i = 0;
        while (i + 2 <= bytes.size()) {
            const uint8_t b0 = bytes[i];
            const uint8_t b1 = bytes[i + 1];
            const bool masked = (b1 & 0x80) != 0;
            size_t len = b1 & 0x7F;
            size_t hdr = 2;
            if (len == 126) {
                if (i + 4 > bytes.size()) break;
                len = (static_cast<size_t>(bytes[i + 2]) << 8) |
                      static_cast<size_t>(bytes[i + 3]);
                hdr = 4;
            } else if (len == 127) {
                if (i + 10 > bytes.size()) break;
                len = 0;
                for (int k = 0; k < 8; ++k) {
                    len = (len << 8) | static_cast<size_t>(bytes[i + 2 + k]);
                }
                hdr = 10;
            }
            const size_t need = hdr + (masked ? 4 : 0) + len;
            if (i + need > bytes.size()) break;

            ParsedClientFrame f;
            f.fin = (b0 & 0x80) != 0;
            f.rsv1 = (b0 & 0x40) != 0;
            f.opcode = b0 & 0x0F;
            f.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(i + hdr + (masked ? 4 : 0)),
                             bytes.begin() + static_cast<std::ptrdiff_t>(i + need));
            if (masked) {
                const uint8_t* m = bytes.data() + i + hdr;
                for (size_t k = 0; k < f.payload.size(); ++k) {
                    f.payload[k] = static_cast<uint8_t>(f.payload[k] ^ m[k % 4]);
                }
            }
            out.push_back(std::move(f));
            i += need;
        }
        return out;
    }

    // A server->client frame: never masked.
    std::vector<uint8_t> server_frame(WsOpcode op, const std::string& payload,
                                      bool fin = true, bool rsv1 = false) {
        std::vector<uint8_t> out;
        uint8_t b0 = static_cast<uint8_t>(op);
        if (fin) b0 |= 0x80;
        if (rsv1) b0 |= 0x40;
        out.push_back(b0);
        const size_t n = payload.size();
        if (n < 126) {
            out.push_back(static_cast<uint8_t>(n));
        } else if (n <= 0xFFFF) {
            out.push_back(126);
            out.push_back(static_cast<uint8_t>(n >> 8));
            out.push_back(static_cast<uint8_t>(n));
        } else {
            out.push_back(127);
            for (int i = 7; i >= 0; --i) {
                out.push_back(static_cast<uint8_t>(n >> (i * 8)));
            }
        }
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
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
            std::vector<uint8_t> echo_buf;
            for (;;) {
                int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                if (n <= 0) break;
                client_frames_.insert(client_frames_.end(), buf, buf + n);
                echo_buf.insert(echo_buf.end(), buf, buf + n);
                // Echo the raw bytes back (a masked client frame unmasked would
                // be wrong for a real server, so unmask then re-frame). The
                // parser keeps a partial trailing frame for the next recv: TCP
                // is free to split a frame.
                auto echo = unmask_and_reframe(echo_buf);
                if (!echo.empty()) {
                    ::send(c, reinterpret_cast<const char*>(echo.data()),
                           static_cast<int>(echo.size()), 0);
                }
            }
            sock_close(c);
        }

        // Client frames are masked; a server echoes the payload unmasked.
        // `data` is consumed up to the last complete frame; a trailing partial
        // frame stays in the buffer.
        static std::vector<uint8_t> unmask_and_reframe(std::vector<uint8_t>& data) {
            std::vector<uint8_t> out;
            size_t i = 0;
            while (i + 2 <= data.size()) {
                const uint8_t b0 = data[i];
                const uint8_t b1 = data[i + 1];
                const bool masked = (b1 & 0x80) != 0;
                size_t len = b1 & 0x7F;
                size_t hdr = 2;
                if (len == 126) {
                    if (i + 4 > data.size()) break;
                    len = (static_cast<size_t>(data[i + 2]) << 8) |
                          static_cast<size_t>(data[i + 3]);
                    hdr = 4;
                } else if (len == 127) {
                    if (i + 10 > data.size()) break;
                    len = 0;
                    for (int k = 0; k < 8; ++k) {
                        len = (len << 8) | static_cast<size_t>(data[i + 2 + k]);
                    }
                    hdr = 10;
                }
                size_t need = hdr + (masked ? 4 : 0) + len;
                if (i + need > data.size()) break;

                std::vector<uint8_t> payload(data.begin() + static_cast<std::ptrdiff_t>(i + hdr + (masked ? 4 : 0)),
                                             data.begin() + static_cast<std::ptrdiff_t>(i + need));
                if (masked) {
                    const uint8_t* m = data.data() + i + hdr;
                    for (size_t k = 0; k < payload.size(); ++k) {
                        payload[k] = static_cast<uint8_t>(payload[k] ^ m[k % 4]);
                    }
                }
                // Server->client: unmasked.
                out.push_back(b0);
                if (payload.size() < 126) {
                    out.push_back(static_cast<uint8_t>(payload.size()));
                } else if (payload.size() <= 0xFFFF) {
                    out.push_back(126);
                    out.push_back(static_cast<uint8_t>(payload.size() >> 8));
                    out.push_back(static_cast<uint8_t>(payload.size()));
                } else {
                    out.push_back(127);
                    for (int k = 7; k >= 0; --k) {
                        out.push_back(static_cast<uint8_t>(payload.size() >> (k * 8)));
                    }
                }
                out.insert(out.end(), payload.begin(), payload.end());
                i += need;
            }
            data.erase(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(i));
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
    // Both backends are supported: the fixture only needs "an Executor" and
    // "a TcpStream", which is exactly the abstraction the library is built on.
    struct SessionFixture {
        std::shared_ptr<Executor> exec;
        std::shared_ptr<TcpStream> stream;
        std::shared_ptr<WebSocketSession> session;

        bool connect(uint16_t port) {
#if MGHTTP_BACKEND_LIBUV
            exec = libuv_backend::UvExecutor::create_internal();
#else
            exec = asio_backend::AsioExecutor::create_internal();
#endif
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
#if MGHTTP_BACKEND_LIBUV
            if (auto e = std::dynamic_pointer_cast<libuv_backend::UvExecutor>(exec)) e->shutdown();
#else
            if (auto e = std::dynamic_pointer_cast<asio_backend::AsioExecutor>(exec)) e->shutdown();
#endif
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

#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
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

TEST_CASE("ws send queue exposes raw and wire occupancy", "[websocket][session][deflate][observability]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> sent{false};
    WebSocketOptions opts;
    opts.enable_deflate = true;
    opts.max_frame_size = 64;  // force several compressed frames

    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(fx.session->negotiated_deflate().enabled);

    std::string payload;
    for (int i = 0; i < 200; ++i) payload += "compressible observable payload ";

    fx.on_loop([&] {
        fx.session->send_text(string(payload.c_str()),
                              [&](const Error&) { sent.store(true); });
        // send_text returns after compression/enqueue; the write completion
        // cannot run until this loop callback returns.
        CHECK(fx.session->pending_send_raw_bytes() == payload.size());
        CHECK(fx.session->pending_send_bytes() > 0);
        CHECK(fx.session->pending_send_bytes() < payload.size());
    });

    REQUIRE(wait_until([&] { return sent.load(); }));
    REQUIRE(wait_until([&] { return fx.session->pending_send_raw_bytes() == 0; }));
    CHECK(fx.session->pending_send_bytes() == 0);
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
#endif

TEST_CASE("ws incremental receive delivers begin/data/end and keeps on_message off",
          "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    std::vector<uint8_t> greeting;
    auto a = server_frame(WsOpcode::Text, "hello ", false);
    auto ping = server_frame(WsOpcode::Ping, "k", true);
    auto b = server_frame(WsOpcode::Continuation, "world", true);
    greeting.insert(greeting.end(), a.begin(), a.end());
    greeting.insert(greeting.end(), ping.begin(), ping.end());
    greeting.insert(greeting.end(), b.begin(), b.end());
    srv.set_greeting(greeting);

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<int> begins{0};
    std::atomic<int> ends{0};
    std::atomic<bool> whole_called{false};
    std::atomic<bool> begin_compressed{true};
    WsMessageType begin_type{WsMessageType::Binary};
    std::mutex chunks_mutex;
    std::vector<std::string> chunks;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>&) {
        whole_called.store(true);
    });
    fx.session->set_incremental_message_callbacks(
        [&](WsMessageType t, bool compressed) {
            begin_type = t;
            begin_compressed.store(compressed);
            begins.fetch_add(1);
        },
        [&](const uint8_t* data, size_t size) {
            std::lock_guard<std::mutex> lk(chunks_mutex);
            chunks.emplace_back(reinterpret_cast<const char*>(data), size);
            return true;
        },
        [&]() { ends.fetch_add(1); });

    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(wait_until([&] { return ends.load() == 1; }));

    CHECK(begins.load() == 1);
    CHECK(begin_type == WsMessageType::Text);
    CHECK(!begin_compressed.load());
    CHECK(!whole_called.load());
    std::lock_guard<std::mutex> lk(chunks_mutex);
    REQUIRE(chunks.size() == 2);
    CHECK(chunks[0] == "hello ");
    CHECK(chunks[1] == "world");
}

TEST_CASE("ws incremental receive pause stops before the next data frame and resumes",
          "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    std::vector<uint8_t> greeting;
    auto a = server_frame(WsOpcode::Text, "one", false);
    auto ping = server_frame(WsOpcode::Ping, "k", true);
    auto b = server_frame(WsOpcode::Continuation, "two", true);
    greeting.insert(greeting.end(), a.begin(), a.end());
    greeting.insert(greeting.end(), ping.begin(), ping.end());
    greeting.insert(greeting.end(), b.begin(), b.end());
    srv.set_greeting(greeting);

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> end_called{false};
    std::mutex chunks_mutex;
    std::vector<std::string> chunks;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.session->set_incremental_message_callbacks(
        [](WsMessageType, bool) {},
        [&](const uint8_t* data, size_t size) {
            std::lock_guard<std::mutex> lk(chunks_mutex);
            chunks.emplace_back(reinterpret_cast<const char*>(data), size);
            return chunks.size() != 1;        // pause after the first frame
        },
        [&]() { end_called.store(true); });

    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(wait_until([&] {
        std::lock_guard<std::mutex> lk(chunks_mutex);
        return chunks.size() == 1;
    }));
    CHECK(fx.session->is_receive_paused());
    CHECK(!end_called.load());
    // The buffered ping must still be processed while paused: the client
    // auto-pongs even though the next data frame is held back.
    REQUIRE(wait_until([&] {
        const auto frames = parse_client_frames(srv.client_frames());
        for (const auto& f : frames) {
            if (f.opcode == 0x0A) return true;
        }
        return false;
    }));

    fx.session->resume_receive();
    REQUIRE(wait_until([&] { return end_called.load(); }));
    CHECK(!fx.session->is_receive_paused());
    std::lock_guard<std::mutex> lk(chunks_mutex);
    REQUIRE(chunks.size() == 2);
    CHECK(chunks[0] == "one");
    CHECK(chunks[1] == "two");
}

#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
TEST_CASE("ws incremental receive decompresses a compressed message per frame",
          "[websocket][session][deflate]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> sent{false};
    std::atomic<bool> end_called{false};
    std::atomic<bool> whole_called{false};
    std::atomic<bool> begin_compressed{false};
    std::string received;
    std::mutex received_mutex;

    WebSocketOptions opts;
    opts.enable_deflate = true;
    opts.max_frame_size = 32;   // force the compressed payload across frames
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>&) {
        whole_called.store(true);
    });
    fx.session->set_incremental_message_callbacks(
        [&](WsMessageType, bool compressed) { begin_compressed.store(compressed); },
        [&](const uint8_t* data, size_t size) {
            std::lock_guard<std::mutex> lk(received_mutex);
            received.append(reinterpret_cast<const char*>(data), size);
            return true;
        },
        [&]() { end_called.store(true); });

    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(fx.session->negotiated_deflate().enabled);

    std::string payload;
    for (int i = 0; i < 100; ++i) {
        payload += "compressed incremental receive payload ";
    }
    fx.on_loop([&] {
        fx.session->send_text(string(payload.c_str()), [&](const Error& e) {
            CHECK(!e);
            sent.store(true);
        });
    });
    REQUIRE(wait_until([&] { return sent.load(); }));
    REQUIRE(wait_until([&] { return end_called.load(); }));
    CHECK(begin_compressed.load());
    CHECK(!whole_called.load());
    std::lock_guard<std::mutex> lk(received_mutex);
    CHECK(received == payload);
}
#endif

TEST_CASE("ws incremental send produces one message and lets ping interleave",
          "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> done{false};
    std::atomic<bool> got{false};
    std::atomic<bool> errored{false};
    Error completion;
    Error session_error;
    std::string received;

    fx.session = std::make_shared<WebSocketSession>(fx.stream, WebSocketOptions{}, fx.exec);
    fx.session->on_error([&](const Error& e) {
        session_error = e;
        errored.store(true);
    });
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

    fx.on_loop([&] {
        CHECK(static_cast<bool>(fx.session->send_begin(WsMessageType::Text)));
        CHECK(fx.session->is_sending_message());
        CHECK(static_cast<bool>(fx.session->send_data(
            reinterpret_cast<const uint8_t*>("hello "), 6)));
        fx.session->send_ping(std::vector<uint8_t>{0x6B});
        CHECK(static_cast<bool>(fx.session->send_data(
            reinterpret_cast<const uint8_t*>("world"), 5)));
        auto r = fx.session->send_end([&](const Error& e) {
            completion = e;
            done.store(true);
        });
        CHECK(static_cast<bool>(r));
        CHECK(!fx.session->is_sending_message());
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(!completion);
    CHECK(!errored);
    INFO("session error: " << std::string(session_error.message().begin(),
                                          session_error.message().end()));
    CHECK(static_cast<int>(session_error.code()) == 0);
    const auto sent_frames = parse_client_frames(srv.client_frames());
    INFO("client frames=" << sent_frames.size() << " bytes=" << srv.client_frames().size());
    CHECK(sent_frames.size() >= 4);
    REQUIRE(wait_until([&] { return got.load(); }));
    CHECK(received == "hello world");

    REQUIRE(wait_until([&] { return parse_client_frames(srv.client_frames()).size() >= 4; }));
    const auto frames = parse_client_frames(srv.client_frames());
    std::vector<ParsedClientFrame> data_frames;
    bool saw_ping = false;
    for (const auto& f : frames) {
        if (f.opcode == 0x09) saw_ping = true;
        if (f.opcode == 0x01 || f.opcode == 0x00) data_frames.push_back(f);
    }
    CHECK(saw_ping);
    REQUIRE(data_frames.size() >= 2);
    CHECK(data_frames.front().opcode == 0x01);
    CHECK(!data_frames.front().fin);
    CHECK(!data_frames.front().rsv1);
    CHECK(data_frames.back().opcode == 0x00);
    CHECK(data_frames.back().fin);
    std::string wire_text;
    for (const auto& f : data_frames) {
        wire_text.append(f.payload.begin(), f.payload.end());
    }
    CHECK(wire_text == "hello world");
}

#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
TEST_CASE("ws incremental compressed send reassembles and fragments by wire size",
          "[websocket][session][deflate]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> done{false};
    std::atomic<bool> got{false};
    Error completion;
    std::string received;

    WebSocketOptions opts;
    opts.enable_deflate = true;
    opts.max_frame_size = 64;   // force several compressed frames
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
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
    REQUIRE(fx.session->negotiated_deflate().enabled);

    std::string payload;
    for (int i = 0; i < 300; ++i) payload += "compressible incremental payload ";

    fx.on_loop([&] {
        CHECK(static_cast<bool>(fx.session->send_begin(WsMessageType::Text)));
        for (size_t off = 0; off < payload.size(); off += 37) {
            const size_t take = (std::min)(size_t{37}, payload.size() - off);
            auto r = fx.session->send_data(
                reinterpret_cast<const uint8_t*>(payload.data() + off), take);
            CHECK(static_cast<bool>(r));
        }
        auto r = fx.session->send_end([&](const Error& e) {
            completion = e;
            done.store(true);
        });
        CHECK(static_cast<bool>(r));
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(!completion);
    REQUIRE(wait_until([&] { return got.load(); }));
    CHECK(received == payload);

    REQUIRE(wait_until([&] {
        const auto fs = parse_client_frames(srv.client_frames());
        return fs.size() >= 2;
    }));
    const auto frames = parse_client_frames(srv.client_frames());
    std::vector<ParsedClientFrame> data_frames;
    for (const auto& f : frames) {
        if (f.opcode == 0x01 || f.opcode == 0x00) data_frames.push_back(f);
    }
    REQUIRE(data_frames.size() >= 2);
    CHECK(data_frames.front().opcode == 0x01);
    CHECK(data_frames.front().rsv1);
    CHECK(!data_frames.front().fin);
    for (size_t i = 1; i < data_frames.size(); ++i) {
        CHECK(data_frames[i].opcode == 0x00);
        CHECK(!data_frames[i].rsv1);
    }
    CHECK(data_frames.back().fin);
}
#endif

TEST_CASE("ws incremental compressed empty message keeps the context in sync",
          "[websocket][session][deflate]") {
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> first_done{false};
    std::atomic<bool> second_done{false};
    std::atomic<int> messages{0};
    std::vector<std::string> received;
    std::mutex received_mutex;

    WebSocketOptions opts;
    opts.enable_deflate = true;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lk(received_mutex);
        received.emplace_back(data.begin(), data.end());
        messages.fetch_add(1);
    });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(fx.session->negotiated_deflate().enabled);

    fx.on_loop([&] {
        CHECK(static_cast<bool>(fx.session->send_begin(WsMessageType::Text)));
        auto r = fx.session->send_end([&](const Error& e) {
            CHECK(!e);
            first_done.store(true);
        });
        CHECK(static_cast<bool>(r));
    });
    REQUIRE(wait_until([&] { return first_done.load(); }));

    // A second compressed message proves both zlib contexts advanced together.
    fx.on_loop([&] {
        fx.session->send_text(string("after-empty"), [&](const Error& e) {
            CHECK(!e);
            second_done.store(true);
        });
    });
    REQUIRE(wait_until([&] { return second_done.load(); }));
    REQUIRE(wait_until([&] { return messages.load() == 2; }));

    std::lock_guard<std::mutex> lk(received_mutex);
    REQUIRE(received.size() == 2);
    CHECK(received[0].empty());
    CHECK(received[1] == "after-empty");
#endif
}

TEST_CASE("ws incremental send validates state and message size",
          "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> done{false};
    Error completion;

    WebSocketOptions opts;
    opts.max_message_size = 8;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    fx.on_loop([&] {
        auto no_begin = fx.session->send_data(
            reinterpret_cast<const uint8_t*>("x"), 1);
        CHECK(!no_begin);
        CHECK(no_begin.error().code() == ErrorCode::WsInvalidState);
        auto no_end = fx.session->send_end();
        CHECK(!no_end);
        CHECK(no_end.error().code() == ErrorCode::WsInvalidState);

        CHECK(static_cast<bool>(fx.session->send_begin(WsMessageType::Text)));
        auto twice = fx.session->send_begin(WsMessageType::Text);
        CHECK(!twice);
        CHECK(twice.error().code() == ErrorCode::WsInvalidState);

        bool sync_rejected = false;
        fx.session->send_text(string("x"), [&](const Error& e) {
            sync_rejected = (e.code() == ErrorCode::WsInvalidState);
        });
        CHECK(sync_rejected);

        auto too_large = fx.session->send_data(
            reinterpret_cast<const uint8_t*>("123456789"), 9);
        CHECK(!too_large);
        CHECK(too_large.error().code() == ErrorCode::WsMessageTooLarge);

        CHECK(static_cast<bool>(fx.session->send_data(
            reinterpret_cast<const uint8_t*>("1234"), 4)));
        auto r = fx.session->send_end([&](const Error& e) {
            completion = e;
            done.store(true);
        });
        CHECK(static_cast<bool>(r));
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(!completion);
}

TEST_CASE("ws send queue rejects before compressing and keeps the message usable",
          "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> got{false};
    std::string received;

    WebSocketOptions opts;
    opts.max_send_queue_bytes = 32;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>& data) {
        received.assign(data.begin(), data.end());
        got.store(true);
    });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    std::atomic<bool> done{false};
    Error completion;
    fx.on_loop([&] {
        REQUIRE(static_cast<bool>(fx.session->send_begin(WsMessageType::Text)));
        std::vector<uint8_t> too_big(100, 'x');
        auto r = fx.session->send_data(too_big);
        CHECK(!r);
        CHECK(r.error().code() == ErrorCode::WsSendQueueFull);
        CHECK(fx.session->is_sending_message());   // rejection is retryable

        CHECK(static_cast<bool>(fx.session->send_data(
            reinterpret_cast<const uint8_t*>("ok"), 2)));
        auto end = fx.session->send_end([&](const Error& e) {
            completion = e;
            done.store(true);
        });
        CHECK(static_cast<bool>(end));
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(!completion);
    REQUIRE(wait_until([&] { return got.load(); }));
    CHECK(received == "ok");
}

TEST_CASE("ws compressed sends from two threads keep the deflate context ordered",
          "[websocket][session][deflate]") {
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<int> completions{0};
    std::atomic<int> messages{0};
    std::vector<std::string> received;
    std::mutex received_mutex;

    WebSocketOptions opts;
    opts.enable_deflate = true;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lk(received_mutex);
        received.emplace_back(data.begin(), data.end());
        messages.fetch_add(1);
    });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    auto send_one = [&](const char* text) {
        fx.session->send_text(string(text), [&](const Error& e) {
            CHECK(!e);
            completions.fetch_add(1);
        });
    };
    std::thread t1([&] { send_one("alpha alpha alpha alpha alpha"); });
    std::thread t2([&] { send_one("beta beta beta beta beta"); });
    t1.join();
    t2.join();

    REQUIRE(wait_until([&] { return completions.load() == 2; }));
    REQUIRE(wait_until([&] { return messages.load() == 2; }));
    std::lock_guard<std::mutex> lk(received_mutex);
    REQUIRE(received.size() == 2);
    const bool alpha = received[0].find("alpha") != std::string::npos ||
                       received[1].find("alpha") != std::string::npos;
    const bool beta = received[0].find("beta") != std::string::npos ||
                      received[1].find("beta") != std::string::npos;
    CHECK(alpha);
    CHECK(beta);
#endif
}

TEST_CASE("ws compressed send data rejection does not consume the deflate context",
          "[websocket][session][deflate]") {
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());
    srv.accept_deflate("permessage-deflate");

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> done{false};
    std::atomic<bool> got{false};
    Error completion;
    std::string received;

    WebSocketOptions opts;
    opts.enable_deflate = true;
    opts.max_send_queue_bytes = 800;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>& data) {
        received.assign(data.begin(), data.end());
        got.store(true);
    });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(fx.session->negotiated_deflate().enabled);

    fx.on_loop([&] {
        CHECK(static_cast<bool>(fx.session->send_begin(WsMessageType::Text)));
        std::vector<uint8_t> too_big(400, 'z');
        auto rejected = fx.session->send_data(too_big);
        CHECK(!rejected);
        CHECK(rejected.error().code() == ErrorCode::WsSendQueueFull);

        // The rejected chunk must not have been fed to zlib: the next accepted
        // chunk must decode as exactly "ok", not "zzz...ok".
        CHECK(static_cast<bool>(fx.session->send_data(
            reinterpret_cast<const uint8_t*>("ok"), 2)));
        auto r = fx.session->send_end([&](const Error& e) {
            completion = e;
            done.store(true);
        });
        CHECK(static_cast<bool>(r));
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(!completion);
    REQUIRE(wait_until([&] { return got.load(); }));
    CHECK(received == "ok");
#endif
}

TEST_CASE("ws whole-message send fragments at max_frame_size", "[websocket][session]") {
    sock_init();
    WsEchoServer srv;
    REQUIRE(srv.start());

    SessionFixture fx;
    REQUIRE(fx.connect(srv.port()));

    std::atomic<bool> opened{false};
    std::atomic<bool> sent{false};
    std::atomic<bool> got{false};
    std::string received;
    std::string payload(500, 'f');

    WebSocketOptions opts;
    opts.max_frame_size = 64;
    fx.session = std::make_shared<WebSocketSession>(fx.stream, opts, fx.exec);
    fx.session->on_message([&](WsMessageType, const std::vector<uint8_t>& data) {
        received.assign(data.begin(), data.end());
        got.store(true);
    });
    fx.on_loop([&] {
        fx.session->start(string("localhost"), string("/"), Headers{},
                          [&](const Error&) { opened.store(true); });
    });
    REQUIRE(wait_until([&] { return opened.load(); }));

    fx.on_loop([&] {
        fx.session->send_text(string(payload.c_str()), [&](const Error& e) {
            CHECK(!e);
            sent.store(true);
        });
    });
    REQUIRE(wait_until([&] { return sent.load(); }));
    REQUIRE(wait_until([&] { return got.load(); }));
    CHECK(received == payload);

    REQUIRE(wait_until([&] { return parse_client_frames(srv.client_frames()).size() >= 2; }));
    const auto frames = parse_client_frames(srv.client_frames());
    std::vector<ParsedClientFrame> data_frames;
    for (const auto& f : frames) {
        if (f.opcode == 0x01 || f.opcode == 0x00) data_frames.push_back(f);
    }
    REQUIRE(data_frames.size() >= 2);
    CHECK(data_frames.front().opcode == 0x01);
    CHECK(!data_frames.front().fin);
    for (size_t i = 1; i < data_frames.size(); ++i) {
        CHECK(data_frames[i].opcode == 0x00);
    }
    CHECK(data_frames.back().fin);
    std::string wire_text;
    for (const auto& f : data_frames) {
        wire_text.append(f.payload.begin(), f.payload.end());
    }
    CHECK(wire_text == payload);
}
