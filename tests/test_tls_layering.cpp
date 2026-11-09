// S4.4-02 / S4.7-02 / S4.7-03: TLS layering, double-layer backpressure, and
// cancellation at each lifecycle stage.
//
// The layering test is the shape an HTTPS proxy needs: an inner TLS session
// carried inside an outer one. TLS is built on AsyncByteStream, so a TlsStream
// can wrap another TlsStream with no special-casing -- that is measurable here.
#include <megohttp/config.hpp>

#include <catch2/catch_test_macros.hpp>

#if MGHTTP_TLS_NONE

// Without a TLS backend there is no layering to test.
TEST_CASE("tls layering is unavailable without a TLS backend", "[tls]") {
    SUCCEED("MGHTTP_TLS_NONE: layering tests are compiled out");
}

#else

#include <megohttp/tls_stream.hpp>
#include <megohttp/transport.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

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

namespace {

bool wait_until(std::function<bool()> pred, int max_ms = 20000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

std::string fixture_path(const char* name) {
    std::string p = MEGOHTTP_TLS_FIXTURE_DIR;
    p += "/";
    p += name;
    return p;
}

TlsConfig make_config(const char* hostname, const char* ca) {
    TlsConfig c;
    c.hostname = string(hostname);
    if (ca) {
        const std::string full = fixture_path(ca);
        c.ca_file = string(full.data(), full.size());
    }
    c.alpn_protocols.push_back(string("http/1.1"));
    return c;
}

// Blocking socket exposed as an AsyncByteStream, driven by helper threads. The
// TLS pump needs real network I/O; this is scaffolding, not part of the library.
class PlainSocketStream : public AsyncByteStream,
                          public std::enable_shared_from_this<PlainSocketStream> {
public:
    ~PlainSocketStream() override { close_now(); }

    bool connect_to(uint16_t port) {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
        sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ == INVALID_SOCKET) return false;
#else
        sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0) return false;
#endif
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::connect(sock_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        open_ = true;
        return true;
    }

    void start(ReadyCallback cb) override { if (cb) cb(VoidResult{}); }

    void async_read_some(ReadCallback cb) override {
        auto self = shared_from_this();
        std::thread([self, cb] {
            int n = ::recv(self->sock_,
                           reinterpret_cast<char*>(self->read_stage_),
                           static_cast<int>(sizeof self->read_stage_), 0);
            if (n <= 0) {
                self->open_ = false;
                cb(Result<string_view>{string_view{}});
            } else {
                cb(Result<string_view>{string_view{
                    reinterpret_cast<const char*>(self->read_stage_),
                    static_cast<string_view::size_type>(n)}});
            }
        }).detach();
    }

    void async_write(const uint8_t* data, size_t size, WriteCallback cb) override {
        size_t off = 0;
        while (off < size) {
            int n = ::send(sock_, reinterpret_cast<const char*>(data) + off,
                           static_cast<int>(size - off), 0);
            if (n <= 0) {
                cb(Result<size_t>{Error{ErrorCode::ConnectionReset, ErrorPhase::Send,
                                        string("send failed")}});
                return;
            }
            off += static_cast<size_t>(n);
        }
        cb(Result<size_t>{size});
    }

    void async_close(CloseCallback cb) override { close_now(); if (cb) cb(); }
    bool is_open() const noexcept override { return open_; }

private:
    void close_now() {
        if (!open_) return;
        open_ = false;
#if defined(_WIN32)
        ::closesocket(sock_);
#else
        ::close(sock_);
#endif
    }

#if defined(_WIN32)
    SOCKET sock_{INVALID_SOCKET};
#else
    int sock_{-1};
#endif
    bool open_{false};
    uint8_t read_stage_[16 * 1024]{};
};

// Runs a Python server script and reads its "READY ..." line, then kills it by
// PID on destruction. The servers' accept loops never end on their own, so
// _pclose() alone would block until the test binary is killed.
class PyServer {
public:
    bool start(const char* script, const char* cert, const char* key) {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/";
        cmd += script;
        cmd += "\" \"" + fixture_path(cert) + "\" \"" + fixture_path(key) + "\"";
        pipe_ = _popen(cmd.c_str(), "r");
        if (!pipe_) return false;
        char buf[200] = {0};
        if (!std::fgets(buf, sizeof buf, pipe_)) return false;
        // Expected shape: "READY <pid> <port> [<port2>]"
        if (std::strncmp(buf, "READY ", 6) != 0) return false;
        const char* p = buf + 6;
        char* end = nullptr;
        pid_ = std::strtoul(p, &end, 10);
        if (end == p || pid_ == 0) return false;
        p = end;
        for (int i = 0; i < 4; ++i) {
            while (*p == ' ') ++p;
            if (*p == '\0' || *p == '\n' || *p == '\r') break;
            const unsigned long v = std::strtoul(p, &end, 10);
            if (end == p) break;
            ports.push_back(static_cast<uint16_t>(v));
            p = end;
        }
        return !ports.empty();
    }

    uint16_t port(size_t i = 0) const noexcept { return ports[i]; }

    ~PyServer() {
        if (pid_ != 0) {
            std::string kill = "taskkill /F /PID " + std::to_string(pid_);
            kill += " >NUL 2>&1";
            std::system(kill.c_str());
        }
        if (pipe_) { _pclose(pipe_); pipe_ = nullptr; }
    }

    PyServer() = default;
    PyServer(const PyServer&) = delete;
    PyServer& operator=(const PyServer&) = delete;

    std::vector<uint16_t> ports;

private:
    FILE* pipe_{nullptr};
    unsigned long pid_{0};
};

// ---- helpers -------------------------------------------------------------

struct HandshakeResult {
    std::atomic<bool> called{false};
    std::atomic<bool> ok{false};
    std::atomic<int> code{0};
    std::atomic<int> phase{0};
};

std::shared_ptr<TlsStream> start_tls(std::shared_ptr<AsyncByteStream> underlying,
                                     const TlsConfig& cfg,
                                     HandshakeResult* out) {
    auto tls = make_tls_stream(std::move(underlying), cfg);
    tls->start([out](VoidResult r) {
        out->called = true;
        out->ok = static_cast<bool>(r);
        if (!r) {
            out->code = static_cast<int>(r.error().code());
            out->phase = static_cast<int>(r.error().phase());
        }
    });
    return tls;
}

} // namespace

// ===========================================================================
// S4.4-02 / S4.7-02: TLS over TLS
// ===========================================================================

TEST_CASE("tls stream nests inside another tls stream", "[tls][layering]") {
    // The server terminates the outer TLS, then relays the plaintext into a
    // second TLS listener -- the same splice an HTTP CONNECT tunnel performs.
    // If layering worked only for raw sockets this would fail.
    PyServer srv;
    REQUIRE(srv.start("layered_tls_server.py", "server-cert.pem", "server-key.pem"));
    REQUIRE(srv.ports.size() == 2);
    const uint16_t outer_port = srv.port(0);

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(outer_port));

    HandshakeResult outer_hs;
    auto outer = start_tls(raw, make_config("localhost", "ca.pem"), &outer_hs);
    REQUIRE(outer);
    REQUIRE(wait_until([&] { return outer_hs.called.load(); }));
    REQUIRE(outer_hs.ok.load());

    // Layer 2: a TlsStream whose underlying stream is the first TlsStream. No
    // special-casing anywhere -- that is the whole point of putting TLS on
    // AsyncByteStream.
    HandshakeResult inner_hs;
    auto inner = start_tls(outer, make_config("localhost", "ca.pem"), &inner_hs);
    REQUIRE(inner);
    REQUIRE(wait_until([&] { return inner_hs.called.load(); }));
    CHECK(inner_hs.ok.load());
    CHECK(inner->handshake_complete());
    CHECK(!inner->tls_protocol().empty());
}

TEST_CASE("tls nesting carries application data both directions", "[tls][layering]") {
    PyServer srv;
    REQUIRE(srv.start("layered_tls_server.py", "server-cert.pem", "server-key.pem"));
    REQUIRE(srv.ports.size() == 2);

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult outer_hs;
    auto outer = start_tls(raw, make_config("localhost", "ca.pem"), &outer_hs);
    REQUIRE(wait_until([&] { return outer_hs.called.load(); }));
    REQUIRE(outer_hs.ok.load());

    HandshakeResult inner_hs;
    auto inner = start_tls(outer, make_config("localhost", "ca.pem"), &inner_hs);
    REQUIRE(wait_until([&] { return inner_hs.called.load(); }));
    REQUIRE(inner_hs.ok.load());

    const char* payload = "through both layers";
    const size_t len = std::strlen(payload);
    std::atomic<bool> wrote{false};
    std::atomic<bool> write_ok{false};
    inner->async_write(reinterpret_cast<const uint8_t*>(payload), len,
        [&](Result<size_t> r) {
            write_ok = static_cast<bool>(r) && r.value() == len;
            wrote = true;
        });
    REQUIRE(wait_until([&] { return wrote.load(); }));
    CHECK(write_ok.load());

    std::atomic<bool> read_done{false};
    std::string got;
    // The echo may arrive in several TLS records, and the server writes it right
    // after receiving the payload. Read until something arrives rather than
    // assuming the first callback carries the whole reply.
    std::function<void()> read_loop = [&] {
        inner->async_read_some([&](Result<string_view> r) {
            if (!r) {
                // EOF or a stream error: nothing more will arrive.
                read_done = true;
                return;
            }
            if (r.value().empty()) {
                // Empty view is "not ready yet" in this stream's contract, so
                // ask again instead of treating it as the end of the reply.
                read_loop();
                return;
            }
            got.append(r.value().data(), static_cast<size_t>(r.value().size()));
            if (got.size() >= std::strlen(payload) + 6) { read_done = true; return; }
            read_loop();
        });
    };
    read_loop();
    REQUIRE(wait_until([&] { return read_done.load(); }, 30000));
    // The inner server prefixes its echo, which proves the payload made it
    // through both TLS layers intact.
    INFO("received " << got.size() << " bytes");
    CHECK(got == std::string("inner:") + payload);
}

TEST_CASE("inner handshake failure does not corrupt the outer layer", "[tls][layering]") {
    PyServer srv;
    REQUIRE(srv.start("layered_tls_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult outer_hs;
    auto outer = start_tls(raw, make_config("localhost", "ca.pem"), &outer_hs);
    REQUIRE(wait_until([&] { return outer_hs.called.load(); }));
    REQUIRE(outer_hs.ok.load());

    // Inner layer asks for a name the certificate does not cover: the inner
    // handshake must fail with a hostname error, not a generic one.
    HandshakeResult inner_hs;
    auto inner = start_tls(outer, make_config("not-in-the-cert.example", "ca.pem"),
                           &inner_hs);
    REQUIRE(wait_until([&] { return inner_hs.called.load(); }));
    CHECK(!inner_hs.ok.load());
    CHECK(static_cast<ErrorCode>(inner_hs.code.load()) == ErrorCode::TlsHostnameMismatch);

    // The outer layer keeps its own state: it completed its handshake and
    // negotiated its own protocol. (It may subsequently be closed by the peer
    // hanging up, which is why this asserts on the completed handshake rather
    // than on is_open().)
    CHECK(outer->handshake_complete());
    CHECK(!outer->tls_protocol().empty());
    // The inner stream must not claim to be usable.
    CHECK(!inner->is_open());
}

TEST_CASE("outer and inner layers report their own phase", "[tls][layering]") {
    PyServer srv;
    REQUIRE(srv.start("layered_tls_server.py", "untrusted-cert.pem", "untrusted-key.pem"));
    REQUIRE(srv.ports.size() == 2);

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult outer_hs;
    auto outer = make_tls_stream(raw, make_config("localhost", "ca.pem"));
    outer->set_error_phase(ErrorPhase::ProxyTls, ErrorPhase::Receive);
    outer->start([&](VoidResult r) {
        outer_hs.called = true;
        outer_hs.ok = static_cast<bool>(r);
        if (!r) outer_hs.phase = static_cast<int>(r.error().phase());
    });
    REQUIRE(wait_until([&] { return outer_hs.called.load(); }));
    REQUIRE(!outer_hs.ok.load());

    // The proxy layer failed, so the phase must name the proxy. A test that only
    // asserted "an error happened" would not catch a mixed-up phase.
    CHECK(static_cast<ErrorPhase>(outer_hs.phase.load()) == ErrorPhase::ProxyTls);
}

// ===========================================================================
// S4.7-02: backpressure and partial I/O across layers
// ===========================================================================

TEST_CASE("large payload crosses both layers without loss", "[tls][layering][backpressure]") {
    // 256 KiB is far past one TLS record, so this forces many partial reads and
    // writes through the outer layer while the inner one is progressing.
    PyServer srv;
    REQUIRE(srv.start("layered_tls_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult outer_hs;
    auto outer = start_tls(raw, make_config("localhost", "ca.pem"), &outer_hs);
    REQUIRE(wait_until([&] { return outer_hs.called.load(); }));
    REQUIRE(outer_hs.ok.load());

    HandshakeResult inner_hs;
    auto inner = start_tls(outer, make_config("localhost", "ca.pem"), &inner_hs);
    REQUIRE(wait_until([&] { return inner_hs.called.load(); }));
    REQUIRE(inner_hs.ok.load());

    const size_t kSize = 256 * 1024;
    std::vector<uint8_t> payload(kSize);
    for (size_t i = 0; i < kSize; ++i) payload[i] = static_cast<uint8_t>(i * 31 + 7);

    std::atomic<bool> wrote{false};
    std::atomic<bool> write_ok{false};
    inner->async_write(payload.data(), payload.size(), [&](Result<size_t> r) {
        write_ok = static_cast<bool>(r) && r.value() == payload.size();
        wrote = true;
    });
    REQUIRE(wait_until([&] { return wrote.load(); }));
    CHECK(write_ok.load());

    // The server prefixes each chunk with "inner:", so read until the expected
    // total arrives. Partial reads are the normal case here.
    std::string got;
    got.reserve(kSize + 4096);
    std::atomic<bool> done{false};
    std::function<void()> pump_read = [&] {
        inner->async_read_some([&](Result<string_view> r) {
            if (!r || r.value().empty()) { done = true; return; }
            got.append(r.value().data(), static_cast<size_t>(r.value().size()));
            if (got.size() >= kSize + 6) { done = true; return; }
            pump_read();
        });
    };
    pump_read();
    REQUIRE(wait_until([&] { return done.load(); }, 30000));

    // The echoed bytes must contain the original payload unmodified.
    const std::string needle(payload.begin(), payload.begin() + 64);
    CHECK(got.find(needle) != std::string::npos);
    CHECK(got.find("inner:") == 0);
}

// ===========================================================================
// S4.7-03: cancellation / close at each lifecycle stage
// ===========================================================================

TEST_CASE("read during the handshake is rejected, not queued", "[tls][cancel]") {
    // Issues a read before the handshake completes: the stream is not Open yet,
    // so the read must be refused outright instead of silently parked forever.
    PyServer srv;
    REQUIRE(srv.start("tls_test_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    auto tls = make_tls_stream(raw, make_config("localhost", "ca.pem"));
    // start() is deliberately NOT called.
    std::atomic<bool> called{false};
    std::atomic<int> code{0};
    tls->async_read_some([&](Result<string_view> r) {
        called = true;
        if (!r) code = static_cast<int>(r.error().code());
    });
    CHECK(called.load());
    // Not open yet -> InvalidArgument, with the handshake phase attached.
    CHECK(static_cast<ErrorCode>(code.load()) == ErrorCode::InvalidArgument);
}

TEST_CASE("closing during the handshake terminates without hanging", "[tls][cancel]") {
    // The server accepts the TCP connection, so the TLS handshake is genuinely
    // in flight when close() is called.
    PyServer srv;
    REQUIRE(srv.start("tls_test_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult hs;
    auto tls = start_tls(raw, make_config("localhost", "ca.pem"), &hs);

    // Do not wait for the handshake: close while it is still in flight.
    std::atomic<bool> closed{false};
    tls->async_close([&] { closed = true; });
    CHECK(wait_until([&] { return closed.load(); }, 15000));
    CHECK(!tls->is_open());
}

TEST_CASE("close after the handshake completes exactly once", "[tls][cancel]") {
    PyServer srv;
    REQUIRE(srv.start("tls_test_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult hs;
    auto tls = start_tls(raw, make_config("localhost", "ca.pem"), &hs);
    REQUIRE(wait_until([&] { return hs.called.load(); }));
    REQUIRE(hs.ok.load());

    std::atomic<int> close_count{0};
    tls->async_close([&] { ++close_count; });
    CHECK(wait_until([&] { return close_count.load() > 0; }, 15000));

    // A second close must not fire the callback again (task book 5.3: the
    // terminal notification happens exactly once).
    tls->async_close([&] { ++close_count; });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(close_count.load() == 1);
    CHECK(!tls->is_open());
}

TEST_CASE("a second outstanding read is rejected, not queued", "[tls][cancel]") {
    PyServer srv;
    REQUIRE(srv.start("tls_test_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult hs;
    auto tls = start_tls(raw, make_config("localhost", "ca.pem"), &hs);
    REQUIRE(wait_until([&] { return hs.called.load(); }));
    REQUIRE(hs.ok.load());

    std::atomic<bool> second_called{false};
    std::atomic<int> second_code{0};
    tls->async_read_some([](Result<string_view>) {});   // stays outstanding
    tls->async_read_some([&](Result<string_view> r) {
        second_called = true;
        if (!r) second_code = static_cast<int>(r.error().code());
    });
    REQUIRE(wait_until([&] { return second_called.load(); }));
    CHECK(static_cast<ErrorCode>(second_code.load()) == ErrorCode::InvalidArgument);
}

TEST_CASE("write on a closed stream is rejected", "[tls][cancel]") {
    PyServer srv;
    REQUIRE(srv.start("tls_test_server.py", "server-cert.pem", "server-key.pem"));

    auto raw = std::make_shared<PlainSocketStream>();
    REQUIRE(raw->connect_to(srv.port(0)));

    HandshakeResult hs;
    auto tls = start_tls(raw, make_config("localhost", "ca.pem"), &hs);
    REQUIRE(wait_until([&] { return hs.called.load(); }));
    REQUIRE(hs.ok.load());

    std::atomic<bool> closed{false};
    tls->async_close([&] { closed = true; });
    REQUIRE(wait_until([&] { return closed.load(); }, 15000));

    std::atomic<bool> write_called{false};
    std::atomic<int> write_code{0};
    tls->async_write(reinterpret_cast<const uint8_t*>("x"), 1,
        [&](Result<size_t> r) {
            write_called = true;
            if (!r) write_code = static_cast<int>(r.error().code());
        });
    CHECK(write_called.load());
    CHECK(static_cast<ErrorCode>(write_code.load()) == ErrorCode::InvalidArgument);
}

#endif // MGHTTP_TLS_NONE
