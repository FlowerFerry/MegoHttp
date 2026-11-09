#ifndef MEGOHTTP_TLS_TEST_SUPPORT_HPP_INCLUDED
#define MEGOHTTP_TLS_TEST_SUPPORT_HPP_INCLUDED

// Shared scaffolding for the TLS test suites.
//
// PlainSocketStream gives the TLS pump real network reads and writes without
// pulling in the whole transport layer, and PythonTlsServer starts
// tests/tls_test_server.py on a dynamic port with an explicit READY signal
// (task book 13: no fixed ports, no sleep-based readiness).
//
// This lives in a header because three suites need the identical harness; a
// fourth copy would be three copies too many.

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
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

#if defined(_WIN32)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#else
#   include <arpa/inet.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#   include <unistd.h>
#endif

namespace tls_test_support {

inline bool wait_until(std::function<bool()> pred, int max_ms = 10000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

inline std::string fixture_path(const char* name) {
    std::string p = MEGOHTTP_TLS_FIXTURE_DIR;
    p += "/";
    p += name;
    return p;
}

// Blocking socket exposed as an AsyncByteStream, driven by helper threads.
class PlainSocketStream : public megohttp::AsyncByteStream,
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

    void start(ReadyCallback cb) override { if (cb) cb(megohttp::VoidResult{}); }

    void async_read_some(ReadCallback cb) override {
        auto self = shared_from_this();
        std::thread([self, cb] {
            int n = ::recv(self->sock_,
                           reinterpret_cast<char*>(self->read_stage_),
                           static_cast<int>(sizeof self->read_stage_), 0);
            if (n <= 0) {
                self->open_ = false;
                cb(megohttp::Result<megohttp::string_view>{megohttp::string_view{}});
            } else {
                cb(megohttp::Result<megohttp::string_view>{megohttp::string_view{
                    reinterpret_cast<const char*>(self->read_stage_),
                    static_cast<megohttp::string_view::size_type>(n)}});
            }
        }).detach();
    }

    void async_write(const uint8_t* data, size_t size, WriteCallback cb) override {
        size_t off = 0;
        while (off < size) {
            int n = ::send(sock_, reinterpret_cast<const char*>(data) + off,
                           static_cast<int>(size - off), 0);
            if (n <= 0) {
                cb(megohttp::Result<size_t>{megohttp::Error{
                    megohttp::ErrorCode::ConnectionReset, megohttp::ErrorPhase::Send,
                    megohttp::string("send failed")}});
                return;
            }
            off += static_cast<size_t>(n);
        }
        cb(megohttp::Result<size_t>{size});
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

// Runs tls_test_server.py and reads "READY <pid> <port>" from its stdout.
// The PID is printed so the harness can terminate the server explicitly: the
// accept loop never ends on its own, so _pclose would hang forever.
class PythonTlsServer {
public:
    bool start(const char* cert, const char* key, const char* extra = "") {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/tls_test_server.py\" \"" + fixture_path(cert) + "\" \"" +
               fixture_path(key) + "\" ";
        cmd += extra;
        pipe_ = _popen(cmd.c_str(), "r");
        if (!pipe_) return false;
        char buf[160] = {0};
        if (!std::fgets(buf, sizeof buf, pipe_)) return false;
        int pid = 0, p = 0;
        if (std::sscanf(buf, "READY %d %d", &pid, &p) != 2) return false;
        pid_ = static_cast<unsigned long>(pid);
        port_ = static_cast<uint16_t>(p);
        return port_ != 0;
    }

    uint16_t port() const noexcept { return port_; }

    ~PythonTlsServer() {
        if (pid_ != 0) {
            std::string kill = "taskkill /F /PID " + std::to_string(pid_);
            kill += " >NUL 2>&1";
            std::system(kill.c_str());
        }
        if (pipe_) {
            _pclose(pipe_);
            pipe_ = nullptr;
        }
    }

    PythonTlsServer() = default;
    PythonTlsServer(const PythonTlsServer&) = delete;
    PythonTlsServer& operator=(const PythonTlsServer&) = delete;

private:
    FILE* pipe_{nullptr};
    uint16_t port_{0};
    unsigned long pid_{0};
};

inline megohttp::TlsConfig make_config(const char* hostname, const char* ca) {
    megohttp::TlsConfig c;
    c.hostname = megohttp::string(hostname);
    if (ca) {
        const std::string full = fixture_path(ca);
        c.ca_file = megohttp::string(full.data(), full.size());
    }
    // TlsConfig leaves alpn_protocols empty on purpose: the library must not
    // offer a protocol the caller did not ask for. These tests are HTTP-shaped,
    // so they opt in explicitly.
    c.alpn_protocols.push_back(megohttp::string("http/1.1"));
    return c;
}

struct HandshakeOutcome {
    std::atomic<bool> called{false};
    std::atomic<bool> ok{false};
    std::atomic<int> code{0};
    std::atomic<int> phase{0};
    std::string protocol;
    std::string alpn;
};

inline std::shared_ptr<megohttp::TlsStream>
handshake(const megohttp::TlsConfig& cfg, uint16_t port, HandshakeOutcome* out) {
    auto raw = std::make_shared<PlainSocketStream>();
    if (!raw->connect_to(port)) {
        out->called = true;
        out->code = static_cast<int>(megohttp::ErrorCode::ConnectFailed);
        out->phase = static_cast<int>(megohttp::ErrorPhase::TcpConnect);
        return nullptr;
    }
    auto tls = megohttp::make_tls_stream(raw, cfg);
    tls->start([out, tls](megohttp::VoidResult r) {
        out->called = true;
        out->ok = static_cast<bool>(r);
        if (!r) {
            out->code = static_cast<int>(r.error().code());
            out->phase = static_cast<int>(r.error().phase());
        } else {
            const megohttp::string_view proto = tls->tls_protocol();
            const megohttp::string alpn_s = tls->negotiated_alpn();
            out->protocol.assign(proto.data(), static_cast<size_t>(proto.size()));
            out->alpn.assign(alpn_s.data(), static_cast<size_t>(alpn_s.size()));
        }
    });
    wait_until([&] { return out->called.load(); });
    return tls;
}

} // namespace tls_test_support

#endif // MEGOHTTP_TLS_TEST_SUPPORT_HPP_INCLUDED
