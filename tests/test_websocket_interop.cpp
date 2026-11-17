// permessage-deflate interop with an INDEPENDENT implementation (T3 / S6.3-10).
//
// The unit tests in test_websocket_deflate.cpp round-trip our own compressor
// through our own decompressor, which cannot catch a shared misreading of RFC
// 7692 -- both sides would be wrong in the same way. This test talks to Python
// `websockets`, so a compression or framing bug shows up as a failed echo.
//
// The server script is tests/ws_deflate_server.py. If Python or the websockets
// package is missing the test reports SKIP rather than failing, because a
// missing interpreter says nothing about the library.

#include <megohttp/client.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#endif

using namespace megohttp;
using namespace std::chrono_literals;

namespace {

    bool wait_until(const std::function<bool()>& pred, int ms = 8000) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            std::this_thread::sleep_for(5ms);
        }
        return false;
    }

    // Runs the Python interop server as a child process and reads the port it
    // reported through a temp file. A pipe deadlocks here: the child inherits
    // the write end, so the parent's blocking read never sees EOF.
    class InteropServer {
    public:
        ~InteropServer() { stop(); }

        bool start(const std::string& extra_args = {}) {
            char tmpdir[MAX_PATH]{};
            if (!GetTempPathA(MAX_PATH, tmpdir)) return false;
            char tmpfile[MAX_PATH]{};
            if (!GetTempFileNameA(tmpdir, "wsio", 0, tmpfile)) return false;
            port_file_ = tmpfile;

            std::string cmd = "cmd.exe /c python -u \"" +
                              std::string(MEGOHTTP_TESTS_DIR) +
                              "/ws_deflate_server.py\"";
            if (!extra_args.empty()) cmd += " " + extra_args;
            cmd += " > \"" + port_file_ + "\" 2>&1";

            STARTUPINFOA si{};
            si.cb = sizeof si;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            std::vector<char> buf(cmd.begin(), cmd.end());
            buf.push_back('\0');
            if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                return false;
            }
            hproc_ = pi.hProcess;
            CloseHandle(pi.hThread);

            std::string text;
            if (!wait_until([&] {
                    text = read_file();
                    return text.find("READY ") != std::string::npos;
                }, 10000)) {
                reason_ = text.empty() ? "server did not report READY" : text;
                stop();
                return false;
            }
            const size_t p = text.find("READY ");
            port_ = static_cast<uint16_t>(std::atoi(text.c_str() + p + 6));
            return port_ != 0;
        }

        void stop() {
            if (hproc_) {
                TerminateProcess(hproc_, 0);
                WaitForSingleObject(hproc_, 3000);
                CloseHandle(hproc_);
                hproc_ = nullptr;
            }
            if (!port_file_.empty()) {
                DeleteFileA(port_file_.c_str());
                port_file_.clear();
            }
        }

        uint16_t port() const { return port_; }
        const std::string& reason() const { return reason_; }

    private:
        std::string read_file() const {
            std::ifstream f(port_file_);
            if (!f) return {};
            std::ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }

        HANDLE hproc_{nullptr};
        std::string port_file_;
        uint16_t port_{0};
        std::string reason_;
    };

    string make_url(uint16_t port) {
        string_builder b;
        detail::sb_append(b, "ws://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", port)));
        detail::sb_append(b, "/");
        return b.release();
    }

} // namespace

TEST_CASE("permessage-deflate interoperates with Python websockets", "[interop][deflate]") {
    InteropServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start ws_deflate_server.py (%s)\n",
                    srv.reason().c_str());
        return;
    }

    Client cli;
    WebSocketOptions wopt;
    wopt.enable_deflate = true;

    WebSocketReconnectPolicy policy;   // reconnect stays off

    std::atomic<bool> opened{false};
    Error open_err;
    std::vector<std::string> echoed;
    std::atomic<bool> got_echo{false};

    auto ws = cli.open_websocket(to_view(make_url(srv.port())), wopt, policy);
    ws->on_open([&](const Error& e) { open_err = e; opened.store(true); });
    ws->on_message([&](WsMessageType t, const std::vector<uint8_t>& d) {
        if (t == WsMessageType::Text) {
            echoed.emplace_back(reinterpret_cast<const char*>(d.data()), d.size());
            got_echo.store(true);
        }
    });

    REQUIRE(wait_until([&] { return opened.load(); }));
    REQUIRE(!open_err);

    // A message long enough to actually compress, and repetitive enough that a
    // silently-uncompressed path would still round-trip -- the negotiation flag
    // below is what proves compression was in play.
    std::string payload;
    for (int i = 0; i < 200; ++i) payload += "permessage-deflate interop ";

    bool sent = ws->send_text(string(payload.c_str()));
    REQUIRE(sent);

    REQUIRE(wait_until([&] { return got_echo.load(); }));
    REQUIRE(echoed.size() == 1);
    CHECK(echoed[0] == payload);

    ws->close(1000, "done");
    cli.shutdown();
    srv.stop();
}

TEST_CASE("a plain message still round-trips when deflate is negotiated",
          "[interop][deflate]") {
    // RFC 7692 allows a peer to send any message uncompressed even after the
    // extension is in effect; the receiver must not feed it to the inflater.
    InteropServer srv;
    if (!srv.start()) {
        std::printf("SKIP: could not start ws_deflate_server.py (%s)\n",
                    srv.reason().c_str());
        return;
    }

    Client cli;
    WebSocketOptions wopt;
    wopt.enable_deflate = true;
    WebSocketReconnectPolicy policy;

    std::atomic<bool> opened{false};
    std::vector<std::string> echoed;
    std::atomic<bool> got{false};

    auto ws = cli.open_websocket(to_view(make_url(srv.port())), wopt, policy);
    ws->on_open([&](const Error&) { opened.store(true); });
    ws->on_message([&](WsMessageType, const std::vector<uint8_t>& d) {
        echoed.emplace_back(reinterpret_cast<const char*>(d.data()), d.size());
        got.store(true);
    });

    REQUIRE(wait_until([&] { return opened.load(); }));

    // Empty and tiny messages: our sender leaves these uncompressed even with
    // the extension active, so this exercises the mixed path.
    REQUIRE(ws->send_text(string("")));
    std::string tiny = "x";
    REQUIRE(ws->send_text(string(tiny.c_str())));
    REQUIRE(wait_until([&] { return got.load(); }));

    ws->terminate();
    cli.shutdown();
    srv.stop();
}
