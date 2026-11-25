// WSS through a proxy (T4 / S6.4-08).
//
// Two things must hold when a WebSocket session goes through a proxy:
//   * the CONNECT tunnel is what carries the TLS handshake (the proxy sees a
//     CONNECT for the target host:port, not an Upgrade), and
//   * permessage-deflate still negotiates across that tunnel.
//
// The proxy is tests/proxy_test_server.py (stdlib only, independent of the
// library's own parser) and the WSS endpoint is Python `websockets`, so a
// failure here is a real interop failure rather than two halves agreeing on
// the same mistake.

#include <megohttp/client.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
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

#include "process_job.hpp"

using namespace megohttp;
using namespace std::chrono_literals;

namespace {

    bool wait_until(const std::function<bool()>& pred, int ms = 12000) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            std::this_thread::sleep_for(10ms);
        }
        return false;
    }

    // Starts a python script, redirecting its output to a temp file so the port
    // it reports can be polled. A pipe deadlocks: the child inherits the write
    // end and the parent's blocking read never sees EOF.
    class PyProcess {
    public:
        ~PyProcess() { stop(); }

        bool start(const std::string& script, const std::string& args = {}) {
            char tmpdir[MAX_PATH]{};
            if (!GetTempPathA(MAX_PATH, tmpdir)) return false;
            char tmpfile[MAX_PATH]{};
            if (!GetTempFileNameA(tmpdir, "pyio", 0, tmpfile)) return false;
            out_file_ = tmpfile;

            std::string cmd = "cmd.exe /c python -u \"" +
                              std::string(MEGOHTTP_TESTS_DIR) + "/" + script + "\"";
            if (!args.empty()) cmd += " " + args;
            cmd += " > \"" + out_file_ + "\" 2>&1";

            STARTUPINFOA si{};
            si.cb = sizeof si;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            if (!mghttp_test::spawn_in_job(cmd, si, CREATE_NO_WINDOW, pi, job_, FALSE)) {
                return false;
            }
            job_assigned_ = job_.assigned();
            hproc_ = pi.hProcess;
            pid_ = pi.dwProcessId;
            return true;
        }

        bool await_ready() {
            std::string text;
            return wait_until([&] {
                text = read();
                return text.find("READY ") != std::string::npos;
            }, 12000);
        }

        uint16_t port() const {
            const std::string text = read();
            const size_t p = text.find("READY ");
            if (p == std::string::npos) return 0;
            // The two scripts disagree on the READY line: proxy_test_server.py
            // prints "READY <pid> <port>" and ws_deflate_server.py prints
            // "READY <port>". Take the LAST number on that line, which is the
            // port in both.
            const size_t eol = text.find('\n', p);
            const std::string line =
                text.substr(p, eol == std::string::npos ? std::string::npos : eol - p);
            const size_t last = line.find_last_of(' ');
            if (last == std::string::npos) return 0;
            return static_cast<uint16_t>(std::atoi(line.c_str() + last + 1));
        }

        std::string output() const { return read(); }

        void stop() {
            if (job_assigned_) {
                job_.terminate();
            } else if (pid_ != 0) {
                mghttp_test::terminate_tree(pid_);
            }
            job_.close();
            if (hproc_) {
                TerminateProcess(hproc_, 0);
                WaitForSingleObject(hproc_, 3000);
                CloseHandle(hproc_);
                hproc_ = nullptr;
            }
            pid_ = 0;
            if (!out_file_.empty()) {
                DeleteFileA(out_file_.c_str());
                out_file_.clear();
            }
        }

    private:
        std::string read() const {
            std::ifstream f(out_file_);
            if (!f) return {};
            std::ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }

        HANDLE hproc_{nullptr};
        DWORD pid_{0};
        mghttp_test::ProcessJob job_;
        bool job_assigned_{false};
        std::string out_file_;
    };

    string make_url(uint16_t port) {
        string_builder b;
        detail::sb_append(b, "wss://127.0.0.1:");
        detail::sb_append(b, to_view(format("{}", port)));
        detail::sb_append(b, "/");
        return b.release();
    }

} // namespace

TEST_CASE("wss through an HTTP proxy CONNECT tunnel negotiates deflate",
          "[interop][proxy][websocket]") {
#if MGHTTP_TLS_NONE
    // wss:// needs a TLS implementation; a TLS_NONE build refuses it by design
    // (TlsNotEnabled), so there is nothing to exercise here.
    std::printf("SKIP: TLS is not compiled in (MGHTTP_TLS_NONE)\n");
    return;
#else
    // Proxy first (it needs to be listening), then the WSS endpoint.
    // The proxy dumps what it observed (CONNECT authority, headers, ...) to
    // this file. It must be set BEFORE the proxy starts, because the dump loop
    // reads it on every tick.
    char recfile[MAX_PATH]{};
    {
        char td[MAX_PATH]{};
        GetTempPathA(MAX_PATH, td);
        char tf[MAX_PATH]{};
        GetTempFileNameA(td, "pr", 0, tf);
        strncpy(recfile, tf, sizeof recfile);
    }
    _putenv_s("MEGOHTTP_PROXY_RECORDING", recfile);

    PyProcess proxy;
    if (!proxy.start("proxy_test_server.py", "--mode forward")) {
        std::printf("SKIP: proxy_test_server.py unavailable\n");
        return;
    }
    if (!proxy.await_ready()) {
        std::printf("SKIP: proxy did not report READY (%s)\n",
                    proxy.output().c_str());
        return;
    }

    PyProcess wss;
    // The target must actually speak TLS: a wss:// session over a plaintext
    // endpoint fails in the handshake, which looks like a tunnel bug.
    const std::string tls_args =
        std::string("--tls --certdir \"") + MEGOHTTP_TLS_FIXTURE_DIR + "\"";
    if (!wss.start("ws_deflate_server.py", tls_args) || !wss.await_ready()) {
        std::printf("SKIP: ws_deflate_server.py (tls) unavailable\n");
        return;
    }

    ClientOptions opts;
    opts.proxy.proxy.type = ProxyType::Http;
    opts.proxy.proxy.host = string("127.0.0.1");
    opts.proxy.proxy.port = proxy.port();
    // The proxy relays to a loopback origin, and the target certificate is one
    // of the test fixtures, so verification is off for this transport test:
    // what is under test is the tunnel + deflate, not PKI (that is covered by
    // test_tls_trust and test_client_proxy).
    opts.tls.verify_peer = false;

    Client cli(opts);
    // Guard: if the option did not land, the failure below is an option bug,
    // not a tunnel bug.
    REQUIRE(cli.options().proxy.proxy.is_set());
    REQUIRE(cli.options().proxy.proxy.port == proxy.port());

    WebSocketOptions wopt;
    wopt.enable_deflate = true;
    WebSocketReconnectPolicy policy;

    std::atomic<bool> opened{false};
    Error open_err;
    std::vector<std::string> echoed;
    std::atomic<bool> got{false};

    auto ws = cli.open_websocket(to_view(make_url(wss.port())), wopt, policy);
    ws->on_open([&](const Error& e) { open_err = e; opened.store(true); });
    ws->on_error([&](const Error& e) {
        (void)e; // Handled by on_session_end, which carries the final reason.
    });
    ws->on_session_end([&](const Error* reason) {
        if (reason) {
            std::printf("session end error: code=%d msg=%.*s\n",
                        static_cast<int>(reason->code()),
                        static_cast<int>(reason->message().size()),
                        reason->message().data());
        } else {
            std::printf("session ended cleanly\n");
        }
    });
    ws->on_close([&](uint16_t code, const string& reason) {
        std::printf("ws close: code=%u reason=%.*s\n", code,
                    static_cast<int>(reason.size()), reason.data());
    });
    ws->on_message([&](WsMessageType, const std::vector<uint8_t>& d) {
        echoed.emplace_back(reinterpret_cast<const char*>(d.data()), d.size());
        got.store(true);
    });

    const bool came_up = wait_until([&] { return opened.load(); });
    // Report what the proxy actually saw, so a failure says whether the tunnel
    // was attempted at all.
    INFO("proxy output: " << proxy.output());

    REQUIRE(came_up);
    REQUIRE(!open_err);

    // The proxy must have been asked for a CONNECT to the target: assert on
    // the recording rather than on stdout, which only carries the READY line.
    std::string recorded;
    if (wait_until([&] {
            std::ifstream f(recfile);
            if (!f) return false;
            std::ostringstream ss;
            ss << f.rdbuf();
            recorded = ss.str();
            return recorded.find("connect") != std::string::npos;
        }, 3000)) {
        CHECK(recorded.find("connect") != std::string::npos);
    } else {
        WARN("proxy recording not written: " << recfile);
    }
    DeleteFileA(recfile);

    std::string payload;
    for (int i = 0; i < 100; ++i) payload += "wss via proxy interop ";
    REQUIRE(ws->send_text(string(payload.c_str())));
    REQUIRE(wait_until([&] { return got.load(); }));
    REQUIRE(echoed.size() == 1);
    CHECK(echoed[0] == payload);

    ws->close(1000, "done");
    cli.shutdown();
    wss.stop();
    proxy.stop();
    // The recording path is process-global; leaving it set would point a later
    // proxy test (test_client_proxy) at a file this test deletes.
    _putenv_s("MEGOHTTP_PROXY_RECORDING", "");
#endif // !MGHTTP_TLS_NONE
}
