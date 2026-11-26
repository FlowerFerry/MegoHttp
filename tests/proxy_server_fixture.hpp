#ifndef MEGOHTTP_TEST_PROXY_SERVER_FIXTURE_HPP_INCLUDED
#define MEGOHTTP_TEST_PROXY_SERVER_FIXTURE_HPP_INCLUDED

// Shared fixture for tests/proxy_test_server.py. Keeps the Job Object and
// READY-banner code in one place; the resolver tests only choose the mode and
// optional TLS/auth/map arguments.
#include <cstdio>
#include <cstdint>
#include <string>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "process_job.hpp"

namespace mghttp_test {

class ProxyServerFixture {
public:
    bool start(const std::string& args) {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/proxy_test_server.py\" ";
        cmd += args;
        return spawn(cmd);
    }

    uint16_t port() const noexcept { return port_; }

    ~ProxyServerFixture() { stop(); }

    void stop() {
        if (job_assigned_) {
            job_.terminate();
            pid_ = 0;
        } else if (pid_ > 0) {
            terminate_tree(static_cast<DWORD>(pid_));
            pid_ = 0;
        }
        job_.close();
    }

private:
    bool spawn(const std::string& cmd) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        HANDLE rd = nullptr, wr = nullptr;
        if (!CreatePipe(&rd, &wr, &sa, 0)) return false;
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = wr;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};
        const BOOL ok = spawn_in_job(cmd, si, 0, pi, job_);
        job_assigned_ = job_.assigned();
        CloseHandle(wr);
        if (!ok) {
            CloseHandle(rd);
            return false;
        }
        pid_ = static_cast<int>(pi.dwProcessId);
        CloseHandle(pi.hProcess);

        std::string banner;
        char buf[256];
        DWORD got = 0;
        const ULONG deadline = GetTickCount() + 15000;
        while (banner.find('\n') == std::string::npos &&
               GetTickCount() < deadline) {
            if (!ReadFile(rd, buf, sizeof buf, &got, nullptr) || got == 0) break;
            banner.append(buf, got);
        }
        CloseHandle(rd);

        int pid = 0, port = 0;
        const size_t p = banner.find("READY ");
        if (p == std::string::npos) return false;
        if (std::sscanf(banner.c_str() + p, "READY %d %d", &pid, &port) != 2) {
            return false;
        }
        port_ = static_cast<uint16_t>(port);
        return true;
    }

    int pid_{0};
    ProcessJob job_;
    bool job_assigned_{false};
    uint16_t port_{0};
};

} // namespace mghttp_test

#endif // _WIN32

#if !defined(_WIN32)
namespace mghttp_test {
class ProxyServerFixture {
public:
    bool start(const std::string&) { return false; }
    uint16_t port() const noexcept { return 0; }
    void stop() {}
};
} // namespace mghttp_test
#endif

#endif // MEGOHTTP_TEST_PROXY_SERVER_FIXTURE_HPP_INCLUDED
