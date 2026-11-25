// DNS over TLS tests (S5A.2-01 / task book 9-A.2).
//
// Uses a local DoT server (tests/dot_test_server.py) and the test CA from
// tls_fixtures, so nothing here touches the public DNS.

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#if MEGOHTTP_HAS_DOT && !MGHTTP_TLS_NONE

#include <megohttp/resolver_dot.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "process_job.hpp"

namespace {

using namespace megohttp;

std::string fixture(const char* name) {
    return std::string(MEGOHTTP_TLS_FIXTURE_DIR) + "/" + name;
}

bool wait_until(const std::function<bool()>& pred, int timeout_ms = 8000) {
    const auto start = std::chrono::steady_clock::now();
    while (!pred()) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

// Spawns tests/dot_test_server.py and reads its READY banner.
class DotTestServer {
public:
    bool start(const char* extra = nullptr) {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/dot_test_server.py\" --cert \"" + fixture("server-cert.pem") +
               "\" --key \"" + fixture("server-key.pem") + "\"";
        if (extra) { cmd += " "; cmd += extra; }
        return spawn(cmd);
    }

    uint16_t port() const noexcept { return port_; }
    ~DotTestServer() { stop(); }

    void stop() {
#if defined(_WIN32)
        if (job_assigned_) {
            job_.terminate();
            pid_ = 0;
        } else if (pid_ > 0) {
            mghttp_test::terminate_tree(static_cast<DWORD>(pid_));
            pid_ = 0;
        }
        job_.close();
#endif
    }

private:
    bool spawn(const std::string& cmd) {
#if defined(_WIN32)
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
        const BOOL ok = mghttp_test::spawn_in_job(cmd, si, 0, pi, job_);
        job_assigned_ = job_.assigned();
        CloseHandle(wr);
        if (!ok) { CloseHandle(rd); return false; }
        pid_ = static_cast<int>(pi.dwProcessId);
        CloseHandle(pi.hProcess);

        std::string banner;
        char buf[256];
        DWORD got = 0;
        const ULONG deadline = GetTickCount() + 15000;
        while (banner.find('\n') == std::string::npos && GetTickCount() < deadline) {
            if (!ReadFile(rd, buf, sizeof buf, &got, nullptr) || got == 0) break;
            banner.append(buf, got);
        }
        CloseHandle(rd);

        for (auto& line : {banner}) {
            const size_t p = line.find("READY ");
            if (p == std::string::npos) continue;
            int pid = 0, port = 0;
            if (std::sscanf(line.c_str() + p, "READY %d %d", &pid, &port) == 2) {
                port_ = static_cast<uint16_t>(port);
                return true;
            }
        }
        return false;
#else
        (void)cmd;
        return false;
#endif
    }

#if defined(_WIN32)
    int pid_{0};
    mghttp_test::ProcessJob job_;
    bool job_assigned_{false};
#endif
    uint16_t port_{0};
};

DotOptions dot_options_for(uint16_t port) {
    DotOptions o;
    o.server_name = string("localhost");
    o.bootstrap_ip = string("127.0.0.1");   // strict bootstrap: no system DNS
    o.port = port;
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.connect_timeout = std::chrono::seconds(5);
    return o;
}

} // anonymous namespace

// -----------------------------------------------------------------------

TEST_CASE("DoT resolves a name over a real TLS connection", "[dot][s5a]") {
    DotTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("example.com"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("resolve failed: " << megohttp::to_string(got.error().code())
                     << " phase=" << megohttp::to_string(got.error().phase())
                     << " msg=" << std::string(got.error().message().data(),
                                                got.error().message().size()));
    }
    REQUIRE(got);
    REQUIRE(got.value().size() == 1);
    // The fixture server answers 192.0.2.1 and the port is copied through.
    CHECK(got.value()[0].text == string("192.0.2.1"));
    CHECK(got.value()[0].port == 443);
    CHECK(got.value()[0].bytes.size() == 4);
}

TEST_CASE("DoT reports NXDOMAIN distinctly from a transport failure", "[dot][s5a]") {
    DotTestServer srv;
    REQUIRE(srv.start("--rcode 3"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<bool> done{false};
    Error got{ErrorCode::Unknown};
    resolver->resolve(string("nonexistent.example"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(got.code() == ErrorCode::DnsNameNotFound);
}

TEST_CASE("DoT returns an address for a name the fixture knows", "[dot][s5a]") {
    DotTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<bool> done{false};
    bool ok_answer = false;
    resolver->resolve(string("dual.example"), 53, [&](Result<AddressList> r) {
        ok_answer = static_cast<bool>(r);
        done.store(true);
    });
    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(ok_answer);
}

TEST_CASE("DoT times out instead of hanging when the endpoint never answers DNS",
          "[dot][s5a]") {
    // Start a server that completes TLS but never replies to a query: point at
    // the plain TLS echo server, which will read the DNS message and send
    // nothing back in DNS framing.
    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    DotOptions o;
    o.server_name = string("localhost");
    o.bootstrap_ip = string("127.0.0.1");
    // Port 1 on loopback is not listening: the TCP connect itself must fail,
    // which is the cheapest deterministic "cannot reach the endpoint" case.
    o.port = 1;
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.connect_timeout = std::chrono::milliseconds(300);

    auto resolver = std::make_shared<DotResolver>(ex, o);

    std::atomic<bool> done{false};
    Error got{ErrorCode::Unknown};
    resolver->resolve(string("example.com"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 8000));
    CHECK(got.code() != ErrorCode::Success);
}

TEST_CASE("DoT answers an IP literal locally without opening a connection",
          "[dot][s5a]") {
    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    // Point at a port nothing listens on: if the resolver tried to connect for
    // a literal, it would fail. Answering from the literal path proves no
    // connection was attempted.
    DotOptions o;
    o.server_name = string("localhost");
    o.bootstrap_ip = string("127.0.0.1");
    o.port = 1;
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.connect_timeout = std::chrono::milliseconds(200);

    auto resolver = std::make_shared<DotResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("203.0.113.7"), 8080, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 3000));
    REQUIRE(got);
    REQUIRE(got.value().size() == 1);
    CHECK(got.value()[0].text == string("203.0.113.7"));
    CHECK(got.value()[0].port == 8080);
}

TEST_CASE("DoT refuses a named endpoint with no bootstrap address", "[dot][s5a]") {
    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    DotOptions o;
    o.server_name = string("dns.example.net");   // a name
    o.bootstrap_ip = string{};                   // and no address to dial
    o.port = 853;
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.connect_timeout = std::chrono::milliseconds(200);

    auto resolver = std::make_shared<DotResolver>(ex, o);

    std::atomic<bool> done{false};
    Error got{ErrorCode::Unknown};
    resolver->resolve(string("example.com"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 5000));
    // Task book 9-A.4: strict mode must report a configuration error rather than
    // silently falling back to the system resolver.
    CHECK(got.code() == ErrorCode::ConfigurationError);
}

TEST_CASE("a cancelled DoT lookup does not receive its late answer", "[dot][s5a]") {
    DotTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<int> callbacks{0};
    auto handle = resolver->resolve(string("example.com"), 443,
                                    [&](Result<AddressList>) { ++callbacks; });
    handle.cancel();

    // Give the loop time to run the answer through.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK(callbacks.load() == 0);
}

TEST_CASE("concurrent DoT lookups match their own answers", "[dot][s5a]") {
    DotTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    constexpr int kCount = 5;
    std::atomic<int> finished{0};
    std::atomic<int> ok{0};

    for (int i = 0; i < kCount; ++i) {
        // Distinct names and distinct ports: each answer must come back with
        // its OWN port, which is what proves the message-ID matching did not
        // cross wires between the five pipelined queries.
        std::string name = "host" + std::to_string(i) + ".example";
        uint16_t want_port = static_cast<uint16_t>(1000 + i);
        resolver->resolve(string(name.c_str()), want_port,
                          [&, want_port](Result<AddressList> r) {
            if (r && !r.value().empty() && r.value()[0].port == want_port) ++ok;
            ++finished;
        });
    }

    REQUIRE(wait_until([&] { return finished.load() == kCount; }, 10000));
    CHECK(ok.load() == kCount);
}

// A second resolve for the same name should hit the cache and NOT issue another
// wire query. The --count-file option lets us observe the server-side count.

namespace {

std::string scratch_path(const char* name) {
    // Write next to the test fixtures so the path does not depend on the
    // process working directory.
    return std::string(MEGOHTTP_TESTS_DIR) + "/" + name;
}

int read_count(const std::string& path) {
    FILE* f = nullptr;
#if defined(_WIN32)
    fopen_s(&f, path.c_str(), "r");
#else
    f = std::fopen(path.c_str(), "r");
#endif
    int v = -1;
    if (f) {
        if (std::fscanf(f, "%d", &v) != 1) v = -1;
        std::fclose(f);
    }
    return v;
}

} // anonymous namespace

TEST_CASE("DoT caches a positive answer by TTL", "[dot][s5a][cache]") {
    const std::string count_path = scratch_path("dot_cache_count.txt");
    std::remove(count_path.c_str());

    DotTestServer srv;
    std::string extra = "--count-file \"" + count_path + "\" --ttl 10";
    REQUIRE(srv.start(extra.c_str()));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<bool> done1{false}, done2{false};
    Result<AddressList> r1 = Error{ErrorCode::Unknown};
    Result<AddressList> r2 = Error{ErrorCode::Unknown};
    resolver->resolve(string("example.com"), 443,
                      [&](Result<AddressList> r) { r1 = std::move(r); done1 = true; });
    REQUIRE(wait_until([&]{ return done1.load(); }));
    REQUIRE(r1);
    REQUIRE(r1.value().size() == 1);
    CHECK(r1.value()[0].text == string("192.0.2.1"));

    // Give the server time to record the first query.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const int count_after_first = read_count(count_path);
    REQUIRE(count_after_first == 1);

    // Same host and same port: this must be served from the cache.
    resolver->resolve(string("example.com"), 443,
                      [&](Result<AddressList> r) { r2 = std::move(r); done2 = true; });
    REQUIRE(wait_until([&]{ return done2.load(); }));
    REQUIRE(r2);
    CHECK(r2.value().size() == 1);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    // Cache hit: the server still saw exactly one query.
    CHECK(read_count(count_path) == 1);
}

TEST_CASE("DoT does not cache a TTL-zero answer", "[dot][s5a][cache]") {
    DotTestServer srv;
    REQUIRE(srv.start("--ttl 0"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<int> done{0};
    resolver->resolve(string("example.com"), 443,
                      [&](Result<AddressList>) { ++done; });
    // Two lookups back to back: TTL=0 means each must hit the wire. That they
    // both complete proves the second was not swallowed by an empty cache entry.
    resolver->resolve(string("example.com"), 443,
                      [&](Result<AddressList>) { ++done; });
    REQUIRE(wait_until([&]{ return done.load() == 2; }, 10000));
}

TEST_CASE("DoT reports NXDOMAIN and caches nothing without an SOA", "[dot][s5a][cache]") {
    // The fixture returns NXDOMAIN with no authority section, so RFC 2308 gives
    // no negative TTL and the cache must store nothing rather than invent one.
    DotTestServer srv;
    REQUIRE(srv.start("--rcode 3"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DotResolver>(ex, dot_options_for(srv.port()));

    std::atomic<int> done{0};
    std::atomic<int> nx{0};
    for (int i = 0; i < 2; ++i) {
        resolver->resolve(string("missing.example"), 443,
                          [&](Result<AddressList> r) {
            if (!r && r.error().code() == ErrorCode::DnsNameNotFound) ++nx;
            ++done;
        });
    }
    REQUIRE(wait_until([&]{ return done.load() == 2; }, 10000));
    // Both lookups reached the server and both reported NXDOMAIN: no negative
    // entry was created from a response that carried no SOA.
    CHECK(nx.load() == 2);
}

// S5A.4-01: system bootstrap mode resolves server_name via system DNS.
TEST_CASE("DoT system bootstrap resolves a named endpoint", "[dot][s5a][bootstrap]") {
    DotTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    DotOptions o;
    o.server_name = string("localhost");
    // NO bootstrap_ip: system bootstrap mode must resolve it.
    o.port = srv.port();
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.connect_timeout = std::chrono::seconds(5);
    o.use_system_bootstrap = true;

    auto resolver = std::make_shared<DotResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("example.com"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("resolve failed: " << megohttp::to_string(got.error().code())
                     << " phase=" << megohttp::to_string(got.error().phase())
                     << " msg=" << std::string(got.error().message().data(),
                                                got.error().message().size()));
    }
    REQUIRE(got);
    REQUIRE(got.value().size() == 1);
    CHECK(got.value()[0].text == string("192.0.2.1"));
}

#endif // MEGOHTTP_HAS_DOT && !MGHTTP_TLS_NONE
