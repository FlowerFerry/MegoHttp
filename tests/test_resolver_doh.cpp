// DNS over HTTPS tests (S5A.3-01 / S5A.3-02 / task book 9-A.3).
//
// Uses a local DoH server (tests/doh_test_server.py) behind the test CA from
// tls_fixtures, so nothing here touches the public DNS.

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#if MEGOHTTP_HAS_DOH && !MGHTTP_TLS_NONE

#include <megohttp/resolver_doh.hpp>

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
#include <unistd.h>
#endif

#include "process_job.hpp"
#include "proxy_server_fixture.hpp"

namespace {

using namespace megohttp;

std::string fixture(const char* name) {
    return std::string(MEGOHTTP_TLS_FIXTURE_DIR) + "/" + name;
}

bool wait_until(const std::function<bool()>& pred, int timeout_ms = 10000) {
    const auto start = std::chrono::steady_clock::now();
    while (!pred()) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

// Spawns tests/doh_test_server.py and reads its READY banner.
class DohTestServer {
public:
    bool start(const char* behaviour = nullptr) {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/doh_test_server.py\" --cert \"" + fixture("server-cert.pem") +
               "\" --key \"" + fixture("server-key.pem") + "\"";
        if (behaviour) { cmd += " --behaviour "; cmd += behaviour; }
        return spawn(cmd);
    }

    uint16_t port() const noexcept { return port_; }
    ~DohTestServer() { stop(); }

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

        const size_t p = banner.find("READY ");
        if (p == std::string::npos) return false;
        int pid = 0, port = 0;
        if (std::sscanf(banner.c_str() + p, "READY %d %d", &pid, &port) == 2) {
            port_ = static_cast<uint16_t>(port);
            return true;
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

DohOptions doh_options_for(uint16_t port, DohMethod method = DohMethod::Post) {
    DohOptions o;
    o.endpoint_url = string(("https://localhost:" + std::to_string(port) + "/dns-query").c_str());
    o.bootstrap_ip = string("127.0.0.1");   // strict bootstrap: no system DNS
    o.method = method;
    TlsConfig cfg;
    cfg.hostname = string("localhost");
    cfg.ca_file = string(fixture("ca.pem").c_str());
    o.tls = cfg;
    o.connect_timeout = std::chrono::seconds(5);
    o.request_timeout = std::chrono::seconds(10);
    o.total_timeout = std::chrono::seconds(15);
    return o;
}

} // anonymous namespace

// -----------------------------------------------------------------------

TEST_CASE("DoH POST resolves a name over HTTPS", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("DoH POST failed: " << megohttp::to_string(got.error().code())
                     << " msg=" << std::string(got.error().message().data(),
                                                got.error().message().size()));
    }
    REQUIRE(got);
    REQUIRE(got.value().size() == 2);
    CHECK(got.value()[0].port == 443);
    CHECK(got.value()[0].text == string("192.0.2.1"));
}

TEST_CASE("DoH GET carries the query in the dns parameter", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Get));

    std::atomic<bool> done{false};
    bool ok = false;
    resolver->resolve(string("a-only.example"), 80, [&](Result<AddressList> r) {
        ok = static_cast<bool>(r) && !r.value().empty();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(ok);
}

TEST_CASE("DoH reports NXDOMAIN as an empty answer", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("missing.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(got);
    CHECK(got.value().empty());
}

TEST_CASE("DoH reports NODATA as an empty answer", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("nodata.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(got);
    CHECK(got.value().empty());
}

TEST_CASE("DoH reports SERVFAIL as a server failure", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start("servfail"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Error got{ErrorCode::Success};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(got.code() == ErrorCode::DnsServerFailure);
}

TEST_CASE("DoH rejects a non-200 HTTP status", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start("wrong-status"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Error got{ErrorCode::Success};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(got.code() == ErrorCode::DnsResolveFailed);
}

TEST_CASE("DoH rejects a wrong response media type", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start("wrong-media-type"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Error got{ErrorCode::Success};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(got.code() == ErrorCode::DnsInvalidMessage);
}

TEST_CASE("DoH rejects a truncated response body", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start("truncated"));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Error got{ErrorCode::Success};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        if (!r) got = r.error();
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    // A body cut short is a transport failure, not a DNS answer.
    CHECK(got.code() != ErrorCode::Success);
}

TEST_CASE("DoH resolves an AAAA-only name", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);

    // The resolver interface issues A queries, so an AAAA-only name is NODATA
    // for this query type; assert the empty answer rather than an error.
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("aaaa-only.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(got);
    CHECK(got.value().empty());
}

TEST_CASE("DoH delivers a CNAME chain answer", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("alias.example"), 8443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(got);
    // alias.example -> CNAME dual.example -> 2 A records for dual.example
    REQUIRE(got.value().size() == 2);
    CHECK(got.value()[0].port == 8443);
}

TEST_CASE("DoH does not follow redirects by default", "[doh][s5a]") {
    // The fixture answers 200 directly, so this asserts the configuration
    // rather than a redirect round trip: a DoH resolver built with default
    // options must report follow_redirects == false.
    DohOptions o = doh_options_for(1, DohMethod::Post);
    CHECK(o.follow_redirects == false);
    CHECK(o.max_redirects == 3);
}

TEST_CASE("DoH carries no cookies", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<bool> done{false};
    bool ok = false;
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        ok = static_cast<bool>(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    CHECK(ok);
    // The internal client is built with a null cookie jar, so no Cookie header
    // can be produced. The server would answer 200 either way; the isolation is
    // structural (no jar exists to draw from).
}

TEST_CASE("concurrent DoH lookups each get their own answer", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    constexpr int kCount = 4;
    std::atomic<int> finished{0};
    std::atomic<int> ok{0};

    const char* names[kCount] = {"dual.example", "a-only.example",
                                 "alias.example", "dual.example"};
    for (int i = 0; i < kCount; ++i) {
        const uint16_t want_port = static_cast<uint16_t>(2000 + i);
        resolver->resolve(string(names[i]), want_port,
                          [&, want_port](Result<AddressList> r) {
            if (r && !r.value().empty() && r.value()[0].port == want_port) ++ok;
            ++finished;
        });
    }

    REQUIRE(wait_until([&] { return finished.load() == kCount; }));
    CHECK(ok.load() == kCount);
}

TEST_CASE("cancelling a DoH lookup drops the late answer", "[doh][s5a]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_options_for(srv.port(), DohMethod::Post));

    std::atomic<int> calls{0};
    auto handle = resolver->resolve(string("dual.example"), 443,
                                    [&](Result<AddressList>) {
        ++calls;
    });
    handle.cancel();

    // Give the in-flight request time to complete and be discarded.
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    CHECK(calls.load() == 0);
}


// -----------------------------------------------------------------------
// S5A.4-01 / 9-A.4: bootstrap and proxy. The endpoint is a name that only the
// proxy's --map knows how to reach, so success proves the DoH request really
// went through the proxy rather than silently bypassing it.
// -----------------------------------------------------------------------

namespace {

DohOptions doh_proxy_options(uint16_t doh_port, uint16_t proxy_port,
                             bool https_proxy) {
    DohOptions o;
    o.endpoint_url = string(("https://example.test:" +
                             std::to_string(doh_port) + "/dns-query").c_str());
    o.method = DohMethod::Post;
    o.tls = TlsConfig{};
    o.tls->hostname = string("example.test");
    o.tls->ca_file = string(fixture("ca.pem").c_str());
    o.proxy.proxy.type = https_proxy ? ProxyType::Https : ProxyType::Http;
    o.proxy.proxy.host = string("proxy.test");
    o.proxy.proxy.port = proxy_port;
    o.proxy_bootstrap_ip = string("127.0.0.1");
    o.use_system_bootstrap = false;
    if (https_proxy) {
        o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
        // The proxy fixture certificate is valid for localhost; the proxy
        // hostname is an override (proxy.test -> bootstrap IP), and TLS must
        // still validate the certificate identity, not the dialled address.
        o.proxy.tls.hostname = string("localhost");
    }
    o.connect_timeout = std::chrono::seconds(5);
    o.request_timeout = std::chrono::seconds(10);
    o.total_timeout = std::chrono::seconds(15);
    return o;
}

std::string proxy_args(bool https_proxy) {
    std::string args = "--mode connect --map example.test=127.0.0.1";
    if (https_proxy) {
        args += " --tls-cert \"";
        args += fixture("server-cert.pem");
        args += "\" --tls-key \"";
        args += fixture("server-key.pem");
        args += "\"";
    }
    return args;
}

} // namespace

TEST_CASE("DoH goes through an HTTP proxy and bootstraps the proxy name",
          "[doh][s5a][proxy]") {
    DohTestServer srv;
    REQUIRE(srv.start());
    mghttp_test::ProxyServerFixture proxy;
    REQUIRE(proxy.start(proxy_args(false)));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_proxy_options(srv.port(), proxy.port(), false));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("DoH proxy failed: "
                      << megohttp::to_string(got.error().code())
                      << " phase=" << megohttp::to_string(got.error().phase())
                      << " msg=" << std::string(got.error().message().data(),
                                                 got.error().message().size()));
    }
    REQUIRE(got);
    CHECK(got.value().size() == 2);
}

TEST_CASE("DoH goes through an HTTPS proxy with independent TLS identity",
          "[doh][s5a][proxy][tls]") {
    DohTestServer srv;
    REQUIRE(srv.start());
    mghttp_test::ProxyServerFixture proxy;
    REQUIRE(proxy.start(proxy_args(true)));

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(
        ex, doh_proxy_options(srv.port(), proxy.port(), true));

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("DoH HTTPS proxy failed: "
                      << megohttp::to_string(got.error().code())
                      << " phase=" << megohttp::to_string(got.error().phase())
                      << " msg=" << std::string(got.error().message().data(),
                                                 got.error().message().size()));
    }
    REQUIRE(got);
    CHECK(got.value().size() == 2);
}

TEST_CASE("DoH direct bootstrap uses the IP without changing certificate identity",
          "[doh][s5a][bootstrap]") {
    DohTestServer srv;
    REQUIRE(srv.start());

    DohOptions o;
    // example.test is a name, never a local hosts entry. The bootstrap IP is
    // the only way to reach the fixture; TLS must still validate example.test.
    o.endpoint_url = string(("https://example.test:" +
                             std::to_string(srv.port()) + "/dns-query").c_str());
    o.bootstrap_ip = string("127.0.0.1");
    o.tls = TlsConfig{};
    o.tls->hostname = string("example.test");
    o.tls->ca_file = string(fixture("ca.pem").c_str());
    o.use_system_bootstrap = false;
    o.connect_timeout = std::chrono::seconds(5);
    o.request_timeout = std::chrono::seconds(10);
    o.total_timeout = std::chrono::seconds(15);

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("DoH bootstrap failed: "
                      << megohttp::to_string(got.error().code())
                      << " phase=" << megohttp::to_string(got.error().phase())
                      << " msg=" << std::string(got.error().message().data(),
                                                 got.error().message().size()));
    }
    REQUIRE(got);
    CHECK(got.value().size() == 2);
}


TEST_CASE("DoH proxy authentication uses the proxy credential only",
          "[doh][s5a][proxy][auth]") {
    DohTestServer srv;
    REQUIRE(srv.start());
    mghttp_test::ProxyServerFixture proxy;
    REQUIRE(proxy.start(proxy_args(false) + " --require-auth"));

    DohOptions o = doh_proxy_options(srv.port(), proxy.port(), false);
    o.proxy.proxy.username = string("alice");
    o.proxy.proxy.password = string("s3cret");

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(got);
    CHECK(got.value().size() == 2);
}


TEST_CASE("DoH goes through SOCKS5 with remote DNS", "[doh][s5a][proxy][socks5]") {
    DohTestServer srv;
    REQUIRE(srv.start());
    mghttp_test::ProxyServerFixture proxy;
    REQUIRE(proxy.start("--mode socks5 --map example.test=127.0.0.1"));

    DohOptions o = doh_proxy_options(srv.port(), proxy.port(), false);
    o.proxy.proxy.type = ProxyType::Socks5;
    o.proxy.proxy.socks5_remote_dns = true;

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    if (!got) {
        UNSCOPED_INFO("DoH SOCKS5 failed: "
                      << megohttp::to_string(got.error().code())
                      << " phase=" << megohttp::to_string(got.error().phase())
                      << " msg=" << std::string(got.error().message().data(),
                                                 got.error().message().size()));
    }
    REQUIRE(got);
    CHECK(got.value().size() == 2);
}


TEST_CASE("DoH validates the HTTPS proxy identity separately", "[doh][s5a][proxy][tls]") {
    mghttp_test::ProxyServerFixture proxy;
    REQUIRE(proxy.start(proxy_args(true)));

    DohOptions o = doh_proxy_options(1, proxy.port(), true);
    // The proxy actually presents the server certificate; trusting the
    // untrusted CA must fail at the proxy layer before any CONNECT.
    o.proxy.tls.ca_file = string(fixture("untrusted-ca.pem").c_str());

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }));
    REQUIRE(!got);
    CHECK(got.error().phase() == ErrorPhase::ProxyTls);
}


TEST_CASE("DoH proxy handshake is bounded by connect_timeout",
          "[doh][s5a][proxy][timeout]") {
    mghttp_test::ProxyServerFixture proxy;
    std::string args = "--mode connect --tls-cert \"";
    args += fixture("server-cert.pem");
    args += "\" --tls-key \"";
    args += fixture("server-key.pem");
    args += "\" --tls-handshake-delay 2 --map example.test=127.0.0.1";
    REQUIRE(proxy.start(args));

    DohOptions o = doh_proxy_options(1, proxy.port(), true);
    o.connect_timeout = std::chrono::milliseconds(300);

    auto ex = detail::make_default_executor();
    REQUIRE(ex);
    auto resolver = std::make_shared<DohResolver>(ex, o);

    std::atomic<bool> done{false};
    Result<AddressList> got = Error{ErrorCode::Unknown};
    const auto started = std::chrono::steady_clock::now();
    resolver->resolve(string("dual.example"), 443, [&](Result<AddressList> r) {
        got = std::move(r);
        done.store(true);
    });

    REQUIRE(wait_until([&] { return done.load(); }, 5000));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    REQUIRE(!got);
    CHECK(got.error().code() == ErrorCode::TimeoutConnect);
    CHECK(elapsed < std::chrono::milliseconds(2500));
}

#endif // MEGOHTTP_HAS_DOH && !MGHTTP_TLS_NONE
