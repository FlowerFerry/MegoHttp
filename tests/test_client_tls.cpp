// S4 Client integration: an https:// request runs end to end over TLS.
//
// This is the item that makes the TLS work count: without it the TLS layer is
// only exercised by its own unit tests and no real HTTP request ever uses it.
#include <megohttp/config.hpp>
#include <megohttp/client.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>

#include <catch2/catch_test_macros.hpp>

#if MGHTTP_TLS_NONE

TEST_CASE("client refuses https when built without a TLS backend", "[tls][client]") {
    megohttp::Client c;
    megohttp::Request req(megohttp::Method::Get,
                          megohttp::string("https://127.0.0.1:1/"));
    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == megohttp::ErrorCode::TlsNotEnabled);
}

#else

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>

using namespace megohttp;

namespace {

bool wait_until(std::function<bool()> pred, int max_ms = 15000) {
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

// Runs the local HTTPS server and reports the port it bound to.
class HttpsServer {
public:
    bool start(const char* cert, const char* key, const char* extra = "") {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/https_test_server.py\" \"" + fixture_path(cert) + "\" \"" +
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

    ~HttpsServer() {
        if (pid_ != 0) {
            // Kill by PID: the accept loop never ends on its own, so _pclose
            // would block until the test binary is killed.
            std::string kill = "taskkill /F /PID " + std::to_string(pid_);
            kill += " >NUL 2>&1";
            std::system(kill.c_str());
        }
        if (pipe_) {
            _pclose(pipe_);
            pipe_ = nullptr;
        }
    }

    HttpsServer() = default;
    HttpsServer(const HttpsServer&) = delete;
    HttpsServer& operator=(const HttpsServer&) = delete;

private:
    FILE* pipe_{nullptr};
    uint16_t port_{0};
    unsigned long pid_{0};
};

ClientOptions https_options(uint16_t port) {
    ClientOptions opt;
    const std::string ca = fixture_path("ca.pem");
    opt.tls.ca_file = string(ca.data(), ca.size());
    // The certificate covers "localhost"; connect to it by that name so the
    // DNS lookup and the identity check agree.
    (void)port;
    return opt;
}

std::string url_for(uint16_t port, const char* path = "/") {
    std::string u = "https://localhost:";
    u += std::to_string(port);
    u += path;
    return u;
}

string to_s(const std::string& s) { return string(s.data(), s.size()); }

} // namespace

TEST_CASE("client performs an https GET end to end", "[tls][client]") {
    HttpsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem"));

    Client c(https_options(srv.port()));
    const std::string url = url_for(srv.port());
    Request req(Method::Get, to_s(url));

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(r.value().body_text() == string_view("hello over https"));
}

TEST_CASE("client surfaces a certificate failure as TlsCertificateInvalid", "[tls][client]") {
    HttpsServer srv;
    // Server presents a certificate from a CA the client does not trust.
    REQUIRE(srv.start("untrusted-cert.pem", "untrusted-key.pem"));

    Client c(https_options(srv.port()));   // trusts ca.pem only
    Request req(Method::Get, to_s(url_for(srv.port())));

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::TlsCertificateInvalid);
    CHECK(r.error().phase() == ErrorPhase::TlsHandshake);
}

TEST_CASE("client surfaces a hostname mismatch separately", "[tls][client]") {
    HttpsServer srv;
    REQUIRE(srv.start("wrongname-cert.pem", "wrongname-key.pem"));

    Client c(https_options(srv.port()));
    Request req(Method::Get, to_s(url_for(srv.port())));

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::TlsHostnameMismatch);
}

TEST_CASE("client does not silently downgrade https to http", "[tls][client]") {
    HttpsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem"));

    // No CA configured: the default trust store does not know the test CA, so
    // the request must fail rather than go out in the clear.
    ClientOptions opt;
    Client c(opt);
    Request req(Method::Get, to_s(url_for(srv.port())));

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().phase() == ErrorPhase::TlsHandshake);
}

TEST_CASE("client validates a certificate signed by an intermediate CA",
          "[tls][client][chain]") {
    // Server presents leaf + intermediate; client trusts only the root.
    // The TLS backend must build the chain leaf -> intermediate -> root to
    // succeed.
    HttpsServer srv;
    REQUIRE(srv.start("intermediate-server-fullchain.pem",
                      "intermediate-server-key.pem"));

    TlsConfig tls;
    tls.hostname = string("localhost");
    // Trust only the root CA; the intermediate is NOT in this file, so the
    // backend must use the intermediate the server sent.
    const std::string ca = fixture_path("ca.pem");
    tls.ca_file = string(ca.data(), ca.size());
    tls.alpn_protocols.push_back(string("http/1.1"));

    ClientOptions opt;
    opt.tls = std::move(tls);
    Client c(opt);
    Request req(Method::Get, to_s(url_for(srv.port())));

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
}

TEST_CASE("handshake timeout aborts a stalled server", "[tls][client][timeout]") {
    // The server accepts the TCP connection but then waits 30 s before ever
    // touching TLS. A 1 s handshake timeout must expire first and return a
    // TimeoutTotal error.
    HttpsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem",
                      "--handshake-delay 30"));

    TlsConfig tls;
    tls.hostname = string("localhost");
    const std::string ca = fixture_path("ca.pem");
    tls.ca_file = string(ca.data(), ca.size());

    ClientOptions opt;
    opt.tls = std::move(tls);
    // 1 s total timeout, short enough to fire before the 30 s handshake delay.
    opt.total_timeout = std::chrono::seconds(1);
    Client c(opt);
    Request req(Method::Get, to_s(url_for(srv.port())));

    auto r = c.request_sync(req);
    REQUIRE(!r);
    // The deadline can land in different stages depending on timing, so accept
    // any of the timeout codes rather than pinning one that may flap.
    const ErrorCode code = r.error().code();
    const bool is_timeout = code == ErrorCode::TimeoutTotal ||
                            code == ErrorCode::TimeoutConnect ||
                            code == ErrorCode::TimeoutSend;
    CHECK(is_timeout);
}

#endif // MGHTTP_TLS_NONE
