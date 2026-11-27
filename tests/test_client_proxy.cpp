#include <megohttp/config.hpp>
#include <megohttp/client.hpp>
#include <megohttp/content_range.hpp>
#include <megohttp/multipart_sink.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <windows.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include "process_job.hpp"

using namespace megohttp;

namespace {

#if defined(_WIN32)
using sock_t = SOCKET;
const sock_t kInvalid = INVALID_SOCKET;
void closesock(sock_t s) { ::closesocket(s); }
#else
using sock_t = int;
const sock_t kInvalid = -1;
void closesock(sock_t s) { ::close(s); }
#endif

// A local HTTP origin that records what it actually received.
//
// Asserting on the CLIENT alone cannot tell a correct forward-proxy relay from a
// client that ignored the proxy and dialled the origin directly, nor can it see
// whether a proxy credential leaked into the request the origin got. Both
// questions are only answerable from the origin's side.
class OriginServer {
public:
    bool start() {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_ == kInvalid) return false;
        int on = 1;
        ::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&on), sizeof on);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::bind(listen_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        if (::listen(listen_, 16) != 0) return false;
        sockaddr_in got{};
        socklen_t glen = sizeof got;
        ::getsockname(listen_, reinterpret_cast<sockaddr*>(&got), &glen);
        port_ = ntohs(got.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }
    int accepts() const noexcept { return accepts_.load(); }

    std::string last_request_line() const {
        std::lock_guard<std::mutex> g(mu_);
        return last_request_line_;
    }
    std::string last_headers() const {
        std::lock_guard<std::mutex> g(mu_);
        return last_headers_;
    }

    ~OriginServer() { stop(); }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (listen_ != kInvalid) { closesock(listen_); listen_ = kInvalid; }
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        while (!stopped_.load()) {
            sock_t c = ::accept(listen_, nullptr, nullptr);
            if (c == kInvalid) break;
            accepts_.fetch_add(1);
            std::thread([this, c] { serve(c); }).detach();
        }
    }

    void serve(sock_t c) {
        std::string head;
        char ch = 0;
        while (head.size() < 64 * 1024) {
            int n = static_cast<int>(::recv(c, &ch, 1, 0));
            if (n <= 0) break;
            head += ch;
            if (head.size() >= 4 && head.compare(head.size() - 4, 4, "\r\n\r\n") == 0) break;
        }
        {
            std::lock_guard<std::mutex> g(mu_);
            const size_t eol = head.find("\r\n");
            last_request_line_ = eol == std::string::npos ? head : head.substr(0, eol);
            const size_t blank = head.find("\r\n\r\n");
            last_headers_ = head.substr(0, blank == std::string::npos ? head.size() : blank);
        }
        const std::string resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
        closesock(c);
    }

    sock_t listen_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    std::atomic<int> accepts_{0};
    mutable std::mutex mu_;
    std::string last_request_line_;
    std::string last_headers_;
    std::thread thread_;
};

// Spawns tests/proxy_test_server.py and reports its dynamic port.
//
// The server runs until killed, so it must NOT be launched through popen():
// pclose() waits for the child to exit and a long-lived server never does --
// that deadlocks the suite. It is launched detached and its READY banner is read
// from a pipe that is then closed.
class ProxyServer {
public:
    bool start(const std::string& mode, const std::string& extra = "") {
        recording_ = temp_path();
#if defined(_WIN32)
        _putenv_s("MEGOHTTP_PROXY_RECORDING", recording_.c_str());
#endif
        std::string cmd = "python \"" + std::string(MEGOHTTP_TESTS_DIR) +
                          "/proxy_test_server.py\" --mode " + mode + " " + extra;
#if defined(_WIN32)
        // Keep the fixture tied to this test process even if it is force-killed.
        cmd += " --parent-pid " + std::to_string(GetCurrentProcessId());
#endif
        return spawn_and_read_banner(cmd);
    }

    uint16_t port() const noexcept { return port_; }

    // Reads what the proxy recorded. Polls briefly: the dump runs on its own
    // cadence rather than synchronously with the request.
    std::string recording() const {
        for (int i = 0; i < 100; ++i) {
            std::ifstream in(recording_);
            if (in) {
                std::stringstream ss;
                ss << in.rdbuf();
                const std::string s = ss.str();
                if (s.size() > 2 && s != "[]") return s;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return std::string("[]");
    }

    ~ProxyServer() { stop(); }

    void stop() {
#if defined(_WIN32)
        if (job_assigned_) {
            // Closing the job with KILL_ON_JOB_CLOSE terminates the tree.
            pid_ = 0;
        } else if (pid_ > 0) {
            mghttp_test::terminate_tree(static_cast<DWORD>(pid_));
            pid_ = 0;
        }
        job_.close();
#endif
        if (!recording_.empty()) std::remove(recording_.c_str());
    }

private:
    static std::string temp_path() {
        static std::atomic<unsigned> counter{0};
        char buf[512] = {0};
        // The pid is part of the name on purpose: the masked clock alone can
        // collide with a file left behind by an earlier run of this exe, and a
        // stale recording makes an assertion read another proxy's content.
#if defined(_WIN32)
        const unsigned pid = static_cast<unsigned>(::GetCurrentProcessId());
#else
        const unsigned pid = static_cast<unsigned>(::getpid());
#endif
        std::snprintf(buf, sizeof buf, "%s/mgproxy_%u_%u_%u.json", MEGOHTTP_TESTS_DIR, pid,
                      static_cast<unsigned>(
                          std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFF),
                      counter.fetch_add(1));
        return std::string(buf);
    }

    bool spawn_and_read_banner(const std::string& cmd) {
#if defined(_WIN32)
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        HANDLE read_h = nullptr;
        HANDLE write_h = nullptr;
        if (!CreatePipe(&read_h, &write_h, &sa, 0)) return false;
        SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = write_h;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};
        const BOOL ok = mghttp_test::spawn_in_job(cmd, si, 0, pi, job_);
        job_assigned_ = job_.assigned();
        CloseHandle(write_h);
        if (!ok) { CloseHandle(read_h); return false; }

        pid_ = static_cast<int>(pi.dwProcessId);
        CloseHandle(pi.hProcess);

        std::string banner;
        char buf[256];
        DWORD got = 0;
        const ULONG deadline = GetTickCount() + 15000;
        while (banner.find('\n') == std::string::npos && GetTickCount() < deadline) {
            if (!ReadFile(read_h, buf, sizeof buf, &got, nullptr) || got == 0) break;
            banner.append(buf, got);
        }
        CloseHandle(read_h);
        return parse_banner(banner);
#else
        FILE* f = popen(cmd.c_str(), "r");
        if (!f) return false;
        char line[256] = {0};
        if (!fgets(line, sizeof line, f)) { pclose(f); return false; }
        pclose(f);
        return parse_banner(line);
#endif
    }

    bool parse_banner(const std::string& banner) {
        std::istringstream is(banner);
        std::string tag;
        int pid = 0;
        int port = 0;
        is >> tag >> pid >> port;
        if (tag != "READY" || port <= 0) return false;
#if !defined(_WIN32)
        pid_ = pid;
#endif
        port_ = static_cast<uint16_t>(port);
        return true;
    }

    uint16_t port_{0};
    int pid_{0};
    std::string recording_;
    mghttp_test::ProcessJob job_;
    bool job_assigned_{false};
};

// recording() returns the first non-empty snapshot, which can predate the entry
// an assertion is about: the proxy records socks5_greeting before the auth
// record, and connect before connect_closed. A one-shot read therefore makes
// these checks racy, so poll until the needle shows up.
bool recording_contains(const ProxyServer& proxy, const char* needle,
                        int timeout_ms = 3000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    do {
        if (proxy.recording().find(needle) != std::string::npos) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

// Returns the library's owning string so Request can take it directly:
// std::string does not convert in MemeString mode, and that is correct.
string url(uint16_t port, const char* path = "/") {
    const std::string s = "http://127.0.0.1:" + std::to_string(port) + path;
    return to_string(s.c_str(), s.size());
}

ClientOptions via_http_proxy(uint16_t proxy_port) {
    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy_port;
    return o;
}

// A resolver that records which names it was asked for.
//
// SOCKS5 remote DNS is only correct if the target NAME never reaches the local
// resolver. Asserting that on the proxy's recorded ATYP proves what the proxy
// received; only the resolver itself can prove what did NOT happen locally.
class CountingResolver final : public Resolver {
public:
    string address{string("127.0.0.1")};

    CancelHandle resolve(string host, uint16_t port, Callback cb) override {
        const std::string name(host.data(), host.size());
        if (name != "127.0.0.1" && name != "::1" && name != "localhost") {
            ++target_lookups_;
        }
        AddressList out = parse_ip_literal(to_view(address), port);
        // Answer inline: the resolver contract allows it, and the Client already
        // marshals onto the loop thread.
        if (cb) cb(std::move(out));
        return CancelHandle{};
    }

    const char* name() const noexcept override { return "counting"; }

    int target_lookups() const { return target_lookups_.load(); }

private:
    std::atomic<int> target_lookups_{0};
};

} // namespace

// ---------------------------------------------------------------------------
// S5.4-01: a cleartext target through a forward proxy
// ---------------------------------------------------------------------------

TEST_CASE("a cleartext target through a forward proxy uses absolute-form",
          "[proxy][client]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("forward"));

    Client c(via_http_proxy(proxy.port()));
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/a/b?x=1")));

    INFO("proxy_port=" << proxy.port() << " origin_port=" << origin.port()
         << " error code=" << (r ? 0 : static_cast<int>(r.error().code()))
         << " phase=" << (r ? 0 : static_cast<int>(r.error().phase())));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    // The proxy must have seen the absolute form: without it a forward proxy has
    // no idea where to relay.
    CHECK(recording_contains(proxy, "\"absolute_form\": true"));

    // The ORIGIN must have seen origin-form. An absolute target reaching an
    // origin is something every real proxy conceals, so only the origin can
    // tell us it did not happen.
    CHECK(origin.last_request_line().rfind("GET /a/b?x=1 ", 0) == 0);
}

TEST_CASE("proxy credentials never reach the target", "[proxy][client][security]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("forward", "--require-auth"));

    ClientOptions o = via_http_proxy(proxy.port());
    o.proxy.proxy.username = string("alice");
    o.proxy.proxy.password = string("s3cret");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/x")));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    // Present on the proxy hop...
    CHECK(recording_contains(proxy, "Basic "));
    // ...and absent from what the origin received. This is the leak a
    // "did the request succeed" test cannot see.
    CHECK(origin.last_headers().find("roxy-authorization") == std::string::npos);
    CHECK(origin.last_headers().find("roxy-connection") == std::string::npos);
}

TEST_CASE("a target Authorization is not reused as proxy credentials",
          "[proxy][client][security]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("forward", "--require-auth"));

    Client c(via_http_proxy(proxy.port()));     // no proxy credentials
    Request req(Method::Get, url(origin.port(), "/y"));
    req.headers().set("authorization", "Bearer target-token");
    auto r = c.request_sync(req);

    // The proxy demands credentials the caller never supplied, so it answers
    // 407 -- not 200 with the target token smuggled in as proxy auth.
    REQUIRE(r);
    CHECK(r.value().head().status_code == 407);

    // The proxy must not have received the target token AS proxy credentials.
    // It legitimately sees the target's Authorization header -- a forward proxy
    // relays the request and cannot avoid seeing it (task book 10.1 says so
    // explicitly) -- so the assertion is on the proxy-authorization field only.
    // Wait for the forward entry itself before asserting on its field: a read
    // taken before the entry lands would pass for the wrong reason.
    CHECK(recording_contains(proxy, "\"kind\": \"forward\""));
    CHECK(proxy.recording().find("\"proxy_authorization\": \"Bearer") == std::string::npos);
}

TEST_CASE("wrong proxy credentials surface as a 407 from the proxy",
          "[proxy][client][security]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("forward", "--require-auth"));

    ClientOptions o = via_http_proxy(proxy.port());
    o.proxy.proxy.username = string("alice");
    o.proxy.proxy.password = string("WRONG");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/z")));
    REQUIRE(r);
    // A forward proxy answers 407 in HTTP: a valid response, not a transport
    // failure, and it must reach the caller rather than be retried away.
    CHECK(r.value().head().status_code == 407);
}

// ---------------------------------------------------------------------------
// S5.4-05: SOCKS5
// ---------------------------------------------------------------------------

TEST_CASE("a SOCKS5 proxy with remote DNS hands over the name",
          "[proxy][client][socks5]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("socks5", "--map proxy.test=127.0.0.1"));

    // The resolver counts calls so "the name never reached the local resolver"
    // becomes a fact instead of an inference. `localhost` is not usable as the
    // target name here: it resolves to ::1 first on this host while the fixture
    // origin binds 127.0.0.1, so the proxy's own connect would fail and the
    // failure would look like a client bug.
    auto counting = std::make_shared<CountingResolver>();
    counting->address = string("127.0.0.1");

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Socks5;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    // socks5h semantics: the NAME travels to the proxy.
    o.proxy.proxy.socks5_remote_dns = true;
    o.resolver = counting;

    Client c(o);
    // "127.0.0.1" is passed as a NAME here on purpose: the proxy is told to
    // treat `proxy.test` as 127.0.0.1 (see --map below), so the tunnel command
    // can carry a domain-type ATYP while the proxy still reaches the fixture
    // origin. Using a real DNS name would depend on this host's resolver.
    const std::string s = "http://proxy.test:" + std::to_string(origin.port()) + "/s";
    auto r = c.request_sync(Request(Method::Get, to_string(s.c_str(), s.size())));
    INFO("socks5-remote-dns error=" << (r ? 0 : static_cast<int>(r.error().code()))
         << " phase=" << (r ? 0 : static_cast<int>(r.error().phase())));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    // The local resolver must never have been asked for the target name: a
    // single lookup here would be the proxy host itself.
    CHECK(counting->target_lookups() == 0);

    // The recorded ATYP is the whole point: "domain" proves the name travelled;
    // "ipv4" would prove the client resolved it locally first.
    CHECK(recording_contains(proxy, "\"atyp\": \"domain\""));
    CHECK(recording_contains(proxy, "proxy.test"));
}

TEST_CASE("a SOCKS5 proxy that rejects the credentials fails with Socks5AuthFailed",
          "[proxy][client][socks5]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("socks5", "--require-auth"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Socks5;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.proxy.username = string("alice");
    o.proxy.proxy.password = string("WRONG");
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/s")));
    REQUIRE_FALSE(r);
    CHECK(r.error().code() == ErrorCode::Socks5AuthFailed);
    CHECK(r.error().phase() == ErrorPhase::ProxyAuth);
}

TEST_CASE("SOCKS5 username/password auth succeeds end to end",
          "[proxy][client][socks5]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("socks5", "--require-auth"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Socks5;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.proxy.username = string("alice");
    o.proxy.proxy.password = string("s3cret");
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/s")));
    INFO("socks5-auth error code=" << (r ? 0 : static_cast<int>(r.error().code()))
         << " phase=" << (r ? 0 : static_cast<int>(r.error().phase())));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(recording_contains(proxy, "\"user\": \"alice\""));
}

// ---------------------------------------------------------------------------
// Transparent behaviour
// ---------------------------------------------------------------------------

TEST_CASE("with no proxy configured the connection goes straight to the target",
          "[proxy][client]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("forward"));

    Client c(ClientOptions{});          // proxy default = None
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/direct")));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    // The proxy must have observed nothing at all.
    CHECK(proxy.recording() == "[]");
}

TEST_CASE("NO_PROXY bypasses a configured proxy", "[proxy][client][no_proxy]") {
    OriginServer origin;
    REQUIRE(origin.start());
    ProxyServer proxy;
    REQUIRE(proxy.start("forward"));

    ClientOptions o = via_http_proxy(proxy.port());
    o.proxy.no_proxy.push_back(string("127.0.0.1"));

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/bypass")));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    // Bypassed means the proxy saw nothing AND the origin got the request.
    // Both halves are needed: "it succeeded" alone proves neither.
    CHECK(proxy.recording() == "[]");
    CHECK(origin.accepts() >= 1);
}

TEST_CASE("an unusable proxy configuration is rejected before any socket opens",
          "[proxy][client]") {
    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;
    o.proxy.proxy.host = string("");     // no host
    o.proxy.proxy.port = 3128;
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, to_string("http://127.0.0.1:1/")));
    REQUIRE_FALSE(r);
    CHECK(r.error().code() == ErrorCode::InvalidArgument);
}
#if !MGHTTP_TLS_NONE


// ---------------------------------------------------------------------------
// S5.4-03 / S5.4-04: HTTPS proxy (TLS to the proxy itself) and layered TLS
//
// Two identities are in play and they must not be confused:
//   - the PROXY's certificate, validated with ProxyOptions::tls;
//   - the TARGET's certificate, validated with ClientOptions::tls.
// Task book 9.3 forbids one object driving both, so the tests below configure
// the two layers separately and assert that neither substitutes for the other.
// ---------------------------------------------------------------------------

namespace {

std::string fixture(const char* name) {
    return std::string(MEGOHTTP_TLS_FIXTURE_DIR) + "/" + name;
}

// Spawns tests/https_test_server.py: a real TLS origin answering a fixed 200.
// OriginServer above speaks cleartext, so a CONNECT-tunnel test needs this one.
class HttpsOriginServer {
public:
    bool start(const char* cert, const char* key, const char* extra_args = nullptr) {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/https_test_server.py\" \"" + fixture(cert) + "\" \"" + fixture(key) + "\"";
        // Lets the server exit if this test binary is force-killed.
        cmd += " --parent-pid " + std::to_string(GetCurrentProcessId());
        if (extra_args) { cmd += " "; cmd += extra_args; }
        return spawn_and_read_banner(cmd);
    }

    uint16_t port() const noexcept { return port_; }
    ~HttpsOriginServer() { stop(); }

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
    bool spawn_and_read_banner(const std::string& cmd) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        HANDLE read_h = nullptr;
        HANDLE write_h = nullptr;
        if (!CreatePipe(&read_h, &write_h, &sa, 0)) return false;
        SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = write_h;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};
        const BOOL ok = mghttp_test::spawn_in_job(cmd, si, 0, pi, job_);
        job_assigned_ = job_.assigned();
        CloseHandle(write_h);
        if (!ok) { CloseHandle(read_h); return false; }

        pid_ = static_cast<int>(pi.dwProcessId);
        CloseHandle(pi.hProcess);

        std::string banner;
        char buf[256];
        DWORD got = 0;
        const ULONG deadline = GetTickCount() + 15000;
        while (banner.find('\n') == std::string::npos && GetTickCount() < deadline) {
            if (!ReadFile(read_h, buf, sizeof buf, &got, nullptr) || got == 0) break;
            banner.append(buf, got);
        }
        CloseHandle(read_h);

        std::istringstream is(banner);
        std::string tag;
        int port = 0;
        is >> tag >> pid_ >> port;
        port_ = static_cast<uint16_t>(port);
        return tag == "READY" && port_ != 0;
    }

    uint16_t port_{0};
    int pid_{0};
    mghttp_test::ProcessJob job_;
    bool job_assigned_{false};
};

// The fixture certificate covers "localhost", so the URL names localhost even
// though the origin binds 127.0.0.1: identity check and dialled address agree.
std::string tunnel_url(uint16_t port, const char* path = "/via-tunnel") {
    return "https://localhost:" + std::to_string(port) + path;
}

string to_owning(const std::string& s) { return string(s.data(), s.size()); }

} // namespace

TEST_CASE("an HTTPS proxy wraps its own connection in TLS", "[proxy][client][https_proxy]") {
    // The proxy speaks TLS; the target is plain HTTP. Completing this proves the
    // proxy layer did TLS of its own, which is the distinction task book 10.2
    // draws between "HTTPS proxy" and "CONNECT".
    OriginServer origin;
    REQUIRE(origin.start());

    ProxyServer proxy;
    REQUIRE(proxy.start("forward", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                    "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    // The PROXY layer trusts the test CA and checks the proxy's own name.
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/via-https-proxy")));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    // The proxy saw the absolute form over TLS, and the origin saw origin-form.
    CHECK(recording_contains(proxy, "\"tls\": true"));
    CHECK(recording_contains(proxy, "\"absolute_form\": true"));
    CHECK(origin.last_request_line().rfind("GET /via-https-proxy ", 0) == 0);
}

TEST_CASE("an HTTPS proxy whose certificate the client does not trust is refused",
          "[proxy][client][https_proxy][security]") {
    OriginServer origin;
    REQUIRE(origin.start());

    ProxyServer proxy;
    REQUIRE(proxy.start("forward", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                    "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    // Trust the WRONG CA: the proxy presents a certificate signed by ca.pem, so
    // this must fail rather than fall back to cleartext.
    o.proxy.tls.ca_file = string(fixture("untrusted-ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/x")));
    REQUIRE_FALSE(r);
    // The failure must be attributed to the PROXY layer, not to the target.
    CHECK(r.error().phase() == ErrorPhase::ProxyTls);
    // And it must not have connected to the origin at all.
    CHECK(origin.accepts() == 0);
}

TEST_CASE("the proxy and the target are validated with separate trust material",
          "[proxy][client][https_proxy][security]") {
    // This test covers ONLY the proxy-layer object: setting ProxyOptions::tls
    // leaves ClientOptions::tls untouched, asserted below. The target-side
    // counterpart is "layered TLS: HTTPS proxy and HTTPS target use independent
    // trust", which drives https:// through a CONNECT tunnel.
    OriginServer origin;
    REQUIRE(origin.start());

    ProxyServer proxy;
    REQUIRE(proxy.start("forward", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                    "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());   // proxy: trusted
    o.proxy.tls.hostname = string("localhost");
    // Target TLS settings stay untouched, proving the two are separate objects:
    // configuring the proxy's CA must not have authorized the target as well.
    CHECK(o.tls.ca_file.empty());

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, url(origin.port(), "/split")));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
}

// ---------------------------------------------------------------------------
// S5.4-02: a real CONNECT tunnel carries an https:// request end to end.
//
// The forward-proxy tests above prove absolute-form relaying, which is a
// DIFFERENT path. Reaching an https:// target through an HTTP-speaking proxy
// requires CONNECT first and then target TLS inside the tunnel; the assertion is
// on the BODY the TLS origin served, and the proxy recording proves the CONNECT
// actually happened rather than the client dialling the origin directly.
// ---------------------------------------------------------------------------
TEST_CASE("an https target behind an HTTP proxy uses a CONNECT tunnel",
          "[proxy][client][connect]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    // Target TLS: trust the test CA and expect the origin's name. This is
    // ClientOptions::tls -- the TARGET layer, not the proxy layer.
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, to_owning(tunnel_url(origin.port()))));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    // The body proves the tunnel carried real TLS-framed HTTP, not merely a 200
    // from the proxy's own CONNECT reply.
    CHECK(r.value().body_text() == string_view("hello over https"));

    CHECK(recording_contains(proxy, "\"kind\": \"connect\""));
    CHECK(recording_contains(proxy, "\"method\": \"CONNECT\""));
    CHECK(recording_contains(proxy, "\"target\": \"localhost:"));
}

// ---------------------------------------------------------------------------
// S5.4-02: a CONNECT the proxy refuses is a proxy-layer failure and the target
// is never contacted.
// ---------------------------------------------------------------------------
TEST_CASE("a CONNECT refused by the proxy does not reach the target",
          "[proxy][client][connect][security]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", "--require-auth"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.proxy.username = string("alice");
    o.proxy.proxy.password = string("WRONG");   // the fixture expects alice:s3cret
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, to_owning(tunnel_url(origin.port()))));
    REQUIRE_FALSE(r);
    // A refused CONNECT is a proxy failure, attributed to the proxy layer rather
    // than to the target's TLS or to a generic transport error.
    CHECK(r.error().phase() == ErrorPhase::ProxyAuth);
    CHECK(r.error().code() == ErrorCode::ProxyAuthRequired);

    CHECK(recording_contains(proxy, "\"kind\": \"connect\""));
}

// ---------------------------------------------------------------------------
// S5.4-04: layered TLS -- an HTTPS proxy whose own certificate the client
// trusts, wrapping a CONNECT tunnel to an HTTPS target. Both layers are real
// TLS and each is configured through its own object.
// ---------------------------------------------------------------------------
TEST_CASE("layered TLS: HTTPS proxy and HTTPS target use independent trust",
          "[proxy][client][https_proxy][security]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    // PROXY layer: Https means TLS to the proxy itself.
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    // TARGET layer: a separate TlsConfig. Same CA on purpose -- the sibling test
    // below uses a wrong proxy CA, which is what proves they are not shared.
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get,
        to_owning(tunnel_url(origin.port(), "/via-layered-tls"))));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(r.value().body_text() == string_view("hello over https"));

    // The proxy saw a CONNECT on its own TLS listener.
    CHECK(recording_contains(proxy, "\"kind\": \"connect\""));
    CHECK(recording_contains(proxy, "\"tls\": true"));
}

// ---------------------------------------------------------------------------
// S3.4-19 / S5.6-05: multipart over an HTTPS proxy CONNECT tunnel.
//
// Layer order under test: TLS to the proxy -> CONNECT -> TLS to the target ->
// HTTP framing -> multipart parsing. Neither individual half is new (the tiered
// TLS path is covered above, multipart over plain HTTP in test_multipart_client),
// but the COMBINATION is what S3.4-19 asks for and it exercises a real risk: the
// multipart parser sits at the very top of the stack, reading bytes that travelled
// through two TLS layers.
// ---------------------------------------------------------------------------
TEST_CASE("multipart response arrives intact through an HTTPS proxy CONNECT tunnel",
          "[proxy][client][https_proxy][multipart][s34-19][s56-05]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--multipart"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct Recorder : MultipartSink {
        int parts_begun{0};
        int parts_ended{0};
        int completions{0};
        bool error_fired{false};
        Error last_error{};
        std::vector<std::string> payloads;
        void on_part_begin(const MultipartPartHead&) override { ++parts_begun; payloads.push_back({}); }
        bool on_part_data(const uint8_t* d, size_t n) override {
            payloads.back().append(reinterpret_cast<const char*>(d), n);
            return true;
        }
        void on_part_end() override { ++parts_ended; }
        void on_complete() override { ++completions; }
        void on_error(const Error& e) override { error_fired = true; last_error = e; }
    };

    auto sink = std::make_shared<Recorder>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/via-layered-tls")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");   // explicit, bypass Content-Type parsing
    req.set_multipart_sink(sink, mopts);

    auto r = c.request_sync(req);
    UNSCOPED_INFO("parts_begun=" << sink->parts_begun
                 << " parts_ended=" << sink->parts_ended
                 << " completions=" << sink->completions
                 << " error=" << sink->error_fired);
    if (sink->error_fired) {
        UNSCOPED_INFO("sink error code=" << megohttp::to_string(sink->last_error.code())
                     << " msg-len=" << sink->last_error.message().size());
    }
    if (!r) {
        UNSCOPED_INFO("request failed: " << megohttp::to_string(r.error().code())
                     << " (" << static_cast<int>(r.error().code()) << ")");
        UNSCOPED_INFO("phase: " << megohttp::to_string(r.error().phase()));
    }
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(r.value().body_is_buffered() == false);

    // Both parts arrived with their exact payloads, over two TLS layers.
    REQUIRE(sink->parts_begun == 2);
    REQUIRE(sink->parts_ended == 2);
    CHECK(sink->completions == 1);
    CHECK(!sink->error_fired);
    REQUIRE(sink->payloads.size() == 2);
    CHECK(sink->payloads[0] == "part-one");
    CHECK(sink->payloads[1] == "part-two");

    // The proxy really did see a CONNECT on its own TLS listener.
    CHECK(recording_contains(proxy, "\"kind\": \"connect\""));
    CHECK(recording_contains(proxy, "\"tls\": true"));
}

// Diagnostic: same multipart payload, but through a PLAIN HTTP proxy CONNECT
// tunnel (one TLS layer instead of two). Isolates "CONNECT" from "second TLS
// layer" as the cause of a failure.
TEST_CASE("multipart through a plain HTTP proxy CONNECT tunnel",
          "[proxy][client][multipart][diagnostic]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--multipart"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;      // cleartext to the proxy
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct Rec : MultipartSink {
        int begun{0}, ended{0}, done{0};
        std::vector<std::string> payloads;
        void on_part_begin(const MultipartPartHead&) override { ++begun; payloads.push_back({}); }
        bool on_part_data(const uint8_t* d, size_t n) override {
            payloads.back().append(reinterpret_cast<const char*>(d), n);
            return true;
        }
        void on_part_end() override { ++ended; }
        void on_complete() override { ++done; }
        void on_error(const Error&) override {}
    };
    auto sink = std::make_shared<Rec>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/p")));
    req.set_multipart_sink(sink);

    auto r = c.request_sync(req);
    UNSCOPED_INFO("begun=" << sink->begun << " ended=" << sink->ended << " done=" << sink->done);
    if (!r) UNSCOPED_INFO("failed: " << megohttp::to_string(r.error().code()));
    REQUIRE(r);
    CHECK(sink->begun == 2);
}

TEST_CASE("a plain body arrives intact through an HTTPS proxy CONNECT tunnel",
          "[proxy][client][https_proxy][diagnostic]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--multipart"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get,
        to_owning(tunnel_url(origin.port(), "/via-layered-tls"))));
    REQUIRE(r);
    // Buffered mode: the raw body must arrive byte-exact through both TLS layers.
    const auto& b = r.value().body_bytes();
    const std::string got(b.begin(), b.end());
    UNSCOPED_INFO("body len=" << got.size());
    UNSCOPED_INFO("body=" << got);
    CHECK(got.size() == 248);   // multipart body: 2 parts + header blank lines
}

// ---------------------------------------------------------------------------
// S3.4-19 / S5.6-05 (streaming guarantees over the tunnel): backpressure,
// cancellation and truncation must behave the same when the bytes travel
// through proxy TLS + CONNECT + target TLS, not only over plain HTTP. The
// multipart parser sits at the very top of that stack.
// ---------------------------------------------------------------------------

TEST_CASE("multipart backpressure works through an HTTPS proxy CONNECT tunnel",
          "[proxy][client][https_proxy][multipart][backpressure][s34-19][s56-05]") {
    constexpr size_t kPartBytes = 256 * 1024;

    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem",
                         "--multipart --part-bytes 262144 --pace-chunk 8192 --pace-delay 0.005"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct PausingSink : MultipartSink {
        std::atomic<bool> paused{false};
        std::atomic<size_t> bytes{0};
        std::atomic<int> begun{0};
        std::atomic<int> ended{0};
        std::atomic<int> completions{0};
        std::atomic<bool> wrong_byte{false};
        void on_part_begin(const MultipartPartHead&) override { begun.fetch_add(1); }
        bool on_part_data(const uint8_t* d, size_t n) override {
            for (size_t i = 0; i < n; ++i) {
                if (d[i] != 'x') { wrong_byte.store(true); break; }
            }
            bytes.fetch_add(n);
            // Ask for a pause exactly once, on the first block.
            if (!paused.exchange(true)) return false;
            return true;
        }
        void on_part_end() override { ended.fetch_add(1); }
        void on_complete() override { completions.fetch_add(1); }
        void on_error(const Error&) override {}
    };

    auto sink = std::make_shared<PausingSink>();
    auto flow = std::make_shared<Request::MultipartSinkFlow>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/paced")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");   // explicit, bypass Content-Type parsing
    req.set_multipart_sink(sink, mopts, flow);

    std::atomic<bool> was_paused{false};
    std::thread resumer([&] {
        for (int i = 0; i < 500 && !sink->paused.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        // Give the exchange a moment to observe the false return and pause the
        // flow, then record that state before resuming.
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        was_paused.store(flow->is_paused());
        flow->resume();
    });

    auto r = c.request_sync(req);
    resumer.join();

    UNSCOPED_INFO("paused=" << was_paused.load() << " bytes=" << sink->bytes.load()
                 << " begun=" << sink->begun.load() << " ended=" << sink->ended.load()
                 << " completions=" << sink->completions.load());
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(r.value().body_is_buffered() == false);
    CHECK(was_paused.load());                  // the pause really reached the flow
    CHECK(sink->begun.load() == 1);
    CHECK(sink->ended.load() == 1);
    CHECK(sink->completions.load() == 1);
    CHECK(sink->bytes.load() == kPartBytes);   // nothing lost across the pause
    CHECK_FALSE(sink->wrong_byte.load());
}

TEST_CASE("cancelling a multipart stream through the tunnel ends in Cancelled",
          "[proxy][client][https_proxy][multipart][cancel][s34-19][s56-05]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem",
                         "--multipart --part-bytes 1048576 --pace-chunk 4096 --pace-delay 0.005"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct CountingSink : MultipartSink {
        std::atomic<int> begun{0};
        std::atomic<int> completions{0};
        void on_part_begin(const MultipartPartHead&) override { begun.fetch_add(1); }
        bool on_part_data(const uint8_t*, size_t) override { return true; }
        void on_part_end() override {}
        void on_complete() override { completions.fetch_add(1); }
        void on_error(const Error&) override {}
    };
    auto sink = std::make_shared<CountingSink>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/slow")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");
    req.set_multipart_sink(sink, mopts);

    std::atomic<bool> done{false};
    std::atomic<int> code{0};
    auto handle = c.request(req, [&](Result<Response> r) {
        if (!r) code.store(static_cast<int>(r.error().code()));
        done.store(true);
    });

    // Cancel only once the stream is actually flowing, so this is a mid-body
    // cancellation rather than a cancel of something that never started.
    for (int i = 0; i < 500 && sink->begun.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(sink->begun.load() == 1);
    handle.cancel();
    for (int i = 0; i < 500 && !done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CHECK(done.load());
    CHECK(static_cast<ErrorCode>(code.load()) == ErrorCode::Cancelled);
    CHECK(sink->completions.load() == 0);   // cancelling is never a success
}

TEST_CASE("a truncated multipart body through the tunnel reports MultipartTruncated",
          "[proxy][client][https_proxy][multipart][truncation][s34-19][s56-05]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--multipart-truncated"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct Recorder : MultipartSink {
        std::atomic<int> begun{0};
        std::atomic<int> completions{0};
        std::atomic<bool> error_fired{false};
        std::atomic<int> last_code{0};
        void on_part_begin(const MultipartPartHead&) override { begun.fetch_add(1); }
        bool on_part_data(const uint8_t*, size_t) override { return true; }
        void on_part_end() override {}
        void on_complete() override { completions.fetch_add(1); }
        void on_error(const Error& e) override {
            last_code.store(static_cast<int>(e.code()));
            error_fired.store(true);
        }
    };
    auto sink = std::make_shared<Recorder>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/cut")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");
    req.set_multipart_sink(sink, mopts);

    auto r = c.request_sync(req);
    UNSCOPED_INFO("begun=" << sink->begun.load()
                 << " completions=" << sink->completions.load()
                 << " error_fired=" << sink->error_fired.load());
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::MultipartTruncated);
    CHECK(sink->error_fired.load());
    CHECK(static_cast<ErrorCode>(sink->last_code.load()) == ErrorCode::MultipartTruncated);
    CHECK(sink->completions.load() == 0);
    CHECK(sink->begun.load() >= 1);   // the part that did arrive was delivered
}

// ---------------------------------------------------------------------------
// S3.4-19 / S5.6-05 (the rest of the streaming matrix): Content-Encoding in
// front of the parser, byteranges, and an endless x-mixed-replace stream. All
// three have plain-HTTP coverage in test_multipart_client; these are the
// two-TLS-layer versions.
// ---------------------------------------------------------------------------

#if MEGOHTTP_HAS_ZLIB
TEST_CASE("gzipped multipart through the tunnel is decoded before parsing",
          "[proxy][client][https_proxy][multipart][gzip][s34-19][s56-05]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--multipart --gzip"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct Recorder : MultipartSink {
        std::atomic<int> begun{0};
        std::atomic<int> completions{0};
        std::atomic<bool> error_fired{false};
        std::vector<std::string> payloads;
        void on_part_begin(const MultipartPartHead&) override {
            begun.fetch_add(1);
            payloads.push_back({});
        }
        bool on_part_data(const uint8_t* d, size_t n) override {
            payloads.back().append(reinterpret_cast<const char*>(d), n);
            return true;
        }
        void on_part_end() override {}
        void on_complete() override { completions.fetch_add(1); }
        void on_error(const Error&) override { error_fired.store(true); }
    };
    auto sink = std::make_shared<Recorder>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/gz")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");
    req.set_multipart_sink(sink, mopts);

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(r.value().body_decoded() == true);   // a decoder chain really ran
    CHECK(r.value().body_is_buffered() == false);
    CHECK(sink->begun.load() == 2);
    CHECK(sink->completions.load() == 1);
    CHECK_FALSE(sink->error_fired.load());
    REQUIRE(sink->payloads.size() == 2);
    CHECK(sink->payloads[0] == "part-one");
    CHECK(sink->payloads[1] == "part-two");
}
#endif // MEGOHTTP_HAS_ZLIB

TEST_CASE("multipart/byteranges through the tunnel exposes per-part Content-Range",
          "[proxy][client][https_proxy][multipart][byteranges][s34-19][s56-05]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--byteranges"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct RangeSink : MultipartSink {
        std::vector<std::optional<ContentRange>> ranges;
        std::vector<size_t> lengths;
        size_t current{0};
        bool range_error{false};
        int completions{0};
        bool error_fired{false};
        void on_part_begin(const MultipartPartHead& head) override {
            auto parsed = multipart_part_content_range(head);
            if (!parsed) {
                range_error = true;
                ranges.push_back(std::nullopt);
            } else {
                ranges.push_back(parsed.value());
            }
            current = 0;
        }
        bool on_part_data(const uint8_t*, size_t n) override {
            current += n;
            return true;
        }
        void on_part_end() override { lengths.push_back(current); }
        void on_complete() override { ++completions; }
        void on_error(const Error&) override { error_fired = true; }
    };
    auto sink = std::make_shared<RangeSink>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/ranges")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");
    req.set_multipart_sink(sink, mopts);

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK_FALSE(sink->range_error);
    CHECK_FALSE(sink->error_fired);
    CHECK(sink->completions == 1);
    REQUIRE(sink->ranges.size() == 2);
    REQUIRE(sink->lengths.size() == 2);

    // The fixture sends 95-99 BEFORE 0-4 on purpose: part order must not be
    // assumed to follow the request's Range order.
    REQUIRE(sink->ranges[0].has_value());
    REQUIRE(sink->ranges[1].has_value());
    CHECK(sink->ranges[0]->first.value() == 95);
    CHECK(sink->ranges[0]->last.value() == 99);
    CHECK(sink->ranges[0]->total.value() == 100);
    CHECK(sink->ranges[1]->first.value() == 0);
    CHECK(sink->ranges[1]->last.value() == 4);

    // The declared range must match the bytes that actually arrived per part.
    CHECK(sink->lengths[0] == 5);
    CHECK(sink->lengths[1] == 5);
    CHECK(validate_content_range(sink->ranges[0].value(), sink->lengths[0], 100).has_value());
    CHECK(validate_content_range(sink->ranges[1].value(), sink->lengths[1], 100).has_value());
}

TEST_CASE("an x-mixed-replace stream through the tunnel ends at connection close",
          "[proxy][client][https_proxy][multipart][continuous][s34-19][s56-05]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem", "--continuous"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");

    struct Recorder : MultipartSink {
        std::atomic<int> begun{0};
        std::atomic<int> completions{0};
        std::atomic<bool> error_fired{false};
        std::vector<std::string> payloads;
        void on_part_begin(const MultipartPartHead&) override {
            begun.fetch_add(1);
            payloads.push_back({});
        }
        bool on_part_data(const uint8_t* d, size_t n) override {
            payloads.back().append(reinterpret_cast<const char*>(d), n);
            return true;
        }
        void on_part_end() override {}
        void on_complete() override { completions.fetch_add(1); }
        void on_error(const Error&) override { error_fired.store(true); }
    };
    auto sink = std::make_shared<Recorder>();

    Client c(o);
    Request req(Method::Get, to_owning(tunnel_url(origin.port(), "/stream")));
    MultipartResponseOptions mopts;
    mopts.boundary = string("megohttp-boundary-42");
    // Without this the missing closing delimiter is a truncation (that is what
    // the truncation case asserts); x-mixed-replace is the documented exception.
    mopts.allow_continuous_stream = true;
    req.set_multipart_sink(sink, mopts);

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(sink->begun.load() == 2);
    CHECK(sink->completions.load() == 1);
    CHECK_FALSE(sink->error_fired.load());
    REQUIRE(sink->payloads.size() == 2);
    CHECK(sink->payloads[0] == "tick-1");
    CHECK(sink->payloads[1] == "tick-2");
}

// ---------------------------------------------------------------------------
// S5.4-04: a wrong PROXY CA must fail at the proxy layer even though the target
// layer is configured correctly -- that asymmetry is the proof of separation.
// ---------------------------------------------------------------------------
TEST_CASE("layered TLS: a wrong proxy CA fails at the proxy layer",
          "[proxy][client][https_proxy][security]") {
    HttpsOriginServer origin;
    REQUIRE(origin.start("server-cert.pem", "server-key.pem"));

    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") + "\""));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("untrusted-ca.pem").c_str());  // wrong for the proxy
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());                  // correct for the target
    o.tls.hostname = string("localhost");

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, to_owning(tunnel_url(origin.port()))));
    REQUIRE_FALSE(r);
    CHECK(r.error().phase() == ErrorPhase::ProxyTls);
}

// ---------------------------------------------------------------------------
// 2026-11-13 code review, defect #2: the CONNECT status code was parsed with
// std::atoi, which has undefined behaviour on overflow. The status line comes
// straight from an untrusted proxy, so "999999999999" must be rejected as a
// protocol error rather than producing whatever the platform does.
// ---------------------------------------------------------------------------
TEST_CASE("an oversized CONNECT status code is rejected",
          "[proxy][client][connect][malformed]") {
    ProxyServer proxy;
    REQUIRE(proxy.start("connect", "--connect-status 999999999999"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, to_owning("https://example.test/")));

    REQUIRE_FALSE(r);
    CHECK(r.error().code() == ErrorCode::ProxyProtocolError);
    CHECK(r.error().phase() == ErrorPhase::ProxyConnectTunnel);
}

TEST_CASE("a non-numeric CONNECT status code is rejected",
          "[proxy][client][connect][malformed]") {
    ProxyServer proxy;
    REQUIRE(proxy.start("connect", "--connect-status banana"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Http;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();

    Client c(o);
    auto r = c.request_sync(Request(Method::Get, to_owning("https://example.test/")));

    REQUIRE_FALSE(r);
    CHECK(r.error().code() == ErrorCode::ProxyProtocolError);
}

// ---------------------------------------------------------------------------
// S5.8-01: the connection-stage deadline covers the PROXY handshake.
//
// The proxy accepts the TCP connection and then says nothing for 30 s. Because
// TCP succeeded, no per-stage timeout can catch this: only a deadline spanning
// DNS -> TCP -> proxy TLS -> CONNECT -> target TLS can. Before this the request
// hung until the Client was destroyed whenever total_timeout was left at 0.
//
// The phase assertion is what keeps the diagnostic honest: the caller must be
// told the PROXY handshake timed out, not "TcpConnect".
// ---------------------------------------------------------------------------
TEST_CASE("a stalled proxy TLS handshake is bounded by connect_timeout",
          "[proxy][client][https_proxy][deadline]") {
    ProxyServer proxy;
    REQUIRE(proxy.start("connect", std::string("--tls-cert \"") + fixture("server-cert.pem") +
                                       "\" --tls-key \"" + fixture("server-key.pem") +
                                       "\" --tls-handshake-delay 30"));

    ClientOptions o;
    o.proxy.proxy.type = ProxyType::Https;
    o.proxy.proxy.host = string("127.0.0.1");
    o.proxy.proxy.port = proxy.port();
    o.proxy.tls.ca_file = string(fixture("ca.pem").c_str());
    o.proxy.tls.hostname = string("localhost");
    o.tls.ca_file = string(fixture("ca.pem").c_str());
    o.tls.hostname = string("localhost");
    // Short connect budget. total_timeout stays disabled on purpose: the
    // connection stage must bound this on its own.
    o.connect_timeout = std::chrono::milliseconds(400);
    o.total_timeout = std::chrono::milliseconds(0);

    Client c(o);
    const auto t0 = std::chrono::steady_clock::now();
    auto r = c.request_sync(Request(Method::Get, to_owning("https://localhost:1/")));
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);

    REQUIRE_FALSE(r);
    CHECK(r.error().code() == ErrorCode::TimeoutConnect);
    CHECK(r.error().phase() == ErrorPhase::ProxyTls);
    // Fired on the 400 ms budget, not after the 30 s stall.
    CHECK(elapsed < std::chrono::milliseconds(5000));
}

#endif // !MGHTTP_TLS_NONE
