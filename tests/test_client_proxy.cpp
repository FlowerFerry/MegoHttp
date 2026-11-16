#include <megohttp/config.hpp>
#include <megohttp/client.hpp>
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
        const std::string cmd = "python \"" + std::string(MEGOHTTP_TESTS_DIR) +
                                "/proxy_test_server.py\" --mode " + mode + " " + extra;
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
        if (pid_ > 0) {
            const std::string cmd = "taskkill /F /PID " + std::to_string(pid_) + " > nul 2>&1";
            std::system(cmd.c_str());
            pid_ = 0;
        }
#endif
        if (!recording_.empty()) std::remove(recording_.c_str());
    }

private:
    static std::string temp_path() {
        static std::atomic<unsigned> counter{0};
        char buf[512] = {0};
        std::snprintf(buf, sizeof buf, "%s/mgproxy_%u_%u.json", MEGOHTTP_TESTS_DIR,
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
        std::vector<char> mutable_cmd(cmd.begin(), cmd.end());
        mutable_cmd.push_back('\0');
        const BOOL ok = CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE, 0,
                                       nullptr, nullptr, &si, &pi);
        CloseHandle(write_h);
        if (!ok) { CloseHandle(read_h); return false; }

        pid_ = static_cast<int>(pi.dwProcessId);
        CloseHandle(pi.hThread);
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
};

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
    const std::string rec = proxy.recording();
    CHECK(rec.find("\"absolute_form\": true") != std::string::npos);

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
    CHECK(proxy.recording().find("Basic ") != std::string::npos);
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
    const std::string rec = proxy.recording();
    CHECK(rec.find("\"proxy_authorization\": \"Bearer") == std::string::npos);
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

    const std::string rec = proxy.recording();
    // The recorded ATYP is the whole point: "domain" proves the name travelled;
    // "ipv4" would prove the client resolved it locally first.
    CHECK(rec.find("\"atyp\": \"domain\"") != std::string::npos);
    CHECK(rec.find("proxy.test") != std::string::npos);
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
    CHECK(proxy.recording().find("\"user\": \"alice\"") != std::string::npos);
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
    bool start(const char* cert, const char* key) {
        std::string cmd = "python \"";
        cmd += MEGOHTTP_TESTS_DIR;
        cmd += "/https_test_server.py\" \"" + fixture(cert) + "\" \"" + fixture(key) + "\"";
        return spawn_and_read_banner(cmd);
    }

    uint16_t port() const noexcept { return port_; }
    ~HttpsOriginServer() { stop(); }

    void stop() {
#if defined(_WIN32)
        if (pid_ > 0) {
            std::string cmd = "taskkill /F /PID " + std::to_string(pid_) + " > nul 2>&1";
            std::system(cmd.c_str());
            pid_ = 0;
        }
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
        std::vector<char> mutable_cmd(cmd.begin(), cmd.end());
        mutable_cmd.push_back('\0');
        const BOOL ok = CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE, 0,
                                       nullptr, nullptr, &si, &pi);
        CloseHandle(write_h);
        if (!ok) { CloseHandle(read_h); return false; }

        pid_ = static_cast<int>(pi.dwProcessId);
        CloseHandle(pi.hThread);
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
    CHECK(proxy.recording().find("\"tls\": true") != std::string::npos);
    CHECK(proxy.recording().find("\"absolute_form\": true") != std::string::npos);
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

    const std::string rec = proxy.recording();
    CHECK(rec.find("\"kind\": \"connect\"") != std::string::npos);
    CHECK(rec.find("\"method\": \"CONNECT\"") != std::string::npos);
    CHECK(rec.find("\"target\": \"localhost:") != std::string::npos);
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

    CHECK(proxy.recording().find("\"kind\": \"connect\"") != std::string::npos);
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
    const std::string rec = proxy.recording();
    CHECK(rec.find("\"kind\": \"connect\"") != std::string::npos);
    CHECK(rec.find("\"tls\": true") != std::string::npos);
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
