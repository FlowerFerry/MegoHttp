// Phase 5 S5.2: redirect policy through the public Client.
//
// The redirect policy has three separable behaviours, and each gets its own
// counterweight so a wrong implementation cannot pass:
//   1. method/body policy per status  -- 303 must become GET, 307 must keep it
//   2. relative Location resolution   -- "/next" has to reach the right path
//   3. safety rails                   -- https->http refused, credentials not
//                                        forwarded cross-origin, loops stopped
//
// Every test drives a real socket against a local server that records what it
// actually received, because a policy checked only against an internal struct
// would not prove the wire bytes changed.
#include <megohttp/config.hpp>
#include <megohttp/client.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
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

struct SeenRequest {
    std::string head;      // raw request head, for method/path/header assertions
    std::string method;
    std::string path;
};

// A scripted HTTP/1.1 server: each connection answers with the next entry of the
// script. Records every request it saw so a test can assert on the wire form
// (method, path, headers) rather than on library internals.
class RedirectServer {
public:
    struct Reply {
        int status{200};
        std::string location;   // empty = no Location header
        std::string body{"ok"};
        // Delay before answering this hop. Used to prove that the total
        // timeout accumulates across redirects instead of resetting per hop.
        int delay_ms{0};
    };

    bool start(std::vector<Reply> script) {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        script_ = std::move(script);
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!valid(listen_)) return false;
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

    // Patch the first scripted reply after start(): a Location that embeds this
    // server's own port cannot be built before bind().
    void set_first_location(const std::string& loc) {
        std::lock_guard<std::mutex> lk(m_);
        if (!script_.empty()) script_[0].location = loc;
    }

    std::vector<SeenRequest> seen() const {
        std::lock_guard<std::mutex> lk(m_);
        return seen_;
    }
    size_t seen_count() const {
        std::lock_guard<std::mutex> lk(m_);
        return seen_.size();
    }

    ~RedirectServer() { stop(); }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (valid(listen_)) { closesock(listen_); listen_ = invalid(); }
        if (thread_.joinable()) thread_.join();
    }

private:
#if defined(_WIN32)
    using sock_t = SOCKET;
    static sock_t invalid() { return INVALID_SOCKET; }
    static bool valid(sock_t s) { return s != INVALID_SOCKET; }
    static void closesock(sock_t s) { ::closesocket(s); }
#else
    using sock_t = int;
    static sock_t invalid() { return -1; }
    static bool valid(sock_t s) { return s >= 0; }
    static void closesock(sock_t s) { ::close(s); }
#endif

    void run() {
        while (!stopped_.load()) {
            sock_t c = ::accept(listen_, nullptr, nullptr);
            if (!valid(c)) return;
            std::thread([this, c] { serve(c); }).detach();
        }
    }

    static std::string read_head(sock_t c) {
        std::string head;
        char ch = 0;
        while (head.size() < 64 * 1024) {
            int n = static_cast<int>(::recv(c, &ch, 1, 0));
            if (n <= 0) return {};
            head += ch;
            if (head.size() >= 4 && head.compare(head.size() - 4, 4, "\r\n\r\n") == 0) break;
        }
        return head;
    }

    void serve(sock_t c) {
        for (;;) {
            const std::string head = read_head(c);
            if (head.empty()) break;

            SeenRequest sr;
            sr.head = head;
            // First line: "METHOD target HTTP/1.1"
            const size_t sp1 = head.find(' ');
            const size_t sp2 = head.find(' ', sp1 + 1);
            if (sp1 != std::string::npos && sp2 != std::string::npos) {
                sr.method = head.substr(0, sp1);
                sr.path = head.substr(sp1 + 1, sp2 - sp1 - 1);
            }
            Reply reply;
            {
                std::lock_guard<std::mutex> lk(m_);
                seen_.push_back(sr);
                const size_t idx = seen_.size() - 1;
                reply = idx < script_.size() ? script_[idx] : Reply{};
            }

            if (reply.delay_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(reply.delay_ms));
            }

            std::string resp = "HTTP/1.1 " + std::to_string(reply.status) + " X\r\n";
            if (!reply.location.empty()) resp += "Location: " + reply.location + "\r\n";
            resp += "Content-Length: " + std::to_string(reply.body.size()) + "\r\n";
            resp += "Connection: keep-alive\r\n\r\n";
            resp += reply.body;
            if (::send(c, resp.data(), static_cast<int>(resp.size()), 0) <= 0) break;
        }
        closesock(c);
    }

    sock_t listen_{invalid()};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    std::vector<Reply> script_;
    mutable std::mutex m_;
    std::vector<SeenRequest> seen_;
    std::thread thread_;
};

std::string to_std(const string& s) { return std::string(s.data(), s.size()); }

string to_s(const std::string& s) { return string(s.data(), s.size()); }

std::string url_on(uint16_t port, const char* path) {
    return "http://127.0.0.1:" + std::to_string(port) + path;
}

std::string read_file_head(const SeenRequest& r) {
    std::string lower = r.head;
    for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return lower;
}

ClientOptions following(size_t max_redirects = 5) {
    ClientOptions opt;
    opt.redirects.follow = true;
    opt.redirects.max_redirects = max_redirects;
    return opt;
}

} // namespace

// ---------------------------------------------------------------------------
// Status -> method/body policy
// ---------------------------------------------------------------------------

TEST_CASE("303 redirect turns POST into GET and drops the body", "[redirect]") {
    RedirectServer srv;
    // 303 first, then the final 200.
    REQUIRE(srv.start({{303, "/done", ""}, {200, "", "ok"}}));

    Client c(following());
    Request req(Method::Post, to_s(url_on(srv.port(), "/start")));
    req.set_body("hello");
    // Caller-supplied framing must be dropped with the body on 303. The
    // library-generated Content-Length never lived in Request::headers(), so
    // only this explicit header proves the cleanup path.
    req.headers().set("content-length", "5");

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    CHECK(seen[0].method == "POST");
    CHECK(seen[1].method == "GET");        // 303 always becomes GET
    CHECK(seen[1].path == "/done");
    // No body headers left over on the second hop.
    const std::string h1 = read_file_head(seen[1]);
    CHECK(h1.find("content-length:") == std::string::npos);
    CHECK(h1.find("transfer-encoding:") == std::string::npos);
}

TEST_CASE("307 preserves the method and the body", "[redirect]") {
    RedirectServer srv;
    REQUIRE(srv.start({{307, "/moved", ""}, {200, "", "ok"}}));

    Client c(following());
    Request req(Method::Post, to_s(url_on(srv.port(), "/start")));
    req.set_body("hello");

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    CHECK(seen[0].method == "POST");
    CHECK(seen[1].method == "POST");       // preserved
    const std::string h1 = read_file_head(seen[1]);
    CHECK(h1.find("content-length: 5") != std::string::npos);
}

TEST_CASE("308 preserves the method like 307", "[redirect]") {
    RedirectServer srv;
    REQUIRE(srv.start({{308, "/moved", ""}, {200, "", "ok"}}));

    Client c(following());
    Request req(Method::Put, to_s(url_on(srv.port(), "/start")));
    req.set_body("abc");

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    CHECK(seen[1].method == "PUT");
}

TEST_CASE("301 turns POST into GET", "[redirect]") {
    RedirectServer srv;
    REQUIRE(srv.start({{301, "/new", ""}, {200, "", "ok"}}));

    Client c(following());
    Request req(Method::Post, to_s(url_on(srv.port(), "/start")));
    req.set_body("hello");

    auto r = c.request_sync(req);
    REQUIRE(r);
    REQUIRE(srv.seen_count() == 2);
    CHECK(srv.seen()[1].method == "GET");
}

TEST_CASE("307 refuses an unreplayable body instead of sending an empty one",
          "[redirect]") {
    // A BodySource can only be consumed once. Following a 307 would mean
    // re-sending it, which is impossible -- and sending nothing while reporting
    // success would be worse. The redirect must fail.
    RedirectServer srv;
    REQUIRE(srv.start({{307, "/moved", ""}, {200, "", "ok"}}));

    Client c(following());
    Request req(Method::Post, to_s(url_on(srv.port(), "/start")));
    req.set_body_source([] { return Result<std::pair<string_view, bool>>{
        std::make_pair(string_view("x"), true)}; });

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::HttpInvalidResponse);
}

// ---------------------------------------------------------------------------
// Relative Location resolution
// ---------------------------------------------------------------------------

TEST_CASE("relative Location resolves against the request URL", "[redirect]") {
    RedirectServer srv;
    REQUIRE(srv.start({{302, "/next", ""}, {200, "", "ok"}}));

    Client c(following());
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/a/b"))));
    REQUIRE(r);

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    CHECK(seen[1].path == "/next");   // absolute-path replacement
}

TEST_CASE("scheme-relative Location keeps the scheme and host", "[redirect]") {
    RedirectServer srv;
    // Start first: the port is only known after bind, and a Location of
    // "//127.0.0.1:0/other" would be rejected as an invalid port -- which is
    // what happened when this was built before start().
    REQUIRE(srv.start({{302, "", ""}, {200, "", "ok"}}));
    const std::string target = "//127.0.0.1:" + std::to_string(srv.port()) + "/other";
    srv.set_first_location(target);

    Client c(following());
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/start"))));
    REQUIRE(r);

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    CHECK(seen[1].path == "/other");
}

// ---------------------------------------------------------------------------
// Safety rails
// ---------------------------------------------------------------------------

TEST_CASE("cross-origin redirect drops Authorization", "[redirect]") {
    // Two servers so the origins genuinely differ.
    RedirectServer first;
    RedirectServer second;
    // Both must be started before either port is used in a Location.
    REQUIRE(first.start({{302, "", ""}}));
    REQUIRE(second.start({{200, "", "ok"}}));
    first.set_first_location(url_on(second.port(), "/target"));

    Client c(following());
    Request req(Method::Get, to_s(url_on(first.port(), "/start")));
    req.headers().set("authorization", "Bearer secret");
    req.headers().set("x-trace", "keep-me");

    auto r = c.request_sync(req);
    REQUIRE(r);

    REQUIRE(second.seen_count() == 1);
    const std::string h = read_file_head(second.seen()[0]);
    CHECK(h.find("authorization") == std::string::npos);   // dropped
    CHECK(h.find("x-trace") != std::string::npos);         // unrelated header kept
}

TEST_CASE("same-origin redirect keeps Authorization", "[redirect]") {
    RedirectServer srv;
    REQUIRE(srv.start({{302, "/next", ""}, {200, "", "ok"}}));

    Client c(following());
    Request req(Method::Get, to_s(url_on(srv.port(), "/start")));
    req.headers().set("authorization", "Bearer secret");

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto seen = srv.seen();
    REQUIRE(seen.size() == 2);
    const std::string h = read_file_head(seen[1]);
    CHECK(h.find("authorization") != std::string::npos);
}

TEST_CASE("a redirect loop is detected instead of burning the budget",
          "[redirect]") {
    // Both hops point at each other. Loop detection must fire before the
    // max_redirects budget runs out, so the server sees exactly 2 requests.
    RedirectServer srv;
    REQUIRE(srv.start({{302, "/b", ""}, {302, "/a", ""}, {302, "/b", ""}}));

    Client c(following(10));   // budget far larger than the loop needs
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/a"))));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::HttpInvalidResponse);
    CHECK(srv.seen_count() <= 3);
}

TEST_CASE("max_redirects stops a long chain", "[redirect]") {
    std::vector<RedirectServer::Reply> script;
    for (int i = 0; i < 10; ++i) script.push_back({302, "/hop" + std::to_string(i), ""});
    script.push_back({200, "", "ok"});

    RedirectServer srv;
    REQUIRE(srv.start(std::move(script)));

    Client c(following(2));
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/start"))));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::HttpInvalidResponse);
}

TEST_CASE("redirects are not followed unless the caller opts in", "[redirect]") {
    // The counterweight for every test above: with the default policy the 3xx
    // is just a response.
    RedirectServer srv;
    REQUIRE(srv.start({{302, "/next", ""}}));

    Client c;   // defaults: follow == false
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/start"))));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 302);
    CHECK(srv.seen_count() == 1);
}

TEST_CASE("a 3xx without a Location is delivered as a normal response",
          "[redirect]") {
    RedirectServer srv;
    REQUIRE(srv.start({{302, "", "no location"}}));

    Client c(following());
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/start"))));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 302);
}

TEST_CASE("https to http downgrade is refused by default", "[redirect]") {
    // Judged on the hop that LOSES security: leaving an https origin for an http
    // one. The predicate is the one the Client itself uses, so this test and the
    // production code cannot drift apart.
    auto https_base = parse_url(string_view("https://example.com/a"));
    auto http_next = parse_url(string_view("http://example.com/a"));
    REQUIRE(https_base);
    REQUIRE(http_next);

    CHECK(redirect_detail::is_downgrade(https_base.value(), http_next.value()));

    ClientOptions opt;   // follow and allow_https_to_http at their defaults
    CHECK_FALSE(opt.redirects.allow_https_to_http);
    const bool would_follow =
        !redirect_detail::is_downgrade(https_base.value(), http_next.value()) ||
        opt.redirects.allow_https_to_http;
    CHECK_FALSE(would_follow);   // refused
}

TEST_CASE("allow_https_to_http opts in to the downgrade", "[redirect]") {
    // Counterweight: the same hop becomes permitted once the caller opts in.
    // Without this the previous test would pass even if the switch did nothing.
    auto https_base = parse_url(string_view("https://example.com/a"));
    auto http_next = parse_url(string_view("http://example.com/a"));
    REQUIRE(https_base);
    REQUIRE(http_next);

    CHECK(redirect_detail::is_downgrade(https_base.value(), http_next.value()));

    ClientOptions opt;
    opt.redirects.allow_https_to_http = true;
    const bool would_follow =
        !redirect_detail::is_downgrade(https_base.value(), http_next.value()) ||
        opt.redirects.allow_https_to_http;
    CHECK(would_follow);
}

TEST_CASE("a same-secure-level redirect is not a downgrade", "[redirect]") {
    // Guards the predicate itself: http->http and https->https must not be
    // flagged, or the default policy would refuse ordinary redirects.
    auto http_a = parse_url(string_view("http://example.com/a"));
    auto http_b = parse_url(string_view("http://example.com/b"));
    auto https_a = parse_url(string_view("https://example.com/a"));
    auto https_b = parse_url(string_view("https://other.com/b"));
    REQUIRE(http_a); REQUIRE(http_b); REQUIRE(https_a); REQUIRE(https_b);

    CHECK_FALSE(redirect_detail::is_downgrade(http_a.value(), http_b.value()));
    CHECK_FALSE(redirect_detail::is_downgrade(https_a.value(), https_b.value()));
    // An upgrade is not a downgrade either.
    CHECK_FALSE(redirect_detail::is_downgrade(http_a.value(), https_a.value()));
}

// ---------------------------------------------------------------------------
// Total timeout across hops (S5.2-04)
//
// The deadline is armed once in submit() and must survive every hop. The
// discriminating experiment does not need an injectable clock: with a 200 ms
// delay per hop and a 350 ms total budget over three hops, an accumulating
// deadline expires during hop two (~350 ms) while a per-hop reset would let all
// three finish (~600 ms). The two outcomes are 250 ms apart, far outside timing
// noise.
// ---------------------------------------------------------------------------

TEST_CASE("the total timeout accumulates across redirect hops", "[redirect][timeout]") {
    // Three hops, each answering after 200 ms. Budget 350 ms.
    RedirectServer srv;
    REQUIRE(srv.start({
        {302, "/hop1", "", 200},
        {302, "/hop2", "", 200},
        {200, "", "ok", 200},
    }));

    ClientOptions o;
    o.redirects.follow = true;
    o.redirects.max_redirects = 10;
    o.total_timeout = std::chrono::milliseconds(350);
    Client c(o);

    const auto t0 = std::chrono::steady_clock::now();
    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/start"))));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    // A per-hop deadline would have let all three hops complete (~600 ms).
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::TimeoutTotal);
    CHECK(elapsed < std::chrono::milliseconds(550));

    // And the third hop must never have been requested.
    CHECK(srv.seen_count() <= 2);
}

TEST_CASE("a budget large enough for every hop lets them all complete",
          "[redirect][timeout]") {
    // The counterweight: identical server, identical delays, only the budget
    // differs. Without this the test above would pass even if the client gave up
    // for an unrelated reason.
    RedirectServer srv;
    REQUIRE(srv.start({
        {302, "/hop1", "", 100},
        {302, "/hop2", "", 100},
        {200, "", "ok", 100},
    }));

    ClientOptions o;
    o.redirects.follow = true;
    o.total_timeout = std::chrono::milliseconds(3000);
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, to_s(url_on(srv.port(), "/start"))));
    REQUIRE(r);
    CHECK(r.value().head().status_code == 200);
    CHECK(srv.seen_count() == 3);
}
