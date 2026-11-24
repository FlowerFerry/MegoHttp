// Request trailer sending tests (S3.1-11; task book 7 "trailer 的读取及受控发送").
//
// A local server parses the chunked upload itself (chunk sizes, data, the zero
// chunk and trailer lines), so the assertions are about bytes on the wire, not
// about the library agreeing with itself.

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace megohttp;

namespace {

#if defined(_WIN32)
using sock_t = SOCKET;
constexpr sock_t kInvalid = INVALID_SOCKET;
inline void closesock(sock_t s) { ::closesocket(s); }
inline void ensure_wsa() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA w{};
        WSAStartup(MAKEWORD(2, 2), &w);
    });
}
#else
using sock_t = int;
constexpr sock_t kInvalid = -1;
inline void closesock(sock_t s) { ::close(s); }
inline void ensure_wsa() {}
#endif

std::string lowercase(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(b, e - b);
}

std::string header_value(const std::string& head, const std::string& name) {
    const std::string lower_head = lowercase(head);
    const std::string needle = "\r\n" + lowercase(name) + ":";
    size_t p = lower_head.find(needle);
    if (p == std::string::npos) return {};
    p += needle.size();
    size_t e = lower_head.find("\r\n", p);
    if (e == std::string::npos) e = head.size();
    return head.substr(p, e - p);
}

// Parses a chunked request: head, data chunks, zero chunk, trailer lines.
class ChunkedUploadServer {
public:
    struct Record {
        std::string head;
        std::string body;
        std::vector<std::pair<std::string, std::string>> trailers;
        bool complete{false};
        bool finished{false};   // the connection was fully handled
    };

    ~ChunkedUploadServer() { stop(); }

    bool start() {
        ensure_wsa();
        s_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s_ == kInvalid) return false;
        int yes = 1;
        ::setsockopt(s_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&yes), sizeof yes);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(s_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        socklen_t len = sizeof a;
        ::getsockname(s_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        if (::listen(s_, 8) != 0) return false;
        th_ = std::thread([this] { serve(); });
        return true;
    }

    void stop() {
        if (stop_.exchange(true)) return;
        if (s_ != kInvalid) {
            closesock(s_);
            s_ = kInvalid;
        }
        if (th_.joinable()) th_.join();
    }

    uint16_t port() const { return port_; }
    size_t accepts() const { return accepts_.load(); }

    Record record() const {
        std::lock_guard<std::mutex> g(mu_);
        return record_;
    }

    bool wait_finished(int timeout_ms) {
        std::unique_lock<std::mutex> lk(mu_);
        return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                            [&] { return record_.finished; });
    }

private:
    static bool send_all(sock_t c, const std::string& data) {
        size_t off = 0;
        while (off < data.size()) {
            const int n = static_cast<int>(
                ::send(c, data.data() + off,
                       static_cast<int>(data.size() - off), 0));
            if (n <= 0) return false;
            off += static_cast<size_t>(n);
        }
        return true;
    }

    void serve() {
        while (!stop_.load()) {
            sock_t c = ::accept(s_, nullptr, nullptr);
            if (c == kInvalid) break;
            ++accepts_;
            handle(c);
        }
    }

    void handle(sock_t c) {
        std::string buf;
        char tmp[4096];
        auto more = [&]() -> bool {
            const int n = static_cast<int>(::recv(c, tmp, sizeof tmp, 0));
            if (n <= 0) return false;
            buf.append(tmp, static_cast<size_t>(n));
            return true;
        };

        // Head.
        size_t head_end = std::string::npos;
        while ((head_end = buf.find("\r\n\r\n")) == std::string::npos) {
            if (!more()) { closesock(c); return; }
            if (buf.size() > 1024 * 1024) { closesock(c); return; }
        }
        const std::string head = buf.substr(0, head_end);
        buf.erase(0, head_end + 4);
        {
            std::lock_guard<std::mutex> g(mu_);
            record_.head = head;
        }

        if (lowercase(trim(header_value(head, "expect"))) == "100-continue") {
            (void)send_all(c, "HTTP/1.1 100 Continue\r\n\r\n");
        }

        Record rec;
        rec.head = head;

        // Chunks.
        for (;;) {
            size_t eol = buf.find("\r\n");
            while (eol == std::string::npos) {
                if (!more()) { rec.complete = false; publish(rec); closesock(c); return; }
                eol = buf.find("\r\n");
            }
            std::string size_line = buf.substr(0, eol);
            buf.erase(0, eol + 2);

            const size_t semi = size_line.find(';');
            if (semi != std::string::npos) size_line.resize(semi);
            const size_t chunk_size = static_cast<size_t>(
                std::strtoull(size_line.c_str(), nullptr, 16));

            if (chunk_size == 0) {
                // Trailer section: field lines until an empty line.
                for (;;) {
                    size_t e = buf.find("\r\n");
                    while (e == std::string::npos) {
                        if (!more()) { rec.complete = false; publish(rec); closesock(c); return; }
                        e = buf.find("\r\n");
                    }
                    std::string line = buf.substr(0, e);
                    buf.erase(0, e + 2);
                    if (line.empty()) {
                        rec.complete = true;
                        break;
                    }
                    const size_t colon = line.find(':');
                    if (colon == std::string::npos) {
                        rec.complete = false;
                        publish(rec);
                        closesock(c);
                        return;
                    }
                    rec.trailers.emplace_back(trim(line.substr(0, colon)),
                                              trim(line.substr(colon + 1)));
                }
                break;
            }

            while (buf.size() < chunk_size + 2) {
                if (!more()) { rec.complete = false; publish(rec); closesock(c); return; }
            }
            if (buf[chunk_size] != '\r' || buf[chunk_size + 1] != '\n') {
                rec.complete = false;
                publish(rec);
                closesock(c);
                return;
            }
            rec.body.append(buf.data(), chunk_size);
            buf.erase(0, chunk_size + 2);
        }

        publish(rec);
        (void)send_all(c,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        closesock(c);
    }

    void publish(const Record& r) {
        std::lock_guard<std::mutex> g(mu_);
        record_ = r;
        record_.finished = true;
        cv_.notify_all();
    }

    sock_t s_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<size_t> accepts_{0};
    std::thread th_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    Record record_;
};

string to_owning(const std::string& s) { return string(s.c_str(), s.size()); }

std::string url_for(uint16_t port) {
    return "http://127.0.0.1:" + std::to_string(port) + "/upload";
}

Request post_to(uint16_t port) {
    return Request(Method::Post, to_owning(url_for(port)));
}

// Emits `payload` in one chunk and then EOF. The shared flag keeps the literal
// view valid and makes the source single-use.
Request::BodySource one_chunk(const std::shared_ptr<bool>& sent,
                              const char* payload) {
    return [sent, payload]() -> Result<std::pair<string_view, bool>> {
        if (*sent) return std::make_pair(string_view{}, true);
        *sent = true;
        return std::make_pair(string_view(payload), false);
    };
}

bool has_trailer(const ChunkedUploadServer::Record& rec,
                 const std::string& name, const std::string& value) {
    for (const auto& f : rec.trailers) {
        if (lowercase(f.first) == lowercase(name) && f.second == value) return true;
    }
    return false;
}

int count_commas(const std::string& s) {
    int n = 0;
    for (char c : s) if (c == ',') ++n;
    return n;
}

} // namespace

TEST_CASE("trailer names are parsed and forbidden fields are rejected",
          "[trailer][http]") {
    auto names = chunked::parse_trailer_names(" X-Sum , x-sum, X-Checksum ");
    REQUIRE(names);
    REQUIRE(names.value().size() == 2);
    CHECK(names.value()[0] == "X-Sum");
    CHECK(names.value()[1] == "X-Checksum");

    CHECK(chunked::is_forbidden_trailer_name("Content-Length"));
    CHECK(chunked::is_forbidden_trailer_name("transfer-encoding"));
    CHECK(chunked::is_forbidden_trailer_name("Host"));
    CHECK_FALSE(chunked::is_forbidden_trailer_name("X-Sum"));
}

TEST_CASE("static request trailers are declared and sent in the terminating chunk",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    Client c;
    auto sent = std::make_shared<bool>(false);
    Request req = post_to(srv.port());
    req.set_body_source(one_chunk(sent, "hello"));
    Headers tr;
    tr.add("X-Sum", "42");
    req.set_trailers(tr);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto rec = srv.record();
    REQUIRE(rec.complete);
    CHECK(rec.body == "hello");
    REQUIRE(rec.trailers.size() == 1);
    CHECK(has_trailer(rec, "X-Sum", "42"));
    CHECK(lowercase(rec.head).find("trailer: x-sum") != std::string::npos);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a dynamic trailer source runs at EOF and can describe the body",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    Client c;
    auto sent = std::make_shared<bool>(false);
    auto bytes_seen = std::make_shared<size_t>(0);

    Request req = post_to(srv.port());
    req.set_body_source([sent, bytes_seen]() -> Result<std::pair<string_view, bool>> {
        if (*sent) return std::make_pair(string_view{}, true);
        *sent = true;
        *bytes_seen = 5;
        return std::make_pair(string_view("hello"), false);
    });
    // The dynamic name must be announced before the head is written.
    req.headers().set("trailer", "X-Body-Length");
    req.set_trailer_source([bytes_seen]() -> Result<Headers> {
        Headers h;
        const string value = format("{}", *bytes_seen);
        h.add("X-Body-Length", to_view(value));
        return h;
    });

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto rec = srv.record();
    REQUIRE(rec.complete);
    CHECK(has_trailer(rec, "X-Body-Length", "5"));
    CHECK(lowercase(rec.head).find("trailer: x-body-length") != std::string::npos);

    c.shutdown();
    srv.stop();
}

TEST_CASE("static and dynamic trailers are merged in order",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    Client c;
    auto sent = std::make_shared<bool>(false);
    Request req = post_to(srv.port());
    req.set_body_source(one_chunk(sent, "data"));
    Headers tr;
    tr.add("X-Static", "1");
    req.set_trailers(tr);
    req.headers().set("trailer", "X-Static, X-Dynamic");
    req.set_trailer_source([]() -> Result<Headers> {
        Headers h;
        h.add("X-Dynamic", "2");
        return h;
    });

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto rec = srv.record();
    REQUIRE(rec.complete);
    CHECK(has_trailer(rec, "X-Static", "1"));
    CHECK(has_trailer(rec, "X-Dynamic", "2"));
    // The declaration is the union, without repeating X-Static.
    const std::string decl = trim(header_value(rec.head, "trailer"));
    CHECK(count_commas(decl) == 1);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a chunked request without trailers keeps the plain terminator",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    Client c;
    auto sent = std::make_shared<bool>(false);
    Request req = post_to(srv.port());
    req.set_body_source(one_chunk(sent, "plain"));

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto rec = srv.record();
    REQUIRE(rec.complete);
    CHECK(rec.body == "plain");
    CHECK(rec.trailers.empty());
    CHECK(lowercase(rec.head).find("\r\ntrailer:") == std::string::npos);

    c.shutdown();
    srv.stop();
}

TEST_CASE("buffered bodies cannot carry trailers", "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());
    Client c;

    Request req = post_to(srv.port());
    req.set_body(string_view("hello"));
    Headers tr;
    tr.add("X-Sum", "42");
    req.set_trailers(tr);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::InvalidArgument);
    CHECK(r.error().phase() == ErrorPhase::Send);
    CHECK(srv.accepts() == 0);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a forbidden trailer field is rejected before connecting",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());
    Client c;

    Request req = post_to(srv.port());
    auto sent = std::make_shared<bool>(false);
    req.set_body_source(one_chunk(sent, "hello"));
    Headers tr;
    tr.add("Content-Length", "5");
    req.set_trailers(tr);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::InvalidArgument);
    CHECK(srv.accepts() == 0);

    c.shutdown();
    srv.stop();
}

TEST_CASE("trailer values are checked for CRLF injection",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());
    Client c;

    Request req = post_to(srv.port());
    auto sent = std::make_shared<bool>(false);
    req.set_body_source(one_chunk(sent, "hello"));
    Headers tr;
    tr.add("X-Evil", "a\r\nInjected: yes");
    req.set_trailers(tr);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::InvalidArgument);
    CHECK(srv.accepts() == 0);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a dynamic trailer that was not declared fails the request",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    Client c;
    auto sent = std::make_shared<bool>(false);
    Request req = post_to(srv.port());
    req.set_body_source(one_chunk(sent, "hello"));
    req.set_trailer_source([]() -> Result<Headers> {
        Headers h;
        h.add("X-Undeclared", "1");
        return h;
    });

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::InvalidArgument);
    CHECK(r.error().phase() == ErrorPhase::Send);

    // The body was sent, but no terminating chunk/trailer followed.
    REQUIRE(srv.wait_finished(3000));
    const auto rec = srv.record();
    CHECK_FALSE(rec.complete);
    CHECK(rec.trailers.empty());

    c.shutdown();
    srv.stop();
}

TEST_CASE("a trailer source error is reported and sends no trailer",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    Client c;
    auto sent = std::make_shared<bool>(false);
    Request req = post_to(srv.port());
    req.set_body_source(one_chunk(sent, "hello"));
    req.headers().set("trailer", "X-Sum");
    req.set_trailer_source([]() -> Result<Headers> {
        return Error{ErrorCode::Unknown, ErrorPhase::None,
                     string("checksum failed")};
    });

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::Unknown);
    CHECK(r.error().phase() == ErrorPhase::Send);

    REQUIRE(srv.wait_finished(3000));
    const auto rec = srv.record();
    CHECK_FALSE(rec.complete);
    CHECK(rec.trailers.empty());

    c.shutdown();
    srv.stop();
}

TEST_CASE("request trailer limits are enforced", "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    ClientOptions opts;
    opts.max_request_trailer_count = 1;
    Client c(opts);

    Request req = post_to(srv.port());
    auto sent = std::make_shared<bool>(false);
    req.set_body_source(one_chunk(sent, "hello"));
    Headers tr;
    tr.add("X-A", "1");
    tr.add("X-B", "2");
    req.set_trailers(tr);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::InvalidArgument);
    CHECK(srv.accepts() == 0);

    c.shutdown();
    srv.stop();
}

TEST_CASE("Expect: 100-continue still sends trailers after the body",
          "[trailer][client]") {
    ChunkedUploadServer srv;
    REQUIRE(srv.start());

    ClientOptions opts;
    opts.expect_continue = true;
    Client c(opts);

    auto sent = std::make_shared<bool>(false);
    Request req = post_to(srv.port());
    req.set_body_source(one_chunk(sent, "hello"));
    Headers tr;
    tr.add("X-Sum", "42");
    req.set_trailers(tr);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto rec = srv.record();
    REQUIRE(rec.complete);
    CHECK(rec.body == "hello");
    CHECK(has_trailer(rec, "X-Sum", "42"));
    CHECK(lowercase(rec.head).find("expect: 100-continue") != std::string::npos);

    c.shutdown();
    srv.stop();
}
