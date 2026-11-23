// End-to-end request body compression tests (task book 7.3).
//
// A real local server reads the request head, reads exactly Content-Length
// bytes, and decodes the body with zlib/Brotli directly -- not through the
// library's decoder -- so an encoder bug cannot be masked by a matching decoder
// bug. It then answers with a configurable response, which lets the redirect and
// retry cases observe both attempts.

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#if MEGOHTTP_HAS_ZLIB
#include <zlib.h>
#endif
#if MEGOHTTP_HAS_BROTLI
#include <brotli/decode.h>
#endif

#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
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
    size_t b = 0;
    size_t e = s.size();
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

#if MEGOHTTP_HAS_ZLIB
// Independent decoder: 31 = gzip wrapper, 15 = zlib wrapper.
bool zlib_decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out, int bits) {
    z_stream s{};
    if (inflateInit2(&s, bits) != Z_OK) return false;
    struct EndGuard {
        z_stream* p;
        ~EndGuard() { if (p->state) inflateEnd(p); }
    } guard{&s};

    size_t offset = 0;
    uint8_t buf[4096];
    for (;;) {
        if (s.avail_in == 0 && offset < in.size()) {
            const size_t take = (std::min)(in.size() - offset,
                static_cast<size_t>(0x7fffffff));
            s.next_in = const_cast<Bytef*>(in.data() + offset);
            s.avail_in = static_cast<uInt>(take);
            offset += take;
        }
        s.next_out = buf;
        s.avail_out = sizeof buf;
        const int rc = inflate(&s, Z_NO_FLUSH);
        const size_t produced = sizeof buf - s.avail_out;
        out.insert(out.end(), buf, buf + produced);
        if (rc == Z_STREAM_END) return true;
        if (rc != Z_OK && rc != Z_BUF_ERROR) return false;
        if (produced == 0 && s.avail_in == 0 && offset >= in.size()) return false;
    }
}
#else
bool zlib_decode(const std::vector<uint8_t>&, std::vector<uint8_t>&, int) {
    return false;
}
#endif

#if MEGOHTTP_HAS_BROTLI
bool brotli_decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    std::vector<uint8_t> tmp(in.size() * 64 + 4096);
    size_t produced = tmp.size();
    const BrotliDecoderResult rc =
        BrotliDecoderDecompress(in.size(), in.data(), &produced, tmp.data());
    if (rc != BROTLI_DECODER_RESULT_SUCCESS) return false;
    out.assign(tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(produced));
    return true;
}
#else
bool brotli_decode(const std::vector<uint8_t>&, std::vector<uint8_t>&) {
    return false;
}
#endif

bool decode_body(const std::string& coding, const std::vector<uint8_t>& in,
                 std::vector<uint8_t>& out) {
    if (coding.empty()) {
        out = in;
        return true;
    }
    if (coding == "gzip") return zlib_decode(in, out, 31);
    if (coding == "deflate") return zlib_decode(in, out, 15);
    if (coding == "br") return brotli_decode(in, out);
    return false;
}

// Accepts one connection per request, records what it saw, and answers with the
// next queued response (or a 200 with "ok"). It deliberately reads the body by
// Content-Length so a wrong length shows up as truncation rather than luck.
class CaptureServer {
public:
    struct Captured {
        std::string head;               // request line + headers, no CRLFCRLF
        std::string method;
        std::string target;
        std::string coding;             // lowercased Content-Encoding, empty = none
        std::vector<uint8_t> body;      // bytes as they arrived on the wire
        std::vector<uint8_t> decoded;
        bool decode_ok{true};
    };

    ~CaptureServer() { stop(); }

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

    void push_response(std::string response) {
        std::lock_guard<std::mutex> g(mu_);
        responses_.push_back(std::move(response));
    }

    size_t accepts() const { return accepts_.load(); }

    std::vector<Captured> captured() const {
        std::lock_guard<std::mutex> g(mu_);
        return captured_;
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
        std::string raw;
        char buf[4096];
        size_t head_end = std::string::npos;
        while ((head_end = raw.find("\r\n\r\n")) == std::string::npos) {
            const int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
            if (n <= 0) { closesock(c); return; }
            raw.append(buf, static_cast<size_t>(n));
            if (raw.size() > 1024 * 1024) { closesock(c); return; }
        }

        const std::string head = raw.substr(0, head_end);
        std::vector<uint8_t> body(
            raw.begin() + static_cast<std::ptrdiff_t>(head_end + 4), raw.end());

        // Expect: 100-continue must be answered before the body is expected.
        if (lowercase(trim(header_value(head, "expect"))) == "100-continue") {
            (void)send_all(c, "HTTP/1.1 100 Continue\r\n\r\n");
        }

        const std::string cl = trim(header_value(head, "content-length"));
        size_t want = 0;
        if (!cl.empty()) {
            want = static_cast<size_t>(std::strtoull(cl.c_str(), nullptr, 10));
        }
        while (body.size() < want) {
            const int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
            if (n <= 0) break;
            body.insert(body.end(), buf, buf + n);
        }
        if (body.size() > want) body.resize(want);

        Captured cap;
        cap.head = head;
        cap.body = body;
        cap.coding = lowercase(trim(header_value(head, "content-encoding")));
        const size_t sp1 = head.find(' ');
        const size_t sp2 = (sp1 == std::string::npos)
                               ? std::string::npos
                               : head.find(' ', sp1 + 1);
        if (sp1 != std::string::npos && sp2 != std::string::npos) {
            cap.method = head.substr(0, sp1);
            cap.target = head.substr(sp1 + 1, sp2 - sp1 - 1);
        }
        cap.decode_ok = decode_body(cap.coding, body, cap.decoded);
        {
            std::lock_guard<std::mutex> g(mu_);
            captured_.push_back(std::move(cap));
        }

        (void)send_all(c, pop_response());
        closesock(c);
    }

    std::string pop_response() {
        std::lock_guard<std::mutex> g(mu_);
        if (!responses_.empty()) {
            std::string r = std::move(responses_.front());
            responses_.pop_front();
            return r;
        }
        return default_response_;
    }

    sock_t s_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<size_t> accepts_{0};
    std::thread th_;
    mutable std::mutex mu_;
    std::deque<std::string> responses_;
    std::vector<Captured> captured_;
    std::string default_response_{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"};
};

std::string payload() {
    static const std::string unit =
        "request body compression payload: 0123456789 abcdefghijklmnopqrstuvwxyz\n";
    std::string p;
    while (p.size() < 4096) p += unit;
    return p;
}

std::vector<uint8_t> payload_bytes() {
    const std::string p = payload();
    return std::vector<uint8_t>(p.begin(), p.end());
}

string to_owning(const std::string& s) { return string(s.c_str(), s.size()); }

std::string url_for(uint16_t port, const char* path = "/upload") {
    return "http://127.0.0.1:" + std::to_string(port) + path;
}

Request post_to(uint16_t port) {
    return Request(Method::Post, to_owning(url_for(port)));
}

std::vector<uint8_t> expected_body() { return payload_bytes(); }

} // namespace

TEST_CASE("request body compression is off by default", "[request-compression][client]") {
    CaptureServer srv;
    REQUIRE(srv.start());

    Client c;
    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].method == "POST");
    CHECK(recs[0].coding.empty());
    CHECK(lowercase(recs[0].head).find("content-encoding") == std::string::npos);
    CHECK(recs[0].body == expected_body());
    CHECK(trim(header_value(recs[0].head, "content-length")) ==
          std::to_string(recs[0].body.size()));

    c.shutdown();
    srv.stop();
}

TEST_CASE("a gzip request body is compressed and Content-Length matches it",
          "[request-compression][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    CaptureServer srv;
    REQUIRE(srv.start());

    Client c;
    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].coding == "gzip");
    CHECK(lowercase(recs[0].head).find("content-encoding: gzip") != std::string::npos);
    REQUIRE(recs[0].decode_ok);
    CHECK(recs[0].decoded == expected_body());
    // The payload is repetitive, so a correct gzip stream is smaller.
    CHECK(recs[0].body.size() < payload().size());
    CHECK(trim(header_value(recs[0].head, "content-length")) ==
          std::to_string(recs[0].body.size()));

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a deflate request body uses the zlib wrapper",
          "[request-compression][client][deflate]") {
#if MEGOHTTP_HAS_ZLIB
    CaptureServer srv;
    REQUIRE(srv.start());

    Client c;
    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Deflate);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].coding == "deflate");
    REQUIRE(recs[0].decode_ok);
    CHECK(recs[0].decoded == expected_body());
    CHECK(recs[0].body.size() < payload().size());
    CHECK(trim(header_value(recs[0].head, "content-length")) ==
          std::to_string(recs[0].body.size()));

    c.shutdown();
    srv.stop();
#else
    SUCCEED("zlib not compiled in");
#endif
}

TEST_CASE("a brotli request body is compressed and decoded by the server",
          "[request-compression][client][brotli]") {
#if MEGOHTTP_HAS_BROTLI && MEGOHTTP_HAS_BROTLI_ENCODER
    CaptureServer srv;
    REQUIRE(srv.start());

    Client c;
    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Brotli);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].coding == "br");
    REQUIRE(recs[0].decode_ok);
    CHECK(recs[0].decoded == expected_body());
    CHECK(recs[0].body.size() < payload().size());
    CHECK(trim(header_value(recs[0].head, "content-length")) ==
          std::to_string(recs[0].body.size()));

    c.shutdown();
    srv.stop();
#else
    SUCCEED("brotli encoder not compiled in");
#endif
}

TEST_CASE("an explicitly empty body is not compressed", "[request-compression][client]") {
    CaptureServer srv;
    REQUIRE(srv.start());

    Client c;
    Request req = post_to(srv.port());
    req.set_body(string_view());
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].coding.empty());
    CHECK(recs[0].body.empty());
    CHECK(trim(header_value(recs[0].head, "content-length")) == "0");

    c.shutdown();
    srv.stop();
}

TEST_CASE("a request with no body gets no Content-Encoding", "[request-compression][client]") {
    CaptureServer srv;
    REQUIRE(srv.start());

    Client c;
    Request req = post_to(srv.port());
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].coding.empty());
    CHECK(recs[0].body.empty());
    CHECK(trim(header_value(recs[0].head, "content-length")).empty());

    c.shutdown();
    srv.stop();
}

TEST_CASE("caller-supplied framing headers are rejected with compression",
          "[request-compression][client]") {
    CaptureServer srv;
    REQUIRE(srv.start());
    Client c;

    struct Case { const char* name; const char* value; };
    const Case cases[] = {
        {"content-length", "7"},
        {"transfer-encoding", "chunked"},
        {"content-encoding", "identity"},
    };

    for (const auto& item : cases) {
        Request req = post_to(srv.port());
        req.set_body(string_view(payload().data(), payload().size()));
        req.set_compress_body(Request::Compression::Gzip);
        req.headers().set(item.name, item.value);

        auto r = c.request_sync(req);
        REQUIRE(!r);
        CHECK(r.error().code() == ErrorCode::InvalidArgument);
        CHECK(r.error().phase() == ErrorPhase::Send);
    }

    // Synchronous rejection: no request was ever accepted, so no connection.
    CHECK(srv.accepts() == 0);

    c.shutdown();
    srv.stop();
}

TEST_CASE("a streaming body cannot be compressed", "[request-compression][client]") {
    CaptureServer srv;
    REQUIRE(srv.start());
    Client c;

    Request req = post_to(srv.port());
    req.set_body_source([]() -> Result<std::pair<string_view, bool>> {
        return std::make_pair(string_view{}, true);
    });
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::NotImplemented);
    CHECK(r.error().phase() == ErrorPhase::Send);
    CHECK(srv.accepts() == 0);

    c.shutdown();
    srv.stop();
}

TEST_CASE("Expect: 100-continue holds a compressed body until the interim response",
          "[request-compression][client]") {
#if MEGOHTTP_HAS_GZIP
    CaptureServer srv;
    REQUIRE(srv.start());

    ClientOptions opts;
    opts.expect_continue = true;
    Client c(opts);

    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 1);
    CHECK(recs[0].coding == "gzip");
    REQUIRE(recs[0].decode_ok);
    CHECK(recs[0].decoded == expected_body());
    CHECK(lowercase(recs[0].head).find("expect: 100-continue") != std::string::npos);

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a retried compressed body is encoded once and reused",
          "[request-compression][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    CaptureServer srv;
    REQUIRE(srv.start());
    srv.push_response(
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Length: 0\r\n"
        "Retry-After: 0\r\n"
        "Connection: close\r\n\r\n");

    ClientOptions opts;
    opts.retry.max_retries = 1;
    opts.retry.base_delay = std::chrono::milliseconds(1);
    opts.retry.max_delay = std::chrono::milliseconds(1);
    opts.retry.jitter = false;
    opts.retry.retry_non_idempotent = true;
    Client c(opts);

    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 2);
    for (const auto& rec : recs) {
        CHECK(rec.method == "POST");
        CHECK(rec.coding == "gzip");
        REQUIRE(rec.decode_ok);
        CHECK(rec.decoded == expected_body());
    }
    // Same logical request, same encoded bytes: no per-attempt re-encoding.
    CHECK(recs[0].body == recs[1].body);

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a 307 redirect re-sends the compressed body unchanged",
          "[request-compression][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    CaptureServer srv;
    REQUIRE(srv.start());
    srv.push_response(
        "HTTP/1.1 307 Temporary Redirect\r\n"
        "Location: " + url_for(srv.port(), "/next") + "\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n");

    ClientOptions opts;
    opts.redirects.follow = true;
    Client c(opts);

    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 2);
    CHECK(recs[0].method == "POST");
    CHECK(recs[1].method == "POST");
    CHECK(recs[1].target == "/next");
    for (const auto& rec : recs) {
        CHECK(rec.coding == "gzip");
        REQUIRE(rec.decode_ok);
        CHECK(rec.decoded == expected_body());
    }
    CHECK(recs[0].body == recs[1].body);

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a 303 redirect drops the body and the Content-Encoding with it",
          "[request-compression][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    CaptureServer srv;
    REQUIRE(srv.start());
    srv.push_response(
        "HTTP/1.1 303 See Other\r\n"
        "Location: " + url_for(srv.port(), "/after") + "\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n");

    ClientOptions opts;
    opts.redirects.follow = true;
    Client c(opts);

    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(r);

    const auto recs = srv.captured();
    REQUIRE(recs.size() == 2);
    CHECK(recs[0].method == "POST");
    CHECK(recs[0].coding == "gzip");
    CHECK(recs[1].method == "GET");
    CHECK(recs[1].target == "/after");
    CHECK(recs[1].coding.empty());
    CHECK(recs[1].body.empty());
    CHECK(lowercase(recs[1].head).find("content-encoding") == std::string::npos);
    CHECK(trim(header_value(recs[1].head, "content-length")).empty());

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a coding this build cannot produce is a synchronous error",
          "[request-compression][client]") {
    CaptureServer srv;
    REQUIRE(srv.start());
    Client c;

#if !MEGOHTTP_HAS_GZIP
    Request req = post_to(srv.port());
    req.set_body(string_view(payload().data(), payload().size()));
    req.set_compress_body(Request::Compression::Gzip);

    auto r = c.request_sync(req);
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::ContentEncodingUnsupported);
    CHECK(r.error().phase() == ErrorPhase::Send);
    CHECK(srv.accepts() == 0);
#else
    SUCCEED("gzip is compiled in");
#endif

    c.shutdown();
    srv.stop();
}
