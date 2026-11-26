// End-to-end Content-Encoding tests through the public Client: a real local
// server, a real gzip body, and the Response's encoding bookkeeping.
//
// The decoder unit tests cover the codecs themselves; this file covers the
// wiring: Accept-Encoding is sent, the head keeps the verbatim header, the body
// arrives decoded, and wire/decode lengths stay distinguishable.

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>

#include <zlib.h>

#include <atomic>
#include <cstdint>
#include <cstring>
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

std::vector<uint8_t> gzip_compress(const std::string& in) {
    z_stream s{};
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return {};
    }
    std::vector<uint8_t> out(deflateBound(&s, static_cast<uLong>(in.size())) + 64);
    s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    s.avail_in = static_cast<uInt>(in.size());
    s.next_out = out.data();
    s.avail_out = static_cast<uInt>(out.size());
    const int rc = deflate(&s, Z_FINISH);
    const size_t produced = out.size() - s.avail_out;
    deflateEnd(&s);
    if (rc != Z_STREAM_END) return {};
    out.resize(produced);
    return out;
}

// Serves one fixed HTTP response and records the request head it saw.
class EncodedServer {
public:
    ~EncodedServer() { stop(); }

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
        if (::listen(s_, 4) != 0) return false;
        th_ = std::thread([this] { serve(); });
        return true;
    }

    void stop() {
        if (stop_.exchange(true)) return;
        if (s_ != kInvalid) { closesock(s_); s_ = kInvalid; }
        if (th_.joinable()) th_.join();
    }

    uint16_t port() const { return port_; }
    std::string request_head() const {
        std::lock_guard<std::mutex> g(mu_);
        return head_;
    }

    void set_full_response(std::string full) {
        std::lock_guard<std::mutex> g(mu_);
        full_ = std::move(full);
    }

private:
    void serve() {
        sock_t c = ::accept(s_, nullptr, nullptr);
        if (c == kInvalid) return;
        char buf[8192];
        int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
        if (n > 0) {
            std::lock_guard<std::mutex> g(mu_);
            head_.assign(buf, static_cast<size_t>(n));
        }
        std::string out;
        {
            std::lock_guard<std::mutex> g(mu_);
            out = full_;
        }
        if (!out.empty()) {
            ::send(c, out.data(), static_cast<int>(out.size()), 0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        closesock(c);
    }

    sock_t s_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::thread th_;
    mutable std::mutex mu_;
    std::string head_;
    std::string full_;
};

const std::string kPayload =
    "content-encoding end to end: the quick brown fox jumps over the lazy dog";

string to_owning(const std::string& s) { return string(s.c_str(), s.size()); }

std::string url_for(uint16_t port) {
    return "http://127.0.0.1:" + std::to_string(port) + "/encoded";
}

} // namespace

TEST_CASE("a gzip response body arrives decoded through the Client",
          "[content][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = gzip_compress(kPayload);
    REQUIRE(!wire.empty());

    EncodedServer srv;
    REQUIRE(srv.start());
    std::string full =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: " + std::to_string(wire.size()) + "\r\n"
        "Connection: close\r\n\r\n";
    full.append(reinterpret_cast<const char*>(wire.data()), wire.size());
    srv.set_full_response(full);

    Client c;
    auto r = c.request_sync(Request(Method::Get, to_owning(url_for(srv.port()))));
    REQUIRE(r);
    const Response& resp = r.value();

    // Body is plain text, and the head still carries the verbatim coding.
    CHECK(std::string(resp.body_text().data(), resp.body_text().size()) == kPayload);
    REQUIRE(resp.head().content_encoding.has_value());
    CHECK(*resp.head().content_encoding == "gzip");

    // The two lengths are distinguishable and both correct.
    CHECK(resp.body_decoded());
    CHECK(resp.wire_body_length().has_value());
    CHECK(*resp.wire_body_length() == wire.size());
    CHECK(resp.decoded_body_length() == kPayload.size());

    // Accept-Encoding was actually advertised.
    const std::string head = srv.request_head();
    CHECK(head.find("accept-encoding") != std::string::npos);
    CHECK(head.find("gzip") != std::string::npos);

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a gzip response body can be kept raw on request",
          "[content][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = gzip_compress(kPayload);
    REQUIRE(!wire.empty());

    EncodedServer srv;
    REQUIRE(srv.start());
    std::string full =
        "HTTP/1.1 200 OK\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: " + std::to_string(wire.size()) + "\r\n"
        "Connection: close\r\n\r\n";
    full.append(reinterpret_cast<const char*>(wire.data()), wire.size());
    srv.set_full_response(full);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));
    req.set_decode_response_body(false);   // caller wants the bytes as sent

    auto r = c.request_sync(req);
    REQUIRE(r);
    const Response& resp = r.value();

    CHECK(resp.body_bytes().size() == wire.size());
    CHECK(std::memcmp(resp.body_bytes().data(), wire.data(), wire.size()) == 0);
    CHECK_FALSE(resp.body_decoded());
    CHECK(resp.head().content_encoding.has_value());
    // Raw mode means no Accept-Encoding was advertised either.
    CHECK(srv.request_head().find("accept-encoding") == std::string::npos);

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a truncated gzip body is an error, not a short body",
          "[content][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    auto wire = gzip_compress(kPayload);
    REQUIRE(wire.size() > 10);
    wire.resize(wire.size() / 2);

    EncodedServer srv;
    REQUIRE(srv.start());
    std::string full =
        "HTTP/1.1 200 OK\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: " + std::to_string(wire.size()) + "\r\n"
        "Connection: close\r\n\r\n";
    full.append(reinterpret_cast<const char*>(wire.data()), wire.size());
    srv.set_full_response(full);

    Client c;
    auto r = c.request_sync(Request(Method::Get, to_owning(url_for(srv.port()))));
    // The HTTP framing completed (Content-Length was honoured), but the coding
    // did not: that is a decoding failure, not a successful short answer.
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::ContentDecodingFailed);

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("a streamed gzip response delivers decoded bytes to the sink",
          "[content][client][gzip]") {
#if MEGOHTTP_HAS_GZIP
    const auto wire = gzip_compress(kPayload);
    REQUIRE(!wire.empty());

    EncodedServer srv;
    REQUIRE(srv.start());
    std::string full =
        "HTTP/1.1 200 OK\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: " + std::to_string(wire.size()) + "\r\n"
        "Connection: close\r\n\r\n";
    full.append(reinterpret_cast<const char*>(wire.data()), wire.size());
    srv.set_full_response(full);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));
    std::string collected;
    bool completed = false;
    auto flow = std::make_shared<Request::BodySinkFlow>();
    req.set_body_sink(
        [&collected](string_view chunk) {
            collected.append(chunk.data(), static_cast<size_t>(chunk.size()));
            return true;
        },
        [&completed](VoidResult) { completed = true; },
        flow);

    auto r = c.request_sync(req);
    REQUIRE(r);
    CHECK(completed);
    // The sink sees plain text, never the compressed bytes.
    CHECK(collected == kPayload);
    CHECK(r.value().head().content_encoding.has_value());

    c.shutdown();
    srv.stop();
#else
    SUCCEED("gzip not compiled in");
#endif
}

TEST_CASE("an unknown content coding is rejected",
          "[content][client][gzip]") {
    EncodedServer srv;
    REQUIRE(srv.start());
    srv.set_full_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Encoding: compress\r\n"
        "Content-Length: 5\r\n"
        "Connection: close\r\n\r\n"
        "hello");

    Client c;
    auto r = c.request_sync(Request(Method::Get, to_owning(url_for(srv.port()))));
    REQUIRE(!r);
    CHECK(r.error().code() == ErrorCode::ContentEncodingUnsupported);

    c.shutdown();
    srv.stop();
}
