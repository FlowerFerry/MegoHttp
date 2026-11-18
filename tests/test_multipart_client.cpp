// S5.7-01: multipart response integration through the public Client API.
//
// Verifies:
// - multipart sink receives part events via a local HTTP server
// - Content-Encoding (gzip) is decoded before multipart parsing
// - pool reuse is blocked when multipart is truncated
// - on_error fires on truncation, not on_complete

#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>
#include <megohttp/multipart_sink.hpp>

#if MEGOHTTP_HAS_ZLIB
#include <zlib.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
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
    std::call_once(once, [] { WSADATA w{}; WSAStartup(MAKEWORD(2, 2), &w); });
}
#else
using sock_t = int;
constexpr sock_t kInvalid = -1;
inline void closesock(sock_t s) { ::close(s); }
inline void ensure_wsa() {}
#endif

#if MEGOHTTP_HAS_ZLIB
std::vector<uint8_t> gzip_compress(const std::string& in) {
    z_stream s{};
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) return {};
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
#endif // MEGOHTTP_HAS_ZLIB

// Serves an HTTP response with the given raw bytes (possibly gzipped).
// Keep-alive: it answers every request on a connection until the client closes,
// and counts accepts so a test can prove whether the connection was REUSED.
class MultipartServer {
public:
    ~MultipartServer() { stop(); }

    // send_cl: if true, send exact Content-Length and Connection: keep-alive.
    //          if false, no Content-Length, Connection: close, close after sending body.
    // chunk_delay_ms: if > 0, the body is written in two halves with this pause
    //          between them. Needed by the backpressure test: a body that
    //          arrives in one read never gives the read loop a chance to stop.
    bool start(const std::string& content_type, const std::string& body,
               bool gzip_body = false, bool send_cl = true, int chunk_delay_ms = 0) {
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

        std::string body_data = body;
        std::string enc;
#if MEGOHTTP_HAS_ZLIB
        if (gzip_body) {
            auto gz = gzip_compress(body);
            if (gz.empty()) return false;
            body_data.assign(reinterpret_cast<const char*>(gz.data()), gz.size());
            enc = "Content-Encoding: gzip\r\n";
        }
#else
        (void)gzip_body;   // no zlib: the gzip fixture cannot be produced
#endif
        if (send_cl) {
            resp_ =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: " + content_type + "\r\n" +
                enc +
                "Content-Length: " + std::to_string(body_data.size()) + "\r\n"
                "Connection: keep-alive\r\n"
                "\r\n" + body_data;
        } else {
            resp_no_cl_ =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: " + content_type + "\r\n" +
                enc +
                "Connection: close\r\n"
                "\r\n" + body_data;
        }

        chunk_delay_ms_ = chunk_delay_ms;

        th_ = std::thread([this, send_cl]() { run(send_cl); });
        return true;
    }

    uint16_t port() const { return port_; }
    int requests() const { return reqs_.load(); }
    int accepts() const { return accepts_.load(); }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (s_ != kInvalid) { closesock(s_); s_ = kInvalid; }
        if (th_.joinable()) th_.join();
    }

private:
    void run(bool send_cl) {
        while (!stopped_.load()) {
            sock_t c = ::accept(s_, nullptr, nullptr);
            if (c == kInvalid) return;
            accepts_.fetch_add(1);
            std::thread([this, c, send_cl]() { serve(c, send_cl); }).detach();
        }
    }

    void serve(sock_t c, bool send_cl) {
        while (!stopped_.load()) {
            std::string head;
            char buf[4096];
            while (head.find("\r\n\r\n") == std::string::npos) {
                int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
                if (n <= 0) { closesock(c); return; }
                head.append(buf, n);
            }
            reqs_.fetch_add(1);
            const std::string& r = send_cl ? resp_ : resp_no_cl_;
            if (chunk_delay_ms_ > 0) {
                // Split right after the response head so the first body read
                // carries only the beginning of the multipart message.
                const size_t hdr = r.find("\r\n\r\n");
                const size_t split = hdr == std::string::npos ? r.size() : hdr + 4;
                if (::send(c, r.data(), static_cast<int>(split), 0) <= 0) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(chunk_delay_ms_));
                if (split < r.size() &&
                    ::send(c, r.data() + split, static_cast<int>(r.size() - split), 0) <= 0) break;
            } else {
                if (::send(c, r.data(), static_cast<int>(r.size()), 0) <= 0) break;
            }
            // Close-delimited framing: the response ends when the connection
            // does, so it must actually be closed. Holding it open would make
            // the client wait for an EOF that never arrives.
            if (!send_cl) break;
        }
        closesock(c);
    }

    sock_t s_{kInvalid};
    uint16_t port_{0};
    std::string resp_;
    std::string resp_no_cl_;
    std::atomic<bool> stopped_{false};
    std::atomic<int> reqs_{0};
    std::atomic<int> accepts_{0};
    int chunk_delay_ms_{0};
    std::thread th_;
};

struct MockMultipartSink : MultipartSink {
    std::vector<MultipartPartHead> part_heads;
    std::vector<std::vector<uint8_t>> part_data;
    std::vector<size_t> part_sizes;
    int parts_started{0};
    int parts_ended{0};
    int complete_count{0};
    bool error_fired{false};
    Error last_error{};

    void on_part_begin(const MultipartPartHead& head) override {
        ++parts_started;
        MultipartPartHead copy;
        copy.headers = head.headers;
        copy.index = head.index;
        part_heads.push_back(std::move(copy));
    }

    bool on_part_data(const uint8_t* data, size_t size) override {
        part_data.emplace_back(data, data + size);
        part_sizes.push_back(size);
        return true;
    }

    void on_part_end() override { ++parts_ended; }
    void on_complete() override { ++complete_count; }
    void on_error(const Error& error) override {
        error_fired = true;
        last_error = error;
    }
};

std::string mp_mixed() {
    return "--b1\r\nContent-Type: text/plain\r\n\r\npart one\r\n"
           "--b1\r\nContent-Type: text/plain\r\n\r\npart two\r\n"
           "--b1--\r\n";
}

} // namespace

TEST_CASE("Client delivers multipart parts via MultipartSink", "[s57][multipart][client]") {
    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=b1", mp_mixed()));

    Client c;
    Request req(Method::Get,
        string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    auto sink = std::make_shared<MockMultipartSink>();
    req.set_multipart_sink(sink);

    std::atomic<int> done{0};
    c.request(req, [&](Result<Response> r) {
        CHECK(r.has_value());
        CHECK(r.value().head().status_code == 200);
        CHECK(r.value().body_is_buffered() == false);
        done.store(1);
    });

    // Wait for completion
    for (int i = 0; i < 200 && done.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    CHECK(done.load() == 1);
    CHECK(sink->parts_started == 2);
    CHECK(sink->parts_ended == 2);
    CHECK(sink->complete_count == 1);
    CHECK(!sink->error_fired);
    CHECK(sink->part_data.size() == 2);
    CHECK(std::string(sink->part_data[0].begin(), sink->part_data[0].end()) == "part one");
    CHECK(std::string(sink->part_data[1].begin(), sink->part_data[1].end()) == "part two");
}

#if MEGOHTTP_HAS_ZLIB
TEST_CASE("Client parses gzipped multipart response", "[s57][multipart][gzip]") {
    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=b1", mp_mixed(), true));

    Client c;
    Request req(Method::Get,
        string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    auto sink = std::make_shared<MockMultipartSink>();
    req.set_multipart_sink(sink);

    std::atomic<int> done{0};
    c.request(req, [&](Result<Response> r) {
        CHECK(r.has_value());
        CHECK(r.value().body_decoded() == true);
        done.store(1);
    });

    for (int i = 0; i < 50 && done.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    CHECK(done.load() == 1);
    CHECK(sink->parts_started == 2);
    CHECK(sink->complete_count == 1);
    CHECK(!sink->error_fired);
}
#endif // MEGOHTTP_HAS_ZLIB

TEST_CASE("Client fires on_error when multipart body is truncated", "[s57][multipart][truncation]") {
    // A multipart body missing its closing boundary. Framing is close-delimited
    // (no Content-Length) so the HTTP message ends exactly where the body ends:
    // that is the shape where "HTTP complete, multipart incomplete" is real
    // rather than an artefact of the fixture sending a matching length.
    std::string truncated = "--b1\r\nContent-Type: text/plain\r\n\r\npart one\r\n"
                            "--b1\r\nContent-Type: text/plain\r\n\r\npart two";
    // no "--b1--\r\n"

    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=b1", truncated, false, false));

    Client c;
    Request req(Method::Get,
        string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    auto sink = std::make_shared<MockMultipartSink>();
    req.set_multipart_sink(sink);

    std::atomic<int> done{0};
    c.request(req, [&](Result<Response> r) {
        // The HTTP message completes (Content-Length matches what the server sent),
        // but multipart is truncated.
        CHECK(r.has_error());
        CHECK(r.error().code() == ErrorCode::MultipartTruncated);
        done.store(1);
    });

    for (int i = 0; i < 50 && done.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    CHECK(done.load() == 1);
    CHECK(sink->error_fired);
    CHECK(sink->last_error.code() == ErrorCode::MultipartTruncated);
    CHECK(sink->complete_count == 0);
    // Parts that arrived before truncation should still be delivered
    CHECK(sink->parts_started >= 1);
}

TEST_CASE("multipart sink and body sink are mutually exclusive", "[s57][multipart]") {
    Request req(Method::Get, "http://example.com/");
    auto sink = std::make_shared<MockMultipartSink>();

    // Set multipart sink first, then body sink → body sink wins
    req.set_multipart_sink(sink);
    CHECK(req.multipart_sink() != nullptr);
    req.set_body_sink([](string_view) { return true; }, [](VoidResult) {});
    CHECK(req.multipart_sink() == nullptr);
    CHECK(req.body_sink().has_value());

    // Set body sink first, then multipart sink → multipart sink wins
    Request req2(Method::Get, "http://example.com/");
    req2.set_body_sink([](string_view) { return true; }, [](VoidResult) {});
    req2.set_multipart_sink(sink);
    CHECK(req2.multipart_sink() != nullptr);
    CHECK(req2.body_sink() == std::nullopt);
}

TEST_CASE("Client reads boundary from Content-Type header", "[s57][multipart]") {
    // No explicit boundary in options → must be parsed from Content-Type
    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=xyz",
        "--xyz\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        "--xyz--\r\n"));

    Client c;
    Request req(Method::Get,
        string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    // No boundary in options
    MultipartResponseOptions opts;
    auto sink = std::make_shared<MockMultipartSink>();
    req.set_multipart_sink(sink, opts);

    std::atomic<int> done{0};
    c.request(req, [&](Result<Response> r) {
        CHECK(r.has_value());
        done.store(1);
    });

    for (int i = 0; i < 50 && done.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    CHECK(done.load() == 1);
    CHECK(sink->parts_started == 1);
    CHECK(sink->complete_count == 1);
}

bool wait_for_pred(std::function<bool()> pred, int max_ms = 3000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

void settle(int ms = 150) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

ClientOptions pooling_options(size_t max_per_origin) {
    ClientOptions opt;
    opt.pool.max_connections_per_origin = max_per_origin;
    opt.pool.max_total_connections = max_per_origin;
    opt.pool.max_waiting = 16;
    return opt;
}

TEST_CASE("pool returns connection after a complete multipart response",
          "[s57][multipart][pool]") {
    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=b1", mp_mixed()));

    Client c(pooling_options(2));
    const string url(string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    auto run_multipart = [&]() -> bool {
        Request req(Method::Get, url);
        auto sink = std::make_shared<MockMultipartSink>();
        req.set_multipart_sink(sink);
        std::atomic<int> done{0};
        c.request(req, [&](Result<Response> r) { done.store(1); });
        for (int i = 0; i < 50 && done.load() == 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return done.load() == 1;
    };

    REQUIRE(run_multipart());
    REQUIRE(run_multipart());

    settle();
    // Two requests, ONE accept → the first connection was reused.
    CHECK(srv.accepts() == 1);
    CHECK(srv.requests() == 2);
}

TEST_CASE("pool does NOT return connection after a truncated multipart response",
          "[s57][multipart][pool][truncation]") {
    std::string truncated = "--b1\r\nContent-Type: text/plain\r\n\r\npart one\r\n"
                            "--b1\r\nContent-Type: text/plain\r\n\r\npart two";
    // no closing boundary

    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=b1", truncated));

    Client c(pooling_options(2));
    const string url(string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    auto run_multipart = [&]() -> bool {
        Request req(Method::Get, url);
        auto sink = std::make_shared<MockMultipartSink>();
        req.set_multipart_sink(sink);
        std::atomic<int> done{0};
        c.request(req, [&](Result<Response> r) { done.store(1); });
        for (int i = 0; i < 50 && done.load() == 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return done.load() == 1;
    };

    REQUIRE(run_multipart());
    REQUIRE(run_multipart());

    settle();
    // The first response was truncated → connection must NOT be pooled →
    // second request opens its own connection.
    CHECK(srv.accepts() >= 2);
    CHECK(srv.requests() >= 2);
}

TEST_CASE("multipart flow receives pause() when sink returns false",
          "[s57][multipart][backpressure]") {
    // Close-delimited framing plus a split write. Close-delimited because the
    // resume path ends with a read that must observe EOF: on a keep-alive
    // connection that read would block forever and the request would only end
    // when the Client was destroyed. The split guarantees the sink sees a
    // pause point while bytes are still on their way, which is the situation
    // backpressure exists for.
    MultipartServer srv;
    REQUIRE(srv.start("multipart/mixed; boundary=b1", mp_mixed(), false, false, 50));

    Client c;
    Request req(Method::Get,
        string(("http://127.0.0.1:" + std::to_string(srv.port()) + "/").c_str()));

    auto sink = std::make_shared<MockMultipartSink>();
    auto flow = std::make_shared<Request::MultipartSinkFlow>();
    req.set_multipart_sink(sink, {}, flow);

    std::atomic<int> done{0};
    std::atomic<bool> flow_was_paused{false};

    // In the sink callback, check if the flow is paused after the first chunk.
    // The sink itself will return false on the first call, which should trigger
    // pause().
    struct PausingSink : MultipartSink {
        std::shared_ptr<Request::MultipartSinkFlow> flow;
        std::atomic<bool>* was_paused;
        std::atomic<bool> paused{false};
        std::vector<std::vector<uint8_t>> data;
        int parts_started{0};
        int parts_ended{0};
        int complete_count{0};
        bool error_fired{false};

        void on_part_begin(const MultipartPartHead&) override { ++parts_started; }
        bool on_part_data(const uint8_t* d, size_t n) override {
            data.emplace_back(d, d + n);
            // Ask for a pause exactly once, on the first block.
            if (!paused.exchange(true)) return false;
            return true;
        }
        void on_part_end() override { ++parts_ended; }
        void on_complete() override { ++complete_count; }
        void on_error(const Error&) override { error_fired = true; }
    };

    auto psink = std::make_shared<PausingSink>();
    psink->flow = flow;
    psink->was_paused = &flow_was_paused;
    req.set_multipart_sink(psink, {}, flow);

    std::thread resume_thread([flow, &psink, &flow_was_paused]() {
        // Wait for the sink to pause, give the exchange a moment to call
        // flow->pause(), then record that and resume.
        for (int i = 0; i < 100 && !psink->paused; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        // The Exchange calls pause() right after the sink returns false, so by
        // now the flag must be visible from this (foreign) thread.
        flow_was_paused = flow->is_paused();
        flow->resume();
    });
    resume_thread.detach();

    c.request(req, [&](Result<Response> r) {
        if (!r) {
            WARN("request error: code=" << static_cast<int>(r.error().code())
                 << " phase=" << static_cast<int>(r.error().phase())
                 << " msg=" << std::string(r.error().message().data(), r.error().message().size()));
        }
        CHECK(r.has_value());
        done.store(1);
    });

    for (int i = 0; i < 50 && done.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    CHECK(done.load() == 1);
    CHECK(flow_was_paused);
    // Both parts should still be delivered (first after resume, second normally)
    CHECK(psink->parts_started == 2);
    CHECK(psink->complete_count == 1);
    CHECK(!psink->error_fired);
}
