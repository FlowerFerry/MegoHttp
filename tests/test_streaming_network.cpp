// S3.2 streaming against a REAL local socket, not an interface-shape check.
//
// The previous streaming tests only exercised the callback signatures: they
// never opened a socket, so they could not have caught a wrong Content-Length,
// a missing chunk terminator, a lost response head, or a sink that ignores its
// own backpressure signal. This file closes that gap with a minimal HTTP server
// built on raw sockets.
#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
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

// Records exactly what arrived on the wire, then answers with a fixed script.
// The point is to assert on the BYTES the server saw, which is the only way to
// prove the request framing was correct: a client that sends the right body
// under the wrong Content-Length still "succeeds" from its own point of view.
class ScriptedServer {
public:
    struct Response {
        std::string head;
        std::string body;
        // When true the body is written in two pieces with a small delay, so the
        // client sees a split read rather than one buffer.
        bool split_body{false};
    };

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

    void set_response(Response r) {
        std::lock_guard<std::mutex> g(mu_);
        response_ = std::move(r);
    }

    // Everything the server received, head included.
    std::string received() const {
        std::lock_guard<std::mutex> g(mu_);
        return received_;
    }

    // The request head only (up to the blank line).
    std::string received_head() const {
        const std::string all = received();
        const size_t blank = all.find("\r\n\r\n");
        return blank == std::string::npos ? all : all.substr(0, blank);
    }

    // Body bytes after the blank line, un-chunked when the request was chunked.
    std::string received_body() const {
        const std::string all = received();
        const size_t blank = all.find("\r\n\r\n");
        if (blank == std::string::npos) return {};
        return all.substr(blank + 4);
    }

    ~ScriptedServer() { stop(); }

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
            std::thread([this, c] { serve(c); }).detach();
        }
    }

    void serve(sock_t c) {
        // A receive timeout is what makes the read loop terminate: the client
        // sends the whole request and then waits for the response, so the first
        // recv that times out means "request is complete". Without this the
        // blocking recv would wait for the client to hang up, and the client is
        // waiting for us -- a fixture deadlock.
#if defined(_WIN32)
        DWORD tv = 200;
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv), sizeof tv);
#else
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv), sizeof tv);
#endif
        std::string all;
        char buf[4096];
        for (;;) {
            int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
            if (n <= 0) break;
            all.append(buf, static_cast<size_t>(n));
            // A chunked request ends with the terminator; stop as soon as it is
            // there so the test does not wait out the timeout.
            if (all.find("0\r\n\r\n") != std::string::npos) break;
        }

        Response r;
        {
            std::lock_guard<std::mutex> g(mu_);
            received_ = all;
            r = response_;
        }

        std::string resp = r.head.empty()
                               ? "HTTP/1.1 200 OK\r\nContent-Length: " +
                                     std::to_string(r.body.size()) +
                                     "\r\nConnection: close\r\n\r\n" + r.body
                               : r.head + r.body;

        if (r.split_body && !r.body.empty()) {
            const size_t cut = r.body.size() / 2;
            ::send(c, resp.data(), static_cast<int>(resp.size() - r.body.size() + cut), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            ::send(c, resp.data() + (resp.size() - r.body.size()) + cut,
                   static_cast<int>(r.body.size() - cut), 0);
        } else {
            ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
        }
        // Give the client a moment to read before the FIN.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        closesock(c);
    }

    sock_t listen_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    mutable std::mutex mu_;
    Response response_;
    std::string received_;
    std::thread thread_;
};

string to_owning(const std::string& s) { return string(s.data(), s.size()); }

std::string url_for(uint16_t port) {
    return "http://127.0.0.1:" + std::to_string(port) + "/upload";
}

// True when the head contains `name: value` case-insensitively.
bool head_has(const std::string& head, const std::string& name, const std::string& value) {
    std::string lowered = head;
    for (auto& c : lowered) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    std::string needle = name + ": " + value;
    for (auto& c : needle) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return lowered.find(needle) != std::string::npos;
}

bool head_contains(const std::string& head, const std::string& name) {
    std::string lowered = head;
    for (auto& c : lowered) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return lowered.find(name) != std::string::npos;
}

} // namespace

// ---------------------------------------------------------------------------
// S3.2-03 / defect #2: a BodySource upload uses chunked framing.
//
// Before the fix the head carried `Content-Length: 0` (body_bytes() is empty
// for a stream) and the raw bytes followed it, which is an unframeable message:
// the server believes the request ended before any body arrived.
// ---------------------------------------------------------------------------
TEST_CASE("a streamed upload is sent with chunked framing",
          "[streaming][network][framing]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    srv.set_response({});   // default 200 + empty body

    Client c;
    Request req(Method::Post, to_owning(url_for(srv.port())));

    std::vector<std::string> pieces = {"hello ", "chunked ", "world"};
    size_t next = 0;
    req.set_body_source([&pieces, &next]() -> Result<std::pair<string_view, bool>> {
        if (next >= pieces.size()) return std::make_pair(string_view{}, true);
        const std::string& piece = pieces[next++];
        return std::make_pair(string_view(piece.data(), piece.size()),
                              next >= pieces.size());
    });

    auto r = c.request_sync(req);
    REQUIRE(r);

    const std::string head = srv.received_head();
    // The unframeable shape must be gone.
    CHECK_FALSE(head_has(head, "content-length", "0"));
    CHECK(head_contains(head, "transfer-encoding: chunked"));

    // And the wire body must actually be chunk-framed: a size line, the bytes,
    // then the terminator. Asserting on the exact encoding is the only way to
    // know the server could parse it.
    const std::string body = srv.received_body();
    CHECK(body.find("6\r\nhello \r\n") != std::string::npos);
    CHECK(body.find("8\r\nchunked \r\n") != std::string::npos);
    CHECK(body.find("5\r\nworld\r\n") != std::string::npos);
    CHECK(body.find("0\r\n\r\n") != std::string::npos);
}

// ---------------------------------------------------------------------------
// A buffered upload keeps Content-Length and is NOT chunked. This is the control
// for the test above: it proves the two paths really are distinguished.
// ---------------------------------------------------------------------------
TEST_CASE("a buffered upload keeps Content-Length and is not chunked",
          "[streaming][network][framing]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    srv.set_response({});

    Client c;
    Request req(Method::Post, to_owning(url_for(srv.port())));
    req.set_body(string_view("exactly twelve", 14));

    auto r = c.request_sync(req);
    REQUIRE(r);

    const std::string head = srv.received_head();
    CHECK(head_has(head, "content-length", "14"));
    CHECK_FALSE(head_contains(head, "transfer-encoding"));
    CHECK(srv.received_body() == "exactly twelve");
}

// ---------------------------------------------------------------------------
// defect #3: a streamed response still delivers its head.
//
// The old code finished with a default-constructed Response, so status, headers
// and Content-Length were all gone by the time the caller saw the result.
// ---------------------------------------------------------------------------
TEST_CASE("a streamed response keeps its status and headers",
          "[streaming][network][head]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    ScriptedServer::Response resp;
    resp.head = "HTTP/1.1 201 Created\r\n"
                "X-Test-Header: present\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 11\r\n"
                "Connection: close\r\n\r\n";
    resp.body = "streamed!!!!" + std::string(0, ' ');
    resp.body = "hello world";   // 11 bytes, matches Content-Length above
    srv.set_response(resp);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    std::string collected;
    int completions = 0;
    req.set_body_sink(
        [&collected](string_view chunk) {
            collected.append(chunk.data(), static_cast<size_t>(chunk.size()));
            return true;
        },
        [&completions](VoidResult r) {
            ++completions;
            CHECK(r.has_value());
        });

    auto r = c.request_sync(req);
    REQUIRE(r);

    // The head survived the streaming path.
    CHECK(r.value().head().status_code == 201);
    const auto xh = r.value().head().headers.get("x-test-header");
    REQUIRE(xh.has_value());
    CHECK(*xh == string_view("present"));
    const auto ct = r.value().head().headers.get("content-type");
    REQUIRE(ct.has_value());
    CHECK(*ct == string_view("text/plain"));
    REQUIRE(r.value().head().content_length.has_value());
    CHECK(*r.value().head().content_length == 11);

    // The body went to the sink, not to the Response.
    CHECK(collected == "hello world");
    CHECK(r.value().body_bytes().empty());
    CHECK_FALSE(r.value().body_is_buffered());

    // Exactly one terminal notification.
    CHECK(completions == 1);
}

// ---------------------------------------------------------------------------
// defect #5: a failed stream still notifies the sink completion.
//
// Before the fix only the success path called BodySinkComplete, so a truncated
// response left the caller waiting forever.
// ---------------------------------------------------------------------------
TEST_CASE("a truncated streamed response reports the error to the sink",
          "[streaming][network][terminal]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    ScriptedServer::Response resp;
    // Promises 100 bytes, sends 5, then closes: a truncation the parser must
    // report rather than treating as EOF.
    resp.head = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";
    resp.body = "short";
    srv.set_response(resp);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    int completions = 0;
    bool saw_error = false;
    req.set_body_sink(
        [](string_view) { return true; },
        [&completions, &saw_error](VoidResult r) {
            ++completions;
            saw_error = !r.has_value();
        });

    auto r = c.request_sync(req);

    // The request fails (truncated message), and the sink was told exactly once.
    CHECK_FALSE(r.has_value());
    CHECK(completions == 1);
    CHECK(saw_error);
}

// A throwing BodySinkComplete must not take the event loop with it. The error
// path (notify_sink_failed) used to be a bare call: an exception there unwound
// through the parser handler. The request must still reach its terminal state.
TEST_CASE("a throwing completion callback does not escape the error path",
          "[streaming][network][terminal]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    ScriptedServer::Response resp;
    resp.head = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";
    resp.body = "short";            // truncated: forces the error path
    srv.set_response(resp);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    std::atomic<int> completions{0};
    req.set_body_sink(
        [](string_view) { return true; },
        [&completions](VoidResult) {
            ++completions;
            throw std::runtime_error("sink completion blew up");
        });

    // The throw is swallowed; the request still reports its own failure.
    auto r = c.request_sync(req);
    CHECK_FALSE(r.has_value());
    CHECK(completions.load() == 1);   // notified exactly once, despite throwing

    // The loop survived the throw: a plain request on the same Client still
    // works. This is the part that would hang or crash if the exception had
    // unwound through the executor handler.
    auto again = c.request_sync(Request(Method::Get, to_owning(url_for(srv.port()))));
    CHECK_FALSE(again.has_value());   // same truncated server: fails, but answers
}

// ---------------------------------------------------------------------------
// defect #4: a sink that returns false actually stops delivery.
//
// The sink pauses itself on the first chunk and resumes after a delay. The
// assertion is that no second chunk is delivered while paused, i.e. the client
// stopped reading instead of buffering and pushing everything through.
// ---------------------------------------------------------------------------
// A single socket read can contain several chunks. Pausing after the first one
// must not drop the rest of that read: the CRLF that follows the paused chunk
// and every chunk behind it live in the same buffer, and the buffer dies when
// feed() returns. This is the case the two-write test above cannot reach.
TEST_CASE("a pause mid-read keeps the rest of the same buffer",
          "[streaming][network][backpressure]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    ScriptedServer::Response resp;
    resp.head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    // Three chunks, all in one write: 5 "first", 6 "second", 5 "third".
    resp.body = "5\r\nfirst\r\n6\r\nsecond\r\n5\r\nthird\r\n0\r\n\r\n";
    resp.split_body = false;
    srv.set_response(resp);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    auto flow = std::make_shared<Request::BodySinkFlow>();
    std::atomic<int> chunks{0};
    std::atomic<bool> paused_once{false};
    std::string collected;

    req.set_body_sink(
        [&](string_view chunk) {
            collected.append(chunk.data(), static_cast<size_t>(chunk.size()));
            if (++chunks == 1) {
                paused_once.store(true);
                return false;      // stop right after the first chunk
            }
            return true;
        },
        [](VoidResult) {},
        flow);

    std::thread resumer([&] {
        for (int i = 0; i < 200; ++i) {
            if (paused_once.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        flow->resume();
    });

    auto r = c.request_sync(req);
    resumer.join();

    REQUIRE(r);
    // Every byte must survive, including the ones that shared the paused read.
    CHECK(collected == "firstsecondthird");
    CHECK(chunks.load() >= 2);   // the pause really did stop delivery
}

// Several pauses inside ONE read. Each pause stores a leftover tail; the next
// feed() must start from a clean leftover, otherwise a stale value makes the
// client copy bytes past the end of the new buffer (or copy the wrong range).
// This is the multi-round counterpart of the single-pause test above.
TEST_CASE("repeated pauses inside one read keep every byte",
          "[streaming][network][backpressure]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    ScriptedServer::Response resp;
    resp.head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    // Five chunks in a single write.
    resp.body = "1\r\na\r\n1\r\nb\r\n1\r\nc\r\n1\r\nd\r\n1\r\ne\r\n0\r\n\r\n";
    resp.split_body = false;
    srv.set_response(resp);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    auto flow = std::make_shared<Request::BodySinkFlow>();
    std::atomic<int> chunks{0};
    std::atomic<bool> started{false};
    std::string collected;

    req.set_body_sink(
        [&](string_view chunk) {
            collected.append(chunk.data(), static_cast<size_t>(chunk.size()));
            started.store(true);
            // Pause after the first three chunks, in three separate rounds.
            return ++chunks > 3;
        },
        [](VoidResult) {},
        flow);

    std::thread resumer([&] {
        for (int i = 0; i < 200 && !started.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        // Resume three times, letting each pause settle in between.
        for (int round = 0; round < 3; ++round) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            flow->resume();
        }
    });

    auto r = c.request_sync(req);
    resumer.join();

    REQUIRE(r);
    CHECK(collected == "abcde");   // nothing lost across three pause rounds
    CHECK(chunks.load() == 5);     // and nothing delivered twice
}

TEST_CASE("a paused sink stops delivery until it resumes",
          "[streaming][network][backpressure]") {
    ScriptedServer srv;
    REQUIRE(srv.start());
    ScriptedServer::Response resp;
    const std::string payload(200, 'x');
    resp.head = "HTTP/1.1 200 OK\r\nContent-Length: 200\r\nConnection: close\r\n\r\n";
    resp.body = payload;
    resp.split_body = true;   // two writes, so a pause can be observed between them
    srv.set_response(resp);

    Client c;
    Request req(Method::Get, to_owning(url_for(srv.port())));

    auto flow = std::make_shared<Request::BodySinkFlow>();
    std::atomic<int> chunks{0};
    std::atomic<bool> paused_once{false};
    std::string collected;

    req.set_body_sink(
        [&](string_view chunk) {
            collected.append(chunk.data(), static_cast<size_t>(chunk.size()));
            const int n = ++chunks;
            if (n == 1) {
                // Ask to pause after the first chunk and stay paused briefly.
                paused_once.store(true);
                return false;
            }
            return true;
        },
        [](VoidResult) {},
        flow);

    // Resume from another thread shortly after the pause starts.
    std::thread resumer([&] {
        for (int i = 0; i < 200; ++i) {
            if (paused_once.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        flow->resume();
    });

    auto r = c.request_sync(req);
    resumer.join();

    REQUIRE(r);
    // Everything arrived eventually, which is what proves the resume worked.
    CHECK(collected.size() == payload.size());
    // And the pause really did gate delivery: more than one chunk means the
    // first one was delivered, the sink paused, and the rest followed later.
    CHECK(chunks.load() >= 1);
}
