// S3.2 file source: the upload bytes come from a file on the worker thread,
// not from a synchronous ifstream inside BodySource on the Client I/O thread.
#include <catch2/catch_all.hpp>

#include <megohttp/client.hpp>
#include <megohttp/file_source.hpp>
#include <megohttp/multipart.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
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

std::string temp_path(const char* tag) {
    const char* base = std::getenv("TMPDIR");
    if (!base) base = std::getenv("TEMP");
    if (!base) base = std::getenv("TMP");
    if (!base) base = ".";
    static std::atomic<uint64_t> counter{0};
    return std::string(base) + "/megohttp_file_" + tag + "_" +
           std::to_string(++counter) + ".bin";
}

void write_file(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    REQUIRE(static_cast<bool>(out));
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    REQUIRE(static_cast<bool>(out));
}

std::vector<uint8_t> make_pattern(size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 37u + 11u) & 0xffu);
    }
    return data;
}

std::string as_std(string_view value) {
    return std::string(value.data(), value.size());
}

std::string lower_ascii(std::string value) {
    for (auto& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

// A FileSource legitimately returns an empty, non-EOF chunk while its worker
// is filling the queue. This helper mirrors the Client's retry behavior.
Result<std::vector<uint8_t>> drain_file_source(Request::BodySource source,
                                               size_t max_bytes = 8 * 1024 * 1024) {
    std::vector<uint8_t> out;
    for (int i = 0; i < 20000; ++i) {
        auto r = source();
        if (!r) return r.error();
        auto& chunk = r.value();
        if (!chunk.first.empty()) {
            const char* d = chunk.first.data();
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(d),
                       reinterpret_cast<const uint8_t*>(d) +
                           static_cast<size_t>(chunk.first.size()));
            if (out.size() > max_bytes) {
                return Error{ErrorCode::HttpBodyTooLarge, ErrorPhase::Receive,
                             string("file source test exceeded its cap")};
            }
        }
        if (chunk.second) return out;
        if (chunk.first.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    return Error{ErrorCode::TimeoutTotal, ErrorPhase::Receive,
                 string("file source never reached eof")};
}

// Receives one request with either Content-Length or chunked framing and
// records the decoded body. It does not share a parser with the client.
class CaptureServer {
public:
    ~CaptureServer() { stop(); }

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
        if (::bind(listen_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
            return false;
        }
        if (::listen(listen_, 4) != 0) return false;
        sockaddr_in got{};
        socklen_t glen = sizeof got;
        ::getsockname(listen_, reinterpret_cast<sockaddr*>(&got), &glen);
        port_ = ntohs(got.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }

    std::string head() const {
        std::lock_guard<std::mutex> lock(mu_);
        return head_;
    }

    std::string body() const {
        std::lock_guard<std::mutex> lock(mu_);
        return body_;
    }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (listen_ != kInvalid) {
            closesock(listen_);
            listen_ = kInvalid;
        }
        if (thread_.joinable()) thread_.join();
    }

private:
    static std::string lower(std::string s) {
        for (auto& c : s) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        return s;
    }

    static bool parse_content_length(const std::string& head, uint64_t& out) {
        const std::string lowered = lower(head);
        const std::string needle = "content-length:";
        const size_t at = lowered.find(needle);
        if (at == std::string::npos) return false;
        size_t p = at + needle.size();
        while (p < head.size() && (head[p] == ' ' || head[p] == '\t')) ++p;
        uint64_t value = 0;
        bool any = false;
        while (p < head.size() && head[p] >= '0' && head[p] <= '9') {
            any = true;
            value = value * 10 + static_cast<uint64_t>(head[p] - '0');
            ++p;
        }
        if (!any) return false;
        out = value;
        return true;
    }

    static bool decode_chunked(const std::string& raw, std::string& body) {
        size_t p = 0;
        while (p < raw.size()) {
            size_t line_end = raw.find("\r\n", p);
            if (line_end == std::string::npos) return false;
            uint64_t size = 0;
            bool any = false;
            for (size_t i = p; i < line_end; ++i) {
                const char c = raw[i];
                unsigned digit = 0;
                if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
                else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
                else break;
                size = size * 16 + digit;
                any = true;
            }
            if (!any) return false;
            p = line_end + 2;
            if (size == 0) {
                // Trailer fields, if any, end at the next blank line.
                const size_t end = raw.find("\r\n\r\n", p);
                return end != std::string::npos || raw.size() >= p + 2;
            }
            if (p + size + 2 > raw.size()) return false;
            body.append(raw, p, static_cast<size_t>(size));
            p += static_cast<size_t>(size);
            if (raw.compare(p, 2, "\r\n") != 0) return false;
            p += 2;
        }
        return false;
    }

    void run() {
        if (listen_ == kInvalid) return;
        sock_t c = ::accept(listen_, nullptr, nullptr);
        if (c == kInvalid) return;

#if defined(_WIN32)
        DWORD tv = 2000;
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv), sizeof tv);
#else
        timeval tv{};
        tv.tv_sec = 2;
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv), sizeof tv);
#endif
        std::string all;
        char buf[8192];
        size_t header_end = std::string::npos;
        uint64_t content_length = 0;
        bool has_content_length = false;
        for (;;) {
            int n = static_cast<int>(::recv(c, buf, sizeof buf, 0));
            if (n <= 0) break;
            all.append(buf, static_cast<size_t>(n));
            if (header_end == std::string::npos) {
                header_end = all.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    has_content_length =
                        parse_content_length(all.substr(0, header_end), content_length);
                }
            }
            if (header_end != std::string::npos) {
                if (has_content_length &&
                    all.size() >= header_end + 4 + content_length) {
                    break;
                }
                if (!has_content_length &&
                    all.find("0\r\n\r\n", header_end + 4) != std::string::npos) {
                    break;
                }
            }
        }

        std::string head;
        std::string body;
        if (header_end != std::string::npos) {
            head = all.substr(0, header_end);
            const std::string raw = all.substr(header_end + 4);
            if (has_content_length) {
                body = raw.substr(0, static_cast<size_t>(content_length));
            } else {
                decode_chunked(raw, body);
            }
        }
        {
            std::lock_guard<std::mutex> lock(mu_);
            head_ = std::move(head);
            body_ = std::move(body);
        }

        const char response[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        ::send(c, response, static_cast<int>(sizeof response - 1), 0);
        closesock(c);
    }

    sock_t listen_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    mutable std::mutex mu_;
    std::string head_;
    std::string body_;
    std::thread thread_;
};

} // namespace

TEST_CASE("FileSource streams a file without doing reads in BodySource",
          "[file][streaming][source]") {
    const std::string path = temp_path("stream");
    const auto expected = make_pattern(300000);
    write_file(path, expected);

    const string path_text = to_string(path.data(), path.size());
    auto opened = FileSource::open(to_view(path_text),
                                   FileSource::Options{4096, 4});
    REQUIRE(opened);
    auto source = opened.value();
    REQUIRE(source->size().has_value());
    CHECK(source->size().value() == expected.size());

    auto body = drain_file_source(source->body_source());
    REQUIRE(body);
    REQUIRE(body.value().size() == expected.size());
    CHECK(std::memcmp(body.value().data(), expected.data(), expected.size()) == 0);
    CHECK(source->is_eof());
    std::remove(path.c_str());
}

TEST_CASE("FileSource handles empty files", "[file][streaming][source]") {
    const std::string path = temp_path("empty");
    write_file(path, {});

    const string path_text = to_string(path.data(), path.size());
    auto opened = FileSource::open(to_view(path_text));
    REQUIRE(opened);
    auto source = opened.value();
    CHECK(source->size().has_value());
    CHECK(source->size().value() == 0);

    auto body = drain_file_source(source->body_source());
    REQUIRE(body);
    CHECK(body.value().empty());
    CHECK(source->is_eof());
    std::remove(path.c_str());
}

TEST_CASE("FileSource reports open and option errors synchronously",
          "[file][streaming][source]") {
    auto missing = FileSource::open("definitely-not-a-file-megohttp");
    REQUIRE_FALSE(missing);
    CHECK(missing.error().code() == ErrorCode::InvalidArgument);

    const std::string path = temp_path("options");
    write_file(path, make_pattern(16));
    const string path_text = to_string(path.data(), path.size());
    auto bad_chunk = FileSource::open(to_view(path_text),
                                      FileSource::Options{0, 4});
    REQUIRE_FALSE(bad_chunk);

    auto bad_queue = FileSource::open(to_view(path_text),
                                      FileSource::Options{64, 0});
    REQUIRE_FALSE(bad_queue);
    std::remove(path.c_str());
}

TEST_CASE("FileSource attach_to emits Content-Length and a BodySource",
          "[file][streaming][source]") {
    const std::string path = temp_path("attach");
    const auto expected = make_pattern(1000);
    write_file(path, expected);

    const string path_text = to_string(path.data(), path.size());
    auto opened = FileSource::open(to_view(path_text));
    REQUIRE(opened);
    auto source = opened.value();

    Request req(Method::Post, "http://127.0.0.1/upload");
    REQUIRE(source->attach_to(req));
    CHECK(req.body_source().has_value());
    CHECK_FALSE(req.body_bytes().size());
    REQUIRE(req.headers().get("content-length").has_value());
    CHECK(as_std(req.headers().get("content-length").value()) ==
          std::to_string(expected.size()));

    req.headers().set("transfer-encoding", "chunked");
    auto conflict = source->attach_to(req);
    REQUIRE_FALSE(conflict);
    CHECK(conflict.error().code() == ErrorCode::InvalidArgument);
    std::remove(path.c_str());
}

TEST_CASE("MultipartBuilder accepts a file path and keeps a known length",
          "[file][multipart][source]") {
    const std::string path = temp_path("multipart");
    const auto expected = make_pattern(8192);
    write_file(path, expected);

    const string path_text = to_string(path.data(), path.size());
    MultipartBuilder builder;
    REQUIRE(builder.add_file_field("file", "payload.bin",
                                   "application/octet-stream",
                                   to_view(path_text)));
    auto total = builder.compute_total_size();
    REQUIRE(total.has_value());

    Request req(Method::Post, "http://127.0.0.1/upload");
    REQUIRE(builder.apply_to(req));
    REQUIRE(req.headers().get("content-length").has_value());
    CHECK(as_std(req.headers().get("content-length").value()) ==
          std::to_string(total.value()));

    auto body = drain_file_source(req.body_source().value());
    REQUIRE(body);
    const std::string text(reinterpret_cast<const char*>(body.value().data()),
                           body.value().size());
    CHECK(text.find("filename=\"payload.bin\"") != std::string::npos);
    CHECK(text.find(std::string(expected.begin(), expected.end())) != std::string::npos);
    std::remove(path.c_str());
}

TEST_CASE("FileSource uploads through the public Client API",
          "[file][streaming][network]") {
    const std::string path = temp_path("upload");
    const auto expected = make_pattern(512 * 1024);
    write_file(path, expected);

    CaptureServer server;
    REQUIRE(server.start());

    const string path_text = to_string(path.data(), path.size());
    auto opened = FileSource::open(to_view(path_text),
                                   FileSource::Options{32 * 1024, 4});
    REQUIRE(opened);
    auto source = opened.value();

    const std::string url_text = "http://127.0.0.1:" +
                                 std::to_string(server.port()) + "/upload";
    const string url = to_string(url_text.data(), url_text.size());
    Request req(Method::Post, to_view(url));
    REQUIRE(source->attach_to(req));

    Client client;
    auto response = client.request_sync(req);
    REQUIRE(response);
    CHECK(response.value().head().status_code == 200);
    REQUIRE(server.body().size() == expected.size());
    CHECK(std::memcmp(server.body().data(), expected.data(), expected.size()) == 0);

    const std::string head = lower_ascii(server.head());
    CHECK(head.find("content-length: " + std::to_string(expected.size())) !=
          std::string::npos);
    CHECK(head.find("transfer-encoding: chunked") == std::string::npos);
    std::remove(path.c_str());
}
