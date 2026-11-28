// Example 8 — streaming a multipart response.
//
// A multipart/mixed response is delivered part by part to a MultipartSink
// instead of being buffered whole: on_part_begin carries the part's headers,
// on_part_data the payload chunks (the view is borrowed for the call only), and
// on_part_end closes the part. on_complete fires exactly once, when BOTH the
// HTTP message and the multipart message are complete; on_error and on_complete
// are mutually exclusive.
//
// MultipartSink is an abstract class rather than a std::function bundle on
// purpose: the callbacks carry state (the part being assembled) and the library
// must know when a part ends, which a single opaque callback could not express.
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python examples/servers/multipart_server.py 8085
//         megohttp_example_multipart_response http://127.0.0.1:8085/batch
//
// Exit code: 0 when at least three parts arrived and the stream completed.

#include <megohttp/client.hpp>
#include <megohttp/multipart_sink.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// Pulls `name="..."` / `filename="..."` out of a Content-Disposition value.
std::string disposition_param(const megohttp::Headers& headers, const char* key) {
    const auto value = headers.get("content-disposition");
    if (!value) return {};
    const std::string text(value->data(), value->size());
    const std::string needle = std::string(key) + "=\"";
    const auto at = text.find(needle);
    if (at == std::string::npos) return {};
    const auto start = at + needle.size();
    const auto end = text.find('"', start);
    if (end == std::string::npos) return {};
    return text.substr(start, end - start);
}

class CollectingSink final : public megohttp::MultipartSink {
public:
    struct Part {
        std::string name;
        std::string filename;
        uint64_t bytes{0};
    };

    void on_part_begin(const megohttp::MultipartPartHead& head) override {
        current_ = Part{disposition_param(head.headers, "name"),
                        disposition_param(head.headers, "filename"), 0};
        std::printf("part %zu begins: name='%s' filename='%s'\n", head.index,
                    current_.name.c_str(), current_.filename.c_str());
    }

    bool on_part_data(const uint8_t*, size_t size) override {
        current_.bytes += size;
        total_bytes_ += size;
        return true;   // no backpressure in this example; see the next one
    }

    void on_part_end() override {
        std::printf("part ends: %llu bytes\n",
                    static_cast<unsigned long long>(current_.bytes));
        parts_.push_back(current_);
    }

    void on_complete() override { completed_.store(true); }

    void on_error(const megohttp::Error& error) override {
        std::string message(error.message().data(), error.message().size());
        {
            std::lock_guard<std::mutex> lock(mutex_);
            error_ = message;
        }
        failed_.store(true);
    }

    size_t part_count() const { return parts_.size(); }
    uint64_t total_bytes() const { return total_bytes_; }
    bool completed() const { return completed_.load(); }
    bool failed() const { return failed_.load(); }
    std::string error() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return error_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<Part> parts_;
    Part current_{};
    uint64_t total_bytes_{0};
    std::atomic<bool> completed_{false};
    std::atomic<bool> failed_{false};
    std::string error_;
};

} // namespace

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8085/batch";

    megohttp::string url(target);
    megohttp::Request request(megohttp::Method::Get, megohttp::to_view(url));

    auto sink = std::make_shared<CollectingSink>();
    request.set_multipart_sink(sink);

    std::printf("GET %s (multipart sink attached)\n", target);

    megohttp::Client client;
    std::atomic<bool> done{false};
    int status = 1;

    client.request(request, [&](megohttp::Result<megohttp::Response> result) {
        if (!result) {
            std::printf("request failed: %.*s\n",
                        static_cast<int>(result.error().message().size()),
                        result.error().message().data());
        } else {
            std::printf("terminal callback: status %d, body buffered=%d\n",
                        result.value().head().status_code,
                        result.value().body_is_buffered() ? 1 : 0);
            status = (result.value().head().status_code == 200) ? 0 : 1;
        }
        done.store(true);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!done.load()) {
        std::printf("timed out\n");
        return 1;
    }
    if (sink->failed()) {
        std::printf("sink error: %s\n", sink->error().c_str());
        return 1;
    }
    std::printf("summary: %zu parts, %llu bytes, completed=%d\n", sink->part_count(),
                static_cast<unsigned long long>(sink->total_bytes()),
                sink->completed() ? 1 : 0);

    const bool ok = sink->completed() && sink->part_count() >= 3 && status == 0;
    return ok ? 0 : 1;
}
