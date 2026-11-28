// Example 9 — continuous multipart stream: backpressure and active cancel.
//
// A long-lived multipart stream cannot be consumed at the network's pace: a
// consumer that writes each part to disk or forwards it to another service must
// be able to say "stop reading until I am ready". That is what the sink's return
// value plus an attached MultipartSinkFlow does:
//
//   • on_part_data returns false  ->  the socket read stops there;
//   • flow->resume() from any thread -> reading continues where it stopped.
//
// Without a flow the return value is ignored (nothing could ever resume it, so
// pausing would hang the transfer forever). And a stream that never ends must be
// cancellable: the CancelHandle returned by request() ends it with
// ErrorCode::Cancelled, and the sink still gets on_error exactly once.
//
// This example pauses on the second part for 300 ms, then cancels once the fifth
// part has been assembled. The timestamps show the pause actually stalled the
// stream instead of the bytes piling up in memory.
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python examples/servers/multipart_server.py 8085
//         megohttp_example_multipart_continuous http://127.0.0.1:8085/stream
//
// Exit code: 0 when the pause was observed, at least five parts arrived and the
// request ended as Cancelled.

#include <megohttp/client.hpp>
#include <megohttp/multipart_sink.hpp>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

namespace {

using Clock = std::chrono::steady_clock;

std::mutex g_print_mutex;

void log_line(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_print_mutex);
    va_list args;
    va_start(args, fmt);
    std::vprintf(fmt, args);
    va_end(args);
    std::fflush(stdout);
}

class PausingSink final : public megohttp::MultipartSink {
public:
    explicit PausingSink(std::shared_ptr<megohttp::Request::MultipartSinkFlow> flow)
        : flow_(std::move(flow)) {}

    void on_part_begin(const megohttp::MultipartPartHead& head) override {
        part_ = head.index;
        part_bytes_ = 0;
    }

    bool on_part_data(const uint8_t*, size_t size) override {
        part_bytes_ += size;
        total_bytes_ += size;
        // Ask for backpressure exactly once, in the middle of the second part.
        if (part_ == 1 && !pause_requested_.exchange(true)) {
            paused_at_ = Clock::now();
            log_line("[%6lld ms] sink returns false on part 1 -> read pauses\n",
                     elapsed_ms());
            return false;
        }
        return true;
    }

    void on_part_end() override {
        ++parts_;
        log_line("[%6lld ms] part %zu assembled: %llu bytes\n", elapsed_ms(),
                 static_cast<size_t>(part_), static_cast<unsigned long long>(part_bytes_));
    }

    void on_complete() override { completed_.store(true); }

    void on_error(const megohttp::Error& error) override {
        cancelled_ = (error.code() == megohttp::ErrorCode::Cancelled);
        std::string message(error.message().data(), error.message().size());
        log_line("[%6lld ms] sink on_error: code=%d %s\n", elapsed_ms(),
                 static_cast<int>(error.code()), message.c_str());
    }

    long long elapsed_ms() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   Clock::now() - start_)
            .count();
    }

    size_t parts() const { return parts_.load(); }
    bool pause_requested() const { return pause_requested_.load(); }
    bool cancelled() const { return cancelled_.load(); }
    bool completed() const { return completed_.load(); }

private:
    std::shared_ptr<megohttp::Request::MultipartSinkFlow> flow_;
    Clock::time_point start_{Clock::now()};
    Clock::time_point paused_at_{};
    std::atomic<size_t> parts_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<bool> pause_requested_{false};
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> completed_{false};
    size_t part_{0};
    uint64_t part_bytes_{0};
};

} // namespace

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8085/stream";

    auto flow = std::make_shared<megohttp::Request::MultipartSinkFlow>();
    auto sink = std::make_shared<PausingSink>(flow);

    megohttp::string url(target);
    megohttp::Request request(megohttp::Method::Get, megohttp::to_view(url));
    request.set_multipart_sink(sink, {}, flow);

    log_line("GET %s (sink + flow attached)\n", target);

    megohttp::Client client;
    std::atomic<bool> done{false};
    int status = 1;

    megohttp::CancelHandle handle = client.request(
        request, [&](megohttp::Result<megohttp::Response> result) {
            if (!result) {
                log_line("[terminal] failed: code=%d\n",
                         static_cast<int>(result.error().code()));
                status = (result.error().code() == megohttp::ErrorCode::Cancelled) ? 0 : 1;
            } else {
                log_line("[terminal] status %d\n", result.value().head().status_code);
                status = 1;   // the stream was supposed to be cancelled, not to finish
            }
            done.store(true);
        });

    // Watcher: two jobs, both driven by state the sink publishes.
    std::thread watcher([&] {
        // 1. Wait for the sink's pause, hold it for 300 ms, then resume.
        while (!sink->pause_requested() && !done.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        if (sink->pause_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            log_line("[%6lld ms] flow->resume() from another thread\n", sink->elapsed_ms());
            flow->resume();
        }
        // 2. Once five parts are in, cancel the endless stream.
        while (sink->parts() < 5 && !done.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        if (!done.load()) {
            log_line("[%6lld ms] cancel() after %zu parts\n", sink->elapsed_ms(),
                     sink->parts());
            handle.cancel();
        }
    });

    const auto deadline = Clock::now() + std::chrono::seconds(30);
    while (!done.load() && Clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    handle.cancel();          // no-op if it already terminated
    watcher.join();

    if (!done.load()) {
        log_line("timed out\n");
        return 1;
    }
    log_line("summary: parts=%zu pause_observed=%d cancelled=%d completed=%d\n",
             sink->parts(), sink->pause_requested() ? 1 : 0, sink->cancelled() ? 1 : 0,
             sink->completed() ? 1 : 0);

    const bool ok = sink->pause_requested() && sink->parts() >= 5 &&
                    sink->cancelled() && !sink->completed() && status == 0;
    return ok ? 0 : 1;
}
