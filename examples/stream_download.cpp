// Example 10 — streaming file download.
//
// A buffered request puts the whole body in memory (up to
// ClientOptions::max_response_body). For a large file that is the wrong shape:
// attach a BodySink and each chunk goes straight to the destination as it
// arrives. body_bytes() then stays empty and body_is_buffered() is false.
//
// The example also attaches a head callback: with a streamed body, the status,
// Content-Length and Content-Type are the only things you can inspect BEFORE
// deciding to keep reading — which is what a download manager needs.
//
// Backpressure: returning false from the sink PAUSES delivery. A sink cannot
// resume itself, which is why a Request with a sink must also carry a
// BodySinkFlow (the third argument). This example returns false only on a write
// error and then cancels, so it never needs to resume; the comment in the sink
// shows where a slow-disk application would call flow->pause()/resume().
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python -m http.server 8080
//         megohttp_example_stream_download http://127.0.0.1:8080/some-file.bin out.bin
//
// Exit code: 0 when the whole body was written, 1 otherwise.

#include <megohttp/client.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "http://127.0.0.1:8080/";
    const char* path = (argc > 2) ? argv[2] : "download.bin";

    FILE* out = std::fopen(path, "wb");
    if (!out) {
        std::printf("cannot open %s for writing\n", path);
        return 1;
    }

    megohttp::string url(target);
    megohttp::Request request(megohttp::Method::Get, megohttp::to_view(url));

    auto flow = std::make_shared<megohttp::Request::BodySinkFlow>();
    std::atomic<uint64_t> received{0};
    std::atomic<bool> write_failed{false};
    std::atomic<bool> done{false};

    request.set_head_callback([](const megohttp::ResponseHead& head) {
        std::printf("head: status %d, content-length %s\n", head.status_code,
                    head.content_length ? "present" : "absent");
    });

    request.set_body_sink(
        [out, &received, &write_failed, flow](megohttp::string_view chunk) {
            if (write_failed.load()) return true;   // draining; nothing else to do
            const size_t written =
                std::fwrite(chunk.data(), 1, chunk.size(), out);
            if (written != chunk.size()) {
                write_failed.store(true);
                // Returning false pauses delivery. Nothing resumes it here on
                // purpose: the request is about to be cancelled. A slow-disk
                // producer would instead call flow->pause() before writing and
                // flow->resume() from a worker thread once the disk caught up.
                return false;
            }
            received.fetch_add(chunk.size());
            return true;
        },
        [&write_failed](megohttp::VoidResult result) {
            if (!result) write_failed.store(true);
        },
        flow);

    megohttp::Client client;
    client.request(request, [&](megohttp::Result<megohttp::Response> result) {
        if (!result) {
            std::printf("request failed: %.*s\n",
                        static_cast<int>(result.error().message().size()),
                        result.error().message().data());
        } else {
            std::printf("done: status %d, buffered=%d\n",
                        result.value().head().status_code,
                        result.value().body_is_buffered() ? 1 : 0);
        }
        done.store(true);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!done.load()) {
        client.shutdown();
        std::fclose(out);
        std::printf("timed out\n");
        return 1;
    }

    std::fclose(out);
    std::printf("wrote %lld bytes to %s\n",
                static_cast<long long>(received.load()), path);
    return write_failed.load() ? 1 : 0;
}
