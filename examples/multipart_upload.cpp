// Example 7 — multipart/form-data file upload.
//
// MultipartBuilder assembles the body and installs it on the Request: text
// fields are copied, a file field can be an in-memory buffer, a FileSource, or
// a path that is opened and streamed from a worker thread. With every field
// size known the builder emits an exact Content-Length instead of chunked
// transfer, which is what most servers prefer for an upload.
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python examples/servers/multipart_server.py 8085
//         megohttp_example_multipart_upload http://127.0.0.1:8085/upload README.md
//
// The server parses the body and answers with a one-line-per-part summary, so the
// output proves the parts arrived with the right names and sizes.
//
// Exit code: 0 on a 200 answer, 1 otherwise.

#include <megohttp/client.hpp>
#include <megohttp/file_source.hpp>
#include <megohttp/multipart.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    const std::string url = (argc > 1) ? argv[1] : "http://127.0.0.1:8085/upload";
    const std::string path = (argc > 2) ? argv[2] : "README.md";
    const std::string filename = path.substr(path.find_last_of("/\\") + 1);

    megohttp::Request request(megohttp::Method::Post, megohttp::string(url.c_str()));

    megohttp::MultipartBuilder builder;
    if (auto r = builder.add_text_field("description", "uploaded by the MegoHttp example");
        !r) {
        std::printf("add_text_field failed: %.*s\n",
                    static_cast<int>(r.error().message().size()),
                    r.error().message().data());
        return 1;
    }
    // A path-backed field streams from disk: the bytes never sit in one buffer.
    if (auto r = builder.add_file_field("file", megohttp::string(filename.c_str()),
                                        "application/octet-stream",
                                        megohttp::string(path.c_str()));
        !r) {
        std::printf("add_file_field failed (is %s readable?): %.*s\n", path.c_str(),
                    static_cast<int>(r.error().message().size()),
                    r.error().message().data());
        return 1;
    }
    if (auto r = builder.apply_to(request); !r) {
        std::printf("apply_to failed: %.*s\n",
                    static_cast<int>(r.error().message().size()),
                    r.error().message().data());
        return 1;
    }

    std::printf("uploading %s as '%s' to %s (boundary %.*s)\n", path.c_str(),
                filename.c_str(), url.c_str(),
                static_cast<int>(builder.boundary().size()), builder.boundary().data());

    megohttp::Client client;
    std::atomic<bool> done{false};
    int status = 1;

    client.request(request, [&](megohttp::Result<megohttp::Response> result) {
        if (!result) {
            std::printf("upload failed: %.*s\n",
                        static_cast<int>(result.error().message().size()),
                        result.error().message().data());
        } else {
            const auto& response = result.value();
            std::printf("status %d\n", response.head().status_code);
            const auto body = response.body_text();
            std::printf("%.*s", static_cast<int>(body.size()), body.data());
            status = (response.head().status_code == 200) ? 0 : 1;
        }
        done.store(true);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!done.load()) {
        std::printf("timed out\n");
        return 1;
    }
    return status;
}
