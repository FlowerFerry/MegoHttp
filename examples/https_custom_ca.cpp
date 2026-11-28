// Example 6 — HTTPS with a custom CA.
//
// The default TLS configuration uses the platform trust store. A private CA (a
// test fixture, an internal service, a pinned root) is supplied per layer via
// TlsConfig: `ca_file` replaces the default store for THIS layer only, and
// `hostname` is the identity that gets verified — never a bootstrap address.
//
// Deliberately not shown: verify_peer = false. Turning verification off is
// available, but an example that disables it teaches the wrong habit; the way to
// make a self-signed endpoint work is to trust its CA.
//
// Build:  cmake -S . -B build -DMGHTTP_TLS_OPENSSL=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
//
// Offline run against the bundled TLS fixture (prints "READY <pid> <port>"):
//   python tests/gen_tls_fixtures.py tests/tls_fixtures        # once
//   python tests/tls_test_server.py tests/tls_fixtures/server-cert.pem \
//                                    tests/tls_fixtures/server-key.pem
//   megohttp_example_https_custom_ca --port <port>
//
// Public host with the system trust store (needs internet):
//   megohttp_example_https_custom_ca --ca "" https://example.com/
//
// Exit code: 0 on a 200 response, 1 otherwise.

#include <megohttp/client.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    std::string url;
    std::string ca = "tests/tls_fixtures/ca.pem";
    std::string hostname;
    unsigned port = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::printf("%s needs a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "--port") {
            port = static_cast<unsigned>(std::strtoul(value("--port").c_str(), nullptr, 10));
        } else if (arg == "--ca") {
            ca = value("--ca");
        } else if (arg == "--hostname") {
            hostname = value("--hostname");
        } else if (arg == "--help" || arg == "-h") {
            std::printf("usage: megohttp_example_https_custom_ca "
                        "[--port n] [--ca path] [--hostname name] [url]\n");
            return 0;
        } else {
            url = arg;
        }
    }
    if (url.empty()) {
        if (port == 0) port = 443;
        url = "https://localhost:" + std::to_string(port) + "/";
    }

    megohttp::ClientOptions options;
    if (!ca.empty()) options.tls.ca_file = megohttp::string(ca.c_str());
    if (!hostname.empty()) options.tls.hostname = megohttp::string(hostname.c_str());

    megohttp::Client client(std::move(options));
    megohttp::string target(url);

    std::printf("GET %s (ca=%s)\n", url.c_str(),
                ca.empty() ? "system trust store" : ca.c_str());

    std::atomic<bool> done{false};
    int status = 1;

    client.get(megohttp::to_view(target), [&](megohttp::Result<megohttp::Response> result) {
        if (!result) {
            const auto& error = result.error();
            std::printf("request failed: code=%d %.*s\n",
                        static_cast<int>(error.code()),
                        static_cast<int>(error.message().size()),
                        error.message().data());
        } else {
            std::printf("status %d, %zu body bytes\n",
                        result.value().head().status_code,
                        static_cast<size_t>(result.value().body_bytes().size()));
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
    return status;
}
