// Example 21 — DNS over TLS (DoT, RFC 7858).
//
// DotResolver is an ordinary Resolver, so it plugs into ClientOptions::resolver
// as a drop-in replacement for the system resolver. It owns a TCP+TLS stream to
// the DoT endpoint and speaks DNS wire format over it.
//
// Two settings matter for a first run:
//   • server_name is the identity in the certificate (SNI), NOT an address;
//   • bootstrap_ip is the numeric address actually dialled. With it set the
//     lookup never touches system DNS — that is the default, strict behaviour.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_DOT=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
//
// Offline run against the bundled fixture (prints "READY <pid> <port>"):
//   python tests/gen_tls_fixtures.py tests/tls_fixtures          # once
//   python tests/dot_test_server.py --cert tests/tls_fixtures/server-cert.pem \
//                                   --key  tests/tls_fixtures/server-key.pem
//   megohttp_example_dot_resolve --port <port> example.com
//
// Public resolver (needs internet and its own trust chain):
//   megohttp_example_dot_resolve --endpoint dns.quad9.net --bootstrap 9.9.9.9 \
//                                --port 853 --ca "" example.com
//
// Exit code: 0 when the name resolved, 1 otherwise.

#include <megohttp/client.hpp>
#include <megohttp/resolver_dot.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

namespace {

void usage() {
    std::printf(
        "usage: megohttp_example_dot_resolve [options] <name>\n"
        "  --endpoint <host>    certificate identity / SNI   (default localhost)\n"
        "  --bootstrap <ip>     numeric address to dial      (default 127.0.0.1)\n"
        "  --port <n>           DoT port                      (default 853)\n"
        "  --ca <path>          CA file; empty = system store (default tests/tls_fixtures/ca.pem)\n");
}

} // namespace

int main(int argc, char** argv) {
    std::string endpoint = "localhost";
    std::string bootstrap = "127.0.0.1";
    std::string ca = "tests/tls_fixtures/ca.pem";
    std::string query = "example.com";
    unsigned port = 853;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::printf("%s needs a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "--endpoint") {
            endpoint = value("--endpoint");
        } else if (arg == "--bootstrap") {
            bootstrap = value("--bootstrap");
        } else if (arg == "--port") {
            port = static_cast<unsigned>(std::strtoul(value("--port").c_str(), nullptr, 10));
        } else if (arg == "--ca") {
            ca = value("--ca");
        } else if (arg == "--help" || arg == "-h") {
            usage();
            return 0;
        } else {
            query = arg;
        }
    }

    megohttp::DotOptions options;
    options.server_name = megohttp::string(endpoint.c_str());
    options.bootstrap_ip = megohttp::string(bootstrap.c_str());
    options.port = static_cast<uint16_t>(port);
    if (!ca.empty()) options.tls.ca_file = megohttp::string(ca.c_str());
    options.connect_timeout = std::chrono::seconds(5);

    auto executor = megohttp::detail::make_default_executor();
    if (!executor) {
        std::printf("no backend available\n");
        return 1;
    }

    auto resolver = std::make_shared<megohttp::DotResolver>(executor, options);
    std::printf("resolving %s over DoT via %s:%u (bootstrap %s)\n",
                query.c_str(), endpoint.c_str(), port, bootstrap.c_str());

    std::atomic<bool> done{false};
    megohttp::Result<megohttp::AddressList> answer = megohttp::Error{megohttp::ErrorCode::Unknown};

    resolver->resolve(megohttp::string(query.c_str()), 443,
                      [&](megohttp::Result<megohttp::AddressList> result) {
                          answer = std::move(result);
                          done.store(true);
                      });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    megohttp::detail::shutdown_executor(executor);

    if (!done.load()) {
        std::printf("timed out\n");
        return 1;
    }
    if (!answer) {
        std::printf("resolve failed: %.*s\n",
                    static_cast<int>(answer.error().message().size()),
                    answer.error().message().data());
        return 1;
    }
    for (const auto& address : answer.value()) {
        std::printf("  %.*s port %u (%s)\n",
                    static_cast<int>(address.text.size()), address.text.data(),
                    static_cast<unsigned>(address.port),
                    address.family == megohttp::ResolvedAddress::Family::IPv4 ? "IPv4" : "IPv6");
    }
    return answer.value().empty() ? 1 : 0;
}
