// Example 22 — DNS over HTTPS (DoH, RFC 8484).
//
// DohResolver sends DNS wire-format messages inside an HTTPS request (POST by
// default, GET with ?dns= is supported too) and parses the answer back. Like
// DotResolver it is a Resolver, so it can be handed to ClientOptions::resolver.
//
// The endpoint is a full URL and the TLS identity comes from that URL's host,
// so TlsConfig::hostname is set explicitly here: a bootstrap IP only changes
// which address is dialled, never the name that is verified.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_DOH=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
//
// Offline run against the bundled fixture (prints "READY <pid> <port>").
// The fixture answers the names in its own table, e.g. dual.example,
// a-only.example, aaaa-only.example; anything else is NXDOMAIN.
//   python tests/gen_tls_fixtures.py tests/tls_fixtures          # once
//   python tests/doh_test_server.py --cert tests/tls_fixtures/server-cert.pem \
//                                   --key  tests/tls_fixtures/server-key.pem
//   megohttp_example_doh_resolve --port <port> dual.example
//
// Public resolver (needs internet):
//   megohttp_example_doh_resolve --endpoint cloudflare-dns.com \
//                                --bootstrap 1.1.1.1 --ca "" example.com
//
// Exit code: 0 when the name resolved, 1 otherwise.

#include <megohttp/client.hpp>
#include <megohttp/resolver_doh.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

namespace {

void usage() {
    std::printf(
        "usage: megohttp_example_doh_resolve [options] <name>\n"
        "  --endpoint <host>    certificate identity / SNI   (default localhost)\n"
        "  --bootstrap <ip>     numeric address to dial      (default 127.0.0.1)\n"
        "  --port <n>           HTTPS port                    (default 443)\n"
        "  --path <p>           request path                  (default /dns-query)\n"
        "  --ca <path>          CA file; empty = system store (default tests/tls_fixtures/ca.pem)\n"
        "  --get                use GET instead of POST\n");
}

} // namespace

int main(int argc, char** argv) {
    std::string endpoint = "localhost";
    std::string bootstrap = "127.0.0.1";
    std::string ca = "tests/tls_fixtures/ca.pem";
    std::string query = "example.com";
    std::string path = "/dns-query";
    unsigned port = 443;
    bool use_get = false;

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
        } else if (arg == "--path") {
            path = value("--path");
        } else if (arg == "--ca") {
            ca = value("--ca");
        } else if (arg == "--get") {
            use_get = true;
        } else if (arg == "--help" || arg == "-h") {
            usage();
            return 0;
        } else {
            query = arg;
        }
    }

    megohttp::DohOptions options;
    const std::string url = "https://" + endpoint + ":" + std::to_string(port) + path;
    options.endpoint_url = megohttp::string(url.c_str());
    options.bootstrap_ip = megohttp::string(bootstrap.c_str());
    options.method = use_get ? megohttp::DohMethod::Get : megohttp::DohMethod::Post;
    // DohOptions::tls is optional: std::nullopt means "use the defaults", and
    // the endpoint's host is what gets verified, so it must be set here.
    megohttp::TlsConfig tls;
    tls.hostname = megohttp::string(endpoint.c_str());
    if (!ca.empty()) tls.ca_file = megohttp::string(ca.c_str());
    options.tls = std::move(tls);
    options.connect_timeout = std::chrono::seconds(5);
    options.request_timeout = std::chrono::seconds(10);
    options.total_timeout = std::chrono::seconds(15);

    auto executor = megohttp::detail::make_default_executor();
    if (!executor) {
        std::printf("no backend available\n");
        return 1;
    }

    auto resolver = std::make_shared<megohttp::DohResolver>(executor, options);
    std::printf("resolving %s over DoH (%s %s)\n", query.c_str(),
                use_get ? "GET" : "POST", url.c_str());

    std::atomic<bool> done{false};
    megohttp::Result<megohttp::AddressList> answer = megohttp::Error{megohttp::ErrorCode::Unknown};

    resolver->resolve(megohttp::string(query.c_str()), 443,
                      [&](megohttp::Result<megohttp::AddressList> result) {
                          answer = std::move(result);
                          done.store(true);
                      });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
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
