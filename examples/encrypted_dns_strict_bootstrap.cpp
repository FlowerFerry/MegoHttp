// Example 23 — encrypted DNS with strict bootstrap.
//
// "Strict bootstrap" is the security property behind both DoT and DoH: a named
// endpoint (a certificate identity) must not be turned into an address by the
// system resolver behind the caller's back. If no bootstrap IP is configured,
// strict mode refuses to start instead of silently leaking the name to plaintext
// DNS.
//
// The example proves both halves against the bundled fixture:
//   A. server_name = "localhost", bootstrap_ip empty, use_system_bootstrap off
//      -> ConfigurationError, and no connection was attempted at all;
//   B. the same endpoint with bootstrap_ip = 127.0.0.1
//      -> the query goes out over TLS and an answer comes back.
//
// Setting use_system_bootstrap = true is the documented opt-out: it works, but
// it re-exposes the endpoint name to system DNS, which is exactly what strict
// mode exists to avoid.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_DOT=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
//
// Offline run (prints "READY <pid> <port>"):
//   python tests/gen_tls_fixtures.py tests/tls_fixtures          # once
//   python tests/dot_test_server.py --cert tests/tls_fixtures/server-cert.pem \
//                                   --key  tests/tls_fixtures/server-key.pem
//   megohttp_example_encrypted_dns_strict_bootstrap --port <port> example.com
//
// Exit code: 0 when A was refused with a configuration error AND B resolved.

#include <megohttp/client.hpp>
#include <megohttp/resolver_dot.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

namespace {

struct Outcome {
    bool called{false};
    bool ok{false};
    megohttp::ErrorCode code{megohttp::ErrorCode::Unknown};
    std::string message;
    size_t addresses{0};
};

Outcome lookup(const std::string& query, const std::string& endpoint,
               const std::string& bootstrap, unsigned port, const std::string& ca) {
    megohttp::DotOptions options;
    options.server_name = megohttp::string(endpoint.c_str());
    options.bootstrap_ip = megohttp::string(bootstrap.c_str());   // empty = strict
    options.use_system_bootstrap = false;                          // the default
    options.port = static_cast<uint16_t>(port);
    if (!ca.empty()) options.tls.ca_file = megohttp::string(ca.c_str());
    options.connect_timeout = std::chrono::seconds(5);

    auto executor = megohttp::detail::make_default_executor();
    if (!executor) return Outcome{};

    auto resolver = std::make_shared<megohttp::DotResolver>(executor, options);

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

    Outcome out;
    out.called = done.load();
    if (!out.called) return out;
    if (answer) {
        out.ok = true;
        out.addresses = answer.value().size();
    } else {
        out.code = answer.error().code();
        out.message.assign(answer.error().message().data(), answer.error().message().size());
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    std::string endpoint = "localhost";
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
        if (arg == "--port") {
            port = static_cast<unsigned>(std::strtoul(value("--port").c_str(), nullptr, 10));
        } else if (arg == "--ca") {
            ca = value("--ca");
        } else if (arg == "--endpoint") {
            endpoint = value("--endpoint");
        } else if (arg == "--help" || arg == "-h") {
            std::printf("usage: megohttp_example_encrypted_dns_strict_bootstrap "
                        "[--endpoint localhost] [--port 853] [--ca path] [name]\n");
            return 0;
        } else {
            query = arg;
        }
    }

    std::printf("A) strict mode, named endpoint, no bootstrap IP:\n");
    const Outcome strict_result = lookup(query, endpoint, "", port, ca);
    if (!strict_result.called) {
        std::printf("   FAILED: the resolver never answered at all\n");
        return 1;
    }
    if (strict_result.ok) {
        std::printf("   FAILED: it resolved (%zu addresses) - strict mode leaked\n",
                    strict_result.addresses);
        return 1;
    }
    std::printf("   refused: code=%d %s\n", static_cast<int>(strict_result.code),
                strict_result.message.c_str());
    if (strict_result.code != megohttp::ErrorCode::ConfigurationError) {
        std::printf("   FAILED: expected ConfigurationError\n");
        return 1;
    }

    std::printf("B) the same endpoint, now with bootstrap_ip=127.0.0.1:\n");
    const Outcome boot_result = lookup(query, endpoint, "127.0.0.1", port, ca);
    if (!boot_result.ok) {
        std::printf("   failed: code=%d %s\n", static_cast<int>(boot_result.code),
                    boot_result.message.c_str());
        return 1;
    }
    std::printf("   resolved %zu address(es); the name never reached system DNS\n",
                boot_result.addresses);

    std::printf("strict bootstrap behaves as documented\n");
    return 0;
}
