// Example 19 — an HTTPS proxy reaching an HTTPS target, with TWO trust anchors.
//
// Two TLS layers, two identities, two CA configurations:
//
//   ProxyOptions::tls   validates the PROXY (the CONNECT endpoint);
//   ClientOptions::tls  validates the TARGET, inside the tunnel.
//
// They are separate objects on purpose (task book 9.3). This example makes the
// separation visible by giving them different CAs: the proxy certificate is
// signed by the fixture root CA, while the target certificate is signed by the
// fixture intermediate CA. A client that reused one TlsConfig for both would
// fail one of the two handshakes.
//
// Build:  cmake -S . -B build -DMGHTTP_TLS_OPENSSL=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:
//   python tests/gen_tls_fixtures.py tests/tls_fixtures            # once
//   # target: HTTPS server whose leaf is signed by the intermediate CA
//   python tests/https_test_server.py tests/tls_fixtures/intermediate-server-fullchain.pem \
//                                     tests/tls_fixtures/intermediate-server-key.pem
//   # proxy: TLS listener whose leaf is signed by the root CA, CONNECT mode
//   python tests/proxy_test_server.py --mode connect \
//       --tls-cert tests/tls_fixtures/server-cert.pem \
//       --tls-key  tests/tls_fixtures/server-key.pem
//   megohttp_example_https_proxy_to_https --proxy 127.0.0.1:<proxy-port> \
//       --proxy-ca tests/tls_fixtures/ca.pem \
//       --target-ca tests/tls_fixtures/intermediate-ca-chain.pem \
//       https://localhost:<target-port>/
//
// Exit code: 0 on a 200 through both layers.

#include <megohttp/client.hpp>
#include <megohttp/proxy.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    std::string proxy;
    std::string proxy_ca = "tests/tls_fixtures/ca.pem";
    std::string target_ca = "tests/tls_fixtures/intermediate-ca-chain.pem";
    std::string url;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&](const char* what) {
            if (i + 1 >= argc) {
                std::printf("%s needs a value\n", what);
                std::exit(2);
            }
            return std::string(argv[++i]);
        };
        if (arg == "--proxy") {
            proxy = value("--proxy");
        } else if (arg == "--proxy-ca") {
            proxy_ca = value("--proxy-ca");
        } else if (arg == "--target-ca") {
            target_ca = value("--target-ca");
        } else if (arg == "--help" || arg == "-h") {
            std::printf("usage: megohttp_example_https_proxy_to_https --proxy host:port "
                        "[--proxy-ca path] [--target-ca path] https://url\n");
            return 0;
        } else {
            url = arg;
        }
    }
    const auto colon = proxy.rfind(':');
    if (proxy.empty() || colon == std::string::npos || url.empty()) {
        std::printf("--proxy host:port and an https URL are required\n");
        return 2;
    }

    megohttp::ClientOptions options;

    // Layer 1: the proxy.
    options.proxy.proxy.type = megohttp::ProxyType::Https;
    options.proxy.proxy.host = megohttp::string(proxy.substr(0, colon).c_str());
    options.proxy.proxy.port = static_cast<uint16_t>(
        std::strtoul(proxy.substr(colon + 1).c_str(), nullptr, 10));
    options.proxy.tls.ca_file = megohttp::string(proxy_ca.c_str());

    // Layer 2: the target. A different CA file from the proxy's on purpose.
    options.tls.ca_file = megohttp::string(target_ca.c_str());

    megohttp::Client client(std::move(options));
    megohttp::string target(url);
    std::printf("GET %s via HTTPS proxy %s\n  proxy CA  = %s\n  target CA = %s\n",
                url.c_str(), proxy.c_str(), proxy_ca.c_str(), target_ca.c_str());

    const auto result = client.get_sync(megohttp::to_view(target));
    if (!result) {
        std::printf("request failed: %.*s\n",
                    static_cast<int>(result.error().message().size()),
                    result.error().message().data());
        return 1;
    }
    const auto body = result.value().body_text();
    std::printf("status %d, %zu bytes: %.*s\n", result.value().head().status_code,
                body.size(), static_cast<int>(body.size()), body.data());
    return result.value().head().status_code == 200 ? 0 : 1;
}
