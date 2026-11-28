// Example 18 — an HTTPS proxy reaching an HTTP target.
//
// "HTTPS proxy" means the connection to the PROXY is wrapped in TLS; it says
// nothing about the target. For an http:// target the proxy still gets an
// absolute-form request line, just over a TLS-protected connection.
//
// The proxy's certificate is validated with ProxyOptions::tls — a SEPARATE
// TlsConfig from ClientOptions::tls, which still describes the target. Task book
// 9.3 forbids one object driving both identities: a proxy CA that also validated
// targets would silently widen trust.
//
// Build:  cmake -S . -B build -DMGHTTP_TLS_OPENSSL=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/cookie_server.py 8090
//         python tests/proxy_test_server.py --mode forward \
//             --tls-cert tests/tls_fixtures/server-cert.pem \
//             --tls-key  tests/tls_fixtures/server-key.pem     # prints READY <pid> <port>
//         megohttp_example_https_proxy_to_http --proxy 127.0.0.1:<port> \
//             --proxy-ca tests/tls_fixtures/ca.pem http://127.0.0.1:8090/
//
// Exit code: 0 on a 200 through the proxy.

#include <megohttp/client.hpp>
#include <megohttp/proxy.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    std::string proxy;
    std::string proxy_ca = "tests/tls_fixtures/ca.pem";
    std::string url = "http://127.0.0.1:8090/";

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
        } else if (arg == "--help" || arg == "-h") {
            std::printf("usage: megohttp_example_https_proxy_to_http --proxy host:port "
                        "[--proxy-ca path] [http://url]\n");
            return 0;
        } else {
            url = arg;
        }
    }
    const auto colon = proxy.rfind(':');
    if (proxy.empty() || colon == std::string::npos) {
        std::printf("--proxy host:port is required\n");
        return 2;
    }

    megohttp::ClientOptions options;
    options.proxy.proxy.type = megohttp::ProxyType::Https;
    options.proxy.proxy.host = megohttp::string(proxy.substr(0, colon).c_str());
    options.proxy.proxy.port = static_cast<uint16_t>(
        std::strtoul(proxy.substr(colon + 1).c_str(), nullptr, 10));
    // Proxy identity only. ClientOptions::tls stays at its default and is not
    // used for an http:// target.
    options.proxy.tls.ca_file = megohttp::string(proxy_ca.c_str());

    megohttp::Client client(std::move(options));
    megohttp::string target(url);
    std::printf("GET %s through HTTPS proxy %s\n", url.c_str(), proxy.c_str());

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
