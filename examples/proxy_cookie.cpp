// Example 17 — proxy routing (HTTP forward / SOCKS5) with a cookie jar.
//
// Two independent pieces that are usually needed together:
//
//   ProxyOptions::proxy  routes the CONNECTION. `Http` is a cleartext forward
//       proxy: an http:// target is sent in absolute form over the proxy's own
//       connection. `Socks5` is RFC 1928 and works for any target; by default the
//       target NAME goes to the proxy (socks5_remote_dns = true), so local DNS is
//       not consulted.
//
//   ClientOptions::cookie_jar  is the cookie store. Null means cookies are off
//       (no Cookie header is sent, no Set-Cookie is stored). Sharing one jar
//       across Clients is the normal case, which is why it is a shared_ptr and
//       not a bool plus an owned container.
//
// The example logs in, then asks for /me: the target echoes the Cookie header it
// received, which proves the jar stored the Set-Cookie and replayed it through
// the proxy.
//
// Build:  cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON && cmake --build build
// Run:    python examples/servers/cookie_server.py 8090
//         python tests/proxy_test_server.py --mode forward        # prints READY <pid> <port>
//         megohttp_example_proxy_cookie --proxy 127.0.0.1:<proxy-port> \
//             http://127.0.0.1:8090
//   or, through SOCKS5:
//         python tests/proxy_test_server.py --mode socks5
//         megohttp_example_proxy_cookie --proxy 127.0.0.1:<proxy-port> \
//             --type socks5 http://127.0.0.1:8090
//
// Exit code: 0 when the second response contains the stored cookie.

#include <megohttp/client.hpp>
#include <megohttp/cookie.hpp>
#include <megohttp/proxy.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

namespace {

std::string body_of(const megohttp::Response& response) {
    const auto view = response.body_text();
    return std::string(view.data(), view.size());
}

} // namespace

int main(int argc, char** argv) {
    std::string proxy;
    std::string base;
    std::string type = "http";

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
        } else if (arg == "--type") {
            type = value("--type");
        } else if (arg == "--help" || arg == "-h") {
            std::printf("usage: megohttp_example_proxy_cookie --proxy host:port "
                        "[--type http|socks5] [http://host:port]\n");
            return 0;
        } else {
            base = arg;
        }
    }
    if (base.empty()) base = "http://127.0.0.1:8090";
    if (proxy.empty()) {
        std::printf("--proxy host:port is required (start tests/proxy_test_server.py)\n");
        return 2;
    }

    const auto colon = proxy.rfind(':');
    if (colon == std::string::npos) {
        std::printf("--proxy must be host:port\n");
        return 2;
    }
    const std::string proxy_host = proxy.substr(0, colon);
    const unsigned proxy_port =
        static_cast<unsigned>(std::strtoul(proxy.substr(colon + 1).c_str(), nullptr, 10));

    megohttp::ClientOptions options;
    options.proxy.proxy.type = (type == "socks5") ? megohttp::ProxyType::Socks5
                                                  : megohttp::ProxyType::Http;
    options.proxy.proxy.host = megohttp::string(proxy_host.c_str());
    options.proxy.proxy.port = static_cast<uint16_t>(proxy_port);
    options.cookie_jar = std::make_shared<megohttp::CookieJar>();

    megohttp::Client client(std::move(options));

    auto fetch = [&](const std::string& path) -> megohttp::Result<megohttp::Response> {
        megohttp::string url(base + path);
        std::printf("GET %s (proxy %s, %s)\n", url.c_str(), proxy.c_str(), type.c_str());
        return client.get_sync(megohttp::to_view(url));
    };

    auto login = fetch("/login");
    if (!login) {
        std::printf("login failed: %.*s\n", static_cast<int>(login.error().message().size()),
                    login.error().message().data());
        return 1;
    }
    std::printf("  login: status %d\n", login.value().head().status_code);

    auto me = fetch("/me");
    if (!me) {
        std::printf("/me failed: %.*s\n", static_cast<int>(me.error().message().size()),
                    me.error().message().data());
        return 1;
    }
    const std::string body = body_of(me.value());
    std::printf("  /me: status %d, body: %s", me.value().head().status_code, body.c_str());
    return body.find("session=demo123") != std::string::npos ? 0 : 1;
}
