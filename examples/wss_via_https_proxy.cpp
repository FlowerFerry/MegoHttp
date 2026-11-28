// Example 20 — WSS through an HTTPS proxy, with permessage-deflate on.
//
// The full stack: TLS to the proxy → CONNECT tunnel → TLS to the target →
// WebSocket Upgrade → permessage-deflate. Each layer keeps its own trust
// configuration:
//
//   ProxyOptions::tls          proxy certificate
//   ClientOptions::tls         target certificate (inside the tunnel)
//   WebSocketOptions::enable_deflate   the extension offer
//
// Client::open_websocket() runs the whole connect + tunnel + handshake path with
// the Client's options, so the security policy is the same one an https://
// request would use. The tunnel is a byte stream: nothing about it is
// WebSocket-aware.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_WEBSOCKET=ON \
//              -DMGHTTP_ENABLE_WEBSOCKET_DEFLATE=ON -DMGHTTP_TLS_OPENSSL=ON \
//              -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:
//   python tests/gen_tls_fixtures.py tests/tls_fixtures            # once
//   # WSS target (TLS listener), deflate enabled
//   python examples/servers/ws_server.py 8091 \
//       --cert tests/tls_fixtures/server-cert.pem \
//       --key  tests/tls_fixtures/server-key.pem
//   # HTTPS proxy in CONNECT mode
//   python tests/proxy_test_server.py --mode connect \
//       --tls-cert tests/tls_fixtures/server-cert.pem \
//       --tls-key  tests/tls_fixtures/server-key.pem
//   megohttp_example_wss_via_https_proxy --proxy 127.0.0.1:<proxy-port> \
//       --proxy-ca tests/tls_fixtures/ca.pem \
//       --target-ca tests/tls_fixtures/ca.pem \
//       wss://localhost:8091/chat
//
// Exit code: 0 when the handshake succeeded, deflate was negotiated and the echo
// came back.

#include <megohttp/client.hpp>
#include <megohttp/proxy.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/websocket_deflate.hpp>
#include <megohttp/websocket_reconnect.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    std::string proxy;
    std::string proxy_ca = "tests/tls_fixtures/ca.pem";
    std::string target_ca = "tests/tls_fixtures/ca.pem";
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
            std::printf("usage: megohttp_example_wss_via_https_proxy --proxy host:port "
                        "[--proxy-ca path] [--target-ca path] wss://url\n");
            return 0;
        } else {
            url = arg;
        }
    }
    const auto colon = proxy.rfind(':');
    if (proxy.empty() || colon == std::string::npos || url.empty()) {
        std::printf("--proxy host:port and a wss:// URL are required\n");
        return 2;
    }

    megohttp::ClientOptions options;
    options.proxy.proxy.type = megohttp::ProxyType::Https;
    options.proxy.proxy.host = megohttp::string(proxy.substr(0, colon).c_str());
    options.proxy.proxy.port = static_cast<uint16_t>(
        std::strtoul(proxy.substr(colon + 1).c_str(), nullptr, 10));
    options.proxy.tls.ca_file = megohttp::string(proxy_ca.c_str());
    options.tls.ca_file = megohttp::string(target_ca.c_str());

    megohttp::Client client(std::move(options));
    megohttp::string target(url);

    megohttp::WebSocketOptions ws_options;
    ws_options.enable_deflate = true;
    ws_options.max_message_size = 4 * 1024 * 1024;
    megohttp::WebSocketReconnectPolicy policy;

    std::printf("WSS %s through HTTPS proxy %s\n", url.c_str(), proxy.c_str());
    auto ws = client.open_websocket(megohttp::to_view(target), ws_options, policy);
    if (!ws) {
        std::printf("open_websocket returned no session\n");
        return 1;
    }

    std::atomic<bool> done{false};
    std::atomic<bool> negotiated{false};
    std::atomic<bool> echoed{false};

    ws->on_open([&](const megohttp::Error& error) {
        if (error) {
            std::printf("handshake failed: %.*s\n",
                        static_cast<int>(error.message().size()), error.message().data());
            done.store(true);
            return;
        }
        const auto neg = ws->negotiated_deflate();
        negotiated.store(neg.enabled);
        std::printf("open through the tunnel: deflate=%d%s\n", neg.enabled ? 1 : 0,
                    neg.enabled ? "" : " (not negotiated)");
        ws->send_text(megohttp::string("wss through an https proxy"));
    });

    ws->on_message([&](megohttp::WsMessageType, const std::vector<uint8_t>& payload) {
        std::printf("echo: %.*s\n", static_cast<int>(payload.size()),
                    reinterpret_cast<const char*>(payload.data()));
        echoed.store(true);
        ws->close(1000, megohttp::string("done"));
    });

    ws->on_close([&](uint16_t code, const megohttp::string& reason) {
        std::printf("closed code=%u reason=%.*s\n", static_cast<unsigned>(code),
                    static_cast<int>(reason.size()), reason.data());
        done.store(true);
    });

    ws->on_error([&](const megohttp::Error& error) {
        std::printf("session error: %.*s\n",
                    static_cast<int>(error.message().size()), error.message().data());
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!done.load()) {
        std::printf("timed out\n");
        return 1;
    }
    return (negotiated.load() && echoed.load()) ? 0 : 1;
}
