// Example 14 — WebSocket large message: streaming compression out, incremental
// receive back.
//
// A multi-megabyte message must not be built in one buffer, and on the receive
// side it must not be assembled into one either. Two APIs make that possible:
//
//   send_begin / send_data / send_end   — one logical message, many chunks.
//       Everything (compression, framing, enqueue) happens under the send lock,
//       so the chunks keep their order. The message is bound to the CURRENT
//       physical connection: a disconnect aborts it and send_end reports the
//       error; it is never replayed on a reconnect.
//
//   set_incremental_message_callbacks   — begin / data / end per message, with
//       `data` firing once per frame (that frame's decompressed output when
//       compression is on). Setting any of these suppresses on_message.
//
// Build:  cmake -S . -B build -DMGHTTP_ENABLE_WEBSOCKET=ON \
//              -DMGHTTP_ENABLE_WEBSOCKET_DEFLATE=ON -DMGHTTP_BUILD_EXAMPLES=ON
//         cmake --build build
// Run:    python examples/servers/ws_server.py 8087
//         megohttp_example_ws_deflate_stream ws://127.0.0.1:8087/chat
//
// Exit code: 0 when the echoed byte count matches what was sent.

#include <megohttp/client.hpp>
#include <megohttp/websocket.hpp>
#include <megohttp/websocket_deflate.hpp>
#include <megohttp/websocket_reconnect.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {

constexpr size_t kChunkBytes = 8 * 1024;
constexpr size_t kChunks = 64;                  // 512 KiB before compression
constexpr size_t kMessageBytes = kChunkBytes * kChunks;

} // namespace

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "ws://127.0.0.1:8087/chat";

    megohttp::Client client;
    megohttp::string url(target);

    megohttp::WebSocketOptions ws_options;
    ws_options.enable_deflate = true;
    ws_options.max_message_size = 8 * 1024 * 1024;   // decompressed limit

    megohttp::WebSocketReconnectPolicy policy;

    auto ws = client.open_websocket(megohttp::to_view(url), ws_options, policy);
    if (!ws) {
        std::printf("open_websocket returned no session\n");
        return 1;
    }

    std::atomic<bool> done{false};
    std::atomic<uint64_t> received{0};
    std::atomic<size_t> messages{0};
    std::atomic<bool> send_ok{false};
    int status = 1;

    ws->set_incremental_message_callbacks(
        [&](megohttp::WsMessageType type, bool compressed) {
            messages.fetch_add(1);
            std::printf("message %zu begins: type=%s compressed=%d\n",
                        messages.load(),
                        type == megohttp::WsMessageType::Text ? "text" : "binary",
                        compressed ? 1 : 0);
        },
        [&](const uint8_t*, size_t size) -> bool {
            received.fetch_add(size);
            return true;   // false would request a frame-boundary pause
        },
        [&]() { std::printf("message ends: %llu bytes total\n",
                            static_cast<unsigned long long>(received.load())); });

    ws->on_open([&](const megohttp::Error& error) {
        if (error) {
            std::printf("handshake failed: %.*s\n",
                        static_cast<int>(error.message().size()), error.message().data());
            done.store(true);
            return;
        }
        const auto neg = ws->negotiated_deflate();
        std::printf("open: deflate=%d, sending %zu KiB in %zu chunks\n",
                    neg.enabled ? 1 : 0, kMessageBytes / 1024, kChunks);

        if (auto r = ws->send_begin(megohttp::WsMessageType::Text); !r) {
            std::printf("send_begin failed: %.*s\n",
                        static_cast<int>(r.error().message().size()),
                        r.error().message().data());
            done.store(true);
            return;
        }

        // Highly compressible payload: the wire size is far below 512 KiB, which
        // is exactly why max_message_size bounds the decompressed size.
        std::vector<char> chunk(kChunkBytes, 'a');
        for (size_t i = 0; i < kChunks; ++i) {
            const size_t offset = i * kChunkBytes;
            if (auto r = ws->send_data(reinterpret_cast<const uint8_t*>(chunk.data()),
                                       chunk.size());
                !r) {
                std::printf("send_data failed at chunk %zu: %.*s\n", i,
                            static_cast<int>(r.error().message().size()),
                            r.error().message().data());
                done.store(true);
                return;
            }
            (void)offset;
        }

        if (auto r = ws->send_end([&](const megohttp::Error& e) {
                if (e) {
                    std::printf("send_end failed: %.*s\n",
                                static_cast<int>(e.message().size()), e.message().data());
                } else {
                    send_ok.store(true);
                    std::printf("send_end: message fully written\n");
                }
            });
            !r) {
            std::printf("send_end rejected: %.*s\n",
                        static_cast<int>(r.error().message().size()),
                        r.error().message().data());
        }
    });

    ws->on_error([&](const megohttp::Error& error) {
        std::printf("session error: %.*s\n",
                    static_cast<int>(error.message().size()), error.message().data());
    });

    // Wait for the echo, then close.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < deadline) {
        if (send_ok.load() && received.load() >= kMessageBytes) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    status = (received.load() == kMessageBytes) ? 0 : 1;
    std::printf("summary: sent=%zu bytes, echoed=%llu bytes, match=%d\n", kMessageBytes,
                static_cast<unsigned long long>(received.load()), status == 0 ? 1 : 0);
    ws->close(1000, megohttp::string("done"));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    return status;
}
