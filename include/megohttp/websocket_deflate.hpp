#ifndef MEGOHTTP_WEBSOCKET_DEFLATE_HPP
#define MEGOHTTP_WEBSOCKET_DEFLATE_HPP

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#if MEGOHTTP_HAS_ZLIB
#include <zlib.h>
#endif

namespace megohttp {

// permessage-deflate configuration (RFC 7692)
struct DeflateOptions {
    bool enabled = false;
    int server_max_window_bits = 15;  // 8-15
    int client_max_window_bits = 15;  // 8-15
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
};

// Negotiated parameters after handshake
struct DeflateNegotiated {
    bool enabled = false;
    int server_window_bits = 15;
    int client_window_bits = 15;
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
};

// Parse Sec-WebSocket-Extensions header for permessage-deflate offers
// Returns nullopt if not offered or malformed
std::optional<DeflateOptions> parse_deflate_offer(const Headers& headers);

// Build Sec-WebSocket-Extensions response header from negotiated parameters
string build_deflate_response(const DeflateNegotiated& params);

// Compress a WebSocket message payload using permessage-deflate
// - Appends 0x00 0x00 0xFF 0xFF tail (RFC 7692 §7.2.1)
// - Uses Z_SYNC_FLUSH
// - Returns compressed bytes
class DeflateCompressor {
public:
    DeflateCompressor(const DeflateNegotiated& params);
    ~DeflateCompressor();

    // Compress one message
    // If no_context_takeover is true, resets state after each message
    std::vector<uint8_t> compress(const std::vector<uint8_t>& input);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Decompress a WebSocket message payload using permessage-deflate
// - Strips 0x00 0x00 0xFF 0xFF tail before decompression
// - Uses Z_SYNC_FLUSH
// - Returns decompressed bytes
//
// `max_output_bytes` is enforced INCREMENTALLY, inside the inflate loop: the
// output buffer grows only up to that cap and the call fails with
// WsCompressionResourceExceeded as soon as the cap would be passed. Passing 0
// disables the cap, which no caller inside this library does -- a compressed
// message is attacker-controlled input and an unbounded inflate is a
// decompression bomb (task book 12.1A).
class DeflateDecompressor {
public:
    DeflateDecompressor(const DeflateNegotiated& params);
    ~DeflateDecompressor();

    // Decompress one message
    // If no_context_takeover is true, resets state after each message
    Result<std::vector<uint8_t>> decompress(const std::vector<uint8_t>& input,
                                            size_t max_output_bytes);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace megohttp

#if MEGOHTTP_HAS_ZLIB
#include <megohttp/websocket_deflate_impl.hpp>
#endif

#endif // MEGOHTTP_WEBSOCKET_DEFLATE_HPP
