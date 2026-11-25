#ifndef MEGOHTTP_WEBSOCKET_DEFLATE_HPP
#define MEGOHTTP_WEBSOCKET_DEFLATE_HPP

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>


#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// zlib is needed for permessage-deflate. The MEGOHTTP_HAS_WEBSOCKET_DEFLATE
// macro is true only when the feature is enabled AND zlib is available. The
// session-level check at websocket_session_impl.hpp refuses enable_deflate at
// runtime when this macro is false, turning a link error into a hard error.
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
#   include <zlib.h>
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

// Everything below needs zlib, so it exists only when the feature is compiled
// in. The two POD structs above stay unconditional: WebSocketOptions holds a
// DeflateOptions by value and must remain a complete type even in a build that
// disabled the feature (a preprocessor-gated member would break every user that
// names the struct). MEGOHTTP_HAS_WEBSOCKET_DEFLATE == 0 means "not compiled",
// and websocket_session_impl.hpp rejects enable_deflate at start() with
// WsCompressionNotCompiled, so nothing can reach these symbols.
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE

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

    // Incremental form for ONE RFC 7692 message (task book 6.6 / 12.1A).
    //
    //   begin_message()
    //   compress_chunk(data, size)  0..n times
    //   end_message()
    //
    // compress_chunk() returns whatever zlib has produced so far, which may
    // be empty; end_message() flushes with Z_SYNC_FLUSH and removes the
    // trailing 0x00 0x00 0xFF 0xFF. The caller sends the returned bytes as
    // one or more WebSocket frames; frame boundaries inside a compressed
    // message are not significant to the receiver.
    //
    // These calls are not thread-safe on their own: WebSocketSession
    // serializes them with its send mutex. begin_message() must be paired
    // with end_message(); an aborted message leaves the zlib context in an
    // undefined position and requires closing the connection.
    VoidResult begin_message();
    Result<std::vector<uint8_t>> compress_chunk(const uint8_t* data, size_t size);
    Result<std::vector<uint8_t>> end_message();
    bool message_open() const noexcept;

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

    // Decompress one message, handing each output chunk to `on_chunk` as it is
    // produced instead of returning one buffer. This is what lets the caller
    // validate UTF-8, enforce limits and deliver incrementally while the
    // payload is still being inflated (task book 12.1A).
    //
    // `on_chunk` returns false to abort: the message is then reported as
    // WsCompressionResourceExceeded if the cap was hit, otherwise the caller's
    // own error is expected to have been recorded. A complete message produces
    // no trailing empty chunk.
    using ChunkSink = std::function<bool(const uint8_t* data, size_t size)>;
    VoidResult decompress_streaming(const std::vector<uint8_t>& input,
                                    size_t max_output_bytes,
                                    const ChunkSink& on_chunk);

    // Incremental receive form (task book 6.6 / 12.1A). begin_message(),
    // decompress_chunk() 0..n times, end_message(). The caller feeds the
    // compressed bytes of each frame as they arrive; end_message() appends the
    // RFC 7692 0x00 0x00 0xFF 0xFF tail and returns the final output.
    //
    // max_output_bytes is a cap for THIS call, not the whole message; the
    // caller passes the remaining message budget. A cap breach is reported as
    // WsCompressionResourceExceeded before the output is materialised.
    VoidResult begin_message();
    Result<std::vector<uint8_t>> decompress_chunk(const uint8_t* data, size_t size,
                                                  size_t max_output_bytes);
    Result<std::vector<uint8_t>> end_message(size_t max_output_bytes);
    bool message_open() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#endif // MEGOHTTP_HAS_WEBSOCKET_DEFLATE

} // namespace megohttp

// The implementation is compiled only when MEGOHTTP_HAS_WEBSOCKET_DEFLATE holds
// (feature enabled AND zlib available). A build with ENABLE_WEBSOCKET_DEFLATE=OFF
// must not compile the DEFLATE code at all (task book 3.21: an explicitly
// disabled feature must not keep its dependency), even when zlib is present for
// HTTP gzip.
#if MEGOHTTP_HAS_WEBSOCKET_DEFLATE
#include <megohttp/websocket_deflate_impl.hpp>
#endif

#endif // MEGOHTTP_WEBSOCKET_DEFLATE_HPP
