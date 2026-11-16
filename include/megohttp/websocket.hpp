#ifndef MEGOHTTP_WEBSOCKET_HPP_INCLUDED
#define MEGOHTTP_WEBSOCKET_HPP_INCLUDED

// ---------------------------------------------------------------------------
// WebSocket protocol pieces (task book 12, phase 6).
//
// This file holds the parts that have real protocol rules and no I/O:
//   - the opening handshake key / Sec-WebSocket-Accept computation
//   - Sec-WebSocket-Extensions / -Protocol header parsing and validation
//   - the frame codec (encode with client mask, decode, fragment reassembly)
//
// The session that owns a connection is a separate concern; keeping the codec
// free of sockets is what makes every framing rule testable byte by byte.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------
    // Handshake
    // ---------------------------------------------------------------------
    namespace ws_detail {

        // RFC 6455 4.1: the client key is 16 random bytes, base64 encoded.
        // The random source is injectable so a test can pin the value.
        string make_client_key();

        // RFC 6455 4.2.2: SHA-1(key + GUID), base64 encoded.
        string accept_key_for(string_view client_key);

        // RFC 6455 4.1: Upgrade and Connection must both contain the required
        // tokens, case-insensitively, and may carry others.
        bool has_token(string_view header_value, string_view token);

        // A client MUST reject a subprotocol it did not offer, and a server may
        // legitimately select none. Distinguished from "offered something and
        // got something else", which is a handshake failure.
        bool subprotocol_was_offered(const std::vector<string>& offered,
                                     string_view selected);

        // True when the response carries a Sec-WebSocket-Extensions entry the
        // client never asked for. RFC 6455 4.1 forbids accepting one.
        bool extensions_unsolicited(const std::vector<string>& requested,
                                    string_view response_value);

    } // namespace ws_detail

    // ---------------------------------------------------------------------
    // Frames
    // ---------------------------------------------------------------------

    enum class WsOpcode : uint8_t {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA,
    };

    enum class WsMessageType { Text, Binary };

    inline bool ws_is_control_opcode(WsOpcode op) noexcept {
        return (static_cast<uint8_t>(op) & 0x8) != 0;
    }

    // A decoded frame. Payload is owned: the decoder produces it from the byte
    // stream and the caller may keep it across calls.
    struct WsFrame {
        bool fin{true};
        bool rsv1{false};
        bool rsv2{false};
        bool rsv3{false};
        WsOpcode opcode{WsOpcode::Text};
        byte_buffer payload;
    };

    // Streaming frame decoder.
    //
    // Feed it raw bytes; it emits whole frames. Every malformed case in
    // RFC 6455 5.4 is a distinct terminal condition rather than a guess:
    // a server frame must not be masked, control frames must be <= 125 bytes
    // and must not be fragmented, continuation frames must follow a data frame.
    class WsFrameDecoder {
    public:
        struct Limits {
            size_t max_frame_bytes{1 * 1024 * 1024};
            size_t max_message_bytes{16 * 1024 * 1024};
        };

        struct Callbacks {
            virtual ~Callbacks() = default;
            // A control frame. Ping/Pong/Close are surfaced as they arrive: a
            // fragmented message must not swallow them.
            virtual VoidResult on_control(const WsFrame& frame) = 0;
            // One complete data message (fragments already reassembled).
            // `compressed` is the RSV1 bit of the FIRST frame, i.e. whether the
            // payload still needs permessage-deflate decoding. The decoder does
            // not decompress: it has no negotiation context, and inflating
            // before UTF-8 validation would validate the wrong bytes.
            virtual VoidResult on_message(WsMessageType type,
                                          const byte_buffer& payload,
                                          bool compressed) = 0;
        };

        WsFrameDecoder(Callbacks& cbs, Limits limits = {});
        ~WsFrameDecoder();

        WsFrameDecoder(const WsFrameDecoder&) = delete;
        WsFrameDecoder& operator=(const WsFrameDecoder&) = delete;

        VoidResult feed(const uint8_t* data, size_t size);

        // True once a protocol violation was reported; the connection must be
        // torn down (the byte stream position is no longer trustworthy).
        bool is_failed() const noexcept;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    // Encodes a client frame: always masked, per RFC 6455 5.3.
    // `mask` of 0 means "generate one".
    void ws_encode_frame(byte_buffer& out, WsOpcode opcode, const uint8_t* payload,
                         size_t size, bool fin, bool rsv1, uint32_t mask = 0);

    // UTF-8 validation over a whole message, so a multi-byte sequence split
    // across fragments is still judged correctly. Returns false on invalid
    // input; this is what RFC 6455 8.1 requires before delivering text.
    bool ws_is_valid_utf8(const uint8_t* data, size_t size);

    // Length of the truncated UTF-8 tail, i.e. the bytes at the end that begin
    // a sequence which has not completed yet. Used for incremental validation
    // across fragments.
    size_t ws_utf8_incomplete_tail(const uint8_t* data, size_t size);

} // namespace megohttp

#include <megohttp/websocket_impl.hpp>

#endif // MEGOHTTP_WEBSOCKET_HPP_INCLUDED
