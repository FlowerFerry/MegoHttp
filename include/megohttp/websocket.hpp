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
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace megohttp {

    // ---------------------------------------------------------------------
    // Handshake
    // ---------------------------------------------------------------------
    namespace ws_detail {

        // RFC 6455 4.1: the client key is 16 random bytes, base64 encoded.
        //
        // The random source is injectable so a test can pin the exact key and
        // assert the Accept value byte for byte (task book 13.7 asks for a
        // fresh random key per handshake, which is only checkable if the test
        // controls the input). Passing an empty function uses the platform RNG.
        using KeyRandomSource = std::function<void(uint8_t* out, size_t size)>;
        string make_client_key();
        string make_client_key(const KeyRandomSource& rng);

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
            //
            // This is the legacy whole-message path. When
            // wants_incremental_messages() returns true, the decoder calls
            // on_message_begin/data/end instead and never calls on_message.
            virtual VoidResult on_message(WsMessageType type,
                                          const byte_buffer& payload,
                                          bool compressed) {
                (void)type;
                (void)payload;
                (void)compressed;
                return VoidResult{};
            }

            // --- incremental receive (task book 6.6 / 12.1A) ---
            // Return true to opt into begin/data/end delivery. The decoder
            // still does framing and fragmentation; the caller owns
            // decompression and UTF-8 validation.
            virtual bool wants_incremental_messages() const { return false; }
            virtual VoidResult on_message_begin(WsMessageType type, bool compressed) {
                (void)type;
                (void)compressed;
                return VoidResult{};
            }
            // One frame payload (or decompressed chunk, if the caller inflates).
            // Empty payloads are not delivered. The pointer is valid only for
            // this call.
            virtual VoidResult on_message_data(const uint8_t* data, size_t size) {
                (void)data;
                (void)size;
                return VoidResult{};
            }
            virtual VoidResult on_message_end() { return VoidResult{}; }

            // Consumer backpressure. While true, the decoder stops before the
            // next DATA frame; control frames that are already buffered are
            // still delivered so ping/close cannot be starved. feed(nullptr, 0)
            // resumes parsing buffered bytes.
            virtual bool pause_requested() const { return false; }
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

    // ---------------------------------------------------------------------
    // Incremental UTF-8 validation (task book 12.1A).
    //
    // A decompressed message arrives in output chunks whose boundaries fall
    // wherever zlib happened to stop, not on code-point boundaries. Validating
    // the whole message after inflating it works, but only reports an error
    // once the entire payload has been materialised; this validator lets the
    // caller reject a bad message at the chunk that made it bad.
    //
    // Feed arbitrary splits. `complete()` says whether the stream ended on a
    // code-point boundary; a trailing partial sequence is an error at EOF, not
    // before it, because the next chunk may finish it.
    // ---------------------------------------------------------------------
    class WsUtf8Validator {
    public:
        // Returns false as soon as the bytes seen so far cannot be valid UTF-8.
        bool feed(const uint8_t* data, size_t size);

        // True when every fed byte formed complete sequences.
        bool complete() const noexcept { return pending_len_ == 0; }

        void reset() noexcept { pending_len_ = 0; }

    private:
        // Bytes of a sequence that started in an earlier chunk.
        uint8_t pending_[4]{};
        size_t pending_len_{0};
    };


} // namespace megohttp

#include <megohttp/websocket_impl.hpp>

#endif // MEGOHTTP_WEBSOCKET_HPP_INCLUDED
