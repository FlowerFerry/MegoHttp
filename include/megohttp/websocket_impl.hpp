#ifndef MEGOHTTP_WEBSOCKET_IMPL_HPP_INCLUDED
#define MEGOHTTP_WEBSOCKET_IMPL_HPP_INCLUDED

#include <megohttp/websocket.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstring>
#include <random>

namespace megohttp {

    using detail::ascii_iequals;
    using detail::sb_append;
    using detail::sb_release;

    // ---------------------------------------------------------------------
    // SHA-1 (RFC 3174) + Base64 (RFC 4648)
    //
    // Both are needed only for the handshake accept value, and pulling in a
    // crypto dependency for one 20-byte digest would be worse than 40 lines of
    // well-tested arithmetic. This is NOT exposed as a general hash.
    // ---------------------------------------------------------------------
    namespace ws_detail {

        struct Sha1State {
            uint32_t h[5]{0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                          0xC3D2E1F0u};
            uint64_t total_len{0};
            uint8_t block[64]{};
            size_t block_len{0};

            static uint32_t rol(uint32_t v, int n) {
                return (v << n) | (v >> (32 - n));
            }

            void process_block(const uint8_t* p) {
                uint32_t w[80];
                for (int i = 0; i < 16; ++i) {
                    w[i] = (static_cast<uint32_t>(p[i * 4]) << 24) |
                           (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
                           (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
                           static_cast<uint32_t>(p[i * 4 + 3]);
                }
                for (int i = 16; i < 80; ++i) {
                    w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
                }

                uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
                for (int i = 0; i < 80; ++i) {
                    uint32_t f, k;
                    if (i < 20) {
                        f = (b & c) | (~b & d);
                        k = 0x5A827999u;
                    } else if (i < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1u;
                    } else if (i < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDCu;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6u;
                    }
                    const uint32_t tmp = rol(a, 5) + f + e + k + w[i];
                    e = d;
                    d = c;
                    c = rol(b, 30);
                    b = a;
                    a = tmp;
                }
                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            void update(const uint8_t* data, size_t size) {
                total_len += size;
                for (size_t i = 0; i < size; ++i) {
                    block[block_len++] = data[i];
                    if (block_len == 64) {
                        process_block(block);
                        block_len = 0;
                    }
                }
            }

            void finish(uint8_t out[20]) {
                const uint64_t bit_len = total_len * 8;
                // Padding: 0x80, then zeros, then the 64-bit length.
                uint8_t pad = 0x80;
                update(&pad, 1);
                const uint8_t zero = 0;
                while (block_len != 56) update(&zero, 1);
                uint8_t len_be[8];
                for (int i = 0; i < 8; ++i) {
                    len_be[i] = static_cast<uint8_t>(bit_len >> (56 - i * 8));
                }
                update(len_be, 8);
                for (int i = 0; i < 5; ++i) {
                    out[i * 4] = static_cast<uint8_t>(h[i] >> 24);
                    out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
                    out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
                    out[i * 4 + 3] = static_cast<uint8_t>(h[i]);
                }
            }
        };

        inline string base64_encode_bytes(const uint8_t* data, size_t size) {
            static const char tbl[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            string_builder b;
            size_t i = 0;
            while (i + 2 < size) {
                const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                                   (static_cast<uint32_t>(data[i + 1]) << 8) |
                                   static_cast<uint32_t>(data[i + 2]);
                sb_append(b, tbl[(v >> 18) & 0x3F]);
                sb_append(b, tbl[(v >> 12) & 0x3F]);
                sb_append(b, tbl[(v >> 6) & 0x3F]);
                sb_append(b, tbl[v & 0x3F]);
                i += 3;
            }
            if (i + 1 == size) {
                const uint32_t v = static_cast<uint32_t>(data[i]) << 16;
                sb_append(b, tbl[(v >> 18) & 0x3F]);
                sb_append(b, tbl[(v >> 12) & 0x3F]);
                sb_append(b, '=');
                sb_append(b, '=');
            } else if (i + 2 == size) {
                const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                                   (static_cast<uint32_t>(data[i + 1]) << 8);
                sb_append(b, tbl[(v >> 18) & 0x3F]);
                sb_append(b, tbl[(v >> 12) & 0x3F]);
                sb_append(b, tbl[(v >> 6) & 0x3F]);
                sb_append(b, '=');
            }
            return sb_release(b);
        }

        inline string make_client_key() {
            std::random_device rd;
            uint8_t rnd[16];
            for (auto& b : rnd) b = static_cast<uint8_t>(rd() & 0xFF);
            return base64_encode_bytes(rnd, sizeof rnd);
        }

        inline string make_client_key(const KeyRandomSource& rng) {
            if (!rng) return make_client_key();
            uint8_t rnd[16];
            rng(rnd, sizeof rnd);
            return base64_encode_bytes(rnd, sizeof rnd);
        }

        inline string accept_key_for(string_view client_key) {
            // RFC 6455 4.2.2: the GUID is fixed by the spec.
            static const char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            Sha1State s;
            s.update(reinterpret_cast<const uint8_t*>(client_key.data()),
                     client_key.size());
            s.update(reinterpret_cast<const uint8_t*>(kGuid), sizeof kGuid - 1);
            uint8_t digest[20];
            s.finish(digest);
            return base64_encode_bytes(digest, sizeof digest);
        }

        inline bool has_token(string_view header_value, string_view token) {
            size_t pos = 0;
            while (pos <= header_value.size()) {
                size_t comma = header_value.find(',', pos);
                if (comma == string_view::npos) comma = header_value.size();
                size_t b = pos, e = comma;
                while (b < e && (header_value[b] == ' ' || header_value[b] == '\t')) ++b;
                while (e > b && (header_value[e - 1] == ' ' || header_value[e - 1] == '\t')) --e;
                if (ascii_iequals(header_value.substr(b, e - b), token)) return true;
                pos = comma + 1;
            }
            return false;
        }

        inline bool subprotocol_was_offered(const std::vector<string>& offered,
                                            string_view selected) {
            for (const auto& s : offered) {
                if (ascii_iequals(to_view(s), selected)) return true;
            }
            return false;
        }

        inline bool extensions_unsolicited(const std::vector<string>& requested,
                                           string_view response_value) {
            // Every entry the server returned must correspond to something the
            // client offered. An empty response is always fine (no extensions).
            if (response_value.empty()) return false;
            size_t pos = 0;
            while (pos <= response_value.size()) {
                size_t comma = response_value.find(',', pos);
                if (comma == string_view::npos) comma = response_value.size();
                size_t b = pos, e = comma;
                while (b < e && (response_value[b] == ' ' || response_value[b] == '\t')) ++b;
                while (e > b && (response_value[e - 1] == ' ' || response_value[e - 1] == '\t')) --e;
                const string_view entry = response_value.substr(b, e - b);
                // Name is everything up to the first ';'.
                size_t semi = entry.find(';');
                const string_view name = (semi == string_view::npos)
                                             ? entry
                                             : entry.substr(0, semi);
                bool matched = false;
                for (const auto& req : requested) {
                    if (ascii_iequals(to_view(req), name)) { matched = true; break; }
                }
                if (!matched) return true;
                pos = comma + 1;
            }
            return false;
        }

    } // namespace ws_detail

    // ---------------------------------------------------------------------
    // UTF-8 validation
    // ---------------------------------------------------------------------
    // RFC 3629: no overlong forms, no surrogates, max U+10FFFF.

    namespace ws_detail {

        // Returns the number of bytes consumed by one valid sequence, or 0 if
        // the sequence starting at p is invalid. `avail` bounds the read.
        inline size_t utf8_seq_len(const uint8_t* p, size_t avail) {
            if (avail == 0) return 0;
            const uint8_t c = p[0];
            size_t len;
            uint32_t cp;
            if (c < 0x80) return 1;
            if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
            else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
            else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
            else return 0;
            if (avail < len) return 0;
            for (size_t i = 1; i < len; ++i) {
                if ((p[i] & 0xC0) != 0x80) return 0;
                cp = (cp << 6) | (p[i] & 0x3F);
            }
            // Overlong encodings, surrogates and out-of-range code points.
            if (len == 2 && cp < 0x80) return 0;
            if (len == 3 && cp < 0x800) return 0;
            if (len == 4 && cp < 0x10000) return 0;
            if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
            if (cp > 0x10FFFF) return 0;
            return len;
        }

    } // namespace ws_detail

    inline bool ws_is_valid_utf8(const uint8_t* data, size_t size) {
        size_t i = 0;
        while (i < size) {
            const size_t n = ws_detail::utf8_seq_len(data + i, size - i);
            if (n == 0) return false;
            i += n;
        }
        return true;
    }

    inline size_t ws_utf8_incomplete_tail(const uint8_t* data, size_t size) {
        // Walk backwards over continuation bytes to find the lead byte.
        size_t trail = 0;
        while (trail < size && trail < 3 &&
               (data[size - 1 - trail] & 0xC0) == 0x80) {
            ++trail;
        }
        if (trail >= size) return 0;
        const uint8_t lead = data[size - 1 - trail];
        size_t needed = 0;
        if ((lead & 0xE0) == 0xC0) needed = 2;
        else if ((lead & 0xF0) == 0xE0) needed = 3;
        else if ((lead & 0xF8) == 0xF0) needed = 4;
        else return 0;
        const size_t have = trail + 1;
        return have < needed ? have : 0;
    }

    // ---------------------------------------------------------------------
    // Incremental UTF-8 validation
    //
    // The pending buffer holds the bytes of a sequence that began in an earlier
    // chunk. Each feed first tries to finish that sequence, then walks whole
    // sequences, then parks a new partial tail. The validation rules are the
    // same ones ws_is_valid_utf8 applies (no overlong forms, no surrogates,
    // nothing above U+10FFFF) -- a streaming validator that accepted input the
    // one-shot validator rejects would be worse than not having it.
    // ---------------------------------------------------------------------
    inline bool WsUtf8Validator::feed(const uint8_t* data, size_t size) {
        size_t i = 0;

        // 1. Try to complete the sequence carried over from the last chunk.
        while (pending_len_ != 0 && i < size) {
            const uint8_t c = data[i];
            if ((c & 0xC0) != 0x80) {
                // Not a continuation byte: the carried sequence is malformed.
                return false;
            }
            pending_[pending_len_++] = c;
            ++i;

            const uint8_t lead = pending_[0];
            size_t need = 0;
            if ((lead & 0xE0) == 0xC0) need = 2;
            else if ((lead & 0xF0) == 0xE0) need = 3;
            else if ((lead & 0xF8) == 0xF0) need = 4;
            else return false;

            if (pending_len_ < need) continue;

            // Complete: judge the code point, then reset.
            if (ws_detail::utf8_seq_len(pending_, need) != need) return false;
            pending_len_ = 0;
        }

        // 2. Whole sequences straight out of this chunk.
        while (i < size) {
            const size_t n = ws_detail::utf8_seq_len(data + i, size - i);
            if (n != 0) {
                i += n;
                continue;
            }
            // Not enough bytes for a sequence that is otherwise well-formed:
            // park them. A genuinely invalid lead byte reports 0 as well, so
            // tell the two apart by checking whether the tail could still be
            // completed from this chunk.
            const size_t avail = size - i;
            const uint8_t lead = data[i];
            size_t need = 0;
            if ((lead & 0xE0) == 0xC0) need = 2;
            else if ((lead & 0xF0) == 0xE0) need = 3;
            else if ((lead & 0xF8) == 0xF0) need = 4;
            else return false;   // neither ASCII, nor a legal lead byte

            if (avail >= need) {
                // The whole sequence was present and still failed: invalid.
                return false;
            }
            for (size_t k = 0; k < avail; ++k) pending_[k] = data[i + k];
            pending_len_ = avail;
            return true;
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // Frame encoder
    // ---------------------------------------------------------------------

    inline void ws_encode_frame(byte_buffer& out, WsOpcode opcode,
                                const uint8_t* payload, size_t size, bool fin,
                                bool rsv1, uint32_t mask) {
        out.clear();
        const uint8_t b0 = (fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00) |
                           static_cast<uint8_t>(opcode);
        out.push_back(b0);

        // A client frame is always masked (RFC 6455 5.3).
        const uint8_t mask_bit = 0x80;
        if (size < 126) {
            out.push_back(static_cast<uint8_t>(mask_bit | size));
        } else if (size <= 0xFFFF) {
            out.push_back(static_cast<uint8_t>(mask_bit | 126));
            out.push_back(static_cast<uint8_t>(size >> 8));
            out.push_back(static_cast<uint8_t>(size));
        } else {
            out.push_back(static_cast<uint8_t>(mask_bit | 127));
            for (int i = 7; i >= 0; --i) {
                out.push_back(static_cast<uint8_t>(size >> (i * 8)));
            }
        }

        uint8_t m[4];
        if (mask == 0) {
            std::random_device rd;
            const uint32_t v = rd();
            m[0] = static_cast<uint8_t>(v >> 24); m[1] = static_cast<uint8_t>(v >> 16);
            m[2] = static_cast<uint8_t>(v >> 8);  m[3] = static_cast<uint8_t>(v);
        } else {
            m[0] = static_cast<uint8_t>(mask >> 24); m[1] = static_cast<uint8_t>(mask >> 16);
            m[2] = static_cast<uint8_t>(mask >> 8);  m[3] = static_cast<uint8_t>(mask);
        }
        out.push_back(m[0]);
        out.push_back(m[1]);
        out.push_back(m[2]);
        out.push_back(m[3]);

        const size_t base = out.size();
        out.resize(base + size);
        for (size_t i = 0; i < size; ++i) {
            out[base + i] = static_cast<uint8_t>(payload[i] ^ m[i % 4]);
        }
    }

    // ---------------------------------------------------------------------
    // Frame decoder
    // ---------------------------------------------------------------------

    class WsFrameDecoder::Impl {
    public:
        Impl(Callbacks& cbs, Limits limits) : cbs_(cbs), limits_(limits) {}

        Callbacks& cbs_;
        Limits limits_;
        bool failed_{false};

        byte_buffer buf_;
        size_t consumed_{0};

        // Fragment assembly. A data frame with FIN=0 starts a message; only its
        // finished form is delivered, so a caller never sees half a message
        // unless it asked for streaming (this decoder does not).
        bool in_message_{false};
        bool message_compressed_{false};
        WsMessageType message_type_{WsMessageType::Text};
        byte_buffer message_;
        size_t incremental_message_bytes_{0};

        VoidResult fail(ErrorCode code, const char* msg) {
            failed_ = true;
            return Error{code, ErrorPhase::TargetProtocol, string(msg)};
        }

        VoidResult parse_available() {
            for (;;) {
                const size_t avail = buf_.size() - consumed_;
                if (avail < 2) return VoidResult{};

                // Backpressure is checked before the next frame. Control
                // frames are allowed through while paused so ping/pong/close
                // cannot be starved; the first data frame stops the loop and
                // stays buffered for feed(nullptr, 0).
                if (cbs_.pause_requested()) {
                    const uint8_t op_raw = buf_[consumed_] & 0x0F;
                    if ((op_raw & 0x8) == 0) return VoidResult{};
                }

                const uint8_t b0 = buf_[consumed_];
                const uint8_t b1 = buf_[consumed_ + 1];
                const bool fin = (b0 & 0x80) != 0;
                const bool rsv1 = (b0 & 0x40) != 0;
                const bool rsv2 = (b0 & 0x20) != 0;
                const bool rsv3 = (b0 & 0x10) != 0;
                const uint8_t op_raw = b0 & 0x0F;
                const bool masked = (b1 & 0x80) != 0;
                uint64_t len = b1 & 0x7F;

                // A server frame must NOT be masked (RFC 6455 5.1). Accepting a
                // masked server frame would also mean the mask handling below is
                // wrong in a way no other test would catch.
                if (masked) {
                    return fail(ErrorCode::WsProtocolError,
                                "a server frame must not be masked");
                }

                // RSV2/RSV3 are only legal with an extension this build does not
                // implement; RSV1 is legal only for a compressed message.
                if (rsv2 || rsv3) {
                    return fail(ErrorCode::WsProtocolError,
                                "RSV2/RSV3 set without a negotiated extension");
                }

                size_t header = 2;
                if (len == 126) {
                    if (avail < 4) return VoidResult{};
                    len = (static_cast<uint64_t>(buf_[consumed_ + 2]) << 8) |
                          static_cast<uint64_t>(buf_[consumed_ + 3]);
                    header = 4;
                } else if (len == 127) {
                    if (avail < 10) return VoidResult{};
                    len = 0;
                    for (int i = 0; i < 8; ++i) {
                        len = (len << 8) | buf_[consumed_ + 2 + i];
                    }
                    header = 10;
                    // The most significant bit must be 0 (RFC 6455 5.2).
                    if ((len >> 63) != 0) {
                        return fail(ErrorCode::WsFrameTooLarge,
                                    "frame length exceeds 2^63-1");
                    }
                }

                WsOpcode op;
                switch (op_raw) {
                    case 0x0: op = WsOpcode::Continuation; break;
                    case 0x1: op = WsOpcode::Text; break;
                    case 0x2: op = WsOpcode::Binary; break;
                    case 0x8: op = WsOpcode::Close; break;
                    case 0x9: op = WsOpcode::Ping; break;
                    case 0xA: op = WsOpcode::Pong; break;
                    default:
                        return fail(ErrorCode::WsProtocolError, "unknown opcode");
                }

                if (ws_is_control_opcode(op)) {
                    if (!fin) {
                        return fail(ErrorCode::WsProtocolError,
                                    "a control frame must not be fragmented");
                    }
                    if (len > 125) {
                        return fail(ErrorCode::WsProtocolError,
                                    "a control frame payload must be <= 125 bytes");
                    }
                    if (rsv1) {
                        return fail(ErrorCode::WsProtocolError,
                                    "a control frame must not be compressed");
                    }
                } else {
                    if (len > limits_.max_frame_bytes) {
                        return fail(ErrorCode::WsFrameTooLarge,
                                    "frame exceeded max_frame_bytes");
                    }
                }

                if (avail < header + len) return VoidResult{};

                WsFrame frame;
                frame.fin = fin;
                frame.rsv1 = rsv1;
                frame.rsv2 = rsv2;
                frame.rsv3 = rsv3;
                frame.opcode = op;
                frame.payload.assign(buf_.begin() + consumed_ + header,
                                     buf_.begin() + consumed_ + header + len);
                consumed_ += header + len;

                auto r = handle_frame(frame);
                if (!r) return r;
            }
        }

        VoidResult handle_frame(const WsFrame& f) {
            if (ws_is_control_opcode(f.opcode)) {
                // A control frame inside a fragmented message is legal and must
                // be surfaced immediately, not queued behind the message.
                return cbs_.on_control(f);
            }

            if (cbs_.wants_incremental_messages()) {
                if (f.opcode == WsOpcode::Continuation) {
                    if (!in_message_) {
                        return fail(ErrorCode::WsProtocolError,
                                    "continuation frame without a message to continue");
                    }
                } else {
                    if (in_message_) {
                        return fail(ErrorCode::WsProtocolError,
                                    "a new data frame started while a fragmented message was open");
                    }
                    in_message_ = true;
                    message_compressed_ = f.rsv1;
                    message_type_ = (f.opcode == WsOpcode::Text)
                                        ? WsMessageType::Text
                                        : WsMessageType::Binary;
                    incremental_message_bytes_ = 0;
                    auto r = cbs_.on_message_begin(message_type_, f.rsv1);
                    if (!r) return r;
                }

                if (f.opcode == WsOpcode::Continuation && f.rsv1) {
                    return fail(ErrorCode::WsProtocolError,
                                "RSV1 set on a continuation frame");
                }

                if (limits_.max_message_bytes > 0 &&
                    incremental_message_bytes_ + f.payload.size() >
                        limits_.max_message_bytes) {
                    return fail(ErrorCode::WsMessageTooLarge,
                                "message exceeded max_message_bytes");
                }
                incremental_message_bytes_ += f.payload.size();

                if (!f.payload.empty()) {
                    auto r = cbs_.on_message_data(f.payload.data(), f.payload.size());
                    if (!r) return r;
                }

                if (!f.fin) return VoidResult{};
                in_message_ = false;
                message_compressed_ = false;
                incremental_message_bytes_ = 0;
                return cbs_.on_message_end();
            }

            if (f.opcode == WsOpcode::Continuation) {
                if (!in_message_) {
                    return fail(ErrorCode::WsProtocolError,
                                "continuation frame without a message to continue");
                }
            } else {
                if (in_message_) {
                    return fail(ErrorCode::WsProtocolError,
                                "a new data frame started while a fragmented message was open");
                }
                in_message_ = true;
                message_compressed_ = f.rsv1;
                message_type_ = (f.opcode == WsOpcode::Text) ? WsMessageType::Text
                                                             : WsMessageType::Binary;
                message_.clear();
            }

            // RSV1 is only legal on the first frame of a message.
            if (f.opcode == WsOpcode::Continuation && f.rsv1) {
                return fail(ErrorCode::WsProtocolError,
                            "RSV1 set on a continuation frame");
            }

            if (limits_.max_message_bytes > 0 &&
                message_.size() + f.payload.size() > limits_.max_message_bytes) {
                return fail(ErrorCode::WsMessageTooLarge,
                            "message exceeded max_message_bytes");
            }
            message_.insert(message_.end(), f.payload.begin(), f.payload.end());

            if (!f.fin) return VoidResult{};

            // The complete message. UTF-8 validation belongs to the caller when
            // the message was compressed: RSV1 means the bytes here are DEFLATE
            // output, and validating that as UTF-8 would reject a legal message.
            if (!message_compressed_ && message_type_ == WsMessageType::Text &&
                !ws_is_valid_utf8(message_.data(), message_.size())) {
                return fail(ErrorCode::WsUtf8Invalid,
                            "text message is not valid UTF-8");
            }

            byte_buffer complete;
            complete.swap(message_);
            in_message_ = false;
            const bool was_compressed = message_compressed_;
            message_compressed_ = false;
            return cbs_.on_message(message_type_, complete, was_compressed);
        }
    };

    inline WsFrameDecoder::WsFrameDecoder(Callbacks& cbs, Limits limits)
        : impl_(std::make_unique<Impl>(cbs, limits)) {}

    inline WsFrameDecoder::~WsFrameDecoder() = default;

    inline VoidResult WsFrameDecoder::feed(const uint8_t* data, size_t size) {
        if (impl_->failed_) {
            return Error{ErrorCode::WsProtocolError, ErrorPhase::TargetProtocol,
                         string("frame decoder already failed")};
        }
        if (size != 0) {
            impl_->buf_.insert(impl_->buf_.end(), data, data + size);
        }
        auto r = impl_->parse_available();
        // Drop the consumed prefix so the buffer does not grow for a long-lived
        // connection.
        if (impl_->consumed_ > 0) {
            impl_->buf_.erase(impl_->buf_.begin(),
                              impl_->buf_.begin() + impl_->consumed_);
            impl_->consumed_ = 0;
        }
        return r;
    }

    inline bool WsFrameDecoder::is_failed() const noexcept {
        return impl_->failed_;
    }

} // namespace megohttp

#endif // MEGOHTTP_WEBSOCKET_IMPL_HPP_INCLUDED
