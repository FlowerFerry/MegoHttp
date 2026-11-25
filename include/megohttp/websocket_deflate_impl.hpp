#ifndef MEGOHTTP_WEBSOCKET_DEFLATE_IMPL_HPP
#define MEGOHTTP_WEBSOCKET_DEFLATE_IMPL_HPP

#include <megohttp/websocket_deflate.hpp>
#include <megohttp/format.hpp>
#include <megohttp/string_adapter.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>

#include <zlib.h>

namespace megohttp {

    using detail::ascii_iequals;
    using detail::sb_append;
    using detail::sb_release;

    namespace websocket_deflate_detail {

        inline string_view trim(string_view s) {
            size_t b = 0, e = s.size();
            while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
            while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
            return s.substr(b, e - b);
        }

        inline std::vector<string_view> split_commas(string_view v) {
            std::vector<string_view> out;
            size_t pos = 0;
            for (;;) {
                const size_t comma = v.find(',', pos);
                const size_t end = (comma == string_view::npos) ? v.size() : comma;
                const string_view piece = trim(v.substr(pos, end - pos));
                if (!piece.empty()) out.push_back(piece);
                if (comma == string_view::npos) break;
                pos = comma + 1;
            }
            return out;
        }

        inline bool ieq(string_view a, string_view b) {
            return ascii_iequals(a, b);
        }

        inline bool parse_int(string_view v, int& out) {
            if (v.empty()) return false;
            int value = 0;
            const auto fr = std::from_chars(v.data(), v.data() + v.size(), value);
            if (fr.ec != std::errc{} || fr.ptr != v.data() + v.size()) return false;
            out = value;
            return true;
        }

    } // namespace websocket_deflate_detail

    // -----------------------------------------------------------------------
    // Negotiation
    // -----------------------------------------------------------------------

    inline std::optional<DeflateOptions> parse_deflate_offer(const Headers& headers) {
        const auto hdr = headers.get("sec-websocket-extensions");
        if (!hdr) return std::nullopt;

        for (const string_view ext : websocket_deflate_detail::split_commas(*hdr)) {
            const size_t semi = ext.find(';');
            const string_view name = websocket_deflate_detail::trim(
                semi == string_view::npos ? ext : ext.substr(0, semi));
            if (!websocket_deflate_detail::ieq(name, "permessage-deflate")) continue;

            DeflateOptions opts;
            opts.enabled = true;

            size_t pos = (semi == string_view::npos) ? ext.size() : semi + 1;
            while (pos < ext.size()) {
                size_t next = ext.find(';', pos);
                if (next == string_view::npos) next = ext.size();
                const string_view param =
                    websocket_deflate_detail::trim(ext.substr(pos, next - pos));
                pos = next + 1;
                if (param.empty()) continue;

                const size_t eq = param.find('=');
                const string_view pname = websocket_deflate_detail::trim(
                    eq == string_view::npos ? param : param.substr(0, eq));
                const string_view pvalue =
                    (eq == string_view::npos)
                        ? string_view{}
                        : websocket_deflate_detail::trim(param.substr(eq + 1));

                if (websocket_deflate_detail::ieq(pname, "server_max_window_bits")) {
                    int v = 0;
                    if (websocket_deflate_detail::parse_int(pvalue, v)) {
                        opts.server_max_window_bits = v;
                    }
                } else if (websocket_deflate_detail::ieq(pname, "client_max_window_bits")) {
                    int v = 0;
                    if (websocket_deflate_detail::parse_int(pvalue, v)) {
                        opts.client_max_window_bits = v;
                    }
                } else if (websocket_deflate_detail::ieq(pname, "server_no_context_takeover")) {
                    opts.server_no_context_takeover = true;
                } else if (websocket_deflate_detail::ieq(pname, "client_no_context_takeover")) {
                    opts.client_no_context_takeover = true;
                }
            }
            return opts;
        }
        return std::nullopt;
    }

    inline string build_deflate_response(const DeflateNegotiated& params) {
        if (!params.enabled) return string{};

        string_builder b;
        sb_append(b, "permessage-deflate");
        // RFC 7692: omitting a window-bits parameter means 15 (the default), so
        // only a non-default value needs to be written.
        if (params.server_window_bits != 15) {
            sb_append(b, "; server_max_window_bits=");
            sb_append(b, to_view(format("{}", params.server_window_bits)));
        }
        if (params.client_window_bits != 15) {
            sb_append(b, "; client_max_window_bits=");
            sb_append(b, to_view(format("{}", params.client_window_bits)));
        }
        if (params.server_no_context_takeover) sb_append(b, "; server_no_context_takeover");
        if (params.client_no_context_takeover) sb_append(b, "; client_no_context_takeover");
        return sb_release(b);
    }

    // -----------------------------------------------------------------------
    // Compressor
    // -----------------------------------------------------------------------

    struct DeflateCompressor::Impl {
        z_stream strm{};
        DeflateNegotiated params;
        bool initialised{false};
        bool in_message{false};

        explicit Impl(const DeflateNegotiated& p) : params(p) {
            // RAW deflate (negative window bits): RFC 7692 forbids the zlib or
            // gzip wrapper on each message.
            if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                             -params.client_window_bits, 8,
                             Z_DEFAULT_STRATEGY) == Z_OK) {
                initialised = true;
            }
        }
        ~Impl() {
            if (initialised) deflateEnd(&strm);
        }
        void reset() {
            if (initialised) deflateReset(&strm);
        }
    };

    inline DeflateCompressor::DeflateCompressor(const DeflateNegotiated& params)
        : impl_(std::make_unique<Impl>(params)) {}

    inline DeflateCompressor::~DeflateCompressor() = default;

    inline VoidResult DeflateCompressor::begin_message() {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate is not available in this build")};
        }
        if (impl_->in_message) {
            return Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                         string("a permessage-deflate message is already open")};
        }
        // Context takeover keeps the stream between messages; no_context_takeover
        // resets it before each message (RFC 7692 7.1.1). Resetting at begin
        // rather than end means a failed message cannot contaminate the next one.
        if (impl_->params.client_no_context_takeover) impl_->reset();
        impl_->in_message = true;
        return VoidResult{};
    }

    inline Result<std::vector<uint8_t>> DeflateCompressor::compress_chunk(
        const uint8_t* data, size_t size) {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate is not available in this build")};
        }
        if (!impl_->in_message) {
            return Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                         string("no permessage-deflate message is open")};
        }

        std::vector<uint8_t> out;
        if (size == 0) return out;

        size_t offset = 0;
        while (offset < size) {
            // zlib's avail_in is uInt; feed a bounded slice for huge inputs.
            const size_t take = (std::min)(size - offset,
                                           static_cast<size_t>(0x40000000));
            impl_->strm.next_in = const_cast<Bytef*>(data + offset);
            impl_->strm.avail_in = static_cast<uInt>(take);

            for (;;) {
                uint8_t buf[32 * 1024];
                impl_->strm.next_out = buf;
                impl_->strm.avail_out = static_cast<uInt>(sizeof buf);
                const uInt before_in = impl_->strm.avail_in;
                const int rc = deflate(&impl_->strm, Z_NO_FLUSH);
                const size_t produced = sizeof buf - impl_->strm.avail_out;
                if (produced) out.insert(out.end(), buf, buf + produced);

                if (rc != Z_OK && rc != Z_BUF_ERROR) {
                    impl_->in_message = false;
                    return Error{ErrorCode::WsCompressionFailed, ErrorPhase::Send,
                                 string("permessage-deflate compression failed")};
                }
                // Stop once all input is consumed and the output buffer was not
                // filled. A full buffer means zlib has more pending output.
                if (impl_->strm.avail_in == 0 && impl_->strm.avail_out != 0) break;
                // Defensive: no progress with input still pending is a broken
                // stream state, not something to spin on.
                if (produced == 0 && impl_->strm.avail_in == before_in &&
                    impl_->strm.avail_in != 0) {
                    impl_->in_message = false;
                    return Error{ErrorCode::WsCompressionFailed, ErrorPhase::Send,
                                 string("permessage-deflate compression made no progress")};
                }
            }
            offset += take;
        }
        return out;
    }

    inline Result<std::vector<uint8_t>> DeflateCompressor::end_message() {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate is not available in this build")};
        }
        if (!impl_->in_message) {
            return Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                         string("no permessage-deflate message is open")};
        }

        std::vector<uint8_t> out;
        impl_->strm.next_in = nullptr;
        impl_->strm.avail_in = 0;
        for (;;) {
            uint8_t buf[16 * 1024];
            impl_->strm.next_out = buf;
            impl_->strm.avail_out = static_cast<uInt>(sizeof buf);
            const int rc = deflate(&impl_->strm, Z_SYNC_FLUSH);
            const size_t produced = sizeof buf - impl_->strm.avail_out;
            if (produced) out.insert(out.end(), buf, buf + produced);

            if (rc != Z_OK && rc != Z_BUF_ERROR) {
                impl_->in_message = false;
                return Error{ErrorCode::WsCompressionFailed, ErrorPhase::Send,
                             string("permessage-deflate flush failed")};
            }
            // Z_SYNC_FLUSH is complete once the output buffer was not filled.
            if (impl_->strm.avail_out != 0) break;
        }
        impl_->in_message = false;

        // RFC 7692 7.2.1: the sender removes the trailing 0x00 0x00 0xFF 0xFF;
        // the receiver appends it back before inflating.
        if (out.size() >= 4 && out[out.size() - 4] == 0x00 && out[out.size() - 3] == 0x00 &&
            out[out.size() - 2] == 0xFF && out[out.size() - 1] == 0xFF) {
            out.resize(out.size() - 4);
        }
        return out;
    }

    inline bool DeflateCompressor::message_open() const noexcept {
        return impl_->in_message;
    }

    inline std::vector<uint8_t> DeflateCompressor::compress(const std::vector<uint8_t>& input) {
        // Legacy convenience entry point: it has no error channel, so a
        // compression failure returns the input unchanged. New code must use
        // begin_message/compress_chunk/end_message and check the Result.
        if (!impl_->initialised) return input;
        if (impl_->in_message) return input;
        if (!begin_message()) return input;
        auto chunk = compress_chunk(input.data(), input.size());
        if (!chunk) return input;
        auto tail = end_message();
        if (!tail) return input;
        std::vector<uint8_t> out = std::move(chunk.value());
        const auto& t = tail.value();
        out.insert(out.end(), t.begin(), t.end());
        return out;
    }

    // -----------------------------------------------------------------------
    // Decompressor
    // -----------------------------------------------------------------------

    struct DeflateDecompressor::Impl {
        z_stream strm{};
        DeflateNegotiated params;
        bool initialised{false};
        bool in_message{false};

        explicit Impl(const DeflateNegotiated& p) : params(p) {
            if (inflateInit2(&strm, -params.server_window_bits) == Z_OK) {
                initialised = true;
            }
        }
        ~Impl() {
            if (initialised) inflateEnd(&strm);
        }
        void reset() {
            if (initialised) inflateReset(&strm);
        }
    };

    inline DeflateDecompressor::DeflateDecompressor(const DeflateNegotiated& params)
        : impl_(std::make_unique<Impl>(params)) {}

    inline DeflateDecompressor::~DeflateDecompressor() = default;

    inline Result<std::vector<uint8_t>> DeflateDecompressor::decompress(
        const std::vector<uint8_t>& input, size_t max_output_bytes) {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::Receive,
                         string("permessage-deflate is not available in this build")};
        }

        if (impl_->params.server_no_context_takeover) impl_->reset();

        // The sender strips the 0x00 0x00 0xFF 0xFF tail; restore it, because
        // that is what lets zlib finish the block.
        std::vector<uint8_t> data = input;
        if (data.size() >= 4 && data[data.size() - 4] == 0x00 &&
            data[data.size() - 3] == 0x00 && data[data.size() - 2] == 0xFF &&
            data[data.size() - 1] == 0xFF) {
            data.resize(data.size() - 4);
        }
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0xFF);
        data.push_back(0xFF);

        // Start small and grow. The buffer never exceeds max_output_bytes, so a
        // 1000:1 expansion is refused while it is still small instead of after
        // the whole message has been materialised.
        const size_t cap = (max_output_bytes == 0) ? 0 : max_output_bytes;
        size_t initial = input.size() * 4;
        if (initial < 1024) initial = 1024;
        if (cap != 0 && initial > cap) initial = cap;
        std::vector<uint8_t> out(initial);

        impl_->strm.next_in = data.data();
        impl_->strm.avail_in = static_cast<uInt>(data.size());

        size_t written = 0;
        for (;;) {
            if (written == out.size()) {
                if (cap != 0 && out.size() >= cap) {
                    // The cap is reached and inflate still wants to write: this
                    // is the bomb case, refuse it now.
                    return Error{ErrorCode::WsCompressionResourceExceeded,
                                 ErrorPhase::Compression,
                                 string("decompressed message exceeded the output limit")};
                }
                size_t next = out.size() * 2;
                if (next == 0) next = 1024;
                if (cap != 0 && next > cap) next = cap;
                out.resize(next);
            }
            impl_->strm.next_out = out.data() + written;
            impl_->strm.avail_out = static_cast<uInt>(out.size() - written);
            const size_t before = written;

            const int rc = inflate(&impl_->strm, Z_SYNC_FLUSH);
            written = out.size() - impl_->strm.avail_out;

            if (rc == Z_STREAM_END) break;
            // permessage-deflate never ends the stream: a message ends when the
            // input is consumed and inflate produced nothing more.
            if (impl_->strm.avail_in == 0) {
                if (rc == Z_BUF_ERROR || written == before) break;
            }
            if (rc == Z_OK || rc == Z_BUF_ERROR) continue;
            return Error{ErrorCode::WsCompressionMalformedData, ErrorPhase::Receive,
                         string("permessage-deflate payload could not be decoded")};
        }

        out.resize(written);
        return out;
    }

    inline VoidResult DeflateDecompressor::decompress_streaming(
        const std::vector<uint8_t>& input, size_t max_output_bytes,
        const ChunkSink& on_chunk) {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::Receive,
                         string("permessage-deflate is not available in this build")};
        }

        if (impl_->params.server_no_context_takeover) impl_->reset();

        // The sender strips the 0x00 0x00 0xFF 0xFF tail; restore it, because
        // that is what lets zlib finish the block.
        std::vector<uint8_t> data = input;
        if (data.size() >= 4 && data[data.size() - 4] == 0x00 &&
            data[data.size() - 3] == 0x00 && data[data.size() - 2] == 0xFF &&
            data[data.size() - 1] == 0xFF) {
            data.resize(data.size() - 4);
        }
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0xFF);
        data.push_back(0xFF);

        const size_t cap = (max_output_bytes == 0) ? 0 : max_output_bytes;
        size_t initial = input.size() * 4;
        if (initial < 1024) initial = 1024;
        if (cap != 0 && initial > cap) initial = cap;
        std::vector<uint8_t> out(initial);

        impl_->strm.next_in = data.data();
        impl_->strm.avail_in = static_cast<uInt>(data.size());

        size_t written = 0;
        for (;;) {
            if (written == out.size()) {
                if (cap != 0 && out.size() >= cap) {
                    return Error{ErrorCode::WsCompressionResourceExceeded,
                                 ErrorPhase::Compression,
                                 string("decompressed message exceeded the output limit")};
                }
                size_t next = out.size() * 2;
                if (next == 0) next = 1024;
                if (cap != 0 && next > cap) next = cap;
                out.resize(next);
            }
            impl_->strm.next_out = out.data() + written;
            impl_->strm.avail_out = static_cast<uInt>(out.size() - written);
            const size_t before = written;

            const int rc = inflate(&impl_->strm, Z_SYNC_FLUSH);
            written = out.size() - impl_->strm.avail_out;

            // Hand the newly-produced bytes to the caller's sink.
            if (written > before) {
                if (!on_chunk(out.data() + before, written - before)) {
                    return Error{ErrorCode::WsCompressionResourceExceeded,
                                 ErrorPhase::Compression,
                                 string("decompressed message exceeded the output limit")};
                }
            }

            if (rc == Z_STREAM_END) break;
            if (impl_->strm.avail_in == 0) {
                if (rc == Z_BUF_ERROR || written == before) break;
            }
            if (rc == Z_OK || rc == Z_BUF_ERROR) continue;
            return Error{ErrorCode::WsCompressionMalformedData, ErrorPhase::Receive,
                         string("permessage-deflate payload could not be decoded")};
        }

        return VoidResult{};
    }

    inline VoidResult DeflateDecompressor::begin_message() {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate is not available in this build")};
        }
        if (impl_->in_message) {
            return Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                         string("a permessage-deflate receive message is already open")};
        }
        if (impl_->params.server_no_context_takeover) impl_->reset();
        impl_->in_message = true;
        return VoidResult{};
    }

    inline Result<std::vector<uint8_t>> DeflateDecompressor::decompress_chunk(
        const uint8_t* data, size_t size, size_t max_output_bytes) {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate is not available in this build")};
        }
        if (!impl_->in_message) {
            return Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                         string("no permessage-deflate receive message is open")};
        }

        std::vector<uint8_t> out;
        if (size == 0) return out;

        size_t offset = 0;
        while (offset < size) {
            const size_t take = (std::min)(size - offset,
                                           static_cast<size_t>(0x40000000));
            impl_->strm.next_in = const_cast<Bytef*>(data + offset);
            impl_->strm.avail_in = static_cast<uInt>(take);

            for (;;) {
                uint8_t buf[32 * 1024];
                impl_->strm.next_out = buf;
                impl_->strm.avail_out = static_cast<uInt>(sizeof buf);
                const uInt before_in = impl_->strm.avail_in;
                const int rc = inflate(&impl_->strm, Z_SYNC_FLUSH);
                const size_t produced = sizeof buf - impl_->strm.avail_out;
                if (produced) {
                    if (max_output_bytes != 0 &&
                        out.size() + produced > max_output_bytes) {
                        impl_->in_message = false;
                        return Error{ErrorCode::WsCompressionResourceExceeded,
                                     ErrorPhase::Compression,
                                     string("decompressed message exceeded the output limit")};
                    }
                    out.insert(out.end(), buf, buf + produced);
                }

                if (rc == Z_STREAM_END) {
                    // RFC 7692 messages use Z_SYNC_FLUSH and never terminate the
                    // DEFLATE stream; a real end marker mid-message is malformed.
                    impl_->in_message = false;
                    return Error{ErrorCode::WsCompressionMalformedData,
                                 ErrorPhase::Receive,
                                 string("unexpected end of permessage-deflate stream")};
                }
                if (rc != Z_OK && rc != Z_BUF_ERROR) {
                    impl_->in_message = false;
                    return Error{ErrorCode::WsCompressionMalformedData,
                                 ErrorPhase::Receive,
                                 string("permessage-deflate payload could not be decoded")};
                }
                if (impl_->strm.avail_in == 0 &&
                    (impl_->strm.avail_out != 0 || produced == 0)) {
                    break;
                }
                if (produced == 0 && impl_->strm.avail_in == before_in &&
                    impl_->strm.avail_in != 0) {
                    impl_->in_message = false;
                    return Error{ErrorCode::WsCompressionMalformedData,
                                 ErrorPhase::Receive,
                                 string("permessage-deflate inflate made no progress")};
                }
            }
            offset += take;
        }
        return out;
    }

    inline Result<std::vector<uint8_t>> DeflateDecompressor::end_message(
        size_t max_output_bytes) {
        if (!impl_->initialised) {
            return Error{ErrorCode::WsCompressionNotCompiled, ErrorPhase::TargetProtocol,
                         string("permessage-deflate is not available in this build")};
        }
        if (!impl_->in_message) {
            return Error{ErrorCode::WsInvalidState, ErrorPhase::TargetProtocol,
                         string("no permessage-deflate receive message is open")};
        }

        const uint8_t tail[4] = {0x00, 0x00, 0xFF, 0xFF};
        impl_->strm.next_in = const_cast<Bytef*>(tail);
        impl_->strm.avail_in = 4;

        std::vector<uint8_t> out;
        for (;;) {
            uint8_t buf[16 * 1024];
            impl_->strm.next_out = buf;
            impl_->strm.avail_out = static_cast<uInt>(sizeof buf);
            const uInt before_in = impl_->strm.avail_in;
            const int rc = inflate(&impl_->strm, Z_SYNC_FLUSH);
            const size_t produced = sizeof buf - impl_->strm.avail_out;
            if (produced) {
                if (max_output_bytes != 0 &&
                    out.size() + produced > max_output_bytes) {
                    impl_->in_message = false;
                    return Error{ErrorCode::WsCompressionResourceExceeded,
                                 ErrorPhase::Compression,
                                 string("decompressed message exceeded the output limit")};
                }
                out.insert(out.end(), buf, buf + produced);
            }

            if (rc == Z_STREAM_END) break;
            if (rc != Z_OK && rc != Z_BUF_ERROR) {
                impl_->in_message = false;
                return Error{ErrorCode::WsCompressionMalformedData,
                             ErrorPhase::Receive,
                             string("permessage-deflate payload could not be decoded")};
            }
            if (impl_->strm.avail_in == 0 && impl_->strm.avail_out != 0) break;
            if (produced == 0 && impl_->strm.avail_in == before_in &&
                impl_->strm.avail_in != 0) {
                impl_->in_message = false;
                return Error{ErrorCode::WsCompressionMalformedData,
                             ErrorPhase::Receive,
                             string("permessage-deflate flush made no progress")};
            }
        }

        impl_->in_message = false;
        return out;
    }

    inline bool DeflateDecompressor::message_open() const noexcept {
        return impl_->in_message;
    }

} // namespace megohttp

#endif // MEGOHTTP_WEBSOCKET_DEFLATE_IMPL_HPP
