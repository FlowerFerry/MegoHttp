#ifndef MEGOHTTP_HTTP_IMPL_HPP_INCLUDED
#define MEGOHTTP_HTTP_IMPL_HPP_INCLUDED

// Included at the end of http.hpp. Header-only, all definitions inline.
//
// The response parser is a byte-driven state machine. It never assumes a chunk
// boundary aligns with a protocol boundary, which is the only safe assumption on
// a real socket.

#include <megohttp/format.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>

namespace MegoHttp {

    inline const char* to_string(Method m) noexcept {
        switch (m) {
        case Method::Get:     return "GET";
        case Method::Head:    return "HEAD";
        case Method::Post:    return "POST";
        case Method::Put:     return "PUT";
        case Method::Delete:  return "DELETE";
        case Method::Patch:   return "PATCH";
        case Method::Options: return "OPTIONS";
        case Method::Trace:   return "TRACE";
        case Method::Connect: return "CONNECT";
        case Method::Custom:  return "";   // name comes from Request::custom_method
        }
        return "";
    }

    inline Method method_from_string(string_view name) noexcept {
        using Detail::ascii_iequals;
        if (ascii_iequals(name, "GET"))     return Method::Get;
        if (ascii_iequals(name, "HEAD"))    return Method::Head;
        if (ascii_iequals(name, "POST"))    return Method::Post;
        if (ascii_iequals(name, "PUT"))     return Method::Put;
        if (ascii_iequals(name, "DELETE"))  return Method::Delete;
        if (ascii_iequals(name, "PATCH"))   return Method::Patch;
        if (ascii_iequals(name, "OPTIONS")) return Method::Options;
        if (ascii_iequals(name, "TRACE"))   return Method::Trace;
        if (ascii_iequals(name, "CONNECT")) return Method::Connect;
        return Method::Custom;
    }

    namespace http_detail {

        inline string_view trim_ows(string_view v) noexcept {
            const char* p = (v).data();
            size_t n = static_cast<size_t>((v).size());
            while (n > 0 && (p[0] == ' ' || p[0] == '\t')) { ++p; --n; }
            while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) { --n; }
            return string_view(p, static_cast<string_view::size_type>(n));
        }

        inline bool header_has_token(string_view value, string_view token) noexcept {
            const char* p = (value).data();
            const size_t n = static_cast<size_t>((value).size());
            size_t i = 0;
            while (i <= n) {
                size_t j = i;
                while (j < n && p[j] != ',') ++j;
                string_view item = trim_ows(string_view(p + i,
                                          static_cast<string_view::size_type>(j - i)));
                if (Detail::ascii_iequals(item, token)) return true;
                if (j >= n) break;
                i = j + 1;
            }
            return false;
        }

        inline std::vector<string_view> split_list(string_view value) {
            std::vector<string_view> out;
            const char* p = (value).data();
            const size_t n = static_cast<size_t>((value).size());
            size_t i = 0;
            while (i <= n) {
                size_t j = i;
                while (j < n && p[j] != ',') ++j;
                string_view item = trim_ows(string_view(p + i,
                                          static_cast<string_view::size_type>(j - i)));
                if (!item.empty()) out.push_back(item);
                if (j >= n) break;
                i = j + 1;
            }
            return out;
        }

        inline string_view status_reason(int status_code) noexcept {
            switch (status_code) {
            case 100: return "Continue";
            case 101: return "Switching Protocols";
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 203: return "Non-Authoritative Information";
            case 204: return "No Content";
            case 205: return "Reset Content";
            case 206: return "Partial Content";
            case 300: return "Multiple Choices";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 303: return "See Other";
            case 304: return "Not Modified";
            case 307: return "Temporary Redirect";
            case 308: return "Permanent Redirect";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 406: return "Not Acceptable";
            case 408: return "Request Timeout";
            case 409: return "Conflict";
            case 410: return "Gone";
            case 411: return "Length Required";
            case 412: return "Precondition Failed";
            case 413: return "Payload Too Large";
            case 414: return "URI Too Long";
            case 414 + 1: return "Unsupported Media Type";   // 415
            case 416: return "Range Not Satisfiable";
            case 417: return "Expectation Failed";
            case 426: return "Upgrade Required";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            case 505: return "HTTP Version Not Supported";
            default:  return {};
            }
        }

    } // namespace http_detail

    // ---------------------------------------------------------------------------
    // Request / response head encoding
    // ---------------------------------------------------------------------------
    inline Result<string> encode_request_head(Method method,
                                              string_view custom_method,
                                              string_view request_target,
                                              const Headers& headers) {
        // Every header must be safe to put on the wire.
        for (const auto& f : headers) {
            if (!is_valid_header_name(to_view(f.first))) {
                return Error{ErrorCode::InvalidArgument, "invalid header name"};
            }
            if (!is_valid_header_value(to_view(f.second))) {
                return Error{ErrorCode::InvalidArgument,
                             "header value contains CR/LF/NUL"};
            }
        }
        // The request target must not smuggle a newline either.
        if (!is_valid_header_value(request_target)) {
            return Error{ErrorCode::InvalidArgument, "request target contains CR/LF/NUL"};
        }

        string_builder b;
        if (method == Method::Custom) {
            if (static_cast<size_t>((custom_method).size()) == 0) {
                return Error{ErrorCode::InvalidArgument, "custom method name is empty"};
            }
            if (!is_valid_header_name(custom_method)) {   // same token grammar
                return Error{ErrorCode::InvalidArgument, "invalid custom method name"};
            }
            Detail::sb_append(b, custom_method);
        } else {
            Detail::sb_append(b, to_string(method));
        }
        Detail::sb_append(b, ' ');
        Detail::sb_append(b, request_target);
        Detail::sb_append(b, " HTTP/1.1\r\n");

        for (const auto& f : headers) {
            Detail::sb_append(b, to_view(f.first));
            Detail::sb_append(b, ": ");
            Detail::sb_append(b, to_view(f.second));
            Detail::sb_append(b, "\r\n");
        }
        Detail::sb_append(b, "\r\n");
        return b.release();
    }

    inline Result<string> encode_response_head(int status_code,
                                               string_view reason,
                                               const Headers& headers) {
        if (status_code < 100 || status_code > 999) {
            return Error{ErrorCode::InvalidArgument, "status code out of range"};
        }
        for (const auto& f : headers) {
            if (!is_valid_header_name(to_view(f.first))) {
                return Error{ErrorCode::InvalidArgument, "invalid header name"};
            }
            if (!is_valid_header_value(to_view(f.second))) {
                return Error{ErrorCode::InvalidArgument,
                             "header value contains CR/LF/NUL"};
            }
        }

        string_builder b;
        Detail::sb_append(b, "HTTP/1.1 ");
        Detail::append_int(b, static_cast<uint32_t>(status_code));
        Detail::sb_append(b, ' ');
        if (!reason.empty()) Detail::sb_append(b, reason);
        Detail::sb_append(b, "\r\n");

        for (const auto& f : headers) {
            Detail::sb_append(b, to_view(f.first));
            Detail::sb_append(b, ": ");
            Detail::sb_append(b, to_view(f.second));
            Detail::sb_append(b, "\r\n");
        }
        Detail::sb_append(b, "\r\n");
        return b.release();
    }

    // ---------------------------------------------------------------------------
    // chunked
    // ---------------------------------------------------------------------------
    namespace chunked {

        inline string encode_chunk(const uint8_t* data, size_t size) {
            string_builder b;
            // Lowercase hex, no padding and no leading zeros (the canonical and
            // shortest form). fmt handles it; a hand-rolled nibble loop would be
            // another place to get the ordering wrong.
            Detail::sb_append(b, Detail::format_string("{:x}", size));
            Detail::sb_append(b, "\r\n");
            if (size != 0) {
                b += string(reinterpret_cast<const char*>(data),
                            static_cast<string::size_type>(size));
            }
            Detail::sb_append(b, "\r\n");
            return b.release();
        }

        inline string encode_last_chunk(const Headers* trailers) {
            string_builder b;
            Detail::sb_append(b, "0\r\n");
            if (trailers != nullptr) {
                for (const auto& f : *trailers) {
                    Detail::sb_append(b, to_view(f.first));
                    Detail::sb_append(b, ": ");
                    Detail::sb_append(b, to_view(f.second));
                    Detail::sb_append(b, "\r\n");
                }
            }
            Detail::sb_append(b, "\r\n");
            return b.release();
        }

        inline Result<uint64_t> parse_chunk_size(string_view line) {
            // chunk-size = 1*HEXDIG [ chunk-ext ]
            const char* p = (line).data();
            const size_t n = static_cast<size_t>((line).size());
            // std::from_chars with base 16 parses hex, stops at the first
            // non-hex digit, and reports overflow -- no manual nibble math.
            size_t i = 0;
            uint64_t acc = 0;
            {
                const auto res = std::from_chars(p, p + n, acc, 16);
                if (res.ec == std::errc::result_out_of_range) {
                    return Error{ErrorCode::HttpChunkError, "chunk size overflows uint64"};
                }
                if (res.ec != std::errc{} || res.ptr == p) {
                    return Error{ErrorCode::HttpChunkError, "chunk size line has no hex digits"};
                }
                i = static_cast<size_t>(res.ptr - p);
            }
            // Anything left must be a chunk extension: ";" + anything but CR/LF.
            if (i < n) {
                if (p[i] != ';') {
                    return Error{ErrorCode::HttpChunkError, "garbage after chunk size"};
                }
                for (size_t k = i; k < n; ++k) {
                    if (p[k] == '\r' || p[k] == '\n') {
                        return Error{ErrorCode::HttpChunkError, "CR/LF inside chunk extension"};
                    }
                }
            }
            return acc;
        }

    } // namespace chunked

    // ---------------------------------------------------------------------------
    // ResponseParser
    // ---------------------------------------------------------------------------
    class ResponseParser::Impl {
    public:
        Impl(Callbacks& cb, ParserLimits limits)
            : limits_(limits), cb_(cb) {
            head_buf_.reserve(1024);
        }

        void set_request_method(Method m) noexcept { request_method_ = m; }

        bool is_complete() const noexcept { return state_ == State::Complete; }
        size_t leftover_offset() const noexcept { return leftover_; }

        VoidResult feed(const uint8_t* data, size_t size) {
            if (state_ == State::Failed) return fail_error_;
            if (state_ == State::Complete) {
                // Extra bytes belong to whatever comes next; the caller decides.
                leftover_ = size;
                return VoidResult{};
            }

            size_t i = 0;
            while (i < size) {
                if (state_ == State::Complete) { leftover_ = size - i; return VoidResult{}; }

                switch (state_) {
                case State::Head: {
                    // Accumulate until the blank line, scanning incrementally so a
                    // huge head is rejected as soon as it exceeds the limit.
                    //
                    // `consumed` is added to `i` exactly ONCE, here. Do not infer
                    // "did I already advance?" from state_: a 1xx response returns
                    // to State::Head, which made the old form add the offset twice
                    // and walk past the buffer.
                    const char* p = reinterpret_cast<const char*>(data + i);
                    const size_t remaining = size - i;
                    size_t consumed = 0;
                    bool head_finished = false;
                    while (consumed < remaining) {
                        head_buf_.push_back(p[consumed]);
                        ++consumed;
                        if (head_buf_.size() > limits_.max_header_bytes) {
                            return fail(ErrorCode::HttpHeaderTooLarge,
                                        "response head exceeds max_header_bytes");
                        }
                        const size_t n = head_buf_.size();
                        if (n >= 4 &&
                            head_buf_[n - 4] == '\r' && head_buf_[n - 3] == '\n' &&
                            head_buf_[n - 2] == '\r' && head_buf_[n - 1] == '\n') {
                            head_finished = true;
                            break;
                        }
                    }
                    i += consumed;
                    if (head_finished) {
                        auto r = parse_head();
                        if (!r) return fail_from(r.error());
                    }
                    break;
                }
                case State::Body_ContentLength: {
                    const uint64_t remaining = content_length_ - body_received_;
                    const size_t avail = size - i;
                    const size_t take = static_cast<size_t>(
                        std::min<uint64_t>(remaining, static_cast<uint64_t>(avail)));
                    if (take > 0) {
                        body_received_ += take;
                        auto r = cb_.on_body_data(data + i, take);
                        if (!r) return fail_from(r.error());
                        i += take;
                    }
                    if (body_received_ == content_length_) {
                        state_ = State::Complete;
                        auto r = cb_.on_complete();
                        if (!r) return fail_from(r.error());
                    }
                    break;
                }
                case State::Body_UntilClose: {
                    const size_t avail = size - i;
                    if (avail > 0) {
                        body_received_ += avail;
                        if (limits_.max_body_bytes != 0 &&
                            body_received_ > limits_.max_body_bytes) {
                            return fail(ErrorCode::HttpBodyTooLarge,
                                        "body exceeds max_body_bytes");
                        }
                        auto r = cb_.on_body_data(data + i, avail);
                        if (!r) return fail_from(r.error());
                        i += avail;
                    }
                    // Completion is signalled by feed_eof(); nothing else can end it.
                    break;
                }
                case State::Body_Chunk_Size: {
                    // Read a whole line first.
                    const char* p = reinterpret_cast<const char*>(data + i);
                    size_t remaining = size - i;
                    auto line_res = read_line(p, remaining, limits_.max_chunk_line_length);
                    if (line_res.status == LineStatus::NeedMore) {
                        i = size;
                        break;
                    }
                    if (line_res.status == LineStatus::TooLong) {
                        return fail(ErrorCode::HttpChunkError, "chunk size line too long");
                    }
                    if (line_res.status == LineStatus::BadTerminator) {
                        return fail(ErrorCode::HttpChunkError, "chunk line not CRLF-terminated");
                    }
                    i += line_res.consumed;
                    auto sz = chunked::parse_chunk_size(
                        string_view(line_res.line.data(),
                                    static_cast<string_view::size_type>(line_res.line.size())));
                    if (!sz) return fail_from(sz.error());
                    chunk_remaining_ = sz.value();
                    if (chunk_remaining_ == 0) {
                        state_ = State::Body_Chunk_Trailer;
                    } else {
                        if (limits_.max_body_bytes != 0 &&
                            body_received_ + chunk_remaining_ > limits_.max_body_bytes) {
                            return fail(ErrorCode::HttpBodyTooLarge,
                                        "body exceeds max_body_bytes");
                        }
                        state_ = State::Body_Chunk_Data;
                    }
                    break;
                }
                case State::Body_Chunk_Data: {
                    const size_t avail = size - i;
                    const size_t take = static_cast<size_t>(
                        std::min<uint64_t>(chunk_remaining_, static_cast<uint64_t>(avail)));
                    if (take > 0) {
                        chunk_remaining_ -= take;
                        body_received_ += take;
                        auto r = cb_.on_body_data(data + i, take);
                        if (!r) return fail_from(r.error());
                        i += take;
                    }
                    if (chunk_remaining_ == 0) state_ = State::Body_Chunk_DataCrlf;
                    break;
                }
                case State::Body_Chunk_DataCrlf: {
                    // The CRLF that terminates a chunk's data. Reading it as an
                    // empty line reuses the split-safe line assembler instead of
                    // hand-rolling a 2-byte lookahead that breaks when the CRLF is
                    // split across feeds.
                    const char* p = reinterpret_cast<const char*>(data + i);
                    const size_t remaining = size - i;
                    auto line_res = read_line(p, remaining, 2);
                    if (line_res.status == LineStatus::NeedMore) {
                        i += line_res.consumed;
                        break;
                    }
                    if (line_res.status == LineStatus::TooLong ||
                        line_res.status == LineStatus::BadTerminator) {
                        return fail(ErrorCode::HttpChunkError,
                                    "chunk data not CRLF-terminated");
                    }
                    if (!line_res.line.empty()) {
                        return fail(ErrorCode::HttpChunkError,
                                    "chunk data not CRLF-terminated");
                    }
                    i += line_res.consumed;
                    state_ = State::Body_Chunk_Size;
                    break;
                }
                case State::Body_Chunk_Trailer: {
                    const char* p = reinterpret_cast<const char*>(data + i);
                    size_t remaining = size - i;
                    auto line_res = read_line(p, remaining, limits_.max_header_field_size);
                    if (line_res.status == LineStatus::NeedMore) { i = size; break; }
                    if (line_res.status == LineStatus::TooLong) {
                        return fail(ErrorCode::HttpTrailerError, "trailer line too long");
                    }
                    if (line_res.status == LineStatus::BadTerminator) {
                        return fail(ErrorCode::HttpTrailerError, "trailer not CRLF-terminated");
                    }
                    i += line_res.consumed;
                    if (line_res.line.empty()) {
                        // Blank line: trailers finished.
                        if (!trailers_.empty()) {
                            auto r = cb_.on_trailers(trailers_);
                            if (!r) return fail_from(r.error());
                        }
                        state_ = State::Complete;
                        auto r = cb_.on_complete();
                        if (!r) return fail_from(r.error());
                        break;
                    }
                    if (++trailer_count_ > limits_.max_trailer_count) {
                        return fail(ErrorCode::HttpTrailerError, "too many trailers");
                    }
                    trailer_bytes_ += line_res.line.size() + 2;
                    if (trailer_bytes_ > limits_.max_trailer_bytes) {
                        return fail(ErrorCode::HttpTrailerError, "trailer block too large");
                    }
                    // "Name: value"
                    size_t colon = 0;
                    for (; colon < line_res.line.size(); ++colon) {
                        if (line_res.line[colon] == ':') break;
                    }
                    if (colon == 0 || colon == line_res.line.size()) {
                        return fail(ErrorCode::HttpTrailerError, "malformed trailer field");
                    }
                    string_view name(line_res.line.data(),
                                     static_cast<string_view::size_type>(colon));
                    string_view value(line_res.line.data() + colon + 1,
                                      static_cast<string_view::size_type>(
                                          line_res.line.size() - colon - 1));
                    if (!is_valid_header_name(name)) {
                        return fail(ErrorCode::HttpTrailerError, "invalid trailer name");
                    }
                    value = http_detail::trim_ows(value);
                    if (!is_valid_header_value(value)) {
                        return fail(ErrorCode::HttpTrailerError, "invalid trailer value");
                    }
                    trailers_.add(name, value);
                    break;
                }
                case State::Complete: {
                    leftover_ = size - i;
                    return VoidResult{};
                }
                case State::Failed:
                    return fail_error_;
                }
            }
            return VoidResult{};
        }

        // Call when the transport reports EOF. Legal only for UntilClose framing.
        VoidResult feed_eof() {
            if (state_ == State::Complete) return VoidResult{};
            if (state_ == State::Failed) return fail_error_;
            if (state_ == State::Body_UntilClose) {
                state_ = State::Complete;
                return cb_.on_complete();
            }
            if (state_ == State::Head) {
                return fail(ErrorCode::HttpInvalidResponse,
                            "connection closed before the response head was complete");
            }
            return fail(ErrorCode::HttpProtocolViolation,
                        "connection closed before the message was complete");
        }

    private:
        enum class State {
            Head,
            Body_ContentLength,
            Body_UntilClose,
            Body_Chunk_Size,
            Body_Chunk_Data,
            Body_Chunk_DataCrlf,
            Body_Chunk_Trailer,
            Complete,
            Failed,
        };

        enum class LineStatus { Ok, NeedMore, TooLong, BadTerminator };
        struct LineResult {
            LineStatus status{LineStatus::NeedMore};
            size_t consumed{0};
            std::vector<char> line;
        };

        // Reads one CRLF-terminated line from [p, p+avail).
        //
        // `consumed` counts the bytes of THIS input buffer that belong to the line
        // (including its terminator). Bytes past the terminator stay with the
        // caller. A line split across feeds is reassembled in line_scratch_.
        LineResult read_line(const char* p, size_t avail, size_t max_len) {
            LineResult r;
            size_t i = 0;
            for (;;) {
                // A complete line may already sit in the scratch from a prior feed.
                for (size_t k = 0; k + 1 < line_scratch_.size(); ++k) {
                    if (line_scratch_[k] == '\r' && line_scratch_[k + 1] == '\n') {
                        r.status = LineStatus::Ok;
                        r.line.assign(line_scratch_.begin(),
                                      line_scratch_.begin() + static_cast<long>(k));
                        line_scratch_.erase(line_scratch_.begin(),
                                            line_scratch_.begin() + static_cast<long>(k + 2));
                        r.consumed = i;
                        return r;
                    }
                    if (line_scratch_[k] == '\n') {
                        r.status = LineStatus::BadTerminator;
                        r.consumed = i;
                        return r;
                    }
                }
                if (line_scratch_.size() > max_len) {
                    r.status = LineStatus::TooLong;
                    r.consumed = i;
                    return r;
                }
                if (i >= avail) {
                    r.status = LineStatus::NeedMore;
                    r.consumed = i;
                    return r;
                }
                line_scratch_.push_back(p[i]);
                ++i;
            }
        }

        VoidResult fail(ErrorCode code, const char* msg) {
            state_ = State::Failed;
            fail_error_ = VoidResult{Error{code, ErrorPhase::Receive,
                                           string(msg)}};
            return fail_error_;
        }

        VoidResult fail_from(const Error& e) {
            state_ = State::Failed;
            fail_error_ = VoidResult{e};
            return fail_error_;
        }

        // Parses the accumulated head buffer: status line, headers, framing decision.
        VoidResult parse_head() {
            const char* p = head_buf_.data();
            const size_t n = head_buf_.size();

            // --- status line: HTTP/1.x SP 3DIGIT [SP reason] CRLF ---
            size_t eol = 0;
            while (eol + 1 < n && !(p[eol] == '\r' && p[eol + 1] == '\n')) ++eol;
            if (eol + 1 >= n) return fail(ErrorCode::HttpInvalidResponse, "no status line terminator");
            if (eol > limits_.max_start_line_length) {
                return fail(ErrorCode::HttpInvalidResponse, "status line too long");
            }

            const string_view status_line(p, static_cast<string_view::size_type>(eol));
            if (static_cast<size_t>((status_line).size()) < 12) {
                return fail(ErrorCode::HttpInvalidResponse, "status line too short");
            }
            if (!Detail::ascii_iequals(string_view(p, 5), "HTTP/")) {
                return fail(ErrorCode::HttpInvalidResponse, "not an HTTP response");
            }
            const char major = p[5];
            if (p[6] != '.' || !Detail::is_digit(major) || major == '0') {
                return fail(ErrorCode::HttpVersionNotSupported, "unsupported HTTP version");
            }
            const char minor = p[7];
            if (!Detail::is_digit(minor)) {
                return fail(ErrorCode::HttpInvalidResponse, "bad HTTP minor version");
            }
            if (p[8] != ' ') return fail(ErrorCode::HttpInvalidResponse, "missing space after version");
            // status-code = 3DIGIT; the leading digit must be 1-9 (no "0xx" codes).
            if (!Detail::is_digit(p[9]) || p[9] == '0' ||
                !Detail::is_digit(p[10]) || !Detail::is_digit(p[11])) {
                return fail(ErrorCode::HttpInvalidResponse, "bad status code");
            }
            const int code = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');

            ParsedResponse pr;
            pr.http_major = major - '0';
            pr.http_minor = minor - '0';
            pr.status_code = code;
            if (static_cast<size_t>((status_line).size()) > 12) {
                if (p[12] != ' ') return fail(ErrorCode::HttpInvalidResponse, "bad reason separator");
                pr.reason = string(p + 13,
                                   static_cast<string::size_type>(eol - 13));
            }

            // --- headers ---
            size_t pos = eol + 2;
            size_t count = 0;
            size_t head_accounted = 0;
            while (pos < n) {
                if (pos + 1 < n && p[pos] == '\r' && p[pos + 1] == '\n') {
                    pos += 2;
                    break;    // end of the head
                }
                size_t line_end = pos;
                while (line_end + 1 < n && !(p[line_end] == '\r' && p[line_end + 1] == '\n')) {
                    ++line_end;
                }
                if (line_end + 1 >= n) {
                    return fail(ErrorCode::HttpInvalidResponse, "unterminated header line");
                }
                const size_t line_len = line_end - pos;
                if (line_len > limits_.max_header_field_size) {
                    return fail(ErrorCode::HttpHeaderTooLarge, "header field too large");
                }
                if (++count > limits_.max_header_count) {
                    return fail(ErrorCode::HttpHeaderCountExceeded, "too many header fields");
                }
                head_accounted += line_len + 2;
                if (head_accounted > limits_.max_header_bytes) {
                    return fail(ErrorCode::HttpHeaderTooLarge, "header block too large");
                }

                // obs-fold (a line starting with SP/HTAB) is rejected, not unfolded:
                // it is obsolete and a known smuggling vector.
                if (p[pos] == ' ' || p[pos] == '\t') {
                    return fail(ErrorCode::HttpProtocolViolation,
                                "obsolete line folding is not accepted");
                }

                size_t colon = pos;
                while (colon < line_end && p[colon] != ':') ++colon;
                if (colon == pos || colon == line_end) {
                    return fail(ErrorCode::HttpInvalidResponse, "malformed header field");
                }
                const string_view name(p + pos, static_cast<string_view::size_type>(colon - pos));
                string_view value(p + colon + 1,
                                  static_cast<string_view::size_type>(line_end - colon - 1));
                if (!is_valid_header_name(name)) {
                    return fail(ErrorCode::HttpInvalidResponse, "invalid header name");
                }
                value = http_detail::trim_ows(value);
                if (!is_valid_header_value(value)) {
                    return fail(ErrorCode::HttpInvalidResponse,
                                "invalid header value (CR/LF/NUL)");
                }
                // A header NAME with a trailing space before ':' is rejected above
                // (name grammar has no SP), which blocks the classic smuggling case.
                pr.headers.add(name, value);
                pos = line_end + 2;
            }

            pr.head_bytes = pos;

            // --- framing decision ---
            auto r = resolve_framing(&pr);
            if (!r) return fail_from(r.error());

            // --- 1xx is informational, not final: keep parsing ---
            if (code >= 100 && code < 200 && code != 101) {
                pr.informational.push_back(code);
                informational_.push_back(code);
                head_buf_.clear();
                state_ = State::Head;
                return VoidResult{};
            }
            if (code == 101) {
                // Protocol switch: this parser hands the connection over. No body.
                pr.framing = ParsedResponse::BodyFraming::None;
            }

            pr.informational = informational_;
            head_buf_.clear();

            auto cb_res = cb_.on_head(pr);
            if (!cb_res) return fail_from(cb_res.error());

            switch (pr.framing) {
            case ParsedResponse::BodyFraming::None:
                state_ = State::Complete;
                return cb_.on_complete();
            case ParsedResponse::BodyFraming::ContentLength:
                if (content_length_ == 0) {
                    state_ = State::Complete;
                    return cb_.on_complete();
                }
                state_ = State::Body_ContentLength;
                return VoidResult{};
            case ParsedResponse::BodyFraming::Chunked:
                state_ = State::Body_Chunk_Size;
                return VoidResult{};
            case ParsedResponse::BodyFraming::UntilClose:
                state_ = State::Body_UntilClose;
                return VoidResult{};
            }
            return VoidResult{};
        }

        VoidResult resolve_framing(ParsedResponse* pr) {
            const bool is_head = (request_method_ == Method::Head);
            const int code = pr->status_code;

            // No body by definition.
            if (is_head || code == 204 || code == 304 || (code >= 100 && code < 200)) {
                pr->framing = ParsedResponse::BodyFraming::None;
                finalize_connection_flags(pr);
                return VoidResult{};
            }

            // Transfer-Encoding beats Content-Length (RFC 7230 3.3.3).
            auto te_all = pr->headers.get_all("transfer-encoding");
            auto cl_all = pr->headers.get_all("content-length");

            if (!te_all.empty()) {
                // Combines all TE header values into one ordered token list.
                string_builder te_b;
                for (size_t k = 0; k < te_all.size(); ++k) {
                    if (k > 0) Detail::sb_append(te_b, ',');
                    Detail::sb_append(te_b, te_all[k]);
                }
                string te = te_b.release();
                auto tokens = http_detail::split_list(to_view(te));
                if (tokens.empty()) {
                    return VoidResult{Error{ErrorCode::HttpAmbiguousFraming,
                                            "empty Transfer-Encoding"}};
                }
                // The FINAL coding must be chunked; anything else is ambiguous here.
                if (!Detail::ascii_iequals(tokens.back(), "chunked")) {
                    return VoidResult{Error{ErrorCode::HttpAmbiguousFraming,
                        "Transfer-Encoding does not end with chunked"}};
                }
                // "chunked" may appear only once and only as the last coding.
                size_t chunked_count = 0;
                for (size_t k = 0; k < tokens.size(); ++k) {
                    if (Detail::ascii_iequals(tokens[k], "chunked")) ++chunked_count;
                }
                if (chunked_count != 1) {
                    return VoidResult{Error{ErrorCode::HttpAmbiguousFraming,
                                            "chunked appears more than once"}};
                }
                pr->framing = ParsedResponse::BodyFraming::Chunked;
                pr->has_trailers = pr->headers.contains("trailer");
                // A Content-Length alongside chunked is a smuggling signal; reject.
                if (!cl_all.empty()) {
                    return VoidResult{Error{ErrorCode::HttpAmbiguousFraming,
                        "both Transfer-Encoding and Content-Length present"}};
                }
                finalize_connection_flags(pr);
                return VoidResult{};
            }

            if (!cl_all.empty()) {
                // Multiple CL values must all be identical (or one list of equal values).
                std::vector<uint64_t> values;
                for (size_t k = 0; k < cl_all.size(); ++k) {
                    auto parts = http_detail::split_list(cl_all[k]);
                    if (parts.empty()) {
                        return VoidResult{Error{ErrorCode::HttpInvalidResponse,
                                                "empty Content-Length"}};
                    }
                    for (size_t j = 0; j < parts.size(); ++j) {
                        const char* q = (parts[j]).data();
                        const size_t qn = static_cast<size_t>((parts[j]).size());
                        if (qn == 0) {
                            return VoidResult{Error{ErrorCode::HttpInvalidResponse,
                                                    "empty Content-Length value"}};
                        }
                        uint64_t acc = 0;
                        for (size_t t = 0; t < qn; ++t) {
                            const char c = q[t];
                            if (c < '0' || c > '9') {
                                return VoidResult{Error{ErrorCode::HttpInvalidResponse,
                                                        "non-numeric Content-Length"}};
                            }
                            const uint64_t d = static_cast<uint64_t>(c - '0');
                            if (acc > (UINT64_MAX - d) / 10) {
                                return VoidResult{Error{ErrorCode::HttpInvalidResponse,
                                                        "Content-Length overflows"}};
                            }
                            acc = acc * 10 + d;
                        }
                        values.push_back(acc);
                    }
                }
                for (size_t k = 1; k < values.size(); ++k) {
                    if (values[k] != values[0]) {
                        return VoidResult{Error{ErrorCode::HttpAmbiguousFraming,
                                                "conflicting Content-Length values"}};
                    }
                }
                pr->content_length = values[0];
                content_length_ = values[0];
                if (limits_.max_body_bytes != 0 && content_length_ > limits_.max_body_bytes) {
                    return VoidResult{Error{ErrorCode::HttpBodyTooLarge,
                                            "Content-Length exceeds max_body_bytes"}};
                }
                pr->framing = ParsedResponse::BodyFraming::ContentLength;
                finalize_connection_flags(pr);
                return VoidResult{};
            }

            pr->framing = ParsedResponse::BodyFraming::UntilClose;
            finalize_connection_flags(pr);
            return VoidResult{};
        }

        void finalize_connection_flags(ParsedResponse* pr) {
            const bool http10 = (pr->http_major == 1 && pr->http_minor == 0);
            auto conn = pr->headers.get("connection");
            bool close_token = false, keep_alive_token = false;
            if (conn) {
                close_token = http_detail::header_has_token(*conn, "close");
                keep_alive_token = http_detail::header_has_token(*conn, "keep-alive");
            }
            if (close_token) pr->connection_close = true;
            else if (http10 && !keep_alive_token) pr->connection_close = true;
            // A UntilClose body inherently closes the connection.
            if (pr->framing == ParsedResponse::BodyFraming::UntilClose) {
                pr->connection_close = true;
            }
            pr->keep_alive = !pr->connection_close;
        }

        ParserLimits limits_;
        Callbacks& cb_;
        State state_{State::Head};

        std::vector<char> head_buf_;
        std::vector<char> line_scratch_;
        Headers trailers_;
        std::vector<int> informational_;

        Method request_method_{Method::Get};
        uint64_t content_length_{0};
        uint64_t body_received_{0};
        uint64_t chunk_remaining_{0};
        size_t trailer_count_{0};
        size_t trailer_bytes_{0};
        size_t leftover_{0};
        VoidResult fail_error_;
    };

    // --- ResponseParser public member definitions ---

    inline ResponseParser::ResponseParser(Callbacks& callbacks, ParserLimits limits)
        : impl_(std::make_unique<Impl>(callbacks, limits)) {}

    inline ResponseParser::~ResponseParser() = default;
    inline ResponseParser::ResponseParser(ResponseParser&&) noexcept = default;
    inline ResponseParser& ResponseParser::operator=(ResponseParser&&) noexcept = default;

    inline void ResponseParser::set_request_method(Method m) noexcept {
        impl_->set_request_method(m);
    }

    inline VoidResult ResponseParser::feed(const uint8_t* data, size_t size) {
        return impl_->feed(data, size);
    }

    inline VoidResult ResponseParser::feed_eof() {
        return impl_->feed_eof();
    }

    inline bool ResponseParser::is_complete() const noexcept {
        return impl_->is_complete();
    }

    inline size_t ResponseParser::leftover_offset() const noexcept {
        return impl_->leftover_offset();
    }

} // namespace MegoHttp

#endif // MEGOHTTP_HTTP_IMPL_HPP_INCLUDED
