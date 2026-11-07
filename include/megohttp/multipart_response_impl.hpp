#ifndef MEGOHTTP_MULTIPART_RESPONSE_IMPL_HPP_INCLUDED
#define MEGOHTTP_MULTIPART_RESPONSE_IMPL_HPP_INCLUDED

#include <megohttp/multipart_response.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdio>
#include <string>

namespace megohttp {

    class MultipartResponseParser::Impl {
    public:
        Impl(Callbacks& cbs, string_view boundary, Limits limits)
            : callbacks_(cbs), limits_(limits) {
            // RFC 2046 caps a boundary at 70 characters; reject an over-long one up
            // front instead of building a needle that can never legally match.
            if (static_cast<size_t>(boundary.size()) > limits_.max_boundary_length) {
                boundary_too_long_ = true;
                return;
            }
            if (!boundary.empty()) {
                needle_.assign("--");
                needle_.append(boundary.data(), boundary.size());
            }
        }

        bool is_complete() const noexcept { return state_ == State::Done; }
        bool is_failed() const noexcept { return state_ == State::Failed; }
        size_t leftover_offset() const noexcept { return leftover_; }

        VoidResult feed(const uint8_t* data, size_t size) {
            if (state_ == State::Failed) return fail_error_;
            if (state_ == State::Done) {
                if (limits_.max_epilogue_size != 0 &&
                    leftover_ + size > limits_.max_epilogue_size) {
                    return fail(ErrorCode::MultipartLimitExceeded,
                                "epilogue exceeds max_epilogue_size");
                }
                leftover_ += size;
                return VoidResult{};
            }
            if (needle_.empty()) {
                if (boundary_too_long_)
                    return fail(ErrorCode::MultipartLimitExceeded,
                                "boundary exceeds max_boundary_length");
                return fail(ErrorCode::MultipartMediaTypeInvalid,
                            "multipart boundary is empty");
            }

            if (paused_skip_ > 0) { buffer_.erase(0, paused_skip_); paused_skip_ = 0; }
            buffer_.append(reinterpret_cast<const char*>(data), size);

            while (state_ != State::Done && state_ != State::Failed) {
                if (state_ == State::Headers) {
                    if (!process_headers()) break;
                    continue;
                }

                const size_t pos = buffer_.find(needle_);
                if (pos == std::string::npos) {
                    const size_t keep = needle_.size() + 1;
                    const size_t safe = buffer_.size() > keep ? buffer_.size() - keep : 0;
                    if (safe > 0) {
                        if (!emit(safe)) break;
                        if (state_ == State::Failed) break;
                    }
                    break;
                }

                const bool at_line_start =
                    (pos == 0) || (pos >= 2 && buffer_[pos - 2] == '\r' && buffer_[pos - 1] == '\n');
                if (!at_line_start) {
                    if (!emit(pos + 1)) break;
                    if (state_ == State::Failed) break;
                    continue;
                }

                const size_t payload_end = (pos >= 2) ? pos - 2 : 0;
                const size_t after = pos + needle_.size();
                if (buffer_.size() < after + 2) break;

                bool is_closing = false;
                size_t suff = 0;
                if (buffer_[after] == '-' && buffer_[after + 1] == '-') {
                    is_closing = true;
                    suff = 2;
                    if (after + 3 < buffer_.size() && buffer_[after + 2] == '\r' &&
                        buffer_[after + 3] == '\n') suff += 2;
                } else if (buffer_[after] == '\r' && buffer_[after + 1] == '\n') {
                    suff = 2;
                } else {
                    if (!emit(pos + 1)) break;
                    if (state_ == State::Failed) break;
                    continue;
                }

                if (state_ == State::Data) {
                    if (payload_end > 0) {
                        part_bytes_ += payload_end;
                        if (limits_.max_part_bytes != 0 &&
                            part_bytes_ > limits_.max_part_bytes) {
                            return fail(ErrorCode::MultipartLimitExceeded,
                                        "part data exceeds max_part_bytes");
                        }
                        if (!callbacks_.on_part_data(
                                string_view(buffer_.data(), payload_end))) {
                            paused_skip_ = payload_end;
                            return VoidResult{};
                        }
                    }
                    auto r = callbacks_.on_part_end();
                    if (!r) return fail_from(r.error());
                } else if (state_ == State::Preamble) {
                    if (limits_.max_preamble_size != 0 &&
                        preamble_bytes_ + payload_end > limits_.max_preamble_size) {
                        return fail(ErrorCode::MultipartLimitExceeded,
                                    "preamble exceeds max_preamble_size");
                    }
                    preamble_bytes_ += payload_end;
                }

                buffer_.erase(0, after + suff);

                if (is_closing) {
                    // The bytes still in the buffer are the epilogue. They are only
                    // counted (never buffered or delivered here), so the cap is
                    // enforced on the count, not on a copy (S3.4-25).
                    if (limits_.max_epilogue_size != 0 &&
                        leftover_ + buffer_.size() > limits_.max_epilogue_size) {
                        return fail(ErrorCode::MultipartLimitExceeded,
                                    "epilogue exceeds max_epilogue_size");
                    }
                    auto r = callbacks_.on_complete();
                    if (!r) return fail_from(r.error());
                    state_ = State::Done;
                    leftover_ = buffer_.size();
                    break;
                }

                ++part_count_;
                if (part_count_ > limits_.max_part_count) {
                    return fail(ErrorCode::MultipartLimitExceeded, "too many parts");
                }
                part_bytes_ = 0;
                state_ = State::Headers;
            }
            return state_ == State::Failed ? fail_error_ : VoidResult{};
        }

        VoidResult feed_eof() {
            if (state_ == State::Done) return VoidResult{};
            if (state_ == State::Failed) return fail_error_;
            if (state_ == State::Data) {
                // A trailing CRLF is the delimiter's leading CRLF, not payload
                // (RFC 2046); the close-delimiter path already strips it.
                if (limits_.allow_continuous_stream && buffer_.size() >= 2 &&
                    buffer_[buffer_.size() - 2] == '\r' && buffer_[buffer_.size() - 1] == '\n') {
                    buffer_.erase(buffer_.size() - 2, 2);
                }
                if (!buffer_.empty()) {
                    part_bytes_ += buffer_.size();
                    if (limits_.max_part_bytes != 0 &&
                        part_bytes_ > limits_.max_part_bytes) {
                        return fail(ErrorCode::MultipartLimitExceeded,
                                    "part data exceeds max_part_bytes");
                    }
                    if (!callbacks_.on_part_data(
                            string_view(buffer_.data(), buffer_.size()))) {
                        // Paused: the caller must resume and feed again. Keep the
                        // bytes so the part is not silently truncated.
                        paused_skip_ = 0;
                        return VoidResult{};
                    }
                    buffer_.clear();
                }
                if (limits_.allow_continuous_stream) {
                    // x-mixed-replace: the peer ends the stream by closing, so a
                    // missing close-delimiter is the normal terminator. The final
                    // CRLF is part of the delimiter that never arrived, not part
                    // of the payload (same rule as the close-delimiter path).
                    auto re = callbacks_.on_part_end();
                    if (!re) return fail_from(re.error());
                    auto rc = callbacks_.on_complete();
                    if (!rc) return fail_from(rc.error());
                    state_ = State::Done;
                    return VoidResult{};
                }
                return fail(ErrorCode::MultipartTruncated, "missing close-delimiter");
            }
            if (state_ == State::Headers)
                return fail(ErrorCode::MultipartTruncated, "EOF inside part headers");
            if (state_ == State::Preamble) {
                if (limits_.allow_continuous_stream) {
                    auto rc = callbacks_.on_complete();
                    if (!rc) return fail_from(rc.error());
                    state_ = State::Done;
                    return VoidResult{};
                }
                return fail(ErrorCode::MultipartTruncated, "EOF before the first boundary");
            }
            return VoidResult{};
        }

    private:
        enum class State { Preamble, Headers, Data, Done, Failed };

        VoidResult fail(ErrorCode code, string_view msg) {
            state_ = State::Failed;
            fail_error_ = VoidResult{Error{code, ErrorPhase::Receive,
                                           string(msg.data(), msg.size())}};
            return fail_error_;
        }
        VoidResult fail_from(const Error& e) {
            state_ = State::Failed;
            fail_error_ = VoidResult{e};
            return fail_error_;
        }

        bool emit(size_t len) {
            if (len == 0) return true;
            if (state_ == State::Data) {
                part_bytes_ += len;
                if (limits_.max_part_bytes != 0 && part_bytes_ > limits_.max_part_bytes) {
                    fail(ErrorCode::MultipartLimitExceeded, "part data exceeds max_part_bytes");
                    return false;
                }
                if (!callbacks_.on_part_data(string_view(buffer_.data(), len))) {
                    paused_skip_ = len;
                    return false;
                }
            } else if (state_ == State::Preamble) {
                if (limits_.max_preamble_size != 0 &&
                    preamble_bytes_ + len > limits_.max_preamble_size) {
                    fail(ErrorCode::MultipartLimitExceeded,
                         "preamble exceeds max_preamble_size");
                    return false;
                }
                preamble_bytes_ += len;
            } else if (state_ == State::Done) {
                if (limits_.max_epilogue_size != 0 &&
                    leftover_ + len > limits_.max_epilogue_size) {
                    fail(ErrorCode::MultipartLimitExceeded,
                         "epilogue exceeds max_epilogue_size");
                    return false;
                }
            }
            buffer_.erase(0, len);
            return true;
        }

        bool process_headers() {
            // A part with NO header fields is legal (RFC 2046): the header block is
            // then just an empty line, so the terminator is a single CRLF at the
            // very start of the buffer. Looking only for CRLFCRLF would block on
            // that case forever.
            if (buffer_.size() >= 2 && buffer_[0] == '\r' && buffer_[1] == '\n') {
                buffer_.erase(0, 2);
                state_ = State::Data;
                Headers empty;
                auto r0 = callbacks_.on_part_start(empty);
                if (!r0) { fail_from(r0.error()); return false; }
                return true;
            }

            const size_t end = buffer_.find("\r\n\r\n");
            if (end == std::string::npos) {
                if (buffer_.size() > limits_.max_header_bytes) {
                    fail(ErrorCode::MultipartLimitExceeded, "part headers too large");
                }
                return false;
            }
            if (end > limits_.max_header_bytes) {
                fail(ErrorCode::MultipartLimitExceeded, "part headers too large");
                return false;
            }
            auto headers = parse_headers(buffer_.data(), end + 2);
            if (!headers) { fail_from(headers.error()); return false; }
            buffer_.erase(0, end + 4);
            state_ = State::Data;
            auto r = callbacks_.on_part_start(headers.value());
            if (!r) { fail_from(r.error()); return false; }
            return true;
        }

        Result<Headers> parse_headers(const char* data, size_t len) {
            Headers out;
            size_t count = 0;
            size_t i = 0;
            while (i + 1 < len) {
                size_t eol = i;
                while (eol + 1 < len && !(data[eol] == '\r' && data[eol + 1] == '\n')) ++eol;
                if (eol + 1 >= len) break;
                const size_t line_len = eol - i;
                if (line_len > 0) {
                    if (data[i] == ' ' || data[i] == '\t') {
                        return Error{ErrorCode::MultipartPartHeaderInvalid, ErrorPhase::Receive,
                                     string("obsolete line folding in part headers")};
                    }
                    size_t colon = i;
                    while (colon < eol && data[colon] != ':') ++colon;
                    if (colon == i || colon == eol) {
                        return Error{ErrorCode::MultipartPartHeaderInvalid, ErrorPhase::Receive,
                                     string("malformed part header field")};
                    }
                    if (++count > limits_.max_header_count) {
                        return Error{ErrorCode::MultipartLimitExceeded, ErrorPhase::Receive,
                                     string("too many part header fields")};
                    }
                    string_view name(data + i,
                                     static_cast<string_view::size_type>(colon - i));
                    string_view value(data + colon + 1,
                                      static_cast<string_view::size_type>(eol - colon - 1));
                    while (!value.empty() && (value.data()[0] == ' ' || value.data()[0] == '\t'))
                        value = string_view(value.data() + 1,
                                            static_cast<string_view::size_type>(value.size() - 1));
                    while (!value.empty()) {
                        const char last = value.data()[value.size() - 1];
                        if (last != ' ' && last != '\t') break;
                        value = string_view(value.data(),
                                            static_cast<string_view::size_type>(value.size() - 1));
                    }
                    if (!is_valid_header_name(name) || !is_valid_header_value(value)) {
                        return Error{ErrorCode::MultipartPartHeaderInvalid, ErrorPhase::Receive,
                                     string("invalid part header field")};
                    }
                    out.add(name, value);
                }
                i = eol + 2;
            }
            return out;
        }

        Callbacks& callbacks_;
        Limits limits_;
        std::string needle_;
        std::string buffer_;
        std::string header_buf_;
        State state_{State::Preamble};
        size_t part_count_{0};
        size_t part_bytes_{0};
        size_t preamble_bytes_{0};
        size_t leftover_{0};
        bool boundary_too_long_{false};
        size_t paused_skip_{0};
        VoidResult fail_error_;
    };

    inline MultipartResponseParser::MultipartResponseParser(Callbacks& cbs,
                                                           string_view boundary,
                                                           Limits limits)
        : impl_(std::make_unique<Impl>(cbs, boundary, limits)) {}
    inline MultipartResponseParser::~MultipartResponseParser() = default;
    inline MultipartResponseParser::MultipartResponseParser(MultipartResponseParser&&) noexcept = default;
    inline MultipartResponseParser& MultipartResponseParser::operator=(MultipartResponseParser&&) noexcept = default;
    inline VoidResult MultipartResponseParser::feed(const uint8_t* data, size_t size) {
        return impl_->feed(data, size);
    }
    inline VoidResult MultipartResponseParser::feed_eof() { return impl_->feed_eof(); }
    inline bool MultipartResponseParser::is_complete() const noexcept { return impl_->is_complete(); }
    inline bool MultipartResponseParser::is_failed() const noexcept { return impl_->is_failed(); }
    inline size_t MultipartResponseParser::leftover_offset() const noexcept { return impl_->leftover_offset(); }

} // namespace megohttp

#endif // MEGOHTTP_MULTIPART_RESPONSE_IMPL_HPP_INCLUDED
