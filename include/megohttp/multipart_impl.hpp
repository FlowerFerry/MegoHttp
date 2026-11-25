#ifndef MEGOHTTP_MULTIPART_IMPL_HPP_INCLUDED
#define MEGOHTTP_MULTIPART_IMPL_HPP_INCLUDED

// Included at the end of multipart.hpp. Header-only: every definition is inline.

#include <megohttp/format.hpp>
#include <megohttp/http.hpp>

#include <algorithm>
#include <cstdio>
#include <random>
#include <variant>

namespace megohttp {

    namespace multipart_detail {

        // Escapes a value for use inside a Content-Disposition quoted-string.
        //
        // RFC 7578 5.1 puts field names and filenames in a quoted string, so the
        // characters that would terminate or corrupt it have to go. CR and LF are
        // rejected outright rather than escaped: a bare newline in a header is a
        // smuggling vector and no legitimate filename needs one.
        inline Result<string> quote_parameter(string_view value, const char* what) {
            fmt::memory_buffer buf;
            auto out = fmt::appender(buf);
            const char* p = (value).data();
            const size_t n = static_cast<size_t>((value).size());
            for (size_t i = 0; i < n; ++i) {
                const unsigned char c = static_cast<unsigned char>(p[i]);
                if (c == '\r' || c == '\n' || c == '\0') {
                    return Error{ErrorCode::MultipartMediaTypeInvalid, ErrorPhase::Send,
                                 format("{} contains a control character", what)};
                }
                if (c == '"' || c == '\\') {
                    buf.push_back('\\');
                }
                buf.push_back(static_cast<char>(c));
            }
            return detail::sb_release(buf);
        }

        // Generates a boundary that cannot appear verbatim in typical payloads.
        //
        // 32 hex characters from a random source: RFC 2046 caps a boundary at 70
        // characters, and a long random value makes an accidental collision with
        // the payload negligible. Not a security boundary -- a caller that needs
        // unpredictability can call set_boundary() with its own value.
        inline string make_boundary() {
            static const char* kHex = "0123456789abcdef";
            std::random_device rd;
            char raw[32];
            for (size_t i = 0; i < sizeof raw; i += 4) {
                const unsigned v = rd();
                raw[i + 0] = kHex[(v >> 28) & 0xF];
                raw[i + 1] = kHex[(v >> 24) & 0xF];
                raw[i + 2] = kHex[(v >> 20) & 0xF];
                raw[i + 3] = kHex[(v >> 16) & 0xF];
            }
            fmt::memory_buffer buf;
            buf.append("----MegoHttpBoundary", "----MegoHttpBoundary" + 21);
            buf.append(raw, raw + sizeof raw);
            return detail::sb_release(buf);
        }

        // A boundary must be 1..70 characters from the RFC 2046 bchars set, and must
        // not end with a space (the closing delimiter would then be ambiguous).
        inline bool is_valid_boundary(string_view b) noexcept {
            const size_t n = static_cast<size_t>(b.size());
            if (n == 0 || n > 70) return false;
            for (size_t i = 0; i < n; ++i) {
                const char c = b.data()[i];
                const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                                (c >= 'A' && c <= 'Z') ||
                                c == '\'' || c == '(' || c == ')' || c == '+' ||
                                c == '_' || c == ',' || c == '-' || c == '.' ||
                                c == '/' || c == ':' || c == '=' || c == '?' ||
                                c == ' ';
                if (!ok) return false;
            }
            return b.data()[n - 1] != ' ';
        }

        // One part of the body, as it will be laid out on the wire.
        struct Part {
            enum class Kind { Text, File, Stream } kind{Kind::Text};

            string name;
            string filename;      // File and Stream only
            string content_type;  // File and Stream only
            std::vector<uint8_t> data;      // Text and File
            Request::BodySource source;     // Stream only
            std::optional<uint64_t> size;   // Stream only, when known
        };

        // Bytes of "--boundary\r\n" that open a part.
        inline string part_opening(string_view boundary) {
            fmt::memory_buffer buf;
            auto out = fmt::appender(buf);
            fmt::format_to(out, "--{}\r\n", boundary);
            return detail::sb_release(buf);
        }

        // Bytes of "\r\n--boundary" that close a part. The terminating CRLF belongs
        // to the delimiter, not to the part data (RFC 2046), which is why the body
        // of a part is emitted followed by CRLF and then this.
        inline string part_separator(string_view boundary) {
            fmt::memory_buffer buf;
            auto out = fmt::appender(buf);
            fmt::format_to(out, "\r\n--{}", boundary);
            return detail::sb_release(buf);
        }

        // "\r\n--boundary--" closes the body.
        inline string closing_delimiter(string_view boundary) {
            fmt::memory_buffer buf;
            auto out = fmt::appender(buf);
            fmt::format_to(out, "\r\n--{}--\r\n", boundary);
            return detail::sb_release(buf);
        }

        // Headers of one part, including the leading blank line that ends them.
        inline Result<string> part_headers(const Part& part) {
            fmt::memory_buffer buf;
            auto out = fmt::appender(buf);

            auto name_q = quote_parameter(to_view(part.name), "field name");
            if (!name_q) return name_q.error();

            if (part.kind == Part::Kind::Text) {
                fmt::format_to(out, "Content-Disposition: form-data; name=\"{}\"\r\n",
                               name_q.value());
            } else {
                auto file_q = quote_parameter(to_view(part.filename), "filename");
                if (!file_q) return file_q.error();
                fmt::format_to(out,
                    "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                    name_q.value(), file_q.value());
                if (!part.content_type.empty()) {
                    fmt::format_to(out, "Content-Type: {}\r\n", part.content_type);
                }
            }
            buf.push_back('\r');
            buf.push_back('\n');
            return detail::sb_release(buf);
        }

    } // namespace multipart_detail

    // ---------------------------------------------------------------------------
    // MultipartBuilder
    // ---------------------------------------------------------------------------
    class MultipartBuilder::Impl {
    public:
        Impl() : boundary(multipart_detail::make_boundary()) {}

        string boundary;
        std::vector<multipart_detail::Part> parts;
    };

    inline MultipartBuilder::MultipartBuilder() : impl_(std::make_unique<Impl>()) {}

    inline MultipartBuilder::~MultipartBuilder() = default;

    inline MultipartBuilder::MultipartBuilder(const MultipartBuilder& other)
        : impl_(std::make_unique<Impl>(*other.impl_)) {}

    inline MultipartBuilder& MultipartBuilder::operator=(const MultipartBuilder& other) {
        if (this != &other) *impl_ = *other.impl_;
        return *this;
    }

    inline MultipartBuilder::MultipartBuilder(MultipartBuilder&&) noexcept = default;
    inline MultipartBuilder& MultipartBuilder::operator=(MultipartBuilder&&) noexcept = default;

    inline VoidResult MultipartBuilder::add_text_field(string_view name, string_view value) {
        if (static_cast<size_t>((name).size()) == 0) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("multipart field name is empty")};
        }
        // Reject a name that cannot be escaped into a header now, not when the body
        // is built: a caller that gets VoidResult{} here expects the field accepted.
        auto name_ok = multipart_detail::quote_parameter(name, "field name");
        if (!name_ok) return name_ok.error();
        multipart_detail::Part p;
        p.kind = multipart_detail::Part::Kind::Text;
        p.name = to_string(name);
        const char* d = (value).data();
        p.data.assign(reinterpret_cast<const uint8_t*>(d),
                      reinterpret_cast<const uint8_t*>(d) + static_cast<size_t>((value).size()));
        p.size = static_cast<uint64_t>(p.data.size());
        impl_->parts.push_back(std::move(p));
        return VoidResult{};
    }

    inline VoidResult MultipartBuilder::add_file_field(string_view name,
                                                       string_view filename,
                                                       string_view content_type,
                                                       std::vector<uint8_t> data) {
        if (static_cast<size_t>((name).size()) == 0) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("multipart field name is empty")};
        }
        auto name_ok = multipart_detail::quote_parameter(name, "field name");
        if (!name_ok) return name_ok.error();
        auto file_ok = multipart_detail::quote_parameter(filename, "filename");
        if (!file_ok) return file_ok.error();
        multipart_detail::Part p;
        p.kind = multipart_detail::Part::Kind::File;
        p.name = to_string(name);
        p.filename = to_string(filename);
        p.content_type = to_string(content_type);
        p.data = std::move(data);
        p.size = static_cast<uint64_t>(p.data.size());
        impl_->parts.push_back(std::move(p));
        return VoidResult{};
    }

    inline VoidResult MultipartBuilder::add_file_field(
        string_view name, string_view filename, string_view content_type,
        std::shared_ptr<FileSource> source) {
        if (!source) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("multipart file field has no source")};
        }
        return add_stream_field(name, filename, content_type,
                                source->body_source(), source->size());
    }

    inline VoidResult MultipartBuilder::add_file_field(
        string_view name, string_view filename, string_view content_type,
        string_view path, FileSource::Options options) {
        auto opened = FileSource::open(path, options);
        if (!opened) return opened.error();
        return add_file_field(name, filename, content_type,
                              std::move(opened.value()));
    }

    inline VoidResult MultipartBuilder::add_stream_field(string_view name,
                                                         string_view filename,
                                                         string_view content_type,
                                                         Request::BodySource source,
                                                         std::optional<uint64_t> size) {
        if (static_cast<size_t>((name).size()) == 0) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("multipart field name is empty")};
        }
        if (!source) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("multipart stream field has no source")};
        }
        auto name_ok = multipart_detail::quote_parameter(name, "field name");
        if (!name_ok) return name_ok.error();
        auto file_ok = multipart_detail::quote_parameter(filename, "filename");
        if (!file_ok) return file_ok.error();
        multipart_detail::Part p;
        p.kind = multipart_detail::Part::Kind::Stream;
        p.name = to_string(name);
        p.filename = to_string(filename);
        p.content_type = to_string(content_type);
        p.source = std::move(source);
        p.size = size;
        impl_->parts.push_back(std::move(p));
        return VoidResult{};
    }

    inline size_t MultipartBuilder::field_count() const noexcept {
        return impl_->parts.size();
    }

    inline string_view MultipartBuilder::boundary() const noexcept {
        return to_view(impl_->boundary);
    }

    inline VoidResult MultipartBuilder::set_boundary(string_view b) {
        if (!multipart_detail::is_valid_boundary(b)) {
            return Error{ErrorCode::MultipartMediaTypeInvalid, ErrorPhase::None,
                         format("boundary must be 1..70 bchars and must not end with a space")};
        }
        impl_->boundary = to_string(b);
        return VoidResult{};
    }

    inline string MultipartBuilder::content_type_header() const {
        fmt::memory_buffer buf;
        auto out = fmt::appender(buf);
        fmt::format_to(out, "multipart/form-data; boundary={}", impl_->boundary);
        return detail::sb_release(buf);
    }

    inline std::optional<uint64_t> MultipartBuilder::compute_total_size() const {
        // An empty builder still emits the closing delimiter, so the size is never
        // really zero -- but there is also nothing to send, and callers expect
        // nullopt to mean "no body". Report 0 for that case.
        if (impl_->parts.empty()) return std::optional<uint64_t>(0);

        uint64_t total = 0;
        const string open = multipart_detail::part_opening(to_view(impl_->boundary));
        for (size_t i = 0; i < impl_->parts.size(); ++i) {
            const auto& p = impl_->parts[i];
            auto hdr = multipart_detail::part_headers(p);
            if (!hdr) return std::nullopt;   // invalid name/filename: let build_body report it
            if (!p.size.has_value()) return std::nullopt;
            total += static_cast<uint64_t>(open.size());
            total += static_cast<uint64_t>(hdr.value().size());
            total += p.size.value();
            total += 2;   // CRLF before the next delimiter
        }
        total += static_cast<uint64_t>(
            multipart_detail::closing_delimiter(to_view(impl_->boundary)).size());
        return std::optional<uint64_t>(total);
    }

    inline Result<std::vector<uint8_t>> MultipartBuilder::build_body() const {
        std::vector<uint8_t> out;
        const string_view b = to_view(impl_->boundary);

        if (impl_->parts.empty()) {
            return out;
        }

        const string opening = multipart_detail::part_opening(b);
        for (const auto& p : impl_->parts) {
            auto hdr = multipart_detail::part_headers(p);
            if (!hdr) return hdr.error();

            // Use data()+size() to avoid depending on memepp::string iterators.
            auto append_str = [&](const string& s) {
                const auto* d = reinterpret_cast<const uint8_t*>(s.data());
                out.insert(out.end(), d, d + static_cast<size_t>(s.size()));
            };

            append_str(opening);
            append_str(hdr.value());

            if (p.kind == multipart_detail::Part::Kind::Stream) {
                // Draining a source here is what apply_to exists to avoid; for the
                // in-memory path a stream must already know its size, and the caller
                // gets the bytes it asked for.
                if (!p.source) {
                    return Error{ErrorCode::InvalidArgument, ErrorPhase::Send,
                                 string("stream part has no source")};
                }
                for (;;) {
                    auto r = p.source();
                    if (!r) return r.error();
                    auto& chunk = r.value();
                    if (!chunk.first.empty()) {
                        const char* d = chunk.first.data();
                        out.insert(out.end(),
                                   reinterpret_cast<const uint8_t*>(d),
                                   reinterpret_cast<const uint8_t*>(d) +
                                       static_cast<size_t>(chunk.first.size()));
                    }
                    if (chunk.second) break;   // eof
                }
            } else {
                out.insert(out.end(), p.data.begin(), p.data.end());
            }
            out.push_back('\r');
            out.push_back('\n');
        }

        const string close = multipart_detail::closing_delimiter(b);
        {
            const auto* d = reinterpret_cast<const uint8_t*>(close.data());
            out.insert(out.end(), d, d + static_cast<size_t>(close.size()));
        }
        return out;
    }

    inline VoidResult MultipartBuilder::apply_to(Request& req) const {
        if (impl_->parts.empty()) {
            return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                         string("multipart body has no fields")};
        }

        // Any previous body is replaced wholesale.
        req.clear_body();
        req.headers().set("content-type", to_view(content_type_header()));

        // Everything in memory (and every stream declares its size): emit the whole
        // body as one buffer and let the client set Content-Length.
        auto total = compute_total_size();
        const bool all_in_memory = std::all_of(
            impl_->parts.begin(), impl_->parts.end(),
            [](const multipart_detail::Part& p) {
                return p.kind != multipart_detail::Part::Kind::Stream;
            });

        if (all_in_memory && total.has_value()) {
            auto body = build_body();
            if (!body) return body.error();
            req.set_body(std::move(body.value()));
            return VoidResult{};
        }

        // A streamed field is involved: hand the body over as a source so nothing is
        // buffered. The parts and boundary are COPIED into the closure: the builder
        // may be destroyed before the request finishes, and capturing `this` would
        // dangle.
        struct Cursor {
            size_t part_index{0};
            enum class Stage { Opening, Headers, Data, Separator } stage{Stage::Opening};
            string framing;        // framing bytes waiting to be handed out
            bool framing_ready{false};
            bool stream_eof{false};
            bool in_memory_pending{false};   // one-shot in-memory buffer not yet handed out
            bool closing_done{false};
        };

        auto cursor = std::make_shared<Cursor>();
        auto parts = std::make_shared<std::vector<multipart_detail::Part>>(impl_->parts);
        auto boundary_copy = std::make_shared<string>(impl_->boundary);

        Request::BodySource source = [cursor, parts, boundary_copy]()
                -> Result<std::pair<string_view, bool>> {
            for (;;) {
                // Framing goes out first: this includes the closing delimiter, so
                // the eof below must not be reached before it has been handed over.
                if (cursor->framing_ready) {
                    cursor->framing_ready = false;
                    const bool last = cursor->closing_done;
                    return std::make_pair(to_view(cursor->framing), last);
                }
                if (cursor->closing_done) {
                    return std::make_pair(string_view{}, true);
                }

                switch (cursor->stage) {
                case Cursor::Stage::Opening: {
                    if (cursor->part_index >= parts->size()) {
                        // Close the body. RFC 2046: "\r\n--boundary--", and the CRLF
                        // before it belongs to the delimiter, not to the last part.
                        cursor->framing =
                            multipart_detail::closing_delimiter(to_view(*boundary_copy));
                        cursor->closing_done = true;
                        cursor->framing_ready = true;
                        continue;
                    }
                    // "--boundary\r\n" opens this part.
                    cursor->framing =
                        multipart_detail::part_opening(to_view(*boundary_copy));
                    cursor->stage = Cursor::Stage::Headers;
                    cursor->framing_ready = true;
                    continue;
                }
                case Cursor::Stage::Headers: {
                    auto hdr = multipart_detail::part_headers((*parts)[cursor->part_index]);
                    if (!hdr) return hdr.error();
                    cursor->framing = std::move(hdr.value());
                    cursor->stage = Cursor::Stage::Data;
                    cursor->stream_eof = false;
                    cursor->in_memory_pending = true;
                    cursor->framing_ready = true;
                    continue;
                }
                case Cursor::Stage::Data: {
                    auto& part = (*parts)[cursor->part_index];
                    if (part.kind == multipart_detail::Part::Kind::Stream) {
                        if (cursor->stream_eof) {
                            cursor->stage = Cursor::Stage::Separator;
                            continue;
                        }
                        auto r = part.source();
                        if (!r) return r.error();
                        auto& chunk = r.value();
                        if (chunk.second) cursor->stream_eof = true;
                        if (!chunk.first.empty()) {
                            return std::make_pair(chunk.first, false);
                        }
                        // Empty and not eof is backpressure: let the client retry.
                        if (!chunk.second) return std::make_pair(string_view{}, false);
                        continue;
                    }
                    // In-memory part: hand the buffer out once, empty or not.
                    if (cursor->in_memory_pending) {
                        cursor->in_memory_pending = false;
                        cursor->stage = Cursor::Stage::Separator;
                        if (!part.data.empty()) {
                            const char* d = reinterpret_cast<const char*>(part.data.data());
                            return std::make_pair(
                                string_view(d, part.data.size()), false);
                        }
                    }
                    continue;
                }
                case Cursor::Stage::Separator: {
                    // CRLF before the next delimiter (or before the closing one).
                    cursor->framing = string("\r\n");
                    ++cursor->part_index;
                    cursor->stage = Cursor::Stage::Opening;
                    cursor->framing_ready = true;
                    continue;
                }
                }
            }
        };

        req.set_body_source(std::move(source));

        // A known total lets the client emit Content-Length instead of chunking.
        if (total.has_value()) {
            req.headers().set("content-length",
                              to_view(format("{}", total.value())));
        }
        return VoidResult{};
    }

    // ---------------------------------------------------------------------------
    // Parameter encoding
    // ---------------------------------------------------------------------------
    inline string encode_multipart_field_name(string_view name) {
        auto r = multipart_detail::quote_parameter(name, "field name");
        return r ? r.value() : string{};
    }

    inline string encode_multipart_filename(string_view filename) {
        auto r = multipart_detail::quote_parameter(filename, "filename");
        return r ? r.value() : string{};
    }

} // namespace megohttp

#endif // MEGOHTTP_MULTIPART_IMPL_HPP_INCLUDED
