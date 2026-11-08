#ifndef MEGOHTTP_CONTENT_TYPE_IMPL_HPP_INCLUDED
#define MEGOHTTP_CONTENT_TYPE_IMPL_HPP_INCLUDED

#include <megohttp/http.hpp>

namespace megohttp {
    namespace content_type_detail {
        inline string_view trim(string_view v) noexcept {
            return http_detail::trim_ows(v);
        }
        inline bool is_token_char(char c) noexcept {
            const unsigned char u = static_cast<unsigned char>(c);
            if (u <= 0x20 || u >= 0x7F) return false;
            switch (c) {
            case '(': case ')': case '<': case '>': case '@':
            case ',': case ';': case ':': case '\\': case '"':
            case '/': case '[': case ']': case '?': case '=':
                return false;
            default: return true;
            }
        }
        inline Error invalid(const char* msg) {
            return Error{ErrorCode::MultipartMediaTypeInvalid, ErrorPhase::Receive, string(msg)};
        }
        inline string_view read_token(string_view s, size_t& i) noexcept {
            const size_t begin = i;
            while (i < static_cast<size_t>(s.size()) && is_token_char(s.data()[i])) ++i;
            return string_view(s.data() + begin, static_cast<string_view::size_type>(i - begin));
        }
        inline string to_lower(string_view s) {
            string_builder b;
            for (size_t i = 0; i < static_cast<size_t>(s.size()); ++i) {
                unsigned char c = static_cast<unsigned char>(s.data()[i]);
                if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
                detail::sb_append(b, static_cast<char>(c));
            }
            return detail::sb_release(b);
        }
        inline Result<string> read_value(string_view s, size_t& i) {
            const size_t n = static_cast<size_t>(s.size());
            if (i >= n) return invalid("Content-Type parameter has no value");
            if (s.data()[i] == '"') {
                ++i; string_builder out; bool closed = false;
                while (i < n) {
                    const char c = s.data()[i];
                    if (c == '"') { ++i; closed = true; break; }
                    if (c == '\\') { if (i+1 >= n) break; detail::sb_append(out, s.data()[i+1]); i += 2; continue; }
                    detail::sb_append(out, c); ++i;
                }
                if (!closed) return invalid("Content-Type has an unterminated quoted string");
                return detail::sb_release(out);
            }
            const string_view tok = read_token(s, i);
            if (tok.empty()) return invalid("Content-Type parameter value is not a token");
            return string(tok.data(), tok.size());
        }
        inline bool is_bchars(char c) noexcept {
            const unsigned char u = static_cast<unsigned char>(c);
            if ((u >= '0' && u <= '9') || (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z')) return true;
            switch (c) {
            case '\'': case '(': case ')': case '+': case '_':
            case ',': case '-': case '.': case '/': case ':':
            case '=': case '?': return true;
            default: return false;
            }
        }
    }
    inline std::optional<string_view> MediaType::parameter(string_view name) const noexcept {
        for (const auto& kv : parameters) {
            if (detail::ascii_iequals(kv.first, name)) {
                return string_view(kv.second.data(), static_cast<string_view::size_type>(kv.second.size()));
            }
        }
        return std::nullopt;
    }
    inline Result<MediaType> parse_media_type(string_view value) {
        using namespace content_type_detail;
        const string_view v = trim(value);
        if (v.empty()) return invalid("Content-Type is empty");
        MediaType mt;
        size_t i = 0; const size_t n = static_cast<size_t>(v.size());
        const string_view type_tok = read_token(v, i);
        if (type_tok.empty()) return invalid("Content-Type has no type");
        if (i >= n || v.data()[i] != '/') return invalid("Content-Type type is not followed by '/'");
        ++i;
        const string_view subtype_tok = read_token(v, i);
        if (subtype_tok.empty()) return invalid("Content-Type has no subtype");
        mt.type = to_lower(type_tok);
        mt.subtype = to_lower(subtype_tok);
        { string_builder vb; detail::sb_append(vb, mt.type); detail::sb_append(vb, '/'); detail::sb_append(vb, mt.subtype); mt.value = detail::sb_release(vb); }
        while (i < n) {
            while (i < n && (v.data()[i] == ' ' || v.data()[i] == '\t')) ++i;
            if (i >= n) break;
            if (v.data()[i] != ';') return invalid("Content-Type has trailing garbage after the media type");
            ++i; while (i < n && (v.data()[i] == ' ' || v.data()[i] == '\t')) ++i;
            if (i >= n) return invalid("Content-Type ends with an empty parameter");
            const string_view name_tok = read_token(v, i);
            if (name_tok.empty()) return invalid("Content-Type parameter has no name");
            while (i < n && (v.data()[i] == ' ' || v.data()[i] == '\t')) ++i;
            if (i >= n || v.data()[i] != '=') return invalid("Content-Type parameter has no '='");
            ++i; while (i < n && (v.data()[i] == ' ' || v.data()[i] == '\t')) ++i;
            auto val = read_value(v, i);
            if (!val) return val.error();
            string lname = to_lower(name_tok);
            bool duplicate_conflict = false;
            for (const auto& kv : mt.parameters) {
                if (kv.first == lname) { if (kv.second != val.value()) duplicate_conflict = true; break; }
            }
            if (duplicate_conflict) return invalid("Content-Type has a duplicated parameter with conflicting values");
            mt.parameters.emplace_back(std::move(lname), std::move(val.value()));
        }
        return mt;
    }
    inline Result<string> parse_multipart_boundary(string_view content_type, const std::vector<string>& expected_subtypes) {
        using namespace content_type_detail;
        namespace d = megohttp::detail;
        auto mt = parse_media_type(content_type);
        if (!mt) return invalid("Content-Type is malformed");
        const MediaType& m = mt.value();
        if (!m.is_multipart()) return invalid("Content-Type is not multipart/*");
        if (!expected_subtypes.empty()) {
            bool ok = false;
            for (const auto& s : expected_subtypes) {
                if (d::ascii_iequals(m.subtype, string_view(s.data(), static_cast<string_view::size_type>(s.size())))) { ok = true; break; }
            }
            if (!ok) return invalid("unsupported multipart subtype");
        }
        const string* boundary = nullptr;
        for (const auto& kv : m.parameters) {
            if (kv.first == string("boundary")) {
                if (boundary == nullptr) boundary = &kv.second;
                else if (kv.second != *boundary) return invalid("Content-Type has conflicting boundary parameters");
            }
        }
        if (boundary == nullptr) return invalid("Content-Type has no boundary parameter");
        const string& b = *boundary;
        const size_t bsize = static_cast<size_t>(b.size());
        if (bsize == 0) return invalid("multipart boundary is empty");
        if (bsize > 70) return invalid("multipart boundary exceeds 70 characters");
        for (size_t k = 0; k < bsize; ++k) if (!is_bchars(b.data()[k])) return invalid("multipart boundary contains an illegal character");
        if (b.data()[bsize - 1] == ' ') return invalid("multipart boundary must not end with a space");
        return b;
    }
}
#endif
