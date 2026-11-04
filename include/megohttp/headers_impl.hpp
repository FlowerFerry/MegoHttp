#ifndef MEGOHTTP_HEADERS_IMPL_HPP_INCLUDED
#define MEGOHTTP_HEADERS_IMPL_HPP_INCLUDED

// Included at the end of headers.hpp. Every definition is inline (header-only, ODR).

#include <charconv>
#include <cstring>
#include <string_view>

namespace MegoHttp {

    // RFC 7230 tchar: ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*"
    // / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
    //
    // The symbol set is fixed and short, so a constexpr lookup beats the hand-
    // written boolean chain in readability and is just as fast at -O2.
    inline bool is_valid_header_name(string_view name) noexcept {
        constexpr std::string_view symbols = "!#$%&'*+-.^_`|~";
        const size_t n = static_cast<size_t>(name.size());
        if (n == 0) return false;
        const char* p = name.data();
        for (size_t i = 0; i < n; ++i) {
            const unsigned char c = static_cast<unsigned char>(p[i]);
            const bool is_alnum =
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9');
            if (!is_alnum && symbols.find(static_cast<char>(c)) == std::string_view::npos) {
                return false;
            }
        }
        return true;
    }

    // field-value: visible chars, SP/HTAB, and obs-text (0x80-0xFF).
    // CR, LF and NUL are rejected -- this is the anti-injection boundary.
    inline bool is_valid_header_value(string_view value) noexcept {
        const size_t n = static_cast<size_t>((value).size());
        const char* p = (value).data();
        for (size_t i = 0; i < n; ++i) {
            const unsigned char c = static_cast<unsigned char>(p[i]);
            if (c == '\r' || c == '\n' || c == 0) return false;
            // Allow 0x20..0xFF except DEL(0x7F), plus HTAB (0x09).
            if (c == 0x7F) return false;
            if (c < 0x20 && c != '\t') return false;
        }
        return true;
    }

    inline void Headers::add(string_view name, string_view value) {
        fields_.emplace_back(to_string(name), to_string(value));
    }

    inline void Headers::add(const char* name, const char* value) {
        fields_.emplace_back(
            string(name, static_cast<string::size_type>(strlen(name))),
            string(value, static_cast<string::size_type>(strlen(value))));
    }

    // Replace every value of `name` with `value`, keeping the FIRST occurrence's
    // position. Removing and re-adding would push the field to the end and reorder
    // the header block, which changes the wire output for no reason.
    inline void Headers::set(string_view name, string_view value) {
        string new_value = to_string(value);
        bool replaced = false;
        for (auto it = fields_.begin(); it != fields_.end();) {
            if (Detail::ascii_iequals(to_view(it->first), name)) {
                if (!replaced) {
                    it->second = new_value;
                    replaced = true;
                    ++it;
                } else {
                    it = fields_.erase(it);   // drop the duplicates
                }
            } else {
                ++it;
            }
        }
        if (!replaced) {
            fields_.emplace_back(to_string(name), std::move(new_value));
        }
    }

    inline bool Headers::remove(string_view name) {
        bool erased = false;
        for (auto it = fields_.begin(); it != fields_.end();) {
            if (Detail::ascii_iequals(to_view(it->first), name)) {
                it = fields_.erase(it);
                erased = true;
            } else {
                ++it;
            }
        }
        return erased;
    }

    inline bool Headers::contains(string_view name) const noexcept {
        for (const auto& f : fields_) {
            if (Detail::ascii_iequals(to_view(f.first), name)) return true;
        }
        return false;
    }

    inline std::optional<string_view> Headers::get(string_view name) const noexcept {
        for (const auto& f : fields_) {
            if (Detail::ascii_iequals(to_view(f.first), name)) return to_view(f.second);
        }
        return std::nullopt;
    }

    inline std::vector<string_view> Headers::get_all(string_view name) const {
        std::vector<string_view> out;
        for (const auto& f : fields_) {
            if (Detail::ascii_iequals(to_view(f.first), name)) out.push_back(to_view(f.second));
        }
        return out;
    }

    // Parse a non-negative decimal integer from a header value. Uses
    // std::from_chars so there is no locale dependency, no UB on overflow, and
    // the function rejects signs/spaces exactly as an unsigned reader should.
    // Renamed from get_uint64 to get_uint to avoid a misleading type name.
    inline std::optional<uint64_t> Headers::get_uint(string_view name) const noexcept {
        auto v = get(name);
        if (!v) return std::nullopt;
        const char* first = v->data();
        const char* last = first + static_cast<size_t>(v->size());
        if (first == last) return std::nullopt;
        uint64_t value = 0;
        const auto res = std::from_chars(first, last, value);
        if (res.ec != std::errc{} || res.ptr != last) return std::nullopt;
        return value;
    }

    inline size_t Headers::byte_size() const noexcept {
        size_t total = 0;
        for (const auto& f : fields_) {
            total += static_cast<size_t>(f.first.size())
                   + static_cast<size_t>(f.second.size())
                   + 4;   // ": " and CRLF
        }
        return total;
    }

} // namespace MegoHttp

#endif // MEGOHTTP_HEADERS_IMPL_HPP_INCLUDED
