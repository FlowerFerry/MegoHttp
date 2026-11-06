#ifndef MEGOHTTP_IDNA_IMPL_HPP_INCLUDED
#define MEGOHTTP_IDNA_IMPL_HPP_INCLUDED

// Included at the end of idna.hpp. Header-only, all inline.

#include <cstring>
#include <vector>

namespace megohttp {
namespace detail {

    inline bool utf8_next(const char* p, size_t n, size_t& i, uint32_t& cp) noexcept {
        if (i >= n) return false;
        const uint8_t* s = reinterpret_cast<const uint8_t*>(p) + i;
        const size_t avail = n - i;
        const uint8_t b0 = s[0];

        // ASCII: the overwhelmingly common case for a DNS label.
        if (b0 < 0x80) { cp = b0; ++i; return true; }

        // 2-byte. 0xC0 and 0xC1 can only produce overlongs, so rejecting
        // b0 < 0xC2 removes that check from the value path.
        if (b0 < 0xE0) {
            if (b0 < 0xC2 || avail < 2) return false;
            const uint8_t b1 = s[1];
            if ((b1 & 0xC0) != 0x80) return false;
            cp = (uint32_t(b0 & 0x1F) << 6) | (b1 & 0x3F);
            i += 2;
            return true;
        }

        // 3-byte. The overlong guard (U+0800) and the surrogate guard (U+D800..
        // U+DFFF) both reduce to a range test on b1 alone.
        if (b0 < 0xF0) {
            if (avail < 3) return false;
            const uint8_t b1 = s[1];
            const uint8_t b2 = s[2];
            uint8_t lo = 0x80, hi = 0xBF;
            if (b0 == 0xE0)      lo = 0xA0;   // reject overlong
            else if (b0 == 0xED) hi = 0x9F;   // reject surrogate halves
            if (b1 < lo || b1 > hi) return false;
            if ((b2 & 0xC0) != 0x80) return false;
            cp = (uint32_t(b0 & 0x0F) << 12) | (uint32_t(b1 & 0x3F) << 6) | (b2 & 0x3F);
            i += 3;
            return true;
        }

        // 4-byte. 0xF5..0xFF exceed U+10FFFF outright; 0xF0 and 0xF4 need the
        // overlong / range guards on b1.
        if (b0 > 0xF4 || avail < 4) return false;
        const uint8_t b1 = s[1];
        const uint8_t b2 = s[2];
        const uint8_t b3 = s[3];
        uint8_t lo = 0x80, hi = 0xBF;
        if (b0 == 0xF0)      lo = 0x90;       // reject overlong
        else if (b0 == 0xF4) hi = 0x8F;       // reject > U+10FFFF
        if (b1 < lo || b1 > hi) return false;
        if ((b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) return false;
        cp = (uint32_t(b0 & 0x07) << 18) | (uint32_t(b1 & 0x3F) << 12)
           | (uint32_t(b2 & 0x3F) << 6) | (b3 & 0x3F);
        i += 4;
        return true;
    }

} // namespace detail

    inline bool is_ascii(const string_view& text) noexcept {
        const size_t n = static_cast<size_t>(text.size());
        const char* p = text.data();
        for (size_t i = 0; i < n; ++i) {
            if (static_cast<unsigned char>(p[i]) >= 0x80) return false;
        }
        return true;
    }

    namespace detail {

        // RFC 3492 parameters (Punycode).
        constexpr uint32_t kBase = 36;
        constexpr uint32_t kTMin = 1;
        constexpr uint32_t kTMax = 26;
        constexpr uint32_t kSkew = 38;
        constexpr uint32_t kDamp = 700;
        constexpr uint32_t kInitialBias = 72;
        constexpr uint32_t kInitialN = 128;
        constexpr uint32_t kMaxInt = 0x7FFFFFFF;

        inline uint32_t adapt(uint32_t delta, uint32_t numpoints, bool first_time) noexcept {
            delta = first_time ? delta / kDamp : delta / 2;
            delta += delta / numpoints;
            uint32_t k = 0;
            while (delta > ((kBase - kTMin) * kTMax) / 2) {
                delta /= kBase - kTMin;
                k += kBase;
            }
            return k + (((kBase - kTMin + 1) * delta) / (delta + kSkew));
        }

        inline char encode_digit(uint32_t d) noexcept {
            // 0..25 -> 'a'..'z', 26..35 -> '0'..'9'
            return static_cast<char>(d < 26 ? d + 'a' : d - 26 + '0');
        }

    } // namespace detail

    inline Result<string> punycode_encode(const string_view& utf8_label) {
        const size_t n = static_cast<size_t>(utf8_label.size());
        const char* p = utf8_label.data();
        if (n == 0) {
            return Error{ErrorCode::InvalidArgument, "empty label"};
        }

        // Decode the label into code points.
        std::vector<uint32_t> cps;
        cps.reserve(n);
        size_t i = 0;
        while (i < n) {
            uint32_t cp = 0;
            if (!detail::utf8_next(p, n, i, cp)) {
                return Error{ErrorCode::InvalidArgument, "label is not valid UTF-8"};
            }
            cps.push_back(cp);
        }

        fmt::memory_buffer out;

        // Basic code points are copied through verbatim.
        for (uint32_t cp : cps) {
            if (cp < 0x80) out.push_back(static_cast<char>(cp));
        }
        size_t handled = out.size();
        const size_t basic_count = handled;

        // RFC 3492 6.3: the delimiter is emitted only when there IS a non-basic
        // part to follow. A label that is entirely ASCII encodes to itself with no
        // trailing '-', which is what makes idna_encode idempotent.
        if (basic_count > 0 && basic_count < cps.size()) {
            out.push_back('-');
        }

        uint32_t n_val = detail::kInitialN;
        uint32_t delta = 0;
        uint32_t bias = detail::kInitialBias;

        while (handled < cps.size()) {
            // Smallest code point >= n_val.
            uint32_t m = 0xFFFFFFFFu;
            for (uint32_t cp : cps) {
                if (cp >= n_val && cp < m) m = cp;
            }
            if (m == 0xFFFFFFFFu) {
                return Error{ErrorCode::InvalidArgument, "punycode: no code point left"};
            }
            // Overflow check from RFC 3492 section 6.3.
            if (static_cast<uint64_t>(m - n_val) > (detail::kMaxInt - delta) /
                                                      static_cast<uint64_t>(handled + 1)) {
                return Error{ErrorCode::InvalidArgument, "punycode: overflow"};
            }
            delta += (m - n_val) * static_cast<uint32_t>(handled + 1);
            n_val = m;

            for (uint32_t cp : cps) {
                if (cp < n_val) {
                    if (delta == detail::kMaxInt) {
                        return Error{ErrorCode::InvalidArgument, "punycode: overflow"};
                    }
                    ++delta;
                }
                if (cp == n_val) {
                    uint32_t q = delta;
                    for (uint32_t k = detail::kBase;; k += detail::kBase) {
                        const uint32_t t =
                            (k <= bias) ? detail::kTMin
                                        : (k >= bias + detail::kTMax ? detail::kTMax
                                                                     : k - bias);
                        if (q < t) break;
                        out.push_back(detail::encode_digit(
                            t + (q - t) % (detail::kBase - t)));
                        q = (q - t) / (detail::kBase - t);
                    }
                    out.push_back(detail::encode_digit(q));
                    bias = detail::adapt(delta, static_cast<uint32_t>(handled + 1),
                                         handled == basic_count);
                    delta = 0;
                    ++handled;
                }
            }
            ++delta;
            ++n_val;
        }

        return detail::sb_release(out);
    }

    inline Result<string> idna_encode(const string_view& host) {
        const size_t n = static_cast<size_t>(host.size());
        if (n == 0) return Error{ErrorCode::InvalidArgument, "empty host"};
        if (n > 253) return Error{ErrorCode::InvalidArgument, "host exceeds 253 bytes"};

        if (is_ascii(host)) {
            // Already ASCII: nothing to convert. Validate the label structure so an
            // obviously bad host is not silently accepted.
            const char* p = host.data();
            size_t label_start = 0;
            for (size_t i = 0; i <= n; ++i) {
                if (i == n || p[i] == '.') {
                    const size_t len = i - label_start;
                    if (len == 0) {
                        return Error{ErrorCode::InvalidArgument, "empty label in host"};
                    }
                    if (len > 63) {
                        return Error{ErrorCode::InvalidArgument, "label exceeds 63 bytes"};
                    }
                    label_start = i + 1;
                }
            }
            return to_string(host);
        }

        // Split on '.', convert each non-ASCII label, keep ASCII labels as-is.
        fmt::memory_buffer out;
        const char* p = host.data();
        size_t label_start = 0;
        bool first = true;

        for (size_t i = 0; i <= n; ++i) {
            if (i != n && p[i] != '.') continue;

            const size_t len = i - label_start;
            if (len == 0) {
                return Error{ErrorCode::InvalidArgument, "empty label in host"};
            }
            const string_view label(p + label_start,
                                    static_cast<string_view::size_type>(len));
            if (!first) out.push_back('.');

            if (is_ascii(label)) {
                detail::buf_append(out, label);
            } else {
                auto encoded = punycode_encode(label);
                if (!encoded) return encoded.error();
                out.push_back('x'); out.push_back('n'); out.push_back('-'); out.push_back('-');
                detail::buf_append(out, to_view(encoded.value()));
            }

            first = false;
            label_start = i + 1;
        }

        string result = detail::sb_release(out);
        // Validate the encoded total length, then each label's own limit.
        if (result.size() > 253) {
            return Error{ErrorCode::InvalidArgument, "encoded host exceeds 253 bytes"};
        }
        {
            const char* q = result.data();
            const size_t m = static_cast<size_t>(result.size());
            size_t ls = 0;
            for (size_t i = 0; i <= m; ++i) {
                if (i == m || q[i] == '.') {
                    if (i - ls > 63) {
                        return Error{ErrorCode::InvalidArgument,
                                     "encoded label exceeds 63 bytes"};
                    }
                    ls = i + 1;
                }
            }
        }
        return result;
    }

} // namespace megohttp

#endif // MEGOHTTP_IDNA_IMPL_HPP_INCLUDED
