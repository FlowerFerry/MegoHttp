#ifndef MEGOHTTP_IDNA_IMPL_HPP_INCLUDED
#define MEGOHTTP_IDNA_IMPL_HPP_INCLUDED

// Included at the end of idna.hpp. Header-only, all inline.

#include <cstring>
#include <vector>

namespace MegoHttp {
namespace Detail {

    inline bool utf8_next(const char* p, size_t n, size_t& i, uint32_t& cp) noexcept {
        if (i >= n) return false;
        const unsigned char b0 = static_cast<unsigned char>(p[i]);
        if (b0 < 0x80) { cp = b0; ++i; return true; }

        size_t len = 0;
        uint32_t value = 0;
        if ((b0 & 0xE0) == 0xC0)      { len = 2; value = b0 & 0x1Fu; }
        else if ((b0 & 0xF0) == 0xE0) { len = 3; value = b0 & 0x0Fu; }
        else if ((b0 & 0xF8) == 0xF0) { len = 4; value = b0 & 0x07u; }
        else return false;                         // continuation byte or invalid lead

        if (i + len > n) return false;             // truncated sequence
        for (size_t k = 1; k < len; ++k) {
            const unsigned char bk = static_cast<unsigned char>(p[i + k]);
            if ((bk & 0xC0) != 0x80) return false; // not a continuation byte
            value = (value << 6) | (bk & 0x3Fu);
        }
        // Reject overlong encodings and values outside the Unicode range.
        if (len == 2 && value < 0x80) return false;
        if (len == 3 && value < 0x800) return false;
        if (len == 4 && value < 0x10000) return false;
        if (value > 0x10FFFF) return false;
        if (value >= 0xD800 && value <= 0xDFFF) return false;   // surrogate half

        cp = value;
        i += len;
        return true;
    }

    inline size_t utf8_encode(uint32_t cp, char* out) noexcept {
        if (cp < 0x80) {
            out[0] = static_cast<char>(cp);
            return 1;
        }
        if (cp < 0x800) {
            out[0] = static_cast<char>(0xC0 | (cp >> 6));
            out[1] = static_cast<char>(0x80 | (cp & 0x3F));
            return 2;
        }
        if (cp < 0x10000) {
            out[0] = static_cast<char>(0xE0 | (cp >> 12));
            out[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out[2] = static_cast<char>(0x80 | (cp & 0x3F));
            return 3;
        }
        out[0] = static_cast<char>(0xF0 | (cp >> 18));
        out[1] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out[2] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out[3] = static_cast<char>(0x80 | (cp & 0x3F));
        return 4;
    }

} // namespace Detail

    inline bool is_ascii(const string_view& text) noexcept {
        const size_t n = static_cast<size_t>(text.size());
        const char* p = text.data();
        for (size_t i = 0; i < n; ++i) {
            if (static_cast<unsigned char>(p[i]) >= 0x80) return false;
        }
        return true;
    }

    namespace Detail {

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

    } // namespace Detail

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
            if (!Detail::utf8_next(p, n, i, cp)) {
                return Error{ErrorCode::InvalidArgument, "label is not valid UTF-8"};
            }
            cps.push_back(cp);
        }

        string_builder out;

        // Basic code points are copied through verbatim.
        for (uint32_t cp : cps) {
            if (cp < 0x80) Detail::sb_append(out, static_cast<char>(cp));
        }
        size_t handled = out.size();
        const size_t basic_count = handled;

        // RFC 3492 6.3: the delimiter is emitted only when there IS a non-basic
        // part to follow. A label that is entirely ASCII encodes to itself with no
        // trailing '-', which is what makes idna_encode idempotent.
        if (basic_count > 0 && basic_count < cps.size()) {
            Detail::sb_append(out, '-');
        }

        uint32_t n_val = Detail::kInitialN;
        uint32_t delta = 0;
        uint32_t bias = Detail::kInitialBias;

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
            if (static_cast<uint64_t>(m - n_val) > (Detail::kMaxInt - delta) /
                                                      static_cast<uint64_t>(handled + 1)) {
                return Error{ErrorCode::InvalidArgument, "punycode: overflow"};
            }
            delta += (m - n_val) * static_cast<uint32_t>(handled + 1);
            n_val = m;

            for (uint32_t cp : cps) {
                if (cp < n_val) {
                    if (delta == Detail::kMaxInt) {
                        return Error{ErrorCode::InvalidArgument, "punycode: overflow"};
                    }
                    ++delta;
                }
                if (cp == n_val) {
                    uint32_t q = delta;
                    for (uint32_t k = Detail::kBase;; k += Detail::kBase) {
                        const uint32_t t =
                            (k <= bias) ? Detail::kTMin
                                        : (k >= bias + Detail::kTMax ? Detail::kTMax
                                                                     : k - bias);
                        if (q < t) break;
                        Detail::sb_append(out, Detail::encode_digit(
                            t + (q - t) % (Detail::kBase - t)));
                        q = (q - t) / (Detail::kBase - t);
                    }
                    Detail::sb_append(out, Detail::encode_digit(q));
                    bias = Detail::adapt(delta, static_cast<uint32_t>(handled + 1),
                                         handled == basic_count);
                    delta = 0;
                    ++handled;
                }
            }
            ++delta;
            ++n_val;
        }

        return out.release();
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
        string_builder out;
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
            if (!first) Detail::sb_append(out, '.');

            if (is_ascii(label)) {
                Detail::sb_append(out, label);
            } else {
                auto encoded = punycode_encode(label);
                if (!encoded) return encoded.error();
                Detail::sb_append(out, "xn--");
                Detail::sb_append(out, to_view(encoded.value()));
            }

            first = false;
            label_start = i + 1;
        }

        string result = out.release();
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

} // namespace MegoHttp

#endif // MEGOHTTP_IDNA_IMPL_HPP_INCLUDED
