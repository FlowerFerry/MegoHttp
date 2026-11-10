#ifndef MEGOHTTP_URL_IMPL_HPP_INCLUDED
#define MEGOHTTP_URL_IMPL_HPP_INCLUDED

// Included at the end of url.hpp. Header-only, all inline.

#include <megohttp/format.hpp>

#include <charconv>
#include <cctype>
#include <cstring>

namespace megohttp {
namespace detail {

    // Character classification and case folding come from the standard library,
    // not hand-written range compares. Each call site converts to unsigned char
    // first: <cctype> functions are undefined for negative arguments, and a plain
    // char is signed on most ABIs.
    inline bool is_digit(char c) noexcept {
        return std::isdigit(static_cast<unsigned char>(c)) != 0;
    }

    inline char to_lower(char c) noexcept {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Lowercase a borrowed view into an owning string. memepp::string has no
    // in-place mutation, so the buffer is built once and moved into the string.
    inline string lower_ascii(string_view v) {
        const size_t n = static_cast<size_t>((v).size());
        const char* p = (v).data();
        if (n == 0) return string();
        std::vector<char> buf(n);
        for (size_t i = 0; i < n; ++i) {
            buf[i] = (static_cast<unsigned char>(p[i]) < 0x80) ? to_lower(p[i]) : p[i];
        }
        return string(buf.data(), static_cast<string::size_type>(n));
    }

    // Strict decimal parse. std::from_chars rejects signs, spaces and overflow for
    // us, which is exactly the semantics an HTTP port needs.
    inline bool parse_port(string_view v, uint16_t* out) noexcept {
        const char* first = (v).data();
        const char* last = first + static_cast<size_t>((v).size());
        if (first == last) return false;
        unsigned value = 0;
        const auto res = std::from_chars(first, last, value);
        if (res.ec != std::errc{} || res.ptr != last) return false;
        if (value == 0 || value > 65535u) return false;   // port 0 is not a port
        *out = static_cast<uint16_t>(value);
        return true;
    }

} // namespace detail

    inline uint16_t Url::default_port(Scheme s) noexcept {
        switch (s) {
        case Scheme::Http:  return 80;
        case Scheme::Https: return 443;
        case Scheme::Ws:    return 80;
        case Scheme::Wss:   return 443;
        case Scheme::Unknown:
            break;
        }
        // Unknown scheme has no default port. Callers must check the scheme before
        // using the port; 0 is the "not applicable" sentinel.
        return 0;
    }

    // Strict IPv6 literal validation (brackets already stripped).
    //
    // "contains a colon" is not a test for an IPv6 address: [not:an:ipv6] passes
    // it, and because parse_url sets is_ip_literal from that answer, the name
    // then skips DNS and goes to connect() as if it were an address.
    //
    // Accepted forms: 8 groups; 1..7 groups with one "::"; and either of those
    // with a trailing dotted-quad (IPv4-mapped / -compatible).
    //
    // (is_ip_literal is declared in url.hpp, so calling it here is fine.)
    inline bool is_ipv6_literal(string_view host) noexcept {
        const size_t n = static_cast<size_t>(host.size());
        const char* p = host.data();
        if (n < 2 || n > 45) return false;

        size_t i = 0;
        int groups = 0;
        bool compressed = false;

        // A leading "::" may collapse any number of zero groups.
        if (p[0] == ':') {
            if (n < 2 || p[1] != ':') return false;
            compressed = true;
            i = 2;
        }

        while (i < n) {
            // Split off the next group.
            const size_t start = i;
            int digits = 0;
            while (i < n && p[i] != ':') {
                const char c = p[i];
                // A dot means this group is actually a dotted-quad tail.
                if (c == '.') {
                    if (digits == 0) return false;
                    // Validate the rest as IPv4 and stop.
                    bool v6 = false;
                    if (!is_ip_literal(string_view(p + start, n - start), &v6)) return false;
                    if (v6) return false;              // no colons left in the tail
                    if (groups + 2 > 8) return false;  // a v4 tail is two groups
                    return true;
                }
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F'))) {
                    return false;
                }
                ++digits;
                if (digits > 4) return false;
                ++i;
            }
            if (digits == 0) return false;
            ++groups;
            if (groups > 8) return false;
            if (i >= n) break;

            // Consume the ':' separator; a second one means "::".
            ++i;
            if (i < n && p[i] == ':') {
                if (compressed) return false;   // at most one "::"
                compressed = true;
                ++i;
                if (i >= n) break;              // trailing "::" is legal
            } else if (i >= n) {
                return false;                   // a trailing single ':' is not
            }
        }

        if (compressed) return groups <= 7;
        return groups == 8;
    }

    inline bool is_ip_literal(string_view host, bool* out_is_ipv6) noexcept {
        const size_t n = static_cast<size_t>((host).size());
        const char* p = (host).data();
        if (n == 0) { if (out_is_ipv6) *out_is_ipv6 = false; return false; }

        // IPv6: must actually parse as one, not merely contain a colon.
        bool has_colon = false, has_dot = false;
        for (size_t i = 0; i < n; ++i) {
            if (p[i] == ':') has_colon = true;
            if (p[i] == '.') has_dot = true;
        }
        if (has_colon) {
            const bool ok = is_ipv6_literal(host);
            if (out_is_ipv6) *out_is_ipv6 = ok;
            return ok;
        }
        if (out_is_ipv6) *out_is_ipv6 = false;

        // IPv4: exactly four 1-3 digit decimal groups, each <= 255
        if (!has_dot) return false;
        size_t i = 0;
        int groups = 0;
        while (i < n) {
            size_t start = i;
            uint32_t acc = 0;
            while (i < n && detail::is_digit(p[i]) && (i - start) < 3) {
                acc = acc * 10u + static_cast<uint32_t>(p[i] - '0');
                ++i;
            }
            if (i == start || acc > 255u) return false;
            ++groups;
            if (i < n) {
                if (p[i] != '.') return false;
                ++i;
                if (i == n) return false;   // trailing dot
            }
        }
        return groups == 4;
    }

    namespace detail {

        // Character classes for an ASCII host name. Every non-classified byte
        // (non-ASCII, control, space, any other punctuation) stays kBad, so the
        // table is both the whitelist and the reject list.
        enum HostCharClass : unsigned char {
            kBad    = 0,
            kAlnum  = 1,   // a-z A-Z 0-9
            kHyphen = 2,   // '-'
            kDot    = 3,   // '.'
        };

        struct HostClassTable {
            unsigned char v[256]{};
            constexpr HostClassTable() {
                for (int c = '0'; c <= '9'; ++c) v[c] = kAlnum;
                for (int c = 'a'; c <= 'z'; ++c) v[c] = kAlnum;
                for (int c = 'A'; c <= 'Z'; ++c) v[c] = kAlnum;
                v[static_cast<unsigned char>('-')] = kHyphen;
                v[static_cast<unsigned char>('.')] = kDot;
            }
            constexpr unsigned char operator[](unsigned char c) const noexcept { return v[c]; }
        };

    } // namespace detail

    inline bool is_valid_ascii_host(string_view host) noexcept {
        using namespace detail;
        // Function-local static: initialised once on first use.
        static constexpr HostClassTable kHostClass{};

        const size_t n = static_cast<size_t>(host.size());
        if (n == 0 || n > 253) return false;

        // A trailing dot is rejected: this validates a Host header / connect
        // target, where "example.com." would not match the certificate name or
        // the DNS answer the caller already holds.
        size_t label_len = 0;
        unsigned char prev = kDot;

        for (unsigned char ch : host) {
            const unsigned char cls = kHostClass[ch];
            switch (cls) {
            case kAlnum:
                ++label_len;
                break;
            case kHyphen:
                if (label_len == 0) return false;    // label starts with '-'
                ++label_len;
                break;
            case kDot:
                if (label_len == 0) return false;    // empty label ("a..b" or ".a")
                if (prev == kHyphen) return false;   // label ends with '-'
                label_len = 0;
                break;
            default:
                return false;                        // non-ASCII / control / other
            }
            if (label_len > 63) return false;        // label too long
            prev = cls;
        }
        // The last label must be non-empty and must not end with '-'.
        return label_len != 0 && prev != kHyphen;
    }

    inline Result<Url> parse_url(string_view text) {

        const size_t n = static_cast<size_t>((text).size());
        const char* p = (text).data();
        if (n == 0) return Error{ErrorCode::InvalidArgument, "empty URL"};

        // Reject control characters up front (request-splitting defence).
        for (size_t i = 0; i < n; ++i) {
            const unsigned char c = static_cast<unsigned char>(p[i]);
            if (c <= 0x20 || c == 0x7F) {
                return Error{ErrorCode::InvalidArgument, "URL contains whitespace or control character"};
            }
        }

        // --- scheme ---
        size_t pos = 0;
        while (pos < n && p[pos] != ':') ++pos;
        if (pos == n || pos + 2 >= n || p[pos + 1] != '/' || p[pos + 2] != '/') {
            return Error{ErrorCode::InvalidArgument, "URL is not absolute (scheme://...)"};
        }
        const string_view scheme_sv(p, static_cast<string_view::size_type>(pos));

        Url u;
        if (detail::ascii_iequals(scheme_sv, "http"))       u.scheme = Scheme::Http;
        else if (detail::ascii_iequals(scheme_sv, "https")) u.scheme = Scheme::Https;
        else if (detail::ascii_iequals(scheme_sv, "ws"))    u.scheme = Scheme::Ws;
        else if (detail::ascii_iequals(scheme_sv, "wss"))   u.scheme = Scheme::Wss;
        else return Error{ErrorCode::InvalidArgument, "unsupported URL scheme"};

        size_t i = pos + 3;   // past "://"

        // --- authority ends at '/', '?' or '#' ---
        size_t auth_end = i;
        while (auth_end < n && p[auth_end] != '/' && p[auth_end] != '?' && p[auth_end] != '#') {
            ++auth_end;
        }
        if (auth_end == i) return Error{ErrorCode::InvalidArgument, "URL has empty authority"};

        string_view authority(p + i, static_cast<string_view::size_type>(auth_end - i));

        // --- strip userinfo (kept, but never auto-applied) ---
        const size_t at = [&] {
            for (size_t k = 0; k < static_cast<size_t>((authority).size()); ++k) {
                if ((authority).data()[k] == '@') return k;
            }
            return static_cast<size_t>((authority).size());
        }();
        if (at < static_cast<size_t>((authority).size())) {
            string_view userinfo((authority).data(),
                                 static_cast<string_view::size_type>(at));
            // split on the first ':'
            size_t colon = static_cast<size_t>((userinfo).size());
            for (size_t k = 0; k < static_cast<size_t>((userinfo).size()); ++k) {
                if ((userinfo).data()[k] == ':') { colon = k; break; }
            }
            u.username = string((userinfo).data(),
                                static_cast<string::size_type>(colon));
            if (colon < static_cast<size_t>((userinfo).size())) {
                u.password = string((userinfo).data() + colon + 1,
                                    static_cast<string::size_type>(static_cast<size_t>((userinfo).size()) - colon - 1));
            }
            authority = string_view((authority).data() + at + 1,
                                    static_cast<string_view::size_type>(static_cast<size_t>((authority).size()) - at - 1));
            if (static_cast<size_t>((authority).size()) == 0) {
                return Error{ErrorCode::InvalidArgument, "URL has empty host after userinfo"};
            }
        }

        // --- host / port ---
        const size_t a_len = static_cast<size_t>((authority).size());
        const char* a = (authority).data();
        string_view host_sv;
        string_view port_sv;
        bool have_port = false;

        if (a[0] == '[') {
            // IPv6 literal: [ ... ] [:port]
            size_t close = 0;
            for (size_t k = 1; k < a_len; ++k) {
                if (a[k] == ']') { close = k; break; }
            }
            if (close == 0) return Error{ErrorCode::InvalidArgument, "unterminated IPv6 literal"};
            host_sv = string_view(a + 1, static_cast<string_view::size_type>(close - 1));
            // Being inside brackets is not the same as being an IPv6 address.
            // "[not:an:ipv6]" used to be accepted here and then skipped DNS,
            // because is_ip_literal was set unconditionally.
            if (!is_ipv6_literal(host_sv)) {
                return Error{ErrorCode::InvalidArgument,
                             "bracketed host is not a valid IPv6 literal"};
            }
            u.is_ipv6_literal = true;
            u.is_ip_literal = true;
            if (close + 1 < a_len) {
                if (a[close + 1] != ':') {
                    return Error{ErrorCode::InvalidArgument, "garbage after IPv6 literal"};
                }
                port_sv = string_view(a + close + 2,
                                      static_cast<string_view::size_type>(a_len - close - 2));
                have_port = true;
            }
        } else {
            size_t colon = a_len;
            for (size_t k = 0; k < a_len; ++k) {
                if (a[k] == ':') { colon = k; break; }
            }
            host_sv = string_view(a, static_cast<string_view::size_type>(colon));
            if (colon < a_len) {
                port_sv = string_view(a + colon + 1,
                                      static_cast<string_view::size_type>(a_len - colon - 1));
                have_port = true;
            }
        }

        if (static_cast<size_t>((host_sv).size()) == 0) return Error{ErrorCode::InvalidArgument, "URL has empty host"};

        if (!u.is_ip_literal) {
            if (is_ascii(host_sv)) {
                if (!is_valid_ascii_host(host_sv)) {
                    return Error{ErrorCode::InvalidArgument,
                                 "host is not a valid ASCII host name"};
                }
                bool v6 = false;
                if (is_ip_literal(host_sv, &v6)) {
                    u.is_ip_literal = true;
                    u.is_ipv6_literal = v6;
                }
            } else {
                // A non-ASCII (IDN) host.
                //
                // Task book 5.4.1: "Unicode 域名必须明确拒绝，除非通过经过验证的
                // IDNA 库转换，不得自行实现不完整的转换逻辑." This library's
                // idna_encode() is RFC 3492 Punycode plus a SUBSET of IDNA2008 --
                // it does not implement NFC folding, the Bidi rule, ContextJ/O,
                // or the DISALLOWED table. Converting here would therefore accept
                // names a conforming IDNA2008 implementation rejects, which is
                // exactly what the task book forbids.
                //
                // So the default is to reject, and the caller converts with a
                // real IDNA library and passes the resulting A-label. idna_encode
                // remains available as an explicit, documented-subset helper.
                return Error{ErrorCode::InvalidArgument,
                             "Unicode host names are rejected: encode to an IDNA "
                             "A-label with a conforming library first (see idna.hpp)"};
            }
        }

        if (u.host.empty()) {
            u.host = detail::lower_ascii(host_sv);
        }

        if (have_port) {
            uint16_t port = 0;
            if (!detail::parse_port(port_sv, &port)) {
                return Error{ErrorCode::InvalidArgument, "invalid port in URL"};
            }
            u.port = port;
            u.port_was_explicit = true;
        } else {
            u.port = Url::default_port(u.scheme);
        }

        // --- path / query ---
        i = auth_end;
        size_t path_end = n;
        for (size_t k = i; k < n; ++k) {
            if (p[k] == '?' || p[k] == '#') { path_end = k; break; }
        }
        if (path_end > i) {
            // auth_end stops only at '/', '?' or '#', so a non-empty path here
            // always starts with '/'; the invariant needs no repair pass.
            u.path = string(p + i, static_cast<string::size_type>(path_end - i));
        } else {
            u.path = string("/", static_cast<string::size_type>(1));
        }

        if (path_end < n && p[path_end] == '?') {
            size_t q_end = n;
            for (size_t k = path_end + 1; k < n; ++k) {
                if (p[k] == '#') { q_end = k; break; }
            }
            u.query = string(p + path_end + 1,
                             static_cast<string::size_type>(q_end - path_end - 1));
            u.has_query = true;
        }
        // A fragment is ignored on the wire, as required for a request URL.

        return u;
    }

    inline string Url::host_port_header() const {
        fmt::memory_buffer buf;
        if (is_ipv6_literal) buf.push_back('[');
        detail::buf_append(buf, host);
        if (is_ipv6_literal) buf.push_back(']');

        if (port != default_port(scheme)) {
            fmt::format_to(fmt::appender(buf), FMT_COMPILE(":{}"),
                           static_cast<uint32_t>(port));
        }
        return detail::sb_release(buf);
    }

    inline string Url::origin() const {
        fmt::memory_buffer buf;
        auto out = fmt::appender(buf);
        switch (scheme) {
        case Scheme::Http:  fmt::format_to(out, FMT_COMPILE("http"));  break;
        case Scheme::Https: fmt::format_to(out, FMT_COMPILE("https")); break;
        case Scheme::Ws:    fmt::format_to(out, FMT_COMPILE("ws"));    break;
        case Scheme::Wss:   fmt::format_to(out, FMT_COMPILE("wss"));   break;
        case Scheme::Unknown: break;
        }
        fmt::format_to(out, FMT_COMPILE("://"));
        detail::buf_append(buf, host_port_header());
        return detail::sb_release(buf);
    }

    inline string Url::request_target() const {
        fmt::memory_buffer buf;
        if (path.empty()) buf.push_back('/'); else detail::buf_append(buf, path);
        if (has_query) {
            buf.push_back('?');
            detail::buf_append(buf, query);
        }
        return detail::sb_release(buf);
    }

    inline string Url::absolute_form_target() const {
        fmt::memory_buffer buf;
        // The scheme must be the URL's own. A hardcoded "http://" here rewrote
        // an https URL into http:// wherever the caller reconstructed the URL
        // from this string, which silently downgrades transport security.
        detail::buf_append(buf, origin());
        detail::buf_append(buf, request_target());
        return detail::sb_release(buf);
    }

} // namespace megohttp

#endif // MEGOHTTP_URL_IMPL_HPP_INCLUDED
