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

    // Decimal into a builder. Formatting goes through fmt, never a hand-rolled
    // digit loop and never snprintf: fmt is locale-independent and cannot
    // overflow a fixed stack buffer.
    inline void append_int(string_builder& b, uint32_t v) {
        const string text = format_string("{}", v);
        sb_append(b, text);
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

    inline bool is_ip_literal(string_view host, bool* out_is_ipv6) noexcept {
        const size_t n = static_cast<size_t>((host).size());
        const char* p = (host).data();
        if (n == 0) { if (out_is_ipv6) *out_is_ipv6 = false; return false; }

        // IPv6: contains a colon (brackets already stripped by the caller)
        bool has_colon = false, has_dot = false;
        for (size_t i = 0; i < n; ++i) {
            if (p[i] == ':') has_colon = true;
            if (p[i] == '.') has_dot = true;
        }
        if (has_colon) { if (out_is_ipv6) *out_is_ipv6 = true; return true; }
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

    inline bool is_valid_ascii_host(string_view host) noexcept {
        const size_t n = static_cast<size_t>((host).size());
        if (n == 0 || n > 253) return false;
        const char* p = (host).data();
        bool prev_dot = true;   // a label must not start with '.'
        for (size_t i = 0; i < n; ++i) {
            const unsigned char c = static_cast<unsigned char>(p[i]);
            if (c >= 0x80) return false;                 // ASCII only; IDNA must pre-encode
            if (c <= 0x20 || c == 0x7F) return false;    // no spaces / controls
            const bool ok =
                (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '.';
            if (!ok) return false;
            if (c == '.' && prev_dot) return false;      // empty label
            prev_dot = (c == '.');
        }
        return !prev_dot;                                 // no trailing dot
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
                // A non-ASCII (IDN) host is converted to its A-label form here, so
                // everything downstream -- DNS, TLS SNI, certificate identity, Host
                // header -- sees the same ASCII name the wire requires.
                auto encoded = idna_encode(host_sv);
                if (!encoded) return encoded.error();
                if (!is_valid_ascii_host(to_view(encoded.value()))) {
                    return Error{ErrorCode::InvalidArgument,
                                 "IDN host is invalid after IDNA encoding"};
                }
                u.host = detail::lower_ascii(to_view(encoded.value()));
                u.is_ip_literal = false;
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
        string_builder b;
        if (is_ipv6_literal) { detail::sb_append(b, '['); detail::sb_append(b, host); detail::sb_append(b, ']'); }
        else { detail::sb_append(b, host); }

        // Omit the port only when it equals the scheme default (RFC 7230 Host rules).
        if (port != default_port(scheme)) {
            detail::sb_append(b, ':');
            detail::append_int(b, static_cast<uint32_t>(port));
        }
        return b.release();
    }

    inline string Url::origin() const {
        string_builder b;
        switch (scheme) {
        case Scheme::Http:  detail::sb_append(b, "http");  break;
        case Scheme::Https: detail::sb_append(b, "https"); break;
        case Scheme::Ws:    detail::sb_append(b, "ws");    break;
        case Scheme::Wss:   detail::sb_append(b, "wss");   break;
        case Scheme::Unknown: break;   // no scheme text for an unparsed URL
        }
        detail::sb_append(b, "://");
        detail::sb_append(b, host_port_header());
        return b.release();
    }

    inline string Url::request_target() const {
        string_builder b;
        if (path.empty()) detail::sb_append(b, '/'); else detail::sb_append(b, path);
        if (has_query) { detail::sb_append(b, '?'); detail::sb_append(b, query); }
        return b.release();
    }

    inline string Url::absolute_form_target() const {
        // absolute-form is only defined for http (a plain forward proxy).
        string_builder b;
        detail::sb_append(b, "http://");
        detail::sb_append(b, host_port_header());
        detail::sb_append(b, request_target());
        return b.release();
    }

} // namespace megohttp

#endif // MEGOHTTP_URL_IMPL_HPP_INCLUDED
