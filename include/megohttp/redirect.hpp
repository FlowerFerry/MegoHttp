#ifndef MEGOHTTP_REDIRECT_HPP_INCLUDED
#define MEGOHTTP_REDIRECT_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Redirect policy (task book 8.3, phase 5 item S5.2-*).
//
// Redirect handling is not "re-send the request to a new URL". Three things
// change depending on the status code, and getting any of them wrong is a
// correctness or security bug:
//
//   301 / 302  Historically "maybe GET". RFC 7231 leaves the method open; every
//              browser and libcurl turned POST into GET here, and servers
//              depend on it. We do the same, and say so.
//   303        Always GET. Defined that way by the RFC.
//   307 / 308  Preserve the method AND the body. A non-replayable body cannot be
//              re-sent, so the redirect fails rather than silently sending an
//              empty body (which would look like success).
//
// Cross-origin hops drop credentials. The rules are per-header, not a blanket
// "drop everything": the standard says Authorization and Cookie must not follow
// a redirect to a different origin, while Host is recomputed regardless.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/http.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/url.hpp>

#include <optional>

namespace megohttp {
namespace redirect_detail {

    // True when this status code is a redirect we are willing to act on.
    // 300 and 304 are deliberately absent: 300 has no single target, and 304 is
    // a cache validator, not a redirect.
    inline bool is_redirect_status(int status) noexcept {
        return status == 301 || status == 302 || status == 303 ||
               status == 307 || status == 308;
    }

    // True when the method must become GET for this status.
    // 303 always; 301/302 only for methods that are not already safe.
    inline bool becomes_get(int status, Method m) noexcept {
        if (status == 303) return true;
        if (status == 301 || status == 302) {
            // A GET or HEAD stays as-is; anything else degrades to GET, matching
            // what browsers and libcurl do and what servers expect.
            return m != Method::Get && m != Method::Head;
        }
        return false;
    }

    // True when the request body must be carried over. Only 307/308 preserve it.
    inline bool preserves_body(int status) noexcept {
        return status == 307 || status == 308;
    }

    // Resolves a Location value against the URL that produced it.
    //
    // Location is frequently relative ("/next", "next", "?q=2"), so it cannot go
    // through parse_url() directly. This implements the RFC 3986 5.2 resolution
    // for the cases that occur in practice: absolute, scheme-relative ("//h/p"),
    // absolute-path ("/p"), and relative-path ("p"). A fragment is dropped
    // because it never travels on the wire.
    inline Result<Url> resolve_location(const Url& base, string_view location) {
        if (location.empty()) {
            return Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                         string("redirect Location header is empty")};
        }

        // Reject control characters: a Location is server-controlled input and
        // must not be able to smuggle a CRLF into the next request line.
        for (size_t i = 0; i < static_cast<size_t>(location.size()); ++i) {
            const unsigned char c = static_cast<unsigned char>(location.data()[i]);
            if (c <= 0x20 || c == 0x7F) {
                return Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                             string("redirect Location contains whitespace or a control character")};
            }
        }

        // Strip a fragment: it is not sent to the server.
        string_view loc = location;
        for (size_t i = 0; i < static_cast<size_t>(loc.size()); ++i) {
            if (loc.data()[i] == '#') {
                loc = string_view(loc.data(), static_cast<string_view::size_type>(i));
                break;
            }
        }
        if (loc.empty()) {
            return Error{ErrorCode::HttpInvalidResponse, ErrorPhase::Receive,
                         string("redirect Location is only a fragment")};
        }

        // Absolute: has a scheme. Hand it to the real parser so every rule
        // (IDNA, port validation, scheme whitelist) applies identically.
        for (size_t i = 0; i + 2 < static_cast<size_t>(loc.size()); ++i) {
            if (loc.data()[i] == ':' && loc.data()[i+1] == '/' && loc.data()[i+2] == '/') {
                return parse_url(loc);
            }
        }

        // Scheme-relative: "//host/path" borrows the base scheme.
        const bool scheme_relative =
            loc.size() >= 2 && loc.data()[0] == '/' && loc.data()[1] == '/';

        string_builder b;
        if (scheme_relative) {
            // loc already starts with "//", so appending it after "https:" yields
            // "https://host/..." -- the correct form.
            detail::sb_append(b, base.scheme == Scheme::Https || base.scheme == Scheme::Wss
                                    ? "https:"
                                    : "http:");
        } else {
            detail::sb_append(b, base.scheme == Scheme::Https || base.scheme == Scheme::Wss
                                    ? "https://"
                                    : "http://");
            detail::sb_append(b, base.host_port_header());
            if (loc.data()[0] != '/') {
                // Relative path: replace the last segment of the base path.
                // "/a/b" + "c" -> "/a/c" (RFC 3986 5.3 merge).
                string_view bp = base.path;
                size_t slash = static_cast<size_t>(bp.size());
                while (slash > 0 && bp.data()[slash - 1] != '/') --slash;
                if (slash == 0) {
                    detail::sb_append(b, "/");
                } else {
                    detail::sb_append(b, string_view(bp.data(),
                                                     static_cast<string_view::size_type>(slash)));
                }
            }
        }
        detail::sb_append(b, loc);
        return parse_url(to_view(b.release()));
    }

    // Headers that must not follow a cross-origin redirect. Task book 8.3 names
    // Authorization explicitly and requires "other sensitive headers" to be
    // dropped too; the list is the intersection of what this library can send
    // and what is unsafe to leak to a different origin.
    inline bool is_origin_bound_header(string_view name) noexcept {
        return detail::ascii_iequals(name, "authorization") ||
               detail::ascii_iequals(name, "cookie") ||
               detail::ascii_iequals(name, "proxy-authorization");
    }

    // True when following this hop would drop the transport's security: an
    // https origin moving to an http one. Judged on the URL being LEFT, because
    // that is where the protection is lost.
    //
    // Extracted rather than inlined into the client so the refusal has exactly
    // one implementation that a test can exercise without opening a socket.
    inline bool is_downgrade(const Url& from, const Url& to) noexcept {
        return from.is_secure() && !to.is_secure();
    }

    inline bool same_origin(const Url& a, const Url& b) noexcept {
        const bool a_secure = a.scheme == Scheme::Https || a.scheme == Scheme::Wss;
        const bool b_secure = b.scheme == Scheme::Https || b.scheme == Scheme::Wss;
        return a_secure == b_secure && a.port == b.port &&
               detail::ascii_iequals(to_view(a.host), to_view(b.host));
    }

} // namespace redirect_detail
} // namespace megohttp

#endif // MEGOHTTP_REDIRECT_HPP_INCLUDED
