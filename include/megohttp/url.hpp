#ifndef MEGOHTTP_URL_HPP_INCLUDED
#define MEGOHTTP_URL_HPP_INCLUDED

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/idna.hpp>
#include <megohttp/string_adapter.hpp>

#include <cstdint>
#include <optional>

namespace MegoHttp {

    enum class Scheme {
        Unknown = 0,   // parse failure placeholder; never produced for a valid URL
        Http,
        Https,
        Ws,
        Wss,
    };

    // Parsed absolute URL. All text is owning, so the Url outlives any input buffer.
    //
    // Scope (per spec 5.4.1): ASCII host names and already-encoded IDNA A-labels.
    // A non-ASCII host is REJECTED rather than guessed at -- no partial IDNA.
    struct Url {
        Scheme scheme{Scheme::Http};
        string host;                 // IPv4 literal, [IPv6] literal (brackets stripped),
                                     // or ASCII / A-label DNS name. Lowercased.
        uint16_t port{0};            // effective port (default applied)
        bool port_was_explicit{false};
        string path{"/"};            // always begins with '/'
        string query;                // without the leading '?'; empty when absent
        bool has_query{false};

        // userinfo, kept only because it must be stripped from the request target
        // and must never be forwarded silently; the library does not auto-auth with it.
        std::optional<string> username;
        std::optional<string> password;

        bool is_ip_literal{false};
        bool is_ipv6_literal{false};

        // --- Helpers ---
        bool is_secure() const noexcept { return scheme == Scheme::Https || scheme == Scheme::Wss; }
        bool is_websocket() const noexcept { return scheme == Scheme::Ws || scheme == Scheme::Wss; }

        // "host[:port]" with the default port omitted; IPv6 re-bracketed.
        string host_port_header() const;

        // origin key for the connection pool: "scheme://host:port"
        string origin() const;

        // origin-form request target: path + ("?" + query)
        string request_target() const;

        // absolute-form target used with a plain HTTP forward proxy
        string absolute_form_target() const;

        static uint16_t default_port(Scheme s) noexcept;
    };

    // Parses an absolute URL. Scheme must be one of http/https/ws/wss.
    // Rejects: relative URLs, empty host, non-ASCII host, bad port, bad percent
    // escapes in the host, control characters anywhere.
    Result<Url> parse_url(string_view text);

    // Validates that a host is ASCII (or an A-label) and is a legal host token.
    bool is_valid_ascii_host(string_view host) noexcept;

    // True when `text` is an IPv4 or IPv6 literal (no DNS needed).
    bool is_ip_literal(string_view host, bool* out_is_ipv6 = nullptr) noexcept;

} // namespace MegoHttp

#include <megohttp/url_impl.hpp>

#endif // MEGOHTTP_URL_HPP_INCLUDED
