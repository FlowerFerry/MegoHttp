#ifndef MEGOHTTP_PROXY_HPP_INCLUDED
#define MEGOHTTP_PROXY_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Proxy routing (task book 10.1 / 10.2, phase 5 item S5.4-*).
//
// Four distinct transports, and confusing any two of them is the bug this file
// exists to prevent:
//
//   HTTP forward proxy     cleartext to the proxy, request in absolute-form.
//                          Only ever for an http:// target -- an https://
//                          target needs CONNECT, because the proxy cannot see
//                          the TLS session it is forwarding.
//   HTTP CONNECT           cleartext to the proxy, then a tunnel. Used for
//                          https:// targets.
//   HTTPS proxy            TLS *to the proxy itself*, then either absolute-form
//                          (http target) or CONNECT (https target). This is a
//                          separate capability from CONNECT; task book 10.2
//                          says completing CONNECT does not count as supporting
//                          it.
//   SOCKS5                 binary handshake, then a raw tunnel.
//
// The environment variable NAMES never decide the transport. `HTTPS_PROXY` is
// named after what you talk *through* it, not what you talk *to* it: an
// `HTTPS_PROXY=http://proxy:3128` means a cleartext proxy for https targets.
// Only the scheme inside the value (`https://proxy:3128`) means TLS-to-proxy.
// Assuming otherwise is the single most common misreading of these variables.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/tls_stream.hpp>
#include <megohttp/url.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace megohttp {

    enum class ProxyType {
        None,
        Http,     // cleartext forward proxy / CONNECT
        Https,    // TLS to the proxy itself (task book 10.2)
        Socks5,
    };

    struct ProxyConfig {
        ProxyType type{ProxyType::None};
        string host;
        uint16_t port{0};
        // Credentials for the proxy only. They are never copied into the
        // request headers sent to the target, and never appear in describe().
        string username;
        string password;
        // SOCKS5 only: true sends the target NAME to the proxy; false resolves
        // the name locally and sends the resulting address. Task book 9-A.5
        // requires the difference to be observable, so it is a real switch and
        // not a hint.
        bool socks5_remote_dns{true};

        bool is_set() const noexcept { return type != ProxyType::None; }
        bool has_credentials() const noexcept {
            return !username.empty() || !password.empty();
        }
    };

    struct ProxyOptions {
        // Explicit configuration. Takes precedence over the environment.
        ProxyConfig proxy;

        // TLS settings for the PROXY layer only. The target layer keeps using
        // ClientOptions::tls: task book 9.3 forbids one object driving both
        // identities, because then a proxy CA would also validate the target.
        TlsConfig tls;

        // Reading the environment is opt-in. A library that silently starts
        // routing through whatever the caller's shell happens to export would
        // change who sees the request without being asked -- the same reason
        // redirects default to off.
        bool from_env{false};

        // NO_PROXY syntax this library supports (documented, not guessed):
        //   "*"              every host
        //   "example.com"    that host and any subdomain
        //   ".example.com"   leading dot is accepted and means the same thing
        //   "example.com:8080"  the port must match too
        //   "127.0.0.1"      IP literal, exact
        // Matching is ASCII case-insensitive. Whitespace around entries is
        // trimmed. IPv6 literals may be written with or without brackets.
        std::vector<string> no_proxy;
    };

    namespace proxy_detail {

        // ---------------------------------------------------------------
        // Classifications
        // ---------------------------------------------------------------

        // True when this proxy type forwards an absolute-form request over its
        // own connection (an http:// target only).
        inline bool is_forward_proxy(ProxyType t) noexcept {
            return t == ProxyType::Http || t == ProxyType::Https;
        }

        // True when the connection to the proxy itself is wrapped in TLS.
        // This is what separates an HTTPS proxy from a CONNECT tunnel.
        inline bool uses_proxy_tls(ProxyType t) noexcept {
            return t == ProxyType::Https;
        }

        // True when reaching an https:// target through this proxy needs a
        // CONNECT tunnel first.
        inline bool needs_connect(ProxyType t, bool target_is_secure) noexcept {
            if (!target_is_secure) return false;
            return t == ProxyType::Http || t == ProxyType::Https;
        }

        // ---------------------------------------------------------------
        // Base64 (RFC 4648) for Basic proxy authorization
        //
        // The standard library has no base64 facility, so it is written here
        // rather than pulled in as a dependency. Only the encode direction is
        // needed: the library never decodes a Proxy-Authenticate challenge.
        // ---------------------------------------------------------------
        inline const char* b64_alphabet() noexcept {
            return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        }

        inline string base64_encode(string_view in) {
            const char* tbl = b64_alphabet();
            string_builder b;
            const size_t n = static_cast<size_t>(in.size());
            size_t i = 0;
            while (i + 2 < n) {
                const uint32_t v = (static_cast<uint32_t>(static_cast<unsigned char>(in.data()[i])) << 16)
                                 | (static_cast<uint32_t>(static_cast<unsigned char>(in.data()[i + 1])) << 8)
                                 | static_cast<uint32_t>(static_cast<unsigned char>(in.data()[i + 2]));
                detail::sb_append(b, tbl[(v >> 18) & 0x3F]);
                detail::sb_append(b, tbl[(v >> 12) & 0x3F]);
                detail::sb_append(b, tbl[(v >> 6) & 0x3F]);
                detail::sb_append(b, tbl[v & 0x3F]);
                i += 3;
            }
            const size_t rest = n - i;
            if (rest == 1) {
                const uint32_t v = static_cast<uint32_t>(static_cast<unsigned char>(in.data()[i])) << 16;
                detail::sb_append(b, tbl[(v >> 18) & 0x3F]);
                detail::sb_append(b, tbl[(v >> 12) & 0x3F]);
                detail::sb_append(b, '=');
                detail::sb_append(b, '=');
            } else if (rest == 2) {
                const uint32_t v = (static_cast<uint32_t>(static_cast<unsigned char>(in.data()[i])) << 16)
                                 | (static_cast<uint32_t>(static_cast<unsigned char>(in.data()[i + 1])) << 8);
                detail::sb_append(b, tbl[(v >> 18) & 0x3F]);
                detail::sb_append(b, tbl[(v >> 12) & 0x3F]);
                detail::sb_append(b, tbl[(v >> 6) & 0x3F]);
                detail::sb_append(b, '=');
            }
            return b.release();
        }

        // The value for a `Proxy-Authorization: Basic ...` header (RFC 7617).
        // Built from the proxy credentials only -- never from the target's.
        inline string basic_auth_value(string_view user, string_view pass) {
            string_builder b;
            detail::sb_append(b, user);
            detail::sb_append(b, ':');
            detail::sb_append(b, pass);
            const string plain = b.release();
            return base64_encode(to_view(plain));
        }

        // ---------------------------------------------------------------
        // NO_PROXY
        // ---------------------------------------------------------------

        namespace np_detail {

            // Trim ASCII whitespace from both ends.
            inline string_view trim(string_view v) noexcept {
                size_t a = 0;
                size_t b = static_cast<size_t>(v.size());
                auto ws = [](char c) {
                    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
                };
                while (a < b && ws(v.data()[a])) ++a;
                while (b > a && ws(v.data()[b - 1])) --b;
                return string_view(v.data() + a, static_cast<string_view::size_type>(b - a));
            }

            // Strip one layer of [] from an IPv6 literal.
            inline string_view unbracket(string_view v) noexcept {
                if (v.size() >= 2 && v.data()[0] == '[' &&
                    v.data()[static_cast<size_t>(v.size()) - 1] == ']') {
                    return string_view(v.data() + 1,
                                       static_cast<string_view::size_type>(v.size() - 2));
                }
                return v;
            }

            // Split "host:port" at the LAST colon, but only when the part after
            // it is all digits -- otherwise the colon belongs to an IPv6 address.
            //
            // An entry with MORE than one colon and no brackets is a bare IPv6
            // literal ("::1", "2001:db8::1"), never host:port: splitting "::1"
            // at its last colon would yield host ":" and port 1, which matches
            // nothing and silently disables a legitimate bypass. An IPv6 entry
            // that needs a port must therefore be bracketed ("[::1]:8080"),
            // which is also the only unambiguous spelling.
            inline bool split_host_port(string_view entry, string_view* host, int* port) {
                // "[v6]:port" -- the only unambiguous way to give an IPv6 entry a
                // port. Split after the closing bracket, never inside it.
                if (!entry.empty() && entry.data()[0] == '[') {
                    size_t close = 0;
                    while (close < static_cast<size_t>(entry.size()) &&
                           entry.data()[close] != ']') ++close;
                    if (close == static_cast<size_t>(entry.size())) return false;
                    const size_t after = close + 1;
                    if (after == static_cast<size_t>(entry.size())) {
                        *host = entry; *port = -1; return true;   // "[v6]" alone
                    }
                    if (entry.data()[after] != ':') return false;
                    int p = 0;
                    if (after + 1 >= static_cast<size_t>(entry.size())) return false;
                    for (size_t i = after + 1; i < static_cast<size_t>(entry.size()); ++i) {
                        const char c = entry.data()[i];
                        if (c < '0' || c > '9') return false;
                        p = p * 10 + (c - '0');
                        if (p > 65535) return false;
                    }
                    *host = string_view(entry.data(),
                                        static_cast<string_view::size_type>(after));
                    *port = p;
                    return true;
                }

                size_t colons = 0;
                for (size_t i = 0; i < static_cast<size_t>(entry.size()); ++i) {
                    if (entry.data()[i] == ':') ++colons;
                }
                if (colons > 1) { *host = entry; *port = -1; return true; }

                size_t colon = static_cast<size_t>(entry.size());
                while (colon > 0 && entry.data()[colon - 1] != ':') --colon;
                if (colon == 0) { *host = entry; *port = -1; return true; }
                const size_t dig_start = colon;                 // first char after ':'
                const size_t len = static_cast<size_t>(entry.size());
                if (dig_start >= len) return false;
                int p = 0;
                for (size_t i = dig_start; i < len; ++i) {
                    const char c = entry.data()[i];
                    if (c < '0' || c > '9') { *host = entry; *port = -1; return true; }
                    p = p * 10 + (c - '0');
                    if (p > 65535) return false;
                }
                *host = string_view(entry.data(),
                                    static_cast<string_view::size_type>(colon - 1));
                *port = p;
                return true;
            }

            // True for a spelling that can only be an address literal: it holds
            // a colon, or it is four all-digit dot-separated groups.
            inline bool looks_like_address(string_view v) noexcept {
                size_t groups = 0;
                size_t digits = 0;
                for (size_t i = 0; i < static_cast<size_t>(v.size()); ++i) {
                    const char c = v.data()[i];
                    if (c == ':') return true;
                    if (c == '.') { groups += 1; digits = 0; continue; }
                    if (c < '0' || c > '9') return false;
                    ++digits;
                }
                return groups == 3 && digits > 0;
            }

            // "example.com" matches example.com and a.example.com, but not
            // notexample.com. A leading dot is accepted and means the same.
            inline bool domain_matches(string_view host, string_view pattern) noexcept {
                if (pattern.empty()) return false;
                if (pattern.data()[0] == '.') {
                    pattern = string_view(pattern.data() + 1,
                                          static_cast<string_view::size_type>(pattern.size() - 1));
                }
                if (pattern.empty()) return false;
                if (detail::ascii_iequals(host, pattern)) return true;
                // A name that contains a colon or four dot-separated digit groups
                // is an address, not a domain: suffix matching it would let
                // "0.0.1" bypass "127.0.0.1".
                if (looks_like_address(host) || looks_like_address(pattern)) return false;
                const size_t hs = static_cast<size_t>(host.size());
                const size_t ps = static_cast<size_t>(pattern.size());
                if (hs <= ps) return false;
                // host must end with "." + pattern
                if (host.data()[hs - ps - 1] != '.') return false;
                return detail::ascii_iequals(
                    string_view(host.data() + (hs - ps),
                                static_cast<string_view::size_type>(ps)),
                    pattern);
            }

        } // namespace np_detail

        // True when the target must bypass the proxy.
        inline bool no_proxy_matches(string_view host, uint16_t port,
                                     string_view one_entry) noexcept {
            using namespace np_detail;
            const string_view e = trim(one_entry);
            if (e.empty()) return false;
            if (e.size() == 1 && e.data()[0] == '*') return true;

            string_view pattern = unbracket(e);
            // Trailing "*" is a common spelling ("example.com*" / "10.*").
            // Only the documented forms are honoured; anything else is treated
            // as a literal host name, which is the safe reading: a spelling we
            // do not understand must NOT widen the bypass set.
            string_view hp = pattern;
            string_view phost;
            int pport = -1;
            if (!split_host_port(hp, &phost, &pport)) return false;
            phost = unbracket(phost);
            if (pport >= 0 && static_cast<uint16_t>(pport) != port) return false;
            return domain_matches(host, phost);
        }

        inline bool no_proxy_matches(string_view host, uint16_t port,
                                     const std::vector<string>& entries) noexcept {
            for (const auto& e : entries) {
                if (no_proxy_matches(host, port, to_view(e))) return true;
            }
            return false;
        }

        // One environment value holds a comma-separated LIST ("a.test,localhost").
        // Passing the whole value to the single-entry matcher would look for a
        // host literally named "a.test,localhost" and bypass nothing -- which
        // is what silently broke the environment path once.
        inline bool no_proxy_list_matches(string_view host, uint16_t port,
                                          string_view list) noexcept {
            size_t start = 0;
            const size_t n = static_cast<size_t>(list.size());
            while (start <= n) {
                size_t comma = start;
                while (comma < n && list.data()[comma] != ',') ++comma;
                const string_view item(list.data() + start,
                                       static_cast<string_view::size_type>(comma - start));
                if (no_proxy_matches(host, port, item)) return true;
                if (comma == n) break;
                start = comma + 1;
            }
            return false;
        }

        // ---------------------------------------------------------------
        // Environment
        // ---------------------------------------------------------------

        using GetenvFn = std::function<const char*(const char*)>;

        // Adapts a C string from getenv into a trimmed view.
        inline string_view from_cstr(const char* v) noexcept {
            if (!v) return string_view();
            size_t n = 0;
            while (v[n] != '\0') ++n;
            return np_detail::trim(string_view(v, static_cast<string_view::size_type>(n)));
        }

        // Environment variable names and their precedence.
        //
        // `http_proxy` is honoured in LOWERCASE ONLY. CGI programs put the raw
        // request header into `HTTP_*`, so an attacker who sends
        // "Proxy: http://evil:1/" creates `HTTP_PROXY`; obeying the uppercase
        // name is the httpoxy vulnerability (CVE-2016-5385 and friends).
        // libcurl refuses it for the same reason.
        //
        // Every other name is accepted in both cases, lowercase first.
        inline const char* env_http_proxy(const GetenvFn& g, bool* found) {
            const char* v = g ? g("http_proxy") : nullptr;   // lowercase only
            *found = (v != nullptr);
            return v;
        }

        inline const char* env_one_of(const GetenvFn& g, const char* lower,
                                      const char* upper) {
            if (!g) return nullptr;
            if (const char* v = g(lower)) return v;
            return g(upper);
        }

        // Parses a proxy URL value ("http://user:pass@host:3128") into a config.
        //
        // The proxy SCHEME decides the transport to the proxy and nothing else
        // does. `socks5` and `socks5h` are not in the library's `Scheme` enum
        // (they are URL schemes this client never dials directly), so the
        // prefix is read here before handing the rest to parse_url.
        inline Result<ProxyConfig> parse_proxy_url(string_view text) {
            // Find "://" without assuming a particular scheme is valid.
            size_t sep = static_cast<size_t>(text.size());
            for (size_t i = 0; i + 2 < static_cast<size_t>(text.size()); ++i) {
                if (text.data()[i] == ':' && text.data()[i + 1] == '/' &&
                    text.data()[i + 2] == '/') { sep = i; break; }
            }
            if (sep == static_cast<size_t>(text.size())) {
                return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                             string("proxy value is not an absolute URL")};
            }

            const string_view scheme = string_view(
                text.data(), static_cast<string_view::size_type>(sep));
            const string_view rest = string_view(
                text.data() + sep + 1,               // keep the leading "//"
                static_cast<string_view::size_type>(text.size() - sep - 1));

            ProxyType type = ProxyType::None;
            bool remote_dns = true;
            if (detail::ascii_iequals(scheme, "http")) {
                type = ProxyType::Http;
            } else if (detail::ascii_iequals(scheme, "https")) {
                type = ProxyType::Https;
            } else if (detail::ascii_iequals(scheme, "socks5")) {
                type = ProxyType::Socks5;
                remote_dns = false;      // socks5 = resolve locally
            } else if (detail::ascii_iequals(scheme, "socks5h")) {
                type = ProxyType::Socks5;
                remote_dns = true;       // socks5h = let the proxy resolve
            } else {
                return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                             string("proxy URL scheme must be http, https, socks5 or socks5h")};
            }

            // Reassemble with a scheme parse_url understands; the authority,
            // userinfo and port rules are the same for all of them, so only
            // the scheme is swapped. `rest` already begins with "//", so the
            // colon has to come from here: "http" + "//h" would be "http//h",
            // not a URL.
            string_builder full;
            detail::sb_append(full, "http:");
            detail::sb_append(full, rest);
            auto parsed = parse_url(to_view(full.release()));
            if (!parsed) return parsed.error();
            const Url& u = parsed.value();

            if (u.host.empty()) {
                return Error{ErrorCode::InvalidArgument, ErrorPhase::None,
                             string("proxy URL has no host")};
            }

            ProxyConfig cfg;
            cfg.type = type;
            cfg.socks5_remote_dns = remote_dns;
            cfg.host = u.host;
            // The URL was re-parsed as http:// so parse_url applied port 80.
            // The proxy scheme decides the real default: an https:// proxy
            // listens on 443 unless the value named a port.
            cfg.port = u.port_was_explicit
                           ? u.port
                           : static_cast<uint16_t>(type == ProxyType::Https ? 443 : u.port);
            if (u.username) cfg.username = *u.username;
            if (u.password) cfg.password = *u.password;
            return cfg;
        }

        // Resolves the effective proxy for one target.
        //
        // Precedence: explicit configuration wins outright; the environment is
        // only consulted when `from_env` is set. NO_PROXY is consulted in BOTH
        // cases, because a bypass list that only worked for environment-derived
        // proxies would surprise anyone who set it explicitly.
        struct ProxyDecision {
            ProxyConfig config;              // type == None means "connect directly"
            bool from_environment{false};
        };

        inline Result<ProxyDecision> select_proxy(
                const ProxyOptions& opts, const GetenvFn& getenv,
                string_view target_host, uint16_t target_port, bool target_secure) {
            ProxyDecision d;

            // NO_PROXY from the environment is consulted for an explicit proxy
            // as well, but only when reading the environment was enabled: the
            // caller who asked for environment handling expects its bypass list
            // to apply, and the caller who did not must not have a stray
            // no_proxy in their shell silently disable the proxy they set.
            auto env_bypass = [&]() -> bool {
                if (!opts.from_env) return false;
                const char* np = env_one_of(getenv, "no_proxy", "NO_PROXY");
                if (!np) return false;
                return no_proxy_list_matches(target_host, target_port, from_cstr(np));
            };

            if (opts.proxy.is_set()) {
                if (no_proxy_matches(target_host, target_port, opts.no_proxy) ||
                    env_bypass()) {
                    d.config = ProxyConfig{};
                    return d;
                }
                d.config = opts.proxy;
                return d;
            }

            if (!opts.from_env) return d;

            const char* raw = nullptr;
            bool found = false;
            if (target_secure) {
                raw = env_one_of(getenv, "https_proxy", "HTTPS_PROXY");
            } else {
                raw = env_http_proxy(getenv, &found);
                if (!raw) raw = env_one_of(getenv, "all_proxy", "ALL_PROXY");
            }
            if (!raw) {
                raw = env_one_of(getenv, "all_proxy", "ALL_PROXY");
            }
            if (!raw || *raw == '\0') return d;

            if (env_bypass()) return d;
            if (no_proxy_matches(target_host, target_port, opts.no_proxy)) {
                return d;
            }

            auto cfg = parse_proxy_url(string_view(raw));
            if (!cfg) return cfg.error();
            d.config = cfg.value();
            d.from_environment = true;
            return d;
        }

        // ---------------------------------------------------------------
        // Wire format: CONNECT and forward-proxy targeting
        // ---------------------------------------------------------------

        inline bool has_colon(string_view s) noexcept {
            for (size_t i = 0; i < static_cast<size_t>(s.size()); ++i) {
                if (s.data()[i] == ':') return true;
            }
            return false;
        }

        // "host:port", re-bracketing an IPv6 literal.
        inline string authority_of(string_view host, uint16_t port) {
            string_builder b;
            const bool v6 = host.size() > 0 && host.data()[0] != '[' && has_colon(host);
            if (v6) detail::sb_append(b, '[');
            detail::sb_append(b, host);
            if (v6) detail::sb_append(b, ']');
            detail::sb_append(b, ':');
            detail::sb_append(b, to_view(format("{}", port)));
            return b.release();
        }

        // The CONNECT request. Two rules that are easy to get wrong:
        //   - the target's `Authorization` must NOT appear here (it belongs to
        //     the tunnel, and leaking it to the proxy hands over the target
        //     credential);
        //   - the only credential that belongs here is `Proxy-Authorization`.
        inline string build_connect_request(string_view host, uint16_t port,
                                          const ProxyConfig& cfg,
                                          string_view user_agent) {
            string_builder b;
            detail::sb_append(b, "CONNECT ");
            detail::sb_append(b, authority_of(host, port));
            detail::sb_append(b, " HTTP/1.1\r\nHost: ");
            detail::sb_append(b, authority_of(host, port));
            detail::sb_append(b, "\r\n");
            if (cfg.has_credentials()) {
                detail::sb_append(b, "Proxy-Authorization: Basic ");
                detail::sb_append(b, basic_auth_value(to_view(cfg.username),
                                                     to_view(cfg.password)));
                detail::sb_append(b, "\r\n");
            }
            if (user_agent.size() > 0) {
                detail::sb_append(b, "User-Agent: ");
                detail::sb_append(b, user_agent);
                detail::sb_append(b, "\r\n");
            }
            detail::sb_append(b, "\r\n");
            return b.release();
        }

        // Outcome of a CONNECT response. 2xx is the only success; 407 means the
        // proxy wants credentials, and its presence is reported distinctly so a
        // caller can tell "wrong password" from "proxy is broken".
        enum class ConnectOutcome { Ok, AuthRequired, AuthFailed, Refused, Malformed };

        inline ConnectOutcome classify_connect_response(int status) noexcept {
            if (status >= 200 && status < 300) return ConnectOutcome::Ok;
            if (status == 407) return ConnectOutcome::AuthRequired;
            if (status == 401 || status == 403) return ConnectOutcome::AuthFailed;
            if (status >= 100) return ConnectOutcome::Refused;
            return ConnectOutcome::Malformed;
        }

        inline Error connect_outcome_error(ConnectOutcome o, int status) {
            switch (o) {
                case ConnectOutcome::Ok:
                    return Error{ErrorCode::Success, ErrorPhase::None, string()};
                case ConnectOutcome::AuthRequired:
                    return Error{ErrorCode::ProxyAuthRequired, ErrorPhase::ProxyAuth,
                                 string("proxy requires authentication (407)")};
                case ConnectOutcome::AuthFailed:
                    return Error{ErrorCode::ProxyAuthFailed, ErrorPhase::ProxyAuth,
                                 string("proxy rejected the credentials")};
                case ConnectOutcome::Refused:
                    return Error{ErrorCode::ProxyConnectFailed, ErrorPhase::ProxyConnectTunnel,
                                 format("proxy refused CONNECT with status {}", status)};
                case ConnectOutcome::Malformed:
                default:
                    return Error{ErrorCode::ProxyProtocolError, ErrorPhase::ProxyConnectTunnel,
                                 string("malformed CONNECT response")};
            }
        }

        // ---------------------------------------------------------------
        // SOCKS5 (RFC 1928 + RFC 1929)
        //
        // Kept as a byte-driven state machine with no sockets so every field,
        // every reserved byte and every reply code can be asserted directly.
        // ---------------------------------------------------------------
        namespace socks5 {

            // SOCKS5 is a BINARY protocol. It must not be built with
            // string_builder: `release()` on the MemeString builder drops a
            // trailing NUL byte (measured: appending 05 02 00 yields a
            // two-byte string), and a SOCKS5 frame legitimately ends in 00 --
            // the greeting for "no authentication" ends in 00, and so does the
            // RSV byte followed by a port whose low byte is 00. Using a text
            // builder here would silently corrupt the handshake on one of the
            // two string modes only, which is the worst kind of defect.
            // byte_buffer is std::vector<uint8_t> in both modes and is
            // explicitly allowed for raw network bytes (task book 4).
            inline void put(byte_buffer& b, uint8_t v) { b.push_back(v); }

            inline void put(byte_buffer& b, const uint8_t* p, size_t n) {
                b.insert(b.end(), p, p + n);
            }

            inline void put_str(byte_buffer& b, string_view s) {
                b.insert(b.end(), reinterpret_cast<const uint8_t*>(s.data()),
                         reinterpret_cast<const uint8_t*>(s.data()) +
                             static_cast<size_t>(s.size()));
            }

            constexpr uint8_t kVersion = 0x05;
            constexpr uint8_t kAuthNone = 0x00;
            constexpr uint8_t kAuthUserPass = 0x02;
            constexpr uint8_t kAuthNoAcceptable = 0xFF;
            constexpr uint8_t kCmdConnect = 0x01;
            constexpr uint8_t kAtypIpv4 = 0x01;
            constexpr uint8_t kAtypDomain = 0x03;
            constexpr uint8_t kAtypIpv6 = 0x04;

            // Client greeting. `methods` are offered in preference order.
            inline byte_buffer build_greeting(bool offer_user_pass) {
                byte_buffer b;
                put(b, kVersion);
                put(b, static_cast<uint8_t>(offer_user_pass ? 2 : 1));
                put(b, kAuthNone);
                if (offer_user_pass) put(b, kAuthUserPass);
                return b;
            }

            // The server's method selection is 2 bytes; anything else means the
            // peer is not speaking SOCKS5.
            inline Result<uint8_t> parse_method_selection(string_view in) {
                if (in.size() < 2) {
                    return Error{ErrorCode::Socks5HandshakeFailed, ErrorPhase::ProxyConnectTunnel,
                                 string("SOCKS5 method selection is truncated")};
                }
                const uint8_t ver = static_cast<uint8_t>(in.data()[0]);
                const uint8_t method = static_cast<uint8_t>(in.data()[1]);
                if (ver != kVersion) {
                    return Error{ErrorCode::Socks5HandshakeFailed, ErrorPhase::ProxyConnectTunnel,
                                 string("SOCKS5 reply has the wrong version byte")};
                }
                if (method == kAuthNoAcceptable) {
                    return Error{ErrorCode::Socks5AuthFailed, ErrorPhase::ProxyAuth,
                                 string("SOCKS5 proxy accepted none of the offered auth methods")};
                }
                return method;
            }

            // RFC 1929 username/password sub-negotiation.
            inline byte_buffer build_user_pass(string_view user, string_view pass) {
                byte_buffer b;
                put(b, 0x01);
                put(b, static_cast<uint8_t>(static_cast<unsigned char>(user.size())));
                put_str(b, user);
                put(b, static_cast<uint8_t>(static_cast<unsigned char>(pass.size())));
                put_str(b, pass);
                return b;
            }

            inline VoidResult parse_user_pass_reply(string_view in) {
                if (in.size() < 2) {
                    return Error{ErrorCode::Socks5HandshakeFailed, ErrorPhase::ProxyConnectTunnel,
                                 string("SOCKS5 auth reply is truncated")};
                }
                if (static_cast<uint8_t>(in.data()[1]) != 0x00) {
                    return Error{ErrorCode::Socks5AuthFailed, ErrorPhase::ProxyAuth,
                                 string("SOCKS5 proxy rejected the username/password")};
                }
                return VoidResult{};
            }

            // CONNECT request. `name` is used only when atyp == kAtypDomain:
            // with remote DNS the name is never resolved locally, which is the
            // whole point of that mode.
            inline byte_buffer build_connect(uint8_t atyp, string_view name,
                                             const uint8_t* addr, size_t addr_len,
                                             uint16_t port) {
                byte_buffer b;
                put(b, kVersion);
                put(b, kCmdConnect);
                put(b, 0);                                   // RSV, must be zero
                put(b, atyp);
                if (atyp == kAtypDomain) {
                    put(b, static_cast<uint8_t>(static_cast<unsigned char>(name.size())));
                    put_str(b, name);
                } else {
                    put(b, addr, addr_len);
                }
                put(b, static_cast<uint8_t>(static_cast<unsigned char>(port >> 8)));
                put(b, static_cast<uint8_t>(static_cast<unsigned char>(port & 0xFF)));
                return b;
            }

            // Reply codes (RFC 1928 section 6).
            enum class Reply : uint8_t {
                Succeeded = 0x00,
                GeneralFailure = 0x01,
                NotAllowed = 0x02,
                NetworkUnreachable = 0x03,
                HostUnreachable = 0x04,
                ConnectionRefused = 0x05,
                TtlExpired = 0x06,
                CommandNotSupported = 0x07,
                AddressTypeNotSupported = 0x08,
            };

            inline Error reply_error(Reply r) {
                switch (r) {
                    case Reply::Succeeded:
                        return Error{ErrorCode::Success, ErrorPhase::None, string()};
                    case Reply::CommandNotSupported:
                    case Reply::AddressTypeNotSupported:
                        return Error{ErrorCode::Socks5HandshakeFailed,
                                     ErrorPhase::ProxyConnectTunnel,
                                     string("SOCKS5 proxy does not support CONNECT to this address")};
                    case Reply::NotAllowed:
                        return Error{ErrorCode::ProxyConnectFailed, ErrorPhase::ProxyConnectTunnel,
                                     string("SOCKS5 proxy denied the connection by rule")};
                    default:
                        return Error{ErrorCode::ProxyConnectFailed, ErrorPhase::ProxyConnectTunnel,
                                     string("SOCKS5 proxy could not reach the target")};
                }
            }

            // Total size of the reply once its ATYP is known, so the client can
            // tell "not enough bytes yet" from "truncated".
            inline size_t reply_size_for_atyp(uint8_t atyp) noexcept {
                switch (atyp) {
                    case kAtypIpv4:   return 4 + 4 + 2;
                    case kAtypIpv6:   return 4 + 16 + 2;
                    case kAtypDomain: return 4 + 1;   // + name length, resolved below
                    default:          return 0;
                }
            }

            // Parses a CONNECT reply. Returns the number of bytes consumed on
            // success so a caller that read past the reply keeps the remainder
            // (the tunnel starts immediately after it).
            struct ParsedReply {
                Reply code{Reply::GeneralFailure};
                size_t consumed{0};
                bool complete{false};
            };

            inline Result<ParsedReply> parse_reply(string_view in) {
                ParsedReply out;
                if (in.size() < 4) return out;              // not complete yet
                if (static_cast<uint8_t>(in.data()[0]) != kVersion) {
                    return Error{ErrorCode::Socks5HandshakeFailed, ErrorPhase::ProxyConnectTunnel,
                                 string("SOCKS5 reply has the wrong version byte")};
                }
                if (static_cast<uint8_t>(in.data()[2]) != 0x00) {
                    return Error{ErrorCode::ProxyProtocolError, ErrorPhase::ProxyConnectTunnel,
                                 string("SOCKS5 reply has a non-zero reserved byte")};
                }
                out.code = static_cast<Reply>(static_cast<uint8_t>(in.data()[1]));
                const uint8_t atyp = static_cast<uint8_t>(in.data()[3]);
                size_t need = reply_size_for_atyp(atyp);
                if (need == 0) {
                    return Error{ErrorCode::Socks5HandshakeFailed, ErrorPhase::ProxyConnectTunnel,
                                 string("SOCKS5 reply has an unsupported address type")};
                }
                if (atyp == kAtypDomain) {
                    // 4 header bytes + 1 length byte + name + 2 port bytes.
                    // The base for a domain is only 5 (4 + the length octet),
                    // so the trailing port has to be added here.
                    if (static_cast<size_t>(in.size()) < 5) return out;
                    need = 5 + static_cast<size_t>(static_cast<uint8_t>(in.data()[4])) + 2;
                }
                if (static_cast<size_t>(in.size()) < need) return out;
                out.consumed = need;
                out.complete = true;
                return out;
            }

            // Chooses the address type for a target. An IP literal has no name
            // to hand over, so it stays a literal in both DNS modes.
            inline uint8_t atyp_for(bool is_domain) noexcept {
                return is_domain ? kAtypDomain : kAtypIpv4;
            }

        } // namespace socks5

    } // namespace proxy_detail
} // namespace megohttp

#endif // MEGOHTTP_PROXY_HPP_INCLUDED
