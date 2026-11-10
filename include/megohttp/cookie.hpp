#ifndef MEGOHTTP_COOKIE_HPP_INCLUDED
#define MEGOHTTP_COOKIE_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Cookie handling (task book 10.3, phase 5 item S5.5-*).
//
// A cookie is not a key/value map entry. Storage and retrieval are governed by
// rules that exist to stop one site from reading another's state, and getting
// any of them wrong is a security bug rather than a bug:
//
//   Domain      A cookie set by a.example.com with Domain=example.com is sent
//               to every subdomain; WITHOUT a Domain attribute it is host-only
//               and must never be sent to a subdomain.
//   Public      Domain=com would let one site set a cookie that every .com host
//   Suffix      receives. The PSL is what distinguishes a registrable domain
//               from a public suffix, and it is why this file ships one.
//   Path        Path=/a does not match /ab. The check is a path-segment prefix,
//               not a string prefix.
//   Secure      Tied to the TARGET URL's scheme. Reaching an http:// target
//               through an HTTPS proxy does NOT make the target secure: the
//               proxy hop is encrypted, the target hop is not.
//   Expires /   Both are accepted; Max-Age wins when both appear. A cookie with
//   Max-Age     a past expiry is a deletion, not a value to store.
//
// Set-Cookie is parsed ONE HEADER AT A TIME. It cannot be split on commas:
// Expires=Wed, 21 Oct 2015 07:28:00 GMT contains one, and splitting there
// corrupts the attribute rather than yielding two cookies.
// ---------------------------------------------------------------------------

#include <megohttp/config.hpp>
#include <megohttp/error.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/string_adapter.hpp>
#include <megohttp/url.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace megohttp {

namespace cookie_detail {

    // ------------------------------------------------------------------
    // Public Suffix List
    //
    // The PSL answers one question: given a host, what is the registrable
    // domain ("example.co.uk") and therefore the widest Domain a cookie may
    // name? Without it, Domain=co.uk would be accepted and one site could
    // plant a cookie every co.uk host receives.
    //
    // A built-in snapshot is used by default (offline, no file I/O). A caller
    // that needs fresher data can install its own with set_public_suffix_data().
    // ------------------------------------------------------------------

    // The compiled-in snapshot, newline-separated, lowercase, wildcard and
    // exception entries included verbatim.
    string_view builtin_public_suffix_data() noexcept;

    // Version tag for the built-in snapshot, so a caller can tell what it has.
    string_view builtin_public_suffix_version() noexcept;

    // Version of the rule set CURRENTLY installed: the built-in tag until
    // set_public_suffix_data() replaces it, then "custom". A deployment can log
    // this to record which PSL data it is running against (task book 10.3).
    string public_suffix_version();

    // Parses PSL text into the internal rule set. Wildcard ("*.ck") and
    // exception ("!www.ck") lines are kept as such, not expanded.
    // Empty or unparsable input leaves the previous rule set untouched.
    void set_public_suffix_data(string_view data);

    // Restores the compiled-in snapshot.
    void reset_public_suffix_data();

    // True when `domain` is a public suffix and therefore may NOT be used as a
    // cookie Domain. An empty or single-label domain is always a suffix.
    bool is_public_suffix(string_view domain);

    // The registrable domain for `host` ("a.b.example.co.uk" -> "example.co.uk"),
    // or an empty string when the host is itself a public suffix.
    string registrable_domain(string_view host);

    // ------------------------------------------------------------------
    // Domain matching (RFC 6265 5.1.3)
    // ------------------------------------------------------------------

    // True when `host` domain-matches `domain`: identical, or host ends with
    // "." + domain. A bare suffix match ("xample.com" vs "example.com") is NOT
    // a match, which is why the dot is part of the comparison.
    bool domain_matches(string_view host, string_view domain) noexcept;

    // ------------------------------------------------------------------
    // Path matching (RFC 6265 5.1.4)
    // ------------------------------------------------------------------

    // True when request path `path` is within cookie path `cookie_path`.
    // "/a" matches "/a", "/a/", "/a/b" -- but NOT "/ab". A segment boundary is
    // required, so this is not a plain starts_with.
    bool path_matches(string_view path, string_view cookie_path) noexcept;

    // The default cookie path for a request path (RFC 6265 5.1.4): everything up
    // to but excluding the last "/", or "/" when that would be empty.
    string default_cookie_path(string_view path);

    // ------------------------------------------------------------------
    // Date parsing for Expires
    // ------------------------------------------------------------------

    // Parses a cookie date into Unix seconds. Accepts the RFC 6265 grammar,
    // which in practice means the IMF-fixdate form plus the two obsolete
    // formats still seen in the wild. Returns nullopt on failure; a cookie
    // whose Expires will not parse is session-scoped, not deleted.
    std::optional<int64_t> parse_cookie_date(string_view text) noexcept;

} // namespace cookie_detail

// ---------------------------------------------------------------------------
// SetCookie
//
// One parsed Set-Cookie header. Attributes the library does not act on
// (SameSite, HttpOnly, Priority) are recorded so a caller can inspect them,
// but the library makes no claim to implement browser behaviour for them.
// ---------------------------------------------------------------------------
struct SetCookie {
    string name;
    string value;

    // Present = the Domain attribute was supplied. Absent = host-only cookie,
    // which must never be sent to a subdomain.
    std::optional<string> domain;
    std::optional<string> path;

    // Expiry in Unix seconds. nullopt = session cookie (dies with the jar).
    std::optional<int64_t> expires_at;

    bool secure{false};
    bool http_only{false};
    bool has_max_age{false};

    // Recorded, not enforced. SameSite requires a browser notion of a
    // cross-site request that a library client does not have.
    std::optional<string> same_site;

    // A cookie whose Max-Age was <= 0, or whose Expires is in the past, is a
    // DELETION instruction: the jar must drop the matching cookie instead of
    // storing this one.
    bool is_deletion{false};

    // Rejects an empty name, a name/value containing a control character, and
    // a domain that fails to normalize.
    VoidResult validate() const;
};

// Parses ONE Set-Cookie header value. Not a comma-separated list: pass each
// header separately, because Expires contains a comma.
Result<SetCookie> parse_set_cookie(string_view header_value);

// Builds the Cookie request header value for a set of cookies ("a=1; b=2").
// Empty when there is nothing to send.
string build_cookie_header(const std::vector<SetCookie>& cookies);

// ---------------------------------------------------------------------------
// CookieJar
//
// Thread-safe, in-memory only. Nothing is written to disk: persistence is the
// caller's decision, and a library that silently wrote cookies to a file would
// be storing credentials nobody asked it to store.
//
// Not a virtual interface. There is exactly one behaviour worth having here,
// and a caller that wants different rules can drive parse_set_cookie() and
// build_cookie_header() directly.
// ---------------------------------------------------------------------------
class CookieJar {
public:
    struct Limits {
        // Per-domain cookie count. Exceeding it evicts the soonest-to-expire
        // entry rather than rejecting the new one, matching what browsers do.
        size_t max_cookies_per_domain{180};

        // Total cookies across all domains.
        size_t max_cookies_total{3000};

        // A cookie larger than this is rejected outright: it cannot be stored
        // without risking a request header larger than servers accept.
        size_t max_cookie_bytes{4096};
    };

    CookieJar();
    explicit CookieJar(Limits limits);
    ~CookieJar();

    CookieJar(const CookieJar&) = delete;
    CookieJar& operator=(const CookieJar&) = delete;

    // --- Store ---

    // Applies ONE Set-Cookie header received from `url`.
    //
    // `url` is the target the response came from, and its scheme decides
    // whether a Secure attribute is honoured: a Secure cookie is never accepted
    // from an http:// response, because anyone on the path could have set it.
    //
    // A deletion instruction removes the matching cookie and returns success.
    VoidResult set_from_header(const Url& url, string_view set_cookie_header);

    // Applies an already-parsed cookie. Same rules as set_from_header.
    VoidResult set(const Url& url, const SetCookie& cookie);

    // --- Retrieve ---

    // Cookies to send to `url`, already filtered by domain, path and Secure.
    // Ordered by path length descending then creation time, so a more specific
    // path wins, which is what servers expect when two cookies share a name.
    //
    // Secure filtering uses `url.is_secure()` ONLY. An HTTPS proxy in front of
    // an http:// target leaves the target hop in the clear, so its Secure
    // cookies stay home (task book 10.3).
    std::vector<SetCookie> get(const Url& url) const;

    // The Cookie header value for `url`, or an empty string.
    string cookie_header(const Url& url) const;

    // --- Maintenance ---

    // Removes every cookie whose expires_at has passed.
    size_t clear_expired();

    // Removes everything, including session cookies.
    void clear();

    // Number of stored cookies.
    size_t size() const;

    // --- Import / export ---
    //
    // A textual form the caller can persist itself. No file I/O happens here.

    // Serializes every cookie as one Set-Cookie-shaped line per cookie.
    // A host-only cookie carries an extra `__HostOnly=1` marker: "no Domain
    // attribute" and "Domain equal to this exact host" are different rules, and
    // the round trip would otherwise widen the cookie to every subdomain.
    std::vector<string> export_all() const;

    // Imports lines produced by export_all(). Lines that fail to parse are
    // skipped rather than aborting the whole import; the count returned is how
    // many were applied. The `__HostOnly=1` marker restores host-only scope.
    size_t import_all(const std::vector<string>& lines);

    // Diagnostics: a summary that never contains cookie values.
    string describe() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Convenience factory, matching the shared_ptr injection style used for
// Resolver and Executor. A null jar in ClientOptions means cookies are off.
std::shared_ptr<CookieJar> make_cookie_jar();

} // namespace megohttp

#include <megohttp/cookie_impl.hpp>

#endif // MEGOHTTP_COOKIE_HPP_INCLUDED
