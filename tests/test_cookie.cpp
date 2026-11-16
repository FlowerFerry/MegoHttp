// S5.5 CookieJar / PSL. Pure-function and jar-level tests: no socket, no
// server. The Client integration is covered separately.
//
// The rules being checked here are the ones that exist to stop one site
// reading another's state, so each test names the failure it prevents rather
// than just describing the happy path.
#include <megohttp/config.hpp>
#include <megohttp/cookie.hpp>
#include <megohttp/url.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace megohttp;
namespace cd = megohttp::cookie_detail;

namespace {

std::string s(const string& v) { return std::string(v.data(), static_cast<size_t>(v.size())); }
string sv(const char* p) { return string(p); }
string_view view(const char* p) { return string_view(p, std::char_traits<char>::length(p)); }

// Builds a Url without going through parse_url, so a test can name an arbitrary
// host without DNS or scheme noise.
Url make_url(const char* scheme, const char* host, const char* path = "/") {
    Url u;
    if (std::string(scheme) == "https") u.scheme = Scheme::Https;
    else if (std::string(scheme) == "http") u.scheme = Scheme::Http;
    u.host = sv(host);
    u.port = Url::default_port(u.scheme);
    u.path = sv(path);
    u.is_ip_literal = is_ip_literal(to_view(u.host));
    return u;
}

} // namespace

// ---------------------------------------------------------------------------
// Domain matching (RFC 6265 5.1.3)
//
// A bare suffix match is the bug this prevents: "xample.com" must NOT match
// "example.com", which a plain ends_with would allow.
// ---------------------------------------------------------------------------
TEST_CASE("domain matching requires a label boundary", "[cookie][domain]") {
    CHECK(cd::domain_matches(view("example.com"), view("example.com")));
    CHECK(cd::domain_matches(view("a.example.com"), view("example.com")));
    CHECK(cd::domain_matches(view("a.b.example.com"), view("example.com")));

    // The dot is part of the comparison.
    CHECK_FALSE(cd::domain_matches(view("xample.com"), view("example.com")));
    CHECK_FALSE(cd::domain_matches(view("notexample.com"), view("example.com")));
    CHECK_FALSE(cd::domain_matches(view("example.com"), view("a.example.com")));

    // Case-insensitive, and a leading dot in the attribute is the same name.
    CHECK(cd::domain_matches(view("A.Example.COM"), view("example.com")));
    CHECK(cd::domain_matches(view("a.example.com"), view(".example.com")));
}

// ---------------------------------------------------------------------------
// Path matching (RFC 6265 5.1.4)
//
// "/a" must not match "/ab": that is a different resource, not a child.
// ---------------------------------------------------------------------------
TEST_CASE("path matching requires a segment boundary", "[cookie][path]") {
    CHECK(cd::path_matches(view("/"), view("/")));
    CHECK(cd::path_matches(view("/a"), view("/a")));
    CHECK(cd::path_matches(view("/a/"), view("/a")));
    CHECK(cd::path_matches(view("/a/b"), view("/a")));
    CHECK(cd::path_matches(view("/a/b/c"), view("/a/b")));

    // The segment-boundary case.
    CHECK_FALSE(cd::path_matches(view("/ab"), view("/a")));
    CHECK_FALSE(cd::path_matches(view("/abc/def"), view("/a")));
    CHECK_FALSE(cd::path_matches(view("/b"), view("/a")));
    CHECK_FALSE(cd::path_matches(view("/"), view("/a")));

    // A cookie path ending in "/" matches everything under it.
    CHECK(cd::path_matches(view("/a/b"), view("/a/")));
    CHECK_FALSE(cd::path_matches(view("/a"), view("/a/")));
}

TEST_CASE("default cookie path drops the last segment", "[cookie][path]") {
    CHECK(s(cd::default_cookie_path(view("/"))) == "/");
    CHECK(s(cd::default_cookie_path(view("/a"))) == "/");
    CHECK(s(cd::default_cookie_path(view("/a/"))) == "/a");
    CHECK(s(cd::default_cookie_path(view("/a/b"))) == "/a");
    CHECK(s(cd::default_cookie_path(view("/a/b/c"))) == "/a/b");
    CHECK(s(cd::default_cookie_path(view(""))) == "/");
}

// ---------------------------------------------------------------------------
// Public Suffix List
//
// Domain=com and Domain=co.uk must be rejected: accepting either would let one
// site plant a cookie every host under that suffix receives.
// ---------------------------------------------------------------------------
TEST_CASE("a single-label domain is a public suffix", "[cookie][psl]") {
    CHECK(cd::is_public_suffix(view("com")));
    CHECK(cd::is_public_suffix(view("org")));
    CHECK(cd::is_public_suffix(view("uk")));
    CHECK(cd::is_public_suffix(view("io")));

    CHECK_FALSE(cd::is_public_suffix(view("example.com")));
    CHECK_FALSE(cd::is_public_suffix(view("example.org")));
}

TEST_CASE("a multi-label public suffix is recognised", "[cookie][psl]") {
    CHECK(cd::is_public_suffix(view("co.uk")));
    CHECK(cd::is_public_suffix(view("org.uk")));
    CHECK(cd::is_public_suffix(view("com.au")));
    CHECK(cd::is_public_suffix(view("co.jp")));
    CHECK(cd::is_public_suffix(view("com.cn")));
    CHECK(cd::is_public_suffix(view("github.io")));

    CHECK_FALSE(cd::is_public_suffix(view("example.co.uk")));
    CHECK_FALSE(cd::is_public_suffix(view("my.github.io")));
}

TEST_CASE("the registrable domain is the first non-suffix label pair", "[cookie][psl]") {
    CHECK(s(cd::registrable_domain(view("a.example.com"))) == "example.com");
    CHECK(s(cd::registrable_domain(view("b.a.example.com"))) == "example.com");
    CHECK(s(cd::registrable_domain(view("a.example.co.uk"))) == "example.co.uk");
    CHECK(s(cd::registrable_domain(view("my.github.io"))) == "my.github.io");

    // A host that is itself a suffix has no registrable domain.
    CHECK(cd::registrable_domain(view("co.uk")).empty());
    CHECK(cd::registrable_domain(view("com")).empty());
}

TEST_CASE("a caller can install its own PSL data and reset it", "[cookie][psl]") {
    // "test-suffix" is not in the built-in snapshot.
    CHECK_FALSE(cd::is_public_suffix(view("co.test-suffix")));

    cd::set_public_suffix_data(view("co.test-suffix\nexample.test\n"));
    CHECK(cd::is_public_suffix(view("co.test-suffix")));
    CHECK(cd::is_public_suffix(view("example.test")));
    // Single labels stay suffixes regardless of the data set.
    CHECK(cd::is_public_suffix(view("com")));

    // The installed rule set reports where it came from, so a deployment can
    // record which PSL data it is running against.
    CHECK(s(cd::public_suffix_version()) == "custom");

    cd::reset_public_suffix_data();
    CHECK_FALSE(cd::is_public_suffix(view("co.test-suffix")));
    CHECK(s(cd::public_suffix_version()) == s(to_string(cd::builtin_public_suffix_version())));

    // Unparsable input must not disable the protection.
    cd::set_public_suffix_data(view(""));
    CHECK(cd::is_public_suffix(view("com")));
}

// ---------------------------------------------------------------------------
// Cookie date parsing
// ---------------------------------------------------------------------------
TEST_CASE("cookie dates parse in all three RFC 6265 formats", "[cookie][date]") {
    // IMF-fixdate.
    const auto a = cd::parse_cookie_date(view("Sun, 06 Nov 1994 08:49:37 GMT"));
    REQUIRE(a.has_value());
    CHECK(*a == 784111777);

    // RFC 850 with a two-digit year.
    const auto b = cd::parse_cookie_date(view("Sunday, 06-Nov-94 08:49:37 GMT"));
    REQUIRE(b.has_value());
    CHECK(*b == 784111777);

    // asctime.
    const auto c = cd::parse_cookie_date(view("Sun Nov  6 08:49:37 1994"));
    REQUIRE(c.has_value());
    CHECK(*c == 784111777);

    // Leap day is valid in a leap year, invalid otherwise.
    CHECK(cd::parse_cookie_date(view("Thu, 29 Feb 1996 00:00:00 GMT")).has_value());
    CHECK_FALSE(cd::parse_cookie_date(view("Fri, 29 Feb 1995 00:00:00 GMT")).has_value());

    // Garbage and impossible values are rejected rather than guessed.
    CHECK_FALSE(cd::parse_cookie_date(view("not a date")).has_value());
    CHECK_FALSE(cd::parse_cookie_date(view("")).has_value());
    CHECK_FALSE(cd::parse_cookie_date(view("Sun, 32 Nov 1994 08:49:37 GMT")).has_value());
    CHECK_FALSE(cd::parse_cookie_date(view("Sun, 06 Nov 1994 25:49:37 GMT")).has_value());
}

// ---------------------------------------------------------------------------
// Set-Cookie parsing
//
// The critical property: a single header only. Splitting on commas would
// corrupt "Expires=Wed, 21 Oct 2015 ..." into two bogus cookies.
// ---------------------------------------------------------------------------
TEST_CASE("a Set-Cookie header parses into name, value and attributes",
          "[cookie][parse]") {
    auto r = parse_set_cookie(
        view("sid=abc123; Domain=example.com; Path=/app; Secure; HttpOnly"));
    REQUIRE(r);
    CHECK(s(r.value().name) == "sid");
    CHECK(s(r.value().value) == "abc123");
    REQUIRE(r.value().domain.has_value());
    CHECK(s(*r.value().domain) == "example.com");
    REQUIRE(r.value().path.has_value());
    CHECK(s(*r.value().path) == "/app");
    CHECK(r.value().secure);
    CHECK(r.value().http_only);
    CHECK_FALSE(r.value().expires_at.has_value());   // session cookie
    CHECK_FALSE(r.value().is_deletion);
}

TEST_CASE("an Expires value containing a comma is not split", "[cookie][parse]") {
    // A naive comma split would produce "a=1; Expires=Wed" and "21 Oct 2015 ...".
    auto r = parse_set_cookie(
        view("a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/"));
    REQUIRE(r);
    CHECK(s(r.value().name) == "a");
    CHECK(s(r.value().value) == "1");
    REQUIRE(r.value().path.has_value());
    CHECK(s(*r.value().path) == "/");
    CHECK(r.value().expires_at.has_value());
}

TEST_CASE("Max-Age wins over Expires", "[cookie][parse]") {
    auto r = parse_set_cookie(
        view("a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600"));
    REQUIRE(r);
    CHECK(r.value().has_max_age);
    // 2015 is long past; Max-Age=3600 is in the future, so the cookie lives.
    CHECK_FALSE(r.value().is_deletion);
}

TEST_CASE("a non-positive Max-Age is a deletion", "[cookie][parse]") {
    auto a = parse_set_cookie(view("a=1; Max-Age=0"));
    REQUIRE(a);
    CHECK(a.value().is_deletion);

    auto b = parse_set_cookie(view("a=1; Max-Age=-1"));
    REQUIRE(b);
    CHECK(b.value().is_deletion);

    // An Expires in the past is also a deletion.
    auto c = parse_set_cookie(view("a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT"));
    REQUIRE(c);
    CHECK(c.value().is_deletion);
}

TEST_CASE("a leading dot in Domain is accepted and stripped", "[cookie][parse]") {
    auto r = parse_set_cookie(view("a=1; Domain=.example.com"));
    REQUIRE(r);
    REQUIRE(r.value().domain.has_value());
    CHECK(s(*r.value().domain) == "example.com");
}

TEST_CASE("malformed Set-Cookie headers are rejected", "[cookie][parse]") {
    CHECK_FALSE(parse_set_cookie(view("")).has_value());
    CHECK_FALSE(parse_set_cookie(view("novalue")).has_value());
    CHECK_FALSE(parse_set_cookie(view("=value")).has_value());

    // A control character in the value could smuggle a CRLF into the next head.
    CHECK_FALSE(parse_set_cookie(view("a=x\r\ny")).has_value());
    CHECK_FALSE(parse_set_cookie(view("a=x\ny")).has_value());
}

TEST_CASE("unknown attributes are ignored, not rejected", "[cookie][parse]") {
    auto r = parse_set_cookie(
        view("a=1; SameSite=Lax; Priority=High; Partitioned; Weird=1"));
    REQUIRE(r);
    CHECK(s(r.value().name) == "a");
    REQUIRE(r.value().same_site.has_value());
    CHECK(s(*r.value().same_site) == "Lax");
    CHECK_FALSE(r.value().is_deletion);
}

// ---------------------------------------------------------------------------
// CookieJar storage: host-only vs Domain
//
// This is the core isolation rule. A cookie without Domain must never reach a
// subdomain; one with Domain must.
// ---------------------------------------------------------------------------
TEST_CASE("a cookie without Domain stays host-only", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("sid=1")));

    CHECK(s(jar.cookie_header(host)) == "sid=1");

    // A subdomain must NOT receive it.
    const Url sub = make_url("http", "a.example.com");
    CHECK(jar.cookie_header(sub).empty());
}

TEST_CASE("a cookie with Domain reaches subdomains", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "www.example.com");

    REQUIRE(jar.set_from_header(host, view("sid=1; Domain=example.com")));

    CHECK(s(jar.cookie_header(make_url("http", "example.com"))) == "sid=1");
    CHECK(s(jar.cookie_header(make_url("http", "a.example.com"))) == "sid=1");
    CHECK(s(jar.cookie_header(make_url("http", "b.a.example.com"))) == "sid=1");

    // A sibling domain is a different site.
    CHECK(jar.cookie_header(make_url("http", "example.org")).empty());
    CHECK(jar.cookie_header(make_url("http", "notexample.com")).empty());
}

TEST_CASE("a cookie cannot be set for an unrelated domain", "[cookie][jar][security]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    // A response from example.com may not set Domain=other.com.
    const auto r = jar.set_from_header(host, view("sid=1; Domain=other.com"));
    REQUIRE_FALSE(r);
    CHECK(jar.size() == 0);
}

TEST_CASE("a cookie cannot be set for a public suffix", "[cookie][jar][security]") {
    CookieJar jar;

    const auto a = jar.set_from_header(make_url("http", "example.com"),
                                       view("sid=1; Domain=com"));
    REQUIRE_FALSE(a);
    CHECK(jar.size() == 0);

    const auto b = jar.set_from_header(make_url("http", "a.example.co.uk"),
                                       view("sid=1; Domain=co.uk"));
    REQUIRE_FALSE(b);
    CHECK(jar.size() == 0);

    // The registrable domain above it is fine.
    REQUIRE(jar.set_from_header(make_url("http", "a.example.co.uk"),
                               view("sid=1; Domain=example.co.uk")));
    CHECK(jar.size() == 1);
}

TEST_CASE("an IP literal host ignores Domain and stays host-only",
          "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "127.0.0.1");

    REQUIRE(jar.set_from_header(host, view("sid=1; Domain=127.0.0.1")));
    CHECK(s(jar.cookie_header(host)) == "sid=1");
    // Another literal is a different host.
    CHECK(jar.cookie_header(make_url("http", "127.0.0.2")).empty());
}

// ---------------------------------------------------------------------------
// Secure
//
// The rule that matters here: Secure is decided by the TARGET scheme. An HTTPS
// proxy in front of an http:// target leaves the target hop in the clear.
// ---------------------------------------------------------------------------
TEST_CASE("a Secure cookie is only sent over https", "[cookie][jar][secure]") {
    CookieJar jar;
    const Url secure = make_url("https", "example.com");

    REQUIRE(jar.set_from_header(secure, view("sid=1; Secure")));

    CHECK(s(jar.cookie_header(secure)) == "sid=1");
    // The same host over http must not receive it.
    CHECK(jar.cookie_header(make_url("http", "example.com")).empty());
}

TEST_CASE("a Secure cookie from an insecure response is refused",
          "[cookie][jar][secure]") {
    CookieJar jar;
    // Anyone on the http path could have injected this header.
    const auto r = jar.set_from_header(make_url("http", "example.com"),
                                       view("sid=1; Secure"));
    REQUIRE_FALSE(r);
    CHECK(jar.size() == 0);
}

// ---------------------------------------------------------------------------
// Path
// ---------------------------------------------------------------------------
TEST_CASE("the cookie path gates which requests receive it", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("a=1; Path=/app")));

    CHECK(s(jar.cookie_header(make_url("http", "example.com", "/app"))) == "a=1");
    CHECK(s(jar.cookie_header(make_url("http", "example.com", "/app/x"))) == "a=1");

    // "/application" is a different path, not a child of "/app".
    CHECK(jar.cookie_header(make_url("http", "example.com", "/application")).empty());
    CHECK(jar.cookie_header(make_url("http", "example.com", "/")).empty());
}

TEST_CASE("the default path comes from the request path", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com", "/a/b/c");

    REQUIRE(jar.set_from_header(host, view("x=1")));

    // No Path attribute -> "/a/b" (everything before the last segment).
    CHECK(s(jar.cookie_header(make_url("http", "example.com", "/a/b"))) == "x=1");
    CHECK(s(jar.cookie_header(make_url("http", "example.com", "/a/b/c"))) == "x=1");
    CHECK(jar.cookie_header(make_url("http", "example.com", "/a")).empty());
}

TEST_CASE("more specific paths are sent first", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("a=root; Path=/")));
    REQUIRE(jar.set_from_header(host, view("a=app; Path=/app")));
    REQUIRE(jar.set_from_header(host, view("b=x; Path=/app/deep")));

    const auto cookies = jar.get(make_url("http", "example.com", "/app/deep/x"));
    REQUIRE(cookies.size() == 3);
    // Longest path first, so a server preferring the first value sees the most
    // specific one.
    CHECK(s(*cookies[0].path) == "/app/deep");
    CHECK(s(*cookies[1].path) == "/app");
    CHECK(s(*cookies[2].path) == "/");
}

// ---------------------------------------------------------------------------
// Replace / delete / expire
// ---------------------------------------------------------------------------
TEST_CASE("setting the same cookie twice replaces it", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("a=1; Path=/")));
    REQUIRE(jar.set_from_header(host, view("a=2; Path=/")));

    CHECK(jar.size() == 1);
    CHECK(s(jar.cookie_header(host)) == "a=2");
}

TEST_CASE("a deletion removes the matching cookie", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("a=1; Path=/")));
    CHECK(jar.size() == 1);

    REQUIRE(jar.set_from_header(host, view("a=; Path=/; Max-Age=0")));
    CHECK(jar.size() == 0);
    CHECK(jar.cookie_header(host).empty());
}

TEST_CASE("clear_expired removes only past-expiry cookies", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("session=1; Path=/")));
    REQUIRE(jar.set_from_header(
        host, view("future=1; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT")));

    CHECK(jar.size() == 2);
    CHECK(jar.clear_expired() == 0);      // neither has passed
    CHECK(jar.size() == 2);

    CHECK(jar.clear_expired() == 0);
    CHECK(s(jar.cookie_header(host)) == "session=1; future=1");
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------
TEST_CASE("the per-domain cap evicts instead of rejecting", "[cookie][jar][limits]") {
    CookieJar::Limits lim;
    lim.max_cookies_per_domain = 3;
    lim.max_cookies_total = 100;
    CookieJar jar(lim);

    const Url host = make_url("http", "example.com");
    for (int i = 0; i < 10; ++i) {
        REQUIRE(jar.set_from_header(host, to_view(format("c{}=v; Path=/", i))));
    }

    // The cap holds even though ten were offered: a site must not be able to
    // break its own later cookies by setting too many.
    CHECK(jar.size() == 3);
}

TEST_CASE("an oversized cookie is rejected", "[cookie][jar][limits]") {
    CookieJar::Limits lim;
    lim.max_cookie_bytes = 16;
    CookieJar jar(lim);

    const Url host = make_url("http", "example.com");
    const auto r = jar.set_from_header(host, view("a=0123456789012345678901234567890"));
    REQUIRE_FALSE(r);
    CHECK(jar.size() == 0);
}

// ---------------------------------------------------------------------------
// Import / export / diagnostics
// ---------------------------------------------------------------------------
TEST_CASE("export and import round-trip the jar", "[cookie][jar][persistence]") {
    CookieJar a;
    const Url host = make_url("https", "example.com");

    REQUIRE(a.set_from_header(host, view("a=1; Path=/; Secure")));
    REQUIRE(a.set_from_header(host, view("b=2; Path=/app")));
    REQUIRE(a.set_from_header(host, view("c=3; Domain=example.com; Path=/")));

    const auto dumped = a.export_all();
    REQUIRE(dumped.size() == 3);

    CookieJar b;
    CHECK(b.import_all(dumped) == 3);
    CHECK(b.size() == 3);

    // The Secure attribute survived the round trip.
    CHECK(s(b.cookie_header(make_url("https", "example.com"))) != "");
    const auto http_cookies = b.get(make_url("http", "example.com"));
    for (const auto& c : http_cookies) {
        CHECK_FALSE(c.secure);
    }
}

// A host-only cookie and a Domain cookie naming the same host are NOT the same
// cookie: the first must never reach a subdomain. A round trip that lost that
// distinction would silently widen the cookie's scope.
TEST_CASE("a host-only cookie stays host-only across export and import",
          "[cookie][jar][persistence]") {
    CookieJar a;
    const Url host = make_url("http", "example.com");

    // No Domain attribute -> host-only.
    REQUIRE(a.set_from_header(host, view("sid=1; Path=/")));
    // Domain attribute -> reaches subdomains.
    REQUIRE(a.set_from_header(host, view("wide=2; Domain=example.com; Path=/")));

    CookieJar b;
    CHECK(b.import_all(a.export_all()) == 2);

    CHECK(s(b.cookie_header(make_url("http", "example.com"))) == "sid=1; wide=2");

    // The subdomain must receive ONLY the Domain cookie.
    const string sub = b.cookie_header(make_url("http", "a.example.com"));
    CHECK(s(sub) == "wide=2");
}

// 2026-11-13 code review, defect #4: the __HostOnly marker was searched as a
// bare substring, so a cookie VALUE that happens to contain "__HostOnly=1" was
// misread as the marker and its Domain was stripped -- silently converting a
// Domain cookie into a host-only one (a scope narrowing this time, but wrong
// either way). The marker is written as "; __HostOnly=1"; matching that form
// with an attribute boundary is what distinguishes it from payload text.
TEST_CASE("a cookie value containing the marker text is not treated as host-only",
          "[cookie][jar][persistence][security]") {
    CookieJar jar;
    // Domain cookie whose VALUE contains the marker text.
    const std::vector<string> lines = {
        sv("k=__HostOnly=1; Domain=example.com; Path=/"),
    };
    REQUIRE(jar.import_all(lines) == 1);

    // Still a Domain cookie: subdomains must receive it.
    CHECK(s(jar.cookie_header(make_url("http", "a.example.com"))) == "k=__HostOnly=1");
}

TEST_CASE("the real marker still makes a cookie host-only on import",
          "[cookie][jar][persistence]") {
    CookieJar jar;
    const std::vector<string> lines = {
        sv("sid=1; Domain=example.com; Path=/; __HostOnly=1"),
    };
    REQUIRE(jar.import_all(lines) == 1);

    // Host-only: the subdomain must NOT receive it.
    CHECK(s(jar.cookie_header(make_url("http", "a.example.com"))) == "");
    CHECK(s(jar.cookie_header(make_url("http", "example.com"))) == "sid=1");
}

TEST_CASE("import skips bad lines without aborting", "[cookie][jar][persistence]") {
    CookieJar jar;
    const std::vector<string> lines = {
        sv("good=1; Domain=example.com; Path=/"),
        sv("second=2; Domain=example.com; Path=/"),
        sv("this is not a cookie"),
        sv("=novalue"),
        sv("also; Domain=example.com; Path=/"),
    };
    // Three of the five are unusable: no '=', empty name, no '='.
    CHECK(jar.import_all(lines) == 2);
    CHECK(jar.size() == 2);
}

TEST_CASE("describe reports counts but never values", "[cookie][jar][security]") {
    CookieJar jar;
    REQUIRE(jar.set_from_header(make_url("http", "example.com"),
                               view("session_token=SECRETVALUE; Path=/")));
    const std::string d = s(jar.describe());
    CHECK(d.find("SECRETVALUE") == std::string::npos);
    CHECK(d.find("session_token") == std::string::npos);
    CHECK(d.find("1") != std::string::npos);   // the count is still useful
}

// ---------------------------------------------------------------------------
// Multiple Set-Cookie headers
//
// The Client must apply each header separately. This test stands in for that:
// two independent parse+set calls, as the Client does it.
// ---------------------------------------------------------------------------
TEST_CASE("two Set-Cookie headers produce two cookies", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");

    REQUIRE(jar.set_from_header(host, view("a=1; Path=/")));
    REQUIRE(jar.set_from_header(host, view("b=2; Path=/")));

    CHECK(jar.size() == 2);
    CHECK(s(jar.cookie_header(host)) == "a=1; b=2");
}

TEST_CASE("clear removes everything including session cookies", "[cookie][jar]") {
    CookieJar jar;
    const Url host = make_url("http", "example.com");
    REQUIRE(jar.set_from_header(host, view("a=1; Path=/")));
    REQUIRE(jar.set_from_header(host, view("b=2; Path=/; Max-Age=3600")));
    CHECK(jar.size() == 2);

    jar.clear();
    CHECK(jar.size() == 0);
    CHECK(jar.cookie_header(host).empty());
}

// ---------------------------------------------------------------------------
// Secure under a proxy (S5.5-03)
//
// The rule is about the TARGET hop, not the connection. Reaching an http://
// target through an HTTPS proxy encrypts only the proxy segment; the target
// segment is still cleartext, so a Secure cookie must not be sent.
//
// get() is driven directly here because the decision lives entirely in the jar
// and the URL it is handed -- the proxy never appears in this code path, which
// is exactly the point: if it did, the rule could be got wrong.
// ---------------------------------------------------------------------------
TEST_CASE("a Secure cookie is not sent to an http target even via a TLS proxy",
          "[cookie][jar][secure]") {
    CookieJar jar;
    const Url secure_host = make_url("https", "example.com");
    REQUIRE(jar.set_from_header(secure_host, view("sid=1; Secure; Path=/")));

    // An https proxy in front of an http target: the URL the jar sees is http,
    // so the cookie stays home.
    const Url http_target = make_url("http", "example.com");
    CHECK(jar.cookie_header(http_target).empty());

    // The same host over https does receive it.
    CHECK(s(jar.cookie_header(secure_host)) == "sid=1");

    // And a non-Secure cookie is unaffected by any of this.
    REQUIRE(jar.set_from_header(http_target, view("plain=2; Path=/")));
    CHECK(s(jar.cookie_header(http_target)) == "plain=2");
}

// ---------------------------------------------------------------------------
// Client integration
//
// The jar tests above prove the storage rules. These prove the Client actually
// uses them: the header goes out, Set-Cookie comes back, and the next request
// carries the cookie. A jar that is correct but never consulted would pass every
// test above and be useless.
// ---------------------------------------------------------------------------

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <megohttp/client.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

namespace {

#if defined(_WIN32)
using sock_t = SOCKET;
const sock_t kInvalid = INVALID_SOCKET;
void closesock(sock_t s) { ::closesocket(s); }
#else
using sock_t = int;
const sock_t kInvalid = -1;
void closesock(sock_t s) { ::close(s); }
#endif

// Minimal HTTP origin: answers every request with a fixed status plus whatever
// Set-Cookie lines the test armed, and records the Cookie header it received.
class CookieServer {
public:
    bool start() {
#if defined(_WIN32)
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_ == kInvalid) return false;
        int on = 1;
        ::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&on), sizeof on);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::bind(listen_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        if (::listen(listen_, 16) != 0) return false;
        sockaddr_in got{};
        socklen_t glen = sizeof got;
        ::getsockname(listen_, reinterpret_cast<sockaddr*>(&got), &glen);
        port_ = ntohs(got.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    uint16_t port() const noexcept { return port_; }

    // Set-Cookie lines returned with every response, until changed.
    void set_cookies(std::vector<std::string> lines) {
        std::lock_guard<std::mutex> g(mu_);
        set_cookie_lines_ = std::move(lines);
    }

    std::string last_cookie_header() const {
        std::lock_guard<std::mutex> g(mu_);
        return last_cookie_;
    }

    int requests() const noexcept { return requests_.load(); }

    ~CookieServer() { stop(); }

    void stop() {
        if (stopped_.exchange(true)) return;
        if (listen_ != kInvalid) { closesock(listen_); listen_ = kInvalid; }
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        while (!stopped_.load()) {
            sock_t c = ::accept(listen_, nullptr, nullptr);
            if (c == kInvalid) break;
            requests_.fetch_add(1);
            std::thread([this, c] { serve(c); }).detach();
        }
    }

    void serve(sock_t c) {
        std::string head;
        char ch = 0;
        while (head.size() < 64 * 1024) {
            int n = static_cast<int>(::recv(c, &ch, 1, 0));
            if (n <= 0) break;
            head += ch;
            if (head.size() >= 4 && head.compare(head.size() - 4, 4, "\r\n\r\n") == 0) break;
        }

        std::string cookie;
        {
            std::lock_guard<std::mutex> g(mu_);
            // Case-insensitive header lookup, deliberately crude: this is a
            // fixture, not a second HTTP parser.
            std::string lowered = head;
            for (auto& x : lowered) {
                if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
            }
            const size_t at = lowered.find("\r\ncookie:");
            if (at != std::string::npos) {
                const size_t vstart = at + 9;
                const size_t vend = head.find("\r\n", vstart);
                cookie = head.substr(vstart, (vend == std::string::npos ? head.size() : vend) - vstart);
                // Trim leading spaces.
                while (!cookie.empty() && (cookie[0] == ' ' || cookie[0] == '\t')) {
                    cookie.erase(cookie.begin());
                }
            }
            last_cookie_ = cookie;
        }

        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n";
        {
            std::lock_guard<std::mutex> g(mu_);
            for (const auto& line : set_cookie_lines_) {
                resp += "Set-Cookie: ";
                resp += line;
                resp += "\r\n";
            }
        }
        resp += "\r\nok";
        ::send(c, resp.data(), static_cast<int>(resp.size()), 0);
        closesock(c);
    }

    sock_t listen_{kInvalid};
    uint16_t port_{0};
    std::atomic<bool> stopped_{false};
    std::atomic<int> requests_{0};
    mutable std::mutex mu_;
    std::vector<std::string> set_cookie_lines_;
    std::string last_cookie_;
    std::thread thread_;
};

string to_owning(const std::string& s) { return string(s.data(), s.size()); }

std::string http_url(uint16_t port, const char* path = "/") {
    return "http://127.0.0.1:" + std::to_string(port) + path;
}

} // namespace

TEST_CASE("the Client sends cookies from the jar and stores Set-Cookie",
          "[cookie][client]") {
    CookieServer srv;
    REQUIRE(srv.start());

    auto jar = make_cookie_jar();
    ClientOptions o;
    o.cookie_jar = jar;

    Client c(o);

    // First request: the server sets a cookie.
    srv.set_cookies({"sid=abc123; Path=/"});
    auto r1 = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/first"))));
    REQUIRE(r1);
    CHECK(r1.value().head().status_code == 200);
    // The first request carried no cookie.
    CHECK(srv.last_cookie_header().empty());
    CHECK(jar->size() == 1);

    // Second request: the cookie goes out, and the server sees it.
    srv.set_cookies({});
    auto r2 = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/second"))));
    REQUIRE(r2);
    CHECK(srv.last_cookie_header() == "sid=abc123");
}

TEST_CASE("a client without a jar sends no cookies", "[cookie][client]") {
    CookieServer srv;
    REQUIRE(srv.start());
    srv.set_cookies({"sid=abc123; Path=/"});

    ClientOptions o;   // cookie_jar left null
    Client c(o);

    auto r1 = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/a"))));
    REQUIRE(r1);
    // Nothing was stored, so nothing is sent.
    auto r2 = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/b"))));
    REQUIRE(r2);
    CHECK(srv.last_cookie_header().empty());
}

TEST_CASE("multiple Set-Cookie headers all reach the jar", "[cookie][client]") {
    CookieServer srv;
    REQUIRE(srv.start());
    // Two independent headers, one of which contains a comma in Expires.
    srv.set_cookies({
        "a=1; Path=/",
        "b=2; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT",
    });

    auto jar = make_cookie_jar();
    ClientOptions o;
    o.cookie_jar = jar;
    Client c(o);

    auto r = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/set"))));
    REQUIRE(r);

    // A comma-joined parse would have produced one cookie, not two.
    CHECK(jar->size() == 2);
    CHECK(s(jar->cookie_header(*parse_url(to_owning(http_url(srv.port()))))) == "a=1; b=2");
}

TEST_CASE("a jar-configured client honours the path on the next request",
          "[cookie][client]") {
    CookieServer srv;
    REQUIRE(srv.start());
    srv.set_cookies({"scoped=1; Path=/app"});

    auto jar = make_cookie_jar();
    ClientOptions o;
    o.cookie_jar = jar;
    Client c(o);

    auto r1 = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/app/x"))));
    REQUIRE(r1);
    CHECK(jar->size() == 1);

    srv.set_cookies({});
    // Same host, outside the cookie path: nothing is sent.
    auto r2 = c.request_sync(Request(Method::Get, to_owning(http_url(srv.port(), "/other"))));
    REQUIRE(r2);
    CHECK(srv.last_cookie_header().empty());
}
