#include <megohttp/proxy.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

using namespace megohttp;
namespace pd = megohttp::proxy_detail;
namespace s5 = megohttp::proxy_detail::socks5;

namespace {

// Renders a library string into a std::string so Catch2 can print it on failure.
std::string sv(string_view v) { return std::string(v.data(), v.size()); }
std::string s(const string& v) { return sv(to_view(v)); }

// SOCKS5 frames are binary: they must be compared byte by byte, never through
// a text string (a trailing NUL would be lost by a text builder).
std::string bs(const byte_buffer& v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

// A getenv stand-in: proves the env parser reads exactly the names it claims to
// and nothing else, without touching the real process environment.
struct FakeEnv {
    std::map<std::string, std::string> vars;
    pd::GetenvFn fn() const {
        return [this](const char* k) -> const char* {
            auto it = vars.find(k);
            return it == vars.end() ? nullptr : it->second.c_str();
        };
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Base64 (RFC 4648 section 10 test vectors)
// ---------------------------------------------------------------------------

TEST_CASE("base64 matches the RFC 4648 vectors", "[proxy][base64]") {
    CHECK(s(pd::base64_encode(string_view(""))) == "");
    CHECK(s(pd::base64_encode(string_view("f"))) == "Zg==");
    CHECK(s(pd::base64_encode(string_view("fo"))) == "Zm8=");
    CHECK(s(pd::base64_encode(string_view("foo"))) == "Zm9v");
    CHECK(s(pd::base64_encode(string_view("foob"))) == "Zm9vYg==");
    CHECK(s(pd::base64_encode(string_view("fooba"))) == "Zm9vYmE=");
    CHECK(s(pd::base64_encode(string_view("foobar"))) == "Zm9vYmFy");
}

TEST_CASE("base64 handles bytes above 0x7F without sign extension", "[proxy][base64]") {
    // A signed char promoted to uint32 without masking would smear 0xFF into the
    // high bits here; the expected value catches that.
    const char raw[] = {static_cast<char>(0xFF), static_cast<char>(0xFE), static_cast<char>(0xFD)};
    CHECK(s(pd::base64_encode(string_view(raw, 3))) == "//79");
}

TEST_CASE("basic auth is user colon password, base64 encoded", "[proxy][base64]") {
    // RFC 7617: the credentials are joined with a colon BEFORE encoding, which
    // is what makes a password containing a colon ambiguous but still correct.
    CHECK(s(pd::basic_auth_value(string_view("Aladdin"), string_view("open sesame"))) ==
          "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    CHECK(s(pd::basic_auth_value(string_view("user"), string_view(""))) ==
          s(pd::base64_encode(string_view("user:"))));
    CHECK(s(pd::basic_auth_value(string_view(""), string_view(""))) ==
          s(pd::base64_encode(string_view(":"))));
}

// ---------------------------------------------------------------------------
// Transport classification
// ---------------------------------------------------------------------------

TEST_CASE("only http and https proxies forward absolute-form requests", "[proxy]") {
    CHECK(pd::is_forward_proxy(ProxyType::Http));
    CHECK(pd::is_forward_proxy(ProxyType::Https));
    // SOCKS5 is a byte tunnel, not an HTTP intermediary: nothing may be
    // rewritten into absolute-form for it.
    CHECK_FALSE(pd::is_forward_proxy(ProxyType::Socks5));
    CHECK_FALSE(pd::is_forward_proxy(ProxyType::None));
}

TEST_CASE("only an https proxy wraps its own connection in TLS", "[proxy]") {
    CHECK(pd::uses_proxy_tls(ProxyType::Https));
    CHECK_FALSE(pd::uses_proxy_tls(ProxyType::Http));
    CHECK_FALSE(pd::uses_proxy_tls(ProxyType::Socks5));
    CHECK_FALSE(pd::uses_proxy_tls(ProxyType::None));
}

TEST_CASE("a CONNECT tunnel is needed only for a secure target", "[proxy]") {
    // http target through an http proxy: absolute-form, no tunnel.
    CHECK_FALSE(pd::needs_connect(ProxyType::Http, false));
    // https target through an http proxy: tunnel required.
    CHECK(pd::needs_connect(ProxyType::Http, true));
    // Same for an HTTPS proxy: TLS to the proxy, then a tunnel inside it.
    CHECK(pd::needs_connect(ProxyType::Https, true));
    CHECK_FALSE(pd::needs_connect(ProxyType::Https, false));
    // SOCKS5 never speaks CONNECT; it always tunnels.
    CHECK_FALSE(pd::needs_connect(ProxyType::Socks5, true));
}

// ---------------------------------------------------------------------------
// NO_PROXY
// ---------------------------------------------------------------------------

TEST_CASE("a NO_PROXY entry matches the host and its subdomains", "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("example.com"), 80, string_view("example.com")));
    CHECK(pd::no_proxy_matches(string_view("a.example.com"), 80, string_view("example.com")));
    CHECK(pd::no_proxy_matches(string_view("a.b.example.com"), 80, string_view("example.com")));
    // Must not match a name that merely ends with the same letters.
    CHECK_FALSE(pd::no_proxy_matches(string_view("notexample.com"), 80, string_view("example.com")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("example.com.evil"), 80, string_view("example.com")));
}

TEST_CASE("a leading dot means the same thing as no dot", "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("example.com"), 80, string_view(".example.com")));
    CHECK(pd::no_proxy_matches(string_view("a.example.com"), 80, string_view(".example.com")));
    // "." alone matches nothing rather than everything.
    CHECK_FALSE(pd::no_proxy_matches(string_view("example.com"), 80, string_view(".")));
}

TEST_CASE("a bare dot entry does not act as a wildcard", "[proxy][no_proxy]") {
    // Getting this wrong would bypass the proxy for every host.
    CHECK_FALSE(pd::no_proxy_matches(string_view("anything.test"), 80, string_view(".")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("anything.test"), 80, string_view("")));
}

TEST_CASE("a star entry bypasses every host", "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("example.com"), 80, string_view("*")));
    CHECK(pd::no_proxy_matches(string_view("127.0.0.1"), 1234, string_view("*")));
}

TEST_CASE("a NO_PROXY entry with a port only matches that port", "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("example.com"), 8080, string_view("example.com:8080")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("example.com"), 80, string_view("example.com:8080")));
    // The bare form matches every port.
    CHECK(pd::no_proxy_matches(string_view("example.com"), 8080, string_view("example.com")));
}

TEST_CASE("an IPv4 literal can be bypassed exactly", "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("127.0.0.1"), 80, string_view("127.0.0.1")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("127.0.0.2"), 80, string_view("127.0.0.1")));
    // Neither direction may suffix-match an address: "0.0.1" must not bypass
    // "127.0.0.1", and an address entry must not swallow a name that merely
    // ends with the same digits.
    CHECK_FALSE(pd::no_proxy_matches(string_view("0.0.1"), 80, string_view("127.0.0.1")));
    // An exact address match still matches.
    CHECK(pd::no_proxy_matches(string_view("0.0.1"), 80, string_view("0.0.1")));
    // A NAME must not be suffix-matched against an address entry: that would
    // let an attacker-registered "a.127.0.0.1" bypass the proxy for 127.0.0.1.
    CHECK_FALSE(pd::no_proxy_matches(string_view("a.127.0.0.1"), 80, string_view("127.0.0.1")));
    // An address entry is a literal, never a domain suffix: "0.0.1" must not
    // bypass 127.0.0.1.
    CHECK_FALSE(pd::no_proxy_matches(string_view("127.0.0.1"), 80, string_view("0.0.1")));
    // A plain domain entry still matches its subdomains (the usual case).
    CHECK(pd::no_proxy_matches(string_view("a.example.com"), 80, string_view("example.com")));
}

TEST_CASE("an IPv6 literal works with and without brackets", "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("::1"), 80, string_view("::1")));
    CHECK(pd::no_proxy_matches(string_view("::1"), 80, string_view("[::1]")));
    // An IPv6 entry that carries a port must be bracketed: "::1:8080" is a
    // bare address with three colons, not host:port, and is treated as such.
    CHECK(pd::no_proxy_matches(string_view("::1"), 8080, string_view("[::1]:8080")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("::1"), 80, string_view("[::1]:8080")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("::1"), 8080, string_view("::1:8080")));
}

TEST_CASE("NO_PROXY matching ignores ASCII case and surrounding space",
          "[proxy][no_proxy]") {
    CHECK(pd::no_proxy_matches(string_view("Example.COM"), 80, string_view("EXAMPLE.com")));
    CHECK(pd::no_proxy_matches(string_view("example.com"), 80, string_view("  example.com  ")));
}

TEST_CASE("an unparseable NO_PROXY entry bypasses nothing", "[proxy][no_proxy]") {
    // A spelling the parser does not understand must not widen the bypass set.
    // "example.com*" is not the documented form, so it is read as a literal
    // host name that matches nothing.
    CHECK_FALSE(pd::no_proxy_matches(string_view("example.com"), 80, string_view("example.com*")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("example.com"), 80, string_view(":8080")));
    CHECK_FALSE(pd::no_proxy_matches(string_view("example.com"), 80, string_view("host:99999")));
}

TEST_CASE("a NO_PROXY list matches when any entry matches", "[proxy][no_proxy]") {
    std::vector<string> list;
    list.push_back(string("10.0.0.1"));
    list.push_back(string("internal.test"));
    list.push_back(string("localhost:8080"));
    CHECK(pd::no_proxy_matches(string_view("internal.test"), 80, list));
    CHECK(pd::no_proxy_matches(string_view("a.internal.test"), 80, list));
    CHECK(pd::no_proxy_matches(string_view("localhost"), 8080, list));
    CHECK_FALSE(pd::no_proxy_matches(string_view("localhost"), 80, list));
    CHECK_FALSE(pd::no_proxy_matches(string_view("external.test"), 80, list));
}

// ---------------------------------------------------------------------------
// Proxy URL parsing: the scheme decides the transport
// ---------------------------------------------------------------------------

TEST_CASE("a proxy URL scheme decides the transport, not the variable name",
          "[proxy][env]") {
    auto a = pd::parse_proxy_url(string_view("http://proxy.test:3128"));
    REQUIRE(a);
    CHECK(a.value().type == ProxyType::Http);
    CHECK(s(a.value().host) == "proxy.test");
    CHECK(a.value().port == 3128);

    auto b = pd::parse_proxy_url(string_view("https://proxy.test:3128"));
    REQUIRE(b);
    CHECK(b.value().type == ProxyType::Https);

    auto c = pd::parse_proxy_url(string_view("socks5://proxy.test:1080"));
    REQUIRE(c);
    CHECK(c.value().type == ProxyType::Socks5);
    // socks5 resolves the target name locally.
    CHECK_FALSE(c.value().socks5_remote_dns);

    auto d = pd::parse_proxy_url(string_view("socks5h://proxy.test:1080"));
    REQUIRE(d);
    CHECK(d.value().type == ProxyType::Socks5);
    // socks5h hands the name to the proxy, which is the only form that keeps
    // the target name off the local resolver.
    CHECK(d.value().socks5_remote_dns);
}

TEST_CASE("a proxy URL carries credentials out of the userinfo", "[proxy][env]") {
    auto p = pd::parse_proxy_url(string_view("http://alice:s3cret@proxy.test:8080"));
    REQUIRE(p);
    CHECK(s(p.value().username) == "alice");
    CHECK(s(p.value().password) == "s3cret");
    CHECK(p.value().has_credentials());
    CHECK(p.value().port == 8080);
}

TEST_CASE("a proxy URL without a port takes the scheme default", "[proxy][env]") {
    auto h = pd::parse_proxy_url(string_view("http://proxy.test"));
    REQUIRE(h);
    CHECK(h.value().port == 80);
    auto t = pd::parse_proxy_url(string_view("https://proxy.test"));
    REQUIRE(t);
    CHECK(t.value().port == 443);
}

TEST_CASE("a proxy URL with an unusable scheme is rejected", "[proxy][env]") {
    CHECK_FALSE(pd::parse_proxy_url(string_view("ftp://proxy.test:21")).has_value());
    CHECK_FALSE(pd::parse_proxy_url(string_view("proxy.test:3128")).has_value());
    CHECK_FALSE(pd::parse_proxy_url(string_view("")).has_value());
    CHECK_FALSE(pd::parse_proxy_url(string_view("http://")).has_value());
}

// ---------------------------------------------------------------------------
// Environment selection
// ---------------------------------------------------------------------------

TEST_CASE("environment variables are ignored unless reading them is enabled",
          "[proxy][env]") {
    // A library that silently followed the caller's shell would change who sees
    // the request without being asked.
    FakeEnv env;
    env.vars["http_proxy"] = "http://proxy.test:3128";
    ProxyOptions opts;                 // from_env defaults to false
    auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"), 80, false);
    REQUIRE(d);
    CHECK(d.value().config.type == ProxyType::None);
}

TEST_CASE("from_env picks up http_proxy for a cleartext target", "[proxy][env]") {
    FakeEnv env;
    env.vars["http_proxy"] = "http://proxy.test:3128";
    ProxyOptions opts;
    opts.from_env = true;
    auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"), 80, false);
    REQUIRE(d);
    CHECK(d.value().config.type == ProxyType::Http);
    CHECK(d.value().from_environment);
    CHECK(s(d.value().config.host) == "proxy.test");
}

TEST_CASE("uppercase HTTP_PROXY is deliberately not honoured", "[proxy][env]") {
    // CGI programs copy request headers into HTTP_*, so an attacker sending
    // "Proxy: http://evil:1/" creates HTTP_PROXY. Obeying it is the httpoxy
    // vulnerability; libcurl refuses it too.
    FakeEnv env;
    env.vars["HTTP_PROXY"] = "http://evil.test:1";
    ProxyOptions opts;
    opts.from_env = true;
    auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"), 80, false);
    REQUIRE(d);
    CHECK(d.value().config.type == ProxyType::None);
}

TEST_CASE("HTTPS_PROXY in either case is honoured for a secure target",
          "[proxy][env]") {
    for (const char* name : {"https_proxy", "HTTPS_PROXY"}) {
        FakeEnv env;
        env.vars[name] = "http://proxy.test:3128";
        ProxyOptions opts;
        opts.from_env = true;
        auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"), 443, true);
        REQUIRE(d);
        // The NAME says what is talked through it, not what is talked to it:
        // an http:// value means a cleartext proxy even for an https target.
        CHECK(d.value().config.type == ProxyType::Http);
        CHECK_FALSE(pd::uses_proxy_tls(d.value().config.type));
    }
}

TEST_CASE("a lowercase https_proxy wins over the uppercase spelling",
          "[proxy][env]") {
    FakeEnv env;
    env.vars["https_proxy"] = "http://lower.test:1";
    env.vars["HTTPS_PROXY"] = "http://upper.test:2";
    ProxyOptions opts;
    opts.from_env = true;
    auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"), 443, true);
    REQUIRE(d);
    CHECK(s(d.value().config.host) == "lower.test");
}

TEST_CASE("all_proxy is the fallback for both schemes", "[proxy][env]") {
    for (bool secure : {false, true}) {
        FakeEnv env;
        env.vars["all_proxy"] = "socks5h://proxy.test:1080";
        ProxyOptions opts;
        opts.from_env = true;
        auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"),
                                  secure ? 443 : 80, secure);
        REQUIRE(d);
        CHECK(d.value().config.type == ProxyType::Socks5);
    }
}

TEST_CASE("NO_PROXY from the environment bypasses the environment proxy",
          "[proxy][env]") {
    FakeEnv env;
    env.vars["http_proxy"] = "http://proxy.test:3128";
    env.vars["no_proxy"] = "internal.test,localhost";
    ProxyOptions opts;
    opts.from_env = true;

    auto a = pd::select_proxy(opts, env.fn(), string_view("internal.test"), 80, false);
    REQUIRE(a);
    CHECK(a.value().config.type == ProxyType::None);

    auto b = pd::select_proxy(opts, env.fn(), string_view("public.test"), 80, false);
    REQUIRE(b);
    CHECK(b.value().config.type == ProxyType::Http);
}

TEST_CASE("an explicit proxy wins over the environment", "[proxy][env]") {
    FakeEnv env;
    env.vars["http_proxy"] = "http://env.test:1";
    ProxyOptions opts;
    opts.from_env = true;
    opts.proxy.type = ProxyType::Http;
    opts.proxy.host = string("explicit.test");
    opts.proxy.port = 2;
    auto d = pd::select_proxy(opts, env.fn(), string_view("example.com"), 80, false);
    REQUIRE(d);
    CHECK(s(d.value().config.host) == "explicit.test");
    CHECK_FALSE(d.value().from_environment);
}

TEST_CASE("NO_PROXY applies to an explicitly configured proxy too",
          "[proxy][no_proxy]") {
    // A bypass list that only worked for environment-derived proxies would
    // surprise anyone who configured the proxy directly.
    ProxyOptions opts;
    opts.proxy.type = ProxyType::Http;
    opts.proxy.host = string("proxy.test");
    opts.proxy.port = 3128;
    opts.no_proxy.push_back(string("local.test"));

    auto a = pd::select_proxy(opts, pd::GetenvFn{}, string_view("local.test"), 80, false);
    REQUIRE(a);
    CHECK(a.value().config.type == ProxyType::None);

    auto b = pd::select_proxy(opts, pd::GetenvFn{}, string_view("remote.test"), 80, false);
    REQUIRE(b);
    CHECK(b.value().config.type == ProxyType::Http);
}

// ---------------------------------------------------------------------------
// Wire format: authority and CONNECT
// ---------------------------------------------------------------------------

TEST_CASE("an authority re-brackets an IPv6 literal", "[proxy][connect]") {
    CHECK(s(pd::authority_of(string_view("example.com"), 443)) == "example.com:443");
    CHECK(s(pd::authority_of(string_view("127.0.0.1"), 8080)) == "127.0.0.1:8080");
    CHECK(s(pd::authority_of(string_view("::1"), 443)) == "[::1]:443");
    CHECK(s(pd::authority_of(string_view("2001:db8::1"), 443)) == "[2001:db8::1]:443");
}

TEST_CASE("a CONNECT request carries the authority and nothing else",
          "[proxy][connect]") {
    ProxyConfig cfg;                     // no credentials
    const string req = pd::build_connect_request(
        string_view("example.com"), 443, cfg, string_view("TestAgent/1"));
    const std::string got = s(req);

    CHECK(got.rfind("CONNECT example.com:443 HTTP/1.1\r\n", 0) == 0);
    CHECK(got.find("Host: example.com:443\r\n") != std::string::npos);
    CHECK(got.find("User-Agent: TestAgent/1\r\n") != std::string::npos);
    // No credentials were configured, so no authorization header at all.
    CHECK(got.find("Proxy-Authorization") == std::string::npos);
    CHECK(got.find("Authorization") == std::string::npos);
    // Ends with the blank line, with nothing after it: the tunnel starts only
    // after the proxy answers.
    CHECK(got.substr(got.size() - 4) == "\r\n\r\n");
}

TEST_CASE("a CONNECT request carries proxy credentials when configured",
          "[proxy][connect]") {
    ProxyConfig cfg;
    cfg.username = string("Aladdin");
    cfg.password = string("open sesame");
    const std::string got = s(pd::build_connect_request(
        string_view("example.com"), 443, cfg, string_view()));
    CHECK(got.find("Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n") !=
          std::string::npos);
}

TEST_CASE("CONNECT status classification separates the failure modes",
          "[proxy][connect]") {
    using O = pd::ConnectOutcome;
    CHECK(pd::classify_connect_response(200) == O::Ok);
    CHECK(pd::classify_connect_response(204) == O::Ok);
    CHECK(pd::classify_connect_response(299) == O::Ok);
    // 407 is the proxy asking for credentials: distinct from a rejection.
    CHECK(pd::classify_connect_response(407) == O::AuthRequired);
    CHECK(pd::classify_connect_response(401) == O::AuthFailed);
    CHECK(pd::classify_connect_response(403) == O::AuthFailed);
    CHECK(pd::classify_connect_response(502) == O::Refused);
    CHECK(pd::classify_connect_response(0) == O::Malformed);
}

TEST_CASE("each CONNECT outcome maps to its own error code", "[proxy][connect]") {
    using O = pd::ConnectOutcome;
    CHECK(pd::connect_outcome_error(O::AuthRequired, 407).code() ==
          ErrorCode::ProxyAuthRequired);
    CHECK(pd::connect_outcome_error(O::AuthFailed, 401).code() ==
          ErrorCode::ProxyAuthFailed);
    CHECK(pd::connect_outcome_error(O::Refused, 502).code() ==
          ErrorCode::ProxyConnectFailed);
    CHECK(pd::connect_outcome_error(O::Malformed, 0).code() ==
          ErrorCode::ProxyProtocolError);
    // A 407 must not be reported as a generic proxy failure: the caller needs to
    // know the difference between "add credentials" and "the proxy is broken".
    CHECK(pd::connect_outcome_error(O::AuthRequired, 407).code() !=
          ErrorCode::ProxyConnectFailed);
}

// ---------------------------------------------------------------------------
// SOCKS5 wire format
// ---------------------------------------------------------------------------

TEST_CASE("a SOCKS5 greeting offers the methods it can actually perform",
          "[proxy][socks5]") {
    const std::string none = bs(s5::build_greeting(false));
    REQUIRE(none.size() == 3);
    CHECK(static_cast<uint8_t>(none[0]) == 0x05);
    CHECK(static_cast<uint8_t>(none[1]) == 1);          // exactly one method
    CHECK(static_cast<uint8_t>(none[2]) == 0x00);       // no auth

    const std::string both = bs(s5::build_greeting(true));
    REQUIRE(both.size() == 4);
    CHECK(static_cast<uint8_t>(both[1]) == 2);
    CHECK(static_cast<uint8_t>(both[2]) == 0x00);       // no-auth preferred
    CHECK(static_cast<uint8_t>(both[3]) == 0x02);       // user/pass fallback
}

TEST_CASE("a SOCKS5 method selection is validated, not trusted",
          "[proxy][socks5]") {
    const char no_auth[] = {static_cast<char>(0x05), static_cast<char>(0x00)};
    auto ok = s5::parse_method_selection(string_view(no_auth, 2));
    REQUIRE(ok);
    CHECK(ok.value() == 0x00);

    const char rejected[] = {static_cast<char>(0x05), static_cast<char>(0xFF)};
    auto bad = s5::parse_method_selection(string_view(rejected, 2));
    REQUIRE_FALSE(bad);
    CHECK(bad.error().code() == ErrorCode::Socks5AuthFailed);

    const char wrong_ver[] = {static_cast<char>(0x04), static_cast<char>(0x00)};
    auto v = s5::parse_method_selection(string_view(wrong_ver, 2));
    REQUIRE_FALSE(v);
    CHECK(v.error().code() == ErrorCode::Socks5HandshakeFailed);

    CHECK_FALSE(s5::parse_method_selection(string_view("\x05", 1)).has_value());
}

TEST_CASE("the SOCKS5 user/pass sub-negotiation is RFC 1929 shaped",
          "[proxy][socks5]") {
    const std::string got = bs(s5::build_user_pass(string_view("us"), string_view("pw")));
    REQUIRE(got.size() == 7);
    CHECK(static_cast<uint8_t>(got[0]) == 0x01);   // sub-negotiation version
    CHECK(static_cast<uint8_t>(got[1]) == 2);      // username length
    CHECK(got.substr(2, 2) == "us");
    CHECK(static_cast<uint8_t>(got[4]) == 2);      // password length
    CHECK(got.substr(5, 2) == "pw");

    const char accept[] = {static_cast<char>(0x01), static_cast<char>(0x00)};
    REQUIRE(s5::parse_user_pass_reply(string_view(accept, 2)));

    const char deny[] = {static_cast<char>(0x01), static_cast<char>(0x01)};
    auto r = s5::parse_user_pass_reply(string_view(deny, 2));
    REQUIRE_FALSE(r);
    CHECK(r.error().code() == ErrorCode::Socks5AuthFailed);
}

TEST_CASE("a SOCKS5 CONNECT with remote DNS sends the name, not an address",
          "[proxy][socks5]") {
    // This is the whole point of the remote-DNS mode: if the name were resolved
    // locally the local resolver would have seen it.
    const std::string got = bs(s5::build_connect(
        s5::kAtypDomain, string_view("example.com"), nullptr, 0, 443));
    REQUIRE(got.size() == 4 + 1 + 11 + 2);
    CHECK(static_cast<uint8_t>(got[0]) == 0x05);
    CHECK(static_cast<uint8_t>(got[1]) == 0x01);            // CONNECT
    CHECK(static_cast<uint8_t>(got[2]) == 0x00);            // RSV must be zero
    CHECK(static_cast<uint8_t>(got[3]) == s5::kAtypDomain);
    CHECK(static_cast<uint8_t>(got[4]) == 11);              // name length
    CHECK(got.substr(5, 11) == "example.com");
    CHECK(static_cast<uint8_t>(got[16]) == 0x01);           // port high byte
    CHECK(static_cast<uint8_t>(got[17]) == 0xBB);           // 443 = 0x01BB
}

TEST_CASE("a SOCKS5 CONNECT with a local address sends the bytes",
          "[proxy][socks5]") {
    const uint8_t addr[4] = {127, 0, 0, 1};
    const std::string got = bs(s5::build_connect(s5::kAtypIpv4, string_view(),
                                                addr, 4, 80));
    REQUIRE(got.size() == 4 + 4 + 2);
    CHECK(static_cast<uint8_t>(got[3]) == s5::kAtypIpv4);
    CHECK(static_cast<uint8_t>(got[4]) == 127);
    CHECK(static_cast<uint8_t>(got[7]) == 1);
    CHECK(static_cast<uint8_t>(got[8]) == 0);
    CHECK(static_cast<uint8_t>(got[9]) == 80);
}

TEST_CASE("a SOCKS5 reply waits for its full address before reporting",
          "[proxy][socks5]") {
    // A parser that accepted the first four bytes would hand a half-read address
    // back and leave the remainder to be mistaken for tunnel data.
    const char partial[] = {static_cast<char>(0x05), static_cast<char>(0x00),
                            static_cast<char>(0x00), static_cast<char>(0x01),
                            static_cast<char>(127), static_cast<char>(0)};
    auto a = s5::parse_reply(string_view(partial, sizeof partial));
    REQUIRE(a);
    CHECK_FALSE(a.value().complete);

    const char full[] = {static_cast<char>(0x05), static_cast<char>(0x00),
                         static_cast<char>(0x00), static_cast<char>(0x01),
                         static_cast<char>(127), static_cast<char>(0),
                         static_cast<char>(0), static_cast<char>(1),
                         static_cast<char>(0x04), static_cast<char>(0x38)};
    auto b = s5::parse_reply(string_view(full, sizeof full));
    REQUIRE(b);
    CHECK(b.value().complete);
    CHECK(b.value().code == s5::Reply::Succeeded);
    CHECK(b.value().consumed == sizeof full);
}

TEST_CASE("a SOCKS5 reply with a domain address consumes its name",
          "[proxy][socks5]") {
    const char reply[] = {static_cast<char>(0x05), static_cast<char>(0x00),
                          static_cast<char>(0x00), static_cast<char>(0x03),
                          static_cast<char>(4), 'h', 'o', 's', 't',
                          static_cast<char>(0x01), static_cast<char>(0xBB)};
    // The name is 4 bytes, so the total is 4 + 1 + 4 + 2.
    const char complete[] = {static_cast<char>(0x05), static_cast<char>(0x00),
                             static_cast<char>(0x00), static_cast<char>(0x03),
                             static_cast<char>(3), 'a', 'b', 'c',
                             static_cast<char>(0x01), static_cast<char>(0xBB)};
    auto a = s5::parse_reply(string_view(reply, sizeof reply));
    REQUIRE(a);
    CHECK(a.value().complete);
    CHECK(a.value().consumed == sizeof reply);

    auto b = s5::parse_reply(string_view(complete, sizeof complete));
    REQUIRE(b);
    CHECK(b.value().consumed == sizeof complete);
}

TEST_CASE("a SOCKS5 reply error code maps to a distinguishable failure",
          "[proxy][socks5]") {
    auto mk = [](uint8_t rep) {
        const char r[] = {static_cast<char>(0x05), static_cast<char>(rep),
                          static_cast<char>(0x00), static_cast<char>(0x01),
                          static_cast<char>(0), static_cast<char>(0),
                          static_cast<char>(0), static_cast<char>(0),
                          static_cast<char>(0), static_cast<char>(0)};
        return s5::parse_reply(string_view(r, sizeof r));
    };
    auto a = mk(0x05);                                  // connection refused
    REQUIRE(a);
    CHECK(a.value().code == s5::Reply::ConnectionRefused);
    CHECK(s5::reply_error(a.value().code).code() == ErrorCode::ProxyConnectFailed);

    auto b = mk(0x07);                                  // command unsupported
    REQUIRE(b);
    CHECK(s5::reply_error(b.value().code).code() == ErrorCode::Socks5HandshakeFailed);

    auto c = mk(0x02);                                  // denied by rule
    REQUIRE(c);
    CHECK(s5::reply_error(c.value().code).code() == ErrorCode::ProxyConnectFailed);
}

TEST_CASE("a SOCKS5 reply with a bad reserved byte or version is rejected",
          "[proxy][socks5]") {
    const char bad_rsv[] = {static_cast<char>(0x05), static_cast<char>(0x00),
                            static_cast<char>(0x01), static_cast<char>(0x01),
                            0, 0, 0, 0, 0, 0};
    auto a = s5::parse_reply(string_view(bad_rsv, sizeof bad_rsv));
    REQUIRE_FALSE(a);
    CHECK(a.error().code() == ErrorCode::ProxyProtocolError);

    const char bad_ver[] = {static_cast<char>(0x04), static_cast<char>(0x00),
                            static_cast<char>(0x00), static_cast<char>(0x01),
                            0, 0, 0, 0, 0, 0};
    auto b = s5::parse_reply(string_view(bad_ver, sizeof bad_ver));
    REQUIRE_FALSE(b);
    CHECK(b.error().code() == ErrorCode::Socks5HandshakeFailed);

    const char bad_atyp[] = {static_cast<char>(0x05), static_cast<char>(0x00),
                             static_cast<char>(0x00), static_cast<char>(0x09),
                             0, 0, 0, 0, 0, 0};
    auto c = s5::parse_reply(string_view(bad_atyp, sizeof bad_atyp));
    REQUIRE_FALSE(c);
    CHECK(c.error().code() == ErrorCode::Socks5HandshakeFailed);
}

TEST_CASE("an IP literal stays a literal under remote DNS",
          "[proxy][socks5]") {
    // There is no name to hand over for an address, so remote DNS does not turn
    // a literal into a domain request.
    CHECK(s5::atyp_for(true) == s5::kAtypDomain);
    CHECK(s5::atyp_for(false) == s5::kAtypIpv4);
}

TEST_CASE("parse_url marks a dotted quad as an IP literal",
          "[proxy][url]") {
    // SOCKS5 local-DNS mode sends an ADDRESS for a literal target, so this flag
    // decides whether that path can work at all.
    auto a = parse_url(string_view("http://127.0.0.1:8080/x"));
    REQUIRE(a);
    CHECK(a.value().is_ip_literal);
    CHECK_FALSE(a.value().is_ipv6_literal);

    auto b = parse_url(string_view("http://[::1]:8080/x"));
    REQUIRE(b);
    CHECK(b.value().is_ip_literal);
    CHECK(b.value().is_ipv6_literal);

    auto c = parse_url(string_view("http://localhost:8080/x"));
    REQUIRE(c);
    CHECK_FALSE(c.value().is_ip_literal);
}

TEST_CASE("has_credentials reflects the configured username and password",
          "[proxy]") {
    ProxyConfig c;
    CHECK_FALSE(c.has_credentials());
    c.username = string("alice");
    CHECK(c.has_credentials());
    ProxyConfig d;
    d.password = string("x");
    CHECK(d.has_credentials());
}

TEST_CASE("a greeting with credentials offers no-auth and user/pass",
          "[proxy][socks5]") {
    const std::string g = bs(proxy_detail::socks5::build_greeting(true));
    REQUIRE(g.size() == 4);
    CHECK(static_cast<uint8_t>(g[0]) == 0x05);
    CHECK(static_cast<uint8_t>(g[1]) == 2);
    CHECK(static_cast<uint8_t>(g[2]) == 0x00);
    CHECK(static_cast<uint8_t>(g[3]) == 0x02);
}
