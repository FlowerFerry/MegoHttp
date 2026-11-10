// Unit tests for url.hpp / headers.hpp. No framework: assert-based, one binary.
// Build (from tests/), std mode:
//   g++ -std=c++17 -DMGHTTP_BACKEND_LIBUV -I../include test_core.cpp -o test_core_std
// Build (from tests/), MemeString mode:
//   g++ -std=c++17 -DMGHTTP_USE_MEMESTRING -DMGHTTP_BACKEND_LIBUV \
//       -I../include -I../../MemeString/include test_core.cpp \
//       ../../MemeString/liblibmeme_string.dll -o test_core_memepp
#include <catch2/catch_all.hpp>

#include <megohttp/url.hpp>
#include <megohttp/headers.hpp>
#include <megohttp/error.hpp>
#include <megohttp/format.hpp>
#include <megohttp/idna.hpp>
#include <megohttp/request.hpp>

#include <cstdio>
#include <cstring>

using namespace megohttp;



static bool sv_eq(string_view a, const char* b) {
    const size_t n = detail::to_size(a);
    return n == std::strlen(b) && std::memcmp(a.data(), b, n) == 0;
}
static bool s_eq(const string& a, const char* b) {
    return a.size() == static_cast<string::size_type>(std::strlen(b))
        && std::memcmp(a.data(), b, std::strlen(b)) == 0;
}

// to_string(const char*) must compile in both modes and not be ambiguous
// (regression test: memepp mode used to see both string_view and string_span
// overloads as equally viable user-defined conversions from const char[N]).
TEST_CASE("to_string literal disambiguation", "[string_adapter]") {
    // This exact syntax (literal, no explicit size) is the one that broke
    // in memepp mode before the dedicated const char* overload.
    const string s = to_string("literal");
    CHECK(s_eq(s, "literal"));
}

TEST_CASE("url basic", "[core]") {
    // Simple http URL
    {
        auto r = parse_url("http://example.com/path?q=1");
        CHECK(r.has_value());
        if (!r) return;
        const Url& u = r.value();
        CHECK(u.scheme == Scheme::Http);
        CHECK(s_eq(u.host, "example.com"));
        CHECK(u.port == 80);
        CHECK(!u.port_was_explicit);
        CHECK(s_eq(u.path, "/path"));
        CHECK(u.has_query);
        CHECK(s_eq(u.query, "q=1"));
        CHECK(!u.is_ip_literal);
    }
    // Default path when absent
    {
        auto r = parse_url("https://example.com");
        CHECK(r.has_value());
        if (!r) return;
        CHECK(r.value().port == 443);
        CHECK(s_eq(r.value().path, "/"));
        CHECK(!r.value().has_query);
        CHECK(s_eq(r.value().request_target(), "/"));
    }
    // Explicit port
    {
        auto r = parse_url("http://example.com:8080/x");
        CHECK(r.has_value());
        if (!r) return;
        CHECK(r.value().port == 8080);
        CHECK(r.value().port_was_explicit);
        CHECK(s_eq(r.value().host_port_header(), "example.com:8080"));
    }
    // Default port written explicitly is omitted from the Host header
    {
        auto r = parse_url("http://example.com:80/");
        CHECK(r.has_value());
        if (!r) return;
        CHECK(s_eq(r.value().host_port_header(), "example.com"));
    }
    // Host is lowercased
    {
        auto r = parse_url("http://ExAmPle.COM/");
        CHECK(r.has_value());
        if (!r) return;
        CHECK(s_eq(r.value().host, "example.com"));
    }
    // ws / wss defaults
    {
        auto r = parse_url("ws://h/a");
        CHECK((r.has_value() && r.value().port == 80));
        auto r2 = parse_url("wss://h/a");
        CHECK((r2.has_value() && r2.value().port == 443));
    }
}

TEST_CASE("url ipv6", "[core]") {
    {
        auto r = parse_url("http://[::1]:8080/p");
        CHECK(r.has_value());
        if (!r) return;
        CHECK(r.value().is_ipv6_literal);
        CHECK(r.value().is_ip_literal);
        CHECK(s_eq(r.value().host, "::1"));
        CHECK(r.value().port == 8080);
        CHECK(s_eq(r.value().host_port_header(), "[::1]:8080"));
    }
    {
        auto r = parse_url("http://[2001:db8::1]/");
        CHECK(r.has_value());
        if (!r) return;
        CHECK(s_eq(r.value().host_port_header(), "[2001:db8::1]"));
    }
    // Unterminated bracket
    CHECK(parse_url("http://[::1/").has_error());
    // Garbage after bracket
    CHECK(parse_url("http://[::1]x/").has_error());
}

TEST_CASE("url ipv4", "[core]") {
    auto r = parse_url("http://192.168.0.1:8080/");
    CHECK(r.has_value());
    if (!r) return;
    CHECK(r.value().is_ip_literal);
    CHECK(!r.value().is_ipv6_literal);
    CHECK(s_eq(r.value().host, "192.168.0.1"));

    // Out-of-range octet is not a valid IPv4 literal -> treated as a host name,
    // which is still legal syntax (a DNS name may contain dots and digits).
    auto r2 = parse_url("http://999.1.1.1/");
    CHECK(r2.has_value());
    if (r2) CHECK(!r2.value().is_ip_literal);
}

TEST_CASE("url rejects", "[core]") {
    CHECK(parse_url("").has_error());                       // empty
    CHECK(parse_url("example.com/x").has_error());          // relative
    CHECK(parse_url("http:/example.com").has_error());      // one slash
    CHECK(parse_url("ftp://example.com/").has_error());     // unsupported scheme
    CHECK(parse_url("http://").has_error());                // empty authority
    CHECK(parse_url("http:///path").has_error());           // empty host
    CHECK(parse_url("http://exam ple.com/").has_error());   // space
    CHECK(parse_url("http://example.com/a\r\nHost: x").has_error());  // CRLF injection
    CHECK(parse_url("http://example.com:0/").has_error());  // port 0
    CHECK(parse_url("http://example.com:99999/").has_error()); // port overflow
    CHECK(parse_url("http://example.com:abc/").has_error());   // non-numeric port
    CHECK(parse_url("http://example..com/").has_error());   // empty label
    CHECK(parse_url("http://example.com./").has_error());   // trailing dot
    // A Unicode host is REJECTED, not converted: the built-in subset is not a
    // conforming IDNA2008 implementation, and task book 5.4.1 forbids an
    // incomplete conversion. The caller converts with a real library and passes
    // the A-label, which then takes the normal ASCII path.
    {
        auto r = parse_url("http://\xE4\xB8\xAD\xE6\x96\x87.com/");
        CHECK_FALSE(r.has_value());
        CHECK(r.error().code() == ErrorCode::InvalidArgument);
    }
    // The already-encoded form is accepted and reaches DNS as an ASCII name.
    {
        auto r = parse_url("http://xn--fiq228c.com/");
        REQUIRE(r.has_value());
        CHECK(s_eq(r.value().host, "xn--fiq228c.com"));
    }
    // Invalid UTF-8 in the host is still rejected.
    CHECK(parse_url("http://\xFF\xFE.com/").has_error());
}

TEST_CASE("url userinfo", "[core]") {
    auto r = parse_url("http://user:pass@example.com/p");
    CHECK(r.has_value());
    if (!r) return;
    CHECK(s_eq(r.value().host, "example.com"));
    CHECK((r.value().username.has_value() && s_eq(*r.value().username, "user")));
    CHECK((r.value().password.has_value() && s_eq(*r.value().password, "pass")));
    // Credentials must not leak into the request target or Host header
    CHECK(s_eq(r.value().request_target(), "/p"));
    CHECK(s_eq(r.value().host_port_header(), "example.com"));
}

TEST_CASE("url targets", "[core]") {
    auto r = parse_url("https://api.example.com:8443/v1/items?page=2");
    CHECK(r.has_value());
    if (!r) return;
    CHECK(s_eq(r.value().request_target(), "/v1/items?page=2"));
    CHECK(s_eq(r.value().origin(), "https://api.example.com:8443"));
    // The absolute form keeps the URL's own scheme. A hardcoded "http://" here
    // rewrote an https URL into http:// in every caller that rebuilt the URL
    // from this string -- a silent transport downgrade.
    CHECK(s_eq(r.value().absolute_form_target(),
               "https://api.example.com:8443/v1/items?page=2"));
    CHECK(r.value().is_secure());
    CHECK(!r.value().is_websocket());
}

TEST_CASE("a parsed https URL survives a store and reread", "[core][url]") {
    auto r = parse_url("https://api.example.com:8443/v1/items?page=2");
    REQUIRE(r.has_value());

    Request req;
    REQUIRE(req.set_parsed_url(r.value()));

    // Reading the URL back must still say https. Storing a proxy request-target
    // form here used to come back as "http://...", and the next submit() would
    // parse that and open a cleartext connection.
    CHECK(s_eq(to_string(req.url()), "https://api.example.com:8443/v1/items?page=2"));

    // Re-parsing what we stored must yield the same scheme and origin.
    auto again = parse_url(req.url());
    REQUIRE(again.has_value());
    CHECK(again.value().is_secure());
    CHECK(s_eq(again.value().origin(), "https://api.example.com:8443"));
}

// ---------------------------------------------------------------------------
// IPv6 literals
//
// "Inside brackets" was treated as "is an IPv6 address", so [not:an:ipv6]
// parsed successfully and then skipped DNS, going to connect() as if it were an
// address. The literal check has to be real.
// ---------------------------------------------------------------------------
TEST_CASE("an IPv6 literal is validated, not merely bracketed", "[core][url][ipv6]") {
    // Well-formed forms.
    bool v6 = false;
    CHECK(is_ip_literal("::1", &v6));
    CHECK(v6);
    CHECK(is_ip_literal("::", &v6));
    CHECK(v6);
    CHECK(is_ip_literal("2001:db8::1", &v6));
    CHECK(v6);
    CHECK(is_ip_literal("fe80::1:2:3:4", &v6));
    CHECK(v6);
    CHECK(is_ip_literal("::ffff:192.168.1.1", &v6));
    CHECK(v6);
    CHECK(is_ip_literal("2001:0db8:0000:0000:0000:0000:0000:0001", &v6));
    CHECK(v6);

    // Not well-formed.
    CHECK_FALSE(is_ip_literal("not:an:ipv6", &v6));
    CHECK_FALSE(is_ip_literal("1:2:3", &v6));               // too few, no "::"
    CHECK_FALSE(is_ip_literal("1:2:3:4:5:6:7:8:9", &v6));  // too many
    CHECK_FALSE(is_ip_literal("12345::1", &v6));            // group > 4 hex
    CHECK_FALSE(is_ip_literal("::1::2", &v6));              // two "::"
    CHECK_FALSE(is_ip_literal("1::2::3:4:5:6:7", &v6));
    CHECK_FALSE(is_ip_literal("gggg::1", &v6));             // not hex
    CHECK_FALSE(is_ip_literal("1:2:3:4:5:6:7:", &v6));      // trailing single ':'

    // And through the URL parser, a bogus bracketed host is rejected rather
    // than accepted as a literal.
    CHECK_FALSE(parse_url("http://[not:an:ipv6]/p").has_value());
    auto good = parse_url("http://[::1]:8080/p");
    REQUIRE(good.has_value());
    CHECK(good.value().is_ipv6_literal);
    CHECK(good.value().port == 8080);
    CHECK(s_eq(good.value().host, "::1"));
}

// ---------------------------------------------------------------------------
// Request body modes are mutually exclusive
// ---------------------------------------------------------------------------
TEST_CASE("setting one body mode clears the other", "[core][request]") {
    Request req;
    req.set_body_source([]() -> Result<std::pair<string_view, bool>> {
        return std::make_pair(string_view{}, true);
    });
    CHECK(req.body_source().has_value());
    CHECK(req.is_body_replayable() == false);

    // A buffer body must replace the stream, not sit beside it.
    req.set_body(string_view("abc", 3));
    CHECK_FALSE(req.body_source().has_value());
    CHECK(req.body_bytes().size() == 3);
    CHECK(req.is_body_replayable());

    // And clear_body() must drop both carriers.
    req.set_body_source([]() -> Result<std::pair<string_view, bool>> {
        return std::make_pair(string_view{}, true);
    });
    req.clear_body();
    CHECK_FALSE(req.has_body());
    CHECK_FALSE(req.body_source().has_value());
    CHECK(req.body_bytes().empty());
}

TEST_CASE("headers basic", "[core]") {
    Headers h;
    CHECK(h.empty());

    h.add("Content-Type", "text/plain");
    h.add("Accept", "*/*");
    CHECK(h.size() == 2);
    CHECK(h.contains("content-type"));      // case-insensitive
    CHECK(h.contains("CONTENT-TYPE"));
    CHECK(!h.contains("X-Missing"));

    auto ct = h.get("Content-Type");
    CHECK((ct.has_value() && sv_eq(*ct, "text/plain")));

    // Duplicate fields are preserved
    h.add("Set-Cookie", "a=1");
    h.add("Set-Cookie", "b=2");
    auto all = h.get_all("set-cookie");
    CHECK(all.size() == 2);
    CHECK(sv_eq(all[0], "a=1"));
    CHECK(sv_eq(all[1], "b=2"));

    // get() returns the FIRST value
    auto first = h.get("Set-Cookie");
    CHECK((first.has_value() && sv_eq(*first, "a=1")));

    // set() replaces every value of that name
    h.set("set-cookie", "only=1");
    CHECK(h.get_all("Set-Cookie").size() == 1);

    // remove() reports whether anything was erased
    CHECK(h.remove("Set-Cookie"));
    CHECK(!h.remove("Set-Cookie"));
    CHECK(!h.contains("Set-Cookie"));

    // Insertion order is preserved
    Headers ord;
    ord.add("X-A", "1");
    ord.add("X-B", "2");
    ord.add("X-C", "3");
    auto it = ord.begin();
    CHECK(sv_eq(to_view(it->first), "X-A")); ++it;
    CHECK(sv_eq(to_view(it->first), "X-B")); ++it;
    CHECK(sv_eq(to_view(it->first), "X-C"));

    // set() replaces in place: the field keeps its original position, and any
    // duplicates are dropped. Removing then re-adding would have moved it to the
    // end, silently reordering the header block.
    Headers ord2;
    ord2.add("X-A", "1");
    ord2.add("X-B", "2");
    ord2.add("X-C", "3");
    ord2.set("X-B", "changed");
    {
        auto it = ord2.begin();
        CHECK(sv_eq(to_view(it->first), "X-A")); ++it;
        CHECK(sv_eq(to_view(it->first), "X-B"));
        CHECK(sv_eq(to_view(it->second), "changed"));
        ++it;
        CHECK(sv_eq(to_view(it->first), "X-C"));
    }
    // Duplicates collapse to the first position.
    Headers ord3;
    ord3.add("Set-Cookie", "a=1");
    ord3.add("X-Mid", "m");
    ord3.add("Set-Cookie", "b=2");
    ord3.set("set-cookie", "only=1");
    CHECK(ord3.get_all("Set-Cookie").size() == 1);
    {
        auto it = ord3.begin();
        CHECK(sv_eq(to_view(it->first), "Set-Cookie"));
        CHECK(sv_eq(to_view(it->second), "only=1"));
        ++it;
        CHECK(sv_eq(to_view(it->first), "X-Mid"));   // X-Mid kept its place after
    }
    // set() on a missing name appends.
    ord3.set("X-New", "n");
    CHECK(ord3.size() == 3);

    ord.clear();
    CHECK(ord.empty());
}

TEST_CASE("headers uint64", "[core]") {
    Headers h;
    h.add("Content-Length", "12345");
    auto cl = h.get_uint("content-length");
    CHECK((cl.has_value() && *cl == 12345));

    h.set("Content-Length", "abc");
    CHECK(!h.get_uint("Content-Length").has_value());

    h.set("Content-Length", "-5");
    CHECK(!h.get_uint("Content-Length").has_value());

    // Overflow must be rejected, not wrapped
    h.set("Content-Length", "99999999999999999999999");
    CHECK(!h.get_uint("Content-Length").has_value());

    h.set("Content-Length", "");
    CHECK(!h.get_uint("Content-Length").has_value());

    h.set("Content-Length", "0");
    auto zero = h.get_uint("Content-Length");
    CHECK((zero.has_value() && *zero == 0));
}

TEST_CASE("header validation", "[core]") {
    CHECK(is_valid_header_name("Content-Type"));
    CHECK(is_valid_header_name("X-Custom_1"));
    CHECK(!is_valid_header_name(""));
    CHECK(!is_valid_header_name("Bad Header"));      // space
    CHECK(!is_valid_header_name("Bad:Header"));      // colon
    CHECK(!is_valid_header_name("Bad\r\nHeader"));   // CRLF

    CHECK(is_valid_header_value("text/plain"));
    CHECK(is_valid_header_value(""));
    CHECK(is_valid_header_value("a\tb"));            // HTAB allowed
    CHECK(!is_valid_header_value("a\rb"));           // CR rejected
    CHECK(!is_valid_header_value("a\nb"));           // LF rejected
    // Explicit length: a string literal "a\0b" would stop at the NUL.
    CHECK(!is_valid_header_value(string_view("a\0b", 3)));   // NUL rejected
    CHECK(is_valid_header_value(string_view("a\0b", 1)));    // "a" is fine
}

TEST_CASE("error", "[core]") {
    Error e{ErrorCode::HttpChunkError, ErrorPhase::Receive, string("bad chunk")};
    CHECK(e.code() == ErrorCode::HttpChunkError);
    CHECK(e.phase() == ErrorPhase::Receive);
    CHECK(e);
    CHECK(std::strcmp(to_string(e.code()), "HttpChunkError") == 0);
    CHECK(std::strcmp(to_string(e.phase()), "Receive") == 0);

    // Error families the spec requires to stay distinct
    CHECK(std::strcmp(to_string(ErrorCode::WsCompressionNotCompiled),
                      to_string(ErrorCode::WsCompressionMalformedData)) != 0);
    CHECK(std::strcmp(to_string(ErrorCode::MultipartTruncated),
                      to_string(ErrorCode::MultipartDelimiterInvalid)) != 0);

    // Result<T>
    Result<int> ok{42};
    CHECK(ok.has_value());
    CHECK(ok.value() == 42);
    CHECK(static_cast<bool>(ok));
    CHECK(ok.value_or(7) == 42);

    Result<int> bad{Error{ErrorCode::TimeoutTotal}};
    CHECK(bad.has_error());
    CHECK(!static_cast<bool>(bad));
    CHECK(bad.error().code() == ErrorCode::TimeoutTotal);
    CHECK(bad.value_or(7) == 7);

    // VoidResult
    VoidResult vok;
    CHECK(vok.has_value());
    CHECK(static_cast<bool>(vok));
    VoidResult vbad{Error{ErrorCode::Cancelled}};
    CHECK(vbad.has_error());
    CHECK(vbad.error().code() == ErrorCode::Cancelled);
}

TEST_CASE("format", "[core]") {
    // fmt is the only formatter: values must land in the library's string type,
    // with the same text in both string modes.
    string a = format("{}", 42);
    CHECK(a.size() == 2);
    CHECK(std::memcmp(a.data(), "42", 2) == 0);

    string b = format("{}-{}", "x", 7);
    CHECK(b.size() == 3);
    CHECK(std::memcmp(b.data(), "x-7", 3) == 0);

    // Hex formatting is what chunked encoding uses.
    string c = format("{:x}", 26u);
    CHECK(c.size() == 2);
    CHECK(std::memcmp(c.data(), "1a", 2) == 0);

    string d = format("{:x}", 0u);
    CHECK((d.size() == 1 && d.data()[0] == '0'));

    // The megohttp alias exposes the same types.
    megohttp::string e = megohttp::to_string(to_view(b));
    CHECK(e.size() == b.size());
}

TEST_CASE("scheme unknown", "[core]") {
    // Scheme has an Unknown value, and it is what default_port answers 0 for.
    CHECK(static_cast<int>(Scheme::Unknown) == 0);
    CHECK(Url::default_port(Scheme::Unknown) == 0);
    CHECK(Url::default_port(Scheme::Http) == 80);

    // A parsed URL never carries Unknown.
    auto r = parse_url("https://example.com/");
    CHECK(r.has_value());
    if (r) CHECK(r.value().scheme != Scheme::Unknown);

    // A failed parse produces an Error, not a Url with an Unknown scheme, so
    // there is no state where scheme==Unknown escapes to a caller.
    CHECK(parse_url("nonsense://x").has_error());
}

TEST_CASE("error std bridge", "[core]") {
    // ErrorCode values live in the -400000 band, disjoint from everything else.
    CHECK(static_cast<int32_t>(ErrorCode::Unknown) < -399999);
    CHECK(static_cast<int32_t>(ErrorCode::SseEventTooLarge) > -499999);
    CHECK(static_cast<int32_t>(ErrorCode::Success) == 0);

    // code / phase / message survive construction.
    Error e{ErrorCode::HttpChunkError, ErrorPhase::Receive, string("bad chunk")};
    CHECK(e.code() == ErrorCode::HttpChunkError);
    CHECK(e.phase() == ErrorPhase::Receive);
    CHECK(!e.message().empty());
    CHECK(e);

    // std::error_code carries the code and our category.
    std::error_code ec = e;
    CHECK(ec.value() == static_cast<int>(ErrorCode::HttpChunkError));
    CHECK(ec.category() == megohttp_category());
    CHECK(std::strcmp(ec.category().name(), "megohttp") == 0);

    // The category names a code on demand, in std::string (its虚 interface).
    CHECK(ec.message() == std::string("HttpChunkError"));

    // std::error_condition comparison: same code matches, different does not.
    std::error_condition cond{static_cast<int>(ErrorCode::HttpChunkError),
                              megohttp_category()};
    CHECK(ec == cond);
    CHECK(e == cond);                       // via the implicit conversion

    Error other{ErrorCode::HttpTrailerError};
    std::error_code ec2 = other;
    CHECK(ec2 != cond);

    // make_error_code() and the category agree with the explicit form.
    CHECK(make_error_code(ErrorCode::HttpChunkError) == ec);

    // A foreign code maps to Unknown rather than lying about the band.
    CHECK(error_code_from_int(-100000) == ErrorCode::Unknown);
    CHECK(error_code_from_int(0) == ErrorCode::Success);

    // native_code is diagnostic-only and round-trips.
    e.set_native_code(42);
    CHECK(e.native_code() == 42);

    // describe() is never empty and includes the phase when present.
    CHECK(!e.describe().empty());
    Error no_phase{ErrorCode::Cancelled};
    CHECK(no_phase.phase() == ErrorPhase::None);
    CHECK(!no_phase.describe().empty());

    // The five WS-compression codes and the multipart codes stay distinct.
    CHECK(ErrorCode::WsCompressionNotCompiled != ErrorCode::WsCompressionMalformedData);
    CHECK(ErrorCode::MultipartTruncated != ErrorCode::MultipartDelimiterInvalid);
}

TEST_CASE("idna", "[core]") {
    // --- Punycode: RFC 3492 section 7.1 sample vectors -----------------------
    {
        auto r = punycode_encode("bücher");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "bcher-kva"));
    }
    {
        // 他们为什么不说中文 -> "ihqwcrb4cv8a8dqg056pqjye" (punycode, no prefix)
        auto r = punycode_encode("\xE4\xBB\x96\xE4\xBB\xAC\xE4\xB8\xBA"
                                 "\xE4\xBB\x80\xE4\xB9\x88\xE4\xB8\x8D\xE8\xAF\xB4"
                                 "\xE4\xB8\xAD\xE6\x96\x87");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "ihqwcrb4cv8a8dqg056pqjye"));
    }
    {
        // 3年B組金八先生 -> "3B-ww4c5e180e575a65lsy2b"
        auto r = punycode_encode("3\xE5\xB9\xB4" "B\xE7\xB5\x84"
                                 "\xE9\x87\x91\xE5\x85\xAB\xE5\x85\x88\xE7\x94\x9F");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "3B-ww4c5e180e575a65lsy2b"));
    }
    // Pure ASCII label: no encoding, no trailing '-'.
    {
        auto r = punycode_encode("hello");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "hello"));
    }
    CHECK(punycode_encode("").has_error());
    // Invalid UTF-8 must be rejected, not silently mangled.
    CHECK(punycode_encode("\xFF\xFE").has_error());
    CHECK(punycode_encode("\xE4\xB8").has_error());   // truncated 3-byte seq

    // --- idna_encode ---------------------------------------------------------
    // ASCII passes through.
    {
        auto r = idna_encode("example.com");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "example.com"));
    }
    // Already-encoded A-label is idempotent.
    {
        auto r = idna_encode("xn--fiq228c.com");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "xn--fiq228c.com"));
    }
    // 中文.com -> xn--fiq228c.com
    {
        auto r = idna_encode("\xE4\xB8\xAD\xE6\x96\x87.com");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "xn--fiq228c.com"));
    }
    // Mixed labels keep their ASCII parts.
    {
        auto r = idna_encode("www.b\xC3\xBC" "cher.example");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value(), "www.xn--bcher-kva.example"));
    }
    CHECK(idna_encode("").has_error());
    CHECK(idna_encode("a..b").has_error());          // empty label

    // --- NOT integrated into parse_url ---------------------------------------
    //
    // parse_url rejects a Unicode host instead of converting it: this encoder is
    // Punycode plus a SUBSET of IDNA2008, and task book 5.4.1 forbids relying on
    // an incomplete conversion. A caller that wants an IDN encodes first with a
    // conforming library and passes the A-label, which parses on the ASCII path.
    {
        auto r = parse_url("https://\xE4\xB8\xAD\xE6\x96\x87.com/path");
        CHECK_FALSE(r.has_value());
        CHECK(r.error().code() == ErrorCode::InvalidArgument);
    }
    // The pre-encoded form parses normally and keeps every field intact.
    {
        auto r = parse_url("https://xn--fiq228c.com/path");
        REQUIRE(r.has_value());
        CHECK(s_eq(r.value().host, "xn--fiq228c.com"));
        CHECK(r.value().port == 443);
        CHECK(s_eq(r.value().host_port_header(), "xn--fiq228c.com"));
        CHECK(s_eq(r.value().request_target(), "/path"));
        CHECK(!r.value().is_ip_literal);
    }
    {
        auto r = parse_url("http://www.xn--bcher-kva.example:8080/");
        REQUIRE(r.has_value());
        CHECK(s_eq(r.value().host, "www.xn--bcher-kva.example"));
        CHECK(r.value().port == 8080);
        CHECK(s_eq(r.value().host_port_header(), "www.xn--bcher-kva.example:8080"));
    }
    // And the encoder itself still works for a caller that asks for it directly.
    {
        auto e = idna_encode("www.b\xC3\xBC" "cher.example");
        REQUIRE(e.has_value());
        CHECK(s_eq(e.value(), "www.xn--bcher-kva.example"));
    }
    // ASCII hosts are untouched by the IDN path.
    {
        auto r = parse_url("http://example.com/");
        CHECK(r.has_value());
        if (r) CHECK(s_eq(r.value().host, "example.com"));
    }
    CHECK(is_ascii("example.com"));
    CHECK(!is_ascii("\xE4\xB8\xAD"));
}


// ---------------------------------------------------------------------------
// UTF-8 validation across every code point that accepts it.
//
// Every function that consumes UTF-8 is exercised with malformed input at the
// beginning, in the middle, and at the end of the string. This catches the
// classic off-by-one and "only check first byte" bugs.
// ---------------------------------------------------------------------------

TEST_CASE("punycode_encode rejects malformed UTF-8 at every position", "[idna]") {
    SECTION("invalid start byte") {
        CHECK(punycode_encode("\xFF\xFE").has_error());              // \xFF is never valid
    }
    SECTION("truncated 2-byte sequence (end)") {
        CHECK(punycode_encode("\xC2").has_error());                  // C2 expects continuation
    }
    SECTION("truncated 3-byte sequence (end)") {
        CHECK(punycode_encode("\xE4\xB8").has_error());
    }
    SECTION("truncated 4-byte sequence (end)") {
        CHECK(punycode_encode("\xF0\x9F\x98").has_error());
    }
    SECTION("bad continuation byte (middle)") {
        CHECK(punycode_encode("\xC2\xFF").has_error());              // \xFF is not a continuation byte
    }
    SECTION("bad continuation after valid prefix (middle)") {
        CHECK(punycode_encode("ab\xC2\xFF cd").has_error());
    }
    SECTION("bad continuation at end of otherwise valid label") {
        CHECK(punycode_encode("\xE4\xB8\xAD\xFF").has_error());      // 中 + invalid lead
    }
    SECTION("overlong encoding (2-byte form of U+002F)") {
        CHECK(punycode_encode("\xC0\xAF").has_error());
    }
    SECTION("surrogate half (U+D800)") {
        CHECK(punycode_encode("\xED\xA0\x80").has_error());
    }
    SECTION("mixed: valid prefix, bad tail") {
        CHECK(punycode_encode("\xE4\xB8\xAD\xE4\xB8").has_error());  // 中 + truncated
    }
    SECTION("empty string") {
        CHECK(punycode_encode("").has_error());
    }
    SECTION("pure ASCII is always accepted") {
        auto r = punycode_encode("hello");
        REQUIRE(r.has_value());
        REQUIRE(s_eq(r.value(), "hello"));
    }
}

TEST_CASE("idna_encode rejects malformed UTF-8 in each label", "[idna]") {
    SECTION("bad start byte") {
        CHECK(idna_encode("\xFF\xFE.com").has_error());
    }
    SECTION("truncated sequence at end of label") {
        CHECK(idna_encode("\xE4\xB8").has_error());
    }
    SECTION("bad continuation in middle of label") {
        CHECK(idna_encode("a\xC2\xFF b").has_error());
    }
    SECTION("empty string") {
        CHECK(idna_encode("").has_error());
    }
    SECTION("empty label (double dot)") {
        CHECK(idna_encode("a..b").has_error());
    }
    SECTION("valid multi-label passes through") {
        auto r = idna_encode("\xE4\xB8\xAD\xE6\x96\x87.example.com");
        REQUIRE(r.has_value());
        REQUIRE(s_eq(r.value(), "xn--fiq228c.example.com"));
    }
}

TEST_CASE("parse_url rejects malformed UTF-8 in host", "[url]") {
    SECTION("invalid lead byte") {
        CHECK(parse_url("http://\xFF\xFE.com/").has_error());
    }
    SECTION("truncated 3-byte at end") {
        CHECK(parse_url("http://\xE4\xB8.com/").has_error());
    }
    SECTION("bad continuation (middle)") {
        CHECK(parse_url("http://ab\xC2\xFF.cd/").has_error());
    }
    SECTION("valid + invalid tail") {
        CHECK(parse_url("http://\xE4\xB8\xAD\xFF.com/").has_error());  // 中 + \xFF
    }
    SECTION("valid UTF-8 is rejected, not converted") {
        // Well-formed UTF-8, but the parser does not convert it: see idna.hpp.
        auto r = parse_url("http://\xE4\xB8\xAD\xE6\x96\x87.com/");
        CHECK_FALSE(r.has_value());
    }
    SECTION("mixed label: valid then bad") {
        CHECK(parse_url("http://\xE4\xB8\xAD\xE4\xB8.com/").has_error());  // 中 + truncated
    }
}

TEST_CASE("parse_url: malformed UTF-8 in path is copied through (no validation)", "[url]") {
    // The path is stored as-is; it is not subject to UTF-8 validation.
    // The only requirement is that it must not contain control characters
    // (CR, LF, or unescaped spaces).
    auto r = parse_url("http://example.com/\xE4\xB8\xAD\xFF");
    REQUIRE(r.has_value());
    // The raw bytes survive: 中 + \xFF
    REQUIRE(r.value().path.size() >= 3);
}

TEST_CASE("parse_url: malformed UTF-8 in query is copied through (no validation)", "[url]") {
    auto r = parse_url("http://example.com/?\xE4\xB8\xAD\xFF");
    REQUIRE(r.has_value());
    REQUIRE(r.value().has_query);
    REQUIRE(r.value().query.size() >= 3);
}


TEST_CASE("is_valid_ascii_host follows the label grammar", "[url]") {
    SECTION("ordinary names") {
        CHECK(is_valid_ascii_host("example.com"));
        CHECK(is_valid_ascii_host("a"));
        CHECK(is_valid_ascii_host("a-b.c-d.e"));
        CHECK(is_valid_ascii_host("123.456"));
        CHECK(is_valid_ascii_host("xn--fiq228c.com"));
    }
    SECTION("label must not start or end with '-'") {
        CHECK(!is_valid_ascii_host("-example.com"));
        CHECK(!is_valid_ascii_host("example-.com"));
        CHECK(!is_valid_ascii_host("a.-b.c"));
        CHECK(!is_valid_ascii_host("a.b-.c"));
    }
    SECTION("empty labels are rejected") {
        CHECK(!is_valid_ascii_host(".a"));
        CHECK(!is_valid_ascii_host("a."));
        CHECK(!is_valid_ascii_host("a..b"));
        CHECK(!is_valid_ascii_host(""));
    }
    SECTION("length limits") {
        const std::string ok63(63, 'a');           // exactly 63: allowed
        CHECK(is_valid_ascii_host(ok63.c_str()));
        const std::string bad64(64, 'a');          // 64: rejected
        CHECK(!is_valid_ascii_host(bad64.c_str()));
        // Total length: 253 allowed, 254 rejected.
        std::string s253;
        while (s253.size() + 63 + 1 <= 253) { s253.append(63, 'a'); s253.push_back('.'); }
        if (s253.size() < 253) s253.append(253 - s253.size(), 'a');
        CHECK(s253.size() == 253);
        CHECK(is_valid_ascii_host(s253.c_str()));
        std::string s254 = s253;
        s254.push_back('b');
        CHECK(s254.size() == 254);
        CHECK(!is_valid_ascii_host(s254.c_str()));
    }
    SECTION("only alnum, hyphen and dot are allowed") {
        CHECK(!is_valid_ascii_host("exa mple.com"));    // space
        CHECK(!is_valid_ascii_host("example_com"));     // underscore
        CHECK(!is_valid_ascii_host("example!.com"));    // punctuation
        CHECK(!is_valid_ascii_host("exam\tple.com"));   // tab
        // NUL byte inside the view: construct the view with an explicit length.
        CHECK(!is_valid_ascii_host(string_view("a\0b", 3)));
        CHECK(!is_valid_ascii_host("\xE4\xB8\xAD.com")); // non-ASCII
    }
    SECTION("trailing dot is rejected") {
        CHECK(!is_valid_ascii_host("example.com."));
        CHECK(!is_valid_ascii_host("a."));
    }
}
