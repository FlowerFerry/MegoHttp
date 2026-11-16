#include <megohttp/cookie.hpp>

// Independent include check: this translation unit includes nothing but the
// public header, so a missing include or a circular dependency shows up as a
// compile failure here instead of in whichever file happened to include it
// first (task book 13.6).

int main() {
    megohttp::CookieJar jar;
    (void)jar.size();
    (void)megohttp::cookie_detail::is_public_suffix(megohttp::string_view("co.uk"));
    (void)megohttp::cookie_detail::domain_matches(megohttp::string_view("a.example.com"),
                                                  megohttp::string_view("example.com"));
    (void)megohttp::cookie_detail::path_matches(megohttp::string_view("/a/b"),
                                                megohttp::string_view("/a"));
    auto c = megohttp::parse_set_cookie(megohttp::string_view("a=1; Path=/"));
    (void)c;
    auto p = megohttp::make_cookie_jar();
    (void)p;
    return 0;
}
