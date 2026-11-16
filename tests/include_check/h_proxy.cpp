#include <megohttp/proxy.hpp>

// Independent include check: this translation unit includes nothing but the
// public header, so a missing include or a circular dependency shows up as a
// compile failure here instead of in whichever file happened to include it
// first (task book 13.6).

int main() {
    megohttp::ProxyOptions opts;
    (void)opts.proxy.is_set();
    (void)megohttp::proxy_detail::is_forward_proxy(megohttp::ProxyType::Http);
    (void)megohttp::proxy_detail::uses_proxy_tls(megohttp::ProxyType::Https);
    (void)megohttp::proxy_detail::socks5::kVersion;
    return 0;
}
