// Independent-include check for <megohttp/dns_cache.hpp>.
#include <megohttp/dns_cache.hpp>

static_assert(sizeof(megohttp::DnsCacheOptions) > 0,
              "DnsCacheOptions must be complete");
static_assert(sizeof(megohttp::DnsCache) > 0, "DnsCache must be complete");

int main() { return 0; }
