// Independent-include check for <megohttp/dns_wire.hpp>.
#include <megohttp/dns_wire.hpp>

int main() {
    // The codec must be usable from this TU alone.
    auto q = megohttp::dns::build_query(1, "example.com",
                                        megohttp::dns::RecordType::A);
    return q ? 0 : 1;
}
