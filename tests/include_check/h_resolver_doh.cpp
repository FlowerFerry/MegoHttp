// Independent-include check for <megohttp/resolver_doh.hpp>.
//
// The header defines nothing when the feature is compiled out, which is exactly
// what it must do in that configuration: this TU has to compile either way.
#include <megohttp/resolver_doh.hpp>

#if MEGOHTTP_HAS_DOH
// Naming the type proves the header is self-sufficient.
static_assert(sizeof(megohttp::DohOptions) > 0, "DohOptions must be complete");
#endif

int main() { return 0; }
