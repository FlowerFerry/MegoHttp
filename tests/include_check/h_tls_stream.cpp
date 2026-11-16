// Independent-include check for tls_stream.hpp (task book 13.6).
#include <megohttp/tls_stream.hpp>

int main() {
    megohttp::TlsConfig cfg;
    (void)cfg.hostname;
    return 0;
}
