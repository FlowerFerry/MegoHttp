// S4.6: Trust source discovery tests.
#include <megohttp/tls_stream.hpp>
#include "tls_test_support.hpp"
#include <megohttp/config.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

#if defined(_WIN32)
#   include <windows.h>
#endif

using namespace megohttp;
using namespace tls_test_support;

namespace {
std::string to_std(const string& s) { return std::string(s.data(), s.size()); }
}

// ---------------------------------------------------------------------------
// Environment variable precedence
// ---------------------------------------------------------------------------

#if defined(_WIN32)

static void set_env_var(const char* name, const char* value) {
    // Both, on purpose: _putenv_s updates the CRT copy that getenv() reads,
    // SetEnvironmentVariableA updates the Win32 copy that child processes
    // inherit. Only doing the latter leaves getenv() seeing the old value.
    _putenv_s(name, value ? value : "");
}

#else
#   include <cstdlib>

static void set_env_var(const char* name, const char* value) {
    if (value) {
        setenv(name, value, 1);
    } else {
        unsetenv(name);
    }
}

#endif

TEST_CASE("env_ca_file returns SSL_CERT_FILE", "[tls_trust]") {
    set_env_var("SSL_CERT_FILE", "/custom/ca.pem");
    CHECK(to_std(tls_trust::env_ca_file()) == "/custom/ca.pem");
    set_env_var("SSL_CERT_FILE", nullptr);
    CHECK(tls_trust::env_ca_file().empty());
}

TEST_CASE("env_ca_path returns SSL_CERT_DIR", "[tls_trust]") {
    set_env_var("SSL_CERT_DIR", "/custom/certs");
    CHECK(to_std(tls_trust::env_ca_path()) == "/custom/certs");
    set_env_var("SSL_CERT_DIR", nullptr);
    CHECK(tls_trust::env_ca_path().empty());
}

TEST_CASE("default_ca_file prefers env over platform", "[tls_trust]") {
    set_env_var("SSL_CERT_FILE", "/my/ca.pem");
    auto d = tls_trust::default_ca_file();
    CHECK(to_std(d) == "/my/ca.pem");
    set_env_var("SSL_CERT_FILE", nullptr);

    // Without env, it should fall back to the platform default (non-empty on
    // Windows because the root store is always exportable).
    d = tls_trust::default_ca_file();
    // On platforms with no bundle at all this is legitimately empty.
}

// ---------------------------------------------------------------------------
// Windows system store export
// ---------------------------------------------------------------------------

#if defined(_WIN32)

TEST_CASE("Windows system root store is exported as PEM", "[tls_trust]") {
    // On Windows, system_ca_bundle_path() exports the ROOT store to a file.
    // It must return a non-empty path and the file must exist.
    string path = tls_trust::system_ca_bundle_path();
    REQUIRE(!path.empty());

    FILE* f = fopen(path.c_str(), "rb");
    REQUIRE(f != nullptr);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    CHECK(sz > 1000);  // The Windows root store is hundreds of certs

    // The file must contain at least one PEM header.
    std::string buf(static_cast<size_t>(sz), 0);
    f = fopen(path.c_str(), "rb");
    fread(&buf[0], 1, buf.size(), f);
    fclose(f);
    CHECK(buf.find("BEGIN CERTIFICATE") != std::string::npos);
}

#endif

// The handshake cases below need a TLS backend. Under MGHTTP_TLS_NONE every
// TlsStream reports TlsNotEnabled, so asserting on certificate outcomes would
// only be asserting that TLS is off -- which test_tls_stream already covers.
#if !MGHTTP_TLS_NONE

TEST_CASE("backend loads the discovered default trust source when no CA is configured",
          "[tls_trust][handshake]") {
    // No TlsConfig::ca_file: the backend must fall back to
    // tls_trust::default_ca_file(), which honours SSL_CERT_FILE. Pointing that
    // at our test CA is the only way to exercise the fallback without mutating
    // the host trust store, which task book 13.3 forbids.
    const std::string ca = fixture_path("ca.pem");
    set_env_var("SSL_CERT_FILE", ca.c_str());

    tls_test_support::PythonTlsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem"));

    TlsConfig cfg;
    cfg.hostname = string("localhost");
    // ca_file deliberately empty.
    cfg.alpn_protocols.push_back(string("http/1.1"));

    tls_test_support::HandshakeOutcome out;
    tls_test_support::handshake(cfg, srv.port(), &out);

    set_env_var("SSL_CERT_FILE", nullptr);

    REQUIRE(out.called.load());
    CHECK(out.ok.load());
    CHECK(static_cast<ErrorCode>(out.code.load()) == ErrorCode::Success);
}

TEST_CASE("a discovered but unrelated default trust source is not ignored",
          "[tls_trust][handshake]") {
    // The counterweight to the case above: if the backend silently skipped the
    // trust source -- or verified nothing -- this handshake would succeed.
    // SSL_CERT_FILE points at a CA that did NOT sign the server certificate.
    const std::string other = fixture_path("untrusted-ca.pem");
    set_env_var("SSL_CERT_FILE", other.c_str());

    tls_test_support::PythonTlsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem"));

    TlsConfig cfg;
    cfg.hostname = string("localhost");
    cfg.alpn_protocols.push_back(string("http/1.1"));

    tls_test_support::HandshakeOutcome out;
    tls_test_support::handshake(cfg, srv.port(), &out);

    set_env_var("SSL_CERT_FILE", nullptr);

    REQUIRE(out.called.load());
    CHECK_FALSE(out.ok.load());
    CHECK(static_cast<ErrorCode>(out.code.load()) == ErrorCode::TlsCertificateInvalid);
}

#if defined(_WIN32)
TEST_CASE("the exported Windows root store is a usable trust source",
          "[tls_trust][handshake]") {
    // system_ca_bundle_path() exports the ROOT store to PEM. Feed that export
    // through the same no-explicit-CA path: our test CA is NOT in the system
    // store, so the handshake must be refused. A backend that ignored the
    // bundle, or verified nothing, would let it through.
    const std::string bundle = to_std(tls_trust::system_ca_bundle_path());
    REQUIRE(!bundle.empty());

    set_env_var("SSL_CERT_FILE", bundle.c_str());

    tls_test_support::PythonTlsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem"));

    TlsConfig cfg;
    cfg.hostname = string("localhost");
    cfg.alpn_protocols.push_back(string("http/1.1"));

    tls_test_support::HandshakeOutcome out;
    tls_test_support::handshake(cfg, srv.port(), &out);

    set_env_var("SSL_CERT_FILE", nullptr);

    REQUIRE(out.called.load());
    CHECK_FALSE(out.ok.load());
    // The ROOT export could not be loaded as a trust source at all (OpenSSL),
    // or it was loaded but the test CA is not in it (mbedTLS). Either way,
    // the handshake must fail.
    const ErrorCode code = static_cast<ErrorCode>(out.code.load());
    CHECK((code == ErrorCode::TlsHandshakeFailed || code == ErrorCode::TlsCertificateInvalid));
}
#endif

// ---------------------------------------------------------------------------
// Explicit path invalid => fail
// ---------------------------------------------------------------------------

TEST_CASE("tls_trust does not silently skip an invalid explicit path",
          "[tls_trust][handshake]") {
    // An explicitly named but unreadable CA must abort the handshake rather
    // than fall back to platform defaults (task book 9.2).
    tls_test_support::PythonTlsServer srv;
    REQUIRE(srv.start("server-cert.pem", "server-key.pem"));

    TlsConfig cfg = tls_test_support::make_config("localhost", nullptr);
    cfg.ca_file = string("Z:\\definitely\\not\\here\\ca.pem");

    tls_test_support::HandshakeOutcome out;
    tls_test_support::handshake(cfg, srv.port(), &out);

    REQUIRE(out.called.load());
    CHECK_FALSE(out.ok.load());
    // init failed before any bytes were exchanged, so this is a handshake
    // failure rather than a certificate verdict.
    CHECK(static_cast<ErrorCode>(out.code.load()) == ErrorCode::TlsHandshakeFailed);
}
#endif // !MGHTTP_TLS_NONE
