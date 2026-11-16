#!/usr/bin/env python3
"""Generate the TLS test fixtures: a local CA, a server certificate, and a
second CA that must NOT be trusted.

The tests never touch the host trust store (task book 13.3 forbids it): every
certificate the tests need is created here, in a scratch directory, and named
explicitly in the TlsConfig.

Usage:  python gen_tls_fixtures.py <out_dir>
"""
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca(cn, not_before, not_after, issuer_key=None, issuer_cert=None):
    """Create a CA certificate. When issuer_key/issuer_cert are given the result
    is an INTERMEDIATE CA signed by that issuer; otherwise it is self-signed."""
    key = make_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    signer_key = issuer_key if issuer_key is not None else key
    signer_name = issuer_cert.subject if issuer_cert is not None else name
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(signer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(signer_key, hashes.SHA256())
    )
    return key, cert


def make_server_cert(ca_key, ca_cert, cn, san_dns, not_before, not_after):
    key = make_key()
    san = [x509.DNSName(d) for d in san_dns]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "tls_fixtures"
    os.makedirs(out, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    day = datetime.timedelta(days=1)

    # --- Trusted CA and a server certificate it signed -----------------------
    ca_key, ca_cert = make_ca("MegoHttp Test CA", now - day, now + 365 * day)
    srv_key, srv_cert = make_server_cert(
        ca_key, ca_cert, "localhost", ["localhost", "example.test"],
        now - day, now + 30 * day,
    )

    # Certificate that expired yesterday: must fail with TlsCertificateExpired.
    exp_key, exp_cert = make_server_cert(
        ca_key, ca_cert, "localhost", ["localhost"],
        now - 10 * day, now - day,
    )

    # Certificate for a DIFFERENT name: must fail with TlsHostnameMismatch when
    # the client asks for localhost.
    other_key, other_cert = make_server_cert(
        ca_key, ca_cert, "wrong.example", ["wrong.example"],
        now - day, now + 30 * day,
    )

    # --- A second, untrusted CA ---------------------------------------------
    bad_key, bad_cert = make_ca("MegoHttp Untrusted CA", now - day, now + 365 * day)
    bad_srv_key, bad_srv_cert = make_server_cert(
        bad_key, bad_cert, "localhost", ["localhost"], now - day, now + 30 * day
    )

    pem = serialization.Encoding.PEM
    key_pem = serialization.PrivateFormat.TraditionalOpenSSL
    no_crypt = serialization.NoEncryption()

    def dump(name, key, cert):
        write(os.path.join(out, name + "-key.pem"),
              key.private_bytes(pem, key_pem, no_crypt))
        write(os.path.join(out, name + "-cert.pem"), cert.public_bytes(pem))

    write(os.path.join(out, "ca.pem"), ca_cert.public_bytes(pem))
    write(os.path.join(out, "untrusted-ca.pem"), bad_cert.public_bytes(pem))

    # --- Intermediate CA chain (root → intermediate → server) ---------------
    int_key, int_cert = make_ca(
        "MegoHttp Intermediate CA", now - day, now + 365 * day,
        issuer_key=ca_key, issuer_cert=ca_cert,
    )
    srv_int_key, srv_int_cert = make_server_cert(
        int_key, int_cert, "localhost", ["localhost"],
        now - day, now + 30 * day,
    )
    # intermediate-ca-chain.pem = intermediate cert + root cert (for the client
    # to trust). The SERVER sends a different file: its own cert + intermediate.
    write(os.path.join(out, "intermediate-ca.pem"), int_cert.public_bytes(pem))
    write(os.path.join(out, "intermediate-ca-chain.pem"),
          int_cert.public_bytes(pem) + ca_cert.public_bytes(pem))
    # Chain the server must present: leaf first, then the intermediate. Sending
    # only the leaf would leave the client unable to build a path to the root.
    write(os.path.join(out, "intermediate-server-fullchain.pem"),
          srv_int_cert.public_bytes(pem) + int_cert.public_bytes(pem))
    dump("intermediate-server", srv_int_key, srv_int_cert)

    dump("server", srv_key, srv_cert)
    dump("expired", exp_key, exp_cert)
    dump("wrongname", other_key, other_cert)
    dump("untrusted", bad_srv_key, bad_srv_cert)

    print("wrote TLS fixtures to", os.path.abspath(out))


if __name__ == "__main__":
    main()
