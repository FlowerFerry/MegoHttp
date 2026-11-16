#!/usr/bin/env python3
"""Local TLS echo server for the MegoHttp TLS tests.

Speaks TLS with a certificate from tests/tls_fixtures, prints the port it bound
to on stdout as "PORT <n>", and echoes every byte back. The test harness reads
that line to learn the port, so there is no fixed port and no sleep-based
readiness check (task book 13 requires dynamic ports plus an explicit ready
signal).

Usage:  python tls_test_server.py <cert.pem> <key.pem> [--alpn http/1.1]

Prints "READY <pid> <port>" once the socket is bound.
"""
import argparse
import os
import socket
import ssl
import sys
import threading


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cert")
    ap.add_argument("key")
    ap.add_argument("--alpn", default="http/1.1")
    ap.add_argument(
        "--max-version",
        choices=["tls1.2", "tls1.3"],
        default=None,
        help="cap the negotiated protocol (used to prove a client-side "
             "minimum-version floor is actually enforced)",
    )
    ap.add_argument(
        "--require-sni",
        metavar="NAME",
        default=None,
        help="abort the handshake unless the client offers this server_name",
    )
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if args.max_version == "tls1.2":
        # Cap the server so a client that insists on TLS 1.3 has nothing to
        # negotiate. The client-side floor is what the test is checking, so the
        # server must be the one that cannot go higher.
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    if args.alpn:
        ctx.set_alpn_protocols([p for p in args.alpn.split(",") if p])

    if args.require_sni:
        # Reject the handshake unless the client offered exactly this
        # server_name. Without this check a client that never sends SNI still
        # handshakes fine against a single-certificate server, so a test could
        # not tell the difference.
        #
        # Python's sni_callback cannot "abort" by returning a value: returning
        # None means "continue with the current context". Raising is the only
        # way to refuse, which surfaces to the client as a TLS alert.
        expected = args.require_sni

        def sni_callback(_sslobj, server_name, _ctx):
            if server_name != expected:
                raise ssl.SSLError(f"SNI {server_name!r} rejected")
            return None

        ctx.sni_callback = sni_callback

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    # Emit the PID as well so the test harness can terminate us precisely
    # instead of waiting for this accept loop to end on its own.
    print("READY", os.getpid(), port, flush=True)

    def serve(conn):
        try:
            while True:
                data = conn.recv(16384)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    try:
        while True:
            conn, _ = srv.accept()
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, ConnectionError, OSError):
                # Handshake failure: the client refused our certificate, or the
                # SNI callback rejected the offered name. Keep serving; the test
                # asserts on the client side.
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            threading.Thread(target=serve, args=(tls,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
