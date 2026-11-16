#!/usr/bin/env python3
"""Two-layer TLS server that tolerates the client layering a TLS stream over a
TLS stream, without relying on Python's ssl module nesting sockets.

Why the relay shape: ssl.SSLContext.wrap_socket refuses to wrap an SSL socket in
another SSL socket (probe_nested_tls.py shows UNEXPECTED_MESSAGE). A CONNECT
tunnel does exactly what the C++ test needs, though -- it relays the inner TLS
record stream as opaque bytes. So this server terminates the outer TLS, then
opens a *separate* TCP connection to a second TLS listener and splices the two.

From the client's point of view: one byte stream, two handshakes, one payload.

Prints "READY <pid> <outer_port> <inner_port>".
"""
import argparse
import os
import socket
import ssl
import sys
import threading


def server_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cert")
    ap.add_argument("key")
    args = ap.parse_args()

    outer_ctx = server_ctx(args.cert, args.key)
    inner_ctx = server_ctx(args.cert, args.key)

    inner_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    inner_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    inner_srv.bind(("127.0.0.1", 0))
    inner_srv.listen(8)
    inner_port = inner_srv.getsockname()[1]

    outer_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outer_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    outer_srv.bind(("127.0.0.1", 0))
    outer_srv.listen(8)
    outer_port = outer_srv.getsockname()[1]

    print("READY", os.getpid(), outer_port, inner_port, flush=True)

    def serve_inner(conn):
        try:
            tls = inner_ctx.wrap_socket(conn, server_side=True)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            return
        try:
            while True:
                data = tls.recv(16384)
                if not data:
                    break
                tls.sendall(b"inner:" + data)
        except Exception:
            pass
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def inner_loop():
        while True:
            try:
                conn, _ = inner_srv.accept()
            except OSError:
                return
            threading.Thread(target=serve_inner, args=(conn,), daemon=True).start()

    threading.Thread(target=inner_loop, daemon=True).start()

    def pump(src, dst, tag=""):
        try:
            while True:
                data = src.recv(16384)
                if not data:
                    break
                if tag:
                    print(f"{tag}: {len(data)} bytes", flush=True)
                dst.sendall(data)
        except Exception as e:
            if tag:
                print(f"{tag} error: {type(e).__name__} {e}", flush=True)

    def relay(outer_tls):
        try:
            up = socket.create_connection(("127.0.0.1", inner_port), timeout=10)
        except Exception:
            try:
                outer_tls.close()
            except Exception:
                pass
            return

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(16384)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass

        threading.Thread(target=pump, args=(outer_tls, up), daemon=True).start()
        pump(up, outer_tls)

    while True:
        try:
            conn, _ = outer_srv.accept()
        except OSError:
            return
        try:
            outer_tls = outer_ctx.wrap_socket(conn, server_side=True)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=relay, args=(outer_tls,), daemon=True).start()


if __name__ == "__main__":
    main()
