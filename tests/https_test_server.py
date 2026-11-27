#!/usr/bin/env python3
"""Local HTTPS server for the Client integration test.

Serves HTTP/1.1 over TLS with a certificate from tests/tls_fixtures. Replies to
every request with a fixed 200 + a known body, so the test can assert on content
rather than just on the handshake.

Prints "READY <pid> <port>" once bound, so the test learns a dynamic port and
can terminate the process by PID.
"""
import argparse
import os
import socket
import ssl
import sys
import threading
import time

import parent_watchdog


BODY = b"hello over https"


def multipart_body(boundary: bytes, parts):
    """Assemble a multipart body from (headers_bytes, payload) pairs."""
    out = b""
    for i, (hdrs, payload) in enumerate(parts):
        out += b"--" + boundary + b"\r\n"
        out += hdrs
        out += b"\r\n\r\n"          # blank line: end of the part's header block
        out += payload
        out += b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cert")
    ap.add_argument("key")
    parent_watchdog.add_argument(ap)
    ap.add_argument(
        "--handshake-delay",
        type=float,
        default=0.0,
        help="seconds to sleep before starting the TLS handshake",
    )
    ap.add_argument(
        "--multipart",
        action="store_true",
        help="answer with a multipart/mixed body instead of plain text",
    )
    ap.add_argument(
        "--multipart-truncated",
        action="store_true",
        help="send a multipart body that stops after one part (no closing boundary)",
    )
    args = ap.parse_args()

    parent_watchdog.start(args.parent_pid)

    boundary = b"megohttp-boundary-42"
    mp_text = multipart_body(boundary, [
        (b'Content-Type: text/plain\r\nContent-Disposition: form-data; name="a"',
         b"part-one"),
        (b'Content-Type: application/octet-stream\r\nContent-Disposition: form-data; name="b"',
         b"part-two"),
    ])
    if args.multipart_truncated:
        # One part, then stop: the closing delimiter never arrives.
        mp_text = (b"--" + boundary + b"\r\n"
                   b'Content-Type: text/plain\r\nContent-Disposition: form-data; name="a"'
                   b"\r\n\r\npart-one\r\n")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    ctx.set_alpn_protocols(["http/1.1"])

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    print("READY", os.getpid(), port, flush=True)

    def serve(conn):
        try:
            buf = b""
            # Read until the request head is complete; no body is expected.
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk

            if args.multipart or args.multipart_truncated:
                ctype = b'multipart/mixed; boundary="' + boundary + b'"'
                body = mp_text
            else:
                ctype = b"text/plain"
                body = BODY

            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: " + ctype + b"\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n" + body
            )
            conn.sendall(resp)
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
            if args.handshake_delay > 0:
                # Stall before touching TLS so a client-side handshake timeout
                # has something to time out on.
                time.sleep(args.handshake_delay)
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, ConnectionError, OSError):
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
