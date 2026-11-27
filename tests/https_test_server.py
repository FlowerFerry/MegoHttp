#!/usr/bin/env python3
"""Local HTTPS server for the Client integration test.

Serves HTTP/1.1 over TLS with a certificate from tests/tls_fixtures. Replies to
every request with a fixed 200 + a known body, so the test can assert on content
rather than just on the handshake.

Prints "READY <pid> <port>" once bound, so the test learns a dynamic port and
can terminate the process by PID.
"""
import argparse
import gzip
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
    ap.add_argument(
        "--part-bytes",
        type=int,
        default=0,
        help="with --multipart: emit ONE part of this many 'x' bytes "
             "(gives the client a body that spans many reads)",
    )
    ap.add_argument(
        "--pace-chunk",
        type=int,
        default=0,
        help="send the response in chunks of this many bytes (0 = one sendall)",
    )
    ap.add_argument(
        "--pace-delay",
        type=float,
        default=0.0,
        help="seconds to sleep between paced chunks",
    )
    ap.add_argument(
        "--gzip",
        action="store_true",
        help="compress the body and advertise Content-Encoding: gzip",
    )
    ap.add_argument(
        "--byteranges",
        action="store_true",
        help="answer with multipart/byteranges, parts NOT in ascending order",
    )
    ap.add_argument(
        "--continuous",
        action="store_true",
        help="answer with multipart/x-mixed-replace and no closing delimiter, "
             "close-delimited so EOF ends the stream",
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
    if args.part_bytes > 0:
        # One big part, so a pausing sink has somewhere to pause and the body
        # spans many TLS records / reads.
        mp_text = multipart_body(boundary, [
            (b'Content-Type: application/octet-stream\r\n'
             b'Content-Disposition: form-data; name="big"',
             b"x" * args.part_bytes),
        ])
    if args.multipart_truncated:
        # One part, then stop: the closing delimiter never arrives.
        mp_text = (b"--" + boundary + b"\r\n"
                   b'Content-Type: text/plain\r\nContent-Disposition: form-data; name="a"'
                   b"\r\n\r\npart-one\r\n")
    if args.byteranges:
        # Two ranges of a 100-byte resource, deliberately NOT in ascending order:
        # the parser must not assume the parts follow the request's Range order.
        mp_text = multipart_body(boundary, [
            (b"Content-Type: application/octet-stream\r\n"
             b"Content-Range: bytes 95-99/100", b"BBBBB"),
            (b"Content-Type: application/octet-stream\r\n"
             b"Content-Range: bytes 0-4/100", b"AAAAA"),
        ])
    if args.continuous:
        # No closing delimiter: this stream only ends when the connection does.
        mp_text = (b"--" + boundary + b"\r\n"
                   b"Content-Type: text/plain\r\n\r\ntick-1\r\n"
                   b"--" + boundary + b"\r\n"
                   b"Content-Type: text/plain\r\n\r\ntick-2\r\n")

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

            if args.byteranges:
                ctype = b'multipart/byteranges; boundary="' + boundary + b'"'
                body = mp_text
                close_delimited = False
            elif args.continuous:
                ctype = b'multipart/x-mixed-replace; boundary="' + boundary + b'"'
                body = mp_text
                close_delimited = True
            elif args.multipart or args.multipart_truncated:
                ctype = b'multipart/mixed; boundary="' + boundary + b'"'
                body = mp_text
                close_delimited = False
            else:
                ctype = b"text/plain"
                body = BODY
                close_delimited = False

            extra = b""
            if args.gzip:
                body = gzip.compress(body)
                extra = b"Content-Encoding: gzip\r\n"

            resp = b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype + b"\r\n" + extra
            if close_delimited:
                resp += b"Connection: close\r\n"
            else:
                resp += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                resp += b"Connection: keep-alive\r\n"
            resp += b"\r\n" + body
            if args.pace_chunk > 0:
                # Paced delivery: gives the client a real pause point and a body
                # it cannot finish in one read, which backpressure and
                # cancellation both need.
                for i in range(0, len(resp), args.pace_chunk):
                    conn.sendall(resp[i:i + args.pace_chunk])
                    if args.pace_delay > 0:
                        time.sleep(args.pace_delay)
            else:
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
