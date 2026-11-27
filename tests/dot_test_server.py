#!/usr/bin/env python3
"""Local DoT server for the Client integration test.

Opens a TCP socket on a dynamic port, wraps it in TLS, and answers DNS queries
in wire format.  Prints "READY <pid> <port>" once bound so the test learns the
port and can kill the process afterwards.
"""
import argparse
import os
import socket
import ssl
import struct
import threading

import parent_watchdog


def read_name(buf, off):
    """Return (end_offset,) for a wire name at `off`."""
    labels = 0
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            return off + 1
        off += 1 + ln
        labels += 1
        if labels > 128:
            raise ValueError("name too long")
    raise ValueError("truncated name")


def build_reply(query, rcode=None, answer_ip="192.0.2.1", ttl=60):
    """Echo the question and, for an A query, add one A record."""
    if len(query) < 12:
        raise ValueError("short query")

    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", query[:12])
    if qd < 1:
        raise ValueError("no question")

    after_name = read_name(query, 12)
    if after_name + 4 > len(query):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", query[after_name:after_name + 4])
    question = query[12:after_name + 4]

    if rcode is not None:
        flags_out = 0x8000 | 0x0100 | 0x0080 | (rcode & 0x000F)
        return struct.pack("!HHHHHH", qid, flags_out, 1, 0, 0, 0) + question

    flags_out = 0x8000 | 0x0100 | 0x0080
    if qtype == 1:
        rdata = bytes(int(x) for x in answer_ip.split("."))
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, len(rdata)) + rdata
        return struct.pack("!HHHHHH", qid, flags_out, 1, 1, 0, 0) + question + answer
    return struct.pack("!HHHHHH", qid, flags_out, 1, 0, 0, 0) + question


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--rcode", type=int, default=None,
                    help="Force a specific RCODE (3 = NXDOMAIN)")
    ap.add_argument("--ttl", type=int, default=60,
                    help="TTL in the answer record (0 = do not cache)")
    ap.add_argument("--count-file", default=None,
                    help="Write the number of queries received to this file")
    parent_watchdog.add_argument(ap)
    args = ap.parse_args()

    parent_watchdog.start(args.parent_pid)

    # Shared across connections so the counter reflects the whole server, which
    # is what a cache test needs: a second lookup that hits the cache must not
    # increase this number.
    query_count = [0]
    count_lock = threading.Lock()

    def bump_and_write():
        with count_lock:
            query_count[0] += 1
            value = query_count[0]
        if args.count_file:
            try:
                with open(args.count_file, "w") as f:
                    f.write(str(value))
            except OSError:
                pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    print("READY", os.getpid(), port, flush=True)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    # DoT uses its own ALPN; no HTTP/1.1 here.

    def handle(conn):
        try:
            while True:
                header = b""
                while len(header) < 2:
                    chunk = conn.recv(2 - len(header))
                    if not chunk:
                        return
                    header += chunk
                length = struct.unpack("!H", header)[0]
                wire = b""
                while len(wire) < length:
                    chunk = conn.recv(length - len(wire))
                    if not chunk:
                        return
                    wire += chunk

                reply = build_reply(wire, rcode=args.rcode, ttl=args.ttl)
                framed = struct.pack("!H", len(reply)) + reply
                conn.sendall(framed)
                bump_and_write()
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    while True:
        conn, _ = srv.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except Exception:
            conn.close()
            continue
        threading.Thread(target=handle, args=(tls,), daemon=True).start()

if __name__ == "__main__":
    main()
