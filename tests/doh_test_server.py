#!/usr/bin/env python3
"""Local DoH test server (RFC 8484), stdlib only.

Serves HTTPS on a dynamic port and answers DNS queries carried in
application/dns-message requests. Both request forms are supported:

  POST /dns-query        -- DNS wire message in the body
  GET  /dns-query?dns=.. -- base64url message, no padding

The server builds answers itself (it does not link a DNS library), so it shares
no parser with the C++ side. Only A and AAAA records are produced.

Startup protocol: prints "READY <pid> <port>" on stdout, then serves until
killed. Certificates come from the same fixtures as the other TLS servers.
"""

import argparse
import base64
import os
import socket
import ssl
import struct
import sys
import threading
import time

RECORD_A = 1
RECORD_AAAA = 28

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

# Names this server knows about, mapping to addresses.
ANSWERS = {
    "dual.example": {
        RECORD_A: ["192.0.2.1", "192.0.2.2"],
        RECORD_AAAA: ["2001:db8::1"],
    },
    "a-only.example": {
        RECORD_A: ["198.51.100.7"],
    },
    "aaaa-only.example": {
        RECORD_AAAA: ["2001:db8::beef"],
    },
    # Present in the map but with no address records -> NOERROR/NODATA.
    "nodata.example": {},
}

# Names that exist only as a CNAME hop.
CNAMES = {
    "alias.example": "dual.example",
}


def decode_name(msg, offset):
    """Decode a possibly compressed DNS name. Returns (name, new_offset)."""
    labels = []
    hops = 0
    jumped = False
    end_offset = offset
    while True:
        if offset >= len(msg):
            raise ValueError("name runs past the end of the message")
        length = msg[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            hops += 1
            if hops > 16:
                raise ValueError("compression pointer loop")
            # Pointers must go strictly backwards.
            if pointer >= offset:
                raise ValueError("forward compression pointer")
            offset = pointer
            continue
        if length > 63:
            raise ValueError("label too long")
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii"))
        offset += 1 + length
    return ".".join(labels), end_offset


def encode_name(name):
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        raw = label.encode("ascii")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def encode_ipv4(text):
    return socket.inet_pton(socket.AF_INET, text)


def encode_ipv6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def build_response(query, force_rcode=None, truncate=False, ttl=60):
    """Build a DNS response for a single-question query."""
    if len(query) < 12:
        raise ValueError("query too short")

    msg_id = struct.unpack("!H", query[0:2])[0]
    name, offset = decode_name(query, 12)
    if offset + 4 > len(query):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", query[offset:offset + 4])
    question = query[12:offset + 4]

    lower = name.lower()
    rcode = RCODE_NOERROR
    answers = []
    cname_target = None

    if force_rcode is not None:
        rcode = force_rcode
    elif lower in CNAMES:
        cname_target = CNAMES[lower]
        # The CNAME record's OWNER is the queried name; its RDATA is the target.
        answers.append((lower, 5, ttl, encode_name(cname_target)))
        records = ANSWERS.get(cname_target, {})
        for text in records.get(qtype, []):
            answers.append((cname_target, qtype, ttl, encode_address(qtype, text)))
    elif lower in ANSWERS:
        records = ANSWERS[lower]
        for text in records.get(qtype, []):
            answers.append((lower, qtype, ttl, encode_address(qtype, text)))
    else:
        rcode = RCODE_NXDOMAIN

    flags = 0x8180  # QR, RD, RA, NOERROR
    flags = (flags & 0xFFF0) | (rcode & 0x000F)
    if truncate:
        flags |= 0x0200  # TC

    header = struct.pack("!HHHHHH", msg_id, flags, 1,
                         0 if truncate else len(answers), 0, 0)

    body = bytearray(header)
    body += question
    if not truncate:
        for owner, rtype, ttl, rdata in answers:
            body += encode_name(owner)
            body += struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
            body += rdata

    return bytes(body)


def encode_address(qtype, text):
    if qtype == RECORD_A:
        return encode_ipv4(text)
    if qtype == RECORD_AAAA:
        return encode_ipv6(text)
    raise ValueError("unsupported record type")


def b64url_decode(text):
    """Decode base64url without padding."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class DohHandler:
    def __init__(self, sock, certfile, keyfile, behaviour, ttl=60, on_answered=None):
        self.sock = sock
        self.certfile = certfile
        self.keyfile = keyfile
        self.behaviour = behaviour
        self.ttl = ttl
        self.on_answered = on_answered

    def serve(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certfile, self.keyfile)
        try:
            tls = context.wrap_socket(self.sock, server_side=True)
        except ssl.SSLError:
            return
        try:
            self.handle(tls)
        except Exception:
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def handle(self, conn):
        # Read one HTTP request. Content-Length framing only; this fixture never
        # receives chunked requests.
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk

        head_end = data.index(b"\r\n\r\n")
        head = data[:head_end].decode("latin-1")
        rest = data[head_end + 4:]

        lines = head.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()

        content_length = int(headers.get("content-length", "0"))
        while len(rest) < content_length:
            chunk = conn.recv(4096)
            if not chunk:
                return
            rest += chunk
        body = rest[:content_length]

        if self.behaviour == "wrong-status":
            self.send(conn, 500, "text/plain", b"server error")
            return
        if self.behaviour == "wrong-media-type":
            self.send(conn, 200, "application/json", b"{}")
            return
        if self.behaviour == "truncated":
            # Announce more bytes than are sent, then close.
            conn.sendall(b"HTTP/1.1 200 OK\r\n"
                         b"Content-Type: application/dns-message\r\n"
                         b"Content-Length: 512\r\n\r\n")
            conn.sendall(b"\x00" * 8)
            return

        # Extract the DNS message from whichever form was used.
        path, _, query_string = target.partition("?")
        if method == "POST":
            if headers.get("content-type", "") != "application/dns-message":
                self.send(conn, 415, "text/plain", b"bad content type")
                return
            dns_query = body
        elif method == "GET":
            dns_param = None
            for pair in query_string.split("&"):
                key, _, value = pair.partition("=")
                if key == "dns":
                    dns_param = value
                    break
            if dns_param is None:
                self.send(conn, 400, "text/plain", b"missing dns parameter")
                return
            try:
                dns_query = b64url_decode(dns_param)
            except Exception:
                self.send(conn, 400, "text/plain", b"bad dns parameter")
                return
        else:
            self.send(conn, 405, "text/plain", b"method not allowed")
            return

        try:
            force_rcode = None
            if self.behaviour == "servfail":
                force_rcode = RCODE_SERVFAIL
            elif self.behaviour == "nxdomain":
                force_rcode = RCODE_NXDOMAIN
            response = build_response(dns_query, force_rcode=force_rcode,
                                     truncate=(self.behaviour == "truncated-bit"),
                                     ttl=self.ttl)
        except Exception as exc:
            # Report the real reason on stderr. Swallowing it made a TypeError in
            # build_response() masquerade as "malformed dns query" and hid a
            # broken fixture behind a plausible-looking 400.
            sys.stderr.write("doh_test_server: build_response failed: %r\n" % (exc,))
            sys.stderr.flush()
            self.send(conn, 400, "text/plain", b"malformed dns query")
            return

        self.send(conn, 200, "application/dns-message", response)
        if self.on_answered:
            self.on_answered()

    def send(self, conn, status, content_type, body):
        reason = {200: "OK", 400: "Bad Request", 405: "Method Not Allowed",
                  415: "Unsupported Media Type", 500: "Internal Server Error"}.get(status, "OK")
        head = ("HTTP/1.1 %d %s\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n\r\n" % (status, reason, content_type, len(body)))
        conn.sendall(head.encode("latin-1") + body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--behaviour", default="normal",
                        choices=["normal", "wrong-status", "wrong-media-type",
                                 "truncated", "servfail", "nxdomain",
                                 "truncated-bit"])
    parser.add_argument("--ttl", type=int, default=60,
                        help="TTL in the answer record (0 = do not cache)")
    parser.add_argument("--count-file", default=None,
                        help="Write the number of DNS answers served to this file")
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    port = listener.getsockname()[1]

    sys.stdout.write("READY %d %d\n" % (os.getpid(), port))
    sys.stdout.flush()

    # Counts every DNS answer served. A cache test needs this: a second lookup
    # that hits the client-side cache must not increase it.
    answer_count = [0]
    count_lock = threading.Lock()

    def bump_and_write():
        with count_lock:
            answer_count[0] += 1
            value = answer_count[0]
        if args.count_file:
            try:
                with open(args.count_file, "w") as f:
                    f.write(str(value))
            except OSError:
                pass

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            break
        handler = DohHandler(conn, args.cert, args.key, args.behaviour,
                             args.ttl, bump_and_write)
        threading.Thread(target=handler.serve, daemon=True).start()


if __name__ == "__main__":
    main()
