#!/usr/bin/env python3
"""WebSocket server for examples 13, 14, 15, 16 and 20.

Standard library + zlib only. Features the examples need and the plain echo
server does not have:

  * permessage-deflate negotiation (RFC 7692). It accepts a client offer,
    echoes a valid response, decompresses inbound RSV1 frames and compresses
    echoes back. Context takeover is kept per connection unless
    --no-context-takeover is given.
  * --vary-negotiation: the FIRST connection negotiates window bits 15, every
    later one negotiates 9 + server_no_context_takeover. That makes the
    "re-query the negotiated result after a reconnect" example observable.
  * --drop-after N: abruptly close the socket after echoing N messages, which
    is what drives the reconnect examples.
  * --require-token T: reject a handshake whose Authorization header is not
    "Bearer T" with 401, so the credential-refresh example can prove the
    refresh actually happened (the old token stops working).
  * --cert/--key: TLS listener, for WSS through an HTTPS proxy (example 20).

Prints "READY <pid> <port>" once bound, plus one line per connection.

Usage:
    python examples/servers/ws_server.py [port] [options]
"""

import argparse
import base64
import hashlib
import socket
import ssl
import struct
import sys
import threading
import zlib

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


class Frame:
    __slots__ = ("fin", "rsv1", "opcode", "payload")

    def __init__(self, fin, rsv1, opcode, payload):
        self.fin, self.rsv1, self.opcode, self.payload = fin, rsv1, opcode, payload


def read_frame(conn):
    first, second = recv_exact(conn, 2)
    fin = bool(first & 0x80)
    rsv1 = bool(first & 0x40)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(conn, 8))[0]
    mask = recv_exact(conn, 4) if masked else b""
    payload = recv_exact(conn, length) if length else b""
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return Frame(fin, rsv1, opcode, payload)


def send_frame(conn, opcode, payload, rsv1=False):
    header = bytes([0x80 | opcode | (0x40 if rsv1 else 0)])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + struct.pack("!H", n)
    else:
        header += bytes([127]) + struct.pack("!Q", n)
    conn.sendall(header + payload)


class Connection:
    """Per-physical-connection permessage-deflate state (context takeover)."""

    def __init__(self, negotiated, params):
        self.negotiated = negotiated
        self.params = params
        self.inflater = zlib.decompressobj(wbits=-15) if negotiated else None
        self.deflater = zlib.compressobj(9, zlib.DEFLATED, -15) if negotiated else None

    def decompress(self, payload):
        if not self.inflater:
            return payload
        # RFC 7692: the sender strips the trailing 0x00 0x00 0xff 0xff; the
        # receiver appends it back before inflating.
        return self.inflater.decompress(payload + b"\x00\x00\xff\xff")

    def compress(self, data):
        out = self.deflater.compress(data) + self.deflater.flush(zlib.Z_SYNC_FLUSH)
        assert out.endswith(b"\x00\x00\xff\xff"), "Z_SYNC_FLUSH tail missing"
        return out[:-4]


def negotiate(offer, vary, index, no_context_takeover):
    """Return (accepted, response_header_value, description)."""
    if not offer or "permessage-deflate" not in offer.lower():
        return False, "", "no offer"
    params = []
    if no_context_takeover:
        params += ["server_no_context_takeover", "client_no_context_takeover"]
    if vary and index > 1:
        # Deliberately different from the first connection so a reconnect that
        # re-reads the negotiation is observable.
        params += ["server_max_window_bits=9", "server_no_context_takeover"]
    value = "permessage-deflate" + ("; " + "; ".join(params) if params else "")
    return True, value, value


def handle(conn, addr, args, state):
    with state["lock"]:
        state["index"] += 1
        index = state["index"]

    try:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk

        headers = {}
        for line in request.split(b"\r\n")[1:]:
            if b":" in line:
                name, _, value = line.partition(b":")
                headers[name.strip().lower().decode("latin1")] = value.strip().decode("latin1")

        key = headers.get("sec-websocket-key", "")
        if not key:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        auth = headers.get("authorization", "")
        token_ok = True
        if args.require_token:
            token_ok = (auth == f"Bearer {args.require_token}")
        elif args.require_token_prefix:
            token_ok = auth.startswith(args.require_token_prefix)
        if not token_ok:
            print(f"connection {index}: 401 (authorization={auth!r})", flush=True)
            conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            return

        accepted, response_ext, description = negotiate(
            headers.get("sec-websocket-extensions", ""), args.vary_negotiation, index,
            args.no_context_takeover)

        accept = base64.b64encode(
            hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        lines = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Accept: {accept}",
        ]
        if accepted:
            lines.append(f"Sec-WebSocket-Extensions: {response_ext}")
        conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))

        print(f"connection {index}: deflate={'yes' if accepted else 'no'} "
              f"({description})", flush=True)
        if auth:
            print(f"connection {index}: authorization={auth!r}", flush=True)

        state_conn = Connection(accepted, description)
        echoed = 0
        while True:
            frame = read_frame(conn)
            if frame.opcode == OP_CLOSE:
                send_frame(conn, OP_CLOSE, frame.payload[:2])
                return
            if frame.opcode == OP_PING:
                send_frame(conn, OP_PONG, frame.payload)
                continue
            if frame.opcode == OP_PONG:
                continue
            if frame.opcode not in (OP_TEXT, OP_BINARY):
                send_frame(conn, OP_CLOSE, struct.pack("!H", 1003))
                return

            data = state_conn.decompress(frame.payload) if frame.rsv1 else frame.payload
            if accepted and state_conn.deflater is not None:
                out = state_conn.compress(data)
                send_frame(conn, frame.opcode, out, rsv1=True)
            else:
                send_frame(conn, frame.opcode, data)

            echoed += 1
            print(f"connection {index}: echoed {len(data)} bytes "
                  f"(#{echoed})", flush=True)
            if args.drop_after and echoed >= args.drop_after:
                print(f"connection {index}: dropping after {echoed} messages",
                      flush=True)
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", type=int, default=8087)
    ap.add_argument("--drop-after", type=int, default=0,
                    help="abruptly close after echoing N messages (0 = never)")
    ap.add_argument("--require-token", default="",
                    help="only accept 'Authorization: Bearer <token>'")
    ap.add_argument("--require-token-prefix", default="",
                    help="accept any Authorization value starting with this prefix")
    ap.add_argument("--vary-negotiation", action="store_true",
                    help="first connection window 15, later ones window 9")
    ap.add_argument("--no-context-takeover", action="store_true")
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(8)
    port = srv.getsockname()[1]

    ctx = None
    if args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)

    print(f"READY {port}", flush=True)
    scheme = "wss" if ctx else "ws"
    print(f"websocket server on {scheme}://127.0.0.1:{port}/chat", flush=True)

    state = {"index": 0, "lock": threading.Lock()}
    try:
        while True:
            raw, addr = srv.accept()
            conn = raw
            if ctx:
                try:
                    conn = ctx.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError):
                    raw.close()
                    continue
            threading.Thread(target=handle, args=(conn, addr, args, state),
                             daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
