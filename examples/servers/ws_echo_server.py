#!/usr/bin/env python3
"""Minimal WebSocket echo server for examples/websocket_echo.cpp.

RFC 6455 server side, written against the standard library only: handshake,
text/echo frames, ping/pong and close. No compression (permessage-deflate has
its own test fixture), no subprotocols.

Usage:
    python examples/servers/ws_echo_server.py [port]

Every text message is echoed verbatim; a close frame is answered with a close
frame and the connection is closed.
"""

import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def read_frame(conn: socket.socket):
    first, second = recv_exact(conn, 2)
    fin = bool(first & 0x80)
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
    return fin, opcode, payload


def send_frame(conn: socket.socket, opcode: int, payload: bytes):
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + struct.pack("!H", n)
    else:
        header += bytes([127]) + struct.pack("!Q", n)
    conn.sendall(header + payload)


def handle(conn: socket.socket, addr):
    try:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk

        key = ""
        for line in request.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip().decode("ascii")
        if not key:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        accept = base64.b64encode(
            hashlib.sha1((key + GUID).encode("ascii")).digest()
        ).decode("ascii")
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode("ascii")
        )
        print(f"{addr[0]}:{addr[1]} connected", flush=True)

        while True:
            _fin, opcode, payload = read_frame(conn)
            if opcode == 0x1:                      # text
                print(f"echo {len(payload)} bytes", flush=True)
                send_frame(conn, 0x1, payload)
            elif opcode == 0x8:                    # close
                send_frame(conn, 0x8, payload[:2])
                return
            elif opcode == 0x9:                    # ping
                send_frame(conn, 0xA, payload)
            elif opcode == 0xA:                    # pong
                continue
            else:
                send_frame(conn, 0x8, struct.pack("!H", 1003))
                return
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()
        print(f"{addr[0]}:{addr[1]} closed", flush=True)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"WebSocket echo server on ws://127.0.0.1:{port}/chat (Ctrl+C to stop)",
          flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
