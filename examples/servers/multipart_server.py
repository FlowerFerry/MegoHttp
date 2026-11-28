#!/usr/bin/env python3
"""Multipart server for examples 7, 8 and 9.

Endpoints:
    POST /upload    parse a multipart/form-data body and answer with a summary
                    (parts, field names, bytes)
    GET  /batch     multipart/mixed with three parts and a Content-Length
    GET  /stream    chunked multipart/mixed that keeps producing parts (for
                    backpressure and cancellation), 200 parts then EOF

Standard library only, loopback only. Usage:
    python examples/servers/multipart_server.py [port]
"""

import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOUNDARY = b"megodemo-boundary-7d1f"
STREAM_PARTS = 200
STREAM_INTERVAL_SECONDS = 0.02


def part_body(index: int) -> bytes:
    head = (
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Disposition: attachment; name=\"part" + str(index).encode() + b"\"; "
        b"filename=\"part" + str(index).encode() + b".bin\"\r\n"
        b"Content-Type: application/octet-stream\r\n\r\n"
    )
    payload = (f"part-{index}-".encode() * 40)[:512]
    return head + payload + b"\r\n"


def batch_body() -> bytes:
    out = bytearray()
    out += (
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Disposition: form-data; name=\"meta\"\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"hello from the multipart fixture\r\n"
    )
    out += (
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Disposition: form-data; name=\"numbers\"\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"1,2,3\r\n"
    )
    out += (
        b"--" + BOUNDARY + b"\r\n"
        b"Content-Disposition: attachment; name=\"blob\"; filename=\"blob.bin\"\r\n"
        b"Content-Type: application/octet-stream\r\n\r\n"
        + bytes(range(64)) + b"\r\n"
    )
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):   # noqa: A002 - name fixed by the base class
        return

    # -- upload ------------------------------------------------------------
    def do_POST(self):
        if not self.path.startswith("/upload"):
            self.send_error(404, "try /upload")
            return
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type") or ""
        match = re.search(r'boundary="?([^";]+)"?', ctype)
        if not match:
            self.send_error(400, "no boundary in Content-Type")
            return
        boundary = b"--" + match.group(1).encode()

        parts = []
        for raw in body.split(boundary)[1:]:
            if raw.startswith(b"--"):
                break
            raw = raw.lstrip(b"\r\n")
            head, _, payload = raw.partition(b"\r\n\r\n")
            if not _:
                continue
            payload = payload[:-2] if payload.endswith(b"\r\n") else payload
            name = "?"
            filename = ""
            disp = b""
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-disposition:"):
                    disp = line
            if disp:
                m = re.search(rb'name="([^"]*)"', disp)
                if m:
                    name = m.group(1).decode("latin1")
                m = re.search(rb'filename="([^"]*)"', disp)
                if m:
                    filename = m.group(1).decode("latin1")
            parts.append((name, filename, len(payload)))

        print("upload: %d parts" % len(parts), flush=True)
        for name, filename, size in parts:
            print(f"  {name!r} filename={filename!r} bytes={size}", flush=True)

        summary = (
            f"received {len(parts)} parts, total {len(body)} bytes\n"
            + "".join(f"{n}|{f}|{s}\n" for n, f, s in parts)
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(summary)))
        self.end_headers()
        self.wfile.write(summary)
        self.wfile.flush()

    # -- downloads ---------------------------------------------------------
    def do_GET(self):
        if self.path.startswith("/batch"):
            body = batch_body()
            self.send_response(200)
            self.send_header("Content-Type",
                             "multipart/mixed; boundary=" + BOUNDARY.decode())
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            print("batch: %d bytes" % len(body), flush=True)
            return

        if self.path.startswith("/stream"):
            self.send_response(200)
            self.send_header("Content-Type",
                             "multipart/mixed; boundary=" + BOUNDARY.decode())
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def chunk(data: bytes):
                self.wfile.write(b"%X\r\n" % len(data) + data + b"\r\n")
                self.wfile.flush()

            try:
                for index in range(STREAM_PARTS):
                    chunk(part_body(index))
                    time.sleep(STREAM_INTERVAL_SECONDS)
                chunk(b"--" + BOUNDARY + b"--\r\n")
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                print("stream: finished %d parts" % STREAM_PARTS, flush=True)
            except OSError:
                print("stream: client went away", flush=True)
            return

        self.send_error(404, "try /upload, /batch or /stream")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"multipart server on http://127.0.0.1:{port}/ "
          f"(/upload, /batch, /stream)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
