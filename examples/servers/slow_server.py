#!/usr/bin/env python3
"""Slow HTTP server for examples/callback_cancel.cpp.

Answers every GET after a fixed delay, so a request is still in flight when the
example's cancelling thread fires. Standard library only, loopback only.

Usage:
    python examples/servers/slow_server.py [port] [delay_ms]
"""

import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DELAY_MS = 2000


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):   # noqa: A002 - name fixed by the base class
        return

    def do_GET(self):
        print(f"request for {self.path}, sleeping {DELAY_MS} ms", flush=True)
        try:
            time.sleep(DELAY_MS / 1000.0)
        except KeyboardInterrupt:
            return
        body = b"slow response\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            # The client cancelled while we were sleeping; that is the point of
            # the example, not an error worth a traceback.
            pass
        print("answered", flush=True)


def main() -> int:
    global DELAY_MS
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8084
    if len(sys.argv) > 2:
        DELAY_MS = int(sys.argv[2])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"slow server on http://127.0.0.1:{port}/ (delay {DELAY_MS} ms)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
