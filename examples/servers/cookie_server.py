#!/usr/bin/env python3
"""Cookie-setting HTTP target for examples/proxy_cookie.cpp.

    GET /login   -> Set-Cookie: session=demo123; Path=/
    GET /me      -> echoes the received Cookie header in the body
    GET /        -> "hello"

Standard library only, loopback only.

Usage:
    python examples/servers/cookie_server.py [port]
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):   # noqa: A002 - name fixed by the base class
        return

    def _send(self, body: bytes, cookie: str = ""):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass

    def do_GET(self):
        if self.path.startswith("/login"):
            self._send(b"logged in\n", "session=demo123; Path=/; HttpOnly")
            return
        if self.path.startswith("/me"):
            cookie = self.headers.get("Cookie") or "(none)"
            body = f"cookie seen by target: {cookie}\n".encode()
            print(f"/me Cookie={cookie!r}", flush=True)
            self._send(body)
            return
        self._send(b"hello\n")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"cookie server on http://127.0.0.1:{port}/ (login, me)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
