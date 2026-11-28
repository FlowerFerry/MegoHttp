#!/usr/bin/env python3
"""Tiny SSE server for examples/sse_client.cpp.

No dependencies, no network access: it listens on 127.0.0.1 and streams events
until the client disconnects. After five events it closes the connection on
purpose, so the example's reconnect path (and Last-Event-ID) is exercised
instead of only the happy path.

Usage:
    python examples/servers/sse_server.py [port]

The server prints one line per connection so the reconnect is visible.
"""

import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EVENTS_PER_CONNECTION = 5
EVENT_INTERVAL_SECONDS = 0.4

_connections = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):   # noqa: A002 - name fixed by the base class
        return

    def do_GET(self):
        global _connections
        if not self.path.startswith("/events"):
            self.send_error(404, "try /events")
            return
        _connections += 1
        connection_no = _connections
        print(f"connection {connection_no}: {self.path}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        base = (connection_no - 1) * EVENTS_PER_CONNECTION
        try:
            for i in range(EVENTS_PER_CONNECTION):
                event_id = base + i + 1
                payload = f"event {event_id} from connection {connection_no}"
                body = (
                    f"id: {event_id}\n"
                    f"event: tick\n"
                    f"data: {payload}\n\n"
                )
                self.wfile.write(body.encode("utf-8"))
                self.wfile.flush()
                time.sleep(EVENT_INTERVAL_SECONDS)
        except OSError:
            # The client cancelled or went away mid-stream. On Windows this is
            # ConnectionAbortedError (WinError 10053), which is not a
            # BrokenPipeError, so catch OSError rather than guessing.
            pass

        # Deliberate drop: the client's reconnect policy takes over from here.
        self.close_connection = True
        print(f"connection {connection_no}: closing after "
              f"{EVENTS_PER_CONNECTION} events", flush=True)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"SSE server on http://127.0.0.1:{port}/events (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
