# Interop server for the permessage-deflate test (T3 / S6.3-10).
#
# This is an INDEPENDENT WebSocket implementation (Python `websockets`), not
# another copy of our own code: the point of an interop test is to be wrong in
# a different way than the code under test. It echoes every message back, with
# compression provided by the library's extension layer.
#
# Protocol with the test driver:
#   * prints "READY <port>" on stdout once listening
#   * echoes each received message back to the sender
#   * exits when stdin closes (the driver holds it open)
#
# Usage: python ws_deflate_server.py [--no-deflate] [--window-bits N]

import argparse
import asyncio
import os
import sys

import websockets
from websockets.extensions.permessage_deflate import (
    ServerPerMessageDeflateFactory,
)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-deflate", action="store_true",
                    help="do not offer permessage-deflate at all")
    ap.add_argument("--window-bits", type=int, default=15)
    ap.add_argument("--no-context-takeover", action="store_true")
    ap.add_argument("--tls", action="store_true",
                    help="serve wss:// using the test fixtures' certificate")
    ap.add_argument("--certdir", default="",
                    help="directory holding server-cert.pem / server-key.pem")
    args = ap.parse_args()

    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    kwargs = {}
    if not args.no_deflate:
        kwargs["extensions"] = [
            ServerPerMessageDeflateFactory(
                server_max_window_bits=args.window_bits,
                client_max_window_bits=args.window_bits,
                server_no_context_takeover=args.no_context_takeover,
                client_no_context_takeover=args.no_context_takeover,
            )
        ]
    if args.tls:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            os.path.join(args.certdir, "server-cert.pem"),
            os.path.join(args.certdir, "server-key.pem"),
        )
        kwargs["ssl"] = ctx

    server = await websockets.serve(handler, "127.0.0.1", 0, **kwargs)
    port = server.sockets[0].getsockname()[1]
    print(f"READY {port}", flush=True)

    # Stay alive until the driver closes stdin.
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    try:
        await loop.run_in_executor(None, sys.stdin.read)
    finally:
        if not fut.done():
            fut.cancel()
    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
