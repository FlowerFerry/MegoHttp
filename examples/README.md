# MegoHttp examples

Runnable programs, one per feature. Every example is gated in CMake on the
feature it demonstrates: a build with a feature off skips the example with a
`MegoHttp examples: skip ...` status line instead of failing.

## Build

    cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON
    cmake --build build

The executables land next to the library's runtime DLLs:

    build/examples/megohttp_example_<name>

Build a specific group by turning features on, e.g. everything:

    cmake -S . -B build -DMGHTTP_BUILD_EXAMPLES=ON \
      -DMGHTTP_BACKEND_LIBUV=ON -DMGHTTP_TLS_OPENSSL=ON \
      -DMGHTTP_ENABLE_SSE=ON -DMGHTTP_ENABLE_WEBSOCKET=ON \
      -DMGHTTP_ENABLE_DOT=ON -DMGHTTP_ENABLE_DOH=ON

Coroutines need C++20 and `-DMGHTTP_ENABLE_COROUTINES=ON`.

## What is here

| No. | Program | Feature gate | Local service it needs |
|-----|---------|--------------|------------------------|
| 1 | `megohttp_example_sync_get` | always | `python -m http.server 8080` |
| 2 | `megohttp_example_callback_cancel` | always | `examples/servers/slow_server.py` |
| 3 | `megohttp_example_future_get` | always | `python -m http.server 8080` |
| 4 | `megohttp_example_external_libuv_loop` | `MGHTTP_BACKEND_LIBUV` | `python -m http.server 8080` |
| 5 | `megohttp_example_external_asio_loop` | `MGHTTP_BACKEND_ASIO` | `python -m http.server 8080` |
| 6 | `megohttp_example_https_custom_ca` | not `MGHTTP_TLS_NONE` | `tests/https_test_server.py` + TLS fixtures |
| 7 | `megohttp_example_multipart_upload` | always | `examples/servers/multipart_server.py` |
| 8 | `megohttp_example_multipart_response` | always | `examples/servers/multipart_server.py` |
| 9 | `megohttp_example_multipart_continuous` | always | `examples/servers/multipart_server.py` |
| 10 | `megohttp_example_stream_download` | always | `python -m http.server 8080` |
| 11 | `megohttp_example_sse_client` | `MGHTTP_ENABLE_SSE` | `examples/servers/sse_server.py` |
| 12 | `megohttp_example_websocket_echo` | `MGHTTP_ENABLE_WEBSOCKET` | `examples/servers/ws_echo_server.py` |
| 13 | `megohttp_example_ws_deflate_negotiation` | `WEBSOCKET` + `WEBSOCKET_DEFLATE` | `examples/servers/ws_server.py` |
| 14 | `megohttp_example_ws_deflate_stream` | `WEBSOCKET` + `WEBSOCKET_DEFLATE` | `examples/servers/ws_server.py` |
| 15 | `megohttp_example_ws_reconnect_auth` | `MGHTTP_ENABLE_WEBSOCKET` | `ws_server.py --require-token-prefix ... --drop-after 1` |
| 16 | `megohttp_example_ws_reconnect_deflate` | `WEBSOCKET` + `WEBSOCKET_DEFLATE` | `ws_server.py --vary-negotiation --drop-after 1` |
| 17 | `megohttp_example_proxy_cookie` | always | `cookie_server.py` + `proxy_test_server.py` |
| 18 | `megohttp_example_https_proxy_to_http` | not `MGHTTP_TLS_NONE` | `proxy_test_server.py --tls-cert` |
| 19 | `megohttp_example_https_proxy_to_https` | not `MGHTTP_TLS_NONE` | HTTPS proxy + HTTPS target, two CAs |
| 20 | `megohttp_example_wss_via_https_proxy` | WS + deflate + TLS | WSS target + HTTPS proxy |
| 21 | `megohttp_example_dot_resolve` | `MGHTTP_ENABLE_DOT` | `tests/dot_test_server.py` + TLS fixtures |
| 22 | `megohttp_example_doh_resolve` | `MGHTTP_ENABLE_DOH` | `tests/doh_test_server.py` + TLS fixtures |
| 23 | `megohttp_example_encrypted_dns_strict_bootstrap` | `MGHTTP_ENABLE_DOT` | `tests/dot_test_server.py` + TLS fixtures |
| 24 | `megohttp_example_coroutine_get` | `MGHTTP_ENABLE_COROUTINES` | `python -m http.server 8080` |

## Quick runs

Plain HTTP (numbers 1, 3, 4, 5, 10):

    python -m http.server 8080
    ./build/examples/megohttp_example_sync_get        http://127.0.0.1:8080/README.md
    ./build/examples/megohttp_example_future_get     http://127.0.0.1:8080/README.md
    ./build/examples/megohttp_example_future_get     http://127.0.0.1:8080/README.md 1   # cancel path
    ./build/examples/megohttp_example_external_libuv_loop http://127.0.0.1:8080/README.md
    ./build/examples/megohttp_example_external_asio_loop  http://127.0.0.1:8080/README.md
    ./build/examples/megohttp_example_stream_download http://127.0.0.1:8080/README.md out.bin

Cancellation (number 2):

    python examples/servers/slow_server.py 8084 2000
    ./build/examples/megohttp_example_callback_cancel http://127.0.0.1:8084/ 200
    # the request is cancelled while the server is still sleeping; exit code 2

Multipart (numbers 7, 8 and 9):

    python examples/servers/multipart_server.py 8085
    ./build/examples/megohttp_example_multipart_upload     http://127.0.0.1:8085/upload README.md
    ./build/examples/megohttp_example_multipart_response   http://127.0.0.1:8085/batch
    ./build/examples/megohttp_example_multipart_continuous http://127.0.0.1:8085/stream

The continuous example pauses the stream from the sink (returning `false`), resumes
it from another thread, then cancels once five parts are in — its output shows the
pause landing and `on_error` reporting `Cancelled`.

HTTPS with a custom CA (number 6):

    python tests/gen_tls_fixtures.py tests/tls_fixtures        # once
    python tests/https_test_server.py tests/tls_fixtures/server-cert.pem \
                                      tests/tls_fixtures/server-key.pem
    # prints: READY <pid> <port>
    ./build/examples/megohttp_example_https_custom_ca --port <port>

SSE (number 11):

    python examples/servers/sse_server.py 8081
    ./build/examples/megohttp_example_sse_client http://127.0.0.1:8081/events 6

The demo server drops the connection after five events on purpose, so the
reconnect path runs and the output shows the ids continuing from the last one.

WebSocket (number 12):

    python examples/servers/ws_echo_server.py 8082
    ./build/examples/megohttp_example_websocket_echo ws://127.0.0.1:8082/chat

WebSocket compression and reconnects (numbers 13–16):

    python examples/servers/ws_server.py 8087                       # deflate echo
    ./build/examples/megohttp_example_ws_deflate_negotiation ws://127.0.0.1:8087/chat
    ./build/examples/megohttp_example_ws_deflate_stream      ws://127.0.0.1:8087/chat

    # reconnects: the server drops the connection after each message
    python examples/servers/ws_server.py 8088 --require-token-prefix "Bearer demo-" --drop-after 1
    ./build/examples/megohttp_example_ws_reconnect_auth ws://127.0.0.1:8088/chat

    # re-query the negotiation: connection 1 uses window 15, connection 2 uses 9
    python examples/servers/ws_server.py 8089 --vary-negotiation --drop-after 1
    ./build/examples/megohttp_example_ws_reconnect_deflate ws://127.0.0.1:8089/chat

Proxies and cookies (numbers 17–20):

    python examples/servers/cookie_server.py 8090
    python tests/proxy_test_server.py --mode forward            # prints READY <pid> <port>
    ./build/examples/megohttp_example_proxy_cookie --proxy 127.0.0.1:<port> \
        http://127.0.0.1:8090
    # the same example accepts --type socks5 against --mode socks5

    # HTTPS proxy → HTTP target
    python tests/proxy_test_server.py --mode forward \
        --tls-cert tests/tls_fixtures/server-cert.pem \
        --tls-key  tests/tls_fixtures/server-key.pem
    ./build/examples/megohttp_example_https_proxy_to_http --proxy localhost:<port> \
        --proxy-ca tests/tls_fixtures/ca.pem http://127.0.0.1:8090/

    # HTTPS proxy → HTTPS target, two different CAs
    python tests/https_test_server.py tests/tls_fixtures/intermediate-server-fullchain.pem \
                                      tests/tls_fixtures/intermediate-server-key.pem
    python tests/proxy_test_server.py --mode connect \
        --tls-cert tests/tls_fixtures/server-cert.pem \
        --tls-key  tests/tls_fixtures/server-key.pem
    ./build/examples/megohttp_example_https_proxy_to_https --proxy localhost:<proxy-port> \
        --proxy-ca tests/tls_fixtures/ca.pem \
        --target-ca tests/tls_fixtures/intermediate-ca-chain.pem \
        https://localhost:<target-port>/

    # WSS through the HTTPS proxy, permessage-deflate on
    python examples/servers/ws_server.py 8091 \
        --cert tests/tls_fixtures/server-cert.pem \
        --key  tests/tls_fixtures/server-key.pem
    ./build/examples/megohttp_example_wss_via_https_proxy --proxy localhost:<proxy-port> \
        wss://localhost:8091/chat

Use `localhost` (not `127.0.0.1`) when the proxy or target certificate is the
fixture's: verification checks the name in the certificate, and connecting by IP
is a hostname mismatch, not a library problem.

Encrypted DNS (numbers 21, 22, 23):

    python tests/gen_tls_fixtures.py tests/tls_fixtures        # once, needs `cryptography`
    python tests/dot_test_server.py --cert tests/tls_fixtures/server-cert.pem \
                                    --key  tests/tls_fixtures/server-key.pem
    # prints: READY <pid> <port>
    ./build/examples/megohttp_example_dot_resolve --port <port> example.com
    ./build/examples/megohttp_example_encrypted_dns_strict_bootstrap --port <port>

    python tests/doh_test_server.py --cert tests/tls_fixtures/server-cert.pem \
                                    --key  tests/tls_fixtures/server-key.pem
    ./build/examples/megohttp_example_doh_resolve --port <port> dual.example

The DoH fixture answers only the names in its own table (`dual.example`,
`a-only.example`, `aaaa-only.example`, `nodata.example`); anything else is
NXDOMAIN. The DoT fixture answers every name with a fixed address.

Both resolvers also work against public endpoints, which needs internet:

    ./build/examples/megohttp_example_dot_resolve --endpoint dns.quad9.net \
        --bootstrap 9.9.9.9 --port 853 --ca "" example.com
    ./build/examples/megohttp_example_doh_resolve --endpoint cloudflare-dns.com \
        --bootstrap 1.1.1.1 --ca "" dual.example

## Three contracts the examples document

**External loop teardown** (`external_libuv_loop.cpp`). A Client that borrows an
executor does not own the loop, but the order of operations still matters:

1. `initialize_external_wake_handle()` from the thread that runs the loop;
2. `Client::shutdown()`, then run the loop so the posted retirement jobs run;
3. destroy the Client (its transport/timer handles close asynchronously);
4. `Executor::shutdown()`;
5. run the loop until nothing is active, then `uv_loop_close()`.

Skipping 2 or 3 makes `uv_loop_close()` fail with "resource busy".

**Strict bootstrap** (`encrypted_dns_strict_bootstrap.cpp`). A named DoT/DoH
endpoint without a bootstrap IP is refused with `ConfigurationError` — the name
is never handed to system DNS. Adding `bootstrap_ip` makes the same endpoint
work. `use_system_bootstrap = true` is the documented opt-out.

**Streaming sinks and cancellation** (`multipart_continuous.cpp`). A sink that
returns `false` pauses the read only when a `MultipartSinkFlow` is attached;
without one the value is ignored, because nothing could resume it. Cancelling a
stream that never ends still delivers exactly one `on_error` to the sink — a
cancel or a total timeout reaches the request's terminal path without going
through the exchange's own failure path, which is why the library routes sink
notification through a hook instead of assuming the normal error path runs.

## Coverage

All 24 examples from the task book list are present: 1–12, 13–16 (compression and
reconnects), 17–20 (proxies and cookies), 21–24 (encrypted DNS and coroutines).
Each has been built and run against the local fixtures described above; the ones
that need a service log what they need rather than assuming a public endpoint.

Two API details worth knowing when reading 13–16:

* `on_open` fires ONCE for the logical session. Later physical connections are
  reported through `ReconnectEvents::on_succeeded(attempt, generation)`, which is
  where a re-negotiated compression result must be read.
* `negotiated_deflate()` reports the CURRENT connection only, and returns
  `enabled == false` while no connection is open. Do not cache it across a
  reconnect.
