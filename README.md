# MegoHttp

A header-only C++17 HTTP/1.1 client library (namespace `megohttp`), with an
additional coroutine interface under C++20. The network backend is libuv **or**
standalone Asio; TLS is built with OpenSSL, mbedTLS, or disabled entirely.

> Status: phases 0–7 are done on the feature side (infrastructure, async
> lifecycle, HTTP completeness/streaming, TLS, pool/redirect/retry/proxy/
> Cookie/gzip+Brotli/multipart, DoT/DoH, SSE/WebSocket/permessage-deflate/
> auto-reconnect, C++20 coroutines). Known gaps are listed under
> [Known limitations](#known-limitations); phase 8 (full matrix, UBSan/TSan,
> aggregated examples, release documents) is in progress.

## Features

- HTTP/1.1: strict parsing, chunked transfer, trailers (read and controlled
  send), 1xx, `Expect: 100-continue`, connection-close-delimited bodies.
- Request trailers: a chunked upload can send static fields or EOF-computed
  fields in the terminating chunk (`set_trailers` / `set_trailer_source`); the
  `Trailer` declaration is generated and validated for you.
- Streaming upload/download: `BodySource` / `BodySink` with backpressure
  (`BodySinkFlow`); `set_head_callback` delivers the response head before the
  body is read. `FileSource` reads the file on a worker thread and `BodySource`
  only pops from a bounded queue, so file I/O never runs on the event loop.
- Connection pool (Keep-Alive), redirects, automatic retries, HTTP forward
  proxy / CONNECT / HTTPS proxy / SOCKS5.
- Timeouts: DNS / unified connection stage / send / receive / total.
  `send_timeout` and `recv_timeout` are **idle** timeouts (re-armed after every
  successful write/read); a user pause on the receive side stops the clock;
  waiting for `100-continue` counts as send idle time.
- Cookies (with a PSL check against public suffixes), gzip / Brotli content
  coding (automatic response decompression plus opt-in request-body
  compression), multipart request encoding and streaming response parsing.
  Multipart responses discard preamble/epilogue per RFC 2046 by default; override
  `MultipartSink::on_preamble_data` / `on_epilogue_data` to opt in, and
  `multipart_part_content_range()` parses a part's `Content-Range`.
- TLS: composable `TlsStream` (wraps any `AsyncByteStream`, which is what makes
  two-layer TLS for an HTTPS proxy possible); `TlsConfig::cert_file/key_file`
  provide mTLS client certificates.
- Encrypted DNS: DoT (RFC 7858) and DoH (RFC 8484) with positive/negative TTL
  caching; both can go through an HTTP, HTTPS or SOCKS5 proxy, where
  `proxy_bootstrap_ip` / `use_system_bootstrap` resolve the proxy name and the
  proxy TLS identity stays separate from the DNS endpoint identity.
- Long-lived sessions: SSE (reconnect, `Last-Event-ID`, `SseFlow`
  backpressure/pause-resume) and WebSocket (RFC 6455 + permessage-deflate +
  optional auto-reconnect + `send_begin/send_data/send_end` incremental send,
  `set_incremental_message_callbacks` incremental receive,
  `pause_receive/resume_receive` frame-level backpressure).
- Four call styles share one state machine: callback, future, synchronous,
  C++20 coroutine.

Explicitly not supported: HTTP/2, HTTP/3, DoQ, PAC/NTLM/Kerberos, on-disk
Cookie persistence, automatic resend of WebSocket messages.

## Requirements

| Dependency | Version | Required? |
|---|---|---|
| C++17 compiler | MSVC 2022 / GCC / Clang | required |
| libuv **or** standalone Asio | 1.53.0 / 1.38.0 | one of them |
| OpenSSL **or** mbedTLS | 1.1.1+ / 3.6.7 | one of them, or `MGHTTP_TLS_NONE` |
| fmt | 12.1.0 | required (the only formatting facility) |
| zlib | 1.3.1 | optional (gzip, permessage-deflate) |
| Brotli | 1.1.0 | optional |
| MemeString | 0.0.5 | optional (`MGHTTP_USE_MEMESTRING=ON` switches the text layer to MemeString; the default is `std::string`) |
| Catch2 | 3.7.1 | tests only |

The build looks for these trees under `deps/` in the source tree; that directory
is deliberately not tracked, so a fresh clone must fetch the pinned versions
listed above. Each dependency keeps its own licence. `CMakeLists.txt` carries
the per-dependency build commands in its comments.

All verification evidence is from **Windows + MSVC 2022 x64** (Ninja and the
Visual Studio generator; the local OpenSSL is 1.1.1g). Other platforms keep a
build path by design but have not been exercised on this host.

## Build

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The default configuration is: libuv backend, OpenSSL, `std::string` (MemeString
off), and gzip/Brotli/SSE/WebSocket/DoT/DoH all enabled. `cmake --build` accepts
`-j N`; keep it modest on a shared machine.

Verification uses the complete backend × TLS × string matrix — 2 backends
(libuv / Asio) × 3 TLS modes (OpenSSL / mbedTLS / disabled) × 2 string modes
(std / MemeString) — plus two `no_uvw` dependency-trimming variants, fourteen
configurations in total. `tests/build_matrix.py` builds them and
`tests/run_matrix.py` runs them; each entry is just the usual CMake flags
(`-DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON`, `-DMGHTTP_TLS_*`,
`-DMGHTTP_USE_MEMESTRING=OFF`, `-DMGHTTP_USE_UVW=OFF`).

### Tests

```bash
python tests/run_tests.py build
```

`run_tests.py` discovers `<build-dir>/tests/test_*.exe` and classifies each
binary by its own summary: Catch2 v3 prints
`All tests passed (N assertions in M test cases)` (or
`test cases: N | ... passed ...` when every case is skipped and the binary still
exits 0), and the multi-translation-unit link test prints `[PASS]`. A run whose
output matches none of those is reported as `FAIL`.

Two harness caveats:

- Binaries produced by the **Visual Studio generator** land in
  `<build-dir>/tests/Release/`, which `run_tests.py` does not scan. Use
  `tests/run_matrix.py` for those configurations, or run the binaries directly.
- `ctest` hangs on this project's verification host, so it is not an acceptance
  path here.

### CI

`.github/workflows/ci.yml` covers the platform/backend/TLS/string axes. Job names
follow `platform toolchain | backend + tls + string | features | scope`, so the
enabled combination is readable without opening the file.

- **Runtime** (builds and runs the suite): Windows MSVC x64/x86 on Asio +
  TLS_NONE; Windows MSVC x64 on libuv + mbedTLS with every optional feature on
  (the Windows runner is the only place the process-spawning fixtures can run);
  Linux GCC/Clang x64/x86 on Asio + TLS_NONE (eight portable suites through a
  `ctest` filter); a Clang ASan+UBSan job on the same eight suites.
- **Build only**: Linux libuv + OpenSSL (also installs the package and builds
  `tests/consumer` against it), Linux Asio + mbedTLS, Linux libuv + OpenSSL +
  MemeString, macOS libuv + OpenSSL, a libuv + uvw build, a C++20 coroutines
  build that additionally runs `test_task`, and a 12-cell
  backend × TLS × string matrix.
- **Compile only**: Android arm64, iOS arm64 and Linux aarch64/armv7l
  cross-compile smoke targets.

The Linux/macOS build-only jobs do not run the suite because the Python
fixtures that serve proxies, DoT/DoH endpoints and two-layer TLS spawn
processes through Windows APIs; runtime coverage outside Windows is limited to
the portable-core and sanitizer jobs until those fixtures gain POSIX process
management.

### Examples

All twenty-four examples from the task book list live in `examples/`, each gated
on the feature it demonstrates so a build with that feature off prints a `skip`
line instead of failing — from sync GET and future/callback forms through external
loops, HTTPS with a custom CA, multipart upload/streaming, SSE, WebSocket
(echo, permessage-deflate negotiation, streaming compression, reconnects with
credential refresh and re-negotiation) and proxies (HTTP/SOCKS5 with a cookie jar,
HTTPS proxy to HTTP, HTTPS proxy to HTTPS with separate proxy/target CAs, WSS
through an HTTPS proxy with deflate) to DoT/DoH/strict bootstrap and the C++20
coroutine GET. `examples/README.md` lists the local server each one needs (the
demo servers live in `examples/servers/`).

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BUILD_EXAMPLES=ON
cmake --build build
python -m http.server 8080                       # another terminal
build/examples/megohttp_example_sync_get http://127.0.0.1:8080/
```

The coroutine example additionally needs `-DCMAKE_CXX_STANDARD=20
-DMGHTTP_ENABLE_COROUTINES=ON`. The remaining examples from the task book list
are still part of phase 8.

## Minimal usage

Synchronous:

```cpp
#include <megohttp/client.hpp>

int main() {
    megohttp::Client client;
    auto r = client.get_sync("http://example.com/");
    if (!r) {
        // r.error().code() / r.error().phase() / r.error().message()
        return 1;
    }
    // 4xx/5xx are valid HTTP transactions: Result is success, the status is in head().
    const int status = r.value().head().status_code;
    const auto body  = r.value().body_text();
    return status == 200 && !body.empty() ? 0 : 1;
}
```

Callback plus cross-thread cancellation (the callback runs on the Client's I/O
thread):

```cpp
auto handle = client.get("http://example.com/",
    [](megohttp::Result<megohttp::Response> r) {
        if (!r) return;                       // Cancelled arrives here too
        // use r.value()
    });
handle.cancel();                              // any thread, idempotent
```

Request-body compression (off by default; buffered `set_body` only — a
`BodySource` is rejected with `NotImplemented` rather than silently sending
plaintext):

```cpp
megohttp::Request req(megohttp::Method::Post, "http://example.com/upload");
req.set_body("...");                                  // buffered, replayable
req.set_compress_body(megohttp::Request::Compression::Gzip);
auto r = client.request_sync(req);                    // gzip + compressed Content-Length
```

Response head before the body (a streaming download can inspect status /
Content-Type / Content-Length first; the callback itself cannot cancel the
request, use `CancelHandle` or the async form for that):

```cpp
megohttp::Request req(megohttp::Method::Get, "http://example.com/big.bin");
req.set_head_callback([](const megohttp::ResponseHead& head) {
    // Runs on the I/O thread; the reference is valid only during the call.
    // A followed redirect does not call it; a retry may call it once per attempt.
});
auto flow = std::make_shared<megohttp::Request::BodySinkFlow>();
req.set_body_sink([](megohttp::string_view) { return true; },
                  [](megohttp::VoidResult) {}, flow);
client.request_sync(req);
```

Request trailers (chunked upload only, i.e. `BodySource`; sent in the
terminating chunk):

```cpp
megohttp::Request req(megohttp::Method::Post, "http://example.com/upload");
req.set_body_source(source);                       // streaming upload
megohttp::Headers tr;
tr.add("X-Checksum", "...");                       // known up front
req.set_trailers(tr);
// Values only computable at EOF: the name must be declared in advance.
req.headers().set("trailer", "X-Body-Length");
req.set_trailer_source([]() -> megohttp::Result<megohttp::Headers> {
    megohttp::Headers h;
    h.add("X-Body-Length", "1234");
    return h;
});
client.request_sync(req);
```

File upload (`FileSource` reads on a worker thread with a bounded queue;
`attach_to` sets `Content-Length` when the size is known):

```cpp
#include <megohttp/file_source.hpp>

auto opened = megohttp::FileSource::open("big.bin");
if (!opened) return;                              // open failure is synchronous
auto file = opened.value();

megohttp::Request req(megohttp::Method::Post, "http://example.com/upload");
if (!file->attach_to(req)) return;                // Content-Length when known
auto r = client.request_sync(req);                // no file I/O on the I/O thread
```

A multipart file field can take a path directly; the builder keeps the exact
`Content-Length`:

```cpp
megohttp::MultipartBuilder form;
form.add_file_field("file", "big.bin", "application/octet-stream", "big.bin");
form.apply_to(req);
```

SSE backpressure (optional `SseFlow`; pause granularity is a line/event
boundary, retained bytes are capped at 4 MiB by default):

```cpp
megohttp::Request req(megohttp::Method::Get, "http://example.com/events");
auto flow = std::make_shared<megohttp::Request::SseFlow>();
req.set_sse_callback(
    [flow](const megohttp::SseEvent& e) {
        // Handle the event; call flow->pause() if you need to stop for a while.
        return megohttp::VoidResult{};
    },
    {},                       // SseParser::Limits, e.g. max_paused_buffer_bytes
    flow);
flow->resume();               // any thread; replays retained bytes and resumes reads
// SseSession: session->pause_receive() / resume_receive() / is_receive_paused()
```

WebSocket incremental send (one logical message, possibly many frames;
compressed per chunk when permessage-deflate is active):

```cpp
auto ws = client.open_websocket(url, ws_opts, ws_policy);
ws->send_begin(megohttp::WsMessageType::Text);
ws->send_data(megohttp::string_view("first "));    // or (const uint8_t*, size)
ws->send_data(megohttp::string_view("second"));
ws->send_end([](const megohttp::Error& e) {         // exactly once, after the last frame
    // non-empty e = the message failed; a disconnect aborts it, never replayed.
});
```

`send_data` reports synchronous rejection through `VoidResult` (not open,
`max_message_size` exceeded, queue full). Those rejections happen before
compression, so the same chunk can be retried.

Queue observability: `pending_send_bytes()` is the encoded wire bytes in the
queue (including the frame being written); `pending_send_raw_bytes()` is the
uncompressed input attributed to those frames. A compressed message is
attributed proportionally across its frames and the last frame takes the
rounding remainder; bytes zlib has consumed but not yet emitted are excluded
from the raw gauge.

WebSocket incremental receive (once set, `on_message` is not called; returning
false from `data` requests a pause):

```cpp
ws->set_incremental_message_callbacks(
    [](megohttp::WsMessageType type, bool compressed) {
        // Once per logical message; compressed is the first frame's RSV1.
    },
    [](const uint8_t* data, size_t size) {
        // Uncompressed: one frame's payload. Compressed: one frame's inflate output.
        // Valid only during this call; copy to keep. Return false to pause.
        return true;
    },
    []() {
        // Exactly once per complete message; not called on disconnect or error.
    });
ws->pause_receive();      // any thread; stops before the next data frame
ws->resume_receive();     // replays buffered frames and resumes reads
```

Receive pause granularity is a frame boundary; buffered control frames are
still delivered while paused. Pausing inside a frame (saving the inflate state)
is not implemented.

C++20 coroutines (`Task` is eager, single-consumer, has no `Task<void>`, and
there is no `spawn()`):

```cpp
megohttp::Task<int> fetch(megohttp::Client& client) {
    auto r = co_await client.get_co("http://127.0.0.1:8080/");
    co_return r ? r.value().head().status_code : -1;
}
```

## Configuration macros

CMake options turn into macros of the same name; they can also be defined
directly in header-only consumption. **Every translation unit of one program
must use the same set of configuration macros.**

| Macro | CMake default | Meaning |
|---|---|---|
| `MGHTTP_BACKEND_LIBUV` / `MGHTTP_BACKEND_ASIO` | ON / OFF | exactly one must be chosen |
| `MGHTTP_TLS_OPENSSL` / `MGHTTP_TLS_MBEDTLS` / `MGHTTP_TLS_NONE` | ON / OFF / OFF | exactly one must be chosen |
| `MGHTTP_USE_MEMESTRING` | OFF | OFF (default) keeps `std::string`, so the string layer needs no third-party code; ON switches every library-owned text type to `memepp::string` |
| `MGHTTP_USE_UVW` | ON | C++ wrapper on top of the libuv backend only |
| `MGHTTP_ENABLE_GZIP` / `MGHTTP_ENABLE_BROTLI` | ON | not defined when the library is missing, so nothing is advertised that cannot be decoded |
| `MGHTTP_ENABLE_SSE` / `MGHTTP_ENABLE_WEBSOCKET` | ON | |
| `MGHTTP_ENABLE_WEBSOCKET_DEFLATE` | ON | needs zlib; an explicit ON with WebSocket disabled is a compile error; the runtime switch is still off by default |
| `MGHTTP_ENABLE_DOT` / `MGHTTP_ENABLE_DOH` | ON | require TLS; combining either with `TLS_NONE` is a compile-time error |
| `MGHTTP_ENABLE_COROUTINES` | ON under C++20 | explicitly enabling it in a C++17 build is a configuration error, never a silent downgrade |
| `MGHTTP_BUILD_TESTS` / `MGHTTP_BUILD_EXAMPLES` | ON | |

Macros are interpreted **numerically**: undefined and `=0` both mean off, `=1`
means on.

## Known limitations

- HTTP/1.1 only; DoH endpoints must support HTTP/1.1 as well.
- Environment-variable proxies require an explicit
  `ProxyOptions::from_env = true`; PAC / NTLM / Kerberos are not supported.
- Cookies live in memory only and are never written to disk
  (`export_all()` / `import_all()` are the caller's responsibility).
- A non-ASCII host name must be converted to an IDNA A-label by the caller;
  `parse_url` rejects it outright.
- No progress callbacks, no `Client::wait_for_complete()`, no `stats()`.
- A `BodySink` returning `false` always means pause, so a streaming download
  must attach a `BodySinkFlow`; submitting without one fails synchronously with
  `InvalidArgument` instead of silently continuing. Multipart needs a
  `MultipartSinkFlow`, SSE needs `Request::SseFlow` (or
  `SseSession::pause_receive`).
- `FileSource` uses one background reader thread and a bounded queue of
  `max_queued_chunks` per instance; opening is synchronous (normally from the
  submitting thread) while `BodySource` itself performs no file I/O. A
  non-seekable source cannot provide `Content-Length` and falls back to chunked.
- SSE pause granularity is a line/event boundary, not inside a line; retained
  bytes while paused are bounded by `max_paused_buffer_bytes` (4 MiB default).
- Multipart responses do not decode a part's `Content-Transfer-Encoding` or its
  own `Content-Encoding`; those headers are preserved verbatim.
- WebSocket incremental receive pauses at data-frame boundaries (a frame's
  inflate output is produced as one chunk); pausing inside a frame is not
  implemented. Sending while disconnected fails immediately (`WsNotOpen`) and
  is never queued.
- `permessage-deflate` is off at runtime by default, and compression leaks
  length information; WSS does not remove that side channel.
- For DoT/DoH through a proxy, the endpoint name is handed to the proxy;
  SOCKS5 local-DNS DoT requires `bootstrap_ip` to be an IP literal, and DoH
  remains subject to the underlying Client's SOCKS5 local-DNS restriction.

## Layout

```
include/megohttp/   the library (headers only)
tests/              unit / integration / matrix / per-header include / install-consumer
examples/           examples (feature-gated)
cmake/              package config and cross-compile toolchains
.github/            CI workflows
CMakeLists.txt      the single build entry point
```

