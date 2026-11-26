#!/usr/bin/env python3
"""Scriptable local proxy for the S5.4 proxy tests.

Four modes, all on one dynamic port so a test can point a single ClientOptions
at it and still exercise the exact transport it means to:

  --mode forward   Plain HTTP forward proxy. For an http:// target it reads the
                   absolute-form request line, relays to the target, and streams
                   the answer back. Records the request line and headers it saw.
  --mode https     TLS listener wrapping the same forward/CONNECT logic, so the
                   client must do TLS *to the proxy* (task book 10.2).
  --mode socks5    SOCKS5 server, RFC 1928 + optional RFC 1929 auth.

The recorder is the point: a proxy test that only asserts "the request
succeeded" cannot tell a correct absolute-form relay from a client that ignored
the proxy and connected directly. Every mode therefore writes what it observed
(absolute-form target, CONNECT authority, Proxy-Authorization presence, SOCKS5
ATYP and destination) so the C++ side can assert on it.

Deliberately built on the standard library only, and it does NOT reuse the
client's own parser: a proxy that shares the client's parser would mask a
framing bug in both.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import time
import sys
import threading

READY_PREFIX = "READY"


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def recv_until(sock, marker, prefix=b""):
    """Read until `marker` appears, starting from `prefix`.

    The prefix matters: the connection dispatcher reads the first chunk to decide
    which role the connection has, so part of the head may already be consumed by
    the time a handler starts. Reading only the remainder would then never see
    the marker.
    """
    buf = prefix
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def parse_head(raw):
    """Split a request head into (request_line, headers dict, leftover)."""
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        head, rest = raw, b""
    else:
        head, rest = raw[:sep], raw[sep + 4:]
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1") if lines else ""
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    return request_line, headers, rest


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def add(self, entry):
        with self.lock:
            self.requests.append(entry)

    def snapshot(self):
        with self.lock:
            return list(self.requests)


def relay(src, dst):
    """Copy bytes one way until EOF. Owns the sockets."""
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def connect_target(host, port, name_map=None):
    """Connect to the target, honouring a test-only name map.

    A SOCKS5 test needs the CONNECT command to carry a DOMAIN-type address, but
    the proxy still has to reach a fixture origin that only listens on loopback.
    Mapping the synthetic name here keeps the wire format realistic without
    depending on this host's resolver.
    """
    if name_map and host in name_map:
        host = name_map[host]
    return socket.create_connection((host, port), timeout=10)


def handle_forward(client, recorder, use_tls, require_auth=False, first=b""):
    """Plain forward proxy: absolute-form request line, then relay."""
    raw = recv_until(client, b"\r\n\r\n", first)
    request_line, headers, leftover = parse_head(raw)

    if not request_line:
        client.close()
        return

    method, target, version = (request_line.split(" ") + ["", ""])[:3]

    entry = {
        "kind": "forward",
        "tls": use_tls,
        "method": method,
        "target": target,
        "absolute_form": target.startswith("http://"),
        "proxy_authorization": headers.get("proxy-authorization"),
        "has_target_authorization": "authorization" in headers,
        "headers": headers,
    }
    recorder.add(entry)

    # --require-auth means the proxy DEMANDS credentials. Checking only when a
    # header happens to be present would let a client that sends none through,
    # which is the opposite of what the test needs to prove.
    if require_auth:
        expect = "Basic " + base64.b64encode(b"alice:s3cret").decode()
        if headers.get("proxy-authorization") != expect:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                           b"Proxy-Authenticate: Basic realm=\"test\"\r\n"
                           b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            client.close()
            return

    if not target.startswith("http://"):
        client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                       b"Connection: close\r\n\r\n")
        client.close()
        return

    authority = target[len("http://"):].split("/")[0]
    host, _, port_s = authority.partition(":")
    port = int(port_s or "80")

    try:
        upstream = connect_target(host, port)
    except OSError:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                       b"Connection: close\r\n\r\n")
        client.close()
        return

    # Rebuild the request in origin-form for the target, dropping the proxy-only
    # header. This is what a real forward proxy does, and it is why the test can
    # assert the target never saw Proxy-Authorization.
    path = target[len("http://") + len(authority):] or "/"
    rebuilt = [f"{method} {path} {version}"]
    for name, value in headers.items():
        if name in ("proxy-authorization", "proxy-connection"):
            continue
        rebuilt.append(f"{name}: {value}")
    upstream.sendall("\r\n".join(rebuilt).encode("latin-1") + b"\r\n\r\n" + leftover)

    t1 = threading.Thread(target=relay, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        client.close()
    except OSError:
        pass
    try:
        upstream.close()
    except OSError:
        pass


def handle_connect(client, recorder, use_tls, require_auth=False, first=b"",
                   forced_status=None, name_map=None):
    """CONNECT tunnel: 2xx only after the tunnel is real."""
    raw = recv_until(client, b"\r\n\r\n", first)
    request_line, headers, leftover = parse_head(raw)
    method, target, _ = (request_line.split(" ") + ["", ""])[:3]

    if forced_status is not None:
        # Feed the client a deliberately broken status line so its parser is
        # exercised with input no real proxy would send.
        client.sendall(b"HTTP/1.1 " + forced_status.encode() + b" Whatever\r\n"
                       b"Content-Length: 0\r\n\r\n")
        client.close()
        return

    recorder.add({
        "kind": "connect",
        "tls": use_tls,
        "method": method,
        "target": target,
        "proxy_authorization": headers.get("proxy-authorization"),
        "has_target_authorization": "authorization" in headers,
        "headers": headers,
    })

    if require_auth:
        expect = "Basic " + base64.b64encode(b"alice:s3cret").decode()
        if headers.get("proxy-authorization") != expect:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                           b"Proxy-Authenticate: Basic realm=\"test\"\r\n"
                           b"Content-Length: 0\r\n\r\n")
            client.close()
            return

    host, _, port_s = target.partition(":")
    port = int(port_s or "443")

    try:
        upstream = connect_target(host, port, name_map)
    except OSError:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        client.close()
        return

    # 200 only now: the tunnel is established, so anything the client sends next
    # (its target TLS ClientHello) has somewhere to go.
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    if leftover:
        upstream.sendall(leftover)

    t1 = threading.Thread(target=relay, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (client, upstream):
        try:
            s.close()
        except OSError:
            pass


def recv_exact(sock, n, raw_log=None):
    """Read exactly n bytes, appending whatever arrives to raw_log.

    recv() may return a short count, and a fixture that assumes otherwise fails
    on the one run where the peer happens to split its write.
    """
    """Read exactly n bytes, or less if the peer closes. recv() is allowed to
    return a short count, and a fixture that assumes otherwise fails on the one
    run where the peer happens to split the write."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def handle_socks5(client, recorder, require_auth, name_map=None):
    """RFC 1928 greeting, optional RFC 1929 auth, then CONNECT."""
    greeting = recv_exact(client, 2)
    if len(greeting) < 2 or greeting[0] != 0x05:
        client.close()
        return
    nmethods = greeting[1]
    methods = recv_exact(client, nmethods) if nmethods else b""

    recorder.add({"kind": "socks5_greeting", "methods": list(methods)})

    if require_auth:
        if 0x02 not in methods:
            client.sendall(bytes([0x05, 0xFF]))
            client.close()
            return
        client.sendall(bytes([0x05, 0x02]))

        ver = recv_exact(client, 2)
        if len(ver) < 2 or ver[0] != 0x01:
            client.close()
            return
        ulen = ver[1]
        user = recv_exact(client, ulen)
        plen = recv_exact(client, 1)
        if not plen:
            client.close()
            return
        password = recv_exact(client, plen[0])

        recorder.add({"kind": "socks5_auth",
                      "user": user.decode("latin-1"),
                      "password": password.decode("latin-1")})

        if user != b"alice" or password != b"s3cret":
            client.sendall(bytes([0x01, 0x01]))
            client.close()
            return
        client.sendall(bytes([0x01, 0x00]))
    else:
        if 0x00 not in methods:
            client.sendall(bytes([0x05, 0xFF]))
            client.close()
            return
        client.sendall(bytes([0x05, 0x00]))

    head = recv_exact(client, 4)
    if len(head) < 4 or head[0] != 0x05 or head[1] != 0x01:
        client.close()
        return

    atyp = head[3]
    if atyp == 0x01:
        raw = recv_exact(client, 4)
        if len(raw) < 4:
            client.close()
            return
        addr = socket.inet_ntoa(raw)
        kind = "ipv4"
    elif atyp == 0x04:
        raw = recv_exact(client, 16)
        if len(raw) < 16:
            client.close()
            return
        addr = socket.inet_ntop(socket.AF_INET6, raw)
        kind = "ipv6"
    elif atyp == 0x03:
        nb = recv_exact(client, 1)
        if not nb:
            client.close()
            return
        nlen = nb[0]
        addr = recv_exact(client, nlen).decode("latin-1")
        kind = "domain"
    else:
        client.sendall(bytes([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        client.close()
        return

    raw_port = recv_exact(client, 2)
    if len(raw_port) < 2:
        client.close()
        return
    port = int.from_bytes(raw_port, "big")
    # The recorded ATYP is what proves remote DNS handed over a NAME and that
    # local DNS handed over an address instead.
    recorder.add({"kind": "socks5_connect", "atyp": kind, "addr": addr, "port": port})

    try:
        upstream = connect_target(addr, port, name_map)
    except OSError:
        client.sendall(bytes([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        client.close()
        return

    client.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    t1 = threading.Thread(target=relay, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (client, upstream):
        try:
            s.close()
        except OSError:
            pass


def _parent_alive(pid):
    """Best-effort liveness check for the C++ test process."""
    if pid <= 0:
        return True
    if os.name == "nt":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return bool(ok) and code.value == STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _watch_parent(pid):
    """Exit if the test executable disappears.

    The Job Object covers normal teardown, but a force-killed test process or a
    nested-job host can leave this proxy orphaned. The child must not outlive
    the process that spawned it.
    """
    while True:
        if not _parent_alive(pid):
            os._exit(0)
        time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["forward", "connect", "socks5"], default="forward")
    ap.add_argument("--parent-pid", type=int, default=0,
                    help="Exit when this process disappears")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    ap.add_argument("--require-auth", action="store_true")
    # NAME=IP pairs; lets a test use a synthetic target name while the fixture
    # origin stays on loopback.
    ap.add_argument("--map", action="append", default=[])
    # Seconds to stall between accept() and the TLS handshake. Used to prove the
    # connection-stage deadline covers the PROXY handshake: the TCP connect has
    # already succeeded, so nothing but that deadline can end the request.
    ap.add_argument("--tls-handshake-delay", type=float, default=0.0)
    # Overrides the CONNECT status line verbatim. Used to feed the client a
    # malformed status code (huge number, non-numeric) instead of a real 2xx.
    ap.add_argument("--connect-status")
    args = ap.parse_args()

    if args.parent_pid:
        threading.Thread(target=_watch_parent, args=(args.parent_pid,),
                         daemon=True).start()

    name_map = {}
    for pair in args.map:
        name, _, ip = pair.partition("=")
        if name and ip:
            name_map[name] = ip

    ctx = None
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(16)
    port = lsock.getsockname()[1]

    recorder = Recorder()

    # Observation dump: the C++ side reads this file after the request settles,
    # because a proxy cannot answer questions about what it saw any other way.
    def dump_path():
        return os.environ.get("MEGOHTTP_PROXY_RECORDING")

    def dump_loop():
        while True:
            threading.Event().wait(0.05)
            path = dump_path()
            if not path:
                continue
            try:
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(recorder.snapshot(), fh)
                os.replace(tmp, path)
            except OSError:
                pass

    threading.Thread(target=dump_loop, daemon=True).start()

    print(f"{READY_PREFIX} {os.getpid()} {port}", flush=True)

    while True:
        try:
            client, _ = lsock.accept()
        except OSError:
            break
        try:
            if ctx is not None:
                if args.tls_handshake_delay > 0:
                    # Stall BEFORE touching TLS, so the client sees an accepted
                    # TCP connection and a silent peer: exactly the state a
                    # bounded connection stage has to escape from.
                    time.sleep(args.tls_handshake_delay)
                client = ctx.wrap_socket(client, server_side=True)

            # One connection, one role. An SSLSocket rejects recv() with flags,
            # so peeking is unavailable; instead the role is decided from the
            # configured mode, and an HTTP proxy additionally looks at the first
            # request line (a CONNECT tunnel starts with a CONNECT method).
            #
            # The bytes read here are handed to the handler as `first` and the
            # handler treats them as the head of its stream.
            if args.mode == "socks5":
                threading.Thread(target=handle_socks5,
                                 args=(client, recorder, args.require_auth, name_map),
                                 daemon=True).start()
            else:
                first = client.recv(4096)
                if not first:
                    client.close()
                    continue
                if first[:7].upper() == b"CONNECT":
                    threading.Thread(target=handle_connect,
                                     args=(client, recorder, ctx is not None,
                                           args.require_auth, first,
                                           args.connect_status, name_map),
                                     daemon=True).start()
                else:
                    threading.Thread(target=handle_forward,
                                     args=(client, recorder, ctx is not None,
                                           args.require_auth, first),
                                     daemon=True).start()
        except (OSError, ssl.SSLError) as exc:
            log(f"accept failed: {exc}")
            try:
                client.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
