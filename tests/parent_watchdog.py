"""Parent-liveness watchdog shared by the Python test fixtures.

The C++ test executables kill their server by PID from a destructor. A
force-killed or crashed test binary never runs that destructor, so every
long-lived fixture must also notice that the parent disappeared and exit on
its own; otherwise its accept loop outlives the suite and keeps the port.

The child must not outlive the process that spawned it. This is a safety net
for abnormal teardown only -- normal teardown still kills by PID.

Usage in a fixture:

    import parent_watchdog
    ...
    parent_watchdog.add_argument(ap)
    args = ap.parse_args()
    parent_watchdog.start(args.parent_pid)

`--parent-pid 0` (the default) disables the watchdog, so a server started by
hand behaves exactly as before.
"""
import os
import threading
import time


def add_argument(ap):
    """Register the `--parent-pid` option on an ArgumentParser."""
    ap.add_argument("--parent-pid", type=int, default=0,
                    help="Exit when this process disappears")


def _parent_alive(pid):
    """Best-effort liveness check for the spawning test process."""
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


def _watch(pid):
    while True:
        if not _parent_alive(pid):
            os._exit(0)
        time.sleep(1)


def start(pid):
    """Start the watchdog thread. No-op when pid is 0 or negative."""
    if pid and pid > 0:
        threading.Thread(target=_watch, args=(pid,), daemon=True).start()
