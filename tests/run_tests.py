#!/usr/bin/env python3
"""Run every MegoHttp test binary and report pass/fail."""
import os, subprocess, sys, glob
TIMEOUT_S = 120
RETRY_ON_TIMEOUT = {"test_core", "test_multi_tu"}

def discover_tests(build_dir):
    pattern = os.path.join(build_dir, "tests", "test_*.exe")
    return sorted(os.path.basename(p)[:-4] for p in glob.glob(pattern))

def run_one(build_dir, name):
    exe = os.path.join(build_dir, "tests", f"{name}.exe")
    if not os.path.exists(exe):
        return ("MISSING", f"{name}: binary not found")
    try:
        p = subprocess.run([exe], capture_output=True, timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", f"{name}: exceeded {TIMEOUT_S}s")
    out = p.stdout.decode("utf-8", "replace").strip()
    # Catch2 v3 format: "All tests passed" appears when there is at least one
    # assertion; a suite that only skips all cases still exits 0 and prints
    # "test cases: N | N passed".
    if "All tests passed" in out and p.returncode == 0:
        return ("PASS", f"{name}: {out.splitlines()[-1]}")
    if "test cases:" in out and "passed" in out and p.returncode == 0:
        return ("PASS", f"{name}: {out.splitlines()[-1]}")
    if "FAILED:" in out:
        return ("FAIL", f"{name}: {out[-800:]}")
    # test_multi_tu is not a Catch2 binary: it prints [PASS] and checks linkage.
    if "[PASS]" in out and p.returncode == 0:
        return ("PASS", f"{name}: {out.splitlines()[-1]}")
    return ("FAIL", f"{name}: rc={p.returncode}")

def main():
    if len(sys.argv) < 2:
        print("usage: run_tests.py <build-dir> [...]")
        return 2
    overall = 0
    for build_dir in sys.argv[1:]:
        print("")
        print(f"--- {build_dir} ---")
        tests = discover_tests(build_dir)
        bad = 0
        for name in tests:
            status, detail = run_one(build_dir, name)
            print(f"  {status:8s} {detail}")
            if status != "PASS": bad += 1
        overall += bad
        print(f"  => {len(tests)-bad}/{len(tests)} suites passed")
    print("")
    print("ALL SUITES PASSED" if overall == 0 else f"{overall} SUITE(S) FAILED")
    return 0 if overall == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
