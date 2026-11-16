"""Run the full config matrix and write results to _matrix.json.

Lives in a file rather than an inline execute_code cell because the whole sweep
takes longer than one cell's timeout.
"""
import glob
import json
import os
import re
import subprocess
import sys

R = r'D:\_mego_openlib\MegoHttp'
# subdir is '' for Ninja (single-config) and 'Release' for the VS generator.
# Getting this wrong reports the PREVIOUS run's numbers, because the glob simply
# finds nothing and the suite count silently drops.
CONFIGS = [
    ('build_msvc', ''),
    ('build_msvc_std', ''),
    ('build_msvc_no_uvw', ''),
    ('build_msvc_no_uvw_std', ''),
    ('build_msvc_asio', ''),
    ('build_msvc_asio_std', ''),
    ('build_msvc_mbedtls', 'Release'),
    ('build_tls_none', 'Release'),
]


def run(name, subdir):
    exes = sorted(glob.glob(os.path.join(R, name, 'tests', subdir, 'test_*.exe')))
    fa = tc = 0
    fails = []
    for e in exes:
        try:
            q = subprocess.run([e], cwd=os.path.dirname(e), capture_output=True,
                               text=True, errors='replace', timeout=200)
            rc, out = q.returncode, q.stdout + q.stderr
        except subprocess.TimeoutExpired:
            rc, out = -1, ''
            fails.append(os.path.basename(e) + '(timeout)')
        if rc != 0:
            fails.append(os.path.basename(e))
        m = re.search(r'\((\d+) assertions in (\d+) test cases?\)', out)
        if m:
            fa += int(m.group(1))
            tc += int(m.group(2))
    return {'name': name, 'suites': len(exes), 'assertions': fa,
            'cases': tc, 'fails': fails}


results = []
for name, sub in CONFIGS:
    if not os.path.isdir(os.path.join(R, name)):
        results.append({'name': name, 'missing': True})
        print(name, 'MISSING', flush=True)
        continue
    r = run(name, sub)
    results.append(r)
    print(r, flush=True)

with open(os.path.join(R, '_matrix.json'), 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=1)
print('DONE', flush=True)
