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

def kill_process_tree(pid):
    if os.name == 'nt':
        subprocess.run(['taskkill', '/F', '/T', '/PID', str(pid)],
                       capture_output=True)

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
        p = subprocess.Popen([e], cwd=os.path.dirname(e),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out_b, err_b = p.communicate(timeout=200)
            rc = p.returncode
            out = out_b.decode('utf-8', 'replace') + err_b.decode('utf-8', 'replace')
        except subprocess.TimeoutExpired:
            kill_process_tree(p.pid)
            try:
                out_b, err_b = p.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                out_b, err_b = p.communicate()
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
