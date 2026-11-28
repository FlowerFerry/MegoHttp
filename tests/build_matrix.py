"""Rebuild every config, then run the full matrix.

run_matrix.py only RUNS existing binaries; a stale build tree silently reports
the previous numbers. This script rebuilds first so a green matrix actually
reflects the current source.
"""
import io
import os
import subprocess
import sys

# Never hog a shared workstation: a quarter of the logical cores, at least one
# core left free (16 -> 4, 8 -> 2, 6 -> 1).
JOBS = max(1, min((os.cpu_count() or 4) // 4, (os.cpu_count() or 4) - 2))

R = r'D:\_mego_openlib\MegoHttp'
VCVARS = r'D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'

CONFIGS = [
    # --- libuv + OpenSSL -----------------------------------------------------
    ('build_msvc', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_USE_MEMESTRING=ON'),
    ('build_msvc_std', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_USE_MEMESTRING=OFF'),
    # uvw-off dependency-trimming regressions of the two cells above
    ('build_msvc_no_uvw', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=ON'),
    ('build_msvc_no_uvw_std', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=OFF'),
    # --- Asio + OpenSSL ------------------------------------------------------
    ('build_msvc_asio', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=ON'),
    ('build_msvc_asio_std', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=OFF'),
    # --- libuv + mbedTLS -----------------------------------------------------
    ('build_msvc_mbedtls', '-G "Visual Studio 17 2022" -A x64 -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=ON -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=ON'),
    ('build_msvc_mbedtls_std', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=ON -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=OFF'),
    # --- libuv + TLS_NONE ----------------------------------------------------
    ('build_tls_none', '-G "Visual Studio 17 2022" -A x64 -DMGHTTP_TLS_NONE=ON -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=OFF -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=OFF -DMGHTTP_ENABLE_DOT=OFF -DMGHTTP_ENABLE_DOH=OFF'),
    ('build_msvc_tls_none_memepp', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_TLS_NONE=ON -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=OFF -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=ON -DMGHTTP_ENABLE_DOT=OFF -DMGHTTP_ENABLE_DOH=OFF'),
    # --- Asio + mbedTLS ------------------------------------------------------
    ('build_msvc_asio_mbedtls', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=ON -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=ON'),
    ('build_msvc_asio_mbedtls_std', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=ON -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=OFF'),
    # --- Asio + TLS_NONE -----------------------------------------------------
    ('build_msvc_asio_tls_none', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_TLS_NONE=ON -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=OFF -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=ON -DMGHTTP_ENABLE_DOT=OFF -DMGHTTP_ENABLE_DOH=OFF'),
    ('build_msvc_asio_tls_none_std', '-G Ninja -DCMAKE_BUILD_TYPE=Release -DMGHTTP_BACKEND_LIBUV=OFF -DMGHTTP_BACKEND_ASIO=ON -DMGHTTP_TLS_NONE=ON -DMGHTTP_TLS_OPENSSL=OFF -DMGHTTP_TLS_MBEDTLS=OFF -DMGHTTP_USE_UVW=OFF -DMGHTTP_USE_MEMESTRING=OFF -DMGHTTP_ENABLE_DOT=OFF -DMGHTTP_ENABLE_DOH=OFF'),
]


for name, extra in CONFIGS:
    bat = os.path.join(R, f'_cfg_{name}.bat')
    cfgdir = name
    lines = [
        '@echo off',
        f'call "{VCVARS}" >nul 2>&1',
        f'cd /d "{R}"',
        f'cmake -S . -B {cfgdir} {extra} -DMGHTTP_BUILD_TESTS=ON > log_{name}.txt 2>&1',
        'if errorlevel 1 exit /b 1',
        f'cmake --build {cfgdir} --config Release -j{JOBS} >> log_{name}.txt 2>&1',
        'exit /b %errorlevel%',
    ]
    io.open(bat, 'w', encoding='ascii', newline='\r\n').write('\r\n'.join(lines) + '\r\n')
    p = subprocess.run(['cmd', '/c', bat], cwd=R, capture_output=True, timeout=900)
    log = io.open(os.path.join(R, f'log_{name}.txt'), encoding='utf-8', errors='replace').read()
    errs = [l for l in log.splitlines() if 'error C' in l or 'CMake Error' in l]
    if p.returncode != 0:
        print(f'{name:24s} BUILD FAIL ({len(errs)})', flush=True)
        for e in errs[:4]:
            print('   ', e[:180], flush=True)
        sys.exit(1)
    print(f'{name:24s} build OK', flush=True)

print('ALL BUILDS OK', flush=True)
