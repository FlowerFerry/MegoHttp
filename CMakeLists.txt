cmake_minimum_required(VERSION 3.14)

project(MegoHttp VERSION 0.1.0 LANGUAGES CXX)

# C++ Standard. C++17 is the baseline; a caller may ask for C++20 to get the
# coroutine surface (MGHTTP_ENABLE_COROUTINES then defaults ON). Do not
# overwrite an explicit -DCMAKE_CXX_STANDARD.
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(MGHTTP_BACKEND_LIBUV "Use libuv as network backend" ON)
option(MGHTTP_BACKEND_ASIO "Use standalone Asio as network backend" OFF)

option(MGHTTP_TLS_NONE "Disable TLS" OFF)
option(MGHTTP_TLS_OPENSSL "Use OpenSSL for TLS" ON)
option(MGHTTP_TLS_MBEDTLS "Use mbedTLS for TLS" OFF)

option(MGHTTP_USE_MEMESTRING "Use MemeString instead of std::string" ON)

option(MGHTTP_ENABLE_GZIP "Enable gzip content encoding" ON)
option(MGHTTP_ENABLE_BROTLI "Enable Brotli content encoding" ON)
option(MGHTTP_ENABLE_SSE "Enable SSE support" ON)
option(MGHTTP_ENABLE_WEBSOCKET "Enable WebSocket support" ON)
option(MGHTTP_ENABLE_WEBSOCKET_DEFLATE "Enable WebSocket permessage-deflate" ON)
option(MGHTTP_ENABLE_DOT "Enable DNS over TLS" ON)
option(MGHTTP_ENABLE_DOH "Enable DNS over HTTPS" ON)

option(MGHTTP_USE_UVW "Use uvw (C++ wrapper) on top of libuv" ON)
option(MGHTTP_BUILD_TESTS "Build tests" ON)
option(MGHTTP_BUILD_EXAMPLES "Build examples" ON)

# Backend selection validation
if(MGHTTP_BACKEND_LIBUV AND MGHTTP_BACKEND_ASIO)
    message(FATAL_ERROR "Cannot enable both LIBUV and ASIO backends")
endif()

if(NOT MGHTTP_BACKEND_LIBUV AND NOT MGHTTP_BACKEND_ASIO)
    message(FATAL_ERROR "Must enable at least one backend (LIBUV or ASIO)")
endif()

# uvw wraps libuv, so it cannot be selected without that backend.
if(MGHTTP_USE_UVW AND NOT MGHTTP_BACKEND_LIBUV)
    message(FATAL_ERROR "MGHTTP_USE_UVW requires MGHTTP_BACKEND_LIBUV")
endif()

# TLS selection validation
set(TLS_COUNT 0)
if(MGHTTP_TLS_NONE)
    math(EXPR TLS_COUNT "${TLS_COUNT} + 1")
endif()
if(MGHTTP_TLS_OPENSSL)
    math(EXPR TLS_COUNT "${TLS_COUNT} + 1")
endif()
if(MGHTTP_TLS_MBEDTLS)
    math(EXPR TLS_COUNT "${TLS_COUNT} + 1")
endif()

if(TLS_COUNT EQUAL 0)
    message(FATAL_ERROR "Must select one TLS backend (NONE, OPENSSL, or MBEDTLS)")
endif()

if(TLS_COUNT GREATER 1)
    message(FATAL_ERROR "Cannot enable multiple TLS backends")
endif()

# DoT/DoH requires TLS
if(MGHTTP_ENABLE_DOT AND MGHTTP_TLS_NONE)
    message(FATAL_ERROR "DoT requires TLS (MGHTTP_TLS_NONE cannot be used with MGHTTP_ENABLE_DOT)")
endif()

if(MGHTTP_ENABLE_DOH AND MGHTTP_TLS_NONE)
    message(FATAL_ERROR "DoH requires TLS (MGHTTP_TLS_NONE cannot be used with MGHTTP_ENABLE_DOH)")
endif()

# WebSocket DEFLATE requires WebSocket
if(MGHTTP_ENABLE_WEBSOCKET_DEFLATE AND NOT MGHTTP_ENABLE_WEBSOCKET)
    message(FATAL_ERROR "WebSocket DEFLATE requires WebSocket support")
endif()

# C++20 coroutine detection
include(CheckCXXSourceCompiles)

check_cxx_source_compiles("
#include <coroutine>
int main() { return 0; }
" MGHTTP_HAS_COROUTINE_HEADER)

if(MGHTTP_HAS_COROUTINE_HEADER AND CMAKE_CXX_STANDARD GREATER_EQUAL 20)
    set(MGHTTP_ENABLE_COROUTINES_DEFAULT ON)
else()
    set(MGHTTP_ENABLE_COROUTINES_DEFAULT OFF)
endif()

option(MGHTTP_ENABLE_COROUTINES "Enable C++20 coroutine support" ${MGHTTP_ENABLE_COROUTINES_DEFAULT})

if(MGHTTP_ENABLE_COROUTINES AND NOT MGHTTP_HAS_COROUTINE_HEADER)
    message(FATAL_ERROR "C++20 coroutines requested but <coroutine> header not available")
endif()

# The header existing is not enough: the compiler must also be in C++20 mode.
# Asking for coroutines under C++17 is a configuration error, not a silent
# downgrade (task book 3.12).
if(MGHTTP_ENABLE_COROUTINES AND CMAKE_CXX_STANDARD LESS 20)
    message(FATAL_ERROR
        "MGHTTP_ENABLE_COROUTINES=ON requires CMAKE_CXX_STANDARD >= 20 "
        "(current: ${CMAKE_CXX_STANDARD}). Reconfigure with -DCMAKE_CXX_STANDARD=20.")
endif()

# Print configuration
message(STATUS "MegoHttp Configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Backend LIBUV: ${MGHTTP_BACKEND_LIBUV}")
message(STATUS "  Backend ASIO: ${MGHTTP_BACKEND_ASIO}")
message(STATUS "  TLS NONE: ${MGHTTP_TLS_NONE}")
message(STATUS "  TLS OpenSSL: ${MGHTTP_TLS_OPENSSL}")
message(STATUS "  TLS mbedTLS: ${MGHTTP_TLS_MBEDTLS}")
message(STATUS "  Use MemeString: ${MGHTTP_USE_MEMESTRING}")
message(STATUS "  Enable gzip: ${MGHTTP_ENABLE_GZIP}")
message(STATUS "  Enable Brotli: ${MGHTTP_ENABLE_BROTLI}")
message(STATUS "  Enable SSE: ${MGHTTP_ENABLE_SSE}")
message(STATUS "  Enable WebSocket: ${MGHTTP_ENABLE_WEBSOCKET}")
message(STATUS "  Enable WebSocket DEFLATE: ${MGHTTP_ENABLE_WEBSOCKET_DEFLATE}")
message(STATUS "  Enable DoT: ${MGHTTP_ENABLE_DOT}")
message(STATUS "  Enable DoH: ${MGHTTP_ENABLE_DOH}")
message(STATUS "  Enable Coroutines: ${MGHTTP_ENABLE_COROUTINES}")

# MemeString ships its prebuilt runtime next to the source tree; deps/MemeString is
# a checkout without build artifacts. Allow either location.
set(MEMESTRING_BIN_DIR "${MEMESTRING_ROOT}")
# The checkout at deps/MemeString carries no build artifacts; the built runtime
# lives wherever the MemeString project was built. Override with
# -DMEMESTRING_RUNTIME=<path to liblibmeme_string.dll> when the layout differs.
if(NOT MEMESTRING_RUNTIME)
    if(MSVC)
        # Prefer the MSVC-built runtime: a MinGW-built MemeString DLL faults at
        # process exit under this machine's sandboxed environment, and its C++
        # ABI does not match an MSVC consumer anyway.
        set(_mm_candidates
            "${MEMESTRING_ROOT}/../MemeString/build/Release/libmeme_string.dll"
            "D:/_mego_openlib/MemeString/build/Release/libmeme_string.dll"
            "${MEMESTRING_ROOT}/liblibmeme_string.dll"
            "D:/_mego_openlib/MemeString/liblibmeme_string.dll")
    else()
        set(_mm_candidates
            "${MEMESTRING_ROOT}/liblibmeme_string.dll"
            "${MEMESTRING_ROOT}/../MemeString/liblibmeme_string.dll"
            "D:/_mego_openlib/MemeString/liblibmeme_string.dll"
            "D:/_mego_openlib/MemeString/build_verify/liblibmeme_string.dll")
    endif()
    foreach(candidate IN LISTS _mm_candidates)
        if(EXISTS "${candidate}")
            set(MEMESTRING_RUNTIME "${candidate}")
            break()
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Dependencies
#
# Versions are pinned to what deps/ contains and what has actually been built and
# tested here. FetchContent is used only when the in-tree copy is absent, so a
# normal checkout builds offline.
# ---------------------------------------------------------------------------

set(MGHTTP_DEPS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps")

# The prebuilt dependency trees are per-toolchain. MSVC objects cannot be linked
# into a MinGW image (and vice versa) -- different name mangling, different CRT,
# different struct layouts. Pick the tree matching the active compiler.
if(MSVC)
    set(MGHTTP_DEP_BUILD "build_msvc")
else()
    set(MGHTTP_DEP_BUILD "build_mingw")
endif()
message(STATUS "Dependency build tree: ${MGHTTP_DEP_BUILD}")

# fmt's Unicode support requires /utf-8 on MSVC, and the sources are UTF-8
# without BOM, so the default code page (936 here) would misread them.
if(MSVC)
    add_compile_options(/utf-8)
endif()

# fmt is the only formatter used anywhere in the library.
set(FMT_ROOT "${MGHTTP_DEPS_DIR}/fmt-12.2.0")
if(MSVC)
    set(FMT_LIB "${FMT_ROOT}/${MGHTTP_DEP_BUILD}/Release/fmt.lib")
else()
    set(FMT_LIB "${FMT_ROOT}/${MGHTTP_DEP_BUILD}/libfmt.a")
endif()
if(EXISTS "${FMT_LIB}")
    set(MGHTTP_FMT_AVAILABLE ON)
    message(STATUS "fmt: in-tree ${FMT_LIB}")
else()
    find_package(fmt CONFIG QUIET)
    set(MGHTTP_FMT_AVAILABLE ${fmt_FOUND})
endif()
if(NOT MGHTTP_FMT_AVAILABLE)
    message(FATAL_ERROR "fmt is required but was not found (expected ${FMT_ROOT} or a system package)")
endif()

if(MGHTTP_USE_UVW)
    set(UVW_ROOT "${MGHTTP_DEPS_DIR}/uvw-3.4.0_libuv_v1.48")
    if(EXISTS "${UVW_ROOT}/src/uvw.hpp")
        set(MGHTTP_UVW_AVAILABLE ON)
        message(STATUS "uvw: in-tree ${UVW_ROOT}/src")
    else()
        message(FATAL_ERROR "MGHTTP_USE_UVW=ON but uvw is missing at ${UVW_ROOT}")
    endif()
endif()


if(MGHTTP_BACKEND_LIBUV)
    # In-tree libuv (1.53.0) built as a static library.
    set(LIBUV_ROOT "${MGHTTP_DEPS_DIR}/libuv-1.53.0")
    if(EXISTS "${LIBUV_ROOT}/include/uv.h")
        if(MSVC)
            set(LIBUV_LIB "${LIBUV_ROOT}/${MGHTTP_DEP_BUILD}/Release/libuv.lib")
        elseif(WIN32)
            set(LIBUV_LIB "${LIBUV_ROOT}/${MGHTTP_DEP_BUILD}/libuv.a")
        else()
            set(LIBUV_LIB "${LIBUV_ROOT}/${MGHTTP_DEP_BUILD}/libuv_a.a")
        endif()
        if(EXISTS "${LIBUV_LIB}")
            set(MGHTTP_LIBUV_AVAILABLE ON)
            message(STATUS "libuv: in-tree ${LIBUV_LIB}")
        else()
            set(MGHTTP_LIBUV_AVAILABLE OFF)
            message(STATUS "libuv headers found but library not built: ${LIBUV_LIB}")
        endif()
    else()
        find_package(libuv CONFIG QUIET)
        set(MGHTTP_LIBUV_AVAILABLE ${libuv_FOUND})
    endif()
endif()

if(MGHTTP_BACKEND_ASIO)
    set(ASIO_ROOT "${MGHTTP_DEPS_DIR}/asio-asio-1-38-0")
    if(EXISTS "${ASIO_ROOT}/asio/include/asio.hpp")
        set(MGHTTP_ASIO_AVAILABLE ON)
        message(STATUS "Asio: in-tree ${ASIO_ROOT}/asio/include")
    else()
        # Standalone Asio only -- Boost.Asio is explicitly out of scope.
        find_package(asio CONFIG QUIET)
        set(MGHTTP_ASIO_AVAILABLE ${asio_FOUND})
    endif()
endif()

if(MGHTTP_TLS_OPENSSL)
    # Now consumed by tls_stream_impl.hpp, so a missing toolkit is fatal rather
    # than a warning: silently compiling without TLS would make every https://
    # request fail at runtime with a misleading error.
    find_package(OpenSSL QUIET)
    if(NOT OpenSSL_FOUND)
        message(FATAL_ERROR
            "MGHTTP_TLS_OPENSSL=ON but OpenSSL was not found. "
            "Set CMAKE_PREFIX_PATH to an OpenSSL installation, or configure with "
            "-DMGHTTP_TLS_NONE=ON / -DMGHTTP_TLS_MBEDTLS=ON.")
    endif()
    message(STATUS "OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")
endif()

if(MGHTTP_TLS_MBEDTLS)
    # Prefer an in-tree build (deps/mbedtls-*), fall back to a system package.
    set(MBEDTLS_ROOT "${MGHTTP_DEPS_DIR}/mbedtls-3.6.7")
    if(MSVC)
        set(MBEDTLS_LIB_DIR "${MBEDTLS_ROOT}/build_msvc/library/Release")
    else()
        set(MBEDTLS_LIB_DIR "${MBEDTLS_ROOT}/build_mingw/library")
    endif()

    if(EXISTS "${MBEDTLS_ROOT}/include/mbedtls/ssl.h" AND
       EXISTS "${MBEDTLS_LIB_DIR}/mbedtls.lib")
        set(MGHTTP_MBEDTLS_AVAILABLE ON)
        add_library(mbedtls_ext STATIC IMPORTED)
        set_target_properties(mbedtls_ext PROPERTIES
            IMPORTED_LOCATION "${MBEDTLS_LIB_DIR}/mbedtls.lib")
        add_library(mbedx509_ext STATIC IMPORTED)
        set_target_properties(mbedx509_ext PROPERTIES
            IMPORTED_LOCATION "${MBEDTLS_LIB_DIR}/mbedx509.lib")
        add_library(mbedcrypto_ext STATIC IMPORTED)
        set_target_properties(mbedcrypto_ext PROPERTIES
            IMPORTED_LOCATION "${MBEDTLS_LIB_DIR}/mbedcrypto.lib")
        message(STATUS "mbedTLS: in-tree ${MBEDTLS_ROOT} (3.6.7)")
    else()
        find_package(MbedTLS QUIET)
        if(MbedTLS_FOUND)
            set(MGHTTP_MBEDTLS_AVAILABLE ON)
            message(STATUS "mbedTLS: system package")
        else()
            message(FATAL_ERROR
                "MGHTTP_TLS_MBEDTLS=ON but mbedTLS was not found. "
                "Expected ${MBEDTLS_LIB_DIR}/mbedtls.lib, or a system package. "
                "Build deps/mbedtls-3.6.7 first (see docs/process/resume-here.md).")
        endif()
    endif()
endif()

set(MEMESTRING_ROOT "${MGHTTP_DEPS_DIR}/MemeString")
if(MGHTTP_USE_MEMESTRING)
    if(NOT EXISTS "${MEMESTRING_ROOT}/include/memepp/string.hpp")
        message(FATAL_ERROR "MGHTTP_USE_MEMESTRING=ON but MemeString is missing at ${MEMESTRING_ROOT}")
    endif()
    message(STATUS "MemeString: ${MEMESTRING_ROOT}")
endif()

# zlib is needed by EITHER HTTP gzip OR WebSocket permessage-deflate; each toggles
# independently and both being off must not link it.
if(MGHTTP_ENABLE_GZIP OR MGHTTP_ENABLE_WEBSOCKET_DEFLATE)
    set(ZLIB_ROOT "${MGHTTP_DEPS_DIR}/zlib-1.3.1")
    # The plain path is needed for EXISTS(); generator expressions cannot be
    # evaluated there. The BUILD_INTERFACE wrapper is only applied when the
    # library is actually linked.
    if(MSVC)
        set(ZLIB_LIB_PATH "${ZLIB_ROOT}/${MGHTTP_DEP_BUILD}/Release/zlibstatic.lib")
    else()
        set(ZLIB_LIB_PATH "${ZLIB_ROOT}/${MGHTTP_DEP_BUILD}/libzlibstatic.a")
    endif()
    if(EXISTS "${ZLIB_LIB_PATH}")
        set(MGHTTP_ZLIB_AVAILABLE ON)
        message(STATUS "zlib: in-tree ${ZLIB_LIB}")
    else()
        find_package(ZLIB QUIET)
        set(MGHTTP_ZLIB_AVAILABLE ${ZLIB_FOUND})
    endif()
    if(NOT MGHTTP_ZLIB_AVAILABLE)
        message(STATUS "zlib not available; gzip/DEFLATE code paths must not be compiled in")
    endif()
else()
    set(MGHTTP_ZLIB_AVAILABLE OFF)
endif()

# Brotli follows the same model as zlib: a prebuilt static library under deps/,
# per toolchain. It is NOT built by this project's generator, because brotli's
# own CMakeLists needs rc.exe (absent from the Ninja toolchain here) and adding
# C sources to this tree would require enable_language(C), which trips the same
# problem.
#
# To populate deps/brotli-1.1.0/build_msvc:
#   cmake -S deps/brotli-1.1.0 -B deps/brotli-1.1.0/build_msvc \
#         -G "Visual Studio 17 2022" -A x64 \
#         -DBROTLI_DISABLE_TESTS=ON -DBROTLI_BUILD_ENCODER=OFF
#   cmake --build deps/brotli-1.1.0/build_msvc --config Release
if(MGHTTP_ENABLE_BROTLI)
    find_package(Brotli QUIET)
    if(BROTLI_FOUND AND TARGET Brotli::Decoder)
        set(MGHTTP_BROTLI_AVAILABLE ON)
        message(STATUS "brotli: system package")
    else()
        set(BROTLI_ROOT "${MGHTTP_DEPS_DIR}/brotli-1.1.0")
        if(MSVC)
            set(BROTLI_DIR "${BROTLI_ROOT}/${MGHTTP_DEP_BUILD}/Release")
            set(BROTLI_LIB "${BROTLI_DIR}/brotlidec.lib")
            set(BROTLI_COMMON "${BROTLI_DIR}/brotlicommon.lib")
        else()
            set(BROTLI_DIR "${BROTLI_ROOT}/${MGHTTP_DEP_BUILD}")
            set(BROTLI_LIB "${BROTLI_DIR}/libbrotlidec.a")
            set(BROTLI_COMMON "${BROTLI_DIR}/libbrotlicommon.a")
        endif()
        if(EXISTS "${BROTLI_LIB}")
            add_library(mghttp_brotli STATIC IMPORTED GLOBAL)
            set_target_properties(mghttp_brotli PROPERTIES
                IMPORTED_LOCATION "${BROTLI_LIB}"
                INTERFACE_LINK_LIBRARIES "${BROTLI_COMMON}"
                INTERFACE_INCLUDE_DIRECTORIES
                    "$<BUILD_INTERFACE:${BROTLI_ROOT}/c/include>")
            add_library(Brotli::Decoder ALIAS mghttp_brotli)
            set(MGHTTP_BROTLI_AVAILABLE ON)
            message(STATUS "brotli: in-tree ${BROTLI_LIB}")
        else()
            set(MGHTTP_BROTLI_AVAILABLE OFF)
            message(STATUS "brotli not available; MGHTTP_ENABLE_BROTLI is ON but "
                           "no prebuilt library was found. Brotli decoding will "
                           "report ContentEncodingUnsupported.")
        endif()
    endif()
else()
    set(MGHTTP_BROTLI_AVAILABLE OFF)
endif()

# Create interface target
add_library(megohttp INTERFACE)
add_library(MegoHttp::megohttp ALIAS megohttp)

target_include_directories(megohttp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(MGHTTP_USE_MEMESTRING)
    target_compile_definitions(megohttp INTERFACE MGHTTP_USE_MEMESTRING=1)
endif()

# MemeString's headers are only on the include path in MemeString mode: config.hpp
# and error.hpp are self-contained, so a std::string build needs nothing from it.
if(MGHTTP_USE_MEMESTRING)
    target_include_directories(megohttp INTERFACE
        $<BUILD_INTERFACE:${MEMESTRING_ROOT}/include>
    )
endif()

# Compile definitions
# Consumers must also compile with /utf-8: fmt's base.h static_asserts on it and
# the MegoHttp headers are UTF-8 without a BOM. Without this an installed package
# fails to compile in a fresh project (S1.9-04).
if(MSVC)
    target_compile_options(megohttp INTERFACE /utf-8)
endif()

target_compile_definitions(megohttp INTERFACE
    MGHTTP_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    MGHTTP_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    MGHTTP_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

if(MGHTTP_BACKEND_LIBUV)
    target_compile_definitions(megohttp INTERFACE MGHTTP_BACKEND_LIBUV=1)
endif()

if(MGHTTP_BACKEND_ASIO)
    target_compile_definitions(megohttp INTERFACE MGHTTP_BACKEND_ASIO=1)
endif()

if(MGHTTP_TLS_NONE)
    target_compile_definitions(megohttp INTERFACE MGHTTP_TLS_NONE=1)
endif()

if(MGHTTP_TLS_OPENSSL)
    target_compile_definitions(megohttp INTERFACE MGHTTP_TLS_OPENSSL=1)
    if(OpenSSL_FOUND)
        target_link_libraries(megohttp INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endif()

if(MGHTTP_TLS_MBEDTLS)
    target_compile_definitions(megohttp INTERFACE MGHTTP_TLS_MBEDTLS=1)
    target_include_directories(megohttp INTERFACE
        $<BUILD_INTERFACE:${MBEDTLS_ROOT}/include>)
    target_link_libraries(megohttp INTERFACE mbedtls_ext mbedx509_ext mbedcrypto_ext)
    if(MSVC)
        # mbedTLS needs bcrypt for CTR-DRBG entropy
        target_link_libraries(megohttp INTERFACE bcrypt)
    endif()
endif()

# A coding is only advertised as available when its library was actually found:
# defining the flag without the library would make Accept-Encoding promise gzip
# or br and then fail to decode what the server sends back.
if(MGHTTP_ENABLE_GZIP AND MGHTTP_ZLIB_AVAILABLE)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_GZIP=1)
endif()

if(MGHTTP_ENABLE_BROTLI AND MGHTTP_BROTLI_AVAILABLE)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_BROTLI=1)
endif()

if(MGHTTP_ENABLE_SSE)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_SSE=1)
endif()

if(MGHTTP_ENABLE_WEBSOCKET)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_WEBSOCKET=1)
endif()

if(MGHTTP_ENABLE_WEBSOCKET_DEFLATE)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_WEBSOCKET_DEFLATE=1)
else()
    # Explicit 0, not omitted: config.hpp treats "not configured" as "follow
    # MGHTTP_ENABLE_WEBSOCKET" (task book 3.16), so omitting it would silently
    # re-enable the feature the caller turned off.
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_WEBSOCKET_DEFLATE=0)
endif()

# zlib is a LIBRARY fact, not a per-feature one: both gzip and permessage-deflate
# need it, so the header needs to know whether it is linkable at all.
if(MGHTTP_ZLIB_AVAILABLE)
    target_compile_definitions(megohttp INTERFACE MGHTTP_HAVE_ZLIB=1)
endif()

if(MGHTTP_ENABLE_DOT)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_DOT=1)
endif()

if(MGHTTP_ENABLE_DOH)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_DOH=1)
endif()

if(MGHTTP_ENABLE_COROUTINES)
    target_compile_definitions(megohttp INTERFACE MGHTTP_ENABLE_COROUTINES=1)
endif()

if(MGHTTP_USE_UVW)
    target_compile_definitions(megohttp INTERFACE MGHTTP_USE_UVW=1)
endif()

# Feature test macros
target_compile_definitions(megohttp INTERFACE
    MGHTTP_HAS_FEATURE_GZIP=$<BOOL:${MGHTTP_ZLIB_AVAILABLE}>
    MGHTTP_HAS_FEATURE_BROTLI=$<BOOL:${MGHTTP_BROTLI_AVAILABLE}>
    MGHTTP_HAS_FEATURE_SSE=$<BOOL:${MGHTTP_ENABLE_SSE}>
    MGHTTP_HAS_FEATURE_WEBSOCKET=$<BOOL:${MGHTTP_ENABLE_WEBSOCKET}>
    MGHTTP_HAS_FEATURE_WEBSOCKET_DEFLATE=$<BOOL:${MGHTTP_ENABLE_WEBSOCKET_DEFLATE}>
    MGHTTP_HAS_FEATURE_DOT=$<BOOL:${MGHTTP_ENABLE_DOT}>
    MGHTTP_HAS_FEATURE_DOH=$<BOOL:${MGHTTP_ENABLE_DOH}>
)

# Link dependencies
if(MGHTTP_BACKEND_LIBUV AND MGHTTP_LIBUV_AVAILABLE)
    if(TARGET libuv::uv)
        target_link_libraries(megohttp INTERFACE libuv::uv)
    else()
        target_link_libraries(megohttp INTERFACE "${LIBUV_LIB}")
        if(WIN32)
            # libuv's Windows build needs these Win32 libraries.
            target_link_libraries(megohttp INTERFACE
                ws2_32 psapi iphlpapi shell32 userenv ole32 dbghelp synchronization advapi32)
        else()
            target_link_libraries(megohttp INTERFACE pthread dl rt)
        endif()
    endif()
    # Headers for the in-tree build sit next to its source root.
    target_include_directories(megohttp INTERFACE
        $<BUILD_INTERFACE:${LIBUV_ROOT}/include>)
    target_compile_definitions(megohttp INTERFACE MGHTTP_HAVE_LIBUV=1)
    if(WIN32)
        # inet_pton / inet_ntop are only declared when the target Windows version
        # is Vista or later; MinGW defaults to an older SDK level.
        target_compile_definitions(megohttp INTERFACE _WIN32_WINNT=0x0601)
    endif()
endif()

if(MGHTTP_BACKEND_ASIO AND MGHTTP_ASIO_AVAILABLE)
    if(TARGET asio::asio)
        target_link_libraries(megohttp INTERFACE asio::asio)
    else()
        target_include_directories(megohttp INTERFACE
            $<BUILD_INTERFACE:${ASIO_ROOT}/asio/include>)
    endif()
    target_compile_definitions(megohttp INTERFACE MGHTTP_HAVE_ASIO=1)
    if(WIN32)
        # Asio needs mswsock for AcceptEx on Windows, and inet_pton/inet_ntop are
        # only declared at _WIN32_WINNT >= 0x0600 (MinGW's default is older).
        target_compile_definitions(megohttp INTERFACE _WIN32_WINNT=0x0601)
        target_link_libraries(megohttp INTERFACE ws2_32 mswsock)
    endif()
endif()

if(MGHTTP_TLS_OPENSSL AND OpenSSL_FOUND)
    target_link_libraries(megohttp INTERFACE OpenSSL::SSL OpenSSL::Crypto)
endif()

# fmt: header-only usage plus the compiled library the in-tree build produced.
if(TARGET fmt::fmt)
    target_link_libraries(megohttp INTERFACE fmt::fmt)
else()
    target_include_directories(megohttp INTERFACE
        $<BUILD_INTERFACE:${FMT_ROOT}/include>)
    target_link_libraries(megohttp INTERFACE "${FMT_LIB}")
endif()

if(MGHTTP_USE_UVW AND MGHTTP_UVW_AVAILABLE)
    # uvw is header-only in this configuration.
    target_include_directories(megohttp INTERFACE
        $<BUILD_INTERFACE:${UVW_ROOT}/src>)
endif()

# MemeString is linked ONLY in MemeString mode: error.hpp and config.hpp no longer
# pull in any MemeString header, so the std::string build needs nothing from it.
if(MGHTTP_USE_MEMESTRING)
    if(MSVC)
        # MSVC's linker needs an import library, not the DLL itself.
        get_filename_component(MEMESTRING_RUNTIME_DIR "${MEMESTRING_RUNTIME}" DIRECTORY)
        get_filename_component(MEMESTRING_RUNTIME_NAME "${MEMESTRING_RUNTIME}" NAME_WE)
        set(MEMESTRING_IMPLIB "${MEMESTRING_RUNTIME_DIR}/${MEMESTRING_RUNTIME_NAME}.lib")
        if(NOT EXISTS "${MEMESTRING_IMPLIB}")
            message(FATAL_ERROR
                "MemeString import library not found: ${MEMESTRING_IMPLIB} "
                "(expected next to ${MEMESTRING_RUNTIME})")
        endif()
        message(STATUS "MemeString runtime: ${MEMESTRING_RUNTIME}")
        message(STATUS "MemeString implib:  ${MEMESTRING_IMPLIB}")
        target_link_libraries(megohttp INTERFACE "${MEMESTRING_IMPLIB}")
        target_compile_definitions(megohttp INTERFACE MGHTTP_MEMESTRING_DIR="${MEMESTRING_RUNTIME_DIR}")
    elseif(WIN32)
        # Link the DLL directly. Its import library in deps/MemeString/build_verify
        # was produced by a different toolchain build and resolves some symbols to a
        # stale `__imp_` form, which fails at link time even though the DLL exports
        # them. Passing the .dll makes MinGW generate a matching import library for
        # exactly the binary we run against.
        if(NOT MEMESTRING_RUNTIME)
            message(FATAL_ERROR
                "MemeString runtime DLL not found. Pass -DMEMESTRING_RUNTIME=<path>.")
        endif()
        message(STATUS "MemeString runtime: ${MEMESTRING_RUNTIME}")
        target_link_libraries(megohttp INTERFACE "${MEMESTRING_RUNTIME}")
        get_filename_component(MEMESTRING_RUNTIME_DIR "${MEMESTRING_RUNTIME}" DIRECTORY)
        target_compile_definitions(megohttp INTERFACE MGHTTP_MEMESTRING_DIR="${MEMESTRING_RUNTIME_DIR}")
    else()
        target_link_libraries(megohttp INTERFACE "${MEMESTRING_ROOT}/libmeme_string.so")
    endif()
endif()

# Runtime DLLs must sit next to the executables. CMake cannot "link-install" a DLL
# this project does not build, so each consumer target copies it after linking.
if(WIN32 AND MEMESTRING_RUNTIME AND MGHTTP_USE_MEMESTRING)
    function(mghttp_copy_runtime_dll target)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<BUILD_INTERFACE:${MEMESTRING_RUNTIME}>" "$<TARGET_FILE_DIR:${target}>"
            VERBATIM)
    endfunction()
else()
    function(mghttp_copy_runtime_dll target)
        # Nothing to copy on this platform/configuration.
    endfunction()
endif()

# OpenSSL on Windows is a shared toolkit: the import library links fine but the
# test binaries die at load with 0xC0000135 (DLL not found) unless libssl /
# libcrypto sit beside the exe or on PATH. Same technique as the MemeString DLL
# above, and the same reason: a green run that depends on whoever happened to
# have the toolkit on PATH is not reproducible evidence.
#
# The import library lives in <prefix>/lib and the runtime DLLs in <prefix>/bin,
# so the DLL directory is derived from the library path rather than guessed.
set(MGHTTP_TLS_RUNTIME_DLLS "")
if(WIN32 AND MGHTTP_TLS_OPENSSL AND OpenSSL_FOUND)
    set(_mghttp_ssl_lib "${OPENSSL_SSL_LIBRARY}")
    if(TARGET OpenSSL::SSL)
        get_target_property(_mghttp_implib OpenSSL::SSL IMPORTED_IMPLIB_RELEASE)
        if(_mghttp_implib AND NOT _mghttp_implib MATCHES "NOTFOUND")
            set(_mghttp_ssl_lib "${_mghttp_implib}")
        endif()
    endif()
    get_filename_component(_mghttp_ssl_libdir "${_mghttp_ssl_lib}" DIRECTORY)
    foreach(_mghttp_bindir "${_mghttp_ssl_libdir}/../bin" "${OPENSSL_INCLUDE_DIR}/../bin")
        file(GLOB _mghttp_found_dlls
             "${_mghttp_bindir}/libssl-*.dll" "${_mghttp_bindir}/libcrypto-*.dll")
        if(_mghttp_found_dlls)
            list(APPEND MGHTTP_TLS_RUNTIME_DLLS ${_mghttp_found_dlls})
        endif()
    endforeach()
    list(REMOVE_DUPLICATES MGHTTP_TLS_RUNTIME_DLLS)
    if(MGHTTP_TLS_RUNTIME_DLLS)
        message(STATUS "OpenSSL runtime DLLs copied beside test binaries: "
                       "${MGHTTP_TLS_RUNTIME_DLLS}")
    else()
        message(WARNING
            "MGHTTP_TLS_OPENSSL=ON but no libssl-*.dll / libcrypto-*.dll was found "
            "next to ${_mghttp_ssl_libdir}. TLS test binaries will fail to load "
            "unless the OpenSSL bin directory is on PATH.")
    endif()
endif()

function(mghttp_copy_tls_runtime_dll target)
    if(MGHTTP_TLS_RUNTIME_DLLS)
        foreach(_dll IN LISTS MGHTTP_TLS_RUNTIME_DLLS)
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_dll}" "$<TARGET_FILE_DIR:${target}>"
                VERBATIM)
        endforeach()
    endif()
endfunction()

if((MGHTTP_ENABLE_GZIP OR MGHTTP_ENABLE_WEBSOCKET_DEFLATE) AND MGHTTP_ZLIB_AVAILABLE)
    if(ZLIB_FOUND AND TARGET ZLIB::ZLIB)
        target_link_libraries(megohttp INTERFACE ZLIB::ZLIB)
    else()
        target_include_directories(megohttp INTERFACE
            $<BUILD_INTERFACE:${ZLIB_ROOT}>
            $<BUILD_INTERFACE:${ZLIB_ROOT}/${MGHTTP_DEP_BUILD}>)
        target_link_libraries(megohttp INTERFACE
            "$<BUILD_INTERFACE:${ZLIB_LIB_PATH}>")
    endif()
endif()

if(MGHTTP_ENABLE_BROTLI AND MGHTTP_BROTLI_AVAILABLE AND TARGET Brotli::Decoder)
    target_link_libraries(megohttp INTERFACE Brotli::Decoder)
endif()

# Tests
if(MGHTTP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(MGHTTP_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

# Install
include(GNUInstallDirs)

install(TARGETS megohttp
    EXPORT MegoHttpTargets
)

install(EXPORT MegoHttpTargets
    FILE MegoHttpTargets.cmake
    NAMESPACE MegoHttp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MegoHttp
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Package configuration
include(CMakePackageConfigHelpers)

# Generate the package config with both @...@ substitution (for boolean options)
# and @PACKAGE_INIT@ expansion (for install tree relocation).
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/MegoHttpConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/MegoHttpConfig.cmake.in2"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MegoHttp
)

# The in2 file still has @MGHTTP_...@ placeholders; resolve them here.
configure_file(
    "${CMAKE_CURRENT_BINARY_DIR}/MegoHttpConfig.cmake.in2"
    "${CMAKE_CURRENT_BINARY_DIR}/MegoHttpConfig.cmake"
    @ONLY
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/MegoHttpConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install the third-party headers the public interface depends on, at the same
# include root the sources use. Without them an installed consumer cannot
# resolve <memepp/string.hpp>, <uv.h>, <fmt/format.h> and friends, because the
# BUILD_INTERFACE include dirs do not survive export (S1.9-04).
#
# These are copied flat into ${CMAKE_INSTALL_INCLUDEDIR} to match the include
# spelling used by the library and by the dependencies themselves.
install(DIRECTORY "${MEMESTRING_ROOT}/include/" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL)
install(DIRECTORY "${LIBUV_ROOT}/include/"       DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL)
install(DIRECTORY "${ASIO_ROOT}/asio/include/"   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL)
install(DIRECTORY "${FMT_ROOT}/include/"         DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL)
install(DIRECTORY "${UVW_ROOT}/src/"             DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL)
# Install the static libraries the exported interface links against, so an
# installed package is self-contained rather than pointing back into deps/.
if(MGHTTP_FMT_AVAILABLE)
    install(FILES "${FMT_LIB}" DESTINATION ${CMAKE_INSTALL_LIBDIR} OPTIONAL)
endif()
if(MGHTTP_BACKEND_LIBUV AND MGHTTP_LIBUV_AVAILABLE)
    install(FILES "${LIBUV_LIB}" DESTINATION ${CMAKE_INSTALL_LIBDIR} OPTIONAL)
endif()
if(MGHTTP_USE_MEMESTRING)
    install(FILES "${MEMESTRING_IMPLIB}"   DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES "${MEMESTRING_RUNTIME}"  DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(FILES "${ZLIB_ROOT}/zlib.h" "${ZLIB_ROOT}/zconf.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} OPTIONAL)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/MegoHttpConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/MegoHttpConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MegoHttp
)
