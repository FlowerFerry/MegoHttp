#ifndef MEGOHTTP_CONFIG_HPP_INCLUDED
#define MEGOHTTP_CONFIG_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Platform / compiler / language detection.
//
// Self-contained: this header must work with NO third-party dependency at all,
// because MegoHttp is usable with MGHTTP_USE_MEMESTRING undefined. Reaching into
// MemeString's mego/predef headers here would force every user of the library to
// have MemeString on the include path even when they asked for std::string.
//
// MSVC quirk handled explicitly: MSVC reports C++17 as __cplusplus == 199711L
// unless /Zc:__cplusplus is given, so _MSVC_LANG is authoritative there.
// ---------------------------------------------------------------------------

// --- Language level --------------------------------------------------------
#if defined(_MSVC_LANG)
#   define MEGOHTTP_CPLUSPLUS _MSVC_LANG
#else
#   define MEGOHTTP_CPLUSPLUS __cplusplus
#endif

#if MEGOHTTP_CPLUSPLUS >= 202002L
#   define MEGOHTTP_HAS_CXX20 1
#else
#   define MEGOHTTP_HAS_CXX20 0
#endif

#if MEGOHTTP_CPLUSPLUS >= 201703L
#   define MEGOHTTP_HAS_CXX17 1
#else
#   define MEGOHTTP_HAS_CXX17 0
#endif

// --- Compiler --------------------------------------------------------------
#if defined(__clang__)
#   define MEGOHTTP_COMPILER_CLANG 1
#elif defined(__GNUC__)
#   define MEGOHTTP_COMPILER_GCC 1
#elif defined(_MSC_VER)
#   define MEGOHTTP_COMPILER_MSVC 1
#else
#   define MEGOHTTP_COMPILER_UNKNOWN 1
#endif

// --- Platform --------------------------------------------------------------
#if defined(_WIN32)
#   define MEGOHTTP_PLATFORM_WINDOWS 1
#elif defined(__ANDROID__)
#   define MEGOHTTP_PLATFORM_ANDROID 1
#elif defined(__APPLE__)
#   include <TargetConditionals.h>
#   if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#       define MEGOHTTP_PLATFORM_IOS 1
#   else
#       define MEGOHTTP_PLATFORM_MACOS 1
#   endif
#elif defined(__linux__)
#   define MEGOHTTP_PLATFORM_LINUX 1
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
      defined(__DragonFly__) || defined(__bsdi__)
#   define MEGOHTTP_PLATFORM_BSD 1
#else
#   define MEGOHTTP_PLATFORM_UNKNOWN 1
#endif

// Version
#define MEGOHTTP_VERSION_MAJOR 0
#define MEGOHTTP_VERSION_MINOR 1
#define MEGOHTTP_VERSION_PATCH 0

#define MEGOHTTP_VERSION_STRING "0.1.0"

// C++17 is the baseline; C++20 only adds the coroutine surface.
#if !MEGOHTTP_HAS_CXX17
#   error "MegoHttp requires C++17 or later"
#endif

// ============================================================================
// Backend Selection (exactly one must be selected)
//
// Every check below uses the VALUE of the macro, not its mere presence, so that
// -DMGHTTP_BACKEND_LIBUV=0 behaves identically to leaving it undefined.
// ============================================================================

#if defined(MGHTTP_BACKEND_LIBUV) && !MGHTTP_BACKEND_LIBUV
#   undef MGHTTP_BACKEND_LIBUV
#endif
#if defined(MGHTTP_BACKEND_ASIO) && !MGHTTP_BACKEND_ASIO
#   undef MGHTTP_BACKEND_ASIO
#endif

#if defined(MGHTTP_BACKEND_LIBUV) && defined(MGHTTP_BACKEND_ASIO)
#   error "Cannot enable both LIBUV and ASIO backends"
#endif

#if !defined(MGHTTP_BACKEND_LIBUV) && !defined(MGHTTP_BACKEND_ASIO)
#   error "Must enable at least one backend (define MGHTTP_BACKEND_LIBUV or MGHTTP_BACKEND_ASIO)"
#endif

// ============================================================================
// TLS Selection (exactly one must be selected)
// ============================================================================

#if defined(MGHTTP_TLS_NONE) && !MGHTTP_TLS_NONE
#   undef MGHTTP_TLS_NONE
#endif
#if defined(MGHTTP_TLS_OPENSSL) && !MGHTTP_TLS_OPENSSL
#   undef MGHTTP_TLS_OPENSSL
#endif
#if defined(MGHTTP_TLS_MBEDTLS) && !MGHTTP_TLS_MBEDTLS
#   undef MGHTTP_TLS_MBEDTLS
#endif

#if defined(MGHTTP_TLS_NONE) && (defined(MGHTTP_TLS_OPENSSL) || defined(MGHTTP_TLS_MBEDTLS))
#   error "Cannot enable TLS_NONE with other TLS backends"
#endif

#if defined(MGHTTP_TLS_OPENSSL) && (defined(MGHTTP_TLS_NONE) || defined(MGHTTP_TLS_MBEDTLS))
#   error "Cannot enable multiple TLS backends"
#endif

#if defined(MGHTTP_TLS_MBEDTLS) && (defined(MGHTTP_TLS_NONE) || defined(MGHTTP_TLS_OPENSSL))
#   error "Cannot enable multiple TLS backends"
#endif

#if !defined(MGHTTP_TLS_NONE) && !defined(MGHTTP_TLS_OPENSSL) && !defined(MGHTTP_TLS_MBEDTLS)
#   define MGHTTP_TLS_OPENSSL 1  // Default to OpenSSL
#endif

// ============================================================================
// Feature Dependencies
// ============================================================================

// DoT/DoH requires TLS
#if defined(MGHTTP_ENABLE_DOT) && MGHTTP_ENABLE_DOT && defined(MGHTTP_TLS_NONE)
#   error "DoT requires TLS (MGHTTP_TLS_NONE cannot be used with MGHTTP_ENABLE_DOT)"
#endif

#if defined(MGHTTP_ENABLE_DOH) && MGHTTP_ENABLE_DOH && defined(MGHTTP_TLS_NONE)
#   error "DoH requires TLS (MGHTTP_TLS_NONE cannot be used with MGHTTP_ENABLE_DOH)"
#endif

// WebSocket DEFLATE requires WebSocket
#if defined(MGHTTP_ENABLE_WEBSOCKET_DEFLATE) && MGHTTP_ENABLE_WEBSOCKET_DEFLATE && \
    !(defined(MGHTTP_ENABLE_WEBSOCKET) && MGHTTP_ENABLE_WEBSOCKET)
#   error "WebSocket DEFLATE requires WebSocket support"
#endif

// ============================================================================
// Coroutine Support
// ============================================================================

#if defined(MGHTTP_ENABLE_COROUTINES) && MGHTTP_ENABLE_COROUTINES
#   if !MEGOHTTP_HAS_CXX20
#       error "C++20 required for coroutines"
#   endif
#   ifdef __has_include
#       if !__has_include(<coroutine>)
#           error "<coroutine> header not available"
#       endif
#   endif
#endif

// ============================================================================
// Feature Availability Macros (used internally)
//
// All consumer-side checks must use the numeric macros (MEGOHTTP_HAS_*) rather
// than #ifdef, so that explicitly passing -DMGHTTP_ENABLE_GZIP=0 produces the
// same "off" result as the flag being absent.  The conversion below is the
// single place where the raw #define / -D flag becomes a 0/1 value.
// ============================================================================

#if defined(MGHTTP_USE_MEMESTRING) && MGHTTP_USE_MEMESTRING != 0
#   define MEGOHTTP_HAS_MEMESTRING 1
#else
#   define MEGOHTTP_HAS_MEMESTRING 0
#endif

#if defined(MGHTTP_ENABLE_GZIP) && MGHTTP_ENABLE_GZIP != 0
#   define MEGOHTTP_HAS_GZIP 1
#else
#   define MEGOHTTP_HAS_GZIP 0
#endif

#if defined(MGHTTP_ENABLE_BROTLI) && MGHTTP_ENABLE_BROTLI != 0
#   define MEGOHTTP_HAS_BROTLI 1
#else
#   define MEGOHTTP_HAS_BROTLI 0
#endif

#if defined(MGHTTP_ENABLE_SSE) && MGHTTP_ENABLE_SSE != 0
#   define MEGOHTTP_HAS_SSE 1
#else
#   define MEGOHTTP_HAS_SSE 0
#endif

#if defined(MGHTTP_ENABLE_WEBSOCKET) && MGHTTP_ENABLE_WEBSOCKET != 0
#   define MEGOHTTP_HAS_WEBSOCKET 1
#else
#   define MEGOHTTP_HAS_WEBSOCKET 0
#endif

#if defined(MGHTTP_ENABLE_WEBSOCKET_DEFLATE) && MGHTTP_ENABLE_WEBSOCKET_DEFLATE != 0
#   define MEGOHTTP_HAS_WEBSOCKET_DEFLATE 1
#else
#   define MEGOHTTP_HAS_WEBSOCKET_DEFLATE 0
#endif

#if defined(MGHTTP_ENABLE_DOT) && MGHTTP_ENABLE_DOT != 0
#   define MEGOHTTP_HAS_DOT 1
#else
#   define MEGOHTTP_HAS_DOT 0
#endif

#if defined(MGHTTP_ENABLE_DOH) && MGHTTP_ENABLE_DOH != 0
#   define MEGOHTTP_HAS_DOH 1
#else
#   define MEGOHTTP_HAS_DOH 0
#endif

#if defined(MGHTTP_ENABLE_COROUTINES) && MGHTTP_ENABLE_COROUTINES != 0
#   define MEGOHTTP_HAS_COROUTINES 1
#else
#   define MEGOHTTP_HAS_COROUTINES 0
#endif

// ============================================================================
// Export/Import Macros
// ============================================================================

// MegoHttp is header-only, no DLL exports needed
#define MEGOHTTP_API

// ============================================================================
// Debug/Release
// ============================================================================

#ifndef NDEBUG
#   define MEGOHTTP_DEBUG 1
#else
#   define MEGOHTTP_RELEASE 1
#endif

// ============================================================================
// Assert Configuration
// ============================================================================

#include <cassert>

#define MEGOHTTP_ASSERT(expr) assert(expr)
#define MEGOHTTP_ASSERT_MSG(expr, msg) assert((expr) && (msg))

#endif // MEGOHTTP_CONFIG_HPP_INCLUDED
