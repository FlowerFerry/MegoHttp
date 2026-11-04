#ifndef MEGOHTTP_CONFIG_HPP_INCLUDED
#define MEGOHTTP_CONFIG_HPP_INCLUDED

// ---------------------------------------------------------------------------
// Platform / compiler / language detection.
//
// Reused from MemeString's `mego/predef` headers rather than re-detected here.
// That keeps this library and MemeString agreeing on every platform question by
// construction, and it puts MSVC's _MSVC_LANG quirk in exactly one place
// (mego/predef/lang/version.h) instead of two places doing it differently.
// ---------------------------------------------------------------------------

#include <mego/predef/lang/version.h>     // MG_LANG__CXX17_AVAIL, MG_LANG__CXX_VER
#include <mego/predef/compiler.h>         // MG_COMP__GCC/CLANG/MSVC_AVAIL
#include <mego/predef/os/windows.h>       // MG_OS__WIN_AVAIL
#include <mego/predef/os/linux.h>         // MG_OS__LINUX_AVAIL
#include <mego/predef/os/macos.h>         // MG_OS__MACOS_AVAIL
#include <mego/predef/os/ios.h>           // MG_OS__IOS_AVAIL
#include <mego/predef/os/bsd.h>           // MG_OS__BSD_AVAIL (+ FREE/NET/OPEN/DRAGONFLY)
#include <mego/predef/platform/android.h> // MG_PLAT__ANDROID_AVAIL

// Version
#define MEGOHTTP_VERSION_MAJOR 0
#define MEGOHTTP_VERSION_MINOR 1
#define MEGOHTTP_VERSION_PATCH 0

#define MEGOHTTP_VERSION_STRING "0.1.0"

// C++17 is the baseline; C++20 only adds the coroutine surface.
#if !MG_LANG__CXX17_AVAIL
#   error "MegoHttp requires C++17 or later"
#endif

// ============================================================================
// Backend Selection (exactly one must be defined)
// ============================================================================

#if defined(MGHTTP_BACKEND_LIBUV) && defined(MGHTTP_BACKEND_ASIO)
#   error "Cannot enable both LIBUV and ASIO backends"
#endif

#if !defined(MGHTTP_BACKEND_LIBUV) && !defined(MGHTTP_BACKEND_ASIO)
#   error "Must enable at least one backend (define MGHTTP_BACKEND_LIBUV or MGHTTP_BACKEND_ASIO)"
#endif

// ============================================================================
// TLS Selection (exactly one must be defined)
// ============================================================================

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
#if defined(MGHTTP_ENABLE_DOT) && defined(MGHTTP_TLS_NONE)
#   error "DoT requires TLS (MGHTTP_TLS_NONE cannot be used with MGHTTP_ENABLE_DOT)"
#endif

#if defined(MGHTTP_ENABLE_DOH) && defined(MGHTTP_TLS_NONE)
#   error "DoH requires TLS (MGHTTP_TLS_NONE cannot be used with MGHTTP_ENABLE_DOH)"
#endif

// WebSocket DEFLATE requires WebSocket
#if defined(MGHTTP_ENABLE_WEBSOCKET_DEFLATE) && !defined(MGHTTP_ENABLE_WEBSOCKET)
#   error "WebSocket DEFLATE requires WebSocket support"
#endif

// ============================================================================
// Coroutine Support
// ============================================================================

#if defined(MGHTTP_ENABLE_COROUTINES)
#   if !MG_LANG__CXX20_AVAIL
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
// ============================================================================

#ifdef MGHTTP_USE_MEMESTRING
#   define MEGOHTTP_HAS_MEMESTRING 1
#else
#   define MEGOHTTP_HAS_MEMESTRING 0
#endif

#ifdef MGHTTP_ENABLE_GZIP
#   define MEGOHTTP_HAS_GZIP 1
#else
#   define MEGOHTTP_HAS_GZIP 0
#endif

#ifdef MGHTTP_ENABLE_BROTLI
#   define MEGOHTTP_HAS_BROTLI 1
#else
#   define MEGOHTTP_HAS_BROTLI 0
#endif

#ifdef MGHTTP_ENABLE_SSE
#   define MEGOHTTP_HAS_SSE 1
#else
#   define MEGOHTTP_HAS_SSE 0
#endif

#ifdef MGHTTP_ENABLE_WEBSOCKET
#   define MEGOHTTP_HAS_WEBSOCKET 1
#else
#   define MEGOHTTP_HAS_WEBSOCKET 0
#endif

#ifdef MGHTTP_ENABLE_WEBSOCKET_DEFLATE
#   define MEGOHTTP_HAS_WEBSOCKET_DEFLATE 1
#else
#   define MEGOHTTP_HAS_WEBSOCKET_DEFLATE 0
#endif

#ifdef MGHTTP_ENABLE_DOT
#   define MEGOHTTP_HAS_DOT 1
#else
#   define MEGOHTTP_HAS_DOT 0
#endif

#ifdef MGHTTP_ENABLE_DOH
#   define MEGOHTTP_HAS_DOH 1
#else
#   define MEGOHTTP_HAS_DOH 0
#endif

#ifdef MGHTTP_ENABLE_COROUTINES
#   define MEGOHTTP_HAS_COROUTINES 1
#else
#   define MEGOHTTP_HAS_COROUTINES 0
#endif

// ============================================================================
// Platform, spelled once, in terms of the mego predef macros.
// ============================================================================

#if MG_OS__WIN_AVAIL
#   define MEGOHTTP_PLATFORM_WINDOWS 1
#elif MG_PLAT__ANDROID_AVAIL
#   define MEGOHTTP_PLATFORM_ANDROID 1
#elif MG_OS__IOS_AVAIL
#   define MEGOHTTP_PLATFORM_IOS 1
#elif MG_OS__MACOS_AVAIL
#   define MEGOHTTP_PLATFORM_MACOS 1
#elif MG_OS__LINUX_AVAIL
#   define MEGOHTTP_PLATFORM_LINUX 1
#elif MG_OS__BSD_AVAIL
#   define MEGOHTTP_PLATFORM_BSD 1
#else
#   define MEGOHTTP_PLATFORM_UNKNOWN 1
#endif

// ============================================================================
// Compiler
// ============================================================================

#if MG_COMP__CLANG_AVAIL
#   define MEGOHTTP_COMPILER_CLANG 1
#elif MG_COMP__GCC_AVAIL
#   define MEGOHTTP_COMPILER_GCC 1
#elif MG_COMP__MSVC_AVAIL
#   define MEGOHTTP_COMPILER_MSVC 1
#else
#   define MEGOHTTP_COMPILER_UNKNOWN 1
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
