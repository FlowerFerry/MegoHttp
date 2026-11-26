# Header cross-compile smoke project.
#
# This intentionally does NOT use the repository's top-level CMakeLists: that
# project locates prebuilt host libraries for the local Windows/MSVC tree. A
# cross toolchain cannot use those objects. The smoke target compiles the
# public header surface with a header-only Asio backend, std::string, and no
# TLS/content-coding dependencies. It is compile-only evidence for the
# "cross-compile-only" matrix class in the task book.
#
# Configure with a toolchain file from cmake/toolchains/ and pass
# MEGOHTTP_SOURCE_DIR=<repository root>.

cmake_minimum_required(VERSION 3.14)
project(MegoHttpCrossCompile LANGUAGES CXX)

set(MEGOHTTP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH
    "MegoHttp repository root")
set(MEGOHTTP_FMT_INCLUDE_DIR
    "${MEGOHTTP_SOURCE_DIR}/deps/fmt-12.1.0/include"
    CACHE PATH "fmt headers")
set(MEGOHTTP_ASIO_INCLUDE_DIR
    "${MEGOHTTP_SOURCE_DIR}/deps/asio-asio-1-38-0/asio/include"
    CACHE PATH "standalone Asio headers")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(megohttp_cross_smoke STATIC smoke.cpp)

target_include_directories(megohttp_cross_smoke PRIVATE
    "${MEGOHTTP_SOURCE_DIR}/include"
    "${MEGOHTTP_FMT_INCLUDE_DIR}"
    "${MEGOHTTP_ASIO_INCLUDE_DIR}")

target_compile_definitions(megohttp_cross_smoke PRIVATE
    MGHTTP_BACKEND_ASIO=1
    MGHTTP_TLS_NONE=1
    MGHTTP_USE_MEMESTRING=0
    MGHTTP_USE_UVW=0
    MGHTTP_ENABLE_GZIP=0
    MGHTTP_ENABLE_BROTLI=0
    MGHTTP_ENABLE_SSE=0
    MGHTTP_ENABLE_WEBSOCKET=0
    MGHTTP_ENABLE_WEBSOCKET_DEFLATE=0
    MGHTTP_ENABLE_DOT=0
    MGHTTP_ENABLE_DOH=0
    MGHTTP_ENABLE_COROUTINES=0
    FMT_HEADER_ONLY=1)
