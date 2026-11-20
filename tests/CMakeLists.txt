# Catch2 v3, same policy as the other dependencies: prefer the in-tree source
# checkout, fall back to FetchContent when it is absent.
set(CATCH2_ROOT "${MGHTTP_DEPS_DIR}/Catch2-v3.7.1")

if(EXISTS "${CATCH2_ROOT}/src/catch2/catch_all.hpp")
    message(STATUS "Catch2: in-tree ${CATCH2_ROOT}")
    add_subdirectory(${CATCH2_ROOT} ${CMAKE_BINARY_DIR}/_deps/catch2-build EXCLUDE_FROM_ALL)
else()
    message(STATUS "Catch2: not in-tree, using FetchContent (needs network)")
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.7.1
        SYSTEM
    )
    FetchContent_MakeAvailable(Catch2)
endif()

set(MGHTTP_TEST_SOURCES
    test_core.cpp
    test_http.cpp
    test_client.cpp
    test_streaming.cpp
    test_streaming_integration.cpp
    test_streaming_network.cpp
    test_multipart.cpp
    test_multipart_response.cpp
    test_multipart_continuous.cpp
    test_multipart_client.cpp
    test_content_range.cpp
    test_content_type.cpp
    test_fuzz_parsers.cpp
    test_tls_stream.cpp
    test_client_tls.cpp
    test_tls_layering.cpp
    test_tls_trust.cpp
    test_connection_pool.cpp
    test_client_pool.cpp
    test_redirect.cpp
    test_retry.cpp
    test_proxy.cpp
    test_client_proxy.cpp
    test_client_retry.cpp
    test_cookie.cpp
    test_reconnect.cpp
    test_dns_wire.cpp
    test_dns_cache.cpp
)

# DoT tests: the resolver builds its own TLS/TCP connection and frames DNS
# queries over it, so it needs the full DoT implementation available.
if(MGHTTP_ENABLE_DOT AND NOT MGHTTP_TLS_NONE)
    list(APPEND MGHTTP_TEST_SOURCES test_resolver_dot.cpp)
endif()

# DoH tests: the resolver drives a real HTTPS request to a local DoH server.
if(MGHTTP_ENABLE_DOH AND NOT MGHTTP_TLS_NONE)
    list(APPEND MGHTTP_TEST_SOURCES test_resolver_doh.cpp)
endif()

# Coroutine tests need C++20 and a toolchain with <coroutine>.
if(MGHTTP_ENABLE_COROUTINES)
    list(APPEND MGHTTP_TEST_SOURCES test_task.cpp)
endif()

# gzip/deflate need zlib; these tests build their own fixtures with zlib's
# encoder, so they cannot exist in a build without it (task book 3.21).
if(MGHTTP_ZLIB_AVAILABLE)
    list(APPEND MGHTTP_TEST_SOURCES
        test_content_decoder.cpp
        test_content_encoding.cpp
    )
endif()

# Feature gates here use the CMake options, not the C++ MEGOHTTP_HAS_* macros:
# those are defined by config.hpp for the compiler and are not visible to CMake.
if(MGHTTP_ENABLE_SSE)
    list(APPEND MGHTTP_TEST_SOURCES
        test_sse.cpp
        test_sse_client.cpp
        test_sse_session.cpp
    )
endif()
if(MGHTTP_ENABLE_WEBSOCKET AND MGHTTP_ENABLE_WEBSOCKET_DEFLATE)
    list(APPEND MGHTTP_TEST_SOURCES
        test_websocket_deflate.cpp
    )
endif()
if(MGHTTP_ENABLE_WEBSOCKET)
    list(APPEND MGHTTP_TEST_SOURCES
        test_websocket.cpp
    )
endif()

# These tests drive a real TcpStream through UvExecutor (directly, or through
# Client::open_websocket's stream provider), so they are libuv-only. The Asio
# backend has its own connect_race/resolver coverage in test_asio.
# test_websocket_session runs on BOTH backends: its fixture only needs an
# Executor and a TcpStream, which is the abstraction the library is built on.
# test_websocket_reconnect (below) drives Client::open_websocket and therefore
# the backend's resolver/connect_race path, so it stays libuv-only; the Asio
# side gets equivalent coverage from test_websocket_reconnect_backend.
if(MGHTTP_ENABLE_WEBSOCKET)
    list(APPEND MGHTTP_TEST_SOURCES test_websocket_session.cpp)
endif()
if(MGHTTP_BACKEND_LIBUV AND MGHTTP_ENABLE_WEBSOCKET)
    list(APPEND MGHTTP_TEST_SOURCES test_websocket_reconnect.cpp)
endif()


# The reconnect state machine sits above the transport, so this one runs on
# BOTH backends: it injects a fake WsStreamProvider instead of dialling a real
# socket. That is what gives the Asio configuration reconnect coverage (T2).
if(MGHTTP_ENABLE_WEBSOCKET)
    list(APPEND MGHTTP_TEST_SOURCES test_websocket_reconnect_backend.cpp)
endif()

# Interop against Python websockets: the only test that can catch a shared
# misreading of RFC 7692. SKIPs (not fails) when Python is unavailable.
if(MGHTTP_ENABLE_WEBSOCKET AND MGHTTP_ENABLE_WEBSOCKET_DEFLATE)
    list(APPEND MGHTTP_TEST_SOURCES test_websocket_interop.cpp)
endif()

# WSS through a proxy CONNECT tunnel (S6.4-08). Needs the python proxy and the
# websockets package, so it SKIPs when they are absent.
if(MGHTTP_ENABLE_WEBSOCKET)
    list(APPEND MGHTTP_TEST_SOURCES test_websocket_proxy.cpp)
endif()

if(MGHTTP_BACKEND_LIBUV)
    list(APPEND MGHTTP_TEST_SOURCES test_executor_libuv.cpp)
    list(APPEND MGHTTP_TEST_SOURCES test_transport.cpp)
endif()

if(MGHTTP_USE_UVW)
    list(APPEND MGHTTP_TEST_SOURCES test_uvw.cpp)
endif()

if(MGHTTP_BACKEND_ASIO)
    list(APPEND MGHTTP_TEST_SOURCES test_asio.cpp)
endif()

foreach(test_src IN LISTS MGHTTP_TEST_SOURCES)
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    # Catch2WithMain supplies main(); the test files contain only TEST_CASEs.
    target_link_libraries(${test_name} PRIVATE MegoHttp::megohttp Catch2::Catch2WithMain)
    target_compile_definitions(${test_name} PRIVATE MGHTTP_INTERNAL_TESTING=1)
    # TLS tests start tests/tls_test_server.py and read PEMs from tls_fixtures/.
    # Paths are compile definitions rather than relative lookups so the test does
    # not depend on the working directory it was launched from.
    target_compile_definitions(${test_name} PRIVATE
        MEGOHTTP_TESTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
        MEGOHTTP_TLS_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tls_fixtures")
    mghttp_copy_runtime_dll(${test_name})
    mghttp_copy_tls_runtime_dll(${test_name})
    # The content-decoding test builds its fixtures with the matching ENCODER,
    # which the library itself never links (decoding only).
    if(test_name STREQUAL "test_content_decoder" AND MGHTTP_BROTLI_AVAILABLE)
        if(MSVC)
            set(_br_dir "${BROTLI_ROOT}/${MGHTTP_DEP_BUILD}/Release")
            target_link_libraries(${test_name} PRIVATE
                "${_br_dir}/brotlienc.lib" "${_br_dir}/brotlicommon.lib")
        endif()
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Multi-TU link test: proves every non-template definition in the headers is
# inline. Two TUs that use the same headers must link together.
# Not a Catch2 binary: it has its own main() and only checks linkage.
add_executable(test_multi_tu tu_a.cpp tu_b.cpp)
target_link_libraries(test_multi_tu PRIVATE MegoHttp::megohttp)
mghttp_copy_runtime_dll(test_multi_tu)
add_test(NAME test_multi_tu COMMAND test_multi_tu)

# Independent-include check (spec 13.6). tests/include_check/ holds one TU per
# public header, each including exactly that header and nothing else. If a
# header stops being self-contained, only its own TU fails, which points at the
# culprit directly instead of producing a cascade.
file(GLOB MGHTTP_INCLUDE_CHECK_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/include_check/*.cpp")
if(MGHTTP_INCLUDE_CHECK_SOURCES)
    # SSE and WebSocket header checks are only compiled when the feature is on.
    set(MGHTTP_IC_SOURCES ${MGHTTP_INCLUDE_CHECK_SOURCES})
    if(NOT MGHTTP_ENABLE_SSE)
        list(FILTER MGHTTP_IC_SOURCES EXCLUDE REGEX "h_sse\\.cpp$")
    endif()
    if(NOT MGHTTP_ENABLE_WEBSOCKET)
        list(FILTER MGHTTP_IC_SOURCES EXCLUDE REGEX "h_websocket.*\\.cpp$")
    endif()
    add_library(mghttp_include_check OBJECT ${MGHTTP_IC_SOURCES})
    target_link_libraries(mghttp_include_check PRIVATE MegoHttp::megohttp)
    # The object library is never linked, so it needs no DLL copy step: it only
    # has to compile.
endif()

