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
    test_multipart.cpp
    test_multipart_response.cpp
    test_multipart_continuous.cpp
    test_content_range.cpp
    test_content_type.cpp
    test_fuzz_parsers.cpp
    test_tls_stream.cpp
    test_client_tls.cpp
    test_tls_layering.cpp
    test_tls_trust.cpp
)

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
    add_library(mghttp_include_check OBJECT ${MGHTTP_INCLUDE_CHECK_SOURCES})
    target_link_libraries(mghttp_include_check PRIVATE MegoHttp::megohttp)
    # The object library is never linked, so it needs no DLL copy step: it only
    # has to compile.
endif()

