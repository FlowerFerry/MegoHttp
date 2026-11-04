# Tests use Catch2 v3 amalgamated (deps/Catch2/):
#   catch_amalgamated.hpp  - headers (included by every test_*.cpp)
#   catch_amalgamated.cpp  - implementation, compiled once into catch2_impl
# catch_amalgamated.cpp provides main(); the test files contain only TEST_CASEs.

add_library(catch2_impl OBJECT
    ${CMAKE_SOURCE_DIR}/deps/Catch2/catch_amalgamated.cpp
)
target_include_directories(catch2_impl PUBLIC
    ${CMAKE_SOURCE_DIR}/deps/Catch2
)
add_library(Catch2::Catch2 ALIAS catch2_impl)

set(MGHTTP_TEST_SOURCES
    test_core.cpp
    test_http.cpp
    test_client.cpp
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
    target_link_libraries(${test_name} PRIVATE MegoHttp::megohttp Catch2::Catch2)
    target_compile_definitions(${test_name} PRIVATE MGHTTP_INTERNAL_TESTING=1)
    mghttp_copy_runtime_dll(${test_name})
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Multi-TU link test: proves every non-template definition in the headers is
# inline. Two TUs that use the same headers must link together.
# Not a Catch2 binary: it has its own main() and only checks linkage.
add_executable(test_multi_tu tu_a.cpp tu_b.cpp)
target_link_libraries(test_multi_tu PRIVATE MegoHttp::megohttp)
mghttp_copy_runtime_dll(test_multi_tu)
add_test(NAME test_multi_tu COMMAND test_multi_tu)
