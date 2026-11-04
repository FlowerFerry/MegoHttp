# Tests are standalone executables that report "=== N passed, M failed ===".
# They use a plain assert-style CHECK macro: no test framework, so a failing
# build never depends on fetching one.

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
    target_link_libraries(${test_name} PRIVATE MegoHttp::megohttp)
    target_compile_definitions(${test_name} PRIVATE MGHTTP_INTERNAL_TESTING=1)
    mghttp_copy_runtime_dll(${test_name})
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Multi-TU link test: proves every non-template definition in the headers is
# inline. Two TUs that use the same headers must link together.
add_executable(test_multi_tu tu_a.cpp tu_b.cpp)
target_link_libraries(test_multi_tu PRIVATE MegoHttp::megohttp)
mghttp_copy_runtime_dll(test_multi_tu)
add_test(NAME test_multi_tu COMMAND test_multi_tu)
