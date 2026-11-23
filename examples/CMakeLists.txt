# ---------------------------------------------------------------------------
# MegoHttp examples
#
# Each example is added only when the feature it demonstrates is compiled in.
# A C++17 tree has MGHTTP_ENABLE_COROUTINES=OFF, so the coroutine example is
# skipped instead of failing to compile with "requires C++20".
#
# Runtime DLLs are copied next to each executable by the helpers defined in the
# top-level CMakeLists (mghttp_copy_runtime_dll for MemeString,
# mghttp_copy_tls_runtime_dll for the OpenSSL shared runtime).
# ---------------------------------------------------------------------------

if(MGHTTP_ENABLE_COROUTINES)
    add_executable(megohttp_example_coroutine_get coroutine_get.cpp)
    target_link_libraries(megohttp_example_coroutine_get PRIVATE MegoHttp::megohttp)
    mghttp_copy_runtime_dll(megohttp_example_coroutine_get)
    mghttp_copy_tls_runtime_dll(megohttp_example_coroutine_get)
    message(STATUS "MegoHttp examples: coroutine_get")
else()
    message(STATUS "MegoHttp examples: none (MGHTTP_ENABLE_COROUTINES is OFF)")
endif()
