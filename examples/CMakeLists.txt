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

function(mghttp_add_example name)
    add_executable(megohttp_example_${name} ${ARGN})
    target_link_libraries(megohttp_example_${name} PRIVATE MegoHttp::megohttp)
    mghttp_copy_runtime_dll(megohttp_example_${name})
    mghttp_copy_tls_runtime_dll(megohttp_example_${name})
    message(STATUS "MegoHttp examples: ${name}")
endfunction()

# Always available: plain HTTP, no optional feature involved.
mghttp_add_example(sync_get sync_get.cpp)
mghttp_add_example(future_get future_get.cpp)
mghttp_add_example(callback_cancel callback_cancel.cpp)
mghttp_add_example(stream_download stream_download.cpp)

# Multipart is part of the core request pipeline (no feature switch), so the
# upload and both response-streaming examples are always built.
mghttp_add_example(multipart_upload multipart_upload.cpp)
mghttp_add_example(multipart_response multipart_response.cpp)
mghttp_add_example(multipart_continuous multipart_continuous.cpp)

# Proxies are part of the core pipeline; the HTTPS-proxy variants additionally
# need a TLS backend, and the WSS one needs WebSocket + deflate.
mghttp_add_example(proxy_cookie proxy_cookie.cpp)

if(NOT MGHTTP_TLS_NONE)
    mghttp_add_example(https_proxy_to_http https_proxy_to_http.cpp)
    mghttp_add_example(https_proxy_to_https https_proxy_to_https.cpp)
else()
    message(STATUS "MegoHttp examples: skip https_proxy_* (MGHTTP_TLS_NONE is ON)")
endif()

if(MGHTTP_ENABLE_WEBSOCKET AND MGHTTP_ENABLE_WEBSOCKET_DEFLATE AND NOT MGHTTP_TLS_NONE)
    mghttp_add_example(wss_via_https_proxy wss_via_https_proxy.cpp)
else()
    message(STATUS "MegoHttp examples: skip wss_via_https_proxy (needs WebSocket + deflate + TLS)")
endif()

# HTTPS + custom CA needs a TLS backend; with TLS_NONE there is no https:// to
# demonstrate, so the example is skipped instead of failing to link.
if(NOT MGHTTP_TLS_NONE)
    mghttp_add_example(https_custom_ca https_custom_ca.cpp)
else()
    message(STATUS "MegoHttp examples: skip https_custom_ca (MGHTTP_TLS_NONE is ON)")
endif()

# External event loops: one per compiled-in backend. The skip is reported, not
# hidden, so a build that silently drops an example cannot look complete.
if(MGHTTP_BACKEND_LIBUV)
    mghttp_add_example(external_libuv_loop external_libuv_loop.cpp)
else()
    message(STATUS "MegoHttp examples: skip external_libuv_loop (libuv backend is OFF)")
endif()

if(MGHTTP_BACKEND_ASIO)
    mghttp_add_example(external_asio_loop external_asio_loop.cpp)
else()
    message(STATUS "MegoHttp examples: skip external_asio_loop (Asio backend is OFF)")
endif()

# Streaming protocols: each is its own feature switch.
if(MGHTTP_ENABLE_SSE)
    mghttp_add_example(sse_client sse_client.cpp)
else()
    message(STATUS "MegoHttp examples: skip sse_client (MGHTTP_ENABLE_SSE is OFF)")
endif()

if(MGHTTP_ENABLE_WEBSOCKET)
    mghttp_add_example(websocket_echo websocket_echo.cpp)
    mghttp_add_example(ws_reconnect_auth ws_reconnect_auth.cpp)
else()
    message(STATUS "MegoHttp examples: skip websocket_echo/ws_reconnect_auth (MGHTTP_ENABLE_WEBSOCKET is OFF)")
endif()

# The deflate examples need the extension compiled in; WebSocketOptions::enabled
# alone does not make `permessage-deflate` available.
if(MGHTTP_ENABLE_WEBSOCKET AND MGHTTP_ENABLE_WEBSOCKET_DEFLATE)
    mghttp_add_example(ws_deflate_negotiation ws_deflate_negotiation.cpp)
    mghttp_add_example(ws_deflate_stream ws_deflate_stream.cpp)
    mghttp_add_example(ws_reconnect_deflate ws_reconnect_deflate.cpp)
else()
    message(STATUS "MegoHttp examples: skip ws_deflate_* (MGHTTP_ENABLE_WEBSOCKET_DEFLATE is OFF)")
endif()

# Encrypted DNS: DoT and DoH are separate switches, and the strict-bootstrap
# example is DoT-based, so it follows the DoT switch.
if(MGHTTP_ENABLE_DOT)
    mghttp_add_example(dot_resolve dot_resolve.cpp)
    mghttp_add_example(encrypted_dns_strict_bootstrap encrypted_dns_strict_bootstrap.cpp)
else()
    message(STATUS "MegoHttp examples: skip dot_resolve/encrypted_dns_strict_bootstrap (MGHTTP_ENABLE_DOT is OFF)")
endif()

if(MGHTTP_ENABLE_DOH)
    mghttp_add_example(doh_resolve doh_resolve.cpp)
else()
    message(STATUS "MegoHttp examples: skip doh_resolve (MGHTTP_ENABLE_DOH is OFF)")
endif()

# C++20: a C++17 tree has MGHTTP_ENABLE_COROUTINES=OFF, so the coroutine example
# is skipped instead of failing to compile with "requires C++20".
if(MGHTTP_ENABLE_COROUTINES)
    mghttp_add_example(coroutine_get coroutine_get.cpp)
else()
    message(STATUS "MegoHttp examples: skip coroutine_get (MGHTTP_ENABLE_COROUTINES is OFF)")
endif()
