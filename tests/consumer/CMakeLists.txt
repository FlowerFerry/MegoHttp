cmake_minimum_required(VERSION 3.16)
project(megohttp_consumer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Consume the INSTALLED package, not the source tree (S1.9-04).
find_package(MegoHttp REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE MegoHttp::megohttp)

# The installed package links libmeme_string.dll at runtime. It is an external,
# separately-built dependency so it is not part of the install tree; the consumer
# is responsible for deployment. Copy it next to the executable when it is
# reachable from this machine.
if(MSVC)
    file(GLOB _meme_dll
         "$ENV{MGHTTP_MEMESTRING_DIR}/*.dll"
         "D:/_mego_openlib/MemeString/build/Release/libmeme_string.dll")
    foreach(_dll IN LISTS _meme_dll)
        if(EXISTS "${_dll}")
            add_custom_command(TARGET consumer POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${_dll}" "$<TARGET_FILE_DIR:consumer>")
            break()
        endif()
    endforeach()
endif()
