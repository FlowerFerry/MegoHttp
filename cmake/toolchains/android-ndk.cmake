# CMake toolchain for Android NDK cross-compilation.
#
# Usage (from tests/cross_compile):
#   cmake -S . -B build-android -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=<repo>/cmake/toolchains/android-ndk.cmake \
#     -DANDROID_ABI=arm64-v8a \
#     -DANDROID_PLATFORM=android-21 \
#     -DMEGOHTTP_SOURCE_DIR=<repo>
#
# ANDROID_NDK_HOME may be set in the environment or passed as a cache
# variable. This file only supplies defaults and delegates the real
# compiler/sysroot setup to the NDK's own toolchain file.

set(ANDROID_NDK_HOME "$ENV{ANDROID_NDK_HOME}" CACHE PATH "Android NDK root")
if(NOT ANDROID_NDK_HOME)
    message(FATAL_ERROR
        "ANDROID_NDK_HOME is not set. Install an NDK and export ANDROID_NDK_HOME "
        "or pass -DANDROID_NDK_HOME=<path>.")
endif()

set(ANDROID_ABI "arm64-v8a" CACHE STRING "Android ABI")
set(ANDROID_PLATFORM "android-21" CACHE STRING "Android API level")
set(ANDROID_STL "c++_static" CACHE STRING "Android STL")

include("${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake")
