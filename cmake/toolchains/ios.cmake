# CMake toolchain for an iOS device build (arm64, iphoneos SDK).
#
# Usage (from tests/cross_compile):
#   cmake -S . -B build-ios -G Xcode \
#     -DCMAKE_TOOLCHAIN_FILE=<repo>/cmake/toolchains/ios.cmake \
#     -DMEGOHTTP_SOURCE_DIR=<repo>
#
# The resulting library is cross-compiled only; running it requires a simulator
# or a signed device build.

set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_SYSROOT "iphoneos" CACHE STRING "iOS SDK")
set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "iOS architectures")
set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum iOS version")
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO" CACHE STRING "No signing for cross-compile")
