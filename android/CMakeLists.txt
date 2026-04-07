cmake_minimum_required(VERSION 3.22.1)
project(fast_crypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security hardening flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# 16KB page size support (required for Android 15+ devices/emulators)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

# Use OpenSSL on Android (1.1.1 - Argon2 not available, other crypto works)
add_definitions(-DFAST_CRYPTO_USE_OPENSSL)

# ---------------------------------------------------------------------------
# Shared C++ core sources (relative to project root cpp/ directory)
# ---------------------------------------------------------------------------

set(CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../cpp")

set(FAST_CRYPTO_CORE_SOURCES
  ${CPP_DIR}/fast_crypto_core.cpp
)

set(FAST_CRYPTO_JNI_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/main/jni/fast_crypto_jni.cpp
)

# ---------------------------------------------------------------------------
# Build shared library
# ---------------------------------------------------------------------------

add_library(fast_crypto SHARED
  ${FAST_CRYPTO_CORE_SOURCES}
  ${FAST_CRYPTO_JNI_SOURCES}
)

target_include_directories(fast_crypto PRIVATE
  ${CPP_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/src/main/jni
)

# ---------------------------------------------------------------------------
# OpenSSL 1.1.1 — provided via prefab
# ---------------------------------------------------------------------------

find_package(openssl REQUIRED CONFIG)

target_link_libraries(fast_crypto
  openssl::crypto
)

# ---------------------------------------------------------------------------
# Android system libraries
# ---------------------------------------------------------------------------

find_library(LOG_LIB log)
target_link_libraries(fast_crypto ${LOG_LIB})
