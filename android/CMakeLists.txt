cmake_minimum_required(VERSION 3.22.1)
project(fast_crypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security hardening flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Use OpenSSL on Android
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
# OpenSSL — provided via prefab from the host app or a third-party package.
# Projects typically provide OpenSSL via one of:
#   1. prefab (find_package)
#   2. Pre-built static libs pointed to by OPENSSL_ROOT_DIR
# ---------------------------------------------------------------------------

# Try prefab first (used by apps that ship OpenSSL via Gradle dependencies)
find_package(openssl QUIET CONFIG)

if(openssl_FOUND)
  target_link_libraries(fast_crypto
    openssl::ssl
    openssl::crypto
  )
else()
  # Fallback: expect OPENSSL_ROOT_DIR to be set (e.g. from build.gradle)
  if(DEFINED OPENSSL_ROOT_DIR)
    target_include_directories(fast_crypto PRIVATE
      ${OPENSSL_ROOT_DIR}/include
    )
    # Link against pre-built static libraries for the target ABI
    find_library(OPENSSL_SSL_LIB ssl PATHS ${OPENSSL_ROOT_DIR}/lib/${ANDROID_ABI} NO_DEFAULT_PATH)
    find_library(OPENSSL_CRYPTO_LIB crypto PATHS ${OPENSSL_ROOT_DIR}/lib/${ANDROID_ABI} NO_DEFAULT_PATH)
    target_link_libraries(fast_crypto
      ${OPENSSL_SSL_LIB}
      ${OPENSSL_CRYPTO_LIB}
    )
  else()
    message(WARNING
      "OpenSSL not found via prefab or OPENSSL_ROOT_DIR. "
      "You must provide OpenSSL for the target Android ABIs. "
      "See the project README for instructions."
    )
    # Still try system find as a last resort
    find_package(OpenSSL REQUIRED)
    target_link_libraries(fast_crypto OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

# ---------------------------------------------------------------------------
# Android system libraries
# ---------------------------------------------------------------------------

find_library(LOG_LIB log)
target_link_libraries(fast_crypto ${LOG_LIB})
