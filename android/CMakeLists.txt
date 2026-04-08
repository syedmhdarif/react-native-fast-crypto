cmake_minimum_required(VERSION 3.22.1)
project(fast_crypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security hardening flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# 16KB page size support (required for Android 15+ devices/emulators)
# Dead code elimination (complements -ffunction-sections/-fdata-sections from OpenSSL build)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384 -Wl,--gc-sections")

# Use OpenSSL on Android (1.1.1w + standalone Argon2id reference implementation)
add_definitions(-DFAST_CRYPTO_USE_OPENSSL)

# ---------------------------------------------------------------------------
# Shared C++ core sources (relative to project root cpp/ directory)
# ---------------------------------------------------------------------------

set(CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../cpp")

set(FAST_CRYPTO_CORE_SOURCES
  ${CPP_DIR}/fast_crypto_core.cpp
  ${CPP_DIR}/argon2_ref.cpp
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
# OpenSSL 1.1.1w — vendored static library (built by scripts/build-openssl-android.sh)
#
# We vendor a pre-built static libcrypto.a for each ABI to guarantee 16KB page
# alignment. The final .so inherits alignment from -Wl,-z,max-page-size=16384
# set above. No prefab dependency needed.
# ---------------------------------------------------------------------------

set(OPENSSL_LIBS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs")

# Find the correct libcrypto.a for the current ABI
set(OPENSSL_CRYPTO_LIB "${OPENSSL_LIBS_DIR}/${ANDROID_ABI}/libcrypto.a")

if(NOT EXISTS "${OPENSSL_CRYPTO_LIB}")
  message(FATAL_ERROR
    "FastCrypto: vendored libcrypto.a not found at ${OPENSSL_CRYPTO_LIB}\n"
    "Run: scripts/build-openssl-android.sh to build OpenSSL for Android."
  )
endif()

message(STATUS "FastCrypto: using vendored OpenSSL from ${OPENSSL_CRYPTO_LIB}")

add_library(openssl_crypto STATIC IMPORTED)
set_target_properties(openssl_crypto PROPERTIES
  IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIB}"
  INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_LIBS_DIR}/include"
)

target_link_libraries(fast_crypto openssl_crypto)

# ---------------------------------------------------------------------------
# Android system libraries (libcrypto.a may need these)
# ---------------------------------------------------------------------------

find_library(LOG_LIB log)
target_link_libraries(fast_crypto ${LOG_LIB} dl atomic)
