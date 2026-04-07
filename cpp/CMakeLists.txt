cmake_minimum_required(VERSION 3.22.1)
project(FastCrypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security hardening flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Shared C++ source files
set(FAST_CRYPTO_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/fast_crypto_core.cpp
)

set(FAST_CRYPTO_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/fast_crypto_core.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memory_guard.h
  ${CMAKE_CURRENT_SOURCE_DIR}/thread_pool.h
)

# Crypto engine selection (default: OpenSSL)
option(FAST_CRYPTO_ENGINE "Crypto engine: openssl or libsodium" "openssl")

if(FAST_CRYPTO_ENGINE STREQUAL "libsodium")
  add_definitions(-DFAST_CRYPTO_USE_LIBSODIUM)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED libsodium)
else()
  add_definitions(-DFAST_CRYPTO_USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
endif()
