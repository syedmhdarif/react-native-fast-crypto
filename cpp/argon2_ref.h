// argon2_ref.h — Standalone Argon2id (RFC 9106) reference implementation
// No external dependencies. Used as fallback when OpenSSL < 3.0 and no libsodium.
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>

namespace fastcrypto {
namespace argon2_ref {

// Compute Argon2id key derivation per RFC 9106.
// Returns 0 on success, -1 on invalid parameters.
int argon2id_hash(uint32_t t_cost,      // number of passes (iterations), >= 1
                  uint32_t m_cost,      // memory in KiB, >= 8*parallelism
                  uint32_t parallelism, // degree of parallelism (lanes), >= 1
                  const void *pwd, size_t pwdlen,
                  const void *salt, size_t saltlen,
                  void *hash, size_t hashlen);

} // namespace argon2_ref
} // namespace fastcrypto
