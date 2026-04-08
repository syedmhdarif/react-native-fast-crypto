// argon2_ref.cpp — Standalone Argon2id (RFC 9106) with inline Blake2b (RFC 7693)
// Self-contained: no external crypto library dependencies.
// Based on the PHC reference implementation structure.
// SPDX-License-Identifier: MIT

#include "argon2_ref.h"
#include "memory_guard.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace fastcrypto {
namespace argon2_ref {
namespace {

// ═══════════════════════════════════════════════════════════════════
// Blake2b (RFC 7693) — minimal implementation for Argon2
// ═══════════════════════════════════════════════════════════════════

static constexpr uint64_t BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static constexpr uint8_t BLAKE2B_SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 13, 0, 12},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static inline uint64_t rotr64(uint64_t x, int n) {
  return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64_le(const void *src) {
  const auto *p = static_cast<const uint8_t *>(src);
  return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
         (static_cast<uint64_t>(p[2]) << 16) |
         (static_cast<uint64_t>(p[3]) << 24) |
         (static_cast<uint64_t>(p[4]) << 32) |
         (static_cast<uint64_t>(p[5]) << 40) |
         (static_cast<uint64_t>(p[6]) << 48) |
         (static_cast<uint64_t>(p[7]) << 56);
}

static inline void store32_le(void *dst, uint32_t val) {
  auto *p = static_cast<uint8_t *>(dst);
  p[0] = static_cast<uint8_t>(val);
  p[1] = static_cast<uint8_t>(val >> 8);
  p[2] = static_cast<uint8_t>(val >> 16);
  p[3] = static_cast<uint8_t>(val >> 24);
}

static inline void store64_le(void *dst, uint64_t val) {
  auto *p = static_cast<uint8_t *>(dst);
  p[0] = static_cast<uint8_t>(val);
  p[1] = static_cast<uint8_t>(val >> 8);
  p[2] = static_cast<uint8_t>(val >> 16);
  p[3] = static_cast<uint8_t>(val >> 24);
  p[4] = static_cast<uint8_t>(val >> 32);
  p[5] = static_cast<uint8_t>(val >> 40);
  p[6] = static_cast<uint8_t>(val >> 48);
  p[7] = static_cast<uint8_t>(val >> 56);
}

#define B2B_G(a, b, c, d, x, y)                                               \
  a = a + b + x;                                                               \
  d = rotr64(d ^ a, 32);                                                       \
  c = c + d;                                                                   \
  b = rotr64(b ^ c, 24);                                                       \
  a = a + b + y;                                                               \
  d = rotr64(d ^ a, 16);                                                       \
  c = c + d;                                                                   \
  b = rotr64(b ^ c, 63);

struct Blake2bState {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t buf[128];
  size_t buflen;
  size_t outlen;
};

static void blake2b_compress(Blake2bState *S, const uint8_t block[128]) {
  uint64_t m[16], v[16];

  for (int i = 0; i < 16; ++i)
    m[i] = load64_le(block + i * 8);

  for (int i = 0; i < 8; ++i)
    v[i] = S->h[i];
  v[8] = BLAKE2B_IV[0];
  v[9] = BLAKE2B_IV[1];
  v[10] = BLAKE2B_IV[2];
  v[11] = BLAKE2B_IV[3];
  v[12] = BLAKE2B_IV[4] ^ S->t[0];
  v[13] = BLAKE2B_IV[5] ^ S->t[1];
  v[14] = BLAKE2B_IV[6] ^ S->f[0];
  v[15] = BLAKE2B_IV[7] ^ S->f[1];

  for (int r = 0; r < 12; ++r) {
    const uint8_t *s = BLAKE2B_SIGMA[r];
    B2B_G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
    B2B_G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
    B2B_G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
    B2B_G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
    B2B_G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
    B2B_G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
    B2B_G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
    B2B_G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
  }

  for (int i = 0; i < 8; ++i)
    S->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_init(Blake2bState *S, size_t outlen) {
  std::memset(S, 0, sizeof(*S));
  for (int i = 0; i < 8; ++i)
    S->h[i] = BLAKE2B_IV[i];
  S->h[0] ^= 0x01010000ULL ^ static_cast<uint64_t>(outlen);
  S->outlen = outlen;
}

static void blake2b_update(Blake2bState *S, const uint8_t *in, size_t inlen) {
  if (inlen == 0)
    return;

  size_t left = S->buflen;
  size_t fill = 128 - left;

  if (inlen > fill) {
    std::memcpy(S->buf + left, in, fill);
    S->t[0] += 128;
    if (S->t[0] < 128)
      S->t[1]++;
    blake2b_compress(S, S->buf);
    S->buflen = 0;
    in += fill;
    inlen -= fill;

    while (inlen > 128) {
      S->t[0] += 128;
      if (S->t[0] < 128)
        S->t[1]++;
      blake2b_compress(S, in);
      in += 128;
      inlen -= 128;
    }
  }

  std::memcpy(S->buf + S->buflen, in, inlen);
  S->buflen += inlen;
}

static void blake2b_final(Blake2bState *S, uint8_t *out) {
  S->t[0] += static_cast<uint64_t>(S->buflen);
  if (S->t[0] < S->buflen)
    S->t[1]++;
  S->f[0] = ~static_cast<uint64_t>(0);

  std::memset(S->buf + S->buflen, 0, 128 - S->buflen);
  blake2b_compress(S, S->buf);

  uint8_t buffer[64];
  for (int i = 0; i < 8; ++i)
    store64_le(buffer + i * 8, S->h[i]);
  std::memcpy(out, buffer, S->outlen);
}

static void blake2b_hash(uint8_t *out, size_t outlen, const uint8_t *in,
                         size_t inlen) {
  Blake2bState S;
  blake2b_init(&S, outlen);
  blake2b_update(&S, in, inlen);
  blake2b_final(&S, out);
}

// ═══════════════════════════════════════════════════════════════════
// Variable-length hash H' (RFC 9106, Section 3.2)
// ═══════════════════════════════════════════════════════════════════

static void hash_long(uint8_t *out, uint32_t outlen, const uint8_t *in,
                      size_t inlen) {
  uint8_t outlen_le[4];
  store32_le(outlen_le, outlen);

  if (outlen <= 64) {
    Blake2bState S;
    blake2b_init(&S, outlen);
    blake2b_update(&S, outlen_le, 4);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out);
    return;
  }

  // outlen > 64: chain Blake2b(64) calls, taking first 32 bytes each
  uint8_t v_prev[64];
  {
    Blake2bState S;
    blake2b_init(&S, 64);
    blake2b_update(&S, outlen_le, 4);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, v_prev);
  }

  std::memcpy(out, v_prev, 32);
  out += 32;
  uint32_t remaining = outlen - 32;

  while (remaining > 64) {
    uint8_t v_next[64];
    blake2b_hash(v_next, 64, v_prev, 64);
    std::memcpy(out, v_next, 32);
    out += 32;
    remaining -= 32;
    std::memcpy(v_prev, v_next, 64);
  }

  // Final block
  uint8_t v_final[64];
  blake2b_hash(v_final, remaining, v_prev, 64);
  std::memcpy(out, v_final, remaining);
}

// ═══════════════════════════════════════════════════════════════════
// Argon2 block operations
// ═══════════════════════════════════════════════════════════════════

static constexpr size_t ARGON2_BLOCK_SIZE = 1024;
static constexpr size_t ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8; // 128
static constexpr uint32_t ARGON2_SYNC_POINTS = 4;
static constexpr uint32_t ARGON2_VERSION = 0x13;
static constexpr uint32_t ARGON2_TYPE_ID = 2; // Argon2id

struct Block {
  uint64_t v[ARGON2_QWORDS_IN_BLOCK];
};

static inline void block_zero(Block *b) { std::memset(b, 0, sizeof(Block)); }

static inline void block_xor(Block *dst, const Block *src) {
  for (size_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
    dst->v[i] ^= src->v[i];
}

static inline void block_copy(Block *dst, const Block *src) {
  std::memcpy(dst, src, sizeof(Block));
}

// Argon2 BlaMka mixing — multiplication of lower 32 bits for memory-hardness
#define ARGON2_GB(a, b, c, d)                                                  \
  do {                                                                         \
    a = a + b + 2 * static_cast<uint64_t>(static_cast<uint32_t>(a)) *         \
                    static_cast<uint64_t>(static_cast<uint32_t>(b));           \
    d = rotr64(d ^ a, 32);                                                     \
    c = c + d + 2 * static_cast<uint64_t>(static_cast<uint32_t>(c)) *         \
                    static_cast<uint64_t>(static_cast<uint32_t>(d));           \
    b = rotr64(b ^ c, 24);                                                     \
    a = a + b + 2 * static_cast<uint64_t>(static_cast<uint32_t>(a)) *         \
                    static_cast<uint64_t>(static_cast<uint32_t>(b));           \
    d = rotr64(d ^ a, 16);                                                     \
    c = c + d + 2 * static_cast<uint64_t>(static_cast<uint32_t>(c)) *         \
                    static_cast<uint64_t>(static_cast<uint32_t>(d));           \
    b = rotr64(b ^ c, 63);                                                     \
  } while (0)

// Permutation P operating on 16 uint64 values (128 bytes)
static void permutation_P(uint64_t *v) {
  ARGON2_GB(v[0], v[4], v[8], v[12]);
  ARGON2_GB(v[1], v[5], v[9], v[13]);
  ARGON2_GB(v[2], v[6], v[10], v[14]);
  ARGON2_GB(v[3], v[7], v[11], v[15]);
  ARGON2_GB(v[0], v[5], v[10], v[15]);
  ARGON2_GB(v[1], v[6], v[11], v[12]);
  ARGON2_GB(v[2], v[7], v[8], v[13]);
  ARGON2_GB(v[3], v[4], v[9], v[14]);
}

// fill_block: matches the canonical PHC reference implementation.
// Computes: result = P(Z) XOR R, where:
//   R = prev XOR ref
//   Z = R (pass 0) or R XOR old_result (pass > 0, with_xor=true)
// The XOR with old is folded BEFORE permutations (not after), which matters
// because the BlaMka permutation is nonlinear.
static void fill_block(const Block *prev, const Block *ref, Block *next_block,
                        bool with_xor) {
  Block R;
  for (size_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
    R.v[i] = prev->v[i] ^ ref->v[i];

  Block Z;
  block_copy(&Z, &R);

  // For pass > 0: fold old value into Z before permutations
  if (with_xor) {
    block_xor(&Z, next_block);
  }

  // Row-wise: 8 rows of 16 uint64 each
  for (int i = 0; i < 8; ++i)
    permutation_P(&Z.v[i * 16]);

  // Column-wise: 8 columns — each column has 8 pairs of uint64
  for (int j = 0; j < 8; ++j) {
    uint64_t col[16];
    for (int k = 0; k < 8; ++k) {
      col[k * 2] = Z.v[k * 16 + j * 2];
      col[k * 2 + 1] = Z.v[k * 16 + j * 2 + 1];
    }
    permutation_P(col);
    for (int k = 0; k < 8; ++k) {
      Z.v[k * 16 + j * 2] = col[k * 2];
      Z.v[k * 16 + j * 2 + 1] = col[k * 2 + 1];
    }
  }

  // next_block = Z XOR R
  for (size_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i)
    next_block->v[i] = Z.v[i] ^ R.v[i];
}

// Convenience wrapper for address generation (no XOR, separate output)
static void compress_G(Block *result, const Block *X, const Block *Y) {
  fill_block(X, Y, result, false);
}

// ═══════════════════════════════════════════════════════════════════
// Argon2id addressing
// ═══════════════════════════════════════════════════════════════════

// Generate next pseudo-random address block (increments counter)
static void next_addresses(Block *address_block, Block *input_block,
                           const Block *zero_block) {
  input_block->v[6]++;
  Block tmp;
  compress_G(&tmp, zero_block, input_block);
  compress_G(address_block, zero_block, &tmp);
}

// Map J1 to a reference block index within the reference area
static uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index,
                            uint32_t pseudo_rand, bool same_lane,
                            uint32_t lane_length, uint32_t segment_length) {
  uint32_t reference_area_size;

  if (pass == 0) {
    if (slice == 0) {
      reference_area_size = index - 1;
    } else {
      if (same_lane) {
        reference_area_size = slice * segment_length + index - 1;
      } else {
        reference_area_size =
            slice * segment_length - (index == 0 ? 1 : 0);
      }
    }
  } else {
    if (same_lane) {
      reference_area_size = lane_length - segment_length + index - 1;
    } else {
      reference_area_size =
          lane_length - segment_length - (index == 0 ? 1 : 0);
    }
  }

  uint64_t relative_position = pseudo_rand;
  relative_position = (relative_position * relative_position) >> 32;
  relative_position =
      reference_area_size - 1 -
      ((static_cast<uint64_t>(reference_area_size) * relative_position) >> 32);

  uint32_t start_position = 0;
  if (pass != 0) {
    start_position = (slice == ARGON2_SYNC_POINTS - 1)
                         ? 0
                         : (slice + 1) * segment_length;
  }

  return (start_position + static_cast<uint32_t>(relative_position)) %
         lane_length;
}

// Fill one segment (one slice of one lane)
static void fill_segment(Block *memory, uint32_t pass, uint32_t slice,
                         uint32_t lane, uint32_t lanes, uint32_t lane_length,
                         uint32_t segment_length, uint32_t total_blocks,
                         uint32_t t_cost) {
  bool data_independent =
      (pass == 0 && slice < (ARGON2_SYNC_POINTS / 2)); // Argon2id

  Block zero_block, input_block, address_block;
  block_zero(&zero_block);
  block_zero(&input_block);

  if (data_independent) {
    input_block.v[0] = pass;
    input_block.v[1] = lane;
    input_block.v[2] = slice;
    input_block.v[3] = total_blocks;
    input_block.v[4] = t_cost;
    input_block.v[5] = ARGON2_TYPE_ID;
    // v[6] = counter (starts at 0, next_addresses increments before use)
  }

  uint32_t starting_index = 0;
  if (pass == 0 && slice == 0) {
    starting_index = 2; // First two blocks already initialized
    if (data_independent) {
      next_addresses(&address_block, &input_block, &zero_block);
    }
  }

  uint32_t curr_offset =
      lane * lane_length + slice * segment_length + starting_index;
  uint32_t prev_offset =
      (curr_offset % lane_length == 0) ? (curr_offset + lane_length - 1)
                                       : (curr_offset - 1);

  for (uint32_t i = starting_index; i < segment_length;
       ++i, ++curr_offset, ++prev_offset) {
    // Wrap prev_offset at lane boundary
    if (curr_offset % lane_length == 1) {
      prev_offset = curr_offset - 1;
    }
    if (curr_offset % lane_length == 0) {
      prev_offset = curr_offset + lane_length - 1;
    }

    uint64_t pseudo_rand;
    if (data_independent) {
      if (i % ARGON2_QWORDS_IN_BLOCK == 0) {
        next_addresses(&address_block, &input_block, &zero_block);
      }
      pseudo_rand = address_block.v[i % ARGON2_QWORDS_IN_BLOCK];
    } else {
      pseudo_rand = memory[prev_offset].v[0];
    }

    uint32_t J1 = static_cast<uint32_t>(pseudo_rand & 0xFFFFFFFF);
    uint32_t J2 = static_cast<uint32_t>(pseudo_rand >> 32);

    uint32_t ref_lane = J2 % lanes;
    if (pass == 0 && slice == 0) {
      ref_lane = lane;
    }

    bool same_lane = (ref_lane == lane);
    uint32_t ref_index =
        index_alpha(pass, slice, i, J1, same_lane, lane_length, segment_length);

    uint32_t ref_offset = ref_lane * lane_length + ref_index;

    fill_block(&memory[prev_offset], &memory[ref_offset],
               &memory[curr_offset], /*with_xor=*/pass != 0);
  }
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

int argon2id_hash(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                  const void *pwd, size_t pwdlen, const void *salt,
                  size_t saltlen, void *hash, size_t hashlen) {
  if (t_cost == 0 || parallelism == 0 || hashlen == 0 ||
      hashlen > 0xFFFFFFFFULL)
    return -1;
  if (!salt || saltlen < 8)
    return -1;
  if (!hash)
    return -1;

  // Minimum memory: 8 * parallelism KiB
  uint32_t memory_blocks = m_cost;
  if (memory_blocks < 8 * parallelism)
    memory_blocks = 8 * parallelism;

  // Round down to multiple of 4 * parallelism
  uint32_t segment_length =
      memory_blocks / (parallelism * ARGON2_SYNC_POINTS);
  if (segment_length < 1)
    segment_length = 1;

  uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
  uint32_t total_blocks = lane_length * parallelism;

  // Allocate memory
  std::vector<Block> memory(total_blocks);
  std::memset(memory.data(), 0, total_blocks * sizeof(Block));

  // ── Step 1: Compute H0 ──────────────────────────────────────────
  uint8_t H0[64];
  {
    Blake2bState S;
    blake2b_init(&S, 64);

    uint8_t le[4];
    store32_le(le, parallelism);
    blake2b_update(&S, le, 4);
    store32_le(le, static_cast<uint32_t>(hashlen));
    blake2b_update(&S, le, 4);
    store32_le(le, m_cost);
    blake2b_update(&S, le, 4);
    store32_le(le, t_cost);
    blake2b_update(&S, le, 4);
    store32_le(le, ARGON2_VERSION);
    blake2b_update(&S, le, 4);
    store32_le(le, ARGON2_TYPE_ID);
    blake2b_update(&S, le, 4);

    store32_le(le, static_cast<uint32_t>(pwdlen));
    blake2b_update(&S, le, 4);
    if (pwdlen > 0)
      blake2b_update(&S, static_cast<const uint8_t *>(pwd), pwdlen);

    store32_le(le, static_cast<uint32_t>(saltlen));
    blake2b_update(&S, le, 4);
    blake2b_update(&S, static_cast<const uint8_t *>(salt), saltlen);

    // Secret key (empty)
    store32_le(le, 0);
    blake2b_update(&S, le, 4);

    // Associated data (empty)
    store32_le(le, 0);
    blake2b_update(&S, le, 4);

    blake2b_final(&S, H0);
  }

  // ── Step 2: Initialize first two blocks per lane ─────────────────
  {
    uint8_t input[72]; // H0(64) + LE32(col_index) + LE32(lane)
    std::memcpy(input, H0, 64);

    for (uint32_t i = 0; i < parallelism; ++i) {
      store32_le(input + 68, i);

      store32_le(input + 64, 0);
      hash_long(reinterpret_cast<uint8_t *>(memory[i * lane_length].v), 1024,
                input, 72);

      store32_le(input + 64, 1);
      hash_long(reinterpret_cast<uint8_t *>(memory[i * lane_length + 1].v),
                1024, input, 72);
    }
  }

  // ── Step 3: Fill memory (sequential — single-threaded) ───────────
  for (uint32_t pass = 0; pass < t_cost; ++pass) {
    for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; ++slice) {
      for (uint32_t lane = 0; lane < parallelism; ++lane) {
        fill_segment(memory.data(), pass, slice, lane, parallelism,
                     lane_length, segment_length, total_blocks, t_cost);
      }
    }
  }

  // ── Step 4: Finalize ─────────────────────────────────────────────
  // XOR last block of all lanes
  Block final_block;
  block_copy(&final_block, &memory[lane_length - 1]);
  for (uint32_t i = 1; i < parallelism; ++i) {
    block_xor(&final_block, &memory[i * lane_length + lane_length - 1]);
  }

  hash_long(static_cast<uint8_t *>(hash), static_cast<uint32_t>(hashlen),
            reinterpret_cast<const uint8_t *>(final_block.v), ARGON2_BLOCK_SIZE);

  // Securely clear memory
  volatile uint8_t *mp =
      reinterpret_cast<volatile uint8_t *>(memory.data());
  for (size_t i = 0; i < total_blocks * sizeof(Block); ++i)
    mp[i] = 0;

  return 0;
}

} // namespace argon2_ref
} // namespace fastcrypto
