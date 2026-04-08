---
name: crypto-perf-analyzer
description: Analyzes and optimizes native cryptography library performance, package size, and security hardening for React Native TurboModules with C++/OpenSSL backends.
---

# Crypto Performance Analyzer

A specialized skill for analyzing and optimizing React Native native cryptography libraries across three pillars: **package size**, **runtime performance**, and **security hardening** — without compromising any of the three.

## When to Use This Skill

Use when working on a React Native TurboModule crypto library that:

- Uses C++/OpenSSL/libsodium native backends
- Ships vendored static libraries (`.a` / `.so`) in the npm package
- Bridges binary data between JS and native via JSI/TurboModule
- Needs to balance speed, size, and cryptographic security

## Architecture Context

```
JS (ArrayBuffer) ─── ab2b64 ──→ TurboModule (Base64 string) ──→ C++ Core (uint8_t*)
                  ←── b642ab ───                              ←──
```

The three optimization surfaces are:
1. **Native binary** — compiled C++/OpenSSL static libs (bulk of package size)
2. **Bridge layer** — Base64 encoding/decoding overhead per call
3. **C++ core** — algorithm implementation, memory management, threading

---

## Pillar 1: Package Size Reduction

### Analysis Checklist

Run these diagnostics to identify size bottlenecks:

```bash
# 1. Measure current npm package size
npm pack --dry-run 2>&1 | tail -1

# 2. Break down what's in the package
npm pack && tar tzf *.tgz | head -50

# 3. Measure native library sizes (the main culprit)
ls -lh android/libs/*/libcrypto.a
# Target: < 3MB per ABI for crypto-only OpenSSL

# 4. Analyze what symbols are in the static library
nm --size-sort android/libs/arm64-v8a/libcrypto.a | tail -30

# 5. Check which OpenSSL modules are compiled in
ar t android/libs/arm64-v8a/libcrypto.a | sort | head -40

# 6. Count shipped OpenSSL headers
ls android/libs/include/openssl/*.h | wc -l
# Target: < 50 headers (only transitive deps of used APIs)
```

### Optimization Strategies (Ordered by Impact)

#### 1. OpenSSL Configure Flags (HIGH IMPACT)

The OpenSSL `./Configure` call determines which algorithms are compiled into `libcrypto.a`. Disable everything not used by the crypto core.

**Required modules** (based on actual C++ code usage):
- `evp` — AES-GCM, ChaCha20-Poly1305, Ed25519, X25519
- `sha` — SHA-256, SHA-512
- `rand` — CSPRNG (RAND_bytes)
- `ec` — Elliptic curves (Ed25519, X25519)
- `bn` — Big number (required by EC)

**Disable flags to add** (if not already present):
```bash
no-aria no-blake2 no-camellia no-cast no-chacha  # Only if NOT using ChaCha20
no-cmac no-cmp no-cms no-comp no-ct
no-des no-dh no-dsa no-dtls no-engine
no-filenames no-gost no-hw no-idea
no-md2 no-md4 no-mdc2 no-nextprotoneg
no-ocsp no-psk no-rc2 no-rc4 no-rc5
no-ripemd no-seed no-sm2 no-sm3 no-sm4
no-srp no-srtp no-ssl no-tls no-ts
no-whirlpool no-async no-sock no-dgram
no-scrypt no-heartbeats no-bf
```

**Verify after rebuild:**
```bash
# Compare before/after
ls -lh android/libs/arm64-v8a/libcrypto.a
# Expected: 30-50% reduction from full OpenSSL build
```

#### 2. Compiler Optimization Flags (MEDIUM IMPACT)

Add to CMakeLists.txt and OpenSSL Configure:

```cmake
# Link-Time Optimization (LTO) — eliminates unused code across translation units
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=thin")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto=thin")

# Garbage collect unused sections
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")

# Optimize for size over speed (trade ~5% speed for ~15% smaller binary)
# Use -Os instead of -O2 if size is the priority
set(CMAKE_CXX_FLAGS_RELEASE "-Os -DNDEBUG")
```

For OpenSSL build script, add to `./Configure`:
```bash
-Os -flto=thin -ffunction-sections -fdata-sections
```

#### 3. Strip Debug Symbols (MEDIUM IMPACT)

```bash
# After building libcrypto.a, strip debug info
llvm-strip --strip-debug android/libs/arm64-v8a/libcrypto.a
llvm-strip --strip-debug android/libs/x86_64/libcrypto.a
# Expected: 10-20% size reduction
```

#### 4. Header Trimming (LOW-MEDIUM IMPACT)

The `trim-openssl-headers.sh` script should keep ONLY headers transitively required by the actual `#include` directives in C++ code. Audit with:

```bash
# Find all OpenSSL headers actually included (direct + transitive)
gcc -M -DFAST_CRYPTO_USE_OPENSSL cpp/fast_crypto_core.cpp 2>/dev/null | \
  tr ' ' '\n' | grep openssl/ | sort -u
```

#### 5. ABI Filtering

Only ship ABIs your users need:

```gradle
// build.gradle — 64-bit only (covers 99%+ of active Android devices)
ndk {
    abiFilters "arm64-v8a", "x86_64"
}
```

Drop `x86_64` if not targeting emulators in production builds (saves ~4.8MB).

#### 6. Consider libsodium Alternative

libsodium is purpose-built for the exact algorithms this library uses and produces a **much smaller** static binary:

| Library | Static Size (arm64) | Algorithms |
|---------|-------------------|------------|
| OpenSSL 1.1.1 (minimal) | ~3-5 MB | Everything + kitchen sink |
| libsodium | ~400-600 KB | AES-GCM, ChaCha20, Ed25519, X25519, Argon2id, SHA |

**Migration path:**
- libsodium natively supports: ChaCha20-Poly1305, Ed25519, X25519, Argon2id, SHA-256/512, CSPRNG
- AES-256-GCM available via `crypto_aead_aes256gcm` (requires AES-NI hardware, available on arm64-v8a)
- The C++ core already has `#ifdef FAST_CRYPTO_USE_LIBSODIUM` stubs

**Size savings: ~80-90% reduction in native library size.**

---

## Pillar 2: Performance Optimization

### Benchmarking Protocol

Always measure before and after changes. Use the existing benchmark suite:

```typescript
// __tests__/benchmarks/crypto-bench.ts
import { runBenchmarks } from './crypto-bench';
const results = await runBenchmarks();
// Reports: name, iterations, totalMs, avgMs, opsPerSec
```

**Key metrics to track:**

| Operation | Target (arm64) | Notes |
|-----------|---------------|-------|
| SHA-256 sync (small) | < 0.05ms | Should be sub-microsecond on native |
| AES-256-GCM encrypt (256B) | < 0.1ms | Hardware-accelerated on ARM |
| Ed25519 keygen | < 1ms | Most expensive common op |
| Ed25519 sign | < 0.5ms | Signature generation |
| generateRandomBytes(32) | < 0.05ms | CSPRNG seeding |

### Optimization Strategies (Ordered by Impact)

#### 1. Eliminate Base64 Bridge Overhead (HIGH IMPACT)

**Current bottleneck:** Every call converts `ArrayBuffer → Base64 string → native bytes → Base64 string → ArrayBuffer`. For a 1KB payload, this adds ~4KB of base64 encoding/decoding overhead per round trip.

**Solution: Direct ArrayBuffer via JSI**

```cpp
// Instead of receiving base64 strings, receive JSI ArrayBuffer directly
jsi::Value hash(jsi::Runtime &rt, const jsi::Value *args, size_t count) {
    auto arrayBuffer = args[0].asObject(rt).getArrayBuffer(rt);
    const uint8_t* data = arrayBuffer.data(rt);
    size_t length = arrayBuffer.size(rt);
    // Process directly — zero copy
}
```

**Impact:** Eliminates ~30-50% overhead on small payloads (where encoding cost dominates compute cost). For SHA-256 of 11 bytes, the base64 round-trip may cost more than the actual hash.

**Tradeoff:** Requires C++ JSI host objects instead of TurboModule codegen spec. More complex but significantly faster for binary-heavy APIs.

#### 2. Thread Pool Tuning (MEDIUM IMPACT)

Current: `std::thread::hardware_concurrency()` clamped to 2-8.

**Guidelines:**
- **Crypto-bound workloads** are CPU-intensive, not I/O-bound
- On mobile, more than 4 threads rarely helps (thermal throttling)
- For async operations, consider a dedicated single-thread pool for crypto to avoid contention with RN's JS thread pool

```cpp
// Optimal for mobile crypto:
// 2 threads on 4-core, 3-4 on 8-core, never more than physical cores / 2
size_t optimalThreads = std::max(2u, std::thread::hardware_concurrency() / 2);
```

#### 3. Batch Operations API (MEDIUM IMPACT)

For apps that hash/encrypt multiple items, the per-call JSI overhead adds up. Consider batch APIs:

```typescript
// Instead of N separate calls:
const hashes = items.map(i => FastCrypto.hashSync(i, 'SHA-256'));

// Single native call that processes all items:
const hashes = FastCrypto.hashBatchSync(items, 'SHA-256');
```

This amortizes the JS→native transition cost across N items.

#### 4. Lazy Initialization (LOW IMPACT)

Current: OpenSSL is initialized in `FastCryptoCore` constructor (called at module load).

```cpp
// Current — eagerly initializes
FastCryptoCore::FastCryptoCore() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}
```

Consider lazy init to avoid startup cost if crypto isn't used immediately. Note: `ERR_load_crypto_strings()` and `OpenSSL_add_all_algorithms()` are deprecated in OpenSSL 1.1.1+ — they're called automatically. Can be safely removed.

#### 5. iOS: Prefer CryptoKit over OpenSSL (PLATFORM-SPECIFIC)

Apple's CryptoKit is:
- Hardware-accelerated (uses Secure Enclave coprocessor)
- Zero additional binary size (ships with iOS)
- Faster for AES-GCM and ChaCha20 on Apple Silicon

```swift
// CryptoKit is ~2-5x faster than OpenSSL for AES-GCM on Apple Silicon
import CryptoKit
let sealedBox = try AES.GCM.seal(plaintext, using: key)
```

**Strategy:** Use CryptoKit on iOS, OpenSSL/libsodium on Android. The `#ifdef` structure already supports this — just needs implementation in the `.mm` layer.

---

## Pillar 3: Security Hardening

### Security Audit Checklist

Run through these checks whenever modifying crypto code:

#### Memory Safety

- [ ] **SecureBuffer RAII** — All key material wrapped in `SecureBuffer` (zeroes on destruction)
- [ ] **No key material in `std::string`** — Strings may be copied/moved by allocator; use `SecureBuffer` or `std::vector<uint8_t>`
- [ ] **OPENSSL_cleanse / sodium_memzero** — Verify compiler doesn't optimize out the zeroing (check with `-O2` disassembly)
- [ ] **Stack-allocated keys** — If keys are on the stack, ensure the function securely zeroes before return
- [ ] **No logging of key material** — Grep for any `console.log`, `NSLog`, `Log.d` that might dump keys

```bash
# Audit for potential key leakage in logs
grep -rn "NSLog\|Log\.d\|console\.log\|printf\|cout" ios/ android/ cpp/ --include="*.mm" --include="*.kt" --include="*.cpp" --include="*.tsx"
```

#### Timing Attack Resistance

- [ ] **constantTimeEquals** uses constant-time comparison (volatile pointer trick or `CRYPTO_memcmp`)
- [ ] **No early-return on verification** — `verify()` should not return early on first mismatched byte
- [ ] **Signature verification** — Uses OpenSSL's `EVP_DigestVerify` (already constant-time internally)

```cpp
// CORRECT: constant-time comparison
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// WRONG: early-return leaks timing information
bool naiveEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0; // May short-circuit
}
```

#### Nonce/IV Safety

- [ ] **AES-GCM nonces** are generated via CSPRNG (`RAND_bytes`), never reused
- [ ] **Nonce size** is exactly 12 bytes for AES-GCM and ChaCha20
- [ ] **No counter-based nonces** unless explicitly managing state (counter reuse = catastrophic key recovery)
- [ ] **Nonce is returned with ciphertext** — caller doesn't need to track it

#### Key Management

- [ ] **Key generation** uses `RAND_bytes` or Secure Enclave, never `rand()` or `Math.random()`
- [ ] **Ed25519 private keys** are 64 bytes (seed + public key), not 32
- [ ] **X25519 shared secrets** should be hashed (HKDF) before use as encryption keys
- [ ] **Secure Enclave keys** are non-exportable and bound to device

#### Input Validation

- [ ] **Null pointer checks** before all native operations
- [ ] **Key size validation** (32 bytes for AES-256, 32 bytes for ChaCha20, 64 bytes for Ed25519 private)
- [ ] **Maximum input size** limits to prevent DoS (e.g., MAX_RANDOM_BYTES = 1MB)
- [ ] **Algorithm string validation** — reject unknown algorithm names

### Security vs. Performance Tradeoffs

| Decision | Security Choice | Performance Choice | Recommendation |
|----------|----------------|-------------------|----------------|
| Memory zeroing | Always zero key buffers | Skip for speed | **Always zero** — the cost is negligible (<1us) |
| Nonce generation | CSPRNG per operation | Pre-generate pool | **CSPRNG per op** — pools add complexity and state |
| Base64 bridge | Acceptable (data in transit briefly) | Direct JSI buffer | **Either** — base64 doesn't affect security |
| Thread pool size | Fewer threads (less attack surface) | More threads | **Fewer** — mobile doesn't benefit from >4 crypto threads |
| Compiler optimization | `-O2` (predictable codegen) | `-O3` (may vectorize timing-sensitive code) | **`-O2` or `-Os`** — `-O3` can break constant-time guarantees |
| LTO | May eliminate security-critical code | Smaller binary | **Use with caution** — verify constant-time code survives LTO |

---

## Combined Analysis Workflow

When asked to analyze and optimize, follow this order:

### Step 1: Measure Current State
```bash
# Package size
npm pack --dry-run
ls -lh android/libs/*/libcrypto.a

# Run benchmarks on-device
# (use example app with crypto-bench.ts)
```

### Step 2: Identify Top Bottleneck
- If package > 3MB: Focus on Pillar 1 (size)
- If ops/sec below targets: Focus on Pillar 2 (performance)
- If shipping to production: Run Pillar 3 (security audit) first

### Step 3: Apply Changes Incrementally
1. Make ONE change at a time
2. Re-measure both size AND benchmarks after each change
3. Verify security properties are preserved (run audit checklist)
4. Never sacrifice security for size or speed

### Step 4: Validate
```bash
# Size regression check
npm pack --dry-run | grep "total files\|package size"

# Benchmark regression check (on-device)
# Compare ops/sec before and after

# Security check
bash scripts/verify-memory-hygiene.sh
```

---

## Quick Reference: What NOT to Optimize

These are intentional design choices, not inefficiencies:

- **Base64 encoding at JS boundary** — Required by TurboModule codegen spec (string-only). Can only be eliminated by switching to C++ JSI host objects.
- **`ERR_load_crypto_strings()`** — Provides human-readable error messages. The size cost is minimal.
- **Separate sync/async APIs** — Sync avoids Promise overhead for sub-ms ops; async prevents JS thread blocking for heavy ops.
- **`-fstack-protector-strong`** — Security hardening flag. Do NOT remove for size savings.
- **16KB page alignment** — Required for Android 15+. Do NOT remove.
- **SecureBuffer zeroing** — Prevents key leakage. Do NOT remove or optimize away.
