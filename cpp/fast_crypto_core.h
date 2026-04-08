#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace fastcrypto {

// ── Result Type ────────────────────────────────────────────────────
// Lightweight Result<T, E> for C++17 (replaces std::expected from C++23)

template <typename T> struct Result {
  T value;
  std::string error;
  bool ok;

  static Result Ok(T val) { return {std::move(val), "", true}; }
  static Result Err(std::string msg) { return {{}, std::move(msg), false}; }
};

template <> struct Result<void> {
  std::string error;
  bool ok;

  static Result Ok() { return {"", true}; }
  static Result Err(std::string msg) { return {std::move(msg), false}; }
};

// ── Cipher Result ──────────────────────────────────────────────────

struct CipherResultNative {
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> tag;
};

// ── Key Pair ───────────────────────────────────────────────────────

struct KeyPairNative {
  std::vector<uint8_t> publicKey;
  std::vector<uint8_t> privateKey;
};

// ── Core Crypto Functions ──────────────────────────────────────────

class FastCryptoCore {
public:
  FastCryptoCore();
  ~FastCryptoCore();

  // Non-copyable
  FastCryptoCore(const FastCryptoCore &) = delete;
  FastCryptoCore &operator=(const FastCryptoCore &) = delete;

  // --- Hashing ---
  Result<std::vector<uint8_t>> hash(const uint8_t *data, size_t dataLen,
                                    const std::string &algorithm);

  // --- Key Derivation (Argon2id) ---
  Result<std::vector<uint8_t>> argon2id(const uint8_t *password,
                                        size_t passwordLen,
                                        const uint8_t *salt, size_t saltLen,
                                        uint32_t memCost, uint32_t timeCost,
                                        size_t outputLen);

  // --- AEAD Encryption ---
  Result<CipherResultNative> encrypt(const uint8_t *plaintext,
                                     size_t plaintextLen, const uint8_t *key,
                                     size_t keyLen,
                                     const std::string &algorithm);

  Result<std::vector<uint8_t>>
  decrypt(const uint8_t *ciphertext, size_t ciphertextLen,
          const uint8_t *nonce, size_t nonceLen, const uint8_t *tag,
          size_t tagLen, const uint8_t *key, size_t keyLen,
          const std::string &algorithm);

  // --- Ed25519 (RFC 8032) ---
  Result<KeyPairNative> generateEd25519KeyPair();
  Result<std::vector<uint8_t>> sign(const uint8_t *message, size_t messageLen,
                                    const uint8_t *privateKey,
                                    size_t privateKeyLen);
  Result<bool> verify(const uint8_t *message, size_t messageLen,
                      const uint8_t *signature, size_t signatureLen,
                      const uint8_t *publicKey, size_t publicKeyLen);

  // --- X25519 (RFC 7748) ---
  Result<KeyPairNative> generateX25519KeyPair();
  Result<std::vector<uint8_t>> x25519DiffieHellman(const uint8_t *privateKey,
                                                   size_t privateKeyLen,
                                                   const uint8_t *peerPublicKey,
                                                   size_t peerPublicKeyLen);

  // --- Feature Detection ---
  static bool isArgon2idAvailable();

  // --- Utilities ---
  Result<std::vector<uint8_t>> generateRandomBytes(size_t length);
  bool constantTimeEquals(const uint8_t *a, size_t aLen, const uint8_t *b,
                          size_t bLen);

private:
  // Implementation uses OpenSSL or Libsodium based on build flag
  Result<CipherResultNative> encryptAesGcm(const uint8_t *plaintext,
                                           size_t plaintextLen,
                                           const uint8_t *key, size_t keyLen);
  Result<CipherResultNative> encryptChaCha20Poly1305(const uint8_t *plaintext,
                                                     size_t plaintextLen,
                                                     const uint8_t *key,
                                                     size_t keyLen);
  Result<std::vector<uint8_t>>
  decryptAesGcm(const uint8_t *ciphertext, size_t ciphertextLen,
                const uint8_t *nonce, size_t nonceLen, const uint8_t *tag,
                size_t tagLen, const uint8_t *key, size_t keyLen);
  Result<std::vector<uint8_t>> decryptChaCha20Poly1305(
      const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *nonce,
      size_t nonceLen, const uint8_t *tag, size_t tagLen, const uint8_t *key,
      size_t keyLen);
};

} // namespace fastcrypto
