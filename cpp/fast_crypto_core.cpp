#include "fast_crypto_core.h"
#include "memory_guard.h"

#include <cstring>

#ifdef FAST_CRYPTO_USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#endif

#ifdef FAST_CRYPTO_USE_LIBSODIUM
#include <sodium.h>
#endif

namespace fastcrypto {

// ── Constants ──────────────────────────────────────────────────────

static constexpr size_t AES_GCM_KEY_SIZE = 32;
static constexpr size_t AES_GCM_NONCE_SIZE = 12;
static constexpr size_t AES_GCM_TAG_SIZE = 16;
static constexpr size_t CHACHA20_KEY_SIZE = 32;
static constexpr size_t CHACHA20_NONCE_SIZE = 12;
static constexpr size_t CHACHA20_TAG_SIZE = 16;
static constexpr size_t ED25519_PRIVATE_KEY_SIZE = 64;
static constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
static constexpr size_t ED25519_SIGNATURE_SIZE = 64;
static constexpr size_t X25519_KEY_SIZE = 32;
static constexpr size_t MAX_RANDOM_BYTES = 1024 * 1024; // 1 MB

// ── Constructor / Destructor ───────────────────────────────────────

FastCryptoCore::FastCryptoCore() {
#ifdef FAST_CRYPTO_USE_LIBSODIUM
  if (sodium_init() < 0) {
    // Already initialized is OK (-1 means failure, 0 means success, 1 means
    // already initialized)
  }
#endif
}

FastCryptoCore::~FastCryptoCore() = default;

// ── Hashing ────────────────────────────────────────────────────────

Result<std::vector<uint8_t>> FastCryptoCore::hash(const uint8_t *data,
                                                  size_t dataLen,
                                                  const std::string &algorithm) {
  if (!data && dataLen > 0) {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: null data pointer");
  }

#ifdef FAST_CRYPTO_USE_OPENSSL
  const EVP_MD *md = nullptr;
  if (algorithm == "SHA-256") {
    md = EVP_sha256();
  } else if (algorithm == "SHA-512") {
    md = EVP_sha512();
  } else {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: unsupported hash algorithm");
  }

  unsigned int digestLen = 0;
  std::vector<uint8_t> digest(EVP_MD_size(md));

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: failed to create hash context");
  }

  bool success = EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
                 EVP_DigestUpdate(ctx, data, dataLen) == 1 &&
                 EVP_DigestFinal_ex(ctx, digest.data(), &digestLen) == 1;

  EVP_MD_CTX_free(ctx);

  if (!success) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: hash computation failed");
  }

  digest.resize(digestLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(digest));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  if (algorithm == "SHA-256") {
    std::vector<uint8_t> digest(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(digest.data(), data, dataLen);
    return Result<std::vector<uint8_t>>::Ok(std::move(digest));
  } else if (algorithm == "SHA-512") {
    std::vector<uint8_t> digest(crypto_hash_sha512_BYTES);
    crypto_hash_sha512(digest.data(), data, dataLen);
    return Result<std::vector<uint8_t>>::Ok(std::move(digest));
  }
  return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: unsupported hash algorithm");
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

// ── Argon2id Key Derivation ────────────────────────────────────────

Result<std::vector<uint8_t>>
FastCryptoCore::argon2id(const uint8_t *password, size_t passwordLen,
                         const uint8_t *salt, size_t saltLen,
                         uint32_t memCost, uint32_t timeCost,
                         size_t outputLen) {
  if (!password || passwordLen == 0) {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: password is required");
  }
  if (!salt || saltLen < 16) {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: salt must be at least 16 bytes");
  }
  if (outputLen == 0 || outputLen > 1024) {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: output length must be 1-1024 bytes");
  }

#ifdef FAST_CRYPTO_USE_OPENSSL
  // OpenSSL 3.2+ has Argon2 via EVP_KDF
  EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (!kdf) {
    return Result<std::vector<uint8_t>>::Err(
        "UNKNOWN_NATIVE_ERROR: Argon2id not available in this OpenSSL build");
  }

  EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: failed to create KDF context");
  }

  uint32_t parallelism = 4;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string("pass", const_cast<uint8_t *>(password),
                                        passwordLen),
      OSSL_PARAM_construct_octet_string("salt", const_cast<uint8_t *>(salt),
                                        saltLen),
      OSSL_PARAM_construct_uint32("memcost", &memCost),
      OSSL_PARAM_construct_uint32("iter", &timeCost),
      OSSL_PARAM_construct_uint32("threads", &parallelism),
      OSSL_PARAM_construct_uint32("lanes", &parallelism),
      OSSL_PARAM_construct_end(),
  };

  std::vector<uint8_t> output(outputLen);
  int rc = EVP_KDF_derive(ctx, output.data(), outputLen, params);
  EVP_KDF_CTX_free(ctx);

  if (rc != 1) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: Argon2id derivation failed");
  }

  return Result<std::vector<uint8_t>>::Ok(std::move(output));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  if (saltLen != crypto_pwhash_SALTBYTES) {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: salt must be exactly 16 bytes for libsodium");
  }

  std::vector<uint8_t> output(outputLen);
  int rc = crypto_pwhash(output.data(), outputLen,
                         reinterpret_cast<const char *>(password), passwordLen,
                         salt, timeCost,
                         static_cast<size_t>(memCost) * 1024,
                         crypto_pwhash_ALG_ARGON2ID13);
  if (rc != 0) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: Argon2id derivation failed");
  }

  return Result<std::vector<uint8_t>>::Ok(std::move(output));
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

// ── AEAD Encryption ────────────────────────────────────────────────

Result<CipherResultNative>
FastCryptoCore::encrypt(const uint8_t *plaintext, size_t plaintextLen,
                        const uint8_t *key, size_t keyLen,
                        const std::string &algorithm) {
  if (!key) {
    return Result<CipherResultNative>::Err("INVALID_KEY_SIZE: key is null");
  }

  if (algorithm == "AES-256-GCM") {
    if (keyLen != AES_GCM_KEY_SIZE) {
      return Result<CipherResultNative>::Err("INVALID_KEY_SIZE: AES-256-GCM requires 32-byte key");
    }
    return encryptAesGcm(plaintext, plaintextLen, key, keyLen);
  } else if (algorithm == "ChaCha20-Poly1305") {
    if (keyLen != CHACHA20_KEY_SIZE) {
      return Result<CipherResultNative>::Err("INVALID_KEY_SIZE: ChaCha20-Poly1305 requires 32-byte key");
    }
    return encryptChaCha20Poly1305(plaintext, plaintextLen, key, keyLen);
  }

  return Result<CipherResultNative>::Err("INVALID_INPUT: unsupported AEAD algorithm");
}

Result<std::vector<uint8_t>>
FastCryptoCore::decrypt(const uint8_t *ciphertext, size_t ciphertextLen,
                        const uint8_t *nonce, size_t nonceLen,
                        const uint8_t *tag, size_t tagLen,
                        const uint8_t *key, size_t keyLen,
                        const std::string &algorithm) {
  if (!key) {
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: key is null");
  }

  if (algorithm == "AES-256-GCM") {
    if (keyLen != AES_GCM_KEY_SIZE) {
      return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: AES-256-GCM requires 32-byte key");
    }
    if (nonceLen != AES_GCM_NONCE_SIZE) {
      return Result<std::vector<uint8_t>>::Err("INVALID_NONCE_SIZE: AES-256-GCM requires 12-byte nonce");
    }
    if (tagLen != AES_GCM_TAG_SIZE) {
      return Result<std::vector<uint8_t>>::Err("DECRYPTION_FAILED: invalid tag size");
    }
    return decryptAesGcm(ciphertext, ciphertextLen, nonce, nonceLen, tag,
                         tagLen, key, keyLen);
  } else if (algorithm == "ChaCha20-Poly1305") {
    if (keyLen != CHACHA20_KEY_SIZE) {
      return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: ChaCha20-Poly1305 requires 32-byte key");
    }
    if (nonceLen != CHACHA20_NONCE_SIZE) {
      return Result<std::vector<uint8_t>>::Err("INVALID_NONCE_SIZE: ChaCha20-Poly1305 requires 12-byte nonce");
    }
    if (tagLen != CHACHA20_TAG_SIZE) {
      return Result<std::vector<uint8_t>>::Err("DECRYPTION_FAILED: invalid tag size");
    }
    return decryptChaCha20Poly1305(ciphertext, ciphertextLen, nonce, nonceLen,
                                   tag, tagLen, key, keyLen);
  }

  return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: unsupported AEAD algorithm");
}

// ── AES-256-GCM Implementation ─────────────────────────────────────

Result<CipherResultNative>
FastCryptoCore::encryptAesGcm(const uint8_t *plaintext, size_t plaintextLen,
                              const uint8_t *key, size_t keyLen) {
#ifdef FAST_CRYPTO_USE_OPENSSL
  CipherResultNative result;
  result.nonce.resize(AES_GCM_NONCE_SIZE);
  result.tag.resize(AES_GCM_TAG_SIZE);

  // Generate random nonce via CSPRNG
  if (RAND_bytes(result.nonce.data(), AES_GCM_NONCE_SIZE) != 1) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: failed to generate nonce");
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: failed to create cipher context");
  }

  int len = 0;
  result.ciphertext.resize(plaintextLen + AES_GCM_TAG_SIZE);

  bool success = true;
  success = success && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                          nullptr, nullptr) == 1;
  success = success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                           AES_GCM_NONCE_SIZE, nullptr) == 1;
  success = success &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key,
                               result.nonce.data()) == 1;
  success = success &&
            EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext,
                              static_cast<int>(plaintextLen)) == 1;
  int ciphertextLen = len;
  success =
      success && EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) == 1;
  ciphertextLen += len;

  success = success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                           AES_GCM_TAG_SIZE,
                                           result.tag.data()) == 1;

  EVP_CIPHER_CTX_free(ctx);

  if (!success) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: AES-GCM encryption failed");
  }

  result.ciphertext.resize(ciphertextLen);
  return Result<CipherResultNative>::Ok(std::move(result));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  CipherResultNative result;
  result.nonce.resize(crypto_aead_aes256gcm_NPUBBYTES);
  result.tag.resize(crypto_aead_aes256gcm_ABYTES);
  result.ciphertext.resize(plaintextLen);

  randombytes_buf(result.nonce.data(), result.nonce.size());

  // libsodium AES-GCM appends tag to ciphertext; we separate them
  std::vector<uint8_t> combined(plaintextLen + crypto_aead_aes256gcm_ABYTES);
  unsigned long long combinedLen = 0;

  if (crypto_aead_aes256gcm_encrypt(combined.data(), &combinedLen, plaintext,
                                    plaintextLen, nullptr, 0, nullptr,
                                    result.nonce.data(), key) != 0) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: AES-GCM encryption failed");
  }

  // Split ciphertext and tag
  size_t ctLen = combinedLen - crypto_aead_aes256gcm_ABYTES;
  result.ciphertext.assign(combined.begin(), combined.begin() + ctLen);
  result.tag.assign(combined.begin() + ctLen, combined.end());

  return Result<CipherResultNative>::Ok(std::move(result));
#else
  return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

Result<std::vector<uint8_t>> FastCryptoCore::decryptAesGcm(
    const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *nonce,
    size_t nonceLen, const uint8_t *tag, size_t tagLen, const uint8_t *key,
    size_t keyLen) {
#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: failed to create cipher context");
  }

  std::vector<uint8_t> plaintext(ciphertextLen);
  int len = 0;

  bool success = true;
  success = success && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                          nullptr, nullptr) == 1;
  success = success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                           static_cast<int>(nonceLen),
                                           nullptr) == 1;
  success = success &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
  success = success &&
            EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext,
                              static_cast<int>(ciphertextLen)) == 1;
  int plaintextLen = len;

  // Set expected tag before finalization
  success = success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                           static_cast<int>(tagLen),
                                           const_cast<uint8_t *>(tag)) == 1;

  // Finalize — this is where tag verification happens
  int finalResult = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
  EVP_CIPHER_CTX_free(ctx);

  if (!success || finalResult != 1) {
    // Authentication failed — do NOT return partial plaintext
    return Result<std::vector<uint8_t>>::Err("DECRYPTION_FAILED: authentication tag verification failed");
  }

  plaintextLen += len;
  plaintext.resize(plaintextLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(plaintext));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  // Reassemble combined ciphertext + tag for libsodium
  std::vector<uint8_t> combined(ciphertextLen + tagLen);
  std::memcpy(combined.data(), ciphertext, ciphertextLen);
  std::memcpy(combined.data() + ciphertextLen, tag, tagLen);

  std::vector<uint8_t> plaintext(ciphertextLen);
  unsigned long long plaintextLen = 0;

  if (crypto_aead_aes256gcm_decrypt(plaintext.data(), &plaintextLen, nullptr,
                                    combined.data(), combined.size(), nullptr, 0,
                                    nonce, key) != 0) {
    return Result<std::vector<uint8_t>>::Err("DECRYPTION_FAILED: authentication tag verification failed");
  }

  plaintext.resize(plaintextLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(plaintext));
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

// ── ChaCha20-Poly1305 Implementation ───────────────────────────────

Result<CipherResultNative> FastCryptoCore::encryptChaCha20Poly1305(
    const uint8_t *plaintext, size_t plaintextLen, const uint8_t *key,
    size_t keyLen) {
#ifdef FAST_CRYPTO_USE_OPENSSL
  CipherResultNative result;
  result.nonce.resize(CHACHA20_NONCE_SIZE);
  result.tag.resize(CHACHA20_TAG_SIZE);

  if (RAND_bytes(result.nonce.data(), CHACHA20_NONCE_SIZE) != 1) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: failed to generate nonce");
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: failed to create cipher context");
  }

  int len = 0;
  result.ciphertext.resize(plaintextLen + CHACHA20_TAG_SIZE);

  bool success = true;
  success = success && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                                          key, result.nonce.data()) == 1;
  success = success &&
            EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext,
                              static_cast<int>(plaintextLen)) == 1;
  int ciphertextLen = len;
  success = success &&
            EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) == 1;
  ciphertextLen += len;

  success = success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                           CHACHA20_TAG_SIZE,
                                           result.tag.data()) == 1;

  EVP_CIPHER_CTX_free(ctx);

  if (!success) {
    return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: ChaCha20-Poly1305 encryption failed");
  }

  result.ciphertext.resize(ciphertextLen);
  return Result<CipherResultNative>::Ok(std::move(result));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  CipherResultNative result;
  result.nonce.resize(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  result.tag.resize(crypto_aead_chacha20poly1305_ietf_ABYTES);

  randombytes_buf(result.nonce.data(), result.nonce.size());

  std::vector<uint8_t> combined(plaintextLen +
                                crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long combinedLen = 0;

  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          combined.data(), &combinedLen, plaintext, plaintextLen, nullptr, 0,
          nullptr, result.nonce.data(), key) != 0) {
    return Result<CipherResultNative>::Err(
        "UNKNOWN_NATIVE_ERROR: ChaCha20-Poly1305 encryption failed");
  }

  size_t ctLen = combinedLen - crypto_aead_chacha20poly1305_ietf_ABYTES;
  result.ciphertext.assign(combined.begin(), combined.begin() + ctLen);
  result.tag.assign(combined.begin() + ctLen, combined.end());

  return Result<CipherResultNative>::Ok(std::move(result));
#else
  return Result<CipherResultNative>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

Result<std::vector<uint8_t>> FastCryptoCore::decryptChaCha20Poly1305(
    const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *nonce,
    size_t nonceLen, const uint8_t *tag, size_t tagLen, const uint8_t *key,
    size_t keyLen) {
#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: failed to create cipher context");
  }

  std::vector<uint8_t> plaintext(ciphertextLen);
  int len = 0;

  bool success = true;
  success = success && EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                                          key, nonce) == 1;
  success = success &&
            EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext,
                              static_cast<int>(ciphertextLen)) == 1;
  int plaintextLen = len;

  success = success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                           static_cast<int>(tagLen),
                                           const_cast<uint8_t *>(tag)) == 1;

  int finalResult = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
  EVP_CIPHER_CTX_free(ctx);

  if (!success || finalResult != 1) {
    return Result<std::vector<uint8_t>>::Err("DECRYPTION_FAILED: authentication tag verification failed");
  }

  plaintextLen += len;
  plaintext.resize(plaintextLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(plaintext));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  std::vector<uint8_t> combined(ciphertextLen + tagLen);
  std::memcpy(combined.data(), ciphertext, ciphertextLen);
  std::memcpy(combined.data() + ciphertextLen, tag, tagLen);

  std::vector<uint8_t> plaintext(ciphertextLen);
  unsigned long long plaintextLen = 0;

  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          plaintext.data(), &plaintextLen, nullptr, combined.data(),
          combined.size(), nullptr, 0, nonce, key) != 0) {
    return Result<std::vector<uint8_t>>::Err("DECRYPTION_FAILED: authentication tag verification failed");
  }

  plaintext.resize(plaintextLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(plaintext));
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

// ── Ed25519 ────────────────────────────────────────────────────────

Result<KeyPairNative> FastCryptoCore::generateEd25519KeyPair() {
#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!ctx) {
    return Result<KeyPairNative>::Err("UNKNOWN_NATIVE_ERROR: failed to create key context");
  }

  if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pkey) != 1) {
    EVP_PKEY_CTX_free(ctx);
    return Result<KeyPairNative>::Err("UNKNOWN_NATIVE_ERROR: Ed25519 key generation failed");
  }
  EVP_PKEY_CTX_free(ctx);

  KeyPairNative kp;
  size_t pubLen = ED25519_PUBLIC_KEY_SIZE;
  size_t privLen = ED25519_PRIVATE_KEY_SIZE;
  kp.publicKey.resize(pubLen);
  kp.privateKey.resize(privLen);

  EVP_PKEY_get_raw_public_key(pkey, kp.publicKey.data(), &pubLen);
  EVP_PKEY_get_raw_private_key(pkey, kp.privateKey.data(), &privLen);
  kp.publicKey.resize(pubLen);
  kp.privateKey.resize(privLen);

  EVP_PKEY_free(pkey);
  return Result<KeyPairNative>::Ok(std::move(kp));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  KeyPairNative kp;
  kp.publicKey.resize(crypto_sign_PUBLICKEYBYTES);
  kp.privateKey.resize(crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(kp.publicKey.data(), kp.privateKey.data());
  return Result<KeyPairNative>::Ok(std::move(kp));
#else
  return Result<KeyPairNative>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

Result<std::vector<uint8_t>>
FastCryptoCore::sign(const uint8_t *message, size_t messageLen,
                     const uint8_t *privateKey, size_t privateKeyLen) {
  if (!privateKey || privateKeyLen == 0) {
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: private key is required");
  }

#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_PKEY *pkey =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privateKey,
                                   privateKeyLen);
  if (!pkey) {
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: invalid Ed25519 private key");
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: failed to create sign context");
  }

  std::vector<uint8_t> signature(ED25519_SIGNATURE_SIZE);
  size_t sigLen = signature.size();

  bool success =
      EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
      EVP_DigestSign(ctx, signature.data(), &sigLen, message, messageLen) == 1;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  if (!success) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: Ed25519 signing failed");
  }

  signature.resize(sigLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(signature));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  if (privateKeyLen != crypto_sign_SECRETKEYBYTES) {
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: invalid Ed25519 private key size");
  }
  std::vector<uint8_t> signature(crypto_sign_BYTES);
  unsigned long long sigLen = 0;
  crypto_sign_detached(signature.data(), &sigLen, message, messageLen,
                       privateKey);
  signature.resize(sigLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(signature));
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

Result<bool> FastCryptoCore::verify(const uint8_t *message, size_t messageLen,
                                   const uint8_t *signature,
                                   size_t signatureLen,
                                   const uint8_t *publicKey,
                                   size_t publicKeyLen) {
  if (!publicKey || publicKeyLen == 0) {
    return Result<bool>::Err("INVALID_KEY_SIZE: public key is required");
  }
  if (!signature || signatureLen == 0) {
    return Result<bool>::Err("INVALID_INPUT: signature is required");
  }

#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_PKEY *pkey =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey,
                                  publicKeyLen);
  if (!pkey) {
    return Result<bool>::Err("INVALID_KEY_SIZE: invalid Ed25519 public key");
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return Result<bool>::Err("UNKNOWN_NATIVE_ERROR: failed to create verify context");
  }

  bool valid = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
               EVP_DigestVerify(ctx, signature, signatureLen, message,
                                messageLen) == 1;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return Result<bool>::Ok(valid);

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  if (publicKeyLen != crypto_sign_PUBLICKEYBYTES) {
    return Result<bool>::Err("INVALID_KEY_SIZE: invalid Ed25519 public key size");
  }
  bool valid = crypto_sign_verify_detached(signature, message, messageLen,
                                           publicKey) == 0;
  return Result<bool>::Ok(valid);
#else
  return Result<bool>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

// ── X25519 ─────────────────────────────────────────────────────────

Result<KeyPairNative> FastCryptoCore::generateX25519KeyPair() {
#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!ctx) {
    return Result<KeyPairNative>::Err("UNKNOWN_NATIVE_ERROR: failed to create key context");
  }

  if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pkey) != 1) {
    EVP_PKEY_CTX_free(ctx);
    return Result<KeyPairNative>::Err("UNKNOWN_NATIVE_ERROR: X25519 key generation failed");
  }
  EVP_PKEY_CTX_free(ctx);

  KeyPairNative kp;
  size_t pubLen = X25519_KEY_SIZE;
  size_t privLen = X25519_KEY_SIZE;
  kp.publicKey.resize(pubLen);
  kp.privateKey.resize(privLen);

  EVP_PKEY_get_raw_public_key(pkey, kp.publicKey.data(), &pubLen);
  EVP_PKEY_get_raw_private_key(pkey, kp.privateKey.data(), &privLen);
  kp.publicKey.resize(pubLen);
  kp.privateKey.resize(privLen);

  EVP_PKEY_free(pkey);
  return Result<KeyPairNative>::Ok(std::move(kp));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  KeyPairNative kp;
  kp.publicKey.resize(crypto_scalarmult_BYTES);
  kp.privateKey.resize(crypto_scalarmult_SCALARBYTES);
  randombytes_buf(kp.privateKey.data(), kp.privateKey.size());
  crypto_scalarmult_base(kp.publicKey.data(), kp.privateKey.data());
  return Result<KeyPairNative>::Ok(std::move(kp));
#else
  return Result<KeyPairNative>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

Result<std::vector<uint8_t>>
FastCryptoCore::x25519DiffieHellman(const uint8_t *privateKey,
                                    size_t privateKeyLen,
                                    const uint8_t *peerPublicKey,
                                    size_t peerPublicKeyLen) {
  if (!privateKey || privateKeyLen != X25519_KEY_SIZE) {
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: X25519 private key must be 32 bytes");
  }
  if (!peerPublicKey || peerPublicKeyLen != X25519_KEY_SIZE) {
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: X25519 public key must be 32 bytes");
  }

#ifdef FAST_CRYPTO_USE_OPENSSL
  EVP_PKEY *privPkey =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey,
                                   privateKeyLen);
  EVP_PKEY *pubPkey =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPublicKey,
                                  peerPublicKeyLen);

  if (!privPkey || !pubPkey) {
    EVP_PKEY_free(privPkey);
    EVP_PKEY_free(pubPkey);
    return Result<std::vector<uint8_t>>::Err("INVALID_KEY_SIZE: invalid X25519 key");
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privPkey, nullptr);
  if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
      EVP_PKEY_derive_set_peer(ctx, pubPkey) != 1) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privPkey);
    EVP_PKEY_free(pubPkey);
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: X25519 ECDH setup failed");
  }

  size_t sharedLen = 0;
  EVP_PKEY_derive(ctx, nullptr, &sharedLen);
  std::vector<uint8_t> shared(sharedLen);
  int rc = EVP_PKEY_derive(ctx, shared.data(), &sharedLen);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(privPkey);
  EVP_PKEY_free(pubPkey);

  if (rc != 1) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: X25519 ECDH failed");
  }

  shared.resize(sharedLen);
  return Result<std::vector<uint8_t>>::Ok(std::move(shared));

#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
  if (crypto_scalarmult(shared.data(), privateKey, peerPublicKey) != 0) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: X25519 ECDH failed");
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(shared));
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif
}

// ── Utilities ──────────────────────────────────────────────────────

Result<std::vector<uint8_t>>
FastCryptoCore::generateRandomBytes(size_t length) {
  if (length == 0 || length > MAX_RANDOM_BYTES) {
    return Result<std::vector<uint8_t>>::Err("INVALID_INPUT: length must be 1-1048576 bytes");
  }

  std::vector<uint8_t> bytes(length);

#ifdef FAST_CRYPTO_USE_OPENSSL
  if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
    return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: random generation failed");
  }
#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  randombytes_buf(bytes.data(), length);
#else
  return Result<std::vector<uint8_t>>::Err("UNKNOWN_NATIVE_ERROR: no crypto engine compiled");
#endif

  return Result<std::vector<uint8_t>>::Ok(std::move(bytes));
}

bool FastCryptoCore::constantTimeEquals(const uint8_t *a, size_t aLen,
                                        const uint8_t *b, size_t bLen) {
  if (aLen != bLen) {
    return false;
  }

#ifdef FAST_CRYPTO_USE_OPENSSL
  return CRYPTO_memcmp(a, b, aLen) == 0;
#elif defined(FAST_CRYPTO_USE_LIBSODIUM)
  return sodium_memcmp(a, b, aLen) == 0;
#else
  // Constant-time comparison fallback
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < aLen; ++i) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
#endif
}

} // namespace fastcrypto
