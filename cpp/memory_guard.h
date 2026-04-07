#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#ifdef FAST_CRYPTO_USE_OPENSSL
#include <openssl/crypto.h>
#endif

#ifdef FAST_CRYPTO_USE_LIBSODIUM
#include <sodium.h>
#endif

namespace fastcrypto {

/**
 * RAII wrapper that guarantees sensitive memory is zeroed on destruction.
 * Prevents sensitive key material from lingering in memory after use.
 */
class SecureBuffer {
public:
  explicit SecureBuffer(size_t size) : size_(size) {
    if (size == 0) {
      throw std::invalid_argument("SecureBuffer size must be > 0");
    }
    data_ = new uint8_t[size];
    std::memset(data_, 0, size_);
  }

  ~SecureBuffer() { secureZero(); }

  // Non-copyable
  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;

  // Movable
  SecureBuffer(SecureBuffer &&other) noexcept
      : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
  }

  SecureBuffer &operator=(SecureBuffer &&other) noexcept {
    if (this != &other) {
      secureZero();
      delete[] data_;
      data_ = other.data_;
      size_ = other.size_;
      other.data_ = nullptr;
      other.size_ = 0;
    }
    return *this;
  }

  uint8_t *data() { return data_; }
  const uint8_t *data() const { return data_; }
  size_t size() const { return size_; }

private:
  void secureZero() {
    if (data_ && size_ > 0) {
#ifdef FAST_CRYPTO_USE_LIBSODIUM
      sodium_memzero(data_, size_);
#elif defined(FAST_CRYPTO_USE_OPENSSL)
      OPENSSL_cleanse(data_, size_);
#else
      // Volatile pointer trick to prevent compiler from optimizing out the
      // memset
      volatile uint8_t *p = data_;
      for (size_t i = 0; i < size_; ++i) {
        p[i] = 0;
      }
#endif
    }
  }

  uint8_t *data_ = nullptr;
  size_t size_ = 0;
};

} // namespace fastcrypto
