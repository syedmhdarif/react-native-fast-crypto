#import "FastCrypto.h"

#include "fast_crypto_core.h"
#include "thread_pool.h"

#import <React/RCTBridge.h>
#import <React/RCTConvert.h>
#import <React/RCTUtils.h>

// Swift bridging header for SecureEnclaveHelper
#import "react_native_fast_crypto-Swift.h"

// ── Singleton C++ objects ────────────────────────────────────────────
static fastcrypto::FastCryptoCore &getCryptoCore() {
  static fastcrypto::FastCryptoCore core;
  return core;
}

static fastcrypto::ThreadPool &getThreadPool() {
  static fastcrypto::ThreadPool pool;
  return pool;
}

// ── Helpers ──────────────────────────────────────────────────────────

static inline NSData *base64Decode(NSString *base64) {
  return [[NSData alloc] initWithBase64EncodedString:base64 options:0];
}

static inline NSString *base64Encode(NSData *data) {
  return [data base64EncodedStringWithOptions:0];
}

static inline NSString *vectorToBase64(const std::vector<uint8_t> &vec) {
  NSData *data = [NSData dataWithBytes:vec.data() length:vec.size()];
  return base64Encode(data);
}

static inline const uint8_t *dataBytes(NSData *data) {
  return static_cast<const uint8_t *>(data.bytes);
}

static inline NSDictionary *keyPairToDict(const fastcrypto::KeyPairNative &kp) {
  return @{
    @"publicKey":  vectorToBase64(kp.publicKey),
    @"privateKey": vectorToBase64(kp.privateKey),
  };
}

static inline NSDictionary *cipherResultToDict(const fastcrypto::CipherResultNative &cr) {
  return @{
    @"ciphertext": vectorToBase64(cr.ciphertext),
    @"nonce":      vectorToBase64(cr.nonce),
    @"tag":        vectorToBase64(cr.tag),
  };
}

/// Parses a C++ error string of the form "CODE: message" into separate code and message.
static void parseError(const std::string &error, NSString **outCode, NSString **outMessage) {
  auto colonPos = error.find(':');
  if (colonPos != std::string::npos) {
    *outCode = [NSString stringWithUTF8String:error.substr(0, colonPos).c_str()];
    std::string msg = error.substr(colonPos + 1);
    // Trim leading space
    if (!msg.empty() && msg[0] == ' ') msg = msg.substr(1);
    *outMessage = [NSString stringWithUTF8String:msg.c_str()];
  } else {
    *outCode = @"UNKNOWN_NATIVE_ERROR";
    *outMessage = [NSString stringWithUTF8String:error.c_str()];
  }
}

static inline void rejectWithError(RCTPromiseRejectBlock reject, const std::string &error) {
  NSString *code = nil;
  NSString *message = nil;
  parseError(error, &code, &message);
  reject(code, message, nil);
}

// ── Implementation ───────────────────────────────────────────────────

@implementation FastCrypto

// ── TurboModule Registration ─────────────────────────────────────────

+ (NSString *)moduleName {
  return @"FastCrypto";
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params {
  return std::make_shared<facebook::react::NativeFastCryptoSpecJSI>(params);
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Hashing
// ═══════════════════════════════════════════════════════════════════════

- (NSString *)hashSync:(NSString *)data algorithm:(NSString *)algorithm {
  NSData *raw = base64Decode(data);
  auto result = getCryptoCore().hash(dataBytes(raw), raw.length,
                                     std::string([algorithm UTF8String]));
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return vectorToBase64(result.value);
}

- (void)hash:(NSString *)data
    algorithm:(NSString *)algorithm
      resolve:(RCTPromiseResolveBlock)resolve
       reject:(RCTPromiseRejectBlock)reject {
  NSData *raw = base64Decode(data);
  NSString *algCopy = [algorithm copy];

  getThreadPool().enqueue([raw, algCopy, resolve, reject]() {
    auto result = getCryptoCore().hash(dataBytes(raw), raw.length,
                                       std::string([algCopy UTF8String]));
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(vectorToBase64(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Argon2id
// ═══════════════════════════════════════════════════════════════════════

- (NSString *)argon2idSync:(NSString *)password
                      salt:(NSString *)salt
                   memCost:(double)memCost
                  timeCost:(double)timeCost
                 outputLen:(double)outputLen {
  NSData *pw = base64Decode(password);
  NSData *sl = base64Decode(salt);
  auto result = getCryptoCore().argon2id(
      dataBytes(pw), pw.length,
      dataBytes(sl), sl.length,
      static_cast<uint32_t>(memCost),
      static_cast<uint32_t>(timeCost),
      static_cast<size_t>(outputLen));
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return vectorToBase64(result.value);
}

- (void)argon2id:(NSString *)password
            salt:(NSString *)salt
         memCost:(double)memCost
        timeCost:(double)timeCost
       outputLen:(double)outputLen
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject {
  NSData *pw = base64Decode(password);
  NSData *sl = base64Decode(salt);
  uint32_t mc = static_cast<uint32_t>(memCost);
  uint32_t tc = static_cast<uint32_t>(timeCost);
  size_t ol = static_cast<size_t>(outputLen);

  getThreadPool().enqueue([pw, sl, mc, tc, ol, resolve, reject]() {
    auto result = getCryptoCore().argon2id(
        dataBytes(pw), pw.length,
        dataBytes(sl), sl.length,
        mc, tc, ol);
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(vectorToBase64(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - AEAD Encryption
// ═══════════════════════════════════════════════════════════════════════

- (NSDictionary *)encryptSync:(NSString *)plaintext
                          key:(NSString *)key
                    algorithm:(NSString *)algorithm {
  NSData *pt = base64Decode(plaintext);
  NSData *k = base64Decode(key);
  auto result = getCryptoCore().encrypt(
      dataBytes(pt), pt.length,
      dataBytes(k), k.length,
      std::string([algorithm UTF8String]));
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return cipherResultToDict(result.value);
}

- (void)encrypt:(NSString *)plaintext
            key:(NSString *)key
      algorithm:(NSString *)algorithm
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject {
  NSData *pt = base64Decode(plaintext);
  NSData *k = base64Decode(key);
  NSString *algCopy = [algorithm copy];

  getThreadPool().enqueue([pt, k, algCopy, resolve, reject]() {
    auto result = getCryptoCore().encrypt(
        dataBytes(pt), pt.length,
        dataBytes(k), k.length,
        std::string([algCopy UTF8String]));
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(cipherResultToDict(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

- (NSString *)decryptSync:(NSString *)ciphertext
                    nonce:(NSString *)nonce
                      tag:(NSString *)tag
                      key:(NSString *)key
                algorithm:(NSString *)algorithm {
  NSData *ct = base64Decode(ciphertext);
  NSData *n = base64Decode(nonce);
  NSData *t = base64Decode(tag);
  NSData *k = base64Decode(key);
  auto result = getCryptoCore().decrypt(
      dataBytes(ct), ct.length,
      dataBytes(n), n.length,
      dataBytes(t), t.length,
      dataBytes(k), k.length,
      std::string([algorithm UTF8String]));
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return vectorToBase64(result.value);
}

- (void)decrypt:(NSString *)ciphertext
          nonce:(NSString *)nonce
            tag:(NSString *)tag
            key:(NSString *)key
      algorithm:(NSString *)algorithm
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject {
  NSData *ct = base64Decode(ciphertext);
  NSData *n = base64Decode(nonce);
  NSData *t = base64Decode(tag);
  NSData *k = base64Decode(key);
  NSString *algCopy = [algorithm copy];

  getThreadPool().enqueue([ct, n, t, k, algCopy, resolve, reject]() {
    auto result = getCryptoCore().decrypt(
        dataBytes(ct), ct.length,
        dataBytes(n), n.length,
        dataBytes(t), t.length,
        dataBytes(k), k.length,
        std::string([algCopy UTF8String]));
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(vectorToBase64(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Ed25519
// ═══════════════════════════════════════════════════════════════════════

- (NSDictionary *)generateEd25519KeyPairSync {
  auto result = getCryptoCore().generateEd25519KeyPair();
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return keyPairToDict(result.value);
}

- (void)generateEd25519KeyPair:(RCTPromiseResolveBlock)resolve
                        reject:(RCTPromiseRejectBlock)reject {
  getThreadPool().enqueue([resolve, reject]() {
    auto result = getCryptoCore().generateEd25519KeyPair();
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(keyPairToDict(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

- (NSString *)signSync:(NSString *)message privateKey:(NSString *)privateKey {
  NSData *msg = base64Decode(message);
  NSData *key = base64Decode(privateKey);
  auto result = getCryptoCore().sign(
      dataBytes(msg), msg.length,
      dataBytes(key), key.length);
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return vectorToBase64(result.value);
}

- (void)sign:(NSString *)message
  privateKey:(NSString *)privateKey
     resolve:(RCTPromiseResolveBlock)resolve
      reject:(RCTPromiseRejectBlock)reject {
  NSData *msg = base64Decode(message);
  NSData *key = base64Decode(privateKey);

  getThreadPool().enqueue([msg, key, resolve, reject]() {
    auto result = getCryptoCore().sign(
        dataBytes(msg), msg.length,
        dataBytes(key), key.length);
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(vectorToBase64(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

- (NSNumber *)verifySync:(NSString *)message
               signature:(NSString *)signature
               publicKey:(NSString *)publicKey {
  NSData *msg = base64Decode(message);
  NSData *sig = base64Decode(signature);
  NSData *key = base64Decode(publicKey);
  auto result = getCryptoCore().verify(
      dataBytes(msg), msg.length,
      dataBytes(sig), sig.length,
      dataBytes(key), key.length);
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return @(result.value);
}

- (void)verify:(NSString *)message
     signature:(NSString *)signature
     publicKey:(NSString *)publicKey
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject {
  NSData *msg = base64Decode(message);
  NSData *sig = base64Decode(signature);
  NSData *key = base64Decode(publicKey);

  getThreadPool().enqueue([msg, sig, key, resolve, reject]() {
    auto result = getCryptoCore().verify(
        dataBytes(msg), msg.length,
        dataBytes(sig), sig.length,
        dataBytes(key), key.length);
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(@(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - X25519
// ═══════════════════════════════════════════════════════════════════════

- (NSDictionary *)generateX25519KeyPairSync {
  auto result = getCryptoCore().generateX25519KeyPair();
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return keyPairToDict(result.value);
}

- (NSString *)xDiffieHellmanSync:(NSString *)privateKey
                   peerPublicKey:(NSString *)peerPublicKey {
  NSData *priv = base64Decode(privateKey);
  NSData *peer = base64Decode(peerPublicKey);
  auto result = getCryptoCore().x25519DiffieHellman(
      dataBytes(priv), priv.length,
      dataBytes(peer), peer.length);
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return vectorToBase64(result.value);
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Secure Enclave / TEE
// ═══════════════════════════════════════════════════════════════════════

- (void)generateSecureEnclaveKey:(NSString *)keyTag
               requireBiometric:(NSNumber *)requireBiometric
                        resolve:(RCTPromiseResolveBlock)resolve
                         reject:(RCTPromiseRejectBlock)reject {
  [SecureEnclaveHelper generateKeyWithKeyTag:keyTag
                           requireBiometric:[requireBiometric boolValue]
                                 completion:^(NSString * _Nullable publicKeyHex, NSError * _Nullable error) {
    if (error) {
      reject(error.userInfo[@"code"] ?: @"UNKNOWN_NATIVE_ERROR",
             error.localizedDescription, error);
    } else {
      resolve(publicKeyHex);
    }
  }];
}

- (void)encryptWithSecureEnclaveKey:(NSString *)keyTag
                          plaintext:(NSString *)plaintextBase64
                            resolve:(RCTPromiseResolveBlock)resolve
                             reject:(RCTPromiseRejectBlock)reject {
  NSData *plaintext = base64Decode(plaintextBase64);
  [SecureEnclaveHelper encryptWithKeyTag:keyTag
                               plaintext:plaintext
                              completion:^(NSData * _Nullable ciphertext, NSError * _Nullable error) {
    if (error) {
      reject(error.userInfo[@"code"] ?: @"UNKNOWN_NATIVE_ERROR",
             error.localizedDescription, error);
    } else {
      resolve(base64Encode(ciphertext));
    }
  }];
}

- (void)decryptWithSecureEnclaveKey:(NSString *)keyTag
                         ciphertext:(NSString *)ciphertextBase64
                            resolve:(RCTPromiseResolveBlock)resolve
                             reject:(RCTPromiseRejectBlock)reject {
  NSData *ciphertext = base64Decode(ciphertextBase64);
  [SecureEnclaveHelper decryptWithKeyTag:keyTag
                              ciphertext:ciphertext
                              completion:^(NSData * _Nullable plaintext, NSError * _Nullable error) {
    if (error) {
      reject(error.userInfo[@"code"] ?: @"UNKNOWN_NATIVE_ERROR",
             error.localizedDescription, error);
    } else {
      resolve(base64Encode(plaintext));
    }
  }];
}

- (void)deleteSecureEnclaveKey:(NSString *)keyTag
                       resolve:(RCTPromiseResolveBlock)resolve
                        reject:(RCTPromiseRejectBlock)reject {
  [SecureEnclaveHelper deleteKeyWithKeyTag:keyTag
                                completion:^(NSError * _Nullable error) {
    if (error) {
      reject(error.userInfo[@"code"] ?: @"UNKNOWN_NATIVE_ERROR",
             error.localizedDescription, error);
    } else {
      resolve(nil);
    }
  }];
}

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Utilities
// ═══════════════════════════════════════════════════════════════════════

- (NSString *)generateRandomBytesSync:(double)length {
  auto result = getCryptoCore().generateRandomBytes(static_cast<size_t>(length));
  if (!result.ok) {
    @throw [NSException exceptionWithName:@"FastCryptoError"
                                   reason:[NSString stringWithUTF8String:result.error.c_str()]
                                 userInfo:nil];
  }
  return vectorToBase64(result.value);
}

- (void)generateRandomBytes:(double)length
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject {
  size_t len = static_cast<size_t>(length);

  getThreadPool().enqueue([len, resolve, reject]() {
    auto result = getCryptoCore().generateRandomBytes(len);
    dispatch_async(dispatch_get_main_queue(), ^{
      if (result.ok) {
        resolve(vectorToBase64(result.value));
      } else {
        rejectWithError(reject, result.error);
      }
    });
  });
}

- (NSNumber *)constantTimeEquals:(NSString *)a b:(NSString *)b {
  NSData *aData = base64Decode(a);
  NSData *bData = base64Decode(b);
  bool equal = getCryptoCore().constantTimeEquals(
      dataBytes(aData), aData.length,
      dataBytes(bData), bData.length);
  return @(equal);
}

@end
