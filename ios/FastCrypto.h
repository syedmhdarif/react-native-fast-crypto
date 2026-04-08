#pragma once

#ifdef __cplusplus
#import <FastCryptoSpec/FastCryptoSpec.h>
#endif

@interface FastCrypto : NSObject <NativeFastCryptoSpec>

// --- Hashing ---
- (NSString *)hashSync:(NSString *)data algorithm:(NSString *)algorithm;
- (void)hash:(NSString *)data
    algorithm:(NSString *)algorithm
      resolve:(RCTPromiseResolveBlock)resolve
       reject:(RCTPromiseRejectBlock)reject;

// --- Key Derivation (Argon2id) ---
- (NSString *)argon2idSync:(NSString *)password
                      salt:(NSString *)salt
                   memCost:(double)memCost
                  timeCost:(double)timeCost
                 outputLen:(double)outputLen;
- (void)argon2id:(NSString *)password
            salt:(NSString *)salt
         memCost:(double)memCost
        timeCost:(double)timeCost
       outputLen:(double)outputLen
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject;

// --- AEAD Encryption ---
- (NSDictionary *)encryptSync:(NSString *)plaintext
                          key:(NSString *)key
                    algorithm:(NSString *)algorithm;
- (void)encrypt:(NSString *)plaintext
            key:(NSString *)key
      algorithm:(NSString *)algorithm
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject;

- (NSString *)decryptSync:(NSString *)ciphertext
                    nonce:(NSString *)nonce
                      tag:(NSString *)tag
                      key:(NSString *)key
                algorithm:(NSString *)algorithm;
- (void)decrypt:(NSString *)ciphertext
          nonce:(NSString *)nonce
            tag:(NSString *)tag
            key:(NSString *)key
      algorithm:(NSString *)algorithm
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject;

// --- Ed25519 ---
- (NSDictionary *)generateEd25519KeyPairSync;
- (void)generateEd25519KeyPair:(RCTPromiseResolveBlock)resolve
                        reject:(RCTPromiseRejectBlock)reject;

- (NSString *)signSync:(NSString *)message privateKey:(NSString *)privateKey;
- (void)sign:(NSString *)message
  privateKey:(NSString *)privateKey
     resolve:(RCTPromiseResolveBlock)resolve
      reject:(RCTPromiseRejectBlock)reject;

- (NSNumber *)verifySync:(NSString *)message
               signature:(NSString *)signature
               publicKey:(NSString *)publicKey;
- (void)verify:(NSString *)message
     signature:(NSString *)signature
     publicKey:(NSString *)publicKey
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject;

// --- X25519 ---
- (NSDictionary *)generateX25519KeyPairSync;
- (NSString *)xDiffieHellmanSync:(NSString *)privateKey
                   peerPublicKey:(NSString *)peerPublicKey;

// --- Secure Enclave / TEE ---
- (void)generateSecureEnclaveKey:(NSString *)keyTag
               requireBiometric:(NSNumber *)requireBiometric
                        resolve:(RCTPromiseResolveBlock)resolve
                         reject:(RCTPromiseRejectBlock)reject;
- (void)encryptWithSecureEnclaveKey:(NSString *)keyTag
                          plaintext:(NSString *)plaintext
                            resolve:(RCTPromiseResolveBlock)resolve
                             reject:(RCTPromiseRejectBlock)reject;
- (void)decryptWithSecureEnclaveKey:(NSString *)keyTag
                         ciphertext:(NSString *)ciphertext
                            resolve:(RCTPromiseResolveBlock)resolve
                             reject:(RCTPromiseRejectBlock)reject;
- (void)deleteSecureEnclaveKey:(NSString *)keyTag
                       resolve:(RCTPromiseResolveBlock)resolve
                        reject:(RCTPromiseRejectBlock)reject;

// --- Feature Detection ---
- (NSNumber *)isArgon2idAvailable;

// --- Utilities ---
- (NSString *)generateRandomBytesSync:(double)length;
- (void)generateRandomBytes:(double)length
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject;
- (NSNumber *)constantTimeEquals:(NSString *)a b:(NSString *)b;

@end
