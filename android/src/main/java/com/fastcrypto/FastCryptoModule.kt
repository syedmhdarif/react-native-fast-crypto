package com.fastcrypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableMap
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class FastCryptoModule(reactContext: ReactApplicationContext) :
  NativeFastCryptoSpec(reactContext) {

  private val executor = Executors.newFixedThreadPool(
    Runtime.getRuntime().availableProcessors().coerceIn(2, 8)
  )

  companion object {
    const val NAME = NativeFastCryptoSpec.NAME
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val GCM_TAG_LENGTH = 128

    init {
      System.loadLibrary("fast_crypto")
    }
  }

  override fun getName(): String = NAME

  // ---------------------------------------------------------------------------
  // JNI external declarations — match native C++ implementations
  // ---------------------------------------------------------------------------

  private external fun nativeHash(data: ByteArray, algorithm: String): ByteArray
  private external fun nativeArgon2id(
    password: ByteArray, salt: ByteArray,
    memCost: Int, timeCost: Int, outputLen: Int
  ): ByteArray

  private external fun nativeEncrypt(
    plaintext: ByteArray, key: ByteArray, algorithm: String
  ): Array<ByteArray> // [ciphertext, nonce, tag]

  private external fun nativeDecrypt(
    ciphertext: ByteArray, nonce: ByteArray, tag: ByteArray,
    key: ByteArray, algorithm: String
  ): ByteArray

  private external fun nativeGenerateEd25519KeyPair(): Array<ByteArray> // [pub, priv]
  private external fun nativeSign(message: ByteArray, privateKey: ByteArray): ByteArray
  private external fun nativeVerify(
    message: ByteArray, signature: ByteArray, publicKey: ByteArray
  ): Boolean

  private external fun nativeGenerateX25519KeyPair(): Array<ByteArray> // [pub, priv]
  private external fun nativeX25519DiffieHellman(
    privateKey: ByteArray, peerPublicKey: ByteArray
  ): ByteArray

  private external fun nativeGenerateRandomBytes(length: Int): ByteArray
  private external fun nativeConstantTimeEquals(a: ByteArray, b: ByteArray): Boolean

  // ---------------------------------------------------------------------------
  // Helpers: base64 <-> ByteArray conversion
  // ---------------------------------------------------------------------------

  private fun makeCipherResultMap(parts: Array<ByteArray>): WritableMap {
    val map = Arguments.createMap()
    map.putString("ciphertext", toB64(parts[0]))
    map.putString("nonce", toB64(parts[1]))
    map.putString("tag", toB64(parts[2]))
    return map
  }

  private fun makeKeyPairMap(parts: Array<ByteArray>): WritableMap {
    val map = Arguments.createMap()
    map.putString("publicKey", toB64(parts[0]))
    map.putString("privateKey", toB64(parts[1]))
    return map
  }

  private fun toB64(bytes: ByteArray): String {
    return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
  }

  private fun fromB64(base64: String): ByteArray {
    return android.util.Base64.decode(base64, android.util.Base64.NO_WRAP)
  }

  private fun runAsync(promise: Promise, block: () -> Unit) {
    executor.execute {
      try {
        block()
      } catch (e: Exception) {
        promise.reject("FAST_CRYPTO_ERROR", e.message, e)
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Hashing
  // ---------------------------------------------------------------------------

  override fun hashSync(data: String, algorithm: String): String {
    return try {
      toB64(nativeHash(fromB64(data), algorithm))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun hash(data: String, algorithm: String, promise: Promise) {
    val raw = fromB64(data)
    runAsync(promise) {
      val result = nativeHash(raw, algorithm)
      promise.resolve(toB64(result))
    }
  }

  // ---------------------------------------------------------------------------
  // Argon2id
  // ---------------------------------------------------------------------------

  override fun argon2idSync(
    password: String, salt: String,
    memCost: Double, timeCost: Double, outputLen: Double
  ): String {
    return try {
      toB64(nativeArgon2id(
        fromB64(password), fromB64(salt),
        memCost.toInt(), timeCost.toInt(), outputLen.toInt()
      ))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun argon2id(
    password: String, salt: String,
    memCost: Double, timeCost: Double, outputLen: Double,
    promise: Promise
  ) {
    val pw = fromB64(password)
    val sl = fromB64(salt)
    runAsync(promise) {
      val result = nativeArgon2id(
        pw, sl, memCost.toInt(), timeCost.toInt(), outputLen.toInt()
      )
      promise.resolve(toB64(result))
    }
  }

  // ---------------------------------------------------------------------------
  // AEAD Encryption
  // ---------------------------------------------------------------------------

  override fun encryptSync(
    plaintext: String, key: String, algorithm: String
  ): WritableMap {
    return try {
      val parts = nativeEncrypt(fromB64(plaintext), fromB64(key), algorithm)
      makeCipherResultMap(parts)
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun encrypt(
    plaintext: String, key: String, algorithm: String,
    promise: Promise
  ) {
    val pt = fromB64(plaintext)
    val k = fromB64(key)
    runAsync(promise) {
      val parts = nativeEncrypt(pt, k, algorithm)
      promise.resolve(makeCipherResultMap(parts))
    }
  }

  override fun decryptSync(
    ciphertext: String, nonce: String, tag: String,
    key: String, algorithm: String
  ): String {
    return try {
      toB64(nativeDecrypt(
        fromB64(ciphertext), fromB64(nonce), fromB64(tag),
        fromB64(key), algorithm
      ))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun decrypt(
    ciphertext: String, nonce: String, tag: String,
    key: String, algorithm: String,
    promise: Promise
  ) {
    val ct = fromB64(ciphertext)
    val n = fromB64(nonce)
    val t = fromB64(tag)
    val k = fromB64(key)
    runAsync(promise) {
      val result = nativeDecrypt(ct, n, t, k, algorithm)
      promise.resolve(toB64(result))
    }
  }

  // ---------------------------------------------------------------------------
  // Ed25519
  // ---------------------------------------------------------------------------

  override fun generateEd25519KeyPairSync(): WritableMap {
    return try {
      val parts = nativeGenerateEd25519KeyPair()
      makeKeyPairMap(parts)
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun generateEd25519KeyPair(promise: Promise) {
    runAsync(promise) {
      val parts = nativeGenerateEd25519KeyPair()
      promise.resolve(makeKeyPairMap(parts))
    }
  }

  override fun signSync(message: String, privateKey: String): String {
    return try {
      toB64(nativeSign(fromB64(message), fromB64(privateKey)))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun sign(message: String, privateKey: String, promise: Promise) {
    val msg = fromB64(message)
    val key = fromB64(privateKey)
    runAsync(promise) {
      val result = nativeSign(msg, key)
      promise.resolve(toB64(result))
    }
  }

  override fun verifySync(
    message: String, signature: String, publicKey: String
  ): Boolean {
    return try {
      nativeVerify(fromB64(message), fromB64(signature), fromB64(publicKey))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun verify(
    message: String, signature: String, publicKey: String,
    promise: Promise
  ) {
    val msg = fromB64(message)
    val sig = fromB64(signature)
    val key = fromB64(publicKey)
    runAsync(promise) {
      val result = nativeVerify(msg, sig, key)
      promise.resolve(result)
    }
  }

  // ---------------------------------------------------------------------------
  // X25519
  // ---------------------------------------------------------------------------

  override fun generateX25519KeyPairSync(): WritableMap {
    return try {
      val parts = nativeGenerateX25519KeyPair()
      makeKeyPairMap(parts)
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun xDiffieHellmanSync(
    privateKey: String, peerPublicKey: String
  ): String {
    return try {
      toB64(nativeX25519DiffieHellman(fromB64(privateKey), fromB64(peerPublicKey)))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  // ---------------------------------------------------------------------------
  // Secure Enclave / TEE (Android Keystore + StrongBox)
  // ---------------------------------------------------------------------------

  override fun generateSecureEnclaveKey(
    keyTag: String, requireBiometric: Boolean, promise: Promise
  ) {
    runAsync(promise) {
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        // Delete existing key with same tag if present
        if (keyStore.containsAlias(keyTag)) {
          keyStore.deleteEntry(keyTag)
        }

        val specBuilder = KeyGenParameterSpec.Builder(
          keyTag,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
          .setKeySize(256)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)

        if (requireBiometric) {
          specBuilder.setUserAuthenticationRequired(true)
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            specBuilder.setUserAuthenticationParameters(
              0, KeyProperties.AUTH_BIOMETRIC_STRONG
            )
          }
        }

        // Use StrongBox if available (Android 9+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          specBuilder.setIsStrongBoxBacked(true)
        }

        val keyGenerator = javax.crypto.KeyGenerator.getInstance(
          KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
        )

        try {
          keyGenerator.init(specBuilder.build())
        } catch (e: Exception) {
          // StrongBox may not be available; fall back without it
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(false)
            keyGenerator.init(specBuilder.build())
          } else {
            throw e
          }
        }

        keyGenerator.generateKey()
        promise.resolve(keyTag)
      } catch (e: Exception) {
        promise.reject("SECURE_ENCLAVE_UNAVAILABLE", e.message, e)
      }
    }
  }

  override fun encryptWithSecureEnclaveKey(
    keyTag: String, plaintext: String, promise: Promise
  ) {
    val pt = fromB64(plaintext)
    runAsync(promise) {
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val secretKey = keyStore.getKey(keyTag, null)
          ?: throw Exception("Key not found: $keyTag")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey as javax.crypto.SecretKey)

        val iv = cipher.iv
        val encrypted = cipher.doFinal(pt)

        // Prepend IV (12 bytes) to ciphertext for storage
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        promise.resolve(toB64(combined))
      } catch (e: android.security.keystore.UserNotAuthenticatedException) {
        promise.reject("BIOMETRIC_AUTH_FAILED", "Biometric authentication required", e)
      } catch (e: Exception) {
        promise.reject("SECURE_ENCLAVE_UNAVAILABLE", e.message, e)
      }
    }
  }

  override fun decryptWithSecureEnclaveKey(
    keyTag: String, ciphertext: String, promise: Promise
  ) {
    val ct = fromB64(ciphertext)
    runAsync(promise) {
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val secretKey = keyStore.getKey(keyTag, null)
          ?: throw Exception("Key not found: $keyTag")

        // Extract IV (first 12 bytes) from combined ciphertext
        val iv = ct.copyOfRange(0, 12)
        val encryptedData = ct.copyOfRange(12, ct.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey as javax.crypto.SecretKey, spec)

        val decrypted = cipher.doFinal(encryptedData)
        promise.resolve(toB64(decrypted))
      } catch (e: android.security.keystore.UserNotAuthenticatedException) {
        promise.reject("BIOMETRIC_AUTH_FAILED", "Biometric authentication required", e)
      } catch (e: javax.crypto.AEADBadTagException) {
        promise.reject("DECRYPTION_FAILED", "Decryption failed: authentication tag mismatch", e)
      } catch (e: Exception) {
        promise.reject("SECURE_ENCLAVE_UNAVAILABLE", e.message, e)
      }
    }
  }

  override fun deleteSecureEnclaveKey(keyTag: String, promise: Promise) {
    runAsync(promise) {
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(keyTag)) {
          keyStore.deleteEntry(keyTag)
        }

        promise.resolve(null)
      } catch (e: Exception) {
        promise.reject("SECURE_ENCLAVE_UNAVAILABLE", e.message, e)
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Utilities
  // ---------------------------------------------------------------------------

  override fun generateRandomBytesSync(length: Double): String {
    return try {
      toB64(nativeGenerateRandomBytes(length.toInt()))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }

  override fun generateRandomBytes(length: Double, promise: Promise) {
    runAsync(promise) {
      val result = nativeGenerateRandomBytes(length.toInt())
      promise.resolve(toB64(result))
    }
  }

  override fun constantTimeEquals(a: String, b: String): Boolean {
    return try {
      nativeConstantTimeEquals(fromB64(a), fromB64(b))
    } catch (e: RuntimeException) {
      throw Exception(e.message)
    }
  }
}
