#include <jni.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fast_crypto_core.h"

// =============================================================================
// Singleton accessor for the crypto core
// =============================================================================

static fastcrypto::FastCryptoCore &getCore() {
  static fastcrypto::FastCryptoCore instance;
  return instance;
}

// =============================================================================
// JNI helpers
// =============================================================================

static std::vector<uint8_t> jbyteArrayToVec(JNIEnv *env, jbyteArray arr) {
  if (arr == nullptr) {
    return {};
  }
  jsize len = env->GetArrayLength(arr);
  std::vector<uint8_t> vec(static_cast<size_t>(len));
  env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte *>(vec.data()));
  return vec;
}

static jbyteArray vecToJbyteArray(JNIEnv *env,
                                  const std::vector<uint8_t> &vec) {
  jbyteArray arr = env->NewByteArray(static_cast<jsize>(vec.size()));
  if (arr == nullptr) {
    return nullptr; // OOM — JVM will throw
  }
  env->SetByteArrayRegion(arr, 0, static_cast<jsize>(vec.size()),
                          reinterpret_cast<const jbyte *>(vec.data()));
  return arr;
}

static std::string jstringToStd(JNIEnv *env, jstring str) {
  if (str == nullptr) {
    return "";
  }
  const char *chars = env->GetStringUTFChars(str, nullptr);
  std::string result(chars);
  env->ReleaseStringUTFChars(str, chars);
  return result;
}

/// Throw a Java RuntimeException with the given message and return the
/// specified default value (for use in early-return from JNI functions).
template <typename T>
static T throwAndReturn(JNIEnv *env, const std::string &msg, T defaultVal) {
  jclass cls = env->FindClass("java/lang/RuntimeException");
  if (cls != nullptr) {
    env->ThrowNew(cls, msg.c_str());
  }
  return defaultVal;
}

static void throwException(JNIEnv *env, const std::string &msg) {
  jclass cls = env->FindClass("java/lang/RuntimeException");
  if (cls != nullptr) {
    env->ThrowNew(cls, msg.c_str());
  }
}

// =============================================================================
// JNI functions — naming: Java_com_fastcrypto_FastCryptoModule_<method>
// All functions wrapped in try-catch to prevent native crashes
// =============================================================================

extern "C" {

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

JNIEXPORT jbyteArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeHash(JNIEnv *env, jobject /*thiz*/,
                                                jbyteArray data,
                                                jstring algorithm) {
  try {
    auto dataVec = jbyteArrayToVec(env, data);
    auto alg = jstringToStd(env, algorithm);

    auto result = getCore().hash(dataVec.data(), dataVec.size(), alg);
    if (!result.ok) {
      return throwAndReturn<jbyteArray>(env, result.error, nullptr);
    }
    return vecToJbyteArray(env, result.value);
  } catch (const std::exception &e) {
    return throwAndReturn<jbyteArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jbyteArray>(env, "Unknown native error", nullptr);
  }
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

JNIEXPORT jbyteArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeArgon2id(
    JNIEnv *env, jobject /*thiz*/, jbyteArray password, jbyteArray salt,
    jint memCost, jint timeCost, jint outputLen) {
  try {
    auto passVec = jbyteArrayToVec(env, password);
    auto saltVec = jbyteArrayToVec(env, salt);

    auto result = getCore().argon2id(
        passVec.data(), passVec.size(), saltVec.data(), saltVec.size(),
        static_cast<uint32_t>(memCost), static_cast<uint32_t>(timeCost),
        static_cast<size_t>(outputLen));
    if (!result.ok) {
      return throwAndReturn<jbyteArray>(env, result.error, nullptr);
    }
    return vecToJbyteArray(env, result.value);
  } catch (const std::exception &e) {
    return throwAndReturn<jbyteArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jbyteArray>(env, "Unknown native error", nullptr);
  }
}

// ---------------------------------------------------------------------------
// AEAD Encryption
// ---------------------------------------------------------------------------

JNIEXPORT jobjectArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeEncrypt(JNIEnv *env,
                                                   jobject /*thiz*/,
                                                   jbyteArray plaintext,
                                                   jbyteArray key,
                                                   jstring algorithm) {
  try {
    auto ptVec = jbyteArrayToVec(env, plaintext);
    auto keyVec = jbyteArrayToVec(env, key);
    auto alg = jstringToStd(env, algorithm);

    auto result =
        getCore().encrypt(ptVec.data(), ptVec.size(), keyVec.data(),
                          keyVec.size(), alg);
    if (!result.ok) {
      return throwAndReturn<jobjectArray>(env, result.error, nullptr);
    }

    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray out = env->NewObjectArray(3, byteArrayClass, nullptr);
    env->SetObjectArrayElement(out, 0,
                               vecToJbyteArray(env, result.value.ciphertext));
    env->SetObjectArrayElement(out, 1,
                               vecToJbyteArray(env, result.value.nonce));
    env->SetObjectArrayElement(out, 2,
                               vecToJbyteArray(env, result.value.tag));
    return out;
  } catch (const std::exception &e) {
    return throwAndReturn<jobjectArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jobjectArray>(env, "Unknown native error", nullptr);
  }
}

JNIEXPORT jbyteArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeDecrypt(
    JNIEnv *env, jobject /*thiz*/, jbyteArray ciphertext, jbyteArray nonce,
    jbyteArray tag, jbyteArray key, jstring algorithm) {
  try {
    auto ctVec = jbyteArrayToVec(env, ciphertext);
    auto nonceVec = jbyteArrayToVec(env, nonce);
    auto tagVec = jbyteArrayToVec(env, tag);
    auto keyVec = jbyteArrayToVec(env, key);
    auto alg = jstringToStd(env, algorithm);

    auto result = getCore().decrypt(ctVec.data(), ctVec.size(), nonceVec.data(),
                                    nonceVec.size(), tagVec.data(), tagVec.size(),
                                    keyVec.data(), keyVec.size(), alg);
    if (!result.ok) {
      return throwAndReturn<jbyteArray>(env, result.error, nullptr);
    }
    return vecToJbyteArray(env, result.value);
  } catch (const std::exception &e) {
    return throwAndReturn<jbyteArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jbyteArray>(env, "Unknown native error", nullptr);
  }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

JNIEXPORT jobjectArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeGenerateEd25519KeyPair(
    JNIEnv *env, jobject /*thiz*/) {
  try {
    auto result = getCore().generateEd25519KeyPair();
    if (!result.ok) {
      return throwAndReturn<jobjectArray>(env, result.error, nullptr);
    }

    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray out = env->NewObjectArray(2, byteArrayClass, nullptr);
    env->SetObjectArrayElement(out, 0,
                               vecToJbyteArray(env, result.value.publicKey));
    env->SetObjectArrayElement(out, 1,
                               vecToJbyteArray(env, result.value.privateKey));
    return out;
  } catch (const std::exception &e) {
    return throwAndReturn<jobjectArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jobjectArray>(env, "Unknown native error", nullptr);
  }
}

JNIEXPORT jbyteArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeSign(JNIEnv *env, jobject /*thiz*/,
                                                jbyteArray message,
                                                jbyteArray privateKey) {
  try {
    auto msgVec = jbyteArrayToVec(env, message);
    auto pkVec = jbyteArrayToVec(env, privateKey);

    auto result = getCore().sign(msgVec.data(), msgVec.size(), pkVec.data(),
                                 pkVec.size());
    if (!result.ok) {
      return throwAndReturn<jbyteArray>(env, result.error, nullptr);
    }
    return vecToJbyteArray(env, result.value);
  } catch (const std::exception &e) {
    return throwAndReturn<jbyteArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jbyteArray>(env, "Unknown native error", nullptr);
  }
}

JNIEXPORT jboolean JNICALL Java_com_fastcrypto_FastCryptoModule_nativeVerify(
    JNIEnv *env, jobject /*thiz*/, jbyteArray message, jbyteArray signature,
    jbyteArray publicKey) {
  try {
    auto msgVec = jbyteArrayToVec(env, message);
    auto sigVec = jbyteArrayToVec(env, signature);
    auto pubVec = jbyteArrayToVec(env, publicKey);

    auto result = getCore().verify(msgVec.data(), msgVec.size(), sigVec.data(),
                                   sigVec.size(), pubVec.data(), pubVec.size());
    if (!result.ok) {
      return throwAndReturn<jboolean>(env, result.error, JNI_FALSE);
    }
    return result.value ? JNI_TRUE : JNI_FALSE;
  } catch (const std::exception &e) {
    return throwAndReturn<jboolean>(env, e.what(), JNI_FALSE);
  } catch (...) {
    return throwAndReturn<jboolean>(env, "Unknown native error", JNI_FALSE);
  }
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

JNIEXPORT jobjectArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeGenerateX25519KeyPair(
    JNIEnv *env, jobject /*thiz*/) {
  try {
    auto result = getCore().generateX25519KeyPair();
    if (!result.ok) {
      return throwAndReturn<jobjectArray>(env, result.error, nullptr);
    }

    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray out = env->NewObjectArray(2, byteArrayClass, nullptr);
    env->SetObjectArrayElement(out, 0,
                               vecToJbyteArray(env, result.value.publicKey));
    env->SetObjectArrayElement(out, 1,
                               vecToJbyteArray(env, result.value.privateKey));
    return out;
  } catch (const std::exception &e) {
    return throwAndReturn<jobjectArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jobjectArray>(env, "Unknown native error", nullptr);
  }
}

JNIEXPORT jbyteArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeX25519DiffieHellman(
    JNIEnv *env, jobject /*thiz*/, jbyteArray privateKey,
    jbyteArray peerPublicKey) {
  try {
    auto privVec = jbyteArrayToVec(env, privateKey);
    auto peerVec = jbyteArrayToVec(env, peerPublicKey);

    auto result = getCore().x25519DiffieHellman(privVec.data(), privVec.size(),
                                                peerVec.data(), peerVec.size());
    if (!result.ok) {
      return throwAndReturn<jbyteArray>(env, result.error, nullptr);
    }
    return vecToJbyteArray(env, result.value);
  } catch (const std::exception &e) {
    return throwAndReturn<jbyteArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jbyteArray>(env, "Unknown native error", nullptr);
  }
}

// ---------------------------------------------------------------------------
// Feature Detection
// ---------------------------------------------------------------------------

JNIEXPORT jboolean JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeIsArgon2idAvailable(
    JNIEnv * /*env*/, jobject /*thiz*/) {
  return fastcrypto::FastCryptoCore::isArgon2idAvailable() ? JNI_TRUE
                                                           : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

JNIEXPORT jbyteArray JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeGenerateRandomBytes(
    JNIEnv *env, jobject /*thiz*/, jint length) {
  try {
    auto result = getCore().generateRandomBytes(static_cast<size_t>(length));
    if (!result.ok) {
      return throwAndReturn<jbyteArray>(env, result.error, nullptr);
    }
    return vecToJbyteArray(env, result.value);
  } catch (const std::exception &e) {
    return throwAndReturn<jbyteArray>(env, e.what(), nullptr);
  } catch (...) {
    return throwAndReturn<jbyteArray>(env, "Unknown native error", nullptr);
  }
}

JNIEXPORT jboolean JNICALL
Java_com_fastcrypto_FastCryptoModule_nativeConstantTimeEquals(
    JNIEnv *env, jobject /*thiz*/, jbyteArray a, jbyteArray b) {
  try {
    auto aVec = jbyteArrayToVec(env, a);
    auto bVec = jbyteArrayToVec(env, b);

    bool result =
        getCore().constantTimeEquals(aVec.data(), aVec.size(), bVec.data(),
                                     bVec.size());
    return result ? JNI_TRUE : JNI_FALSE;
  } catch (const std::exception &e) {
    return throwAndReturn<jboolean>(env, e.what(), JNI_FALSE);
  } catch (...) {
    return throwAndReturn<jboolean>(env, "Unknown native error", JNI_FALSE);
  }
}

} // extern "C"
