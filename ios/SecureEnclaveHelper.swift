import Foundation
import Security

/// Manages Secure Enclave key generation, encryption, and decryption for the
/// react-native-fast-crypto TurboModule. All public methods use completion handlers
/// so they can be called from Obj-C++ promise-based bridge code.
@objcMembers
@objc public class SecureEnclaveHelper: NSObject {

  // MARK: - Error Helpers

  private static let domain = "com.fastcrypto.secureenclave"

  private static func makeError(code: String, message: String) -> NSError {
    return NSError(
      domain: domain,
      code: -1,
      userInfo: [
        "code": code,
        NSLocalizedDescriptionKey: message,
      ]
    )
  }

  // MARK: - Generate Key

  /// Generates an elliptic-curve key pair inside the Secure Enclave.
  /// Returns the public key as a hex-encoded string on success.
  @objc public static func generateKey(
    keyTag: String,
    requireBiometric: Bool,
    completion: @escaping (String?, NSError?) -> Void
  ) {
    guard SecureEnclaveHelper.isSecureEnclaveAvailable() else {
      completion(nil, makeError(
        code: "SECURE_ENCLAVE_UNAVAILABLE",
        message: "Secure Enclave is not available on this device"))
      return
    }

    // Build access control flags
    var accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if requireBiometric {
      accessFlags.insert(.biometryCurrentSet)
    }

    var accessError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      accessFlags,
      &accessError
    ) else {
      let msg = accessError?.takeRetainedValue().localizedDescription ?? "Unknown error"
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Failed to create access control: \(msg)"))
      return
    }

    let tagData = keyTag.data(using: .utf8)!

    let privateKeyAttrs: [String: Any] = [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: tagData,
      kSecAttrAccessControl as String: accessControl,
    ]

    let keyAttributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: privateKeyAttrs,
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
      let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Failed to generate key: \(msg)"))
      return
    }

    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Failed to extract public key"))
      return
    }

    var exportError: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
      let msg = exportError?.takeRetainedValue().localizedDescription ?? "Unknown error"
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Failed to export public key: \(msg)"))
      return
    }

    let hexString = publicKeyData.map { String(format: "%02x", $0) }.joined()
    completion(hexString, nil)
  }

  // MARK: - Encrypt

  /// Encrypts data using the public key associated with the given key tag.
  /// Uses ECIES (Elliptic Curve Integrated Encryption Scheme) via SecKeyCreateEncryptedData.
  @objc public static func encrypt(
    keyTag: String,
    plaintext: Data,
    completion: @escaping (Data?, NSError?) -> Void
  ) {
    guard let privateKey = lookupPrivateKey(keyTag: keyTag) else {
      completion(nil, makeError(code: "KEY_NOT_FOUND", message: "No key found for tag: \(keyTag)"))
      return
    }

    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Failed to get public key for encryption"))
      return
    }

    let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Encryption algorithm not supported"))
      return
    }

    var error: Unmanaged<CFError>?
    guard let ciphertext = SecKeyCreateEncryptedData(
      publicKey,
      algorithm,
      plaintext as CFData,
      &error
    ) as Data? else {
      let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Encryption failed: \(msg)"))
      return
    }

    completion(ciphertext, nil)
  }

  // MARK: - Decrypt

  /// Decrypts data using the Secure Enclave private key associated with the given key tag.
  /// This may trigger biometric authentication if the key was created with requireBiometric = true.
  @objc public static func decrypt(
    keyTag: String,
    ciphertext: Data,
    completion: @escaping (Data?, NSError?) -> Void
  ) {
    guard let privateKey = lookupPrivateKey(keyTag: keyTag) else {
      completion(nil, makeError(code: "KEY_NOT_FOUND", message: "No key found for tag: \(keyTag)"))
      return
    }

    let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
      completion(nil, makeError(code: "UNKNOWN_NATIVE_ERROR", message: "Decryption algorithm not supported"))
      return
    }

    // Dispatch to background to avoid blocking the main thread during biometric prompt
    DispatchQueue.global(qos: .userInitiated).async {
      var error: Unmanaged<CFError>?
      guard let plaintext = SecKeyCreateDecryptedData(
        privateKey,
        algorithm,
        ciphertext as CFData,
        &error
      ) as Data? else {
        let cfError = error?.takeRetainedValue()
        let msg = cfError?.localizedDescription ?? "Unknown error"

        // Check for user cancellation / biometric failure
        let nsError = cfError as NSError?
        let resultError: NSError
        if nsError?.domain == NSOSStatusErrorDomain {
          switch nsError?.code {
          case Int(errSecUserCanceled):
            resultError = makeError(code: "OPERATION_CANCELLED", message: "User cancelled biometric authentication")
          case Int(errSecAuthFailed):
            resultError = makeError(code: "BIOMETRIC_AUTH_FAILED", message: "Biometric authentication failed")
          default:
            resultError = makeError(code: "DECRYPTION_FAILED", message: "Decryption failed: \(msg)")
          }
        } else {
          resultError = makeError(code: "DECRYPTION_FAILED", message: "Decryption failed: \(msg)")
        }

        DispatchQueue.main.async {
          completion(nil, resultError)
        }
        return
      }

      DispatchQueue.main.async {
        completion(plaintext as Data, nil)
      }
    }
  }

  // MARK: - Delete Key

  /// Deletes the Secure Enclave key pair associated with the given key tag.
  @objc public static func deleteKey(
    keyTag: String,
    completion: @escaping (NSError?) -> Void
  ) {
    let tagData = keyTag.data(using: .utf8)!
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]

    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
      completion(nil)
    } else {
      completion(makeError(
        code: "UNKNOWN_NATIVE_ERROR",
        message: "Failed to delete key, OSStatus: \(status)"))
    }
  }

  // MARK: - Private Helpers

  /// Looks up a Secure Enclave private key by its application tag.
  private static func lookupPrivateKey(keyTag: String) -> SecKey? {
    let tagData = keyTag.data(using: .utf8)!
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else {
      return nil
    }
    return (item as! SecKey)
  }

  /// Checks whether the Secure Enclave is available on this device.
  private static func isSecureEnclaveAvailable() -> Bool {
    // Attempt to create access control with Secure Enclave constraints.
    // If it succeeds, the Secure Enclave is available.
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage],
      &error
    )
    return accessControl != nil
  }
}
