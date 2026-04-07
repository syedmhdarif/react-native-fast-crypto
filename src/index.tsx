import NativeFastCrypto from './NativeFastCrypto';
import type { CipherResult, KeyPair } from './types';

export type {
  HashAlgorithm,
  AEADAlgorithm,
  FastCryptoErrorCode,
} from './NativeFastCrypto';
export type { CipherResult, KeyPair } from './types';
export { FastCryptoError } from './types';
export type { KeySecurityLevel } from './types';
export { toHex, fromHex, toBase64, fromBase64, toUint8Array } from './utils';

// ── Internal base64 <-> ArrayBuffer helpers ────────────────────────────

function ab2b64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function b642ab(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

function nativeKeyPairToKeyPair(nkp: {
  publicKey: string;
  privateKey: string;
}): KeyPair {
  return {
    publicKey: b642ab(nkp.publicKey),
    privateKey: b642ab(nkp.privateKey),
  };
}

function nativeCipherResultToCipherResult(ncr: {
  ciphertext: string;
  nonce: string;
  tag: string;
}): CipherResult {
  return {
    ciphertext: b642ab(ncr.ciphertext),
    nonce: b642ab(ncr.nonce),
    tag: b642ab(ncr.tag),
  };
}

// ── Public API (ArrayBuffer interface) ─────────────────────────────────

export const FastCrypto = {
  // --- Hashing ---
  hashSync(data: ArrayBuffer, algorithm: string): ArrayBuffer {
    return b642ab(NativeFastCrypto.hashSync(ab2b64(data), algorithm));
  },
  async hash(data: ArrayBuffer, algorithm: string): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.hash(ab2b64(data), algorithm);
    return b642ab(result);
  },

  // --- Key Derivation (Argon2id) ---
  argon2idSync(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    memCost: number,
    timeCost: number,
    outputLen: number
  ): ArrayBuffer {
    return b642ab(
      NativeFastCrypto.argon2idSync(
        ab2b64(password),
        ab2b64(salt),
        memCost,
        timeCost,
        outputLen
      )
    );
  },
  async argon2id(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    memCost: number,
    timeCost: number,
    outputLen: number
  ): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.argon2id(
      ab2b64(password),
      ab2b64(salt),
      memCost,
      timeCost,
      outputLen
    );
    return b642ab(result);
  },

  // --- AEAD Encryption ---
  encryptSync(
    plaintext: ArrayBuffer,
    key: ArrayBuffer,
    algorithm: string
  ): CipherResult {
    const result = NativeFastCrypto.encryptSync(
      ab2b64(plaintext),
      ab2b64(key),
      algorithm
    );
    return nativeCipherResultToCipherResult(result);
  },
  async encrypt(
    plaintext: ArrayBuffer,
    key: ArrayBuffer,
    algorithm: string
  ): Promise<CipherResult> {
    const result = await NativeFastCrypto.encrypt(
      ab2b64(plaintext),
      ab2b64(key),
      algorithm
    );
    return nativeCipherResultToCipherResult(result);
  },

  decryptSync(
    ciphertext: ArrayBuffer,
    nonce: ArrayBuffer,
    tag: ArrayBuffer,
    key: ArrayBuffer,
    algorithm: string
  ): ArrayBuffer {
    return b642ab(
      NativeFastCrypto.decryptSync(
        ab2b64(ciphertext),
        ab2b64(nonce),
        ab2b64(tag),
        ab2b64(key),
        algorithm
      )
    );
  },
  async decrypt(
    ciphertext: ArrayBuffer,
    nonce: ArrayBuffer,
    tag: ArrayBuffer,
    key: ArrayBuffer,
    algorithm: string
  ): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.decrypt(
      ab2b64(ciphertext),
      ab2b64(nonce),
      ab2b64(tag),
      ab2b64(key),
      algorithm
    );
    return b642ab(result);
  },

  // --- Ed25519 ---
  generateEd25519KeyPairSync(): KeyPair {
    return nativeKeyPairToKeyPair(
      NativeFastCrypto.generateEd25519KeyPairSync()
    );
  },
  async generateEd25519KeyPair(): Promise<KeyPair> {
    const result = await NativeFastCrypto.generateEd25519KeyPair();
    return nativeKeyPairToKeyPair(result);
  },

  signSync(message: ArrayBuffer, privateKey: ArrayBuffer): ArrayBuffer {
    return b642ab(
      NativeFastCrypto.signSync(ab2b64(message), ab2b64(privateKey))
    );
  },
  async sign(
    message: ArrayBuffer,
    privateKey: ArrayBuffer
  ): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.sign(
      ab2b64(message),
      ab2b64(privateKey)
    );
    return b642ab(result);
  },

  verifySync(
    message: ArrayBuffer,
    signature: ArrayBuffer,
    publicKey: ArrayBuffer
  ): boolean {
    return NativeFastCrypto.verifySync(
      ab2b64(message),
      ab2b64(signature),
      ab2b64(publicKey)
    );
  },
  async verify(
    message: ArrayBuffer,
    signature: ArrayBuffer,
    publicKey: ArrayBuffer
  ): Promise<boolean> {
    return NativeFastCrypto.verify(
      ab2b64(message),
      ab2b64(signature),
      ab2b64(publicKey)
    );
  },

  // --- X25519 ---
  generateX25519KeyPairSync(): KeyPair {
    return nativeKeyPairToKeyPair(
      NativeFastCrypto.generateX25519KeyPairSync()
    );
  },
  xDiffieHellmanSync(
    privateKey: ArrayBuffer,
    peerPublicKey: ArrayBuffer
  ): ArrayBuffer {
    return b642ab(
      NativeFastCrypto.xDiffieHellmanSync(
        ab2b64(privateKey),
        ab2b64(peerPublicKey)
      )
    );
  },

  // --- Secure Enclave / TEE ---
  generateSecureEnclaveKey(
    keyTag: string,
    requireBiometric: boolean
  ): Promise<string> {
    return NativeFastCrypto.generateSecureEnclaveKey(keyTag, requireBiometric);
  },
  async encryptWithSecureEnclaveKey(
    keyTag: string,
    plaintext: ArrayBuffer
  ): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.encryptWithSecureEnclaveKey(
      keyTag,
      ab2b64(plaintext)
    );
    return b642ab(result);
  },
  async decryptWithSecureEnclaveKey(
    keyTag: string,
    ciphertext: ArrayBuffer
  ): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.decryptWithSecureEnclaveKey(
      keyTag,
      ab2b64(ciphertext)
    );
    return b642ab(result);
  },
  deleteSecureEnclaveKey(keyTag: string): Promise<void> {
    return NativeFastCrypto.deleteSecureEnclaveKey(keyTag);
  },

  // --- Utilities ---
  generateRandomBytesSync(length: number): ArrayBuffer {
    return b642ab(NativeFastCrypto.generateRandomBytesSync(length));
  },
  async generateRandomBytes(length: number): Promise<ArrayBuffer> {
    const result = await NativeFastCrypto.generateRandomBytes(length);
    return b642ab(result);
  },
  constantTimeEquals(a: ArrayBuffer, b: ArrayBuffer): boolean {
    return NativeFastCrypto.constantTimeEquals(ab2b64(a), ab2b64(b));
  },
};
