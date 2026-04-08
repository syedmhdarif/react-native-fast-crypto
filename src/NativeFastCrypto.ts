import { TurboModuleRegistry, type TurboModule } from 'react-native';

// ── Type Aliases (CodeGen-compatible) ──────────────────────────────
// Binary data is passed as base64-encoded strings across the bridge.
// The JS wrapper (src/index.tsx) converts ArrayBuffer <-> base64.
export type HashAlgorithm = 'SHA-256' | 'SHA-512';
export type AEADAlgorithm = 'AES-256-GCM' | 'ChaCha20-Poly1305';

export type NativeCipherResult = {
  ciphertext: string;
  nonce: string;
  tag: string;
};

export type NativeKeyPair = {
  publicKey: string;
  privateKey: string;
};

// ── Error Codes ────────────────────────────────────────────────────
export type FastCryptoErrorCode =
  | 'INVALID_KEY_SIZE'
  | 'INVALID_NONCE_SIZE'
  | 'DECRYPTION_FAILED'
  | 'BIOMETRIC_AUTH_FAILED'
  | 'BIOMETRIC_NOT_ENROLLED'
  | 'SECURE_ENCLAVE_UNAVAILABLE'
  | 'KEY_NOT_FOUND'
  | 'INVALID_INPUT'
  | 'OPERATION_CANCELLED'
  | 'UNKNOWN_NATIVE_ERROR';

// ── TurboModule Spec (Single Source of Truth for CodeGen) ──────────
// All binary data is base64-encoded strings at the native boundary.
export interface Spec extends TurboModule {
  // --- Hashing ---
  hashSync(data: string, algorithm: string): string;
  hash(data: string, algorithm: string): Promise<string>;

  // --- Key Derivation (Argon2id — RFC 9106) ---
  argon2idSync(
    password: string,
    salt: string,
    memCost: number,
    timeCost: number,
    outputLen: number
  ): string;
  argon2id(
    password: string,
    salt: string,
    memCost: number,
    timeCost: number,
    outputLen: number
  ): Promise<string>;

  // --- Authenticated Encryption (AEAD) ---
  encryptSync(
    plaintext: string,
    key: string,
    algorithm: string
  ): NativeCipherResult;
  encrypt(
    plaintext: string,
    key: string,
    algorithm: string
  ): Promise<NativeCipherResult>;

  decryptSync(
    ciphertext: string,
    nonce: string,
    tag: string,
    key: string,
    algorithm: string
  ): string;
  decrypt(
    ciphertext: string,
    nonce: string,
    tag: string,
    key: string,
    algorithm: string
  ): Promise<string>;

  // --- Asymmetric Crypto (Ed25519 — RFC 8032) ---
  generateEd25519KeyPairSync(): NativeKeyPair;
  generateEd25519KeyPair(): Promise<NativeKeyPair>;

  signSync(message: string, privateKey: string): string;
  sign(message: string, privateKey: string): Promise<string>;

  verifySync(message: string, signature: string, publicKey: string): boolean;
  verify(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean>;

  // --- X25519 Key Exchange (RFC 7748) ---
  generateX25519KeyPairSync(): NativeKeyPair;
  xDiffieHellmanSync(privateKey: string, peerPublicKey: string): string;

  // --- Secure Enclave / TEE ---
  generateSecureEnclaveKey(
    keyTag: string,
    requireBiometric: boolean
  ): Promise<string>;
  encryptWithSecureEnclaveKey(
    keyTag: string,
    plaintext: string
  ): Promise<string>;
  decryptWithSecureEnclaveKey(
    keyTag: string,
    ciphertext: string
  ): Promise<string>;
  deleteSecureEnclaveKey(keyTag: string): Promise<void>;

  // --- Feature Detection ---
  isArgon2idAvailable(): boolean;

  // --- Utilities ---
  generateRandomBytesSync(length: number): string;
  generateRandomBytes(length: number): Promise<string>;
  constantTimeEquals(a: string, b: string): boolean;
}

export default TurboModuleRegistry.getEnforcing<Spec>('FastCrypto');
