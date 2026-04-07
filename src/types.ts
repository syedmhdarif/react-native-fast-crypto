export type { HashAlgorithm, AEADAlgorithm, FastCryptoErrorCode } from './NativeFastCrypto';

export type CipherResult = {
  ciphertext: ArrayBuffer;
  nonce: ArrayBuffer;
  tag: ArrayBuffer;
};

export type KeyPair = {
  publicKey: ArrayBuffer;
  privateKey: ArrayBuffer;
};

export class FastCryptoError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'FastCryptoError';
    this.code = code;
  }
}

export type KeySecurityLevel = 'SOFTWARE' | 'KEYSTORE' | 'SECURE_ENCLAVE';
