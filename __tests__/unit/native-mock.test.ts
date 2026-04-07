/**
 * Tests that verify the public API surface can be imported correctly.
 * Native module is mocked since Jest runs in Node, not on-device.
 */

jest.mock('react-native', () => ({
  TurboModuleRegistry: {
    getEnforcing: jest.fn(() => ({
      hashSync: jest.fn(),
      hash: jest.fn(),
      argon2idSync: jest.fn(),
      argon2id: jest.fn(),
      encryptSync: jest.fn(),
      encrypt: jest.fn(),
      decryptSync: jest.fn(),
      decrypt: jest.fn(),
      generateEd25519KeyPairSync: jest.fn(),
      generateEd25519KeyPair: jest.fn(),
      signSync: jest.fn(),
      sign: jest.fn(),
      verifySync: jest.fn(),
      verify: jest.fn(),
      generateX25519KeyPairSync: jest.fn(),
      xDiffieHellmanSync: jest.fn(),
      generateSecureEnclaveKey: jest.fn(),
      encryptWithSecureEnclaveKey: jest.fn(),
      decryptWithSecureEnclaveKey: jest.fn(),
      deleteSecureEnclaveKey: jest.fn(),
      generateRandomBytesSync: jest.fn(),
      generateRandomBytes: jest.fn(),
      constantTimeEquals: jest.fn(),
    })),
  },
}));

import { FastCrypto, FastCryptoError } from '../../src/index';

describe('FastCrypto module', () => {
  it('is defined', () => {
    expect(FastCrypto).toBeDefined();
  });

  it('exposes hashSync', () => {
    expect(typeof FastCrypto.hashSync).toBe('function');
  });

  it('exposes hash', () => {
    expect(typeof FastCrypto.hash).toBe('function');
  });

  it('exposes encryptSync', () => {
    expect(typeof FastCrypto.encryptSync).toBe('function');
  });

  it('exposes generateEd25519KeyPairSync', () => {
    expect(typeof FastCrypto.generateEd25519KeyPairSync).toBe('function');
  });

  it('exposes signSync', () => {
    expect(typeof FastCrypto.signSync).toBe('function');
  });

  it('exposes verifySync', () => {
    expect(typeof FastCrypto.verifySync).toBe('function');
  });

  it('exposes generateX25519KeyPairSync', () => {
    expect(typeof FastCrypto.generateX25519KeyPairSync).toBe('function');
  });

  it('exposes xDiffieHellmanSync', () => {
    expect(typeof FastCrypto.xDiffieHellmanSync).toBe('function');
  });

  it('exposes Secure Enclave methods', () => {
    expect(typeof FastCrypto.generateSecureEnclaveKey).toBe('function');
    expect(typeof FastCrypto.encryptWithSecureEnclaveKey).toBe('function');
    expect(typeof FastCrypto.decryptWithSecureEnclaveKey).toBe('function');
    expect(typeof FastCrypto.deleteSecureEnclaveKey).toBe('function');
  });

  it('exposes utility methods', () => {
    expect(typeof FastCrypto.generateRandomBytesSync).toBe('function');
    expect(typeof FastCrypto.generateRandomBytes).toBe('function');
    expect(typeof FastCrypto.constantTimeEquals).toBe('function');
  });
});

describe('FastCryptoError', () => {
  it('creates error with code', () => {
    const err = new FastCryptoError('INVALID_KEY_SIZE', 'Key must be 32 bytes');
    expect(err.code).toBe('INVALID_KEY_SIZE');
    expect(err.message).toBe('Key must be 32 bytes');
    expect(err.name).toBe('FastCryptoError');
    expect(err instanceof Error).toBe(true);
  });
});
