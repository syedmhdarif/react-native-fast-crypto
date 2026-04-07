import FastCrypto from './NativeFastCrypto';

export function multiply(a: number, b: number): number {
  return FastCrypto.multiply(a, b);
}
