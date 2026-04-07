/**
 * Performance benchmark suite for react-native-fast-crypto.
 *
 * This file is meant to be run on-device (not in Jest).
 * Import it in the example app or a Detox test to collect timings.
 */

import { FastCrypto } from '../../src/index';

type BenchmarkResult = {
  name: string;
  iterations: number;
  totalMs: number;
  avgMs: number;
  opsPerSec: number;
};

async function benchmark(
  name: string,
  fn: () => void | Promise<void>,
  iterations: number = 1000
): Promise<BenchmarkResult> {
  // Warmup
  for (let i = 0; i < 10; i++) {
    await fn();
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const totalMs = performance.now() - start;

  return {
    name,
    iterations,
    totalMs: Math.round(totalMs * 100) / 100,
    avgMs: Math.round((totalMs / iterations) * 1000) / 1000,
    opsPerSec: Math.round(iterations / (totalMs / 1000)),
  };
}

export async function runBenchmarks(): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];
  const encoder = new TextEncoder();

  // SHA-256 sync (small payload)
  const smallData = encoder.encode('hello world').buffer as ArrayBuffer;
  results.push(
    await benchmark('SHA-256 sync (11B)', () => {
      FastCrypto.hashSync(smallData, 'SHA-256');
    })
  );

  // SHA-256 sync (1KB payload)
  const mediumData = FastCrypto.generateRandomBytesSync(1024);
  results.push(
    await benchmark('SHA-256 sync (1KB)', () => {
      FastCrypto.hashSync(mediumData, 'SHA-256');
    })
  );

  // AES-256-GCM encrypt sync (256B)
  const aesKey = FastCrypto.generateRandomBytesSync(32);
  const aesData = FastCrypto.generateRandomBytesSync(256);
  results.push(
    await benchmark('AES-256-GCM encrypt sync (256B)', () => {
      FastCrypto.encryptSync(aesData, aesKey, 'AES-256-GCM');
    })
  );

  // Ed25519 keygen
  results.push(
    await benchmark(
      'Ed25519 keygen sync',
      () => {
        FastCrypto.generateEd25519KeyPairSync();
      },
      500
    )
  );

  // Ed25519 sign
  const { privateKey } = FastCrypto.generateEd25519KeyPairSync();
  const signMsg = encoder.encode('benchmark message').buffer as ArrayBuffer;
  results.push(
    await benchmark('Ed25519 sign sync', () => {
      FastCrypto.signSync(signMsg, privateKey);
    })
  );

  // Random bytes
  results.push(
    await benchmark('generateRandomBytesSync(32)', () => {
      FastCrypto.generateRandomBytesSync(32);
    })
  );

  return results;
}
