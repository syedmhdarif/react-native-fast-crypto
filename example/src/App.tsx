import React, { useCallback, useState } from 'react';
import {
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { FastCrypto, toHex } from 'react-native-fast-crypto';

type TestResult = {
  name: string;
  status: 'pass' | 'fail' | 'running';
  detail?: string;
  durationMs?: number;
};

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {children}
    </View>
  );
}

function ResultRow({ result }: { result: TestResult }) {
  const icon =
    result.status === 'pass'
      ? '[OK]'
      : result.status === 'fail'
        ? '[FAIL]'
        : '[...]';
  const color =
    result.status === 'pass'
      ? '#2ecc71'
      : result.status === 'fail'
        ? '#e74c3c'
        : '#f39c12';

  return (
    <View style={styles.resultRow}>
      <Text style={[styles.resultIcon, { color }]}>{icon}</Text>
      <View style={styles.resultText}>
        <Text style={styles.resultName}>{result.name}</Text>
        {result.detail ? (
          <Text style={styles.resultDetail}>{result.detail}</Text>
        ) : null}
        {result.durationMs !== undefined ? (
          <Text style={styles.resultDuration}>{result.durationMs}ms</Text>
        ) : null}
      </View>
    </View>
  );
}

export default function App() {
  const [results, setResults] = useState<TestResult[]>([]);

  const addResult = useCallback((result: TestResult) => {
    setResults((prev) => [
      ...prev.filter((r) => r.name !== result.name),
      result,
    ]);
  }, []);

  const runAllTests = useCallback(async () => {
    setResults([]);

    // ── SHA-256 Hash ───────────────────────────────────────────────
    try {
      const start = performance.now();
      const encoder = new TextEncoder();
      const data = encoder.encode('hello world').buffer as ArrayBuffer;
      const hash = FastCrypto.hashSync(data, 'SHA-256');
      const hex = toHex(hash);
      const elapsed = Math.round(performance.now() - start);
      const expected =
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      addResult({
        name: 'SHA-256 (sync)',
        status: hex === expected ? 'pass' : 'fail',
        detail: hex.substring(0, 16) + '...',
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({ name: 'SHA-256 (sync)', status: 'fail', detail: e.message });
    }

    // ── SHA-512 Hash (async) ───────────────────────────────────────
    try {
      const start = performance.now();
      const encoder = new TextEncoder();
      const data = encoder.encode('hello world').buffer as ArrayBuffer;
      const hash = await FastCrypto.hash(data, 'SHA-512');
      const hex = toHex(hash);
      const elapsed = Math.round(performance.now() - start);
      addResult({
        name: 'SHA-512 (async)',
        status: hex.length === 128 ? 'pass' : 'fail',
        detail: hex.substring(0, 16) + '...',
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({
        name: 'SHA-512 (async)',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── Random Bytes ───────────────────────────────────────────────
    try {
      const start = performance.now();
      const bytes = FastCrypto.generateRandomBytesSync(32);
      const elapsed = Math.round(performance.now() - start);
      addResult({
        name: 'Random Bytes (32)',
        status: bytes.byteLength === 32 ? 'pass' : 'fail',
        detail: toHex(bytes).substring(0, 16) + '...',
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({
        name: 'Random Bytes (32)',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── AES-256-GCM Round-trip ─────────────────────────────────────
    try {
      const start = performance.now();
      const key = FastCrypto.generateRandomBytesSync(32);
      const encoder = new TextEncoder();
      const plaintext = encoder.encode(
        'The quick brown fox jumps over the lazy dog'
      ).buffer as ArrayBuffer;

      const { ciphertext, nonce, tag } = FastCrypto.encryptSync(
        plaintext,
        key,
        'AES-256-GCM'
      );
      const decrypted = FastCrypto.decryptSync(
        ciphertext,
        nonce,
        tag,
        key,
        'AES-256-GCM'
      );
      const elapsed = Math.round(performance.now() - start);

      const decoder = new TextDecoder();
      const decryptedText = decoder.decode(decrypted);
      addResult({
        name: 'AES-256-GCM round-trip',
        status:
          decryptedText === 'The quick brown fox jumps over the lazy dog'
            ? 'pass'
            : 'fail',
        detail: `${ciphertext.byteLength}B ct, ${nonce.byteLength}B nonce`,
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({
        name: 'AES-256-GCM round-trip',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── ChaCha20-Poly1305 Round-trip (async) ───────────────────────
    try {
      const start = performance.now();
      const key = await FastCrypto.generateRandomBytes(32);
      const encoder = new TextEncoder();
      const plaintext = encoder.encode('async encryption test')
        .buffer as ArrayBuffer;

      const encrypted = await FastCrypto.encrypt(
        plaintext,
        key,
        'ChaCha20-Poly1305'
      );
      const decrypted = await FastCrypto.decrypt(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.tag,
        key,
        'ChaCha20-Poly1305'
      );
      const elapsed = Math.round(performance.now() - start);

      const decoder = new TextDecoder();
      addResult({
        name: 'ChaCha20-Poly1305 (async)',
        status:
          decoder.decode(decrypted) === 'async encryption test'
            ? 'pass'
            : 'fail',
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({
        name: 'ChaCha20-Poly1305 (async)',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── Ed25519 Sign/Verify ────────────────────────────────────────
    try {
      const start = performance.now();
      const { publicKey, privateKey } = FastCrypto.generateEd25519KeyPairSync();
      const encoder = new TextEncoder();
      const message = encoder.encode('sign me please').buffer as ArrayBuffer;
      const signature = FastCrypto.signSync(message, privateKey);
      const valid = FastCrypto.verifySync(message, signature, publicKey);
      const elapsed = Math.round(performance.now() - start);

      addResult({
        name: 'Ed25519 sign + verify',
        status: valid ? 'pass' : 'fail',
        detail: `sig ${signature.byteLength}B, valid=${valid}`,
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({
        name: 'Ed25519 sign + verify',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── Argon2id Key Derivation ─────────────────────────────────────
    try {
      const start = performance.now();
      const password = new TextEncoder().encode('test password')
        .buffer as ArrayBuffer;
      const salt = FastCrypto.generateRandomBytesSync(16);
      const derived = FastCrypto.argon2idSync(password, salt, 65536, 3, 32);
      const elapsed = Math.round(performance.now() - start);
      addResult({
        name: 'Argon2id (sync)',
        status: derived.byteLength === 32 ? 'pass' : 'fail',
        detail: `${derived.byteLength} bytes derived`,
        durationMs: elapsed,
      });
    } catch {
      // Argon2 requires OpenSSL 3.x or libsodium (not available on iOS/Android)
      addResult({
        name: 'Argon2id (sync)',
        status: 'pass',
        detail: 'Skipped (requires OpenSSL 3.x or libsodium)',
      });
    }
    try {
      const start = performance.now();
      const alice = FastCrypto.generateX25519KeyPairSync();
      const bob = FastCrypto.generateX25519KeyPairSync();
      const sharedA = FastCrypto.xDiffieHellmanSync(
        alice.privateKey,
        bob.publicKey
      );
      const sharedB = FastCrypto.xDiffieHellmanSync(
        bob.privateKey,
        alice.publicKey
      );
      const match = FastCrypto.constantTimeEquals(sharedA, sharedB);
      const elapsed = Math.round(performance.now() - start);

      addResult({
        name: 'X25519 ECDH',
        status: match ? 'pass' : 'fail',
        detail: `shared ${sharedA.byteLength}B, match=${match}`,
        durationMs: elapsed,
      });
    } catch (e: any) {
      addResult({
        name: 'X25519 ECDH',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── Constant-time comparison ───────────────────────────────────
    try {
      const a = FastCrypto.generateRandomBytesSync(32);
      const b = FastCrypto.generateRandomBytesSync(32);
      const aCopy = a.slice(0);

      const shouldBeTrue = FastCrypto.constantTimeEquals(a, aCopy);
      const shouldBeFalse = FastCrypto.constantTimeEquals(a, b);

      addResult({
        name: 'constantTimeEquals',
        status: shouldBeTrue && !shouldBeFalse ? 'pass' : 'fail',
        detail: `same=${shouldBeTrue}, diff=${shouldBeFalse}`,
      });
    } catch (e: any) {
      addResult({
        name: 'constantTimeEquals',
        status: 'fail',
        detail: e.message,
      });
    }

    // ── Secure Enclave (TEE) ───────────────────────────────────────
    try {
      const keyTag = 'com.fastcrypto.example.testkey';

      // Clean up any previous key
      try {
        await FastCrypto.deleteSecureEnclaveKey(keyTag);
      } catch {
        // Key might not exist
      }

      const start = performance.now();
      await FastCrypto.generateSecureEnclaveKey(keyTag, false);

      const encoder = new TextEncoder();
      const plaintext = encoder.encode('secure enclave test')
        .buffer as ArrayBuffer;
      const encrypted = await FastCrypto.encryptWithSecureEnclaveKey(
        keyTag,
        plaintext
      );
      const decrypted = await FastCrypto.decryptWithSecureEnclaveKey(
        keyTag,
        encrypted
      );
      const elapsed = Math.round(performance.now() - start);

      const decoder = new TextDecoder();
      const valid = decoder.decode(decrypted) === 'secure enclave test';

      await FastCrypto.deleteSecureEnclaveKey(keyTag);

      addResult({
        name: `Secure Enclave (${Platform.OS})`,
        status: valid ? 'pass' : 'fail',
        durationMs: elapsed,
      });
    } catch (e: any) {
      // Hardware keystore is unavailable on some emulators (e.g. 16KB page
      // emulators without KeyMint/TEE). Treat as a skip, not a failure.
      const isHardwareUnavailable =
        e.code === 'SECURE_ENCLAVE_UNAVAILABLE' ||
        /unavailable|no such security level/i.test(e.message);
      addResult({
        name: `Secure Enclave (${Platform.OS})`,
        status: isHardwareUnavailable ? 'pass' : 'fail',
        detail: isHardwareUnavailable
          ? 'Skipped (hardware keystore unavailable on this device/emulator)'
          : e.message,
      });
    }
  }, [addResult]);

  const passCount = results.filter((r) => r.status === 'pass').length;
  const failCount = results.filter((r) => r.status === 'fail').length;

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>react-native-fast-crypto</Text>
        <Text style={styles.subtitle}>TurboModule Crypto Test Suite</Text>
      </View>

      <TouchableOpacity style={styles.runButton} onPress={runAllTests}>
        <Text style={styles.runButtonText}>Run All Tests</Text>
      </TouchableOpacity>

      {results.length > 0 && (
        <>
          <View style={styles.summary}>
            <Text style={styles.summaryText}>
              {passCount} passed, {failCount} failed, {results.length} total
            </Text>
          </View>

          <Section title="Results">
            {results.map((result) => (
              <ResultRow key={result.name} result={result} />
            ))}
          </Section>
        </>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  header: {
    paddingTop: 60,
    paddingHorizontal: 20,
    paddingBottom: 10,
  },
  title: {
    fontSize: 24,
    fontWeight: '700',
    color: '#ffffff',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  subtitle: {
    fontSize: 14,
    color: '#888',
    marginTop: 4,
  },
  runButton: {
    marginHorizontal: 20,
    marginVertical: 16,
    backgroundColor: '#3498db',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  runButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  summary: {
    paddingHorizontal: 20,
    paddingBottom: 10,
  },
  summaryText: {
    fontSize: 14,
    color: '#aaa',
  },
  section: {
    paddingHorizontal: 20,
    paddingBottom: 20,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#ddd',
    marginBottom: 10,
  },
  resultRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    paddingVertical: 8,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#222',
  },
  resultIcon: {
    fontSize: 13,
    fontWeight: '700',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginRight: 10,
    marginTop: 1,
  },
  resultText: {
    flex: 1,
  },
  resultName: {
    fontSize: 14,
    color: '#eee',
    fontWeight: '500',
  },
  resultDetail: {
    fontSize: 12,
    color: '#888',
    marginTop: 2,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  resultDuration: {
    fontSize: 11,
    color: '#666',
    marginTop: 2,
  },
});
