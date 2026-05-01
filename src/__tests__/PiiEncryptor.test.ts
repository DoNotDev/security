import { describe, it, expect } from 'vitest';

import { PiiEncryptor } from '../server/PiiEncryptor';

// Valid secret (32+ chars, sufficient entropy) and salt (8+ chars)
const TEST_SECRET = 'abcdefghijklmnopqrstuvwxyz123456';
const TEST_SALT = 'test-salt-value';

function createEncryptor(): PiiEncryptor {
  return new PiiEncryptor(TEST_SECRET, TEST_SALT);
}

describe('PiiEncryptor', () => {
  describe('constructor validation', () => {
    it('throws if secret is shorter than 32 characters', () => {
      expect(() => new PiiEncryptor('short', TEST_SALT)).toThrow(
        'secret must be at least 32 characters'
      );
    });

    it('throws if secret is empty', () => {
      expect(() => new PiiEncryptor('', TEST_SALT)).toThrow(
        'secret must be at least 32 characters'
      );
    });

    it('throws if secret has insufficient entropy (fewer than 4 distinct chars)', () => {
      const lowEntropy = 'a'.repeat(32);
      expect(() => new PiiEncryptor(lowEntropy, TEST_SALT)).toThrow(
        'insufficient entropy'
      );
    });

    it('throws if secret has exactly 3 distinct chars', () => {
      // 32 chars using only a, b, c
      const threeChars = 'abcabcabcabcabcabcabcabcabcabcab';
      expect(() => new PiiEncryptor(threeChars, TEST_SALT)).toThrow(
        'insufficient entropy'
      );
    });

    it('accepts secret with exactly 4 distinct chars', () => {
      const fourChars = 'abcdabcdabcdabcdabcdabcdabcdabcd';
      expect(() => new PiiEncryptor(fourChars, TEST_SALT)).not.toThrow();
    });

    it('throws if salt is empty', () => {
      expect(() => new PiiEncryptor(TEST_SECRET, '')).toThrow(
        'salt is required'
      );
    });

    it('throws if salt is shorter than 8 characters', () => {
      expect(() => new PiiEncryptor(TEST_SECRET, 'short')).toThrow(
        'salt is required and must be at least 8 characters'
      );
    });
  });

  describe('encrypt / decrypt roundtrip', () => {
    it('roundtrips a simple ASCII string', () => {
      const enc = createEncryptor();
      const plaintext = 'alice@example.com';
      const encrypted = enc.encrypt(plaintext);
      expect(enc.decrypt(encrypted)).toBe(plaintext);
    });

    it('roundtrips unicode characters', () => {
      const enc = createEncryptor();
      const plaintext = 'Héllo Wörld! 日本語';
      expect(enc.decrypt(enc.encrypt(plaintext))).toBe(plaintext);
    });

    it('roundtrips empty string', () => {
      const enc = createEncryptor();
      expect(enc.decrypt(enc.encrypt(''))).toBe('');
    });

    it('roundtrips special characters', () => {
      const enc = createEncryptor();
      const plaintext = '<script>alert("xss")</script>&foo=bar';
      expect(enc.decrypt(enc.encrypt(plaintext))).toBe(plaintext);
    });

    it('roundtrips long strings', () => {
      const enc = createEncryptor();
      const plaintext = 'x'.repeat(10_000);
      expect(enc.decrypt(enc.encrypt(plaintext))).toBe(plaintext);
    });
  });

  describe('encryption format', () => {
    it('encrypted values have dnpii1: prefix', () => {
      const enc = createEncryptor();
      const encrypted = enc.encrypt('test');
      expect(encrypted.startsWith('dnpii1:')).toBe(true);
    });

    it('encrypted value has 4 colon-separated parts (prefix:iv:tag:ciphertext)', () => {
      const enc = createEncryptor();
      const encrypted = enc.encrypt('test');
      // dnpii1:iv:tag:ciphertext -> split by : gives 4 parts
      const parts = encrypted.split(':');
      expect(parts.length).toBe(4);
      expect(parts[0]).toBe('dnpii1');
    });

    it('IV is 24 hex chars (12 bytes)', () => {
      const enc = createEncryptor();
      const encrypted = enc.encrypt('test');
      const ivHex = encrypted.split(':')[1]!;
      expect(ivHex.length).toBe(24);
      expect(/^[0-9a-f]+$/.test(ivHex)).toBe(true);
    });

    it('auth tag is 32 hex chars (16 bytes)', () => {
      const enc = createEncryptor();
      const encrypted = enc.encrypt('test');
      const tagHex = encrypted.split(':')[2]!;
      expect(tagHex.length).toBe(32);
      expect(/^[0-9a-f]+$/.test(tagHex)).toBe(true);
    });
  });

  describe('randomness (unique IV per encryption)', () => {
    it('same plaintext produces different ciphertexts', () => {
      const enc = createEncryptor();
      const a = enc.encrypt('same-value');
      const b = enc.encrypt('same-value');
      expect(a).not.toBe(b);
    });

    it('different plaintexts produce different ciphertexts', () => {
      const enc = createEncryptor();
      const a = enc.encrypt('value-a');
      const b = enc.encrypt('value-b');
      expect(a).not.toBe(b);
    });
  });

  describe('decrypt validation', () => {
    it('throws on malformed ciphertext (wrong number of parts)', () => {
      const enc = createEncryptor();
      expect(() => enc.decrypt('dnpii1:only-two')).toThrow(
        'invalid ciphertext format'
      );
    });

    it('throws on invalid IV length', () => {
      const enc = createEncryptor();
      // IV should be 24 hex chars (12 bytes), use 6 hex chars (3 bytes) instead
      expect(() =>
        enc.decrypt('dnpii1:aabbcc:' + 'aa'.repeat(16) + ':' + 'bb'.repeat(4))
      ).toThrow('invalid IV length');
    });

    it('throws on invalid auth tag length', () => {
      const enc = createEncryptor();
      // Valid IV (24 hex), invalid tag (4 hex chars instead of 32)
      expect(() =>
        enc.decrypt('dnpii1:' + 'aa'.repeat(12) + ':aabb:' + 'cc'.repeat(4))
      ).toThrow('invalid auth tag length');
    });
  });

  describe('encryptFields / decryptFields', () => {
    it('encrypts only specified fields', () => {
      const enc = createEncryptor();
      const data = { email: 'alice@example.com', name: 'Alice', age: 30 };
      const encrypted = enc.encryptFields(data, ['email']);
      expect(encrypted['email']).not.toBe('alice@example.com');
      expect((encrypted['email'] as string).startsWith('dnpii1:')).toBe(true);
      expect(encrypted['name']).toBe('Alice');
      expect(encrypted['age']).toBe(30);
    });

    it('decrypts only specified encrypted fields', () => {
      const enc = createEncryptor();
      const data = { email: 'alice@example.com', name: 'Alice' };
      const encrypted = enc.encryptFields(data, ['email']);
      const decrypted = enc.decryptFields(encrypted, ['email']);
      expect(decrypted['email']).toBe('alice@example.com');
      expect(decrypted['name']).toBe('Alice');
    });

    it('skips missing fields without error', () => {
      const enc = createEncryptor();
      const data = { name: 'Alice' };
      const result = enc.encryptFields(data, ['email', 'phone']);
      expect(result).toEqual({ name: 'Alice' });
    });

    it('returns data unchanged when piiFields is empty', () => {
      const enc = createEncryptor();
      const data = { email: 'test@test.com' };
      expect(enc.encryptFields(data, [])).toBe(data);
      expect(enc.decryptFields(data, [])).toBe(data);
    });

    it('skips non-string field values', () => {
      const enc = createEncryptor();
      const data = { count: 42, active: true };
      const result = enc.encryptFields(data, ['count', 'active']);
      expect(result['count']).toBe(42);
      expect(result['active']).toBe(true);
    });

    it('does not mutate the original object', () => {
      const enc = createEncryptor();
      const data = { email: 'alice@example.com' };
      const encrypted = enc.encryptFields(data, ['email']);
      expect(data['email']).toBe('alice@example.com');
      expect(encrypted['email']).not.toBe('alice@example.com');
    });

    it('decryptFields leaves non-encrypted strings as-is', () => {
      const enc = createEncryptor();
      const data = { email: 'plain-text-email' };
      const result = enc.decryptFields(data, ['email']);
      expect(result['email']).toBe('plain-text-email');
    });
  });

  describe('dispose', () => {
    it('zeros the key buffer so decrypt no longer roundtrips', () => {
      const enc = createEncryptor();
      const encrypted = enc.encrypt('test');
      enc.dispose();
      // After dispose, the key is zeroed. Decryption should either throw
      // (auth tag mismatch) or produce garbled output - never the original plaintext.
      let decrypted: string | undefined;
      try {
        decrypted = enc.decrypt(encrypted);
      } catch {
        // Expected: GCM auth tag verification fails with zeroed key
      }
      if (decrypted !== undefined) {
        expect(decrypted).not.toBe('test');
      }
    });
  });
});
