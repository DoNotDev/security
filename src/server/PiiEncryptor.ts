// packages/security/src/server/PiiEncryptor.ts

/**
 * @fileoverview PiiEncryptor
 * @description AES-256-GCM field-level encryption for PII at rest.
 * Uses Node.js native crypto — zero extra deps.
 * Covers SOC2 C1 (Confidentiality) and CC6.1 (encryption at rest).
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LEN = 32; // 256-bit
const IV_LEN = 12; // 96-bit — NIST SP 800-38D mandated length for AES-GCM
const GCM_TAG_LEN = 16; // GCM auth tag is always 16 bytes

/**
 * Prefix added to every encrypted value produced by this class.
 * Format: `dnpii1:<ivHex>:<authTagHex>:<ciphertextHex>`
 *
 * The version prefix (v1) makes encrypted values unambiguous — no false positives
 * on URLs, timestamps, or other hex strings. It also enables key-rotation strategies
 * by bumping the version (v2, v3 …) without breaking existing data.
 */
const CIPHER_PREFIX = 'dnpii1:';

/**
 * AES-256-GCM PII encryptor with per-field IV (SOC2 C1, CC6.1).
 *
 * **IMPORTANT:** Instantiate ONCE at app startup (e.g. inside `DndevSecurity`).
 * The constructor calls `scryptSync` which is CPU-intensive by design — repeated
 * construction per-request is a DoS vector.
 *
 * Each field gets a fresh random IV — identical plaintext produces different ciphertext.
 * Output format: `dnpii1:<ivHex>:<authTagHex>:<ciphertextHex>`
 *
 * @example
 * ```typescript
 * // Salt MUST be a per-deployment secret stored alongside piiSecret in your secret manager.
 * // NEVER use a hard-coded or framework-level salt.
 * const enc = new PiiEncryptor(process.env.PII_SECRET!, process.env.PII_SALT!);
 * const stored = enc.encryptFields({ email: 'alice@example.com', name: 'Alice' }, ['email']);
 * // stored.email → 'dnpii1:a1b2...:c3d4...:e5f6...' (encrypted)
 * // stored.name  → 'Alice' (unchanged)
 *
 * const plain = enc.decryptFields(stored, ['email']);
 * // plain.email → 'alice@example.com'
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class PiiEncryptor {
  private readonly key: Buffer;

  /**
   * @param secret - Master secret (min 32 chars). Store in secret manager, never in code.
   * @param salt   - Per-deployment salt. Must be unique per deployment and stored as a secret.
   *                 Do NOT use a shared or hard-coded value — a universal salt eliminates
   *                 rainbow-table resistance for the derived key.
   */
  constructor(secret: string, salt: string) {
    if (!secret || secret.length < 32) {
      throw new Error(
        '[dndev/security] PiiEncryptor: secret must be at least 32 characters'
      );
    }
    // Entropy check: require at least 4 distinct characters to prevent low-entropy secrets
    const uniqueChars = new Set(secret).size;
    if (uniqueChars < 4) {
      throw new Error(
        '[dndev/security] PiiEncryptor: secret has insufficient entropy — use a randomly generated value'
      );
    }
    if (!salt || salt.length < 8) {
      throw new Error(
        '[dndev/security] PiiEncryptor: salt is required and must be at least 8 characters. ' +
          'Use a per-deployment secret stored in your secret manager — never a hard-coded value.'
      );
    }
    // OWASP 2024+ recommendation: N≥65536 (2^16), r=8, p=1 for scrypt key derivation.
    // Higher N values increase memory and CPU cost, hardening against offline brute-force.
    const N = 65536;
    const r = 8;
    this.key = scryptSync(secret, salt, KEY_LEN, {
      N,
      r,
      p: 1,
      maxmem: 128 * N * r + 1024 * 1024, // scrypt needs 128*N*r (64MB) + 1MB headroom
    });
  }

  /**
   * Encrypt a single string value.
   * @returns `dnpii1:<iv>:<tag>:<ciphertext>` (all hex, prefixed for unambiguous detection)
   */
  encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return `${CIPHER_PREFIX}${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * Decrypt a value produced by `encrypt()`.
   * Supports the legacy format (no `dnpii1:` prefix) for backward compatibility.
   * @throws if ciphertext is malformed or authentication tag is invalid.
   */
  decrypt(ciphertext: string): string {
    const body = ciphertext.startsWith(CIPHER_PREFIX)
      ? ciphertext.slice(CIPHER_PREFIX.length)
      : ciphertext; // Legacy: values encrypted before v0.0.2

    const parts = body.split(':');
    if (parts.length !== 3) {
      throw new Error(
        '[dndev/security] PiiEncryptor: invalid ciphertext format'
      );
    }
    const [ivHex, tagHex, encHex] = parts as [string, string, string];
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const encrypted = Buffer.from(encHex, 'hex');

    if (iv.length !== IV_LEN) {
      throw new Error(
        `[dndev/security] PiiEncryptor: invalid IV length ${iv.length}, expected ${IV_LEN}`
      );
    }
    if (tag.length !== GCM_TAG_LEN) {
      throw new Error(
        `[dndev/security] PiiEncryptor: invalid auth tag length ${tag.length}, expected ${GCM_TAG_LEN}`
      );
    }

    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted).toString('utf8') + decipher.final('utf8');
  }

  /**
   * Encrypt specified fields in a data object (returns new object, input unchanged).
   * Missing fields are skipped. Non-string field values emit a warning and are skipped.
   */
  encryptFields<T extends Record<string, unknown>>(
    data: T,
    piiFields: string[]
  ): T {
    if (piiFields.length === 0) return data;
    const result = { ...data };
    for (const field of piiFields) {
      const val = result[field as keyof T];
      if (typeof val === 'string') {
        (result as Record<string, unknown>)[field] = this.encrypt(val);
      } else if (val !== undefined && val !== null) {
        if (process.env.NODE_ENV !== 'test') {
          process.stderr.write(
            JSON.stringify({
              level: 'warn',
              service: 'dndev-pii',
              type: 'pii.field.not_string',
              field,
              actualType: typeof val,
              timestamp: new Date().toISOString(),
            }) + '\n'
          );
        }
      }
    }
    return result;
  }

  /**
   * Detect whether a string was produced by `encrypt()`.
   * Requires the `dnpii1:` version prefix — unambiguous, no false positives on
   * URLs with ports, timestamps, or other hex-like strings.
   */
  private isEncrypted(val: string): boolean {
    return val.startsWith(CIPHER_PREFIX);
  }

  /** Zero the derived key buffer. Call when the encryptor is no longer needed. */
  dispose(): void {
    this.key.fill(0);
  }

  /** TC39 explicit resource management support. */
  [Symbol.dispose](): void {
    this.dispose();
  }

  /**
   * Decrypt specified fields in a data object (returns new object, input unchanged).
   * Fields that do not pass the encrypted-format check are left as-is.
   * Auth tag failures (wrong key / tampered data) are re-thrown — they must not be silenced.
   */
  decryptFields<T extends Record<string, unknown>>(
    data: T,
    piiFields: string[]
  ): T {
    if (piiFields.length === 0) return data;
    const result = { ...data };
    for (const field of piiFields) {
      const val = result[field as keyof T];
      if (typeof val === 'string' && this.isEncrypted(val)) {
        // Throws on auth tag failure — callers must handle or let it propagate
        (result as Record<string, unknown>)[field] = this.decrypt(val);
      }
    }
    return result;
  }
}
