// packages/security/src/server/SecretValidator.ts

/**
 * @fileoverview SecretValidator
 * @description Log scrubbing and secret exposure prevention.
 * Covers SOC2 CC6 (access controls): secrets must never appear in logs or error messages.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

/** Patterns that indicate a secret value is present in a string */
const SECRET_STRING_PATTERNS: RegExp[] = [
  /password\s*[:=]\s*\S+/gi,
  /secret\s*[:=]\s*\S+/gi,
  /api[_-]?key\s*[:=]\s*\S+/gi,
  /token\s*[:=]\s*\S+/gi,
  /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /-----BEGIN .+?-----/g,
  /sk_live_[A-Za-z0-9]+/g,
  /sk_test_[A-Za-z0-9]+/g,
  /ghp_[A-Za-z0-9]{36,}/g,
  /gho_[A-Za-z0-9]{36,}/g,
  /AKIA[A-Z0-9]{16}/g,
  /xox[bpsa]-[A-Za-z0-9\-]+/g,
  /glpat-[A-Za-z0-9\-_]{20,}/g,
  // Firebase service account private key
  /-----BEGIN RSA PRIVATE KEY-----/g,
  // GCP API keys (AIza...)
  /AIza[A-Za-z0-9\-_]{35}/g,
  // Supabase service role / anon keys (eyJ...)
  /eyJ[A-Za-z0-9\-_]{100,}/g,
  // Firebase web API key
  /AIza[A-Za-z0-9]{33}/g,
  // Supabase project reference password patterns
  /sbp_[A-Za-z0-9]{40,}/g,
  // Azure storage account keys (86 base64 chars + ==)
  /[a-zA-Z0-9+/]{86}==/g,
  // SendGrid API keys
  /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
  // Twilio API keys
  /SK[0-9a-fA-F]{32}/g,
  // npm tokens
  /npm_[a-zA-Z0-9]{36}/g,
  // Mailgun API keys
  /key-[a-zA-Z0-9]{32}/g,
];

/**
 * Object key names that likely contain secrets.
 * `auth` uses a word boundary (`\bauth\b`) to avoid false positives on
 * `author`, `authorId`, `authorName`, etc.
 * Tokens under `authToken` / `authKey` are caught by the `token` / `secret` alternatives.
 */
const SECRET_KEY_PATTERN =
  /password|passwd|secret|token|apikey|api_key|apiToken|authToken|authKey|credential|private_key|privateKey|access_key|accessKey|\bauth\b/i;

/**
 * Recursively scrub secret values from a log payload.
 * Replaces matching string values with `[REDACTED]`.
 * Safe to use as a Pino serializer or before any `console.log` call.
 *
 * @example
 * ```typescript
 * const payload = { user: 'alice', password: 'hunter2', meta: { apiKey: 'sk_live_abc' } };
 * console.log(JSON.stringify(scrubSecrets(payload)));
 * // → {"user":"alice","password":"[REDACTED]","meta":{"apiKey":"[REDACTED]"}}
 * ```
 */
export function scrubSecrets(value: unknown): unknown {
  if (typeof value === 'string') {
    let result = value;
    for (const pattern of SECRET_STRING_PATTERNS) {
      result = result.replace(pattern, '[REDACTED]');
    }
    return result;
  }

  if (Array.isArray(value)) {
    return value.map(scrubSecrets);
  }

  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    // Trade-off: aggressive key-name matching may redact non-secret fields (e.g. "tokenCount",
    // "passwordPolicy"). This is intentional — false positives are safer than leaked secrets.
    // If a field is incorrectly redacted, rename the key to avoid matching SECRET_KEY_PATTERN.
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      result[key] = SECRET_KEY_PATTERN.test(key)
        ? '[REDACTED]'
        : scrubSecrets(val);
    }
    return result;
  }

  return value;
}

/**
 * Assert that an object does NOT contain any detectable secrets.
 * Throws before the value would reach a log sink.
 *
 * @example
 * ```typescript
 * assertNoSecrets(responsePayload, 'API response');
 * ```
 *
 * @throws {Error} if secrets are detected or if the value is non-serializable
 */
export function assertNoSecrets(obj: unknown, context: string): void {
  let scrubbed: string;
  let original: string;
  try {
    original = JSON.stringify(obj);
    scrubbed = JSON.stringify(scrubSecrets(obj));
  } catch {
    // Circular reference, BigInt, or other non-serializable value — treat as potentially
    // unsafe since we cannot inspect it. Callers must audit the object manually.
    throw new Error(
      `[dndev/security] assertNoSecrets: cannot serialize value in "${context}". ` +
        'Non-serializable values cannot be verified for secrets. Audit the object manually.'
    );
  }
  if (scrubbed !== original) {
    throw new Error(
      `[dndev/security] Secret detected in ${context}. Aborting to prevent credential leak.`
    );
  }
}
