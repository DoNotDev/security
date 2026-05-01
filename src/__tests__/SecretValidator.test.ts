import { describe, it, expect } from 'vitest';

import { scrubSecrets, assertNoSecrets } from '../server/SecretValidator';

describe('scrubSecrets', () => {
  describe('key-name scrubbing', () => {
    it('redacts values under secret key names', () => {
      const input = {
        password: 'hunter2',
        apiKey: 'my-key-123',
        api_key: 'another-key',
        secret: 's3cret',
        token: 'tok-abc',
        credential: 'cred-xyz',
        privateKey: 'pk-value',
        private_key: 'pk-value2',
        accessKey: 'ak-value',
        access_key: 'ak-value2',
        authToken: 'at-value',
        authKey: 'ak3-value',
      };
      const result = scrubSecrets(input) as Record<string, unknown>;
      for (const key of Object.keys(input)) {
        expect(result[key]).toBe('[REDACTED]');
      }
    });

    it('redacts "auth" as a standalone key (word boundary)', () => {
      const result = scrubSecrets({ auth: 'bearer-token' }) as Record<
        string,
        unknown
      >;
      expect(result['auth']).toBe('[REDACTED]');
    });

    it('does NOT redact "author" or "authorId" (word boundary on auth)', () => {
      const input = { author: 'Alice', authorId: '123', authorName: 'Bob' };
      const result = scrubSecrets(input) as Record<string, unknown>;
      expect(result['author']).toBe('Alice');
      expect(result['authorId']).toBe('123');
      expect(result['authorName']).toBe('Bob');
    });

    it('redacts "passwd" key', () => {
      const result = scrubSecrets({ passwd: 'abc' }) as Record<string, unknown>;
      expect(result['passwd']).toBe('[REDACTED]');
    });
  });

  describe('string pattern scrubbing', () => {
    it('scrubs AWS access key IDs (AKIA...)', () => {
      // Build key at runtime so public-repo sync secret scan never sees a contiguous AKIA… literal in source.
      const fakeKey = 'AKIA' + 'IOSFODNN7EXAMPLE';
      const input = `my key is ${fakeKey}`;
      expect(scrubSecrets(input)).toBe('my key is [REDACTED]');
    });

    it('scrubs Stripe live keys', () => {
      expect(scrubSecrets('key: sk_live_abc123DEF456')).toBe('key: [REDACTED]');
    });

    it('scrubs Stripe test keys', () => {
      expect(scrubSecrets('sk_test_XYZ789abc')).toBe('[REDACTED]');
    });

    it('scrubs GitHub personal access tokens (ghp_)', () => {
      const token = 'ghp_' + 'a'.repeat(36);
      expect(scrubSecrets(`token=${token}`)).toContain('[REDACTED]');
    });

    it('scrubs GitHub OAuth tokens (gho_)', () => {
      const token = 'gho_' + 'B'.repeat(36);
      expect(scrubSecrets(token)).toBe('[REDACTED]');
    });

    it('scrubs GitLab tokens (glpat-)', () => {
      const token = 'glpat-' + 'x'.repeat(20);
      expect(scrubSecrets(token)).toBe('[REDACTED]');
    });

    it('scrubs Slack tokens (xoxb-, xoxp-, xoxs-, xoxa-)', () => {
      expect(scrubSecrets('xoxb-abc-def')).toBe('[REDACTED]');
      expect(scrubSecrets('xoxp-123-456')).toBe('[REDACTED]');
    });

    it('scrubs Bearer tokens', () => {
      expect(scrubSecrets('bearer eyJhbGciOiJ')).toBe('[REDACTED]');
    });

    it('scrubs PEM headers', () => {
      expect(scrubSecrets('-----BEGIN RSA PRIVATE KEY-----')).toBe(
        '[REDACTED]'
      );
    });

    it('scrubs GCP API keys (AIza...)', () => {
      const key = 'AIza' + 'X'.repeat(35);
      expect(scrubSecrets(key)).toBe('[REDACTED]');
    });

    it('scrubs Supabase long JWT tokens (eyJ...)', () => {
      const jwt = 'eyJ' + 'a'.repeat(100);
      expect(scrubSecrets(jwt)).toBe('[REDACTED]');
    });

    it('scrubs Supabase project passwords (sbp_)', () => {
      const token = 'sbp_' + 'z'.repeat(40);
      expect(scrubSecrets(token)).toBe('[REDACTED]');
    });

    it('scrubs inline password=value patterns', () => {
      expect(scrubSecrets('password=hunter2')).toBe('[REDACTED]');
      expect(scrubSecrets('password: secret123')).toBe('[REDACTED]');
    });

    it('scrubs inline api_key=value patterns', () => {
      expect(scrubSecrets('api_key=abc123')).toBe('[REDACTED]');
    });

    it('scrubs inline token=value patterns', () => {
      expect(scrubSecrets('token=mytoken')).toBe('[REDACTED]');
    });
  });

  describe('recursive scrubbing', () => {
    it('scrubs nested objects', () => {
      const input = {
        user: 'alice',
        meta: { apiKey: 'sk_live_abc', nested: { password: 'pw' } },
      };
      const result = scrubSecrets(input) as Record<string, unknown>;
      expect(result['user']).toBe('alice');
      const meta = result['meta'] as Record<string, unknown>;
      expect(meta['apiKey']).toBe('[REDACTED]');
      const nested = meta['nested'] as Record<string, unknown>;
      expect(nested['password']).toBe('[REDACTED]');
    });

    it('scrubs arrays of objects', () => {
      const input = [{ password: 'a' }, { token: 'b' }];
      const result = scrubSecrets(input) as Record<string, unknown>[];
      expect(result[0]!['password']).toBe('[REDACTED]');
      expect(result[1]!['token']).toBe('[REDACTED]');
    });

    it('scrubs strings inside arrays', () => {
      const input = ['safe', 'sk_live_abc123'];
      const result = scrubSecrets(input) as string[];
      expect(result[0]).toBe('safe');
      expect(result[1]).toBe('[REDACTED]');
    });
  });

  describe('passthrough of non-secret values', () => {
    it('returns null as-is', () => {
      expect(scrubSecrets(null)).toBeNull();
    });

    it('returns undefined as-is', () => {
      expect(scrubSecrets(undefined)).toBeUndefined();
    });

    it('returns numbers as-is', () => {
      expect(scrubSecrets(42)).toBe(42);
    });

    it('returns booleans as-is', () => {
      expect(scrubSecrets(true)).toBe(true);
    });

    it('returns clean strings as-is', () => {
      expect(scrubSecrets('hello world')).toBe('hello world');
    });

    it('returns empty object as empty object', () => {
      expect(scrubSecrets({})).toEqual({});
    });

    it('returns empty array as empty array', () => {
      expect(scrubSecrets([])).toEqual([]);
    });
  });
});

describe('assertNoSecrets', () => {
  it('passes on clean data', () => {
    expect(() =>
      assertNoSecrets({ user: 'alice', count: 5 }, 'test')
    ).not.toThrow();
  });

  it('throws when secret key names are present', () => {
    expect(() =>
      assertNoSecrets({ password: 'hunter2' }, 'user payload')
    ).toThrow(/Secret detected in user payload/);
  });

  it('throws when secret string patterns are present', () => {
    expect(() =>
      assertNoSecrets({ data: 'sk_live_abc123' }, 'API response')
    ).toThrow(/Secret detected in API response/);
  });

  it('throws on non-serializable values (circular reference)', () => {
    const circular: Record<string, unknown> = { a: 1 };
    circular['self'] = circular;
    expect(() => assertNoSecrets(circular, 'circular')).toThrow(
      /cannot serialize value in "circular"/
    );
  });

  it('includes context in error message', () => {
    expect(() => assertNoSecrets({ token: 'x' }, 'my-context')).toThrow(
      'my-context'
    );
  });

  it('passes on null', () => {
    expect(() => assertNoSecrets(null, 'null-check')).not.toThrow();
  });

  it('passes on empty string', () => {
    expect(() => assertNoSecrets('', 'empty')).not.toThrow();
  });

  it('passes on arrays of clean data', () => {
    expect(() =>
      assertNoSecrets([{ name: 'alice' }, { name: 'bob' }], 'array')
    ).not.toThrow();
  });
});
