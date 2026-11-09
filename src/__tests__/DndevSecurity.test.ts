import { describe, it, expect, vi } from 'vitest';

import { AnomalyDetector } from '../server/AnomalyDetector';
import { AuditLogger } from '../server/AuditLogger';
import { AuthHardening } from '../server/AuthHardening';
import { DndevSecurity } from '../server/DndevSecurity';
import { PrivacyManager } from '../server/PrivacyManager';
import { DndevRateLimiter } from '../server/RateLimiter';

describe('DndevSecurity', () => {
  describe('facade creation', () => {
    it('creates all sub-modules with zero config', () => {
      const sec = new DndevSecurity();

      expect(sec.auditLogger).toBeInstanceOf(AuditLogger);
      expect(sec.rateLimiter).toBeInstanceOf(DndevRateLimiter);
      expect(sec.authHardening).toBeInstanceOf(AuthHardening);
      expect(sec.anomalyDetector).toBeInstanceOf(AnomalyDetector);
      expect(sec.privacyManager).toBeInstanceOf(PrivacyManager);
      expect(sec.piiEncryptor).toBeNull();
    });
  });

  describe('PII config validation', () => {
    it('throws when piiSecret is provided without piiSalt', () => {
      expect(
        () => new DndevSecurity({ piiSecret: 'my-secret-key-1234' })
      ).toThrow('piiSecret and piiSalt');
    });

    it('throws when piiSecret has insufficient character diversity', () => {
      expect(
        () => new DndevSecurity({ piiSecret: 'aaaa', piiSalt: 'salt' })
      ).toThrow('insufficient character diversity');
    });

    it('creates PiiEncryptor when both piiSecret and piiSalt provided', () => {
      const sec = new DndevSecurity({
        piiSecret: 'my-secret-key-that-is-long-enough',
        piiSalt: 'unique-deployment-salt',
      });

      expect(sec.piiEncryptor).not.toBeNull();
    });
  });

  describe('rate limiter', () => {
    it('is accessible and functional', async () => {
      const sec = new DndevSecurity({
        rateLimit: { writes: { points: 2, durationSeconds: 60 } },
      });

      // First two calls should pass
      await sec.checkRateLimit('user1', 'write');
      await sec.checkRateLimit('user1', 'write');

      // Third should throw
      await expect(sec.checkRateLimit('user1', 'write')).rejects.toThrow(
        'Rate limit exceeded'
      );
    });
  });

  describe('audit logger', () => {
    it('is accessible and functional', () => {
      const writeFn = vi.fn();
      const sec = new DndevSecurity({
        logger: { write: writeFn, service: 'test-app' },
      });

      sec.audit({ type: 'auth.login.success', userId: 'u1' });

      expect(writeFn).toHaveBeenCalledTimes(1);
      expect(writeFn).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'auth.login.success',
          userId: 'u1',
          service: 'test-app',
        })
      );
    });
  });

  describe('anomaly detector', () => {
    it('is accessible and records anomalies', () => {
      const handler = vi.fn();
      const sec = new DndevSecurity({
        anomaly: { authFailures: 2, onAnomaly: handler },
      });

      sec.recordAnomaly('auth.failures', 'u1');
      sec.recordAnomaly('auth.failures', 'u1');

      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith('auth.failures', 2, 'u1');
    });

    it('throws on unknown anomaly type', () => {
      const sec = new DndevSecurity();

      expect(() => sec.recordAnomaly('invalid.type', 'u1')).toThrow(
        'unknown anomaly type'
      );
    });
  });

  describe('auth hardening', () => {
    it('is accessible and provides lockout functionality', () => {
      const sec = new DndevSecurity();
      expect(sec.authHardening).toBeInstanceOf(AuthHardening);
      // AuthHardening has its own test suite; just verify wiring
      expect(typeof sec.authHardening.recordFailure).toBe('function');
    });
  });

  describe('custom rate limit backend', () => {
    it('delegates to injected backend instead of in-memory limiter', async () => {
      const mockBackend = {
        check: vi.fn().mockResolvedValue({ allowed: true }),
      };

      const sec = new DndevSecurity({ rateLimitBackend: mockBackend });

      await sec.checkRateLimit('user1', 'write');

      expect(mockBackend.check).toHaveBeenCalledTimes(1);
      expect(mockBackend.check).toHaveBeenCalledWith(
        'user1',
        expect.objectContaining({
          maxAttempts: 100,
          windowMs: 60_000,
        })
      );
    });

    it('throws and records anomaly when backend returns not allowed', async () => {
      const handler = vi.fn();
      const mockBackend = {
        check: vi.fn().mockResolvedValue({
          allowed: false,
          blockRemainingSeconds: 30,
        }),
      };

      const sec = new DndevSecurity({
        rateLimitBackend: mockBackend,
        anomaly: { rateLimitExceeded: 1, onAnomaly: handler },
      });

      await expect(sec.checkRateLimit('user1', 'read')).rejects.toThrow(
        'Rate limit exceeded'
      );
      expect(handler).toHaveBeenCalledWith('rate_limit.exceeded', 1, 'user1');
    });
  });
});
