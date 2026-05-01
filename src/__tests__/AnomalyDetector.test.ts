import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { AnomalyDetector } from '../server/AnomalyDetector';

import type { AnomalyHandler, AnomalyType } from '../server/AnomalyDetector';

describe('AnomalyDetector', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('below threshold', () => {
    it('does not fire handler when count is below threshold', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector({ authFailures: 5 }, handler);

      for (let i = 0; i < 4; i++) {
        detector.record('auth.failures', 'user1');
      }

      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('at threshold', () => {
    it('fires handler exactly once when threshold is reached', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector({ authFailures: 3 }, handler);

      for (let i = 0; i < 3; i++) {
        detector.record('auth.failures', 'user1');
      }

      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith('auth.failures', 3, 'user1');
    });

    it('does not fire again on subsequent records in same window', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector({ authFailures: 3 }, handler);

      for (let i = 0; i < 6; i++) {
        detector.record('auth.failures', 'user1');
      }

      expect(handler).toHaveBeenCalledTimes(1);
    });
  });

  describe('window reset', () => {
    it('resets counter after window expires and fires again on next breach', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector(
        { authFailures: 2, windowMs: 1000 },
        handler
      );

      // First window - breach
      detector.record('auth.failures', 'user1');
      detector.record('auth.failures', 'user1');
      expect(handler).toHaveBeenCalledTimes(1);

      // Advance past window
      vi.advanceTimersByTime(1001);

      // Second window - breach again
      detector.record('auth.failures', 'user1');
      detector.record('auth.failures', 'user1');
      expect(handler).toHaveBeenCalledTimes(2);
    });

    it('getCount returns 0 after window expires', () => {
      const detector = new AnomalyDetector({
        authFailures: 10,
        windowMs: 1000,
      });

      detector.record('auth.failures', 'user1');
      expect(detector.getCount('auth.failures', 'user1')).toBe(1);

      vi.advanceTimersByTime(1001);
      expect(detector.getCount('auth.failures', 'user1')).toBe(0);
    });
  });

  describe('independent type tracking', () => {
    it('tracks different anomaly types independently', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector(
        { authFailures: 2, bulkDeletes: 3 },
        handler
      );

      // 2 auth failures triggers anomaly
      detector.record('auth.failures', 'user1');
      detector.record('auth.failures', 'user1');
      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith('auth.failures', 2, 'user1');

      // 2 bulk deletes does NOT trigger (threshold is 3)
      detector.record('bulk.deletes', 'user1');
      detector.record('bulk.deletes', 'user1');
      expect(handler).toHaveBeenCalledTimes(1);

      // 3rd bulk delete triggers
      detector.record('bulk.deletes', 'user1');
      expect(handler).toHaveBeenCalledTimes(2);
      expect(handler).toHaveBeenCalledWith('bulk.deletes', 3, 'user1');
    });

    it('tracks different users independently', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector({ authFailures: 2 }, handler);

      detector.record('auth.failures', 'user1');
      detector.record('auth.failures', 'user2');

      expect(handler).not.toHaveBeenCalled();
      expect(detector.getCount('auth.failures', 'user1')).toBe(1);
      expect(detector.getCount('auth.failures', 'user2')).toBe(1);
    });
  });

  describe('lazy eviction', () => {
    it('evicts expired entries when counter map exceeds 10k keys', () => {
      const detector = new AnomalyDetector({ windowMs: 1000 });

      // Fill with 10k entries
      for (let i = 0; i < 10_000; i++) {
        detector.record('auth.failures', `user-${i}`);
      }

      // Advance past window so all entries are expired
      vi.advanceTimersByTime(1001);

      // Next record from a new key triggers eviction
      detector.record('auth.failures', 'new-user');
      // Verify old entries are gone
      expect(detector.getCount('auth.failures', 'user-0')).toBe(0);
      // New entry is tracked
      expect(detector.getCount('auth.failures', 'new-user')).toBe(1);
    });
  });

  describe('custom handler data', () => {
    it('passes correct anomaly type, count, and userId to handler', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector({ bulkExports: 1 }, handler);

      detector.record('bulk.exports', 'admin-42');

      expect(handler).toHaveBeenCalledWith('bulk.exports', 1, 'admin-42');
    });

    it('passes undefined userId for system-level events', () => {
      const handler = vi.fn();
      const detector = new AnomalyDetector({ bulkReads: 1 }, handler);

      detector.record('bulk.reads');

      expect(handler).toHaveBeenCalledWith('bulk.reads', 1, undefined);
    });
  });

  describe('default handler', () => {
    it('writes to stderr when no custom handler provided', () => {
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      // Default handler skips in NODE_ENV=test, so temporarily override
      const origEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        const detector = new AnomalyDetector({ authFailures: 1 });
        detector.record('auth.failures', 'user1');

        expect(stderrSpy).toHaveBeenCalledTimes(1);
        const written = stderrSpy.mock.calls[0]![0] as string;
        const parsed = JSON.parse(written.trim());
        expect(parsed.level).toBe('warn');
        expect(parsed.anomalyType).toBe('auth.failures');
        expect(parsed.userId).toBe('user1');
        expect(parsed.service).toBe('dndev-anomaly');
      } finally {
        process.env.NODE_ENV = origEnv;
        stderrSpy.mockRestore();
      }
    });
  });

  describe('getCount', () => {
    it('returns 0 for unknown type/user combinations', () => {
      const detector = new AnomalyDetector();
      expect(detector.getCount('auth.failures', 'nobody')).toBe(0);
    });

    it('returns current count within active window', () => {
      const detector = new AnomalyDetector();
      detector.record('auth.failures', 'user1');
      detector.record('auth.failures', 'user1');
      detector.record('auth.failures', 'user1');
      expect(detector.getCount('auth.failures', 'user1')).toBe(3);
    });
  });
});
