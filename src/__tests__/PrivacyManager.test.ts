import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { PrivacyManager } from '../server/PrivacyManager';

describe('PrivacyManager', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('eraseUser', () => {
    it('returns all collections as erased on full success', async () => {
      const pm = new PrivacyManager();
      const deleteUserData = vi.fn().mockResolvedValue(undefined);

      const result = await pm.eraseUser({
        userId: 'u123',
        collections: ['users', 'orders', 'sessions'],
        deleteUserData,
      });

      expect(result.erased).toEqual(['users', 'orders', 'sessions']);
      expect(result.errors).toEqual([]);
    });

    it('collects partial errors without aborting remaining collections', async () => {
      const pm = new PrivacyManager();
      const deleteUserData = vi.fn().mockImplementation(async (col: string) => {
        if (col === 'orders') throw new Error('FK constraint');
      });

      const result = await pm.eraseUser({
        userId: 'u123',
        collections: ['users', 'orders', 'sessions'],
        deleteUserData,
      });

      expect(result.erased).toEqual(['users', 'sessions']);
      expect(result.errors).toEqual([
        { collection: 'orders', message: 'FK constraint' },
      ]);
      // deleteUserData was called for all 3 collections (not aborted after error)
      expect(deleteUserData).toHaveBeenCalledTimes(3);
    });

    it('passes correct userId and collection to deleteUserData callback', async () => {
      const pm = new PrivacyManager();
      const deleteUserData = vi.fn().mockResolvedValue(undefined);

      await pm.eraseUser({
        userId: 'u456',
        collections: ['audit_logs'],
        deleteUserData,
      });

      expect(deleteUserData).toHaveBeenCalledWith('audit_logs', 'u456');
    });

    it('throws on empty collections array', async () => {
      const pm = new PrivacyManager();
      const deleteUserData = vi.fn();

      await expect(
        pm.eraseUser({ userId: 'u123', collections: [], deleteUserData })
      ).rejects.toThrow('collections array is empty');
    });

    it('handles non-Error thrown values', async () => {
      const pm = new PrivacyManager();
      const deleteUserData = vi.fn().mockRejectedValue('string error');

      const result = await pm.eraseUser({
        userId: 'u123',
        collections: ['users'],
        deleteUserData,
      });

      expect(result.errors).toEqual([
        { collection: 'users', message: 'string error' },
      ]);
    });
  });

  describe('shouldPurge', () => {
    it('returns true for data older than retention policy', () => {
      const pm = new PrivacyManager([{ collection: 'audit_logs', days: 365 }]);

      // Set "now" to a known time
      vi.setSystemTime(new Date('2025-06-01T00:00:00Z'));
      // Date from 400 days ago
      const oldDate = new Date('2024-04-27T00:00:00Z').toISOString();

      expect(pm.shouldPurge('audit_logs', oldDate)).toBe(true);
    });

    it('returns false for data within retention period', () => {
      const pm = new PrivacyManager([{ collection: 'audit_logs', days: 365 }]);

      vi.setSystemTime(new Date('2025-06-01T00:00:00Z'));
      const recentDate = new Date('2025-05-01T00:00:00Z').toISOString();

      expect(pm.shouldPurge('audit_logs', recentDate)).toBe(false);
    });

    it('returns false for collection with no policy', () => {
      const pm = new PrivacyManager([{ collection: 'audit_logs', days: 365 }]);

      expect(pm.shouldPurge('unknown_collection', '2020-01-01T00:00:00Z')).toBe(
        false
      );
    });

    it('returns false when policy days is 0 (no automatic purge)', () => {
      const pm = new PrivacyManager([{ collection: 'permanent', days: 0 }]);

      expect(pm.shouldPurge('permanent', '2000-01-01T00:00:00Z')).toBe(false);
    });

    it('throws on missing dateIso', () => {
      const pm = new PrivacyManager([{ collection: 'logs', days: 30 }]);

      expect(() => pm.shouldPurge('logs', '')).toThrow('missing dateIso');
    });

    it('throws on invalid dateIso', () => {
      const pm = new PrivacyManager([{ collection: 'logs', days: 30 }]);

      expect(() => pm.shouldPurge('logs', 'not-a-date')).toThrow(
        'invalid dateIso'
      );
    });
  });

  describe('getPolicies', () => {
    it('returns configured retention policies', () => {
      const policies = [
        { collection: 'audit_logs', days: 365 },
        { collection: 'sessions', days: 90 },
      ];
      const pm = new PrivacyManager(policies);

      expect(pm.getPolicies()).toEqual(policies);
    });

    it('returns empty array when no policies configured', () => {
      const pm = new PrivacyManager();
      expect(pm.getPolicies()).toEqual([]);
    });
  });
});
