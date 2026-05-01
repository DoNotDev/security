import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { AuditLogger } from '../server/AuditLogger';

describe('AuditLogger', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T12:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('log output', () => {
    it('calls custom write function with correct entry', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({ write: (e) => entries.push(e) });

      logger.log({ type: 'auth.login.success', userId: 'u123' });

      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({
        level: 'info',
        service: 'dndev',
        type: 'auth.login.success',
        userId: 'u123',
      });
    });

    it('includes timestamp in ISO format', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({ write: (e) => entries.push(e) });

      logger.log({ type: 'auth.logout' });

      expect(entries[0]!['timestamp']).toBe('2025-01-15T12:00:00.000Z');
    });

    it('preserves explicitly provided timestamp', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({ write: (e) => entries.push(e) });

      logger.log({
        type: 'auth.login.success',
        timestamp: '2024-06-01T00:00:00.000Z',
      });

      expect(entries[0]!['timestamp']).toBe('2024-06-01T00:00:00.000Z');
    });

    it('uses custom service name', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({
        service: 'my-app',
        write: (e) => entries.push(e),
      });

      logger.log({ type: 'data.created' });

      expect(entries[0]!['service']).toBe('my-app');
    });

    it('uses custom level', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({
        level: 'warn',
        write: (e) => entries.push(e),
      });

      logger.log({ type: 'anomaly.detected' });

      expect(entries[0]!['level']).toBe('warn');
    });

    it('includes all event fields (collection, docId, ip, userAgent, metadata)', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({ write: (e) => entries.push(e) });

      logger.log({
        type: 'data.created',
        userId: 'u1',
        collection: 'users',
        docId: 'doc1',
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        metadata: { source: 'api' },
      });

      expect(entries[0]).toMatchObject({
        collection: 'users',
        docId: 'doc1',
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        metadata: { source: 'api' },
      });
    });
  });

  describe('secret scrubbing', () => {
    it('scrubs secret key names from event data', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({ write: (e) => entries.push(e) });

      logger.log({
        type: 'auth.login.success',
        userId: 'u1',
        metadata: { password: 'hunter2', action: 'login' },
      } as never);

      const meta = entries[0]!['metadata'] as Record<string, unknown>;
      expect(meta['password']).toBe('[REDACTED]');
      expect(meta['action']).toBe('login');
    });

    it('scrubs secret string patterns from values', () => {
      const entries: Record<string, unknown>[] = [];
      const logger = new AuditLogger({ write: (e) => entries.push(e) });

      logger.log({
        type: 'config.changed',
        metadata: { info: 'key is sk_live_abc123' },
      } as never);

      const meta = entries[0]!['metadata'] as Record<string, unknown>;
      expect(meta['info']).not.toContain('sk_live_abc123');
      expect(meta['info']).toContain('[REDACTED]');
    });
  });

  describe('default writer (stdout)', () => {
    it('writes JSON line to stdout', () => {
      const writeSpy = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      const logger = new AuditLogger({ service: 'test-svc' });

      logger.log({ type: 'auth.login.success', userId: 'u1' });

      expect(writeSpy).toHaveBeenCalledTimes(1);
      const output = writeSpy.mock.calls[0]![0] as string;
      expect(output.endsWith('\n')).toBe(true);

      const parsed = JSON.parse(output.trim());
      expect(parsed).toMatchObject({
        level: 'info',
        service: 'test-svc',
        type: 'auth.login.success',
        userId: 'u1',
      });

      writeSpy.mockRestore();
    });

    it('handles circular references in default writer gracefully', () => {
      const writeSpy = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      const logger = new AuditLogger();

      const circular: Record<string, unknown> = { val: 1 };
      circular['self'] = circular;

      // scrubSecrets will break circular ref (it creates new objects),
      // but we test the serialization error path by creating a value
      // that survives scrubbing but fails JSON.stringify
      // Use BigInt which can't be serialized
      logger.log({
        type: 'data.created',
        userId: 'u1',
        metadata: { big: BigInt(123) } as never,
      } as never);

      expect(writeSpy).toHaveBeenCalledTimes(1);
      const output = writeSpy.mock.calls[0]![0] as string;
      const parsed = JSON.parse(output.trim());
      // Degraded entry should still have key fields
      expect(parsed['type']).toBe('data.created');
      expect(parsed['userId']).toBe('u1');
      expect(parsed['_serializeError']).toBeDefined();

      writeSpy.mockRestore();
    });
  });
});
