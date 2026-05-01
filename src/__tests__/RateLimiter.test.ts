import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  DndevRateLimiter,
  MemoryRateLimitStorageBackend,
} from '../server/RateLimiter';

import type { RateLimitStorageBackend } from '../server/RateLimiter';

describe('MemoryRateLimitStorageBackend', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('increments count for a key', async () => {
    const backend = new MemoryRateLimitStorageBackend();
    expect(await backend.increment('k', 60_000)).toBe(1);
    expect(await backend.increment('k', 60_000)).toBe(2);
    expect(await backend.increment('k', 60_000)).toBe(3);
  });

  it('resets count after window expires', async () => {
    const backend = new MemoryRateLimitStorageBackend();
    await backend.increment('k', 60_000);
    await backend.increment('k', 60_000);

    vi.advanceTimersByTime(60_001);

    expect(await backend.increment('k', 60_000)).toBe(1);
  });

  it('tracks separate keys independently', async () => {
    const backend = new MemoryRateLimitStorageBackend();
    await backend.increment('a', 60_000);
    await backend.increment('a', 60_000);
    await backend.increment('b', 60_000);

    expect(await backend.increment('a', 60_000)).toBe(3);
    expect(await backend.increment('b', 60_000)).toBe(2);
  });

  it('reset deletes a key', async () => {
    const backend = new MemoryRateLimitStorageBackend();
    await backend.increment('k', 60_000);
    await backend.increment('k', 60_000);

    await backend.reset('k');

    expect(await backend.increment('k', 60_000)).toBe(1);
  });

  it('lazy eviction triggers at threshold (10,000 entries)', async () => {
    const backend = new MemoryRateLimitStorageBackend();
    const windowMs = 1_000;

    // Fill up to threshold with expired entries
    for (let i = 0; i < 10_000; i++) {
      await backend.increment(`key-${i}`, windowMs);
    }

    // Advance past window so all entries are expired
    vi.advanceTimersByTime(windowMs + 1);

    // Next increment on a NEW key triggers eviction
    await backend.increment('new-key', windowMs);

    // Verify the new key works correctly
    expect(await backend.increment('new-key', windowMs)).toBe(2);
  });
});

describe('DndevRateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('uses default limits (100 writes, 500 reads, 60s window)', async () => {
    const limiter = new DndevRateLimiter();

    // 100 writes should pass
    for (let i = 0; i < 100; i++) {
      await limiter.check('user1', 'write');
    }

    // 101st write should throw
    await expect(limiter.check('user1', 'write')).rejects.toThrow(
      'Rate limit exceeded'
    );
  });

  it('allows requests under write limit', async () => {
    const limiter = new DndevRateLimiter({ writes: { points: 5 } });
    for (let i = 0; i < 5; i++) {
      await expect(limiter.check('user', 'write')).resolves.toBeUndefined();
    }
  });

  it('blocks requests over write limit', async () => {
    const limiter = new DndevRateLimiter({ writes: { points: 3 } });
    await limiter.check('user', 'write');
    await limiter.check('user', 'write');
    await limiter.check('user', 'write');

    await expect(limiter.check('user', 'write')).rejects.toThrow(
      'Rate limit exceeded'
    );
  });

  it('blocks requests over read limit', async () => {
    const limiter = new DndevRateLimiter({ reads: { points: 2 } });
    await limiter.check('user', 'read');
    await limiter.check('user', 'read');

    await expect(limiter.check('user', 'read')).rejects.toThrow(
      'Rate limit exceeded'
    );
  });

  it('error message includes count, limit, operation, and duration', async () => {
    const limiter = new DndevRateLimiter({
      writes: { points: 1, durationSeconds: 30 },
    });
    await limiter.check('u', 'write');

    await expect(limiter.check('u', 'write')).rejects.toThrow(
      /2\/1 write requests in 30s/
    );
  });

  it('window resets after duration', async () => {
    const limiter = new DndevRateLimiter({
      writes: { points: 2, durationSeconds: 10 },
    });

    await limiter.check('u', 'write');
    await limiter.check('u', 'write');
    // Now at limit

    vi.advanceTimersByTime(10_001);

    // Window reset - should pass again
    await expect(limiter.check('u', 'write')).resolves.toBeUndefined();
  });

  it('tracks separate keys independently', async () => {
    const limiter = new DndevRateLimiter({ writes: { points: 1 } });

    await limiter.check('user-a', 'write');
    await limiter.check('user-b', 'write');

    // user-a exhausted
    await expect(limiter.check('user-a', 'write')).rejects.toThrow(
      'Rate limit exceeded'
    );
    // user-b also exhausted
    await expect(limiter.check('user-b', 'write')).rejects.toThrow(
      'Rate limit exceeded'
    );
  });

  it('write and read limits are independent', async () => {
    const limiter = new DndevRateLimiter({
      writes: { points: 1 },
      reads: { points: 1 },
    });

    await limiter.check('u', 'write');
    await limiter.check('u', 'read');

    // Write exhausted, read exhausted
    await expect(limiter.check('u', 'write')).rejects.toThrow();
    await expect(limiter.check('u', 'read')).rejects.toThrow();
  });

  it('accepts a custom backend', async () => {
    const mockBackend: RateLimitStorageBackend = {
      increment: vi.fn().mockResolvedValue(1),
      reset: vi.fn().mockResolvedValue(undefined),
    };

    const limiter = new DndevRateLimiter({
      backend: mockBackend,
      writes: { points: 10 },
    });

    await limiter.check('key', 'write');

    expect(mockBackend.increment).toHaveBeenCalledWith('write:key', 60_000);
  });

  it('custom backend returning over-limit count triggers error', async () => {
    const mockBackend: RateLimitStorageBackend = {
      increment: vi.fn().mockResolvedValue(999),
      reset: vi.fn(),
    };

    const limiter = new DndevRateLimiter({
      backend: mockBackend,
      writes: { points: 5 },
    });

    await expect(limiter.check('k', 'write')).rejects.toThrow(
      'Rate limit exceeded'
    );
  });
});
