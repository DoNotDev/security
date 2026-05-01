import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { HealthMonitor } from '../client/HealthMonitor';

describe('HealthMonitor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('initial state', () => {
    it('starts with healthy status', () => {
      const monitor = new HealthMonitor();
      expect(monitor.status).toBe('healthy');
    });
  });

  describe('circuit breaker transitions', () => {
    it('transitions to open (unhealthy) after N failures', async () => {
      const monitor = new HealthMonitor({ failureThreshold: 3 });
      const failingFn = () => Promise.reject(new Error('down'));
      const protected_ = monitor.protect(failingFn);

      for (let i = 0; i < 3; i++) {
        await protected_().catch(() => {});
      }

      expect(monitor.status).toBe('unhealthy');
      // Further calls are rejected immediately
      await expect(protected_()).rejects.toThrow('Circuit breaker open');
    });

    it('transitions to half-open after cooldown', async () => {
      const monitor = new HealthMonitor({
        failureThreshold: 2,
        resetTimeoutMs: 5000,
      });
      const failingFn = () => Promise.reject(new Error('down'));
      const protected_ = monitor.protect(failingFn);

      // Trip the breaker
      await protected_().catch(() => {});
      await protected_().catch(() => {});
      expect(monitor.status).toBe('unhealthy');

      // Advance past cooldown
      vi.advanceTimersByTime(5001);

      // Next call should attempt (half-open) rather than reject immediately
      const succeedingFn = () => Promise.resolve('ok');
      const protectedOk = monitor.protect(succeedingFn);
      const result = await protectedOk();
      expect(result).toBe('ok');
      expect(monitor.status).toBe('healthy');
    });

    it('successful probe in half-open transitions to closed (healthy)', async () => {
      const monitor = new HealthMonitor({
        failureThreshold: 1,
        resetTimeoutMs: 1000,
      });

      // Trip breaker
      const fail = monitor.protect(() => Promise.reject(new Error('fail')));
      await fail().catch(() => {});
      expect(monitor.status).toBe('unhealthy');

      // Wait for cooldown
      vi.advanceTimersByTime(1001);

      // Succeed in half-open
      const succeed = monitor.protect(() => Promise.resolve(42));
      const result = await succeed();
      expect(result).toBe(42);
      expect(monitor.status).toBe('healthy');
    });

    it('failed probe in half-open transitions back to open', async () => {
      const monitor = new HealthMonitor({
        failureThreshold: 1,
        resetTimeoutMs: 1000,
      });

      // Trip breaker
      const fail = monitor.protect(() => Promise.reject(new Error('fail')));
      await fail().catch(() => {});
      expect(monitor.status).toBe('unhealthy');

      // Wait for cooldown
      vi.advanceTimersByTime(1001);

      // Fail again in half-open
      const failAgain = monitor.protect(() =>
        Promise.reject(new Error('still down'))
      );
      await failAgain().catch(() => {});
      expect(monitor.status).toBe('unhealthy');

      // Circuit is open again - calls rejected
      await expect(failAgain()).rejects.toThrow('Circuit breaker open');
    });
  });

  describe('concurrency guard in half-open', () => {
    it('rejects concurrent probes when one is already in progress', async () => {
      const monitor = new HealthMonitor({
        failureThreshold: 1,
        resetTimeoutMs: 1000,
      });

      // Trip the breaker
      const fail = monitor.protect(() => Promise.reject(new Error('fail')));
      await fail().catch(() => {});

      // Advance to half-open
      vi.advanceTimersByTime(1001);

      // Create a slow probe that doesn't resolve immediately
      let resolveProbe!: (val: string) => void;
      const slowProbe = new Promise<string>((resolve) => {
        resolveProbe = resolve;
      });
      const protectedSlow = monitor.protect(() => slowProbe);

      // Start the first probe (does not await - stays pending)
      const firstCall = protectedSlow();

      // Second concurrent call should be rejected
      const protectedSecond = monitor.protect(() => Promise.resolve('second'));
      await expect(protectedSecond()).rejects.toThrow('probe in progress');

      // Resolve the first probe
      resolveProbe('done');
      await expect(firstCall).resolves.toBe('done');
      expect(monitor.status).toBe('healthy');
    });
  });

  describe('checkLiveness', () => {
    it('returns true when no livenessUrl configured', async () => {
      const monitor = new HealthMonitor();
      const alive = await monitor.checkLiveness();
      expect(alive).toBe(true);
    });

    it('returns true when fetch responds with 2xx', async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal('fetch', mockFetch);

      const monitor = new HealthMonitor({ livenessUrl: '/api/health' });
      const alive = await monitor.checkLiveness();

      expect(alive).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/health',
        expect.objectContaining({ signal: expect.anything() })
      );

      vi.unstubAllGlobals();
    });

    it('returns false when fetch responds with non-2xx', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }));

      const monitor = new HealthMonitor({ livenessUrl: '/api/health' });
      const alive = await monitor.checkLiveness();

      expect(alive).toBe(false);
      vi.unstubAllGlobals();
    });

    it('returns false when fetch throws', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockRejectedValue(new Error('network error'))
      );

      const monitor = new HealthMonitor({ livenessUrl: '/api/health' });
      const alive = await monitor.checkLiveness();

      expect(alive).toBe(false);
      vi.unstubAllGlobals();
    });
  });

  describe('status getter', () => {
    it('reflects degraded state on failures below threshold', async () => {
      const monitor = new HealthMonitor({ failureThreshold: 3 });
      const fail = monitor.protect(() => Promise.reject(new Error('err')));

      await fail().catch(() => {});
      expect(monitor.status).toBe('degraded');

      await fail().catch(() => {});
      expect(monitor.status).toBe('degraded');
    });

    it('returns healthy after successful calls', async () => {
      const monitor = new HealthMonitor();
      const succeed = monitor.protect(() => Promise.resolve('ok'));

      await succeed();
      expect(monitor.status).toBe('healthy');
    });
  });
});
