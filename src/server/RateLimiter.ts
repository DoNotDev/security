// packages/security/src/server/RateLimiter.ts

/**
 * @fileoverview RateLimiter
 * @description In-memory fixed-window rate limiter. Zero deps.
 * Covers SOC2 CC6.6 / OWASP API4: unrestricted resource consumption.
 *
 * Note: This is a fixed-window (not sliding-window) implementation. A burst of
 * `points` requests at the end of window N and `points` at the start of N+1 can
 * briefly double the effective rate. Use a Redis-backed backend with a true
 * sliding-window for strict rate control in production.
 *
 * For distributed (multi-replica) deployments, implement RateLimitStorageBackend
 * and provide a Redis-backed implementation.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

export interface RateLimitWindow {
  /** Max requests in window (default: 100 for writes, 500 for reads) */
  points: number;
  /** Window duration in seconds (default: 60) */
  durationSeconds: number;
}

interface WindowEntry {
  count: number;
  windowStart: number;
  /** Window size used when this entry was created — required for correct eviction. */
  windowMs: number;
}

/**
 * Backend interface for rate limiting — implement with Redis in production.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export interface RateLimitStorageBackend {
  increment(key: string, windowMs: number): Promise<number>;
  reset(key: string): Promise<void>;
}

/** Max entries before a lazy eviction sweep is triggered. */
const EVICTION_THRESHOLD = 10_000;

/**
 * In-memory rate limiter (single instance / single replica).
 * Performs lazy eviction of expired entries when the store exceeds
 * {@link EVICTION_THRESHOLD} keys to prevent unbounded memory growth.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class MemoryRateLimitStorageBackend implements RateLimitStorageBackend {
  private readonly store = new Map<string, WindowEntry>();

  async increment(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now - entry.windowStart > windowMs) {
      // Lazy eviction: sweep expired entries before adding a new key
      if (!entry && this.store.size >= EVICTION_THRESHOLD) {
        this._evictExpired(now);
      }
      this.store.set(key, { count: 1, windowStart: now, windowMs });
      return 1;
    }

    entry.count += 1;
    return entry.count;
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }

  private _evictExpired(now: number): void {
    for (const [k, v] of this.store) {
      // Use the per-entry windowMs — avoids incorrectly evicting entries created
      // with a different window size when the same backend is shared.
      if (now - v.windowStart > v.windowMs) {
        this.store.delete(k);
      }
    }
  }
}

export interface RateLimiterOptions {
  writes?: Partial<RateLimitWindow>;
  reads?: Partial<RateLimitWindow>;
  /** Custom backend (default: MemoryRateLimitStorageBackend) */
  backend?: RateLimitStorageBackend;
}

/**
 * Rate limiter with separate write/read limits (SOC2 CC6.6).
 *
 * @example
 * ```typescript
 * const limiter = new DndevRateLimiter({ writes: { points: 50 } });
 * await limiter.check('user:abc', 'write'); // throws if > 50 writes/min
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class DndevRateLimiter {
  private readonly backend: RateLimitStorageBackend;
  private readonly writes: RateLimitWindow;
  private readonly reads: RateLimitWindow;

  constructor(opts: RateLimiterOptions = {}) {
    this.backend = opts.backend ?? new MemoryRateLimitStorageBackend();
    this.writes = {
      points: opts.writes?.points ?? 100,
      durationSeconds: opts.writes?.durationSeconds ?? 60,
    };
    this.reads = {
      points: opts.reads?.points ?? 500,
      durationSeconds: opts.reads?.durationSeconds ?? 60,
    };
  }

  /**
   * Consume one point for key + operation.
   *
   * **Fixed-window limitation:** A burst of `points` requests at the end of window N
   * and `points` at the start of window N+1 can briefly double the effective rate.
   * For strict rate control in production, use a sliding-window backend (e.g. Redis
   * with `SLIDING_WINDOW` algorithm) via the `rateLimitBackend` option on DndevSecurity.
   *
   * @throws {Error} with message 'Rate limit exceeded' when threshold breached.
   */
  async check(key: string, operation: 'read' | 'write'): Promise<void> {
    const cfg = operation === 'write' ? this.writes : this.reads;
    const windowMs = cfg.durationSeconds * 1000;
    const count = await this.backend.increment(`${operation}:${key}`, windowMs);

    if (count > cfg.points) {
      throw new Error(
        `Rate limit exceeded: ${count}/${cfg.points} ${operation} requests in ${cfg.durationSeconds}s`
      );
    }
  }
}
