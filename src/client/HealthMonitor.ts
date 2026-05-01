// packages/security/src/client/HealthMonitor.ts

/**
 * @fileoverview HealthMonitor
 * @description Circuit breaker pattern + health check probes for availability.
 * Covers SOC2 Availability Principle (A1): health monitoring, graceful degradation.
 *
 * Zero deps — uses fetch + AbortSignal for liveness probes.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

/** Current health state of a monitored service. */
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

export interface CircuitBreakerConfig {
  /**
   * Failure count threshold before circuit opens (default: 5).
   */
  failureThreshold?: number;
  /**
   * Cooldown before attempting half-open (ms, default: 10_000).
   */
  resetTimeoutMs?: number;
  /**
   * Request timeout for health checks (ms, default: 3_000).
   */
  probeTimeoutMs?: number;
}

type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Simple circuit breaker (no external deps).
 * closed → (failures >= threshold) → open → (after cooldown) → half-open → closed|open
 */
class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failures = 0;
  private lastOpenedAt = 0;

  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;

  constructor(config: CircuitBreakerConfig = {}) {
    this.failureThreshold = config.failureThreshold ?? 5;
    this.resetTimeoutMs = config.resetTimeoutMs ?? 10_000;
  }

  /**
   * Evaluate current circuit state, transitioning 'open' → 'half-open' if the
   * cooldown has elapsed. State transitions live here (not in a getter) to
   * avoid getter side effects.
   */
  private _evaluateState(): CircuitState {
    if (
      this.state === 'open' &&
      Date.now() - this.lastOpenedAt > this.resetTimeoutMs
    ) {
      this.state = 'half-open';
    }
    return this.state;
  }

  /** Current circuit state (read-only, no side effects). */
  get currentState(): CircuitState {
    return this.state;
  }

  isOpen(): boolean {
    return this._evaluateState() === 'open';
  }

  recordSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  recordFailure(): void {
    this.failures += 1;
    if (this.failures >= this.failureThreshold) {
      this.state = 'open';
      this.lastOpenedAt = Date.now();
    }
  }
}

export interface HealthMonitorConfig extends CircuitBreakerConfig {
  /**
   * URL to probe for liveness (e.g., '/api/health').
   * If not set, liveness checks always return true.
   */
  livenessUrl?: string;
}

/**
 * Availability monitor: circuit breaker + liveness probe (SOC2 A1).
 *
 * Wrap downstream calls with `protect()` to prevent cascading failures.
 * Use `checkLiveness()` in health check endpoints.
 *
 * @example
 * ```typescript
 * const monitor = new HealthMonitor({ livenessUrl: '/api/health', failureThreshold: 3 });
 *
 * // Protect a downstream call:
 * const safeCall = monitor.protect(async () => fetchUserData(id));
 * try {
 *   const data = await safeCall();
 * } catch {
 *   // Circuit open — show cached/degraded UI
 * }
 *
 * // Liveness probe in API route:
 * const alive = await monitor.checkLiveness();
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class HealthMonitor {
  private readonly breaker: CircuitBreaker;
  private readonly config: HealthMonitorConfig;
  private _status: HealthStatus = 'healthy';
  /**
   * Guards the half-open state: only one probe executes at a time.
   * Concurrent calls in half-open state are rejected rather than all executing,
   * which would re-open the circuit on a mass failure storm.
   */
  private _probing = false;

  constructor(config: HealthMonitorConfig = {}) {
    this.config = config;
    this.breaker = new CircuitBreaker(config);
  }

  /**
   * Wrap an async function with circuit-breaker protection.
   * The returned function throws when the circuit is open.
   * In half-open state only one probe executes at a time — concurrent calls are rejected.
   */
  protect<T>(fn: () => Promise<T>): () => Promise<T> {
    return async () => {
      if (this.breaker.isOpen()) {
        this._status = 'unhealthy';
        throw new Error(
          '[dndev/security] Circuit breaker open — downstream service unavailable'
        );
      }

      // Half-open: allow only one probe at a time to prevent mass-failure storms
      // that would immediately re-open the circuit.
      // Atomic flag pattern: set _probing = true in the same synchronous block as the
      // check to prevent TOCTOU — no await between read and write of the guard flag.
      const isHalfOpen = this.breaker.currentState === 'half-open';
      if (isHalfOpen) {
        if (this._probing) {
          this._status = 'unhealthy';
          throw new Error(
            '[dndev/security] Circuit breaker half-open — probe in progress, retry shortly'
          );
        }
        // Set flag immediately (same microtask) before any async work
        this._probing = true;
      }

      try {
        const result = await fn();
        this.breaker.recordSuccess();
        this._status = 'healthy';
        return result;
      } catch (err) {
        this.breaker.recordFailure();
        this._status = this.breaker.isOpen() ? 'unhealthy' : 'degraded';
        throw err;
      } finally {
        // Only release the probe flag if we were the one who set it
        if (isHalfOpen) {
          this._probing = false;
        }
      }
    };
  }

  /** Current circuit health status. */
  get status(): HealthStatus {
    return this._status;
  }

  /**
   * HTTP liveness probe — returns true if the endpoint responds 2xx within timeout.
   * Always returns true if no `livenessUrl` configured.
   */
  async checkLiveness(): Promise<boolean> {
    if (!this.config.livenessUrl) return true;
    try {
      // AbortSignal.timeout() requires Safari 16+. Use AbortController + setTimeout
      // for universal browser support (Safari 11+).
      const controller = new AbortController();
      const timeoutMs = this.config.probeTimeoutMs ?? 3_000;
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(this.config.livenessUrl, {
          signal: controller.signal,
        });
        return res.ok;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return false;
    }
  }
}
