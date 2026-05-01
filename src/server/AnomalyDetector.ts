// packages/security/src/server/AnomalyDetector.ts

/**
 * @fileoverview AnomalyDetector
 * @description Threshold-based behavioral anomaly detection with configurable alerting.
 * Covers SOC2 CC7.2 (anomaly detection), CC7.3 (incident response triggers).
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

/** Categories of behavioral anomalies tracked by the detector. */
export type AnomalyType =
  | 'auth.failures'
  | 'bulk.deletes'
  | 'bulk.reads'
  | 'bulk.exports'
  | 'rate_limit.exceeded';

export interface AnomalyThresholds {
  /**
   * Max auth failures per window before alert.
   * @default 10
   */
  authFailures?: number;
  /**
   * Max deletes per window before alert.
   * @default 50
   */
  bulkDeletes?: number;
  /**
   * Max reads per window before alert.
   * @default 1000
   */
  bulkReads?: number;
  /**
   * Max bulk exports per window before alert.
   * @default 5
   */
  bulkExports?: number;
  /**
   * Max rate-limit-exceeded events per window before alert.
   * Defaults to 10 rather than 1 to prevent flooding alert handlers (Slack, PagerDuty)
   * during sustained attacks. Every individual breach is still recorded in the audit log.
   * @default 10
   */
  rateLimitExceeded?: number;
  /**
   * Window size in milliseconds.
   * @default 60_000 (1 minute)
   */
  windowMs?: number;
}

/**
 * Called when an anomaly is detected.
 * @param type - anomaly type
 * @param count - current count in window
 * @param userId - user who triggered it (undefined for system)
 */
export type AnomalyHandler = (
  type: AnomalyType,
  count: number,
  userId?: string
) => void;

interface CounterEntry {
  count: number;
  windowStart: number;
}

/**
 * Fixed-window anomaly detector (SOC2 CC7.2).
 *
 * Tracks event counts per user per window and fires `onAnomaly` when a threshold
 * is breached. Default handler logs to stderr — replace with webhook, email, or SIEM.
 *
 * @example
 * ```typescript
 * const detector = new AnomalyDetector(
 *   { authFailures: 5, bulkDeletes: 20 },
 *   (type, count, userId) => notifySlack(`Anomaly: ${type} x${count} by ${userId}`)
 * );
 *
 * detector.record('auth.failures', userId);
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
/** Max counter keys tracked before a lazy eviction sweep is triggered. */
const EVICTION_THRESHOLD = 10_000;

export class AnomalyDetector {
  private readonly counters = new Map<string, CounterEntry>();
  private readonly thresholds: Required<AnomalyThresholds>;
  private readonly onAnomaly: AnomalyHandler;

  constructor(thresholds: AnomalyThresholds = {}, onAnomaly?: AnomalyHandler) {
    this.thresholds = {
      authFailures: thresholds.authFailures ?? 10,
      bulkDeletes: thresholds.bulkDeletes ?? 50,
      bulkReads: thresholds.bulkReads ?? 1000,
      bulkExports: thresholds.bulkExports ?? 5,
      rateLimitExceeded: thresholds.rateLimitExceeded ?? 10,
      windowMs: thresholds.windowMs ?? 60_000,
    };
    this.onAnomaly =
      onAnomaly ??
      ((type, count, userId) => {
        if (process.env.NODE_ENV !== 'test') {
          process.stderr.write(
            JSON.stringify({
              level: 'warn',
              service: 'dndev-anomaly',
              type: 'anomaly.detected',
              anomalyType: type,
              count,
              userId,
              timestamp: new Date().toISOString(),
            }) + '\n'
          );
        }
      });
  }

  /**
   * Record an event and fire `onAnomaly` if threshold is breached.
   * For `rate_limit.exceeded`, the handler fires once per window threshold
   * (not on every single breach) to prevent flooding alert sinks during attacks.
   */
  record(type: AnomalyType, userId?: string): void {
    const key = `${type}:${userId ?? '__global__'}`;
    const now = Date.now();
    const isNewKey = !this.counters.has(key);

    // Lazy eviction before adding new key
    if (isNewKey && this.counters.size >= EVICTION_THRESHOLD) {
      this._evictExpired(now);
    }

    const entry = this.counters.get(key) ?? { count: 0, windowStart: now };

    // Reset if window has expired
    if (now - entry.windowStart > this.thresholds.windowMs) {
      entry.count = 0;
      entry.windowStart = now;
    }

    entry.count += 1;
    this.counters.set(key, entry);

    const threshold = this.getThreshold(type);
    // Fire once when crossing threshold — not on every subsequent record
    if (entry.count >= threshold && entry.count - 1 < threshold) {
      this.onAnomaly(type, entry.count, userId);
    }
  }

  private getThreshold(type: AnomalyType): number {
    switch (type) {
      case 'auth.failures':
        return this.thresholds.authFailures;
      case 'bulk.deletes':
        return this.thresholds.bulkDeletes;
      case 'bulk.reads':
        return this.thresholds.bulkReads;
      case 'bulk.exports':
        return this.thresholds.bulkExports;
      case 'rate_limit.exceeded':
        return this.thresholds.rateLimitExceeded;
      default: {
        if (process.env.NODE_ENV !== 'test') {
          process.stderr.write(
            JSON.stringify({
              level: 'warn',
              service: 'dndev-anomaly',
              type: 'unknown.anomaly.type',
              anomalyType: type,
              timestamp: new Date().toISOString(),
            }) + '\n'
          );
        }
        return 100;
      }
    }
  }

  private _evictExpired(now: number): void {
    for (const [k, v] of this.counters) {
      if (now - v.windowStart > this.thresholds.windowMs) {
        this.counters.delete(k);
      }
    }
  }

  /** Current count for a type + userId in the active window. */
  getCount(type: AnomalyType, userId?: string): number {
    const key = `${type}:${userId ?? '__global__'}`;
    const entry = this.counters.get(key);
    if (!entry) return 0;
    if (Date.now() - entry.windowStart > this.thresholds.windowMs) return 0;
    return entry.count;
  }
}
