// packages/security/src/server/DndevSecurity.ts

/**
 * @fileoverview DndevSecurity
 * @description Main SOC2 security context. Wires all server-side security controls
 * into a single object that CrudService and auth adapters consume.
 *
 * Zero-config path: all baseline controls active with sensible defaults.
 * Advanced controls (PII encryption, MFA, retention) require explicit config.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

import { AnomalyDetector } from './AnomalyDetector';
import { AuditLogger } from './AuditLogger';
import { AuthHardening } from './AuthHardening';
import { PiiEncryptor } from './PiiEncryptor';
import { PrivacyManager } from './PrivacyManager';
import { DndevRateLimiter } from './RateLimiter';

import type {
  AnomalyThresholds,
  AnomalyHandler,
  AnomalyType,
} from './AnomalyDetector';
import type { AuditLoggerOptions } from './AuditLogger';
import type { AuthHardeningConfig } from './AuthHardening';
import type { RetentionPolicy } from './PrivacyManager';
import type { RateLimiterOptions } from './RateLimiter';
import type {
  SecurityContext,
  AuditEvent,
  AuthHardeningContext,
  RateLimitBackend,
  ServerRateLimitConfig,
} from '../common/SecurityConfig';

export interface DndevSecurityConfig {
  /**
   * Master secret for PII field encryption (AES-256-GCM).
   * Required if any entity defines `security.piiFields`.
   * Store in your secret manager — never in code.
   */
  piiSecret?: string;
  /** PII encryption salt — required when piiSecret is set (no default) */
  piiSalt?: string;
  /** Rate limiter options (default: 100 writes/min, 500 reads/min) */
  rateLimit?: RateLimiterOptions;
  /** Auth hardening options (default: 5 attempts → 15min lockout, 8h session) */
  auth?: AuthHardeningConfig;
  /** Anomaly detection thresholds + handler */
  anomaly?: AnomalyThresholds & { onAnomaly?: AnomalyHandler };
  /** Data retention policies (required for SOC2 P6) */
  retention?: RetentionPolicy[];
  /** Audit logger options (default: JSON to stdout) */
  logger?: AuditLoggerOptions;
  /**
   * Pluggable rate limit backend (default: in-memory).
   * Provide a Firestore, Postgres, or Redis-backed implementation for
   * distributed/serverless deployments where in-memory state is lost between invocations.
   *
   * @example
   * ```typescript
   * import { checkRateLimitWithFirestore } from '@donotdev/functions/shared';
   * const security = new DndevSecurity({
   *   rateLimitBackend: { check: (key, cfg) => checkRateLimitWithFirestore(key, cfg) },
   * });
   * ```
   */
  rateLimitBackend?: RateLimitBackend;
}

/**
 * Main SOC2 security context for DoNotDev applications.
 *
 * Implements `SecurityContext` — pass an instance to `CrudService` and auth adapters.
 * All baseline controls are ON by default at zero config:
 * - Structured audit logging (stdout JSON)
 * - Rate limiting (100 writes/min, 500 reads/min per key)
 * - Brute-force lockout (5 attempts → 15min lockout)
 * - Session timeout tracking (8h idle)
 * - Anomaly detection (stderr warn at thresholds)
 * - Secret scrubbing on all log output
 *
 * Advanced controls require explicit config:
 * - PII encryption → `piiSecret`
 * - Data retention/erasure → `retention`
 * - Custom anomaly handler → `anomaly.onAnomaly`
 *
 * @example
 * ```typescript
 * // Zero-config (baseline SOC2 controls):
 * export const security = new DndevSecurity();
 *
 * // Full SOC2 config:
 * export const security = new DndevSecurity({
 *   piiSecret: process.env.PII_SECRET,
 *   auth: { maxAttempts: 3, lockoutMs: 30 * 60 * 1000 },
 *   retention: [
 *     { collection: 'audit_logs', days: 365 },
 *     { collection: 'sessions', days: 90 },
 *   ],
 *   anomaly: {
 *     authFailures: 5,
 *     onAnomaly: (type, count, userId) => notifySlack(`${type} x${count} by ${userId}`),
 *   },
 * });
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class DndevSecurity implements SecurityContext {
  /** Structured audit logger (stdout JSON) */
  readonly auditLogger: AuditLogger;
  /** Rate limiter (in-memory fixed-window, used when no rateLimitBackend provided) */
  readonly rateLimiter: DndevRateLimiter;
  /** PII field encryptor (null if piiSecret not provided) */
  readonly piiEncryptor: PiiEncryptor | null;
  /**
   * Auth hardening (brute-force lockout, session timeout).
   * Also satisfies `SecurityContext.authHardening` — auth adapters delegate
   * lockout here to avoid running a second, hardcoded lockout Map in parallel.
   */
  readonly authHardening: AuthHardening & AuthHardeningContext;
  /** Anomaly detector (threshold-based behavioral alerts) */
  readonly anomalyDetector: AnomalyDetector;
  /** Privacy manager (retention policies, right-to-erasure) */
  readonly privacyManager: PrivacyManager;
  /** Optional pluggable backend (Firestore, Postgres, Redis) — replaces in-memory limiter */
  private readonly _rateLimitBackend?: RateLimitBackend;
  /** RateLimitConfig derived from rateLimit options, used when delegating to backend */
  private readonly _backendWriteConfig: ServerRateLimitConfig;
  private readonly _backendReadConfig: ServerRateLimitConfig;

  constructor(config: DndevSecurityConfig = {}) {
    this.auditLogger = new AuditLogger(config.logger);
    this.rateLimiter = new DndevRateLimiter(config.rateLimit);
    if (config.piiSecret && !config.piiSalt) {
      throw new Error(
        '[dndev/security] DndevSecurity: PII encryption requires both piiSecret and piiSalt configuration. ' +
          'Provide a per-deployment unique salt stored in your secret manager.'
      );
    }
    if (config.piiSecret && new Set(config.piiSecret).size < 4) {
      throw new Error(
        '[dndev/security] DndevSecurity: piiSecret has insufficient character diversity ' +
          '(fewer than 4 unique characters). Use a cryptographically random secret.'
      );
    }
    this.piiEncryptor =
      config.piiSecret && config.piiSalt
        ? new PiiEncryptor(config.piiSecret, config.piiSalt)
        : null;
    this.authHardening = new AuthHardening(config.auth);
    this.anomalyDetector = new AnomalyDetector(
      config.anomaly,
      config.anomaly?.onAnomaly
    );
    this.privacyManager = new PrivacyManager(config.retention);
    this._rateLimitBackend = config.rateLimitBackend;
    const writeDuration =
      (config.rateLimit?.writes?.durationSeconds ?? 60) * 1000;
    const readDuration =
      (config.rateLimit?.reads?.durationSeconds ?? 60) * 1000;
    this._backendWriteConfig = {
      maxAttempts: config.rateLimit?.writes?.points ?? 100,
      windowMs: writeDuration,
      blockDurationMs: writeDuration,
    };
    this._backendReadConfig = {
      maxAttempts: config.rateLimit?.reads?.points ?? 500,
      windowMs: readDuration,
      blockDurationMs: readDuration,
    };
  }

  // =========================================================================
  // SecurityContext implementation
  // =========================================================================

  /**
   * Emit a structured audit event. Secrets in metadata are automatically scrubbed.
   */
  audit(event: Omit<AuditEvent, 'timestamp'>): void {
    // AuditLogger.log() already scrubs secrets — no need to scrub here
    this.auditLogger.log(event);
  }

  /**
   * Check rate limit for key + operation.
   * Delegates to injected `rateLimitBackend` when provided (Firestore, Postgres, Redis),
   * otherwise falls back to the in-memory limiter.
   * @throws {Error} 'Rate limit exceeded' when threshold is breached.
   */
  async checkRateLimit(
    key: string,
    operation: 'read' | 'write'
  ): Promise<void> {
    if (this._rateLimitBackend) {
      const config =
        operation === 'write'
          ? this._backendWriteConfig
          : this._backendReadConfig;
      const result = await this._rateLimitBackend.check(key, config);
      if (!result.allowed) {
        this.anomalyDetector.record('rate_limit.exceeded', key);
        const wait = result.blockRemainingSeconds ?? 'a few';
        throw new Error(`Rate limit exceeded. Try again in ${wait} seconds.`);
      }
      return;
    }
    try {
      await this.rateLimiter.check(key, operation);
    } catch (err) {
      // Record anomaly on rate limit breach
      this.anomalyDetector.record('rate_limit.exceeded', key);
      throw err;
    }
  }

  /** Encrypt PII fields using AES-256-GCM (no-op if piiSecret not configured). */
  encryptPii<T extends Record<string, unknown>>(
    data: T,
    piiFields: string[]
  ): T {
    if (!this.piiEncryptor || piiFields.length === 0) return data;
    return this.piiEncryptor.encryptFields(data, piiFields);
  }

  /** Decrypt PII fields (no-op if piiSecret not configured). */
  decryptPii<T extends Record<string, unknown>>(
    data: T,
    piiFields: string[]
  ): T {
    if (!this.piiEncryptor || piiFields.length === 0) return data;
    return this.piiEncryptor.decryptFields(data, piiFields);
  }

  /**
   * Record a behavioral anomaly event. Called by CrudService after mutations so
   * the anomaly detector can fire alerts when thresholds are breached.
   */
  private static readonly VALID_ANOMALY_TYPES: ReadonlySet<string> =
    new Set<AnomalyType>([
      'auth.failures',
      'bulk.deletes',
      'bulk.reads',
      'bulk.exports',
      'rate_limit.exceeded',
    ]);

  recordAnomaly(type: string, userId?: string): void {
    if (!DndevSecurity.VALID_ANOMALY_TYPES.has(type)) {
      throw new Error(
        `[dndev/security] DndevSecurity: unknown anomaly type "${type}". ` +
          `Valid types: ${[...DndevSecurity.VALID_ANOMALY_TYPES].join(', ')}`
      );
    }
    this.anomalyDetector.record(type as AnomalyType, userId);
  }
}
