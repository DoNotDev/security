// packages/security/src/server/AuditLogger.ts

/**
 * @fileoverview AuditLogger
 * @description Structured JSON audit logger. Zero deps — writes to stdout (pipe to SIEM).
 * Covers SOC2 CC7.1: logging all auth + CRUD events with who/what/when/where.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

import { scrubSecrets } from './SecretValidator';
import type { AuditEvent } from '../common/SecurityConfig';

export interface AuditLoggerOptions {
  /** Log level (default: 'info') */
  level?: 'debug' | 'info' | 'warn' | 'error';
  /** Service name tag added to every entry (default: 'dndev') */
  service?: string;
  /** Custom writer — defaults to process.stdout (JSON per line) */
  write?: (entry: Record<string, unknown>) => void;
}

/**
 * Structured JSON audit logger (SOC2 CC7.1).
 *
 * Produces one JSON object per line on stdout. Pipe to cloud logging
 * (Cloud Logging, Datadog, Splunk, etc.) for SIEM ingestion and immutable storage.
 *
 * @example
 * ```typescript
 * const logger = new AuditLogger({ service: 'my-app' });
 * logger.log({ type: 'auth.login.success', userId: 'u123' });
 * // → {"level":"info","service":"my-app","type":"auth.login.success","userId":"u123","timestamp":"..."}
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class AuditLogger {
  private readonly service: string;
  private readonly level: NonNullable<AuditLoggerOptions['level']>;
  private readonly write: (entry: Record<string, unknown>) => void;

  constructor(opts: AuditLoggerOptions = {}) {
    this.service = opts.service ?? 'dndev';
    this.level = opts.level ?? 'info';
    this.write =
      opts.write ??
      ((entry) => {
        let line: string;
        try {
          line = JSON.stringify(entry);
        } catch (serializeErr) {
          // Circular reference or BigInt — emit a degraded entry preserving key fields
          line = JSON.stringify({
            level: entry['level'],
            service: entry['service'],
            type: entry['type'],
            userId: entry['userId'],
            timestamp: entry['timestamp'],
            _serializeError:
              serializeErr instanceof Error
                ? serializeErr.message
                : 'Audit entry contained non-serializable values',
          });
        }
        process.stdout.write(line + '\n');
      });
  }

  /**
   * Log an audit event with automatic timestamp.
   * Secrets in all event fields are automatically scrubbed before writing.
   */
  log(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): void {
    const safeEvent = scrubSecrets(event) as typeof event;
    const entry: Record<string, unknown> = {
      level: this.level,
      service: this.service,
      ...safeEvent,
      timestamp: safeEvent.timestamp ?? new Date().toISOString(),
    };
    this.write(entry);
  }
}
