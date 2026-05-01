// packages/security/src/common/SecurityConfig.ts

/**
 * @fileoverview Security Config Types
 * @description Re-exports SecurityContext types from @donotdev/core.
 * Keeping the canonical definition in core avoids circular deps.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

export type {
  AuditEventType,
  AuditEvent,
  SecurityContext,
  AuthHardeningContext,
  ServerRateLimitConfig,
  ServerRateLimitResult,
  RateLimitBackend,
} from '@donotdev/core';
