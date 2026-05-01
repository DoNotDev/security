// packages/security/src/server/index.ts

export { AuditLogger } from './AuditLogger';
export type { AuditLoggerOptions } from './AuditLogger';

export { DndevRateLimiter, MemoryRateLimitStorageBackend } from './RateLimiter';
export type {
  RateLimitStorageBackend,
  RateLimiterOptions,
  RateLimitWindow,
} from './RateLimiter';

export { PiiEncryptor } from './PiiEncryptor';

export { AuthHardening } from './AuthHardening';
export type { AuthHardeningConfig, LockoutResult } from './AuthHardening';

export { AnomalyDetector } from './AnomalyDetector';
export type {
  AnomalyThresholds,
  AnomalyHandler,
  AnomalyType,
} from './AnomalyDetector';

export { PrivacyManager } from './PrivacyManager';
export type {
  RetentionPolicy,
  ErasureRequest,
  ErasureResult,
} from './PrivacyManager';

export { scrubSecrets, assertNoSecrets } from './SecretValidator';

export { DndevSecurity } from './DndevSecurity';
export type { DndevSecurityConfig } from './DndevSecurity';

// Re-export common types for server consumers
export type {
  SecurityContext,
  AuditEvent,
  AuditEventType,
  RateLimitBackend,
  ServerRateLimitConfig,
  ServerRateLimitResult,
  AuthHardeningContext,
} from '../common/SecurityConfig';
