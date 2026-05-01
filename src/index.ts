// packages/security/src/index.ts
// Client barrel — exports client + common (browser-safe)

export { HealthMonitor } from './client/HealthMonitor';
export type {
  HealthMonitorConfig,
  HealthStatus,
  CircuitBreakerConfig,
} from './client/HealthMonitor';

export type {
  SecurityContext,
  AuditEvent,
  AuditEventType,
} from './common/SecurityConfig';

// AuthHardening is isomorphic — safe for browser use (no Node.js deps)
export { AuthHardening } from './common/AuthHardening';
export type {
  AuthHardeningConfig,
  LockoutResult,
} from './common/AuthHardening';
