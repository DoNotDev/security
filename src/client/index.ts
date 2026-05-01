// packages/security/src/client/index.ts

export { HealthMonitor } from './HealthMonitor';
export type {
  HealthMonitorConfig,
  HealthStatus,
  CircuitBreakerConfig,
} from './HealthMonitor';

// Re-export common types for client consumers
export type {
  SecurityContext,
  AuditEvent,
  AuditEventType,
} from '../common/SecurityConfig';

// AuthHardening is isomorphic — safe for browser use (no Node.js deps)
export { AuthHardening } from '../common/AuthHardening';
export type {
  AuthHardeningConfig,
  LockoutResult,
} from '../common/AuthHardening';
