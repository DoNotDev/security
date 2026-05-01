# @donotdev/security

Opt-in SOC2-grade security controls for DoNotDev apps — audit logging, rate limiting, PII encryption, anomaly detection, auth hardening, and GDPR privacy management.

> **Opt-in by design.** Baseline safety (brute-force lockout, session timeout) lives in `@donotdev/core` and is always active. This package adds the compliance and observability layer for teams that need SOC2, GDPR, or enterprise-grade audit trails.

## Installation

```bash
bun add @donotdev/security
```

## Import Paths

```typescript
// Client-safe (HealthMonitor, AuthHardening, SecurityContext type)
import { HealthMonitor, AuthHardening } from '@donotdev/security';

// Server-only (DndevSecurity, AuditLogger, PiiEncryptor, etc.)
import { DndevSecurity } from '@donotdev/security/server';
```

## Quick Start

### Zero-config (all baseline controls active)

```typescript
// functions/src/security.ts
import { DndevSecurity } from '@donotdev/security/server';

export const security = new DndevSecurity();
```

Pass to `CrudService` and base functions:

```typescript
import { createBaseFunction } from '@donotdev/functions/firebase';
import { security } from './security';

export const myFunction = createBaseFunction(
  'my-operation',
  schema,
  handler,
  'user',
  undefined, // requiredRole config
  security   // ← opt-in SOC2 audit trail
);
```

### Full SOC2 config

```typescript
export const security = new DndevSecurity({
  // PII field encryption (AES-256-GCM)
  piiSecret: process.env.PII_SECRET,

  // Auth hardening overrides (default: 5 attempts → 15min lockout, 8h session)
  auth: {
    maxAttempts: 3,
    lockoutMs: 30 * 60 * 1000,
  },

  // Data retention (SOC2 P6)
  retention: [
    { collection: 'audit_logs', days: 365 },
    { collection: 'sessions', days: 90 },
  ],

  // Anomaly detection with custom handler
  anomaly: {
    authFailures: 5,
    onAnomaly: (type, count, userId) =>
      notifySlack(`[ANOMALY] ${type} x${count} by ${userId}`),
  },

  // Pluggable rate limit backend (Firestore, Postgres, Redis)
  // Default: in-memory (fine for single-instance, not for serverless)
  rateLimitBackend: {
    check: (key, cfg) => checkRateLimitWithFirestore(key, cfg),
  },
});
```

## Controls

| Control | Default | Config |
|---|---|---|
| Structured audit log (stdout JSON) | ✅ on | `logger` |
| Rate limiting (100 writes / 500 reads per min) | ✅ on | `rateLimit` |
| In-memory rate limit backend | ✅ default | `rateLimitBackend` to swap |
| Brute-force lockout (5 attempts → 15min) | ✅ on | `auth` |
| Session timeout tracking (8h idle) | ✅ on | `auth.sessionTimeoutMs` |
| Anomaly detection (stderr warn) | ✅ on | `anomaly` + `onAnomaly` |
| Secret scrubbing on all log output | ✅ on | — |
| PII field encryption (AES-256-GCM) | ❌ opt-in | `piiSecret` |
| Data retention / right-to-erasure | ❌ opt-in | `retention` |

## Package Structure

```
security/src/
├── client/
│   └── HealthMonitor.ts     # Circuit breaker + uptime tracking (browser-safe)
├── common/
│   ├── AuthHardening.ts     # Re-export stub → canonical impl in @donotdev/core
│   └── SecurityConfig.ts    # Re-exports SecurityContext types from @donotdev/core
└── server/
    ├── DndevSecurity.ts     # Main SOC2 orchestrator (implements SecurityContext)
    ├── AuditLogger.ts       # Structured JSON audit log (stdout / custom transport)
    ├── RateLimiter.ts       # In-memory fixed-window rate limiter
    ├── PiiEncryptor.ts      # AES-256-GCM field-level encryption
    ├── AuthHardening.ts     # Re-export → common/AuthHardening
    ├── AnomalyDetector.ts   # Threshold-based behavioral alerts
    ├── PrivacyManager.ts    # Retention policies + right-to-erasure
    └── SecretValidator.ts   # Secret scrubbing for log output
```

> **`AuthHardening` canonical implementation** lives in `@donotdev/core` (always installed).
> `@donotdev/security` re-exports it for backwards compatibility.
> Firebase and Supabase providers import directly from `@donotdev/core` — no forced security dep.

## SecurityContext Interface

`DndevSecurity` implements `SecurityContext` from `@donotdev/core`:

```typescript
interface SecurityContext {
  audit(event: Omit<AuditEvent, 'timestamp'>): void | Promise<void>;
  checkRateLimit(key: string, operation: 'read' | 'write'): Promise<void>;
  encryptPii<T>(data: T, piiFields: string[]): T;
  decryptPii<T>(data: T, piiFields: string[]): T;
  authHardening?: AuthHardeningContext;
}
```

Any object implementing this interface can be passed as `security` — no hard dep on this package.

## Audit Event Types

Covers SOC2 CC6, CC7, C1, P1–P8:

```typescript
type AuditEventType =
  | 'auth.login.success' | 'auth.login.failure' | 'auth.logout'
  | 'auth.locked' | 'auth.unlocked' | 'auth.session.expired'
  | 'auth.mfa.enrolled' | 'auth.mfa.challenged'
  | 'auth.password.reset' | 'auth.role.changed'
  | 'crud.create' | 'crud.read' | 'crud.update' | 'crud.delete'
  | 'pii.access' | 'pii.export' | 'pii.erase'
  | 'rate_limit.exceeded' | 'anomaly.detected' | 'config.changed';
```

## PII Encryption

Mark fields for encryption in your entity definition, then pass `security` to `CrudService`:

```typescript
// Entity definition
const UserEntity = defineEntity('users', {
  fields: { email: field.email(), ssn: field.string() },
  security: { piiFields: ['email', 'ssn'] },
});

// Service setup
const security = new DndevSecurity({ piiSecret: process.env.PII_SECRET });
crudService.setSecurity(security);
// email + ssn are now transparently encrypted at rest
```

## Pluggable Rate Limit Backend

For serverless/distributed deployments where in-memory state is lost between invocations:

```typescript
import { checkRateLimitWithFirestore } from '@donotdev/functions/shared';

const security = new DndevSecurity({
  rateLimitBackend: {
    check: (key, cfg) => checkRateLimitWithFirestore(key, cfg),
  },
});
```

Implement `RateLimitBackend` from `@donotdev/core` for custom backends (Redis, Postgres, etc.):

```typescript
import type { RateLimitBackend } from '@donotdev/core';

const redisBackend: RateLimitBackend = {
  async check(key, { maxAttempts, windowMs, blockDurationMs }) {
    // your Redis logic
    return { allowed: true, remaining: 99, resetAt: null, blockRemainingSeconds: null };
  },
};
```

## License

All rights reserved. The DoNotDev framework and its premium features are the exclusive property of **Ambroise Park Consulting**.

© Ambroise Park Consulting – 2025
