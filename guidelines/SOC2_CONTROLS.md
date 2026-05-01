# SOC2 Trust Services Criteria - @donotdev/security

SOC2 controls mapped to framework utilities. Each control specifies the criteria, what the framework enforces, and what to verify in code review.

## CC6.1 Authentication and Access Control

**Criteria:** Logical and physical access controls to protect against unauthorized access.

**Framework:**
- `AuthHardening`: brute-force lockout (5 attempts / 15 min), session timeout (8h idle).
- `DndevSecurity` orchestrates auth hardening automatically when wired to auth provider.
- MFA enforcement via `requireMfa` in entity security config.

**Review checklist:**
- [ ] `DndevSecurity` wired to auth provider (`auth.setSecurity(security)`)
- [ ] Sensitive entities have `requireMfa` set
- [ ] No custom auth bypassing provider SDK
- [ ] Session timeout configured for compliance (max 8h default)

## CC6.3 Role-Based Access Control

**Criteria:** Access restricted based on roles and responsibilities.

**Framework:**
- Entity-level RBAC via `defineEntity({ security: { roles } })`.
- Field-level visibility per role.
- Supabase: RLS policies enforced at database level.
- Firestore: security rules with default-deny.

**Review checklist:**
- [ ] Every entity with sensitive data has `security.roles` defined
- [ ] Supabase tables have `ENABLE ROW LEVEL SECURITY` in migrations
- [ ] Firestore rules start with `allow read, write: if false` (default-deny)
- [ ] No direct database access bypassing RBAC layer

## CC6.6 Rate Limiting

**Criteria:** Measures to prevent and detect system abuse.

**Framework:**
- `DndevRateLimiter`: in-memory fixed-window rate limiter.
- Default: 100 writes/min, 500 reads/min per user.
- Configurable per `DndevSecurity` constructor.
- Automatically enforced on all CRUD operations when security is wired.

**Review checklist:**
- [ ] `DndevSecurity` wired to `CrudService` (`crudService.setSecurity(security)`)
- [ ] Custom API endpoints have rate limiting (not just CRUD)
- [ ] Rate limits appropriate for entity sensitivity (lower for payments, higher for reads)

## CC7.1 Audit Logging

**Criteria:** Detect and record security-relevant events.

**Framework:**
- `AuditLogger`: structured NDJSON to stdout (pipe to SIEM).
- Events: `crud.create`, `crud.read`, `crud.update`, `crud.delete`, `auth.login`, `auth.login.failure`, `auth.logout`.
- Fields: `timestamp`, `type`, `userId`, `resource`, `resourceId`, `ip`, `details`.
- Automatic when `DndevSecurity` is wired.

**Review checklist:**
- [ ] All CRUD operations produce audit events (automatic via `DndevSecurity`)
- [ ] Auth events logged (login, failure, logout)
- [ ] Stdout piped to persistent logging (Cloud Logging, Datadog, Logflare)
- [ ] No `console.log` used for security events (use `AuditLogger`)
- [ ] PII scrubbed from log details (`scrubSecrets()`)

## CC7.2 Anomaly Detection

**Criteria:** Monitor for anomalous activity and respond.

**Framework:**
- `AnomalyDetector`: threshold-based behavioral alerts.
- Detects: brute-force auth, bulk deletions, auth spikes, impossible travel, privilege escalation attempts.
- `anomalyHandler` callback for alerting (Slack, PagerDuty, SIEM webhook).

**Review checklist:**
- [ ] `anomalyHandler` configured in production `DndevSecurity`
- [ ] Alert destination verified (Slack webhook, SIEM endpoint)
- [ ] Thresholds reviewed for business context (defaults may be too permissive for financial apps)

## CC7.3 Incident Response

**Criteria:** Procedures to respond to identified security incidents.

**Framework:**
- `AnomalyDetector` alerts trigger incident workflow.
- `AuditLogger` provides forensic trail for investigation.
- `HealthMonitor` circuit breaker can isolate failing dependencies.

**Review checklist:**
- [ ] Incident runbook exists and references audit log location
- [ ] Anomaly alerts route to on-call channel
- [ ] Circuit breaker configured for critical external dependencies

## A1 Availability

**Criteria:** System available for operation and use as committed.

**Framework:**
- `HealthMonitor`: circuit breaker with configurable failure/success thresholds.
- Liveness probe via `checkLiveness()` for health endpoints.
- Graceful degradation - circuit opens after consecutive failures, half-opens to test recovery.

**Review checklist:**
- [ ] `HealthMonitor` wraps external dependency calls (database, APIs)
- [ ] Health endpoint exposed (`/api/health`)
- [ ] Circuit breaker thresholds match SLA (default: 3 failures to open, 2 successes to close)

## C1 Confidentiality

**Criteria:** Confidential information protected as committed.

**Framework:**
- `PiiEncryptor`: AES-256-GCM field-level encryption at rest.
- Entities with personal data declare `piiFields` in security config.
- `PII_SECRET` env var required (min 32 chars). Startup fails if missing when `piiFields` exist.

**Review checklist:**
- [ ] Entities with email, phone, SSN, health data have `piiFields` declared
- [ ] `PII_SECRET` in production env (not hardcoded, not in code)
- [ ] Encryption key rotation plan documented
- [ ] Decrypted PII never logged (verify with `scrubSecrets()`)

## P1-P4 Privacy Notice and Consent

**Criteria:** Privacy notice provided, consent obtained, data used only for stated purpose.

**Framework:**
- Entity config declares data purpose via field metadata.
- CRUD layer enforces field-level access per role.

**Review checklist:**
- [ ] Privacy policy URL configured in app
- [ ] Consent collection wired before PII storage
- [ ] Data usage limited to declared purpose in entity config

## P5 Data Quality

**Criteria:** Personal information is accurate, complete, and relevant.

**Framework:**
- Entity validation rules enforce data quality at write time.
- `CrudService` validates required fields, types, and constraints.

**Review checklist:**
- [ ] PII fields have appropriate validation rules
- [ ] Update operations validate completeness

## P6 Retention

**Criteria:** Personal information retained only as long as necessary.

**Framework:**
- `PrivacyManager`: retention policies via `retention.days` in entity security config.
- `shouldPurge(createdAt, retentionDays)` for scheduled cleanup.
- Audit logs: recommended 365-day retention minimum for compliance.

**Review checklist:**
- [ ] Entities with PII have `retention.days` configured
- [ ] Scheduled purge function deployed (Cloud Function / cron)
- [ ] Audit log retention meets compliance requirement (min 1 year)

## P7-P8 Data Disclosure and Erasure

**Criteria:** Personal information disclosed only to authorized parties. Right to erasure honored.

**Framework:**
- `PrivacyManager.eraseUser(userId, callback)`: GDPR Art. 17 right-to-erasure.
- Caller provides per-collection erasure logic.
- Audit event logged for erasure operations.

**Review checklist:**
- [ ] Account deletion handler calls `privacyManager.eraseUser()`
- [ ] All collections with user PII covered in erasure callback
- [ ] Erasure audit event captured for compliance proof
- [ ] Third-party data sharing documented and erasure propagated
