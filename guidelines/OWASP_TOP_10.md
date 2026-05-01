# OWASP Top 10 (2021) - @donotdev/security

Web application security risks mapped to DoNotDev framework mitigations. Each category includes the risk, framework pattern, anti-patterns to flag in review, and what to grep for.

## A01 Broken Access Control

**Risk:** Users act outside intended permissions. Missing authorization checks, IDOR, CORS misconfiguration.

**Framework:**
- Entity-level RBAC via `defineEntity({ security: { roles } })` - field visibility and write access per role.
- Supabase: Row Level Security (RLS) policies. Firestore: default-deny rules (`allow read, write: if false`).
- `DndevSecurity` enforces role checks on every CRUD operation automatically.

**Anti-pattern:** Direct database queries bypassing the CRUD layer. Manual role checks instead of declarative entity config. `allow read, write: if true` in Firestore rules.

**Review flag:** Grep for raw `db.from(` / `collection(` calls that bypass `CrudService`. Check Firestore rules for permissive `if true`.

## A02 Cryptographic Failures

**Risk:** Sensitive data exposed due to weak/missing encryption. Cleartext PII, weak algorithms, missing TLS.

**Framework:**
- `PiiEncryptor` provides AES-256-GCM field-level encryption at rest for fields marked `piiFields` in entity config.
- `SecretValidator.scrubSecrets()` detects 15+ secret patterns (API keys, tokens, passwords) in strings before logging.
- `PII_SECRET` env var (min 32 chars) required when `piiFields` are defined.

**Anti-pattern:** Storing email/phone/SSN without `piiFields` declaration. Rolling custom encryption. Hardcoded encryption keys. Using MD5/SHA1 for sensitive data.

**Review flag:** Grep for `email`, `phone`, `ssn`, `dateOfBirth` in entity fields without `piiFields`. Check for `crypto.createCipher` (deprecated, use `createCipheriv`).

## A03 Injection

**Risk:** Untrusted data sent to interpreter. SQL injection, NoSQL injection, command injection, template injection.

**Framework:**
- Supabase SDK uses parameterized queries by default - all `.eq()`, `.in()`, `.filter()` are safe.
- Firestore SDK uses typed references - no raw query strings.
- `CrudService` mediates all data access, preventing direct query construction.

**Anti-pattern:** String concatenation/template literals in SQL: `` `SELECT * FROM ${table} WHERE id = '${id}'` ``. Raw `eval()`. Shell commands with user input via `child_process.exec()`.

**Review flag:** Grep for template literals containing SQL keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `FROM`, `WHERE`). Grep for `eval(`, `new Function(`, `child_process`.

## A04 Insecure Design

**Risk:** Missing security controls by design. No rate limiting, no abuse prevention, no threat modeling.

**Framework:**
- `DndevRateLimiter` enforces per-user write/read limits (default 100 writes/min, 500 reads/min).
- `AnomalyDetector` flags behavioral anomalies (bulk deletes, auth spikes, impossible travel).
- `HealthMonitor` circuit breaker prevents cascade failures.
- Entity config is declarative - security is part of the schema, not an afterthought.

**Anti-pattern:** CRUD endpoints without rate limiting. No anomaly detection on sensitive operations. Unbounded list queries without pagination.

**Review flag:** Check that `DndevSecurity` is wired into `CrudService` and auth. Verify rate limit config exists for write-heavy entities.

## A05 Security Misconfiguration

**Risk:** Default credentials, unnecessary features enabled, verbose error messages, missing security headers.

**Framework:**
- Framework enforces opinionated defaults: default-deny Firestore rules, RLS on Supabase, strict CORS.
- `DndevSecurity` constructor validates config at startup - missing `PII_SECRET` when `piiFields` exist throws immediately.
- Error responses never expose stack traces or internal paths (framework error boundary).

**Anti-pattern:** `Access-Control-Allow-Origin: *` in production. Debug mode in production. Verbose error messages with stack traces in API responses. Default Firebase/Supabase credentials.

**Review flag:** Grep for `*` in CORS config. Check for `console.error` that leaks to client. Check `.env.example` for placeholder secrets that match production values.

## A06 Vulnerable and Outdated Components

**Risk:** Using components with known vulnerabilities. Outdated dependencies, unpatched frameworks.

**Framework:**
- `@donotdev/security` has zero production dependencies - no transitive vulnerability surface.
- Framework packages pin peer dependency ranges and test against latest.
- `dn bundle` validates dependency tree before publishing.

**Anti-pattern:** Ignoring `npm audit` warnings. Pinning to old major versions without security review. Using deprecated Node.js APIs.

**Review flag:** Check `package.json` for outdated peer dependencies. Run `npm audit` in CI.

## A07 Identification and Authentication Failures

**Risk:** Weak authentication, credential stuffing, missing MFA, session fixation.

**Framework:**
- `AuthHardening` enforces brute-force lockout (default 5 attempts, 15 min lockout).
- Session timeout (default 8h idle) via `DndevSecurity`.
- MFA enforcement per entity via `requireMfa` in entity config.
- Auth providers (Supabase Auth, Firebase Auth) handle credential storage - framework never touches raw passwords.

**Anti-pattern:** Custom password storage. Session tokens in localStorage (use httpOnly cookies). Missing lockout on login endpoints. No MFA on admin operations.

**Review flag:** Grep for `localStorage.setItem` with tokens/sessions. Check for custom auth implementations bypassing provider SDKs.

## A08 Software and Data Integrity Failures

**Risk:** Code and infrastructure without integrity verification. Insecure CI/CD, unsigned updates, deserialization attacks.

**Framework:**
- `AuditLogger` creates tamper-evident audit trails (structured NDJSON with timestamps).
- Entity mutations always go through `CrudService` which logs before/after state.
- `assertNoSecrets()` prevents accidental secret exposure in build artifacts.

**Anti-pattern:** `JSON.parse()` on untrusted input without schema validation. Deserializing user-provided objects with `eval`. Missing audit trail on sensitive operations.

**Review flag:** Grep for `JSON.parse` on request bodies without validation. Check for missing audit events on create/update/delete operations.

## A09 Security Logging and Monitoring Failures

**Risk:** Insufficient logging, missing audit trails, no alerting on security events.

**Framework:**
- `AuditLogger` logs all CRUD operations + auth events as structured NDJSON to stdout.
- `AnomalyDetector` triggers alerts on: brute-force attempts, bulk deletions, auth spikes, impossible travel, privilege escalation.
- `anomalyHandler` callback sends alerts to SIEM/Slack/PagerDuty.
- Audit events include: timestamp, type, userId, resource, resourceId, IP.

**Anti-pattern:** Using `console.log` for security events. No structured logging. Missing correlation IDs. Logging PII in plaintext (use `scrubSecrets()` first).

**Review flag:** Grep for `console.log` in auth/CRUD handlers - should use `AuditLogger`. Check that `anomalyHandler` is configured in production. Verify `scrubSecrets()` is called before logging user data.

## A10 Server-Side Request Forgery

**Risk:** Application fetches remote resources without validating user-supplied URLs. Internal service exposure.

**Framework:**
- Framework does not perform arbitrary HTTP fetches - all data access is through typed SDK clients (Supabase, Firebase).
- Edge functions should validate and allowlist outbound URLs.

**Anti-pattern:** `fetch(userProvidedUrl)` without URL validation. Allowing redirects to internal IPs (`127.0.0.1`, `169.254.169.254`, `10.*`). Exposing internal service URLs in client config.

**Review flag:** Grep for `fetch(` with dynamic URLs from user input. Check for internal IP ranges in any URL construction. Verify no internal service URLs in client-side env vars.
