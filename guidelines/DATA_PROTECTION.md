# Data Protection - @donotdev/security

Rules for PII handling, encryption, secret management, and log hygiene. Every rule maps to a framework utility or a mandatory code pattern.

## PII Field Declaration

**Rule:** Every entity storing personal data MUST declare `piiFields` in its security config.

**Framework:** `PiiEncryptor` (AES-256-GCM) encrypts declared fields at rest transparently. Decryption happens on read through `CrudService`.

**Fields that require declaration:** email, phone, dateOfBirth, ssn, nationalId, healthData, financialData, biometric, address, fullName (when combined with other identifiers).

**Pattern:**
```typescript
export const userEntity = defineEntity({
  name: 'User',
  security: {
    piiFields: ['email', 'phone', 'dateOfBirth'],
  },
  fields: { /* ... */ },
});
```

**Anti-pattern:** Storing PII without `piiFields`. Rolling custom encryption. Encrypting at the application layer instead of entity config.

## Encryption Key Management

**Rule:** `PII_SECRET` must be a cryptographically random string (min 32 chars), stored in environment variables only.

**Framework:** `DndevSecurity` constructor validates `PII_SECRET` presence and length at startup. Fails loud if `piiFields` exist without it.

**Pattern:**
```bash
# Generate: openssl rand -hex 32
PII_SECRET=a1b2c3d4e5f6...  # 64 hex chars = 32 bytes
```

**Anti-pattern:** Hardcoded keys in source. Short or predictable keys. Keys in `.env` committed to git. Shared keys across environments.

**Review flag:** Grep for `PII_SECRET` in source files (should only appear in `.env.example` as placeholder).

## Secret Detection

**Rule:** Never log, transmit, or store secrets in plaintext. Scrub before any output.

**Framework:** `SecretValidator` detects 15+ patterns: AWS keys, Firebase keys, Supabase keys, JWTs, private keys, bearer tokens, basic auth, connection strings, API keys with common prefixes.

**Pattern:**
```typescript
import { scrubSecrets } from '@donotdev/security/server';
const safeLog = scrubSecrets(rawString); // replaces matches with [REDACTED]
```

```typescript
import { assertNoSecrets } from '@donotdev/security/server';
assertNoSecrets(configOutput); // throws if secrets detected
```

**Anti-pattern:** Logging request headers verbatim. Logging full error objects that may contain tokens. `JSON.stringify(process.env)` anywhere.

**Review flag:** Grep for `process.env` in log statements. Check error handlers for unfiltered `error.message` or `error.stack` that may contain connection strings.

## Log Scrubbing

**Rule:** All structured logs must pass through `scrubSecrets()` before output. Audit events managed by `AuditLogger` are safe by design.

**Framework:** `AuditLogger` handles security events with a safe schema (no free-form fields that could contain secrets). Custom log output must use `scrubSecrets()`.

**Pattern:**
```typescript
// AuditLogger events are safe (structured schema)
auditLogger.log({ type: 'crud.create', userId, resource, resourceId });

// Custom logs must be scrubbed
logger.info(scrubSecrets(`User ${userId} accessed ${resource}`));
```

**Anti-pattern:** `console.log(JSON.stringify(request))`. Logging full request/response bodies. Error messages with database connection strings.

## Environment Variables

**Rule:** Secrets live in environment variables only. Never in code, config files committed to git, or client-side bundles.

**Mandatory env vars for security:**
- `PII_SECRET` - PII encryption key (when `piiFields` used)
- Auth provider credentials (Supabase URL/key, Firebase config)
- SIEM webhook URL (for anomaly alerts)

**Client-side safety:**
- Vite: only `VITE_` prefixed vars reach the client
- Next.js: only `NEXT_PUBLIC_` prefixed vars reach the client
- NEVER prefix secret keys with `VITE_` or `NEXT_PUBLIC_`

**Anti-pattern:** `VITE_PII_SECRET` (exposes to client). Committing `.env` to git. Using `.env.local` in CI without secrets manager.

**Review flag:** Grep for `VITE_.*SECRET`, `VITE_.*KEY`, `NEXT_PUBLIC_.*SECRET` in env files.
