# Auth Hardening - @donotdev/security

Authentication and session security rules. Maps to `AuthHardening` and `DndevSecurity` framework utilities.

## Brute Force Protection

**Rule:** All authentication endpoints MUST have brute-force lockout. No exceptions.

**Framework:** `AuthHardening` enforces lockout after N failed attempts (default: 5 attempts, 15 min lockout). Configurable via `DndevSecurity` constructor.

**Configuration:**
```typescript
const security = new DndevSecurity({
  lockout: {
    maxAttempts: 5,        // attempts before lockout
    lockoutMs: 15 * 60000, // lockout duration
  },
});
```

**Anti-pattern:** Login endpoint without lockout. Lockout by IP only (shared IPs lock out legitimate users). Instant unlock on password reset (allows lockout bypass).

**Review flag:** Check that `DndevSecurity` is wired to auth provider. Verify lockout config matches sensitivity (financial apps: 3 attempts, 30 min).

## Session Management

**Rule:** Sessions MUST expire after idle timeout. No permanent sessions.

**Framework:** `DndevSecurity` enforces session timeout (default: 8h idle). Provider-level session management (Supabase Auth / Firebase Auth handles token refresh).

**Configuration:**
```typescript
const security = new DndevSecurity({
  sessionTimeoutMs: 8 * 60 * 60 * 1000, // 8 hours
});
```

**Anti-pattern:** `rememberMe` without expiry. Storing session tokens in `localStorage` (XSS-vulnerable). Custom session management instead of provider SDK. Disabling token refresh to "simplify" auth.

**Review flag:** Grep for `localStorage.setItem` with auth-related keys. Check for custom token management bypassing provider.

## MFA Enforcement

**Rule:** Sensitive entities and admin operations SHOULD require MFA. Financial/health data MUST require MFA.

**Framework:** Entity-level MFA via `requireMfa` in security config. Enforced at CRUD layer - operations on protected entities fail if user has no MFA.

**Configuration:**
```typescript
const paymentEntity = defineEntity({
  security: {
    requireMfa: 'admin', // 'admin' | 'manager' | 'user'
  },
});
```

**Provider setup:**
- Supabase: Dashboard > Auth > Multi Factor Authentication > Enable TOTP
- Firebase: Console > Authentication > Multi-factor Auth > Enable

**Anti-pattern:** No MFA on admin panels. MFA check only at login (not per-operation for sensitive resources). Client-side MFA check without server verification.

## Token Handling

**Rule:** Auth tokens handled exclusively by provider SDKs. Never parse, store, or transmit tokens manually.

**Framework:** Supabase SDK and Firebase SDK manage token lifecycle (creation, refresh, revocation). Framework auth layer wraps provider SDK - no raw token handling.

**Anti-pattern:** Extracting JWTs from cookies and parsing manually. Storing tokens in state management (Redux/Zustand). Passing tokens in URL query parameters. Custom token refresh logic.

**Review flag:** Grep for `jwt`, `token`, `bearer` in application code outside auth provider setup. Check for manual `Authorization` header construction.

## Password Policy

**Rule:** Password requirements enforced at provider level. Framework does not store or validate passwords.

**Framework:** Auth providers (Supabase, Firebase) enforce password policy. Framework delegates entirely - never touches raw credentials.

**Anti-pattern:** Custom password validation in application code. Storing password hashes in application database. Password hints or security questions (insecure pattern).

**Review flag:** Grep for `password` in entity fields or database schemas. Should only appear in auth provider config, never in application data model.
