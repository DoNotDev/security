# Gotchas: @donotdev/security

Common mistakes related to authentication, authorization, and SOC2 controls.

---

## Security Imports [Phase 1, 2, 3]

**Server-side security code MUST use `/server` imports.**

```typescript
// CORRECT
import { DndevSecurity } from '@donotdev/security/server';

// WRONG - crashes on deploy
import { DndevSecurity } from '@donotdev/security';
```

The client entry point (`@donotdev/security`) only exports client-safe utilities like `HealthMonitor`. Server-side classes (`DndevSecurity`, `privacyManager`, `AuditLogger`) require the `/server` path.
