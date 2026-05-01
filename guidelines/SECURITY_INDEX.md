# Security Guidelines - @donotdev/security

Actionable security rulesets for code review and generation. Each guideline maps compliance requirements to framework patterns.

Query specific topics: `get_guideline("owasp")`, `get_guideline("soc2")`, `get_guideline("data_protection")`, `get_guideline("auth_hardening")`, `get_guideline("input_validation")`.

Drill into sections: `get_guideline("owasp:injection")`, `get_guideline("soc2:audit")`, etc.

## OWASP Top 10 (2021)

OWASP_TOP_10.md - Web application security risks mapped to framework mitigations. Covers: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Data Integrity, Logging Failures, SSRF.

## SOC2 Controls

SOC2_CONTROLS.md - Trust Services Criteria (CC6, CC7, A1, C1, P1-P8) mapped to `@donotdev/security` utilities. Each control references the framework class that enforces it.

## Data Protection

DATA_PROTECTION.md - PII field encryption, secret detection, log scrubbing, environment variable handling. Covers AES-256-GCM field-level encryption via `PiiEncryptor`, secret patterns via `SecretValidator`.

## Auth Hardening

AUTH_HARDENING.md - Brute-force lockout, session timeout, MFA enforcement, token handling. Covers `AuthHardening`, `DndevSecurity` orchestrator, provider-level MFA.

## Input Validation

INPUT_VALIDATION.md - Server boundary validation, client boundary sanitization, file upload rules, URL parameter handling. Framework-agnostic rules enforced at system boundaries.
