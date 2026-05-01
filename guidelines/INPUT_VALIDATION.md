# Input Validation - @donotdev/security

Validation and sanitization rules for system boundaries. Trust nothing from outside the system boundary.

## Server Boundary

**Rule:** Validate ALL input at the server boundary. Type, shape, range, length. Reject invalid input immediately with clear error messages.

**Framework:** `CrudService` validates entity fields against schema before write. Custom API endpoints must validate manually.

**Pattern:**
```typescript
// Entity validation is automatic via defineEntity field config
const productEntity = defineEntity({
  fields: {
    name: { type: 'string', required: true, maxLength: 200 },
    price: { type: 'number', required: true, min: 0 },
    category: { type: 'enum', values: ['A', 'B', 'C'] },
  },
});
```

```typescript
// Custom endpoints: validate at entry point
function handleWebhook(req: Request) {
  const body = parseAndValidate(req.body, webhookSchema); // throws on invalid
  // ... process validated body
}
```

**Anti-pattern:** Trusting `req.body` shape without validation. Using `as` type assertion on user input. Validating only on client side.

**Review flag:** Grep for `as` casts on `req.body`, `req.params`, `req.query`. Check custom API routes for missing validation.

## Client Boundary

**Rule:** Client-side validation is UX only, never security. Always re-validate on server. Sanitize before render.

**Framework:** Entity field config drives both client-side form validation (UX) and server-side enforcement. Single source of truth.

**Anti-pattern:** Client-only validation for security constraints. Rendering user HTML without sanitization. `dangerouslySetInnerHTML` with user content.

**Review flag:** Grep for `dangerouslySetInnerHTML`. Check that every client validation has a server-side counterpart.

## File Uploads

**Rule:** Validate file type, size, and content on the server. Never trust client-provided MIME type or extension.

**Checklist:**
- [ ] Max file size enforced server-side (not just client `accept` attribute)
- [ ] File type validated by content (magic bytes), not extension
- [ ] Uploaded files stored outside web root / in object storage (Supabase Storage, Cloud Storage)
- [ ] Filenames sanitized (no path traversal: `../`, null bytes)
- [ ] Virus/malware scanning for user-uploaded files in production

**Anti-pattern:** Storing uploads in `/public` directory. Using client-provided filename as storage path. Trusting `Content-Type` header. No size limit.

## URL Parameters

**Rule:** URL parameters are untrusted user input. Validate type and range. Never use in database queries without parameterization.

**Pattern:**
```typescript
// Route param validation
const id = params.id;
if (!id || typeof id !== 'string' || id.length > 36) {
  throw new ValidationError('Invalid ID format');
}
```

**Anti-pattern:** Using URL params directly in queries: `db.from(params.table)`. Open redirects: `redirect(params.returnUrl)` without allowlist. Template injection via URL params.

**Review flag:** Grep for `params.` or `searchParams.` used directly in database calls or redirects.

## API Response Sanitization

**Rule:** API responses must not leak internal state. No stack traces, internal paths, database schemas, or system info in client-facing responses.

**Framework:** Framework error boundary sanitizes errors before client response. Custom error handlers must follow the same pattern.

**Pattern:**
```typescript
// Framework error response (automatic)
{ error: { code: 'NOT_FOUND', message: 'Resource not found' } }

// Never expose internals
{ error: { message: err.message, stack: err.stack } } // WRONG
```

**Anti-pattern:** Returning raw `Error` objects. Including SQL error messages in API responses. Exposing internal service names or paths. `process.env` in error details.

**Review flag:** Grep for `err.stack`, `error.stack`, `err.message` in API response construction. Check error handlers return sanitized messages.
