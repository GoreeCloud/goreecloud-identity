# GoreeCloud Identity Authentication Boundary

GoreeCloud Identity centralizes authentication for approved GoreeCloud applications while preserving mature authentik security semantics.

## Supported direction

OIDC/OAuth 2.0 is the preferred modern application integration. Password authentication may remain available where approved. Passkey/WebAuthn and MFA capabilities are validated when enabled. No broad mandatory-MFA rule is introduced solely by this product layer.

## Required validation

Production acceptance must validate login, logout, re-authentication, recovery, enrollment, lockout/rate-limit behavior, passkey/WebAuthn when enabled, MFA when enabled, session expiration/revocation, denied access, and relying-application callback/error handling.

## Security rule

Presentation changes must never alter server-side authentication decisions, credential verification, authenticator semantics, recovery enforcement, CSRF protections, redirect validation, or abuse controls without a separately reviewed security change.
