# GoreeCloud Identity SSO Boundary

GoreeCloud Identity provides single sign-on as a convenience and consistency layer across approved GoreeCloud applications, but SSO must not collapse application authorization or recovery boundaries.

## SSO principles

- OIDC/OAuth 2.0 is preferred for modern first-party GoreeCloud integrations.
- Each relying application retains its own authorization decisions.
- Each application registration should remain independently identifiable and narrowly scoped.
- Logout, session revocation, provider failure, and denied access must be tested rather than assumed.
- A relying application must not fall back to unauthenticated access when Identity is unavailable.

## Recovery

Identity failure may affect multiple applications, so SSO convenience increases the importance of independent Identity recovery, break-glass administration, monitoring, and rollback.
