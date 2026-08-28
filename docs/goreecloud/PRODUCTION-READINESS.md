# GoreeCloud Identity Production Readiness

GoreeCloud Identity is not production-accepted merely because source code builds, inherited authentik tests pass, or GoreeCloud branding is present. Stable and production acceptance are separate, fail-closed decisions based on evidence from the exact release candidate and target environment.

A required gate that is unknown, skipped, unavailable, or unverified does not count as passing unless a separately documented GoreeCloud exception explicitly applies.

## Source and provenance

- Exact upstream authentik baseline and license obligations are recorded.
- GoreeCloud divergence is documented and reviewable.
- Applicable source, lint, protocol-conformance, migration, security-analysis, and dependency-vulnerability checks pass on the exact candidate.
- Known release-blocking vulnerabilities are corrected or covered by an approved, evidence-based exception.
- Build inputs and release artifacts are traceable to the approved source revision.

## Glaze UI and product identity

- GoreeCloud Identity is the primary user-facing product identity where legally and technically permitted.
- Glaze UI 1.3 Stable conformance covers authentication, account, administration, onboarding/enrollment, recovery, settings, error, loading, empty, denied-access, warning, notification, and other GoreeCloud-controlled surfaces.
- Canvas, Solid, Raised, Glaze, and Overlay surface semantics are used consistently.
- Light, dark, and system appearance behavior are accepted.
- Compact, Medium, Expanded, and Wide layouts are accepted where applicable.
- Keyboard, focus, zoom/reflow, contrast, forced-colors, reduced-motion, reduced-transparency, and assistive-technology behavior are accepted.
- A unique canonical GoreeCloud Identity product mark/icon and required web assets are approved before Stable.
- Any retained upstream production-facing presentation has a documented material exception or legal/technical basis.

## Wardveil Security

- Wardveil Security presentation is evidence-backed and does not replace or obscure the underlying technical authority.
- Security-facing views do not expose reusable secrets or overstate protection.
- Authentication, authorization, session, authenticator, administrative, audit, and vulnerability evidence is available to appropriately authorized administrators.

## Authentication and authorization

- Password flows retained by the approved configuration are validated.
- Passkey/WebAuthn capability is validated when enabled.
- MFA capability is validated where used; no broad mandatory-MFA policy is introduced without separate approval.
- Login, logout, re-authentication, session expiration/revocation, recovery, enrollment, denial, and lockout/rate-limit behavior are validated.
- Administrative accounts and ordinary user identities remain separate according to GoreeCloud policy.
- Application-specific authorization remains application-owned; successful SSO is not treated as authorization to another user's data.

## Privacy and secrets

- Secrets are separated from source, images, ordinary documentation, and logs.
- Production credentials use least privilege and are individually scoped where supported.
- Logs, errors, metrics, health checks, and monitoring avoid unnecessary identity data and secret material.
- No analytics, trackers, third-party font/icon delivery, or unrelated remote UI dependencies are introduced by the GoreeCloud product layer.

## Runtime and network

- The approved container/deployment definition is validated using controlled versions and immutable references where practical.
- Backend ports are not directly exposed to the public internet.
- Private publication is validated through the approved GoreeCloud DNS, NetBird, Caddy, HTTPS, and firewall model.
- Health/readiness checks are useful to operators without leaking sensitive authentication state.
- Database and required supporting services are healthy, least-privilege, monitored, and documented.

## Observability and integration

- Structured service and security evidence satisfies `docs/goreecloud/OBSERVABILITY.md`.
- At least one controlled GoreeCloud application integration passes end-to-end OIDC login, logout, user mapping, denied-access, failure, recovery, and rollback validation.
- Monitoring can detect Identity unavailability independently of Identity itself and can alert through an approved path without embedding authentication secrets.

## Backup, restore, and recovery

- All required persistent state is inventoried.
- Database and required configuration/state are backed up.
- Signing/encryption material required to preserve identity continuity is protected and recoverable.
- An isolated restoration succeeds from approved backup material.
- Restored authentication, authorization, signing, session/recovery behavior, and the first application integration are validated.
- Break-glass administration is tested and documented without weakening ordinary access controls.

## Release and rollback

- Exact release source and artifact identities are recorded.
- Upgrade from the approved predecessor is validated when applicable.
- Rollback or recovery behavior is demonstrated for the initial deployment/integration boundary.
- Manual product/security acceptance is complete.
- Production cutover is approved separately from source validation.
- Post-cutover monitoring and rollback criteria are defined before traffic or users are migrated.

Until every applicable gate passes, GoreeCloud Identity remains a development or release-candidate system and must not be represented as Stable or production-accepted.
