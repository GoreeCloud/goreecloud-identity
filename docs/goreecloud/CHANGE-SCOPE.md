# GoreeCloud Identity Product-Hardening Change Scope

This branch is intentionally limited to the GoreeCloud product, security, observability, accessibility, reliability, and release-governance layer.

It does not authorize or implement changes to OAuth/OIDC/SAML semantics, password verification, WebAuthn/passkey behavior, MFA enforcement, authorization policy evaluation, session persistence, cryptographic algorithms, signing/encryption behavior, database migrations, production DNS, Caddy, NetBird, firewall, database credentials, or production cutover.

Any future change in those areas requires its own reviewed scope, security analysis, validation evidence, and recovery/rollback plan.
