# GoreeCloud Identity Security Review Boundary

GoreeCloud Identity inherits authentik's mature authentication and identity-provider engine. GoreeCloud hardening must preserve that security boundary unless a separately reviewed change has a demonstrated security or correctness requirement.

## Protected upstream semantics

The GoreeCloud product layer must not silently change OAuth/OIDC/SAML protocol handling, password verification, WebAuthn/passkey semantics, MFA enforcement, policy evaluation, session persistence, cryptographic algorithms, signing/encryption key handling, database migrations, CSRF protections, redirect validation, recovery enforcement, or rate-limit/abuse behavior.

## Secure defaults

Production configuration must use least privilege; separate ordinary and administrative identities; avoid shared administrator accounts; keep reusable secrets out of source and ordinary documentation; restrict backend publication to the approved GoreeCloud private-service path; and ensure monitoring, logging, and health checks do not disclose authentication secrets.

## Required security evidence

Before Stable acceptance, the exact release candidate must have passing applicable static analysis, protocol-conformance, migration, dependency-vulnerability, and build validation; manually validated authentication, authorization, recovery, enrollment, denial, and session behaviors; backup/restore and signing-material recovery evidence; break-glass proof; and an independently monitored target deployment.

Wardveil Security by GoreeCloud may summarize these controls but does not replace them.
