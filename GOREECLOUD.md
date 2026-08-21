# GoreeCloud Identity

GoreeCloud Identity is the planned long-term authentication and identity authority for GoreeCloud applications and services.

This repository is a GoreeCloud-maintained fork of [`goauthentik/authentik`](https://github.com/goauthentik/authentik). The project intentionally retains authentik's mature identity-provider foundation while GoreeCloud develops a controlled product layer, Glaze UI integration, deployment policy, recovery model, and application-integration contracts.

## Project role

GoreeCloud Identity is responsible for establishing and authenticating platform identities. Participating applications remain responsible for their own authorization, data ownership, and application-specific permissions.

The intended control layers are:

1. **NetBird** controls approved private-network connectivity.
2. **GoreeCloud Identity** authenticates an approved human or service identity.
3. **Each application** authorizes what that identity may access or change.

Single sign-on must not collapse these boundaries.

## Initial integration direction

OpenID Connect and OAuth 2.0 are the preferred modern integration paths for GoreeCloud-controlled applications where appropriate. Additional upstream-supported identity protocols may be retained when they satisfy a documented GoreeCloud requirement.

Planned platform capabilities include:

- individual user identities rather than shared family accounts;
- multi-factor authentication;
- passkeys/WebAuthn where supported;
- session visibility and revocation;
- application/client registration;
- groups and role mappings;
- service or machine identities where justified;
- auditable authentication events;
- recoverable administrative access.

Protocol and feature support must be validated against the exact upstream baseline before GoreeCloud records a capability as implemented.

## Product experience

The long-term product name is **GoreeCloud Identity**. GoreeCloud-controlled user-facing surfaces should progressively adopt the Glaze UI design language while preserving accessibility, security, upstream maintainability, and legal obligations.

Normal family users should not need to understand identity-provider implementation terminology to sign in, enroll MFA or passkeys, review sessions, recover an account, or manage basic account security.

## Security boundary

Identity infrastructure is security-critical. GoreeCloud will avoid unnecessary modification of mature protocol and cryptographic behavior. Customization should prefer supported configuration, templates, themes, extension points, and upstream-compatible changes before deep source divergence.

GoreeCloud Identity must maintain an independently documented break-glass recovery path. Recovery must not depend exclusively on successfully authenticating through the failed identity service itself.

Passwords, client secrets, signing material, recovery credentials, tokens, private keys, SMTP credentials, and other reusable secrets must never be committed to this repository.

## Deployment direction

The planned deployment model is Docker and Docker Compose. The long-term production placement is the GoreeCloud Infrastructure Services VM. The planned private product hostname is `identity.goreecloud.com`.

Production deployment is not authorized merely because this fork exists. Before production acceptance, GoreeCloud will validate the exact upstream baseline, licensing, builds, persistence, backups, restores, break-glass access, private publication, monitoring, security controls, and at least one end-to-end application integration.

## Upstream relationship

See [`UPSTREAM.md`](UPSTREAM.md) for the fork-maintenance contract, provenance rules, and synchronization principles.

## Current status

**Status: Foundation / upstream evaluation.**

The fork exists and the GoreeCloud project boundary is being established. No production cutover or GoreeCloud-wide authentication migration is implied by this repository state.
