# GoreeCloud Identity — Repository Specifications

Status: Development  
Canonical project record: `GoreeCloud/Projects/Project Specification — Identity`  
Repository: `GoreeCloud/goreecloud-identity`

## Product authority

GoreeCloud Identity is the GoreeCloud platform system responsible for identity, authentication, authorization, accounts, devices, credentials, sessions, and delegated authority. The user and administrative surface is Identity Center.

## Native implementation mandate

The long-term platform must be an original GoreeCloud-owned implementation. The current repository contains an upstream-derived transitional runtime and may use that code only for continuity, compatibility, migration, security reference, or rollback while native contracts and implementation replace it. The upstream runtime is not the permanent GoreeCloud architecture.

## Current GoreeCloud-owned source contracts

- Short-lived, narrowly scoped GoreeCloud Mesh service JWT issuance bound to verified workload principals.
- Public-only JWKS publication with fail-closed key-loading behavior and public-only retained rotation keys.
- Provider-independent exact-handle consumer resolution with explicit discoverability and per-service disclosure policy.
- Privacy-preserving unresolved behavior that does not distinguish private, unauthorized, and nonexistent accounts.

## Required native capabilities

- Account creation, lifecycle, suspension/deletion, recovery, and portability.
- OIDC/OAuth-style application authentication and authorization contracts.
- Sessions, devices, credentials, passkeys/security keys, and recovery credentials.
- Workload/service identity and delegated authority.
- Auditing, risk/security controls, administrative policy, and user control.
- Privacy Shield, Wardveil Security, Everkeep, GoreeCloud Mesh, and Glaze UI 2.0+ integration.

## Consumer-directory requirements

- Exact user-supplied handle lookup only by default.
- No default browsable, prefix, fuzzy, or bulk account directory.
- Account discoverability must be explicit.
- Requesting-service disclosure must be explicit and scoped.
- Returned data must be minimized to what the consumer requires.
- Negative results must avoid leaking whether a private account exists.

## Acceptance boundary

The current exact-handle module and Mesh credential modules are Development source contracts, not proof of a complete native Identity service, production persistence, production consumer HTTP endpoints, GoreeCloud-wide SSO, or Stable deployment. Production claims require focused GoreeCloud-owned CI, security/privacy acceptance, deployment evidence, and current platform integration acceptance.