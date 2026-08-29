# GoreeCloud Identity

GoreeCloud Identity is the platform authority for GoreeCloud identity, authentication, authorization, accounts, devices, credentials, sessions, and delegated authority.

## Status

**Active Development — transitional upstream-derived runtime plus GoreeCloud-owned native contracts.**

This repository currently contains substantial code inherited from the authentik project and remains useful as a transition, compatibility, security-reference, and migration host. It is **not** the permanent architectural definition of GoreeCloud Identity. Governing GoreeCloud instructions require the long-term Identity platform to be an original GoreeCloud-owned implementation; upstream architecture may not silently become the final native product.

Current GoreeCloud-owned work in this repository includes narrowly scoped Mesh service-token issuance/JWKS behavior and a provider-independent exact-handle consumer directory contract. These contracts are intended to survive native migration even if the transitional host implementation is replaced.

The repository is not yet approved as GoreeCloud-wide production Identity infrastructure.

## Current GoreeCloud contracts

- GoreeCloud project boundary: [`GOREECLOUD.md`](GOREECLOUD.md)
- GoreeCloud architecture baseline: [`docs/goreecloud/ARCHITECTURE.md`](docs/goreecloud/ARCHITECTURE.md)
- UI customization boundaries: [`docs/goreecloud/UI-CUSTOMIZATION.md`](docs/goreecloud/UI-CUSTOMIZATION.md)
- Validation gates: [`docs/goreecloud/VALIDATION.md`](docs/goreecloud/VALIDATION.md)
- Transitional upstream maintenance contract: [`UPSTREAM.md`](UPSTREAM.md)
- GoreeCloud Mesh service credential source: `authentik/goreecloud/mesh_service_token.py`
- Privacy-preserving consumer directory contract: `authentik/goreecloud/consumer_directory.py`

## Native product requirements

GoreeCloud Identity must ultimately provide first-party account/session/device authority with clear contracts for OIDC/OAuth-style application authentication, service/workload credentials, account recovery, device and credential lifecycle, delegated authority, auditing, privacy controls, and integration with Wardveil Security, Privacy Shield, Everkeep, GoreeCloud Mesh, and Glaze UI 2.0 or newer.

Consumer discovery must not become a browsable account directory by default. The current exact-handle contract intentionally supports only a user-supplied exact handle, explicit account discoverability, explicit requesting-service disclosure, and a minimal consumer projection. Private, unauthorized, and nonexistent accounts are intentionally indistinguishable to consumers.

## Upstream transition boundary

The inherited authentik codebase remains subject to its original licensing, attribution, and security requirements. GoreeCloud continues to track relevant upstream security fixes while this transition host remains in use. See [`LICENSE`](LICENSE), [`website/LICENSE`](website/LICENSE), [`authentik/enterprise/LICENSE`](authentik/enterprise/LICENSE), and [`SECURITY.md`](SECURITY.md).

Upstream installation examples and upstream workflow results are not automatic GoreeCloud production acceptance. GoreeCloud-owned validation and deployment evidence are required independently.

## Current limitations

- The native GoreeCloud Identity runtime is not complete.
- The exact-handle directory contract is source-level Development work; persistent account-policy storage and authenticated consumer HTTP integration are not yet implemented by this branch.
- Existing broader upstream-derived CI can contain failures unrelated to the narrow GoreeCloud contract surface and must not substitute for focused native-contract acceptance.
- Production GoreeCloud-wide SSO, recovery, device/session administration, and Stable Glaze UI 2.0 acceptance are not established by this repository state.

## Repository documentation

See [`SPECIFICATIONS.md`](SPECIFICATIONS.md), [`FEATURES.md`](FEATURES.md), [`BENEFITS.md`](BENEFITS.md), and [`COMPETITIVE-OBJECTIVES.md`](COMPETITIVE-OBJECTIVES.md) for the repository-level GoreeCloud product contract.