# GoreeCloud Identity — Features

## Implemented GoreeCloud-owned Development contracts

- Verified-workload-bound GoreeCloud Mesh service-token issuance.
- RS256 signing with bounded token lifetime and allowed-scope ceilings.
- Public JWKS endpoint with fail-closed runtime key handling.
- Public-only retained verification keys for signing-key rotation.
- Exact consumer handle normalization and lookup contract.
- Explicit discoverability and per-service disclosure controls.
- Minimal subject/handle/display-name consumer projection.
- Indistinguishable negative resolution for private, unauthorized, and nonexistent accounts.

## Transitional capabilities

The repository also contains extensive inherited authentik identity-provider functionality. These capabilities are transitional and are not automatically classified as native GoreeCloud features or production-accepted GoreeCloud Identity behavior.

## Required / incomplete native work

- Native account and profile persistence.
- Native browser/app session service and OIDC/OAuth application integration.
- Native device, passkey/security-key, credential, recovery, and delegated-authority lifecycles.
- Persistent consumer-directory policy and authenticated consumer-resolution API.
- First-party administrative Identity Center.
- Stable Glaze UI 2.0+ user/admin experience.
- Focused Wardveil, Privacy Shield, Everkeep, Mesh, audit, recovery, and production deployment acceptance.