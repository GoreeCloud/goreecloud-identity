# GoreeCloud Network Application Registration Contract

**Status:** Development contract — runtime registration and production acceptance pending.

This directory defines the Identity-owned registration boundary required before GoreeCloud Network may advance from its current source-level Identity consumer boundary toward authenticated administrative mutation.

## Why this exists

GoreeCloud Network already contains a fail-closed OAuth token-introspection consumer and a bounded runtime verifier. Those Network-side components cannot create or approve their own identity authority. The authoritative application-registration contract therefore belongs in GoreeCloud Identity.

The machine-readable contract is `network-application-registration.v1.json`. It defines the current Development expectations that can be verified without storing reusable secrets:

- application identity: `goreecloud-network`;
- expected issuer: `https://identity.goreecloud.com/application/o/network/`;
- resource audience: `goreecloud-network`;
- Network administrator scope: `goreecloud.network.admin`;
- server-side introspection client identity: `goreecloud-network-server`;
- runtime-only handling of the confidential introspection credential;
- explicit `productionAccepted: false` semantics; and
- the broader runtime checks that remain required beyond one successful token-introspection probe.

## Current boundary

This contract does **not** create a live application registration. It does not contain a client secret. It is not loaded automatically by the transitional authentik-derived runtime. It does not approve production SSO.

Interactive login registrations for the Web Dashboard, Android, Google TV, and iOS surfaces remain unimplemented because Network does not yet have an accepted interactive Identity flow or final redirect-URI contract. Their protocol/redirect details must be established and independently validated before they are added here.

The current server-introspection contract is intentionally separate from future interactive clients. The server client is confidential and has no redirect URI because its bounded responsibility is authenticating the Network server to the Identity token-introspection endpoint. It does not represent a user-facing login client.

## Validation tool

Run the source-contract validation from the repository root:

```bash
python scripts/goreecloud/validate_network_application_registration.py
```

The command returns minimized JSON evidence with state `contract_valid_runtime_observation_pending` when the source contract is internally consistent.

Once an approved Development Identity runtime contains the Network registration, capture only non-secret observation fields in a local JSON file and validate them with:

```bash
python scripts/goreecloud/validate_network_application_registration.py --observed /path/to/minimized-observation.json
```

A matching observation returns `observed_registration_matches_contract_runtime_acceptance_pending`. It still returns `productionAccepted: false`.

The observed file must not contain a client secret, bearer token, refresh token, ID token, private key, password, recovery code, or other reusable credential material. The validator rejects evidence containing prohibited secret-field names.

## Runtime acceptance sequence

After a real Development registration exists through the approved Identity runtime path:

1. Verify the Identity-side registration against this contract with minimized non-secret evidence.
2. Run GoreeCloud Network's `cmd/network-identity-verify` against that real runtime using a short-lived probe token supplied only for the invocation.
3. Confirm the Network verifier reports `runtime_probe_passed_production_acceptance_pending` and still reports `productionAccepted: false`.
4. Validate the broader application-integration behavior required by the canonical Identity architecture, including client registration, issuer/discovery, audience, authority scope, session expiration, disabled-account behavior, outage behavior, recovery, rollback, and interactive login/logout/MFA behavior when those flows exist.
5. Record runtime acceptance only after the required independent evidence exists. Do not infer acceptance from source files, one successful probe, or a configured client alone.

## Native migration boundary

The current repository still contains transitional authentik-derived runtime code. This contract defines GoreeCloud's application-registration semantics and evidence requirements; it does not make authentik the permanent GoreeCloud Identity architecture. A future native Identity implementation must preserve or deliberately migrate the approved contract and its evidence semantics before Network can rely on the replacement runtime.
