# Transitional Upstream Provenance and Retirement Contract

GoreeCloud Identity currently contains source inherited from [`goauthentik/authentik`](https://github.com/goauthentik/authentik). The inherited codebase is transitional migration and reference infrastructure while GoreeCloud develops and accepts original GoreeCloud-owned native Identity services and interfaces.

This document defines how GoreeCloud preserves upstream provenance, licensing, security maintenance, migration safety, and retirement discipline. It does **not** define a permanent maintained-fork architecture.

## Upstream provenance

Historical upstream project: `goauthentik/authentik`

Current GoreeCloud repository: `GoreeCloud/goreecloud-identity`

For every inherited component that remains material to a GoreeCloud runtime, GoreeCloud must be able to identify the relevant upstream baseline and distinguish inherited behavior from GoreeCloud-owned native behavior.

The existence of the repository does not make every upstream `main` commit an automatically approved GoreeCloud change or release.

## Provenance and legal rules

GoreeCloud will:

- retain required upstream copyright, license, attribution, and third-party notices;
- preserve enough Git provenance to identify inherited source and its historical origin;
- avoid rewriting upstream history merely to make inherited code appear GoreeCloud-originated;
- identify GoreeCloud-owned native contracts, services, migration adapters, and product surfaces separately from inherited source;
- preserve licensing distinctions for code GoreeCloud does not own;
- retain migration and rollback evidence while inherited runtime components remain operationally necessary.

Native migration is not a license to erase attribution.

## Native replacement policy

The target architecture is original GoreeCloud-owned native Identity software.

For each inherited capability, GoreeCloud should determine whether it is:

1. a product/application implementation that should be replaced by a GoreeCloud-native component;
2. a temporary compatibility or migration boundary that can be retired after native acceptance;
3. a narrow standards, protocol, or cryptographic foundation whose independent replacement would materially increase security or interoperability risk; or
4. unused inherited code that should be removed when removal is safe and legally/documentarily complete.

A complete upstream application, UI, workflow system, or general product architecture must not be retained merely because replacing it requires engineering work.

## Narrow-foundation exception

GoreeCloud should not write custom cryptography or casually replace mature protocol primitives simply to increase the quantity of GoreeCloud-owned code.

A retained third-party foundation must have a bounded responsibility and a documented reason. The exception should be as narrow as practical and must not become a route to preserving an upstream identity product as the permanent GoreeCloud Identity architecture.

## Transitional update process

While an inherited component remains part of an active GoreeCloud runtime, relevant upstream security fixes and migration changes may still need evaluation.

Before integrating a material upstream change into a transitional component, GoreeCloud should:

1. identify the exact upstream source commit or release;
2. determine whether the affected inherited component is still required or can instead be retired/replaced;
3. review relevant security advisories, migrations, dependency changes, and breaking behavior;
4. compare the change against GoreeCloud-owned integration and migration boundaries;
5. integrate only the change needed to keep the transitional component safe and interoperable;
6. run applicable upstream tests plus GoreeCloud-specific validation for the affected boundary;
7. validate persistent-state migrations when applicable;
8. record the accepted source and evidence when the component remains deployed;
9. keep the prior accepted state recoverable until the change is accepted.

Transitional maintenance must not expand dependency on upstream product architecture without a documented migration necessity.

## Security updates

Relevant security fixes take priority while inherited code remains reachable or deployed. If maintaining a GoreeCloud customization obstructs timely remediation, GoreeCloud should prefer reducing or removing that inherited dependency rather than accumulating deeper product divergence.

The upstream `SECURITY.md` remains relevant to inherited authentik code. GoreeCloud-native defects, contracts, deployment boundaries, and migration adapters are governed by GoreeCloud security processes and Wardveil Security requirements.

## Licensing baseline

The repository currently preserves upstream licensing. The root `LICENSE` and component-specific license records remain authoritative for inherited source and third-party components.

Rebranding or native migration does not authorize removal of required notices or relicensing of code that GoreeCloud does not own. When inherited components are removed, their applicable historical licensing/provenance records must remain available where required for audit and compliance.

## Retirement evidence

An inherited runtime component may be retired when its required GoreeCloud capability has a native replacement with sufficient evidence for the target environment. Retirement should record:

- the inherited component and upstream baseline being removed;
- the native GoreeCloud replacement and exact revision;
- migration and compatibility behavior;
- persistence/data migration when applicable;
- security and privacy acceptance;
- backup/recovery and rollback coverage;
- representative application integration;
- any narrow third-party standards/crypto foundation intentionally retained.

## Release identity during migration

While a GoreeCloud Identity release still contains material inherited authentik source, release records should identify both the GoreeCloud release/revision and the applicable inherited upstream baseline. Once a native release no longer depends on the upstream product architecture, release identity should reflect that native state while historical provenance remains preserved.
