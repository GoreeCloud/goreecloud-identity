# Upstream Maintenance Contract

GoreeCloud Identity is maintained from the upstream [`goauthentik/authentik`](https://github.com/goauthentik/authentik) project.

This document defines how GoreeCloud preserves provenance, evaluates upstream changes, and limits avoidable divergence.

## Upstream authority

Upstream project: `goauthentik/authentik`

GoreeCloud fork: `GoreeCloud/goreecloud-identity`

Default development baseline: the exact commit or release selected and recorded for a GoreeCloud development cycle.

The existence of this fork does not make every upstream `main` commit an automatically approved GoreeCloud release. GoreeCloud must evaluate and validate the exact baseline used for each release or deployment.

## Provenance rules

GoreeCloud will:

- preserve the GitHub fork relationship whenever practical;
- retain required upstream copyright, license, attribution, and third-party notices;
- record the exact upstream commit or release used as each GoreeCloud baseline;
- keep GoreeCloud-specific changes reviewable and attributable;
- avoid rewriting upstream history merely to make the repository appear independently originated;
- distinguish upstream security fixes from GoreeCloud product-layer changes;
- retain a rollback path for material upstream integrations.

## Divergence policy

GoreeCloud should prefer the lowest-maintenance customization method that satisfies the documented requirement.

Preferred order:

1. Supported configuration.
2. Supported templates or themes.
3. Documented extension points.
4. Small, isolated source changes.
5. Broader source divergence only when justified by security, privacy, maintainability, integration, recoverability, or technology-independence requirements.

GoreeCloud will not rewrite mature identity, protocol, cryptographic, session, or authentication behavior merely to increase the amount of GoreeCloud-owned code.

## Upstream update process

Before integrating a material upstream update, GoreeCloud should:

1. Identify the exact upstream source commit or release.
2. Review upstream release notes, security advisories, migrations, dependency changes, and breaking changes relevant to the selected baseline.
3. Compare the upstream change against GoreeCloud-specific modifications.
4. Resolve conflicts without silently discarding GoreeCloud security or product requirements.
5. Run applicable upstream tests plus GoreeCloud-specific validation.
6. Validate database and persistent-state migrations when applicable.
7. Validate authentication, session, MFA, recovery, and provider behavior affected by the update.
8. Record the accepted baseline and validation evidence.
9. Keep the previous accepted state recoverable until the new state is accepted.

## Security updates

Security fixes receive priority over cosmetic or product-layer changes.

When upstream publishes a relevant security fix, GoreeCloud should minimize the delay introduced by local divergence. If a GoreeCloud customization materially obstructs timely security updates, that customization must be reconsidered.

The upstream `SECURITY.md` remains important for authentik vulnerability-reporting and supported-version information. GoreeCloud-specific deployment or customization defects must also be evaluated within the GoreeCloud project boundary.

## Licensing baseline

The fork currently preserves upstream licensing. The repository root `LICENSE` states that content outside specifically identified exceptions is MIT licensed, while `website/` and `authentik/enterprise/` have separate licensing conditions and incorporated third-party components retain their original licenses.

GoreeCloud must preserve those distinctions. Rebranding does not authorize removal of required notices or relicensing of code that GoreeCloud does not own.

## Release identity

A future GoreeCloud Identity release should identify both:

- its GoreeCloud release/version; and
- the exact upstream authentik baseline from which it was built.

This dual identity makes security review, reproduction, upstream comparison, migration, and rollback practical.
