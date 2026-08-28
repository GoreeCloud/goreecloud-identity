# GoreeCloud Identity Current Status

Lifecycle state: **Active Development**.

The maintained-fork foundation has been merged to `main`. The current product-hardening candidate is being rebuilt cleanly from that validated foundation on `agent/glaze-ui-1.3-hardening`.

Implemented at source level on this branch:

- Glaze UI 1.3 Stable compatibility bridge through authentik's reserved brand layer and all three global UI entry points.
- Wardveil Security by GoreeCloud presentation and evidence boundaries.
- Observability, privacy, secure-defaults, administration, integration, accessibility, performance/reliability, deployment, recovery, testing, threat-model, audit-evidence, and release-acceptance contracts.
- Fail-closed production-readiness gates.
- Hardened GoreeCloud workflow guardrails with immutable checkout pinning.

Not yet accepted:

- Exact-head CI for the clean product-hardening branch.
- Manual Glaze UI/accessibility acceptance.
- Canonical GoreeCloud Identity application mark.
- Target private publication and runtime validation.
- Independent monitoring.
- Representative GoreeCloud OIDC application integration.
- Backup/isolated restore, signing-material recovery, and break-glass proof.
- Upgrade/rollback and production cutover.

GoreeCloud Identity must not be represented as Stable or production-accepted until the applicable gates pass.
