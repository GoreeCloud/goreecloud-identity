# GoreeCloud Identity Testing Contract

Testing for GoreeCloud Identity must cover both inherited authentik correctness and GoreeCloud-specific product behavior.

## Automated source validation

The exact candidate should pass applicable upstream/inherited unit, integration, web, protocol-conformance, migration, static-analysis, dependency-vulnerability, documentation, translation, and outpost/build workflows, plus GoreeCloud maintained-fork and product-layer guardrails.

## Critical workflow validation

Representative validation must include login, logout, re-authentication, session expiry/revocation, recovery, enrollment, passkey/WebAuthn when enabled, MFA when enabled, denied access, invalid/expired callback behavior, application consent where applicable, administrative identity actions, and relying-application mapping.

## Glaze UI validation

Authentication, account, user, administrator, static, loading, success, warning, denied, degraded, empty, and error states require representative visual and interaction acceptance under Glaze UI 1.3 Stable, including responsive and accessibility modes.

## Recovery and integration validation

Production acceptance additionally requires isolated restore, signing/encryption-material recovery where applicable, break-glass access, independent monitoring, one controlled GoreeCloud application integration, and rollback proof.

## Regression rule

A passing source build does not override a failing security, accessibility, recovery, integration, or production-readiness gate. Known release-blocking regressions remain blockers until corrected or covered by an explicitly approved GoreeCloud exception.
