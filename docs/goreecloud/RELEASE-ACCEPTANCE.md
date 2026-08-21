# GoreeCloud Identity Release Acceptance Evidence

This file is the source-controlled acceptance checklist for a GoreeCloud Identity release candidate. It is intentionally evidence-oriented and fail-closed. A blank, unknown, skipped, unavailable, or unverified mandatory item is not acceptance.

## Candidate identity

- Source commit: pending
- Built artifact/image identity: pending
- Upstream authentik baseline: pending verification for candidate
- GoreeCloud release-lifecycle state: Development

## Source validation

- GoreeCloud guardrails: pending exact-head CI
- Inherited authentik Main CI: pending exact-head CI
- Web CI: pending exact-head CI
- Outpost CI: pending exact-head CI
- CodeQL: pending exact-head CI
- Semgrep: pending exact-head CI
- Dependency/vulnerability evidence: pending exact-head CI and platform capability review

## Glaze UI 1.3 acceptance

- Authentication flows: pending manual acceptance
- Enrollment and recovery: pending manual acceptance
- User interface: pending manual acceptance
- Administrative interface: pending manual acceptance
- Static/error/system-generated experiences: pending manual acceptance
- Light/dark/system appearance: pending manual acceptance
- Compact/Medium/Expanded/Wide behavior: pending manual acceptance
- Keyboard/focus/zoom/contrast/forced-colors/reduced-motion/reduced-transparency: pending manual acceptance
- Canonical GoreeCloud Identity application mark: pending approval

## Wardveil Security acceptance

- Security presentation tied to actual evidence: pending
- Secret-redaction review: pending
- Authentication/session/audit evidence: pending
- Vulnerability status evidence: pending

## Runtime and integration acceptance

- Target private DNS/NetBird/Caddy/HTTPS/firewall publication: pending
- Independent monitoring and alerting: pending
- Controlled GoreeCloud OIDC application integration: pending
- Denied-access/failure/recovery behavior: pending
- Backup and isolated restoration: pending
- Required signing/encryption-material recovery: pending
- Break-glass administration: pending
- Upgrade and rollback proof: pending

## Decision

Current release decision: **Not Stable / not production-accepted**.

This record must be updated with exact evidence before promotion under the GoreeCloud application and service release lifecycle.
