# GoreeCloud Identity Validation Gates

GoreeCloud Identity is a security-critical maintained fork. Validation is therefore divided into lightweight fork guardrails and upstream application validation.

## Foundation guardrails

The GoreeCloud foundation guardrail is intentionally dependency-free. It verifies that the repository still contains the minimum provenance and project-boundary records expected for a maintained fork.

The guardrail checks:

- `GOREECLOUD.md` exists;
- `UPSTREAM.md` exists;
- `docs/goreecloud/ARCHITECTURE.md` exists;
- `docs/goreecloud/UI-CUSTOMIZATION.md` exists;
- the root README links to the GoreeCloud and upstream-maintenance records;
- upstream license records used by the root repository, web application, and theme package remain present;
- the Python project and primary web package have not been silently renamed during the foundation phase.

These checks do not prove that authentik itself builds or that authentication behavior is correct. They protect the fork-maintenance boundary while deeper validation remains upstream-compatible.

## Upstream validation remains authoritative

The repository already contains upstream workflows for the server, web application, documentation, outposts, and supporting build paths. GoreeCloud should continue to use those workflows rather than creating parallel substitutes for mature upstream test suites.

When GoreeCloud begins modifying runtime or UI code, the relevant upstream workflow must pass before the change is considered eligible for merge.

## Required validation by change class

### Documentation or fork-governance changes

Required:

- GoreeCloud fork guardrail;
- Markdown review for accuracy and links;
- confirmation that licensing and provenance statements remain intact.

### Glaze UI token or brand-layer changes

Required:

- GoreeCloud fork guardrail;
- upstream web formatting/lint checks;
- upstream web type checks;
- affected web tests;
- manual keyboard and focus review;
- light/dark/reduced-motion review;
- sign-in and sign-out smoke test.

### Authentication-flow presentation changes

Required in addition to the UI checks:

- login failure-path smoke test;
- account recovery smoke test;
- MFA/passkey enrollment test when affected;
- confirmation that server-side flow semantics are unchanged;
- authorization/consent review when affected.

### Backend, protocol, policy, migration, or cryptographic changes

These changes require explicit security review and the full relevant upstream validation path. They are outside the scope of the foundation phase and must not be introduced as incidental branding work.

## Merge policy during foundation

The current GoreeCloud foundation branch should remain narrow. A change belongs in the foundation PR when it improves documentation, fork provenance, validation, or clearly maps a future customization seam without changing runtime identity behavior.

Runtime product work should be placed in subsequent focused branches and pull requests so upstream synchronization and security review remain auditable.
