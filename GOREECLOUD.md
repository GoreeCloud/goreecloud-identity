# GoreeCloud Identity

GoreeCloud Identity is GoreeCloud's platform authority for identity, authentication, authorization, accounts, devices, credentials, sessions, and delegated authority.

The repository currently contains an inherited authentik-derived codebase plus GoreeCloud-owned contracts and integration work. That inherited product architecture is **transitional migration and reference infrastructure**, not the approved permanent GoreeCloud Identity architecture. The target is original GoreeCloud-owned native Identity software built around GoreeCloud-owned contracts and service boundaries.

GoreeCloud preserves the provenance, licenses, notices, and security obligations of inherited code for as long as that code remains present. Native migration must not rewrite history or imply GoreeCloud authorship of upstream code.

## Project role

GoreeCloud Identity establishes and authenticates GoreeCloud human, service, device, session, and delegated identities and supplies platform authorization primitives where defined by GoreeCloud Identity contracts. Participating applications remain authoritative for their own business rules, data ownership, and application-specific permissions unless a separate GoreeCloud platform contract explicitly assigns a decision to Identity.

Authentication must never be interpreted as automatic Privacy Shield data-use authorization, Wardveil Security acceptance, Everkeep recovery readiness, or application permission.

## Native development direction

The long-term architecture is GoreeCloud-owned native software. Migration proceeds capability by capability so security-critical behavior is replaced deliberately rather than through a cosmetic rebrand or a risky all-at-once rewrite.

Narrow standards, protocol, and cryptographic foundations may be retained when independently reimplementing them would materially increase security or interoperability risk. Such exceptions must stay bounded: they do not justify retaining a complete upstream identity product, upstream UI, upstream workflow architecture, or upstream general application logic as the permanent GoreeCloud Identity implementation.

Current GoreeCloud-owned source boundaries include platform contracts and service-token integration used by GoreeCloud Mesh. New native components should be added behind GoreeCloud-owned interfaces and acceptance evidence so inherited product dependencies can be retired progressively.

## Platform capabilities

The target platform includes:

- individual human identities;
- first-class service and machine identities;
- passkeys/WebAuthn and appropriate multi-factor authentication;
- session visibility, policy, and revocation;
- application/client registration and standards-based federation where required;
- device identity and device-bound trust inputs;
- groups, roles, grants, and delegated authority;
- auditable authentication and authorization decisions;
- independently recoverable administrative access;
- minimized producer-authoritative Identity evidence for GoreeCloud Mesh;
- Identity Center as the GoreeCloud-owned user and administrative experience.

A capability is not considered production-accepted merely because equivalent behavior exists in the inherited authentik-derived tree. GoreeCloud acceptance requires the exact implementation, authority boundary, security behavior, persistence/recovery path, and target-environment evidence to be validated.

## Product experience

The product is **GoreeCloud Identity**. GoreeCloud-controlled user-facing surfaces must use the current applicable Stable Glaze UI contract and the governed **Identity Center** name.

Users should not need to understand inherited identity-provider implementation terminology to sign in, enroll a passkey or MFA method, review sessions/devices, recover an account, or manage account security. Native Identity Center work must simplify those tasks without weakening security, privacy, accessibility, or authority boundaries.

## Security boundary

Identity infrastructure is security-critical. GoreeCloud must avoid unnecessary custom cryptography and must use well-reviewed standards/cryptographic foundations where justified. That security constraint does not require permanent dependence on an upstream product architecture.

GoreeCloud Identity must maintain an independently documented break-glass recovery path. Recovery must not depend exclusively on successfully authenticating through the failed identity service itself.

Passwords, client secrets, signing material, recovery credentials, bearer tokens, session secrets, private keys, SMTP credentials, and other reusable secrets must never be committed to this repository or transported as Mesh evidence.

## Mesh evidence boundary

`contracts/identity.evidence.schema.json` is the producer-owned minimized Identity evidence contract. `contracts/identity.mesh-evidence-profile.json` defines the Identity authority domains and Mesh integration boundary.

`contracts/mesh-service-token.v1.json` is an authentication credential contract for service delivery. It is intentionally separate from the producer evidence contract: a valid service token proves the service principal and granted Mesh scope, not the truth of an Identity-domain evidence assertion.

Identity evidence delivery remains source-level and unaccepted for production until an Identity-owned delivery client, deployed verifier, key/signing custody, target routing, runtime evidence, and acceptance gates are complete.

## Deployment direction

The final deployment topology must be defined by the native GoreeCloud Identity architecture and current GoreeCloud infrastructure requirements. Transitional inherited components may continue to run only as explicitly documented migration infrastructure while their native replacements are implemented and accepted.

Production deployment is not authorized merely because inherited code or a source contract exists. Acceptance requires exact-revision validation of identity protocols and security behavior, persistence, backups/restores, key custody, break-glass access, private publication, monitoring, Wardveil/Privacy Shield/Everkeep/Mesh integration, and representative end-to-end application use.

## Upstream relationship

See [`UPSTREAM.md`](UPSTREAM.md) for provenance, licensing, security-maintenance, and retirement rules governing the inherited authentik-derived source while it remains in this repository.

## Current status

**Status: Active native migration / source integration.**

The repository still contains substantial inherited authentik-derived implementation. GoreeCloud-owned service-token and evidence contracts now establish part of the native platform boundary, but the broader native Identity runtime, Identity Center, production Mesh evidence delivery, and production acceptance remain incomplete. No production cutover or GoreeCloud-wide authentication migration is implied by repository source state alone.
