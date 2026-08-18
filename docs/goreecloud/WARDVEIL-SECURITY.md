# Wardveil Security in GoreeCloud Identity

Wardveil Security by GoreeCloud is the security and protection identity used for GoreeCloud-controlled security presentation. It does not replace authentik's authentication, authorization, protocol, session, cryptographic, audit, or policy enforcement.

## Presentation contract

GoreeCloud Identity may present **Wardveil Security**, **Wardveil Security by GoreeCloud**, and **Protected by Wardveil** only where the surrounding interface is actually backed by identified technical controls. Wardveil language must not convert a configuration state into a security guarantee or obscure the underlying control that produced the state.

Security status surfaces must identify their evidence source where practical: identity policy, session state, authenticator enrollment, authorization decision, application integration, event/audit record, network publication state, backup/recovery evidence, or release-validation evidence.

## Identity-specific scope

Wardveil presentation is appropriate for:

- authentication and session-security status;
- passkey, WebAuthn, MFA, and recovery configuration when those capabilities are intentionally enabled;
- administrative access and identity-policy status;
- security and audit events;
- provider/application integration security;
- signing, encryption, certificate, and key lifecycle status when safely summarized;
- release-security and vulnerability status;
- backup, restore, and break-glass readiness when evidence exists.

Wardveil must not imply that MFA is mandatory platform-wide. GoreeCloud Identity retains the project-approved authentication policy and uses additional factors only where separately approved.

## Privacy boundary

Wardveil-facing views and logs must not expose reusable passwords, session cookies, bearer tokens, OAuth/OIDC client secrets, signing private keys, encryption keys, recovery codes, WebAuthn private material, environment-file values, raw authorization headers, or secret-bearing URLs.

Security summaries should prefer bounded identifiers, event categories, result states, policy names, timestamps, and non-secret evidence references. Where an upstream authentik event contains more detail than a GoreeCloud summary needs, the GoreeCloud presentation should minimize rather than duplicate it.

## Glaze UI boundary

All Wardveil-facing GoreeCloud Identity presentation uses Glaze UI. Wardveil remains a distinct security identity inside the GoreeCloud visual family; it is not a replacement design system.

## Production gate

A release must not claim **Protected by Wardveil** as a blanket product guarantee merely because Wardveil assets or labels are present. Production acceptance requires evidence for the applicable authentication, authorization, vulnerability, private-publication, backup/restore, break-glass, observability, integration, and rollback controls.