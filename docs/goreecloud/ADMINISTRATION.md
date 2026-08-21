# GoreeCloud Identity Administration Boundary

GoreeCloud Identity administration is security-sensitive infrastructure work.

## Administrative identity

Administrative access uses individually assigned administrative identities. Shared administrator accounts and ordinary daily-use identities are not the preferred administrative model.

## Least privilege

Administrative permissions should be limited to the role actually required. Application administrators, service identities, and human platform administrators should remain distinguishable where the underlying platform supports that separation.

## High-impact actions

Credential-policy changes, provider changes, application registrations, signing/encryption changes, recovery settings, authenticator resets, session revocation, privilege assignment, and user disablement should be auditable and presented with clear consequences.

## Recovery

Normal Identity administration must not be the only way to recover Identity. A separately protected and tested break-glass path is required before production acceptance.

## User privacy

Administrative capability does not authorize unnecessary browsing of private user information. Administrative views and logs should expose only what is required to operate, secure, troubleshoot, and recover the service.
