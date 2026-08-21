# GoreeCloud Identity Operations Boundary

GoreeCloud Identity is a shared platform capability and must be operated as infrastructure, not as an ordinary user application.

## Operating principles

Routine administration should use individually assigned administrative identities, least privilege, documented changes, and the approved GoreeCloud private administrative access model. Production changes require validation and a recovery path. Identity must not be used as the sole mechanism required to recover Identity itself.

## Health and dependency awareness

Operators must be able to distinguish Identity application health from the health of its database, cache or worker dependencies, reverse proxy, DNS/private-network publication, and external relying applications. A green HTTP response alone is not sufficient production evidence.

## Change management

Security updates and upstream authentik fixes should be reviewed promptly. GoreeCloud-specific divergence should remain narrow, documented, and revalidated after upstream synchronization. Changes to authentication semantics, protocol handling, signing/encryption behavior, migrations, or recovery require higher scrutiny than presentation-layer changes.

## Incident behavior

During an incident, preserve audit evidence, avoid exposing credentials through troubleshooting output, prefer reversible containment, and use the documented break-glass/recovery path when normal Identity access is unavailable. Recovery actions must be followed by validation of authentication, authorization, integration, and monitoring behavior before normal operation resumes.
