# GoreeCloud Identity Secure Defaults

GoreeCloud Identity defaults must minimize exposure and privilege while preserving recoverability.

## Default principles

- Individual identities are preferred over shared accounts.
- Administrative identities remain separate from ordinary daily-use identities.
- Relying applications receive only the scopes, redirect URIs, and credentials they require.
- Backend services are not directly published to the public internet.
- Secrets remain outside repository source, ordinary documentation, logs, and client-delivered assets.
- Security-sensitive administrative interfaces remain restricted to authorized administrators.
- Logging is useful but data-minimized.
- Recovery remains possible through a separately protected break-glass path.
- Optional integrations are disabled until their role, permissions, data flow, and recovery behavior are understood.

## Configuration changes

A less-restrictive configuration requires a documented operational need and validation. Convenience alone is not sufficient justification for broad scopes, public backend exposure, shared credentials, bypassed authentication, unrestricted administrative access, or secret-bearing diagnostic output.
