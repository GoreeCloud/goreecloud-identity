# GoreeCloud Identity Architecture Baseline

## Purpose

This document records the initial GoreeCloud-specific architecture boundary for GoreeCloud Identity without pretending that the exact production runtime has already been approved.

## Logical role

GoreeCloud Identity is a shared infrastructure service. It is not part of one family application and must not become a hidden authorization database for unrelated products.

```text
Approved user/device
        |
        v
     NetBird
(private connectivity)
        |
        v
GoreeCloud Identity
(authentication / SSO)
        |
        v
Participating application
(application authorization)
        |
        v
Application-owned data
```

## Trust boundaries

### Network trust

NetBird determines whether an approved device or peer can reach private GoreeCloud services. Private-network reachability does not by itself authenticate a user to an application.

### Identity trust

GoreeCloud Identity establishes the authenticated identity and provides approved identity claims to participating applications.

### Application trust

Each application remains responsible for its own authorization, record ownership, administrative roles, and data-access decisions.

## Preferred integration model

OIDC/OAuth 2.0 is the preferred modern application integration model where the application supports it safely. Integrations should request the minimum claims and scopes required for the application's documented role.

Every application integration requires independent validation of:

- redirect URIs;
- login and logout;
- account mapping;
- session expiration;
- MFA interaction when applicable;
- role/group mapping when used;
- disabled-account behavior;
- identity-provider outage behavior;
- rollback behavior;
- preservation of existing application data ownership.

## Runtime boundary

The exact authentik runtime topology must be derived from the selected upstream baseline. GoreeCloud must not copy an outdated deployment diagram or assume a historical dependency is still required.

The intended GoreeCloud deployment characteristics are:

- Docker and Docker Compose for the initial controlled deployment;
- PostgreSQL and other dependencies only as required by the selected upstream baseline;
- no unnecessary public backend host ports;
- Caddy as the approved HTTPS/reverse-proxy boundary;
- `identity.goreecloud.com` as the planned private service hostname;
- NetBird and GoreeCloud private DNS controls for routine access;
- persistent data separated from ephemeral containers;
- secrets separated from source and ordinary configuration;
- health and recovery evidence suitable for GoreeCloud monitoring.

## Recovery architecture

Because Identity can become a dependency for many applications, recovery must be designed before broad adoption.

Required recovery properties include:

- backup of all required persistent identity state;
- recovery of signing/encryption material that is required to preserve application trust;
- recovery of application/client registrations and provider configuration;
- isolated restore testing;
- an administrative break-glass path independent of normal SSO;
- documented credential/key rotation procedures;
- controlled re-establishment of application trust after a severe recovery event.

## Product-layer architecture

GoreeCloud-controlled presentation should progressively provide a Glaze UI experience for sign-in, MFA, passkeys, recovery, profile/account security, sessions, authorized applications, and administrative identity management.

The customization layer must stay as isolated from the upstream identity engine as practical. UI and branding work must not weaken security controls or make upstream security updates unnecessarily difficult.

## Initial engineering rule

Until a GoreeCloud-specific change is shown to be necessary, upstream identity and security behavior remains the baseline. Early development should concentrate on product boundaries, integration contracts, safe theming/branding seams, test coverage, deployment controls, backup/recovery, and upstream maintainability rather than broad rewrites.
