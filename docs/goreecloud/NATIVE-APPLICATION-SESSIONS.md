# GoreeCloud Identity — Native Application Session Foundation

## Status

**Lifecycle:** Development source contract  
**Runtime implementation:** Contract only  
**Production accepted:** No

This document defines the first GoreeCloud-owned authorization and session boundary for first-party native applications such as GoreeCloud Tasks, Calendar, Messenger, and other Android/Linux clients.

It does not establish a deployed native authorization server, production client registrations, accepted access/refresh token runtime, production signing-key custody, application migration, or Stable qualification.

## Purpose

Native GoreeCloud applications need user-scoped Identity credentials without inventing application-local password stores, shared application credentials, reusable service tokens, or a second identity authority.

The governing principle is:

**Identity authenticates the principal and issues bounded delegated claims; the application remains authoritative for its own data and application-specific authorization.**

A valid Identity session never means that a task, event, message, file, or other application object is automatically readable or mutable. The owning application must independently enforce its existing authorization rules.

## Protocol profile

The source contract requires a public native-client profile based on OIDC/OAuth authorization code flow with PKCE S256.

The native application must:

- send authentication through an external user agent rather than collecting the user's Identity password itself;
- use an authorization code and PKCE S256;
- validate state and, when OIDC is used, nonce;
- use an exact registered client identifier and exact registered redirect;
- avoid wildcard redirects;
- use HTTPS outside explicitly bounded loopback Development cases;
- never rely on an embedded native client secret as proof of client identity;
- never use the implicit grant or resource-owner-password grant for this profile.

The existing Identity redirect-security rules remain applicable. Redirect userinfo and fragments are prohibited.

## Token boundary

Native application access must be delegated and minimized.

The contract requires:

- short-lived access tokens;
- exact audience binding;
- explicit scope binding;
- ID tokens not being accepted as application API bearer tokens;
- refresh-token rotation;
- refresh-token reuse detection;
- refresh-token-family revocation;
- no refresh-token material in logs or ordinary documentation.

A refresh token is not an application-wide credential and must never be shared among users, installations, services, or unrelated applications.

## Application and client-instance binding

Each accepted native session must be bound to:

- the authenticated user;
- the registered GoreeCloud application;
- a specific client instance.

The client-instance identifier is required to be locally random. Hardware fingerprinting is explicitly prohibited. Device/session visibility must therefore be based on explicit Identity/session records, not covert device fingerprint inference.

The user must ultimately be able to see and revoke individual native application sessions. Account disablement and application disablement must both trigger revocation evaluation.

## Application acceptance proof

The native-session contract now defines a common, non-secret acceptance-proof shape that consuming applications may validate before they consider an Identity-bound operation.

The common proof metadata is:

- `principalId` — the exact authenticated Identity principal expected by the consumer;
- `audience` — the exact registered consumer audience;
- `issuedAt` — the proof/session issue time;
- `expiresAt` — the exclusive expiry time.

The common acceptance rules are fail-closed:

- principal and audience strings must already be canonical for the consuming contract; clients must not trim, case-fold, decode, coerce, or otherwise normalize them during acceptance;
- blank, trim-dependent, or control-bearing principal/audience values are invalid;
- the audience must match the registered consumer audience exactly;
- `issuedAt` must be strictly earlier than `expiresAt`;
- a proof with an issue time in the future is not acceptable;
- expiry is exclusive, so a proof is expired when the acceptance time is equal to or later than `expiresAt`;
- the proof metadata contains no credential material and is not itself a bearer credential;
- the proof metadata alone does not authenticate a caller and does not authorize application data;
- the consuming application must independently accept the proof and continue to enforce its own authorization.

A consumer may require additional exact opaque bindings when its own authorization model needs them. For example, a Mail client may require an exact application-owned account identifier in addition to the Identity principal and audience. Such additional bindings narrow the operation; they do not expand Identity authority or transfer application authorization to Identity.

This source contract does not register or activate any concrete Android/Linux audience. Consumer-side audience strings remain Development inputs until the corresponding Identity application registration exists and is independently accepted.

## Application authorization remains independent

GoreeCloud Identity owns platform identity, authentication, sessions, credentials, application registration, and delegated platform claims.

The consuming application retains authority for application data and application permissions. In particular:

- Identity does not decide whether a specific Tasks task is visible or editable;
- Identity does not decide whether a Calendar event is visible or editable;
- Identity does not turn authentication into Privacy Shield data-use authorization;
- Identity does not turn authentication into Wardveil security acceptance;
- Identity does not turn a cached session into offline mutation authority.

An application may narrow Identity-issued authority further. It may not expand beyond the issued audience or scopes.

## Native credential storage and transport

The native client must not store the user's GoreeCloud Identity password.

Reusable native credential material must use protected platform credential storage appropriate to the target runtime. Reusable credentials are prohibited from source control, ordinary documentation, and authentication logs.

A browser-authenticated session cookie is not a native application credential and must not become the long-term mobile or desktop client credential model.

TLS is required outside explicitly bounded loopback Development use.

## Revocation and offline behavior

The contract deliberately fails closed around stale authorization:

- an expired credential cannot fall back to an old accepted state;
- a revoked native session cannot refresh itself back into authority;
- cached Identity state does not imply authorization for offline mutations;
- server mutations require current credential validation;
- revocation propagation is a runtime requirement.

This does not prohibit an application from maintaining a bounded read cache under its own privacy and recovery policy. It means cached identity evidence cannot silently grant new server-side authority.

## Audit requirements

The native runtime must eventually emit minimized security events for:

- authorization started;
- authorization succeeded;
- authorization failed;
- native application session created;
- refresh credential rotated;
- native application session revoked.

Passwords, authorization codes, access tokens, and refresh tokens must not be written into those audit records.

## Consumer requirements

A native application consuming this contract must not:

- substitute GoreeCloud Mesh/service credentials for a human session;
- use a shared application password;
- query the Identity database directly;
- bypass its own application authorization database/model;
- allow the client to select another user as the authorization principal.

This keeps user identity, service identity, and application-specific authorization as separate authorities.

## GoreeCloud Tasks dependency

The GoreeCloud Tasks read-only `/api/v1/client/` foundation currently uses the existing authenticated web/session boundary and explicitly does not define a mobile bearer-credential model.

The future Tasks Android client should consume this Identity-owned native application-session profile only after the corresponding Identity runtime is implemented and accepted for the required Development environment. Tasks must then map the validated Identity principal into its existing `visible_to(user)` and `editable_by(user)` authorization paths rather than replacing those checks.

Until that runtime exists, Tasks should not invent its own refresh-token database, reuse browser cookies as the long-term native credential, or use GoreeCloud Mesh service credentials as user credentials.

## Migration boundary

The repository still contains substantial authentik-derived transitional runtime code. Existing OAuth/OIDC capability may inform compatibility work, but inherited protocol support does not count as acceptance of this GoreeCloud-owned native contract.

Migration of existing application sessions must be explicit. Identity bindings must not be silently reassigned, and application-owned authorization/data must remain preserved.

## Required follow-on work

The next implementation milestones are:

1. implement the GoreeCloud-owned native application registration and authorization runtime;
2. implement PKCE-bound authorization-code issuance/exchange with exact redirect validation;
3. implement bounded access-token audience/scope validation, native session records, and production-derived application-acceptance proof metadata;
4. implement refresh rotation, reuse detection, family revocation, and account/application revocation propagation;
5. implement session/device visibility and individual revocation without secret disclosure;
6. validate protected native credential storage patterns for Android and Linux clients;
7. integrate one controlled first-party application that independently validates the canonical proof contract without bypassing its application authorization;
8. complete exact-revision runtime, security, recovery, Wardveil, Privacy Shield, monitoring, rollback, and production acceptance.

## Acceptance boundary

`contracts/native-application-session.v1.json` is source-contract evidence only.

It does **not** establish native runtime implementation, deployed application registrations, production OAuth/OIDC migration, production signing keys, accepted Android/Linux client credentials, production application-acceptance proof issuance, production session revocation, production audit retention, Release Candidate status, Stable status, or production approval.
