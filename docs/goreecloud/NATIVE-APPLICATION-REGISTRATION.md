# GoreeCloud Identity — Native Application Registration Contract

## Status

**Lifecycle:** Development source contract  
**Runtime implementation:** Contract only  
**Production accepted:** No  
**Concrete native registrations:** None

This contract defines how GoreeCloud Identity will represent first-party native application registrations before a GoreeCloud-owned native authorization runtime is implemented.

It does not register GoreeCloud Mail, Tasks, Calendar, Contacts, Messenger, or any other Android/Linux client. Consumer-side audience strings remain Development expectations until an explicit Identity-owned registration is added and independently accepted.

## Registration record

A future native application registration must explicitly contain:

- `applicationId` — exact GoreeCloud application identity;
- `clientId` — exact public native OAuth/OIDC client identifier;
- `audience` — exact API/consumer audience;
- `redirectUris` — exact registered redirect set;
- `allowedScopes` — explicit allowed scope set;
- `enabled` — registration lifecycle state.

`applicationId`, `clientId`, and `audience` are exact identifiers. Identity and consumers must not trim, case-fold, decode, string-coerce, or otherwise normalize them during authorization acceptance. Blank or control-bearing identifiers are invalid.

Native applications are public clients. An embedded client secret is not accepted as proof of native client identity.

## Redirect boundary

Redirects must be explicitly registered and matched exactly. Wildcard redirects are prohibited. Redirect userinfo and fragments are prohibited. HTTPS is required outside explicitly bounded loopback Development use, and loopback exceptions must be deliberate rather than inferred.

A consuming application cannot override its registered redirect at runtime.

## Audience and scope boundary

Each native registration owns an exact audience. Unrelated applications must not silently share that audience.

Allowed scopes must be explicit. Wildcard scopes and client-side scope expansion are prohibited. A native client may request less authority than its registration permits, but it cannot create new authority outside the registered scope set.

## Lifecycle and revocation

A disabled registration cannot authorize new sessions. Application disablement requires session revocation evaluation. Material registration changes require existing native sessions to be reevaluated.

Audience and client-ID reassignment must be explicit; they must not silently migrate existing sessions or consumer bindings.

## Consumer authority boundary

A native consumer cannot:

- self-register at runtime;
- select another application's audience;
- select another application's client ID;
- override its registered redirect;
- treat registration as application-data authorization;
- treat registration as Privacy Shield authorization;
- treat registration as Wardveil acceptance.

Registration establishes only an Identity-owned client/audience/scope/redirect boundary. The consuming application still independently owns its data authorization and runtime acceptance.

## Empty registry boundary

The current `registrations` array is intentionally empty. An empty registry means that this Development contract establishes **no runtime native application registrations**.

Adding a concrete registration later must be an explicit governed change with an exact client ID, exact audience, exact redirects, explicit scopes, lifecycle state, and consumer-side acceptance evidence. Consumer source constants alone do not create an Identity registration.

## Relationship to native application sessions

`contracts/native-application-session.v1.json` defines session, proof, revocation, storage, and application-authorization boundaries. This registration contract defines the prerequisite record that would bind an application/client/audience/redirect/scope set before such a session may be issued.

Neither contract currently establishes a deployed native authorization runtime.

## Required follow-on work

1. implement a GoreeCloud-owned registration datastore/model with exact identifier handling;
2. add governed registration creation/update/disable workflows;
3. implement exact redirect and allowed-scope enforcement in the authorization endpoint;
4. bind issued native sessions to the exact registration revision and client instance;
5. implement session reevaluation/revocation when a registration changes or is disabled;
6. add one controlled first-party Development registration only after the corresponding consumer contract and runtime path are ready;
7. complete Wardveil, Privacy Shield, recovery, audit, representative-runtime, rollback, signing, and production acceptance.

## Acceptance boundary

`contracts/native-application-registration.v1.json` is source-contract evidence only.

It does **not** establish concrete native registrations, deployed OAuth/OIDC clients, access/refresh token issuance, redirect runtime acceptance, protected credential storage, production signing keys, production authorization, Release Candidate status, Stable status, or production approval.
