# GoreeCloud Identity — Native Account Security Foundation

## Status

Development source contract only. Native runtime implementation, target-environment validation, production acceptance, and Stable qualification remain pending.

## Purpose

This document defines the first GoreeCloud-owned native source contract for the authentication and account-security capabilities required by the canonical Project Specification — Identity.

The current repository still contains substantial authentik-derived transitional runtime code. Existing inherited password, WebAuthn, MFA, recovery, session, audit, redirect, and abuse-protection behavior may inform migration and compatibility work, but inherited feature parity is not accepted as proof that the native GoreeCloud Identity architecture has implemented or accepted these capabilities.

## Contract scope

`contracts/native-account-security.v1.json` defines source requirements for:

- password authentication where required;
- passkeys and WebAuthn;
- TOTP multi-factor authentication;
- secure recovery and separate break-glass administration;
- session visibility, expiration, revocation, and disablement-triggered revocation evaluation;
- device and credential visibility without reusable-secret disclosure;
- authentication and account-security audit events;
- exact OAuth/OIDC redirect validation;
- protected runtime secrets and restrictive permissions;
- bounded authentication attempts and rate limiting or equivalent abuse controls.

Every capability in this first contract deliberately records `runtimeAccepted: false`.

## Fail-closed security rules

The source contract requires, at minimum:

- no plaintext password storage;
- protected password verifiers;
- standards-based passkey/WebAuthn behavior without passkey private-key export;
- explicit WebAuthn user-verification policy;
- protected TOTP secrets and replay protection;
- recovery that does not silently reduce the security model;
- no reusable recovery material in logs or ordinary documentation;
- an independently governed break-glass path rather than exclusive dependence on normal SSO;
- visible, expiring, revocable sessions;
- no disclosure of session secrets through session-management surfaces;
- credential/device visibility paired with revocation capability and secret minimization;
- security-event auditing without passwords, tokens, MFA secrets, or recovery secrets;
- exact registered redirect matching, wildcard redirects disabled by default, HTTPS outside explicitly bounded loopback development, and no redirect userinfo or fragments;
- reusable secrets excluded from source control, ordinary documentation, and authentication logs;
- protected runtime configuration and restrictive permissions;
- bounded authentication attempts, rate limiting or equivalent protection, and fail-closed behavior when security-sensitive protection cannot be applied.

## Authority and data boundary

GoreeCloud Identity remains authoritative for platform identity, authentication, authorization primitives, credentials, sessions, and delegated authority. Application-owned authorization and application-owned data remain with the owning application unless a separately documented platform policy delegates that decision.

Disabling an Identity account or revoking an Identity credential does not authorize deletion or ownership transfer of application-owned data.

## Recovery boundary

Recovery is part of Identity security but must not become a general-purpose secrets vault. GoreeCloud Vault remains the separate credential, password, passkey, recovery-information, and sensitive-secret management product where applicable. Everkeep remains the resilience and recovery-evidence authority. Recovery material and administrative secrets must stay out of source control and ordinary documentation.

## Migration boundary

The inherited authentik-derived tree is transitional reference infrastructure only. The native account-security contract is intended to drive replacement with GoreeCloud-owned architecture while allowing narrowly justified standards, protocol, and cryptographic foundations to remain where replacing them would increase security or interoperability risk.

No capability becomes native Runtime Validated merely because an equivalent authentik feature exists.

## Acceptance boundary

This source milestone does not establish:

- a native authentication server;
- accepted native password hashing/runtime storage;
- deployed passkey/WebAuthn ceremonies;
- deployed TOTP enrollment or verification;
- production recovery or break-glass acceptance;
- production session/device/credential management;
- production audit retention or monitoring;
- production redirect validation across registered applications;
- production secret custody;
- runtime abuse/rate-limit acceptance;
- production deployment, application migration, Release Candidate, or Stable status.

Each capability must advance through implementation, exact-revision tests, runtime validation, recovery/security review, and production acceptance independently.
