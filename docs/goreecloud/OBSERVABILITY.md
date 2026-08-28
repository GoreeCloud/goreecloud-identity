# GoreeCloud Identity Observability Contract

GoreeCloud Identity requires operational, security, administrative, integration, and authentication evidence that is useful for troubleshooting and investigation without turning logs into a secondary credential or personal-data store.

## Event families

Production observability should preserve structured evidence for service lifecycle and health, authentication outcomes, authorization and policy decisions, administrative changes, session lifecycle, authenticator enrollment and removal, provider/application integration failures, background-task failures, dependency failures, security-relevant configuration changes, and backup/recovery validation.

Existing authentik events remain the authoritative application audit source where they already capture the required state. GoreeCloud-specific logging should complement rather than duplicate that evidence.

## Minimum structured context

Where supported, operational events should include a stable event category, component, normalized operation or route, result/status, timestamp, bounded request or correlation identifier, and duration for latency-sensitive operations. Security and administrative events should identify the affected non-secret object or policy when necessary for auditability.

## Sensitive-data exclusions

Broad operational logging must not record reusable passwords, session cookies, bearer tokens, authorization headers, OAuth/OIDC client secrets, private signing or encryption keys, recovery codes, WebAuthn private material, environment-file values, raw request or response bodies, database dumps, or full secret-bearing URLs.

Authentication logging must be proportionate. Failed-login evidence should support investigation and rate-limit/security analysis without unnecessarily copying submitted credentials or other secret material into logs. Any user identifier retained for audit purposes must have a documented operational reason and appropriate access/retention controls.

## Error handling

Unexpected errors exposed to ordinary users must use safe, actionable Glaze UI error states and must not reveal stack traces, secret-bearing configuration, internal database details, or cryptographic material. Operator-facing evidence may retain an exception class, bounded error code, and correlation identifier while protecting raw sensitive values.

Retries are appropriate only for operations that are safe to retry and should use bounded attempts and backoff. Authentication decisions, enrollment mutations, credential rotation, and other security-sensitive state changes must not be blindly retried in a way that can duplicate or corrupt state.

## Access and retention

Operational logs and identity audit data are administrative records. Access follows least privilege. Retention should be long enough to support troubleshooting, security investigations, and recovery validation but should not be extended merely because storage is available.

## Production acceptance

Before Stable or production acceptance, GoreeCloud Identity must demonstrate that expected service, authentication, administrative, integration, and failure events are observable; sensitive values are excluded; error states correlate safely to operator evidence; log access is restricted; and monitoring can detect loss of service without requiring exposure of authentication secrets.
