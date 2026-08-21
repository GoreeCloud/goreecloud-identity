# GoreeCloud Identity Audit Evidence Boundary

Audit evidence must support troubleshooting, administrative review, security investigation, integration validation, and recovery verification without becoming a secret store.

## Evidence expectations

Where available, audit evidence should identify event category, affected non-secret object, actor or service identity as appropriate, result, timestamp, and bounded correlation context. Security-sensitive state changes should be distinguishable from ordinary informational activity.

## Prohibited audit content

Passwords, bearer tokens, session cookies, authorization headers, OAuth/OIDC client secrets, private signing/encryption keys, recovery codes, WebAuthn private material, raw secret-bearing request/response bodies, and environment secret values must not be copied into ordinary audit records.

## Production evidence

Release and production acceptance should retain exact source/artifact identity, applicable CI results, security/vulnerability status, representative UI/accessibility acceptance, target runtime validation, application-integration proof, backup/restore evidence, break-glass proof, monitoring evidence, and rollback outcome.
