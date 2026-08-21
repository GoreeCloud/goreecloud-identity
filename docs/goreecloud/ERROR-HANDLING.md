# GoreeCloud Identity Error-Handling Boundary

Identity failures must be safe, actionable, observable, and non-secret-bearing.

## User-facing behavior

Users should receive a clear Glaze UI state that distinguishes validation problems, denied access, expired state, dependency degradation, recoverable failures, and terminal failures where doing so is safe. User-facing errors must not expose stack traces, database details, secret-bearing configuration, tokens, keys, internal network paths, or cryptographic material.

## Operator evidence

Operator-facing evidence may include a bounded error code, exception class, normalized component/operation, timestamp, and correlation identifier. Sensitive request bodies, credentials, authorization headers, cookies, bearer tokens, and secret-bearing URLs remain excluded.

## Retry behavior

Only idempotent or explicitly retry-safe operations should be retried automatically. Retries must be bounded and use backoff where appropriate. Credential enrollment/removal, recovery mutations, policy changes, key rotation, and similar security-sensitive state changes must not be blindly repeated.
