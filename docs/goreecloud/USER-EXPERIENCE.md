# GoreeCloud Identity User Experience Boundary

The GoreeCloud Identity experience should make authentication and account security understandable without exposing unnecessary identity-provider complexity to ordinary users.

## Core UX principles

Normal sign-in, passkey/MFA enrollment when enabled, recovery, logout, session management, and application-consent flows should use plain language, clear primary actions, explicit security consequences, and consistent Glaze UI states. Administrative terminology should remain in administrative contexts rather than leaking into routine family-facing workflows.

## Required states

Controlled workflows must account for loading, success, empty, warning, denied-access, degraded, validation-error, recoverable-error, and terminal-error states. Errors should explain what the user can safely do next without exposing stack traces, secrets, internal database details, or cryptographic material.

## Security-sensitive interactions

Recovery, authenticator removal, session revocation, administrative changes, and other high-impact actions require clear confirmation and must not be visually disguised as ordinary low-risk navigation. Security messaging must remain understandable in compact layouts and accessibility modes.

## Performance perception

Long-running operations should provide honest progress or pending feedback rather than dead controls. Retries should be bounded and limited to operations that are safe to repeat; security-sensitive mutations must not be blindly retried.
