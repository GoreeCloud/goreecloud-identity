# GoreeCloud Identity — Glaze UI 1.3 Adoption Record

This record defines the current source-level Glaze UI 1.3 Stable adoption boundary for GoreeCloud Identity.

## Scope

The current implementation uses authentik's reserved `brand` layer and global CSS entry points to apply GoreeCloud presentation without changing authentication protocol semantics, authorization enforcement, cryptography, session behavior, or database migrations.

The product layer covers the Canvas, Solid, Raised, Glaze, and Overlay surface hierarchy; light, dark, and system appearance; visible keyboard focus; 44-pixel minimum interaction targets; Compact, Medium, Expanded, and Wide adaptive ranges; reduced motion; reduced transparency; increased contrast; forced colors; unsupported-translucency fallback; and print-safe presentation.

## Controlled surfaces

The Glaze layer is loaded by the user/admin interface, authentication-flow interface, and static Django-template interface. These entry points are intended to ensure that GoreeCloud-controlled presentation is not limited to the post-login administrative shell.

## Security boundary

Glaze UI is presentation and interaction architecture. It must never weaken or replace server-side authentication, authorization, MFA/passkey semantics, consent, recovery, anti-abuse controls, session management, or protocol validation.

Security-facing Glaze UI surfaces use Wardveil Security by GoreeCloud identity only where supported by actual technical evidence.

## Acceptance boundary

Source-level adoption is not equivalent to visual acceptance or production acceptance. Before Stable, representative authentication, enrollment, recovery, account-security, user, and administrative surfaces must be manually reviewed for Glaze UI consistency, accessibility, responsive behavior, denied/error/degraded states, and security-message clarity on the exact release candidate.
