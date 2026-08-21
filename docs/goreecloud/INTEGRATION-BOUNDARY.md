# GoreeCloud Identity Integration Boundary

GoreeCloud Identity provides authentication and identity-provider services to approved GoreeCloud applications. It does not become the authorization database for application-owned data.

## Preferred protocol

OIDC/OAuth 2.0 is the preferred integration path for modern GoreeCloud applications. SAML or other supported protocols remain compatibility options when a specific application requires them.

## Authorization boundary

A successful GoreeCloud Identity authentication establishes who the user is. Each relying application remains responsible for deciding what that identity may access or modify inside the application. SSO success must never be interpreted as blanket authorization to another user's data.

## Client registration

Each application integration should use a separately identifiable client/application registration with the smallest required redirect URI set, scope set, credential permissions, and lifecycle. Reusable client secrets are sensitive information and must not be committed to Git or ordinary documentation.

## Failure isolation

An application must handle Identity unavailability, denied authentication, invalid callback state, expired or revoked sessions, and provider errors without exposing secrets or silently broadening access. Error states should use safe Glaze UI presentation and provide bounded diagnostic correlation for administrators.

## Acceptance

Before production acceptance, at least one controlled GoreeCloud application must pass end-to-end login, logout, mapping, denied-access, failure, recovery, and rollback validation against the exact Identity release candidate.
