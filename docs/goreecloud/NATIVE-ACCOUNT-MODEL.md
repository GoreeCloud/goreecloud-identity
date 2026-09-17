# GoreeCloud Identity — Native Account Model Foundation

**Roadmap:** FR-004 / FR-005  
**Lifecycle:** Development source contract  
**Runtime implementation state:** contract-only

This contract defines GoreeCloud-owned identity semantics that the native Identity rebuild must preserve. It does not represent the inherited authentik-derived runtime as the permanent GoreeCloud architecture and does not claim that the native runtime is complete.

Human identities, administrator identities, and service identities are distinct canonical identity kinds. Administrator privilege is explicit and separate from ordinary human identity. Service identities do not masquerade as human users and require a separate credential lifecycle.

The default registration policy is invite-only. Administrators may create accounts. Self-registration is disabled by default and may be enabled only through explicit operator configuration.

The human account lifecycle is `invited`, `active`, `disabled`, and `archived`. Disablement denies new authentication and requires active-session revocation evaluation. Identity disablement does not authorize deletion of application-owned data and does not transfer ownership of that data to Identity.

The migration boundary treats the inherited runtime as transitional reference infrastructure only. Inherited product/object names do not become canonical GoreeCloud Identity concepts by default. Migration must not silently rebind identities, and application-owned data must be preserved.

This source contract establishes architecture and lifecycle invariants only. It does not implement the native account database, authentication flows, migration tooling, session revocation runtime, application migration, production recovery, production acceptance, or Stable qualification.
