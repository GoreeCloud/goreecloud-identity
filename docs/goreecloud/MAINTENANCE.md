# GoreeCloud Identity Maintenance Boundary

GoreeCloud Identity is a maintained open-source fork. Maintenance must balance prompt security updates with controlled GoreeCloud divergence.

## Upstream synchronization

Upstream authentik releases and security fixes should be reviewed routinely. Synchronization should preserve GoreeCloud-specific changes only where they remain necessary and should prefer supported extension/theming seams over deep source divergence.

## Security maintenance

Dependency and vulnerability findings are reviewed as engineering evidence. Valid security issues should be corrected through upstream or minimal compatible fixes rather than hidden by broad exclusions. Emergency fixes still require exact-revision validation and a documented rollback/recovery path.

## Product maintenance

Glaze UI, Wardveil Security, Privacy Shield, Everkeep, accessibility, observability, integration, and production-readiness contracts must be reviewed when their platform standards change. Version labels and machine guardrails must not remain pinned to superseded GoreeCloud standards.
