# GoreeCloud Identity Supply-Chain Boundary

GoreeCloud Identity inherits upstream build systems and dependencies and adds a deliberately small GoreeCloud layer.

## Build integrity

Release builds and CI should use exact source revisions, controlled dependency resolution, immutable action references where practical, and preserved upstream license/provenance records.

## Dependency integrity

Dependency updates must be reviewable and limited to intended changes. Generated lockfiles should not carry unrelated dependency drift when a security fix can be represented as a minimal compatible update.

## CI permissions

GoreeCloud-owned workflows default to read-only repository permissions unless a narrowly scoped write is explicitly required. Temporary write-capable repair mechanisms are not retained as permanent CI surfaces after their purpose is complete.

## Publication

Downstream GoreeCloud validation must not accidentally publish to, mutate, or comment through upstream-owned authentik resources. Downstream container/cache/publication targets must be owned by GoreeCloud when publication is later approved.
