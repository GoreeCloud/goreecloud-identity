# GoreeCloud Identity Dependency Boundary

GoreeCloud Identity inherits a substantial upstream dependency graph from authentik. GoreeCloud must preserve visibility into those dependencies and avoid adding unnecessary product-layer dependencies.

## Product-layer rule

The GoreeCloud product layer should prefer existing platform capabilities and CSS/customization seams. It must not add analytics SDKs, trackers, remote UI frameworks, remote fonts, remote icon services, or unrelated client dependencies merely for branding.

## Vulnerability handling

Applicable dependency vulnerability findings are release evidence. Valid findings are corrected through an appropriate upstream or minimal compatible update where practical; they must not be silently suppressed to obtain a green build. Exceptions require an evidence-based GoreeCloud decision with scope, impact, and follow-up recorded.

## Upstream maintenance

Upstream authentik security and maintenance updates should be reviewed routinely. GoreeCloud divergence should remain narrow enough that updates can be integrated and validated without broad manual reconstruction.
