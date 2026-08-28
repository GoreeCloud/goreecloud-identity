# GoreeCloud Identity Product-Hardening Merge Criteria

The current source-hardening pull request may be merged to `main` only when its exact head is mergeable and the applicable automated validation suite is clean. Merge of the product layer does not authorize Stable production deployment.

Post-merge production promotion still requires the target-runtime, integration, monitoring, recovery, break-glass, accessibility, artwork, and rollback evidence recorded in the production-readiness documents.
