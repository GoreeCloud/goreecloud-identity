# GoreeCloud Identity Release-Lifecycle Boundary

GoreeCloud Identity follows the GoreeCloud application and service release lifecycle. Source development, release-candidate validation, production acceptance, and Stable status are separate states.

## Current state

Current state: **Active Development**.

A source merge, green CI run, or successful build does not by itself promote Identity to Stable. Promotion requires the applicable production-readiness and release-acceptance evidence for the exact candidate and target environment.

## Promotion rule

A candidate may advance only when security, correctness, Glaze UI/accessibility, Wardveil evidence, integration, observability, backup/restore, break-glass, monitoring, upgrade/rollback, and target-runtime gates applicable to that stage are satisfied.

## Regression rule

A newly discovered release-blocking security, reliability, recovery, accessibility, or integration regression returns the candidate to the appropriate earlier lifecycle state until corrected and revalidated.
