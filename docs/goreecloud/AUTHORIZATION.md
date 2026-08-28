# GoreeCloud Identity Authorization Boundary

Authentication through GoreeCloud Identity does not grant blanket authorization inside relying applications.

## Core rule

Identity proves or conveys who the user is according to the approved protocol and provider policy. Each GoreeCloud application remains authoritative for permissions to its own records, projects, files, notes, tasks, administrative functions, and other application-owned resources.

## Administrative authorization

Identity administrative permissions are themselves security-sensitive and must use least privilege, individually attributable identities, and auditable role changes. Ordinary user accounts must not receive administrative capabilities merely because they can authenticate successfully.

## Integration validation

Representative application testing must include successful login for an authorized user and denied access for an identity that lacks application authorization. Failure must remain fail-closed without exposing another user's data.
