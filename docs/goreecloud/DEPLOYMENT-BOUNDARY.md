# GoreeCloud Identity Deployment Boundary

GoreeCloud Identity is intended for self-hosted deployment with Docker and Docker Compose where appropriate, with long-term placement in the GoreeCloud Infrastructure Services environment.

## Network publication

The service must follow the approved GoreeCloud private web-service publication model: private DNS and NetBird provide the approved access path, Caddy is the controlled HTTPS reverse-proxy authority, and backend application ports are not exposed directly to the public internet.

## Container and dependency controls

Container images and supporting services must use controlled, documented versions. Production credentials and secrets are externalized from repository source and ordinary documentation. Database and other supporting services should be reachable only by components that require them.

## Health checks

Health/readiness checks must confirm meaningful service state without disclosing authentication details, credentials, tokens, or user-specific information. Independent monitoring must be able to detect loss of Identity without depending on a successful Identity login.

## Production gate

No DNS, Caddy, NetBird, firewall, database, credential, or production-runtime cutover is authorized solely by source merge. Target-environment deployment requires the production-readiness and release-acceptance evidence defined in this directory.
