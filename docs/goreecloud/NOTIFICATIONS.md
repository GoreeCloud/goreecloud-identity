# GoreeCloud Identity Notification Boundary

Identity notifications may communicate security-relevant account, administrative, recovery, integration, or operational events where an approved notification channel exists.

## Privacy and security

Notifications must minimize identity data and must not contain reusable passwords, bearer tokens, session cookies, OAuth/OIDC client secrets, private keys, recovery codes, or direct secret-bearing URLs.

## Actionability

Security notifications should distinguish informational events from events that require user or administrator action. Links or instructions should direct users to an authenticated GoreeCloud-controlled interface rather than exposing sensitive state in the notification itself.

## Reliability

Notification failure must not silently replace server-side enforcement. Authentication, authorization, session revocation, and recovery controls remain authoritative even when a notification cannot be delivered.
