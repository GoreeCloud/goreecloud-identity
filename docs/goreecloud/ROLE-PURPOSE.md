# GoreeCloud Identity Role and Purpose

## Role

GoreeCloud Identity is the centralized authentication, single sign-on, and identity-provider platform for approved GoreeCloud applications and services.

## Purpose

Its purpose is to provide a common platform identity, reduce duplicated authentication implementation across GoreeCloud applications, support standards-based OIDC/OAuth 2.0 integrations, retain compatibility protocols where justified, centralize account/session/authenticator security where appropriate, and preserve a controlled self-hosted identity foundation without making Identity the authorization database for every application.

## Boundaries

Identity establishes who a user is. Each relying application remains responsible for authorization to its own data and actions. Identity is a shared platform capability rather than a family-content store. It belongs with infrastructure/shared platform services and requires independent recovery and monitoring because failure can affect access to multiple applications.
