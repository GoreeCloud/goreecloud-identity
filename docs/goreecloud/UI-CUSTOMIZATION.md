# GoreeCloud Identity UI Customization Boundaries

This document records the first GoreeCloud-specific map of the current upstream user-interface and theming seams. It is intentionally conservative: it identifies places that exist in this exact fork baseline without authorizing deep front-end divergence.

## Objective

GoreeCloud Identity should progressively adopt the Glaze UI design language while preserving upstream maintainability, accessibility, authentication correctness, and upgradeability.

The preferred order of customization is:

1. deployment-level brand configuration and CSS custom properties;
2. upstream-provided brand/theme layers and supported custom CSS;
3. narrowly scoped GoreeCloud theme additions that consume existing tokens and component parts;
4. small component-level changes when the first three approaches cannot satisfy a documented requirement;
5. deep UI or identity-flow rewrites only after explicit review.

## Confirmed upstream styling architecture

The current baseline documents its front-end styling system in `web/src/styles/README.md`.

The important current entry points are:

- `web/src/styles/interface.global.css` — Admin and User interfaces;
- `web/src/styles/flows.global.css` — authentication and enrollment flows;
- `web/src/styles/static.global.css` — Django-rendered static templates;
- `web/src/styles/layers.css` — CSS layer ordering;
- `web/src/styles/global/` — document-level reset, theme, mode, locale, and brand definitions;
- `web/src/styles/shadow/` — styles adopted by shared web-component shadow roots;
- `web/src/styles/authentik/` — component and login-screen styling;
- `packages/theme/` — the upstream theme package used by the web application.

The current upstream layer order is:

```css
@layer reset, vendor, components, theme, mode, brand;
```

The upstream design-system documentation explicitly reserves the `brand` layer for per-deployment branding and describes CSS custom properties as the principal token mechanism. It also documents a custom-CSS path for advanced branding. That makes token-level and brand-layer customization the preferred first implementation seam for Glaze UI.

## GoreeCloud implementation boundary

During the foundation phase, GoreeCloud should not rename upstream package identities, replace PatternFly wholesale, or rewrite authentication-flow components merely to achieve visual differentiation.

Initial Glaze UI work should concentrate on:

- color, surface, border, radius, shadow, spacing, and typography tokens that can be represented safely as CSS custom properties;
- GoreeCloud logos, marks, favicons, and product naming through supported branding surfaces;
- sign-in, enrollment, recovery, and account-security presentation without changing the security semantics of those flows;
- accessible light/dark/high-contrast behavior that continues to respect upstream mode handling;
- responsive behavior and touch targets without bypassing upstream component contracts.

## Surfaces requiring extra caution

The following surfaces are security-sensitive even when a requested change appears visual:

- login and re-authentication flows;
- MFA and passkey enrollment;
- recovery and password-reset interfaces;
- OAuth/OIDC consent and authorization screens;
- session and credential management;
- administrative identity and policy controls;
- error states that distinguish authentication failure from authorization failure.

Changes to these surfaces must preserve labels, warnings, confirmation steps, anti-phishing signals, accessibility semantics, and server-side enforcement.

## Recommended Glaze UI path

### Phase 1 — token overlay

Create a small GoreeCloud-owned token overlay that targets the upstream brand layer or supported deployment-level custom CSS. Avoid editing vendored PatternFly resources.

The first token set should cover only values that can be changed without altering interaction semantics. Each token should map back to a Glaze UI design decision rather than becoming an application-specific one-off.

### Phase 2 — asset and identity pass

Replace product-facing assets and naming through supported brand configuration. Keep upstream legal and provenance notices where required by licenses or repository-maintenance policy.

### Phase 3 — component exceptions

Where token-level branding cannot reproduce the required Glaze UI behavior, document the specific component, the upstream limitation, the smallest required code change, accessibility impact, and expected merge burden before modifying component source.

### Phase 4 — upstream synchronization test

Before accepting substantial UI divergence, perform an upstream synchronization exercise and verify that the GoreeCloud layer can be reapplied without broad manual conflict resolution.

## Non-goals for the current phase

The current phase does not authorize:

- authentication protocol changes;
- cryptographic changes;
- database or migration changes;
- replacement of the upstream front-end framework;
- removal of upstream accessibility modes;
- replacement of the complete admin interface;
- production deployment or migration of GoreeCloud users.

## Acceptance criteria for the first Glaze UI implementation

A first visual implementation is acceptable only when:

- the GoreeCloud layer is clearly separated from upstream-owned styling where practical;
- upstream CSS entry points still build normally;
- login, logout, recovery, MFA/passkey, and authorization flows retain their original security behavior;
- keyboard navigation and visible focus remain functional;
- light/dark and reduced-motion behavior remain coherent;
- no reusable secret or production credential is introduced;
- the change can be reverted without data migration;
- the divergence is documented for future upstream synchronization.
