# Identity Center website

GoreeCloud Identity owns the standalone **Identity Center** public website source in this repository.

## Target address

- Public hostname: `https://identity.goreecloud.com/`
- Cloudflare Pages project name: `goreecloud-identity`
- Production branch: `main`
- Framework preset: `None`
- Build command: `python scripts/build_identity_public_site.py`
- Build output directory: `dist`
- Root directory: blank

The Cloudflare project and DNS/custom-domain binding are deployment operations separate from source implementation. The website must not be described as publicly deployed until those operations and production verification are complete.

## Glaze UI contract

Identity Center targets **Glaze UI 2.1.0 Stable**, promoted from canonical design-system revision `c49113eb8b93c267613fdf1bbca1f814495acad7`.

The site follows the 2.1 material rule **Content is solid. Interaction is glazed.** Durable identity, authority, policy, scope, and acceptance content remains on solid surfaces. Navigation, appropriate controls, and the bounded hero overview may use controlled Glaze material.

The public surface carries the 48px general interaction floor, 56px Touch Assistance floor, density and clarity semantics, large-text compatibility, reduced-motion and reduced-transparency handling, increased/forced-contrast resilience, safe-area behavior, and responsive navigation across desktop, tablet, and mobile.

Glaze UI controls presentation only. It does not establish production Identity acceptance, authentication correctness, authorization authority, credential custody, recovery readiness, or application migration.

## Source layout

- `identity-center-site/` — reviewed standalone public source, deliberately isolated from the inherited authentik `website/` Docusaurus workspace
- `identity-center-site/assets/identity.svg` — byte-identical consumer derivative of `products/identity/app-icon.svg` from `GoreeCloud/goreecloud-branding-assets`
- `identity-center-site/glaze-ui-2.1.0.css` — same-origin Glaze UI 2.1.0 Stable public integration bundle
- `scripts/build_identity_public_site.py` — creates the isolated `dist/` artifact
- `scripts/validate_identity_public_site.py` — validates branding provenance, Glaze UI markers, security headers, truth boundaries, responsive/accessibility behavior, and artifact identity
- `.github/workflows/validate-website.yml` — exact-revision CI gate

## Repository-boundary rule

The inherited authentik-derived `website/` directory remains a transitional upstream documentation workspace. Identity Center must not place standalone public-site files in that directory or depend on its package manager, Docusaurus build, formatting rules, or publication lifecycle. This separation prevents the native GoreeCloud public surface from becoming coupled to inherited product documentation architecture.

## Public truth boundary

Identity Center describes the approved GoreeCloud Identity domain and the current GoreeCloud-owned native work without converting planned scope into an implementation claim.

The inherited authentik-derived repository tree remains transitional migration/reference infrastructure. Source implementation, successful CI, a preview deployment, or historical authentik behavior do not establish production GoreeCloud Identity, production application migration, recovery acceptance, or Stable qualification.

Identity remains authoritative for identity, authentication, authorization, accounts, devices, credentials, sessions, application/service identity, and delegated authority. Network connectivity, application-domain ownership and permissions, Wardveil Security, Privacy Shield, Everkeep, Glaze UI, and GoreeCloud Mesh retain their separate authorities.
