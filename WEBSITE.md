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

## Source layout

- `identity-center-site/` — reviewed standalone public source, deliberately isolated from the inherited authentik `website/` Docusaurus workspace
- `identity-center-site/assets/identity.svg` — byte-identical consumer derivative of `products/identity/app-icon.svg` from `GoreeCloud/goreecloud-branding-assets`
- `scripts/build_identity_public_site.py` — creates the isolated `dist/` artifact
- `scripts/validate_identity_public_site.py` — validates branding provenance, Glaze UI markers, security headers, truth boundaries, and artifact identity
- `.github/workflows/validate-website.yml` — exact-revision CI gate

## Repository-boundary rule

The inherited authentik-derived `website/` directory remains a transitional upstream documentation workspace. Identity Center must not place standalone public-site files in that directory or depend on its package manager, Docusaurus build, formatting rules, or publication lifecycle. This separation prevents the native GoreeCloud public surface from becoming coupled to inherited product documentation architecture.

## Public truth boundary

Identity Center describes the approved GoreeCloud Identity domain and the current GoreeCloud-owned native work without converting planned scope into an implementation claim.

The inherited authentik-derived repository tree remains transitional migration/reference infrastructure. Source implementation, successful CI, a preview deployment, or historical authentik behavior do not establish production GoreeCloud Identity, production application migration, recovery acceptance, or Stable qualification.

Identity remains authoritative for identity, authentication, authorization, accounts, devices, credentials, sessions, application/service identity, and delegated authority. Network connectivity, application-domain ownership and permissions, Wardveil Security, Privacy Shield, Everkeep, Glaze UI, and GoreeCloud Mesh retain their separate authorities.
