# Identity Center website

GoreeCloud Identity owns the standalone **Identity Center** public website source in this repository.

## Target address

- Public hostname: `https://id.goreecloud.com/`
- Cloudflare Pages project name: `goreecloud-identity`
- Production branch: `main`
- Framework preset: `None`
- Build command: `python scripts/build_identity_public_site.py`
- Build output directory: `dist`
- Root directory: blank

The Cloudflare project and DNS/custom-domain binding are deployment operations separate from source implementation. The website must not be described as publicly deployed until those operations and production verification are complete.

## GLAZE UI contract

The current governed consumer baseline remains **GLAZE UI V1.1 / 1.1.0**, tag `v1.1.0`, at immutable release revision `15cc76d2bcd4065552dc31c77145b63f34d9e7b2`.

The published V1.1 entrypoint is `css/glaze-v1.1.0.css`. Identity Center pins that release identity and all thirteen expected CSS Git blobs in `identity-center-site/glaze.lock.json` instead of following a mutable design-system branch or requiring a runtime UI CDN.

The immutable `v1.1.0` source graph currently has a known dependency defect: `glaze-v1.components.css` imports `./glaze-v1.candidate.css`, but that file is not part of the accepted release graph. A byte-perfect lock therefore does **not** establish a complete browser dependency graph.

Identity Center must fail closed on that condition. `scripts/build_identity_public_site.py` resolves every locked asset, verifies each Git blob, validates every local CSS `@import` against the complete locked set, and only then may replace `dist`. The current `v1.1.0` graph is consequently expected to fail the publication gate before a new artifact is written.

Canonical GLAZE UI repair work may prepare a corrected candidate, but Identity Center must not locally recreate the missing Candidate file, silently patch the immutable `v1.1.0` release, or treat an unreleased correction as Stable. A corrected immutable Stable Glaze release must be published and Identity must be explicitly re-pinned and revalidated before current Glaze conformance or website publication acceptance can be claimed.

The site follows the material rule **Content is solid. Interaction is glazed.** Durable identity, authority, policy, scope, and acceptance content remains on solid surfaces. Navigation, appropriate controls, and the bounded hero overview may use controlled Glaze material.

The public surface is designed for the 48px general interaction floor, 56px Touch Assistance floor, density and clarity semantics, large-text compatibility, reduced-motion and reduced-transparency handling, increased/forced-contrast resilience, safe-area behavior, and deliberate responsive navigation across desktop, tablet, and mobile. Those source properties remain subject to fresh rendered and accessibility acceptance after a valid immutable design-system graph is available.

GLAZE UI controls presentation only. It does not establish production Identity acceptance, authentication correctness, authorization authority, credential custody, recovery readiness, or application migration.

## Source layout

- `identity-center-site/` — reviewed standalone public source, deliberately isolated from the inherited authentik `website/` Docusaurus workspace
- `identity-center-site/assets/identity.svg` — byte-identical consumer derivative of `products/identity/app-icon.svg` from `GoreeCloud/goreecloud-branding-assets`
- `identity-center-site/glaze.lock.json` — immutable GLAZE UI V1.1 consumer lock, including release identity and exact Git blob identities
- `scripts/build_identity_public_site.py` — validates the complete locked GLAZE UI CSS dependency graph before creating the isolated `dist/` artifact
- `scripts/validate_identity_public_site.py` — validates branding provenance, GLAZE UI release/blob identity, security headers, truth boundaries, responsive/accessibility behavior, and artifact identity when the build dependency gate is satisfiable
- `.github/workflows/validate-website.yml` — exact-revision CI gate that checks out the pinned GLAZE UI release revision separately from the Identity source revision

No remote runtime GLAZE UI dependency is intended for the built site; after a complete accepted release graph exists, verified files are copied into the same-origin `/glaze/` artifact directory.

## Repository-boundary rule

The inherited authentik-derived `website/` directory remains a transitional upstream documentation workspace. Identity Center must not place standalone public-site files in that directory or depend on its package manager, Docusaurus build, formatting rules, or publication lifecycle. This separation prevents the native GoreeCloud public surface from becoming coupled to inherited product documentation architecture.

## Public truth boundary

Identity Center describes the approved GoreeCloud Identity domain and the current GoreeCloud-owned native work without converting planned scope into an implementation claim.

The inherited authentik-derived repository tree remains transitional migration/reference infrastructure. Source implementation, a passing non-publication test, a preview, or historical authentik behavior does not establish production GoreeCloud Identity, production application migration, recovery acceptance, website deployed-byte identity, or Stable qualification.

Identity remains authoritative for identity, authentication, authorization, accounts, devices, credentials, sessions, application/service identity, and delegated authority. Network connectivity, application-domain ownership and permissions, Wardveil Security, Privacy Shield, Everkeep, GLAZE UI, and GoreeCloud Mesh retain their separate authorities.
