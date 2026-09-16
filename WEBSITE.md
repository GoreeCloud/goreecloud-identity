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

Identity Center's **implemented presentation baseline remains historical GLAZE UI V1.1 / 1.1.0**. The original immutable V1.1 Stable release identity is tag `v1.1.0` at revision `15cc76d2bcd4065552dc31c77145b63f34d9e7b2`.

That original immutable release has a known CSS dependency defect: `glaze-v1.components.css` imports `./glaze-v1.candidate.css`, but that file is not part of the accepted V1.1 release graph. GoreeCloud later repaired that inherited V1 import closure canonically in the Glaze repository rather than rewriting the immutable V1.1 tag.

Current Glaze lifecycle authority is **GLAZE UI V1.5 / 1.5.0 Stable**. Identity Center therefore sources its locked historical V1 CSS graph from exact V1.5.0 Stable integration revision `b7fa8164bfdeaa1dc0acb21b770e7601120da04e`, where the canonical V1 import-closure repair is present. The historical V1.1 release identity remains recorded separately for provenance.

This distinction is deliberate:

- Identity Center is **not** relabeled as a V1.5.0 consumer merely because its historical V1 assets are sourced from a later Stable repository revision.
- The site still declares and renders its existing V1.1 / 1.1.0 presentation semantics.
- `identity-center-site/glaze.lock.json` records both the immutable historical V1.1 release revision and the exact repaired source revision used to build the closed asset graph.
- Every copied CSS file remains Git-blob pinned. The only historical V1 asset whose bytes differ from the original V1.1 release is the canonically repaired `glaze-v1.components.css` dependency layer.
- Migration to current Stable GLAZE UI V1.5 / 1.5.0 remains separate product work requiring repository-local source, rendered, accessibility, representative-target, rollback, release, and production acceptance.

The published historical V1.1 entrypoint remains `css/glaze-v1.1.0.css`. Identity Center validates every locked asset, every Git blob identity, and complete local CSS `@import` closure before replacing `dist`. It does not recreate the missing Candidate file, mutate the immutable V1.1 tag, consume an unreleased repair, or treat source compatibility as current-Stable consumer acceptance.

The site follows the material rule **Content is solid. Interaction is glazed.** Durable identity, authority, policy, scope, and acceptance content remains on solid surfaces. Navigation, appropriate controls, and the bounded hero overview may use controlled Glaze material.

The public surface is designed for the 48px general interaction floor, 56px Touch Assistance floor, density and clarity semantics, large-text compatibility, reduced-motion and reduced-transparency handling, increased/forced-contrast resilience, safe-area behavior, and deliberate responsive navigation across desktop, tablet, and mobile. Those source properties remain subject to fresh rendered and accessibility acceptance for any current-Stable migration.

GLAZE UI controls presentation only. It does not establish production Identity acceptance, authentication correctness, authorization authority, credential custody, recovery readiness, or application migration.

## Source layout

- `identity-center-site/` — reviewed standalone public source, deliberately isolated from the inherited authentik `website/` Docusaurus workspace
- `identity-center-site/assets/identity.svg` — byte-identical consumer derivative of `products/identity/app-icon.svg` from `GoreeCloud/goreecloud-branding-assets`
- `identity-center-site/glaze.lock.json` — exact historical V1.1 presentation lock plus current-Stable repaired source provenance and exact Git blob identities
- `scripts/build_identity_public_site.py` — validates the complete locked GLAZE UI CSS dependency graph before creating the isolated `dist/` artifact
- `scripts/validate_identity_public_site.py` — validates branding provenance, historical-baseline/current-source distinction, security headers, truth boundaries, responsive/accessibility behavior, and artifact identity
- `.github/workflows/validate-website.yml` — exact-revision CI gate that checks out the pinned current Stable Glaze source revision separately from the Identity source revision

No remote runtime GLAZE UI dependency is intended for the built site; verified files are copied into the same-origin `/glaze/` artifact directory.

## Repository-boundary rule

The inherited authentik-derived `website/` directory remains a transitional upstream documentation workspace. Identity Center must not place standalone public-site files in that directory or depend on its package manager, Docusaurus build, formatting rules, or publication lifecycle. This separation prevents the native GoreeCloud public surface from becoming coupled to inherited product documentation architecture.

## Public truth boundary

Identity Center describes the approved GoreeCloud Identity domain and the current GoreeCloud-owned native work without converting planned scope into an implementation claim.

The inherited authentik-derived repository tree remains transitional migration/reference infrastructure. Source implementation, a passing non-publication test, a preview, or historical authentik behavior does not establish production GoreeCloud Identity, production application migration, recovery acceptance, website deployed-byte identity, or Stable qualification.

Identity remains authoritative for identity, authentication, authorization, accounts, devices, credentials, sessions, application/service identity, and delegated authority. Network connectivity, application-domain ownership and permissions, Wardveil Security, Privacy Shield, Everkeep, GLAZE UI, and GoreeCloud Mesh retain their separate authorities.
