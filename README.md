# GoreeCloud Identity

> **Foundation status:** GoreeCloud Identity is a GoreeCloud-maintained fork of [`goauthentik/authentik`](https://github.com/goauthentik/authentik). It is being developed as the long-term authentication and identity authority for participating GoreeCloud applications. This fork is not yet approved for GoreeCloud-wide production SSO.

The project intentionally retains authentik's mature identity-provider foundation while GoreeCloud establishes its own product boundaries, Glaze UI experience, deployment model, recovery controls, and application-integration contracts.

- GoreeCloud project boundary: [`GOREECLOUD.md`](GOREECLOUD.md)
- Upstream maintenance contract: [`UPSTREAM.md`](UPSTREAM.md)
- GoreeCloud architecture baseline: [`docs/goreecloud/ARCHITECTURE.md`](docs/goreecloud/ARCHITECTURE.md)
- UI customization boundaries: [`docs/goreecloud/UI-CUSTOMIZATION.md`](docs/goreecloud/UI-CUSTOMIZATION.md)
- Validation gates: [`docs/goreecloud/VALIDATION.md`](docs/goreecloud/VALIDATION.md)
- Upstream security policy and reporting: [`SECURITY.md`](SECURITY.md)

---

## Upstream authentik

<p align="center">
    <img src="https://goauthentik.io/img/icon_top_brand_colour.svg" height="150" alt="authentik logo">
</p>

[![Join Discord](https://img.shields.io/discord/809154715984199690?label=Discord&style=for-the-badge)](https://goauthentik.io/discord)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/goauthentik/authentik/ci-main.yml?branch=main&label=core%20build&style=for-the-badge)](https://github.com/goauthentik/authentik/actions/workflows/ci-main.yml)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/goauthentik/authentik/ci-outpost.yml?branch=main&label=outpost%20build&style=for-the-badge)](https://github.com/goauthentik/authentik/actions/workflows/ci-outpost.yml)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/goauthentik/authentik/ci-web.yml?branch=main&label=web%20build&style=for-the-badge)](https://github.com/goauthentik/authentik/actions/workflows/ci-web.yml)
[![Code Coverage](https://img.shields.io/codecov/c/gh/goauthentik/authentik?style=for-the-badge)](https://codecov.io/gh/goauthentik/authentik)
![Latest version](https://img.shields.io/docker/v/authentik/server?sort=semver&style=for-the-badge)
[![](https://img.shields.io/badge/Help%20translate-transifex-blue?style=for-the-badge)](https://explore.transifex.com/authentik/authentik/)

### What is authentik?

authentik is an open-source Identity Provider (IdP) for modern SSO. It supports SAML, OAuth2/OIDC, LDAP, RADIUS, and more, designed for self-hosting from small labs to large production clusters.

The upstream enterprise offering is available for organizations that need additional commercial capabilities. GoreeCloud's maintained fork preserves upstream licensing boundaries and does not treat enterprise-licensed code as MIT-licensed GoreeCloud code.

### Installation

Upstream provides multiple deployment methods, including Docker Compose and Kubernetes. GoreeCloud will separately validate and document its approved deployment rather than treating an upstream installation example as automatic production approval.

See the upstream [Developer Documentation](https://docs.goauthentik.io/docs/developer-docs/) for build and contribution information.

### Security

Please see [`SECURITY.md`](SECURITY.md). GoreeCloud will continue to track upstream security fixes as a priority and will keep local divergence low enough to integrate relevant fixes promptly.

### License

The repository preserves upstream licensing and attribution. See [`LICENSE`](LICENSE), [`website/LICENSE`](website/LICENSE), and [`authentik/enterprise/LICENSE`](authentik/enterprise/LICENSE) for the applicable licensing boundaries.