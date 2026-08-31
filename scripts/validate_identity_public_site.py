#!/usr/bin/env python3
import re
from hashlib import sha1
from pathlib import Path

from build_identity_public_site import build

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "identity-center-site"
DIST = ROOT / "dist"
GLAZE_ASSET = "glaze-ui-2.1.0.css"
GLAZE_PROMOTION_REVISION = "c49113eb8b93c267613fdf1bbca1f814495acad7"
REQUIRED = (
    "index.html",
    "style.css",
    GLAZE_ASSET,
    "app.js",
    "_headers",
    "robots.txt",
    "sitemap.xml",
    "assets/identity.svg",
)
APPROVED_ICON_GIT_BLOB_SHA = "dc8287e385f86767f0105c48a8f234d8440d7623"


def git_blob_sha(data: bytes) -> str:
    """Return the Git object identifier for byte-identity comparison only."""

    payload = f"blob {len(data)}\0".encode() + data
    return sha1(payload, usedforsecurity=False).hexdigest()


for relative in REQUIRED:
    path = SITE / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"missing or unsafe Identity Center source: {relative}")

html = (SITE / "index.html").read_text(encoding="utf-8")
css = (SITE / "style.css").read_text(encoding="utf-8")
glaze = (SITE / GLAZE_ASSET).read_text(encoding="utf-8")
headers = (SITE / "_headers").read_text(encoding="utf-8")
icon = (SITE / "assets/identity.svg").read_bytes()

for marker in (
    "Identity Center — GoreeCloud",
    "GoreeCloud Identity",
    "Identity Center",
    "One identity.",
    "Accounts",
    "Authentication",
    "Authorization",
    "Devices + sessions",
    "Apps + services",
    "Recovery + audit",
    "Single sign-on must not collapse security boundaries",
    "Identity is not Network",
    "Identity is not GoreeVault",
    "Production identity remains a separate acceptance gate",
    "Not yet accepted",
    "authentik-derived transitional runtime",
    'name="goreecloud-glaze-ui" content="2.1.0"',
    'data-glaze-ui="2.1.0"',
    'class="topbar glaze-material-soft"',
    'class="glaze-navigation-capsule"',
):
    if marker not in html:
        raise SystemExit(f"Identity Center marker missing: {marker}")

for forbidden in (
    "production-ready",
    "Production Ready",
    "fully migrated",
    "fully deployed",
    "permanent authentik architecture",
    "glaze-ui-2.0.0.css",
    'data-glaze-ui="2.0.0"',
    "data:image",
    "raw.githubusercontent.com",
):
    if forbidden in html:
        raise SystemExit(f"Identity Center publishes forbidden or misleading marker: {forbidden}")

if "Content is solid. Interaction is glazed." not in glaze:
    raise SystemExit("Identity Center Glaze UI 2.1 material rule is missing")
if GLAZE_PROMOTION_REVISION not in glaze:
    raise SystemExit("Identity Center Glaze UI 2.1 promotion reference is missing")
if "--glaze-touch-min:48px" not in glaze or "--glaze-touch-assisted:56px" not in glaze:
    raise SystemExit("Identity Center Glaze UI 2.1 touch floors are missing")
if "--g-touch-assisted:56px" not in css:
    raise SystemExit("Identity Center Touch Assistance fallback is missing")
if "background:var(--g-surface-strong)" not in css:
    raise SystemExit("Identity Center durable-content solid material marker is missing")
if ".topbar nav{display:flex;order:3;width:100%" not in css:
    raise SystemExit("Identity Center responsive primary-navigation fallback is missing")

if git_blob_sha(icon) != APPROVED_ICON_GIT_BLOB_SHA:
    raise SystemExit(
        "Identity Center icon derivative does not match the approved canonical Git blob"
    )

for src in re.findall(r'(?:src|href)=["\']([^"\']+)', html):
    is_external = src.startswith(("http://", "https://"))
    is_approved = "github.com/GoreeCloud/" in src or "goreecloud.com/" in src
    if is_external and not is_approved:
        raise SystemExit(f"unauthorized external link/resource: {src}")

for directive in (
    "Content-Security-Policy:",
    "default-src 'self'",
    "connect-src 'none'",
    "frame-ancestors 'none'",
    "X-Content-Type-Options: nosniff",
):
    if directive not in headers:
        raise SystemExit(f"Identity Center security header marker missing: {directive}")
if not headers.startswith("/*\n  X-Content-Type-Options: nosniff") or "\n*/" in headers:
    raise SystemExit(
        "Identity Center _headers must use Cloudflare Pages route syntax, not CSS comment syntax"
    )

for marker in (
    "prefers-reduced-motion",
    "prefers-reduced-transparency",
    "prefers-contrast:more",
    "forced-colors",
    "--g-touch:48px",
):
    if marker not in css:
        raise SystemExit(
            f"Identity Center accessibility/responsiveness marker missing: {marker}"
        )

build()
for relative in REQUIRED:
    if (DIST / relative).read_bytes() != (SITE / relative).read_bytes():
        raise SystemExit(
            f"isolated Identity Center artifact drifted from reviewed source: {relative}"
        )
if (DIST / "glaze-ui-2.0.0.css").exists():
    raise SystemExit("obsolete Glaze UI 2.0 asset leaked into Identity Center artifact")
print("Identity Center public website validation passed with Glaze UI 2.1.0 Stable")
