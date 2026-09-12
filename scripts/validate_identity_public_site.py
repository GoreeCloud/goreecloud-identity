#!/usr/bin/env python3
import json
import re
from hashlib import sha1
from pathlib import Path
from urllib.parse import urlsplit

from build_identity_public_site import build

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "identity-center-site"
DIST = ROOT / "dist"
LOCK_PATH = SITE / "glaze.lock.json"
SOURCE_FILES = (
    "index.html",
    "style.css",
    "app.js",
    "_headers",
    "robots.txt",
    "sitemap.xml",
    "assets/identity.svg",
)
APPROVED_ICON_GIT_BLOB_SHA = "dc8287e385f86767f0105c48a8f234d8440d7623"
PUBLIC_HOST = "id.goreecloud.com"
PUBLIC_ORIGIN = f"https://{PUBLIC_HOST}"
GLAZE_STABLE_COMMIT = "15cc76d2bcd4065552dc31c77145b63f34d9e7b2"
EXPECTED_GLAZE_FILES = {
    "glaze-v1.1.0.css": "c689e8e58cefc49f931862996a1e0e871497fe88",
    "glaze-v1.0.0.css": "eca2209c5d678830f92907b4d44ea6cc5b1c8536",
    "glaze-v1.1.css": "aa0250f01151f17cd3c77e9a67544c6af4b5aa32",
    "glaze-v1.1-appearance.css": "c4e10e043d537c68f1e4a5f97bdb8b6f0d371dce",
    "glaze-v1.foundation.css": "b01051203831ce011c08f37b79f2e2032d34d0c8",
    "glaze-v1.components.css": "f74d5d4a4dd3ae22354812260e06a042d3928507",
    "glaze-v1.components.adaptive.css": "e174ea4923ec1ac6e1eb52d7ee33c14f2f77d5ca",
    "glaze-v1.components.runtime.css": "a89356172d74b66c62cfda198ae827fe9b71c520",
    "glaze-v1.structure.css": "9781c3e162edbac9fce67b93fd3287fdacbcd504",
    "glaze-v1.overlay.css": "cb937fae3166289c9c935d7ae25cefe3f82f3ec0",
    "glaze-v1.advanced.css": "d6e60a9b23354b1dc62dafac284c93b772e582a4",
    "glaze-v1.visual-refinement.css": "f5696fdb81f8deda3ce75e112989d772b7d74909",
    "glaze-v1.optical-reachability.css": "6123cff22f06b4c537156a1285e2664763f33316",
}


def git_blob_sha(data: bytes) -> str:
    """Return the Git object identifier for byte-identity comparison only."""

    payload = f"blob {len(data)}\0".encode() + data
    return sha1(payload, usedforsecurity=False).hexdigest()


def approved_external_url(value: str) -> bool:
    """Allow only exact HTTPS GoreeCloud web hosts or the GoreeCloud GitHub org."""

    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port:
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if host == "github.com":
        return parsed.path == "/GoreeCloud" or parsed.path.startswith("/GoreeCloud/")
    return host == "goreecloud.com" or host.endswith(".goreecloud.com")


for relative in SOURCE_FILES:
    path = SITE / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"missing or unsafe Identity Center source: {relative}")
if not LOCK_PATH.is_file() or LOCK_PATH.is_symlink():
    raise SystemExit("missing or unsafe Identity Center Glaze consumer lock")

lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
expected_lock = {
    "schema": "goreecloud.glaze.consumer-lock.v1",
    "version": "1.1.0",
    "lifecycle": "Stable",
    "repository": "GoreeCloud/goreecloud-glaze-ui",
    "tag": "v1.1.0",
    "stable_commit": GLAZE_STABLE_COMMIT,
    "files": EXPECTED_GLAZE_FILES,
}
if lock != expected_lock:
    raise SystemExit("Identity Center GLAZE UI V1.1 / 1.1.0 Stable consumer lock drifted")

html = (SITE / "index.html").read_text(encoding="utf-8")
css = (SITE / "style.css").read_text(encoding="utf-8")
headers = (SITE / "_headers").read_text(encoding="utf-8")
robots = (SITE / "robots.txt").read_text(encoding="utf-8")
sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")
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
    'name="goreecloud-glaze-ui" content="1.1.0"',
    'href="/glaze/glaze-v1.1.0.css"',
    'data-glaze-ui="1.1.0"',
    'data-glaze-version="1.1"',
    'class="topbar glaze-material-soft"',
    'class="glaze-navigation-capsule"',
    f'rel="canonical" href="{PUBLIC_ORIGIN}/"',
    f"<dd>{PUBLIC_HOST}</dd>",
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
    "glaze-ui-2.1.0.css",
    "glaze-2.2.0.css",
    'data-glaze-ui="2.0.0"',
    'data-glaze-ui="2.1.0"',
    'data-glaze-ui="2.2.0"',
    "2.2.0-candidate.1",
    "data:image",
    "raw.githubusercontent.com",
    "identity.goreecloud.com",
):
    if forbidden in html + robots + sitemap:
        raise SystemExit(f"Identity Center publishes forbidden or misleading marker: {forbidden}")

if f"Sitemap: {PUBLIC_ORIGIN}/sitemap.xml" not in robots:
    raise SystemExit("Identity Center robots.txt does not use the approved public hostname")
if f"<loc>{PUBLIC_ORIGIN}/</loc>" not in sitemap:
    raise SystemExit("Identity Center sitemap does not use the approved public hostname")

if "--g-touch-assisted:56px" not in css:
    raise SystemExit("Identity Center Touch Assistance fallback is missing")
if "background:var(--g-surface-strong)" not in css:
    raise SystemExit("Identity Center durable-content solid material marker is missing")
if ".glaze-material{background:var(--g-surface)" not in css:
    raise SystemExit("Identity Center bounded Glaze interaction material marker is missing")
if html.count('class="hero-panel glaze-material"') != 1:
    raise SystemExit("Identity Center must keep exactly one dominant Glaze panel")

responsive_markers = (
    ".topbar{position:relative;inset:auto;",
    ".topbar nav{grid-column:1/-1;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));",
    ".topbar nav{grid-template-columns:repeat(2,minmax(0,1fr));",
    ".hero{grid-template-columns:1fr;padding-top:58px;",
    ".hero-actions{display:grid;grid-template-columns:1fr;",
    ".card-grid,.boundary-grid{grid-template-columns:1fr}",
    ".footer nav{grid-template-columns:repeat(2,minmax(0,1fr))}",
)
for marker in responsive_markers:
    if marker not in css:
        raise SystemExit(f"Identity Center responsive contract marker missing: {marker}")

for stale_pattern in (
    ".topbar{position:sticky",
    ".topbar nav{display:flex;order:3;width:100%",
    "overflow-x:auto",
):
    if stale_pattern in css:
        raise SystemExit(
            "Identity Center retains obsolete sticky/scroller responsive pattern: "
            f"{stale_pattern}"
        )

if git_blob_sha(icon) != APPROVED_ICON_GIT_BLOB_SHA:
    raise SystemExit(
        "Identity Center icon derivative does not match the approved canonical Git blob"
    )

for src in re.findall(r'(?:src|href)=["\']([^"\']+)', html):
    if src.startswith("//"):
        raise SystemExit(f"protocol-relative resource is not allowed: {src}")
    if src.startswith(("http://", "https://")) and not approved_external_url(src):
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
        raise SystemExit(f"Identity Center accessibility/responsiveness marker missing: {marker}")

build()

for relative in SOURCE_FILES:
    if (DIST / relative).read_bytes() != (SITE / relative).read_bytes():
        raise SystemExit(
            f"isolated Identity Center artifact drifted from reviewed source: {relative}"
        )

for name, expected_sha in EXPECTED_GLAZE_FILES.items():
    built = DIST / "glaze" / name
    if not built.is_file() or built.is_symlink():
        raise SystemExit(f"missing or unsafe built Glaze asset: {name}")
    actual_sha = git_blob_sha(built.read_bytes())
    if actual_sha != expected_sha:
        raise SystemExit(
            f"built Glaze asset identity drifted for {name}: {actual_sha} != {expected_sha}"
        )

for obsolete in (
    DIST / "glaze-ui-2.0.0.css",
    DIST / "glaze-ui-2.1.0.css",
    DIST / "glaze" / "glaze-2.1.0.css",
    DIST / "glaze" / "glaze-2.2.0.css",
):
    if obsolete.exists():
        raise SystemExit(f"obsolete Glaze asset leaked into artifact: {obsolete.name}")

print(
    "Identity Center public website validation passed with "
    f"GLAZE UI V1.1 / 1.1.0 Stable at {GLAZE_STABLE_COMMIT}"
)
