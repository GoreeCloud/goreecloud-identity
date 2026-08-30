#!/usr/bin/env python3
from hashlib import sha1
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "identity-center-site"
DIST = ROOT / "dist"
REQUIRED = (
    "index.html", "style.css", "glaze-ui-2.0.0.css", "app.js", "_headers",
    "robots.txt", "sitemap.xml", "assets/identity.svg",
)

for relative in REQUIRED:
    path = SITE / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"missing or unsafe Identity Center source: {relative}")

html = (SITE / "index.html").read_text(encoding="utf-8")
css = (SITE / "style.css").read_text(encoding="utf-8")
headers = (SITE / "_headers").read_text(encoding="utf-8")
icon = (SITE / "assets/identity.svg").read_bytes()

def git_blob_sha(data: bytes) -> str:
    return sha1(f"blob {len(data)}\0".encode() + data).hexdigest()

for marker in (
    "Identity Center — GoreeCloud", "GoreeCloud Identity", "Identity Center",
    "One identity.", "Accounts", "Authentication", "Authorization",
    "Devices + sessions", "Apps + services", "Recovery + audit",
    "Single sign-on must not collapse security boundaries",
    "Identity is not Network", "Identity is not GoreeVault",
    "Production identity remains a separate acceptance gate",
    "Not yet accepted", "authentik-derived transitional runtime",
    'name="goreecloud-glaze-ui" content="2.0.0"', 'data-glaze-ui="2.0.0"',
):
    if marker not in html:
        raise SystemExit(f"Identity Center marker missing: {marker}")

for forbidden in (
    "production-ready", "Production Ready", "fully migrated", "fully deployed",
    "permanent authentik architecture", "data:image", "raw.githubusercontent.com",
):
    if forbidden in html:
        raise SystemExit(f"Identity Center publishes forbidden or misleading marker: {forbidden}")

if git_blob_sha(icon) != "dc8287e385f86767f0105c48a8f234d8440d7623":
    raise SystemExit("Identity Center icon derivative does not match the approved canonical Git blob")

for src in re.findall(r'(?:src|href)=["\']([^"\']+)', html):
    if src.startswith(("http://", "https://")) and "github.com/GoreeCloud/" not in src and "goreecloud.com/" not in src:
        raise SystemExit(f"unauthorized external link/resource: {src}")

for directive in (
    "Content-Security-Policy:", "default-src 'self'", "connect-src 'none'",
    "frame-ancestors 'none'", "X-Content-Type-Options: nosniff",
):
    if directive not in headers:
        raise SystemExit(f"Identity Center security header marker missing: {directive}")
if not headers.startswith("/*\n  X-Content-Type-Options: nosniff") or "\n*/" in headers:
    raise SystemExit("Identity Center _headers must use Cloudflare Pages route syntax, not CSS comment syntax")

for marker in ("prefers-reduced-motion", "prefers-reduced-transparency", "forced-colors", "--g-touch:48px"):
    if marker not in css:
        raise SystemExit(f"Identity Center accessibility/responsiveness marker missing: {marker}")

subprocess.run([sys.executable, str(ROOT / "scripts" / "build_identity_public_site.py")], check=True)
for relative in REQUIRED:
    if (DIST / relative).read_bytes() != (SITE / relative).read_bytes():
        raise SystemExit(f"isolated Identity Center artifact drifted from reviewed source: {relative}")
print("Identity Center public website validation passed")
