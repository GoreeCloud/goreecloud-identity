#!/usr/bin/env python3
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "identity-center-site"
DIST = ROOT / "dist"
LOCK = json.loads((SOURCE / "glaze.lock.json").read_text(encoding="utf-8"))
GLAZE_REPOSITORY = "GoreeCloud/goreecloud-glaze-ui"
GLAZE_BASELINE_TAG = "v1.1.0"
GLAZE_BASELINE_COMMIT = "15cc76d2bcd4065552dc31c77145b63f34d9e7b2"
GLAZE_SOURCE_COMMIT = "b7fa8164bfdeaa1dc0acb21b770e7601120da04e"
CURRENT_GLAZE_STABLE_VERSION = "1.5.0"
GLAZE_RAW_HOST = "raw.githubusercontent.com"
HTTP_OK = 200
MAX_GLAZE_ASSET_BYTES = 1_048_576
PUBLIC_FILES = (
    "index.html",
    "style.css",
    "app.js",
    "_headers",
    "robots.txt",
    "sitemap.xml",
    "assets/identity.svg",
)
IMPORT_DIRECTIVE_RE = re.compile(r"@import\s+[^;]+;", re.IGNORECASE)
IMPORT_TARGET_RE = re.compile(
    r"@import\s+(?:url\(\s*)?[\"'](?P<target>[^\"']+)[\"']\s*\)?\s*;",
    re.IGNORECASE,
)

if LOCK.get("schema") != "goreecloud.glaze.consumer-lock.v1":
    raise SystemExit("unsupported Glaze consumer lock schema")
if LOCK.get("version") != "1.1.0" or LOCK.get("lifecycle") != "Historical Stable Baseline":
    raise SystemExit("Identity Center must preserve its historical GLAZE UI V1.1 / 1.1.0 presentation baseline")
if LOCK.get("stable_commit") != GLAZE_BASELINE_COMMIT:
    raise SystemExit("unexpected historical GLAZE UI V1.1 Stable promotion commit")
if LOCK.get("source_commit") != GLAZE_SOURCE_COMMIT:
    raise SystemExit("unexpected GLAZE UI repaired source revision")
if LOCK.get("current_stable_version") != CURRENT_GLAZE_STABLE_VERSION:
    raise SystemExit("unexpected current Stable GLAZE UI version")
if LOCK.get("repository") != GLAZE_REPOSITORY:
    raise SystemExit("unexpected Glaze UI source repository")
if LOCK.get("tag") != GLAZE_BASELINE_TAG:
    raise SystemExit("unexpected historical Glaze UI baseline tag")


def git_blob_sha(data: bytes) -> str:
    prefix = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(prefix + data, usedforsecurity=False).hexdigest()


def require_file(path: Path) -> Path:
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"missing or unsafe public source: {path.relative_to(ROOT)}")
    return path


def require_glaze_name(name: str) -> str:
    if not name.endswith(".css") or "/" in name or "\\" in name or name in {".", ".."}:
        raise SystemExit(f"unsafe Glaze asset name: {name}")
    return name


def fetch_glaze(name: str) -> bytes:
    safe_name = require_glaze_name(name)
    # Identity retains its historical V1.1 presentation baseline, but assets are
    # sourced from the exact current Stable integration revision that carries
    # the canonical V1 import-closure repair. This avoids modifying immutable
    # v1.1.0 release bytes in place or consuming an unreleased patch candidate.
    path = f"/{GLAZE_REPOSITORY}/{GLAZE_SOURCE_COMMIT}/css/{safe_name}"
    connection = http.client.HTTPSConnection(
        GLAZE_RAW_HOST,
        timeout=20,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "GET",
            path,
            headers={"User-Agent": "GoreeCloud-Identity-public-site-builder/1"},
        )
        response = connection.getresponse()
        if response.status != HTTP_OK:
            raise SystemExit(f"failed to fetch Glaze UI asset {safe_name}: HTTP {response.status}")
        data = response.read(MAX_GLAZE_ASSET_BYTES + 1)
        if len(data) > MAX_GLAZE_ASSET_BYTES:
            raise SystemExit(f"Glaze UI asset exceeds size limit: {safe_name}")
        return data
    finally:
        connection.close()


def read_glaze(name: str, expected_sha: str) -> bytes:
    safe_name = require_glaze_name(name)
    source_root = os.environ.get("GLAZE_UI_SOURCE")
    if source_root:
        data = require_file(Path(source_root) / "css" / safe_name).read_bytes()
    else:
        data = fetch_glaze(safe_name)
    actual_sha = git_blob_sha(data)
    if actual_sha != expected_sha:
        raise SystemExit(
            f"Glaze integrity mismatch for {safe_name}: {actual_sha} != {expected_sha}"
        )
    return data


def validate_glaze_import_closure(assets: dict[str, bytes]) -> None:
    """Fail closed when any locked stylesheet imports an unshipped local file."""

    for name, data in assets.items():
        try:
            css = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"Glaze stylesheet is not UTF-8: {name}") from exc

        directives = IMPORT_DIRECTIVE_RE.findall(css)
        targets = [match.group("target") for match in IMPORT_TARGET_RE.finditer(css)]
        if len(directives) != len(targets):
            raise SystemExit(f"unsupported or ambiguous CSS @import syntax in {name}")

        for target in targets:
            if not target.startswith("./"):
                raise SystemExit(
                    f"Glaze import must be same-directory relative in {name}: {target}"
                )
            if any(marker in target for marker in ("?", "#", "..")):
                raise SystemExit(f"unsafe Glaze import target in {name}: {target}")
            imported_name = require_glaze_name(target[2:])
            if imported_name not in assets:
                raise SystemExit(
                    f"Glaze import closure failure: {name} imports missing {imported_name}"
                )


def load_verified_glaze_assets() -> dict[str, bytes]:
    files = LOCK.get("files")
    if not isinstance(files, dict) or not files:
        raise SystemExit("Identity Center Glaze lock must contain CSS files")

    assets: dict[str, bytes] = {}
    for name, expected_sha in files.items():
        if not isinstance(name, str) or not isinstance(expected_sha, str):
            raise SystemExit("invalid Identity Center Glaze lock entry")
        safe_name = require_glaze_name(name)
        assets[safe_name] = read_glaze(safe_name, expected_sha)

    validate_glaze_import_closure(assets)
    return assets


def build() -> None:
    """Build the isolated Identity Center public artifact from reviewed source."""

    glaze_assets = load_verified_glaze_assets()

    if DIST.exists():
        if DIST.is_symlink():
            raise SystemExit("unsafe Identity Center dist symlink")
        shutil.rmtree(DIST)

    for relative in PUBLIC_FILES:
        source = require_file(SOURCE / relative)
        target = DIST / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    glaze_target = DIST / "glaze"
    glaze_target.mkdir(parents=True)
    for name, data in glaze_assets.items():
        (glaze_target / name).write_bytes(data)

    print(
        "Built Identity Center public site preserving GLAZE UI V1.1 / "
        f"{LOCK['version']} historical presentation semantics from repaired "
        f"current-Stable source {LOCK['source_commit']} (current Stable "
        f"{LOCK['current_stable_version']})"
    )


if __name__ == "__main__":
    build()
