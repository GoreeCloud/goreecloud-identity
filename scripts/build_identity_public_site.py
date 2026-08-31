#!/usr/bin/env python3
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "identity-center-site"
DIST = ROOT / "dist"
GLAZE_ASSET = "glaze-ui-2.1.0.css"
FILES = {
    SOURCE / "index.html": DIST / "index.html",
    SOURCE / "style.css": DIST / "style.css",
    SOURCE / GLAZE_ASSET: DIST / GLAZE_ASSET,
    SOURCE / "app.js": DIST / "app.js",
    SOURCE / "_headers": DIST / "_headers",
    SOURCE / "robots.txt": DIST / "robots.txt",
    SOURCE / "sitemap.xml": DIST / "sitemap.xml",
    SOURCE / "assets" / "identity.svg": DIST / "assets" / "identity.svg",
}


def build() -> None:
    """Build the isolated Identity Center public artifact from reviewed source."""

    if DIST.exists():
        if DIST.is_symlink():
            raise SystemExit("unsafe Identity Center dist symlink")
        shutil.rmtree(DIST)
    for source, target in FILES.items():
        if not source.is_file() or source.is_symlink():
            raise SystemExit(f"missing or unsafe public source: {source.relative_to(ROOT)}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    print(
        f"Built Identity Center public site: {len(FILES)} files -> dist/ "
        "with Glaze UI 2.1.0 Stable"
    )


if __name__ == "__main__":
    build()
