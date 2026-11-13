"""Offline capture viewer and self-contained, private HTML export."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def viewer_path() -> Path:
    return Path(__file__).with_name("web") / "viewer.html"


def render_html(capture: dict[str, Any] | None = None) -> str:
    """Inline local assets and optional data; capture claims are never certified here."""
    assets = viewer_path().parent
    page = viewer_path().read_text(encoding="utf-8")
    css = (assets / "viewer.css").read_text(encoding="utf-8")
    script = (assets / "viewer.js").read_text(encoding="utf-8")
    data = json.dumps(capture, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    data = data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    page = page.replace('<link rel="stylesheet" href="viewer.css">', f"<style>{css}</style>")
    page = page.replace('<script src="viewer.js"></script>', f"<script>{script}</script>")
    return page.replace("<!-- VFL_CAPTURE -->", f'<script type="application/json" id="vfl-capture">{data}</script>')


def export_html(capture: dict[str, Any], path: str | Path) -> Path:
    """Write atomically with mode 0600. The caller selects an allowed private directory."""
    target = Path(path)
    page = render_html(capture)
    pending: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, delete=False) as handle:
            pending = Path(handle.name)
            handle.write(page)
        os.replace(pending, target)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    return target
