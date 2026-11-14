"""Build an allowlisted source archive, never an experiment directory."""

import gzip
import hashlib
import io
import re
import tarfile
from pathlib import Path

from .model import LabError, canonical, file_digest, load_json, private_path, require

MANIFEST = "source-manifest.json"
ROOT_FILES = {"README.md", "LICENSE", "pyproject.toml", "flake.nix", "flake.lock", ".gitignore", "Makefile", MANIFEST}
TEXT_EXTENSIONS = {".py", ".md", ".js", ".html", ".css", ".toml", ".nix", ".json", ".yml", ".yaml", ".java", ".h", ".cpp", ".c", ".ld"}
PRIVATE_PATTERNS = [
    re.compile(r"/home/[A-Za-z0-9_.-]+/"),
    re.compile(r"/mnt/[a-z]/Users/", re.I),
    re.compile(r"/Users/[A-Za-z0-9_.-]+/"),
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+\\", re.I),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
]


def source_files(root):
    root = Path(root).resolve()
    require((root / "pyproject.toml").is_file(), "source root must contain pyproject.toml")
    files, errors = [], []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        parts = relative.parts
        if any(part in {".git", "__pycache__", ".pytest_cache", ".venv"} or part.endswith(".egg-info") for part in parts):
            continue
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink():
            errors.append(f"symlink not allowed: {relative}")
            continue
        if not path.is_file():
            errors.append(f"not a regular source file: {relative}")
            continue
        allowed = str(relative) in ROOT_FILES or (
            parts[0] in {"vfl", "tests", "docs", "examples", ".github"}
            and path.suffix in TEXT_EXTENSIONS
        )
        if not allowed:
            errors.append(f"not an allowlisted source file: {relative}")
            continue
        if any(part in {"private", "captures", "firmware", "runs", "results"} for part in parts) or any(token in path.name for token in (".private.", ".capture.", ".trace.")):
            errors.append(f"private artifact name: {relative}")
            continue
        if path.stat().st_size > 2 * 1024 * 1024:
            errors.append(f"source file too large: {relative}")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            errors.append(f"non-text source: {relative}")
            continue
        if "\x00" in content or any(pattern.search(content) for pattern in PRIVATE_PATTERNS):
            errors.append(f"private path, key or binary data detected: {relative}")
            continue
        if path.suffix == ".json":
            try:
                data = load_json(path)
            except (LabError, OSError) as exc:
                errors.append(f"invalid source JSON: {relative}: {exc}")
                continue
            schema = data.get("schema") if isinstance(data, dict) else None
            private_schemas = {"vfl.capture.v1", "vfl.trace.v1", "vfl.comparison.v1", "vfl.request.v1",
                               "vfl.tone-calibration.v1", "vfl.tone-observations.v1", "tycvl.native-build.v1",
                               "tycvl.device-coverage.v1", "vfl.device-coverage.v1"}
            raw_observations = (isinstance(data, list) and data and all(isinstance(row, dict)
                                and {"frequency_hz", "values"} <= set(row) for row in data))
            raw_fit = isinstance(data, dict) and ( {"observations", "baseline", "input_peak"} <= set(data)
                       or {"knots", "baseline", "input_peak"} <= set(data))
            if ((isinstance(schema, str) and (schema in private_schemas or schema.startswith("tycvl.board.")))
                    or raw_observations or raw_fit):
                errors.append(f"experiment data is not source: {relative}")
                continue
            if parts[0] == "vfl" and len(parts) > 1 and parts[1] == "profiles":
                if (not isinstance(data, dict) or data.get("firmware")
                        or not isinstance(data.get("backend"), dict) or data["backend"].get("kind") != "demo"):
                    errors.append(f"bundled profile must be a firmware-free synthetic demo: {relative}")
                    continue
        files.append(path)
    return files, errors


def _checked_sources(root, *, require_manifest=False):
    root = Path(root).resolve()
    files, errors = source_files(root)
    manifest_path = root / MANIFEST
    payloads = [path for path in files if path != manifest_path]
    present = manifest_path.exists() or manifest_path.is_symlink()
    verified = False
    if manifest_path in files:
        try:
            manifest = load_json(manifest_path)
            require(isinstance(manifest, dict) and set(manifest) == {"schema", "files"},
                    "manifest must contain only schema and files")
            require(manifest["schema"] == "tycvl.source-manifest.v1", "unsupported source manifest schema")
            declared = manifest["files"]
            require(isinstance(declared, dict) and declared, "manifest files must be a nonempty object")
            for name, checksum in declared.items():
                require(isinstance(name, str) and name != MANIFEST and "\\" not in name
                        and not name.startswith("/") and all(part not in {"", ".", ".."} for part in name.split("/")),
                        "manifest contains an invalid source path")
                require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum),
                        "manifest contains an invalid SHA256")
            actual = {str(path.relative_to(root)): file_digest(path) for path in payloads}
            missing = sorted(set(declared) - set(actual))
            extra = sorted(set(actual) - set(declared))
            require(not missing, "manifest files are missing or rejected: " + ", ".join(missing))
            require(not extra, "source files are absent from manifest: " + ", ".join(extra))
            changed = [name for name in actual if declared[name] != actual[name]]
            require(not changed, "source manifest hash mismatch: " + ", ".join(changed))
            verified = True
        except (LabError, OSError) as exc:
            errors.append(f"invalid source manifest: {exc}")
    elif require_manifest:
        errors.append("a readable, allowlisted source-manifest.json is required")
    return payloads, errors, present, verified


def audit(root):
    files, errors, present, verified = _checked_sources(root)
    return {"schema": "vfl.source-audit.v1", "clean": not errors, "files": len(files), "errors": errors,
            "manifest": {"present": present, "verified": verified},
            "scope": "Allowlisted working-tree text source and optional exact source manifest; excludes Git history and caches"}


def verify_source(root):
    """Verify an extracted source tree against its exact payload manifest.

    This establishes byte integrity and the source audit boundary. It does not
    authenticate the manifest's publisher or inspect Git history.
    """
    files, errors, present, verified = _checked_sources(root, require_manifest=True)
    return {"schema": "vfl.source-verification.v1", "clean": not errors and verified,
            "files": len(files), "errors": errors,
            "manifest": {"present": present, "verified": verified},
            "scope": "Exact allowlisted source inventory and SHA256; no publisher authentication or Git-history audit"}


def export_source(root, output):
    root = Path(root).resolve()
    target = private_path(output)
    require(not target.is_relative_to(root), "source export must be outside the selected source root")
    require(not target.exists(), "source export already exists")
    files, errors, _, _ = _checked_sources(root)
    require(not errors, "source audit failed: " + "; ".join(errors))
    target.parent.mkdir(parents=True, exist_ok=True)
    # Snapshot once so archived payload bytes and their hashes always agree.
    # An incoming manifest was verified above, but is regenerated, not copied.
    payloads = [(str(path.relative_to(root)), path.read_bytes()) for path in files]
    manifest = {"schema": "tycvl.source-manifest.v1", "files": {
        name: hashlib.sha256(data).hexdigest() for name, data in payloads}}
    created = False
    try:
        with target.open("xb") as raw:
            created = True
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w") as archive:
                    for name, data in payloads:
                        info = tarfile.TarInfo("TycVirtualLab/" + name)
                        info.size, info.mode, info.mtime = len(data), 0o644, 0
                        archive.addfile(info, io.BytesIO(data))
                    data = canonical(manifest) + b"\n"
                    info = tarfile.TarInfo("TycVirtualLab/source-manifest.json")
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    archive.addfile(info, io.BytesIO(data))
    except BaseException:
        if created:
            target.unlink(missing_ok=True)
        raise
    return manifest
