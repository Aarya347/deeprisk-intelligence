from __future__ import annotations

import json
import re

from app.scanner.parsers.base import Dependency

_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")


def parse_package_json(text: str, source_file: str = "package.json") -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    for section, is_dev in (
        ("dependencies", False),
        ("optionalDependencies", False),
        ("devDependencies", True),
    ):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            deps.append(Dependency("npm", name.strip(), None, spec, is_dev, source_file))
    return deps


def best_guess_version(specifier: str | None) -> tuple[str | None, str]:
    """Best-effort lower-bound extraction from semver ranges (^1.2.3, ~2.0, >=3.4).
    Returns (version, source_tag). Approximation: treats the range's floor as the version."""
    if not specifier:
        return None, "none"
    m = _VERSION_RE.search(specifier)
    if not m:
        return None, "none"
    v = m.group(0)
    if v.count(".") == 1:
        v += ".0"
    return v, "guess"


def _is_top_level_package_name(name: str) -> bool:
    """True only for a bare package name ('lodash') or a scoped name
    ('@scope/pkg') — rejects nested node_modules copies AND any sub-path
    within a package (e.g. 'express/lib/x', which isn't a package name)."""
    if "node_modules/" in name:
        return False
    parts = name.split("/")
    return len(parts) == 2 if name.startswith("@") else len(parts) == 1


def parse_package_lock(text: str) -> dict[str, str]:
    """Resolve exact versions from package-lock.json (v2/v3 'packages' block,
    falls back to legacy v1 'dependencies'). Top-level packages only."""
    data = json.loads(text)
    resolved: dict[str, str] = {}
    for key, info in (data.get("packages") or {}).items():
        if not key.startswith("node_modules/"):
            continue
        name = key.removeprefix("node_modules/")
        if not _is_top_level_package_name(name):
            continue
        if isinstance(info, dict) and info.get("version"):
            resolved[name] = info["version"].lstrip("=v ")
    if not resolved:
        for name, info in (data.get("dependencies") or {}).items():
            if isinstance(info, dict) and info.get("version"):
                resolved[name] = info["version"].lstrip("=v ")
    return resolved
