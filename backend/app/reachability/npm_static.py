from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_STATIC_FROM = re.compile(r"""\b(?:import|export)\b[^'"();]*?\bfrom\s*['"]([^'"]+)['"]""")
_SIDE_EFFECT = re.compile(r"""\bimport\s*['"]([^'"]+)['"]""")
_REQUIRE     = re.compile(r"""\brequire(?:\.resolve)?\s*\(\s*['"]([^'"]+)['"]""")
_DYNAMIC     = re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]""")
_ALL = re.compile("|".join(f"(?:{r.pattern})" for r in (_STATIC_FROM, _SIDE_EFFECT, _REQUIRE, _DYNAMIC)))


@dataclass
class NpmReachabilityResult:
    dependency_name: str
    reachable: bool
    hits: list[str] = field(default_factory=list)   # "file:line"


def _specifier_to_package(spec: str) -> str | None:
    if spec.startswith((".", "/", "node:", "http:", "https:", "data:")):
        return None
    if spec.startswith("@"):                         # @scope/pkg[/sub]
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return spec.split("/")[0]


def build_npm_import_index(repo_dir: str | Path) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    root = Path(repo_dir)
    for path in root.rglob("*"):
        if path.suffix.lower() not in _SOURCE_EXTS:
            continue
        if any(part in {"node_modules", ".git", "dist", "build", "coverage"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in _ALL.finditer(line):
                # Each alternative pattern has its own capture group, so only
                # one of match.group(1..4) is populated depending on which
                # branch matched — grab whichever one isn't None.
                spec = next((g for g in match.groups() if g is not None), None)
                if not spec:
                    continue
                pkg = _specifier_to_package(spec)
                if pkg:
                    index.setdefault(pkg, []).append(f"{rel}:{line_no}")
    return index


def assess_npm_dependency(dep_name: str, import_index: dict[str, list[str]]) -> NpmReachabilityResult:
    hits = import_index.get(dep_name, [])
    return NpmReachabilityResult(dep_name, bool(hits), hits[:10])