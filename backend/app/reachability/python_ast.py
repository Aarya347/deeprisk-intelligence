from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

try:  # exact mapping if the package is installed in THIS environment
    from importlib.metadata import packages_distributions
    _PKG_DISTS: dict[str, list[str]] = packages_distributions() or {}
except Exception:
    _PKG_DISTS = {}

# Well-known PyPI-name -> import-name mismatches.
TOP_LEVEL_OVERRIDES = {
    "pillow": {"pil"}, "beautifulsoup4": {"bs4"}, "beautifulsoup": {"bs4"},
    "opencv-python": {"cv2"}, "opencv-python-headless": {"cv2"},
    "pyyaml": {"yaml"}, "python-dateutil": {"dateutil"}, "python-dotenv": {"dotenv"},
    "scikit-learn": {"sklearn"}, "scikit-image": {"skimage"},
    "attrs": {"attr"}, "gitpython": {"git"}, "pycryptodome": {"crypto", "cryptodome"},
    "python-jose": {"jose"}, "msgpack": {"msgpack"}, "pyjwt": {"jwt"},
}


@dataclass
class ImportHit:
    file: str
    line: int
    statement: str


@dataclass
class ReachabilityResult:
    dependency_name: str
    reachable: bool
    confidence: str                      # "medium" for import-level analysis
    hits: list[ImportHit] = field(default_factory=list)


class _ImportCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.roots: list[tuple[str, int, str]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.roots.append((alias.name.split(".")[0], node.lineno, f"import {alias.name}"))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module:  # skip relative imports
            self.roots.append((node.module.split(".")[0], node.lineno,
                               f"from {node.module} import ..."))


def build_import_index(repo_dir: str | Path) -> dict[str, list[ImportHit]]:
    """Map: imported top-level module name -> evidence of where it's imported."""
    index: dict[str, list[ImportHit]] = {}
    root = Path(repo_dir)
    for path in root.rglob("*.py"):
        if any(part in {"node_modules", ".venv", "venv", ".git", "site-packages"} for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        collector = _ImportCollector()
        collector.visit(tree)
        rel = str(path.relative_to(root))
        for mod, lineno, stmt in collector.roots:
            index.setdefault(mod, []).append(ImportHit(rel, lineno, stmt))
    return index


def _candidate_modules(dep_name: str) -> set[str]:
    norm = dep_name.lower().strip()
    candidates = {norm, norm.replace("-", "_"), norm.replace("_", "-"), norm.replace("-", "")}
    candidates |= TOP_LEVEL_OVERRIDES.get(norm, set())
    canon = canonicalize_name(norm)
    for import_name, dists in _PKG_DISTS.items():   # exact mapping when installed locally
        if any(canonicalize_name(d) == canon for d in dists):
            candidates.add(import_name.lower())
    return candidates


def assess_python_dependency(dep_name: str, import_index: dict[str, list[ImportHit]]) -> ReachabilityResult:
    wanted = _candidate_modules(dep_name)
    hits = [h for mod in wanted for h in import_index.get(mod, [])]
    return ReachabilityResult(
        dependency_name=dep_name,
        reachable=bool(hits),
        confidence="medium",
        hits=hits[:10],
    )
