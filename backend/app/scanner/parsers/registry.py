from __future__ import annotations

import os
import re

from app.scanner.parsers.base import Dependency
from app.scanner.parsers.npm import parse_package_json, parse_package_lock
from app.scanner.parsers.python_reqs import parse_requirements_txt

_REQ_FILE_RE = re.compile(r"requirements[-\w.]*\.txt$", re.IGNORECASE)


def parse_dep_file(path: str, content: str) -> list[Dependency]:
    base = os.path.basename(path).lower()
    if _REQ_FILE_RE.fullmatch(base):
        return parse_requirements_txt(content, source_file=path)
    if base == "package.json":
        return parse_package_json(content, source_file=path)
    raise ValueError(f"No parser registered for {path}")


def select_dep_file_paths(tree_paths: list[str]) -> list[str]:
    """Pick likely manifest paths out of a repo file tree, skipping vendored/test noise."""
    out: list[str] = []
    for p in tree_paths:
        pl = p.lower()
        if "node_modules/" in pl or "/fixtures/" in pl or pl.startswith(("test", "example", "docs/")):
            continue
        base = pl.rsplit("/", 1)[-1]
        if base == "package.json" or _REQ_FILE_RE.fullmatch(base):
            out.append(p)
    return out[:30]
