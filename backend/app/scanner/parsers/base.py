from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    """A parsed dependency declaration."""
    ecosystem: str            # "PyPI" | "npm" (matches OSV ecosystem names)
    name: str                 # canonical package name
    version: str | None       # exact version if determinable
    raw_specifier: str | None # original constraint, e.g. ">=2.0,<3"
    is_dev: bool
    source_file: str
