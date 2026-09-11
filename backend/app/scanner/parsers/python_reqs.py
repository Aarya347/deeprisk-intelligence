from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from app.scanner.parsers.base import Dependency

_COMMENT_RE = re.compile(r"(^|\s)#.*$")


def _strip_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line).strip()


def _pinned_version(req: Requirement) -> str | None:
    for spec in req.specifier:
        if spec.operator == "==":
            v = spec.version
            return v[:-2] if v.endswith(".*") else v
    return None


def parse_requirements_txt(
    text: str, source_file: str = "requirements.txt", is_dev: bool = False
) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line or line.startswith("-"):        # skips -r, -e, --hash, options
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue                                 # VCS/direct-URL deps: skipped in v1
        deps.append(
            Dependency(
                ecosystem="PyPI",
                name=canonicalize_name(req.name),
                version=_pinned_version(req),
                raw_specifier=str(req.specifier) or None,
                is_dev=is_dev,
                source_file=source_file,
            )
        )
    return deps
