from app.scanner.parsers.npm import best_guess_version, parse_package_lock
from app.scanner.parsers.python_reqs import parse_requirements_txt

REQS = """
# core
requests==2.31.0
Flask>=2.3,<4  # comment
celery[redis]==5.3.*
numpy
"""

def test_parse_requirements():
    deps = {d.name: d for d in parse_requirements_txt(REQS)}
    assert deps["requests"].version == "2.31.0"
    # packaging.Requirement doesn't guarantee specifier order, so compare
    # the parsed clauses as a set rather than the exact string.
    assert deps["flask"].version is None
    assert set(deps["flask"].raw_specifier.split(",")) == {">=2.3", "<4"}
    assert deps["celery"].version == "5.3"          # wildcard pin trimmed
    assert deps["numpy"].version is None

LOCK = (
    '{"packages": {'
    '"": {}, '
    '"node_modules/lodash": {"version": "4.17.21"}, '
    '"node_modules/@scope/pkg": {"version": "1.0.0"}, '
    '"node_modules/express/lib/x": {"version": "9.9.9"}, '
    '"node_modules/express/node_modules/inner": {"version": "2.0.0"}'
    '}}'
)

def test_lockfile_resolution_skips_nested_and_subpaths():
    # Only bare top-level packages and scoped packages should resolve —
    # sub-paths within a package and doubly-nested transitive copies must
    # both be excluded (regression test for the nested-path bug).
    assert parse_package_lock(LOCK) == {
        "lodash": "4.17.21",
        "@scope/pkg": "1.0.0",
    }

def test_best_guess():
    assert best_guess_version("^1.2.3") == ("1.2.3", "guess")
    assert best_guess_version("~2.4") == ("2.4.0", "guess")
    assert best_guess_version("*") == (None, "none")
