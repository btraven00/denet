"""
Regression guard for Python 3.13/3.14 support.

Two things broke installs on new Python versions and must not regress:

1. The Rust extension must be built as a forward-compatible abi3 module, so a
   single wheel covers 3.9+ (incl. 3.13/3.14) instead of a version-locked
   cp3XX wheel that pip can't use on a newer interpreter.
2. pyo3 must be recent enough to compile against 3.13+ (0.21 could not), so the
   sdist fallback build actually succeeds.

These assert on Cargo.toml rather than the interpreter because an abi3 wheel is
tagged for the version it was built with; the real guarantee lives in the build
config. The functional "does it import and run" side is covered by running this
suite across the CI Python matrix (3.12/3.13/3.14).
"""

import re
import tomllib
from pathlib import Path

import denet

CARGO_TOML = Path(__file__).resolve().parents[2] / "Cargo.toml"


PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _pyo3():
    cfg = tomllib.loads(CARGO_TOML.read_text())
    return cfg["dependencies"]["pyo3"]


def test_version_matches_package_metadata():
    """__version__ is derived from install metadata, not a drifting hardcode."""
    declared = tomllib.loads(PYPROJECT.read_text())["project"]["version"]
    assert denet.__version__ == declared, (
        f"denet.__version__ ({denet.__version__}) != pyproject version ({declared})"
    )


def test_ext_module_imports_and_runs():
    """The compiled extension loads and produces a sample on this interpreter."""
    m = denet.ProcessMonitor(cmd=["sleep", "0.1"], base_interval_ms=20, max_interval_ms=40)
    assert "ts_ms" in (m.sample_once() or "")


def test_pyo3_builds_abi3_wheel():
    """abi3 feature keeps the wheel forward-compatible (one wheel for 3.9+)."""
    features = _pyo3().get("features", [])
    assert any(f.startswith("abi3") for f in features), (
        f"pyo3 must enable an abi3-pyXX feature for forward-compatible wheels; got {features}"
    )


def test_pyo3_recent_enough_for_py313():
    """pyo3 >= 0.23 to compile against Python 3.13/3.14 (0.21 could not)."""
    ver = _pyo3()["version"]
    major, minor = (int(x) for x in re.findall(r"\d+", ver)[:2])
    assert (major, minor) >= (0, 23), f"pyo3 {ver} predates Python 3.13 support"
