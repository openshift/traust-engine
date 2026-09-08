"""Regression tests for safe_exec profile binding — catches unbound production paths.

The suite autouse-binds operator profiles (see conftest). Tests here opt out via
``@pytest.mark.unbound_safe_exec`` so a missing ``profile_map=`` surfaces as the
fallback warning instead of staying green.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

import pytest
import yaml

from traust_engine._util import safe_exec
from traust_engine.engine import HarnessEngine

_FIXTURE = Path(__file__).parent / "fixtures" / "config"


def _home_with_progress_tracker(tmp_path: Path, pt: Path) -> Path:
    home = tmp_path / f"cfg-{pt.name}"
    shutil.copytree(_FIXTURE, home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt)}), encoding="utf-8"
    )
    return home


@pytest.mark.unbound_safe_exec
def test_unbound_profiles_warn_and_use_fallback(caplog):
    """Without bind or profile_map, operator policy is NOT in effect."""
    safe_exec.reset_profiles()
    with caplog.at_level(logging.WARNING, logger="traust_engine._util.safe_exec"):
        profiles = safe_exec.profiles()

    assert profiles.keys() == safe_exec._FALLBACK_PROFILES.keys()
    assert any("NOT in effect" in rec.message for rec in caplog.records)


@pytest.mark.unbound_safe_exec
def test_explicit_profile_map_skips_fallback(tmp_path, caplog):
    """Engine-scoped profile_map is the production contract — no module bind needed."""
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    profile_map = h.adapters.safe_exec_profile_map()

    safe_exec.reset_profiles()
    with caplog.at_level(logging.WARNING, logger="traust_engine._util.safe_exec"):
        profile = safe_exec.get_profile("go-scan", profile_map=profile_map)

    assert "govulncheck" in profile.allow
    assert not caplog.records


@pytest.mark.unbound_safe_exec
def test_govulncheck_scan_without_profile_map_warns(tmp_path, caplog, monkeypatch):
    """Adapter scan() without profile_map must not silently inherit autouse bind."""
    from traust_engine.adapters import govulncheck as gv

    repo = tmp_path / "mod"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/x\n\ngo 1.21\n", encoding="utf-8")

    def fake_run_govulncheck(_repo, _timeout, _bin, *, profile_map=None, freeze=True):
        safe_exec.profiles(profile_map=profile_map)
        return 0, '{"version":"v1.0.0"}\n', "", {"version": "v1.0.0"}, []

    monkeypatch.setattr(gv, "_run_govulncheck", fake_run_govulncheck)

    safe_exec.reset_profiles()
    with caplog.at_level(logging.WARNING, logger="traust_engine._util.safe_exec"):
        gv.scan(repo, profile_map=None)

    assert any("NOT in effect" in rec.message for rec in caplog.records)
