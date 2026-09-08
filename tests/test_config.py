"""Runtime locations are config-owned (locations.yaml), not env or heuristics.

The accessors are pure: they take the ``Locations`` section from an already-loaded
context and never self-fetch, so these tests inject it directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from traust_contracts import DeploymentConfigMissing, Locations

from traust_engine import locations as cfg


def test_workspace_dir_reads_config():
    assert cfg.workspace_dir(Locations(workspace="/estate/ws")) == Path("/estate/ws")


def test_workspace_dir_fails_loud_when_unconfigured():
    """No cwd fallback: an unconfigured workspace raises rather than writing a
    stray tree into wherever the process started."""
    for loc in (None, Locations()):
        with pytest.raises(DeploymentConfigMissing):
            cfg.workspace_dir(loc)


def test_progress_tracker_dir_reads_config():
    assert cfg.progress_tracker_dir(Locations(progress_tracker="/estate/pt")) == Path("/estate/pt")


def test_progress_tracker_dir_is_none_when_unset():
    """No sibling-of-analysis-results heuristic; unset means the feature is off."""
    for loc in (None, Locations()):
        assert cfg.progress_tracker_dir(loc) is None


def test_rule_drafts_dir_reads_explicit_config():
    assert cfg.rule_drafts_dir(Locations(rule_drafts="/estate/drafts")) == Path("/estate/drafts")


def test_rule_drafts_dir_defaults_under_progress_tracker():
    loc = Locations(progress_tracker="/estate/pt")
    assert cfg.rule_drafts_dir(loc) == Path("/estate/pt/metrics/rule-mining/rule-drafts")


def test_rule_drafts_dir_is_none_when_unset():
    for loc in (None, Locations()):
        assert cfg.rule_drafts_dir(loc) is None


def test_feeds_cache_dir_reads_config():
    assert cfg.feeds_cache_dir(Locations(feeds_cache="/estate/cache")) == Path("/estate/cache")
    assert cfg.feeds_cache_dir(None) is None


def test_gitleaks_config_path_reads_config():
    assert cfg.gitleaks_config_path(Locations(gitleaks_config="/estate/gitleaks.toml")) == Path(
        "/estate/gitleaks.toml"
    )
    assert cfg.gitleaks_config_path(None) is None


def test_opengrep_rules_dir_reads_config():
    assert cfg.opengrep_rules_dir(Locations(opengrep_rules="/estate/rules")) == Path(
        "/estate/rules"
    )
    assert cfg.opengrep_rules_dir(None) is None


def test_resolve_rule_pack_dir_uses_locations(tmp_path):
    from traust_engine.adapters.opengrep import resolve_rule_pack_dir

    configured = tmp_path / "from-locations"
    configured.mkdir()
    assert resolve_rule_pack_dir(loc=Locations(opengrep_rules=str(configured))) == configured


def test_resolve_gitleaks_config_uses_locations(tmp_path):
    from traust_engine.adapters.gitleaks import resolve_gitleaks_config

    configured = tmp_path / "from-locations.toml"
    configured.write_text("title = 'x'\n", encoding="utf-8")
    assert resolve_gitleaks_config(loc=Locations(gitleaks_config=str(configured))) == configured


def test_resolve_gitleaks_config_rejects_remote_uri():
    from traust_engine.adapters.gitleaks import resolve_gitleaks_config

    with pytest.raises(ValueError, match="no local path form"):
        resolve_gitleaks_config(loc=Locations(gitleaks_config="s3://bucket/gitleaks.toml"))


def test_resolve_rule_pack_dir_rejects_remote_uri():
    from traust_engine.adapters.opengrep import resolve_rule_pack_dir

    with pytest.raises(ValueError, match="no local path form"):
        resolve_rule_pack_dir(loc=Locations(opengrep_rules="s3://bucket/rules"))


def test_bundled_defaults_exist_on_disk():
    from traust_engine.assets import default_gitleaks_config, default_rule_pack_dir

    assert default_gitleaks_config().is_file()
    assert default_rule_pack_dir().is_dir()
