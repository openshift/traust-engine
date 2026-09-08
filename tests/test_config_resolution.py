"""Config resolution is owned by traust_contracts (one var, one answer,
fail closed). The engine no longer resolves config itself and ships none."""

from __future__ import annotations

from pathlib import Path

import pytest
from traust_contracts import config as C


def test_env_var_wins(monkeypatch, tmp_path):
    monkeypatch.setenv(C.TRAUST_CONFIG_HOME_ENV, str(tmp_path))
    (tmp_path / "corpus-config.yaml").write_text("version: 1\n")
    assert C.config_path("corpus-config.yaml") == tmp_path / "corpus-config.yaml"


def test_default_home_used_only_when_it_exists(monkeypatch, tmp_path):
    monkeypatch.delenv(C.TRAUST_CONFIG_HOME_ENV, raising=False)
    monkeypatch.setattr(C, "TRAUST_CONFIG_HOME_DEFAULT", tmp_path / "absent")
    assert C.deployment_config_dir() is None
    monkeypatch.setattr(C, "TRAUST_CONFIG_HOME_DEFAULT", tmp_path)
    assert C.deployment_config_dir() == tmp_path


def test_missing_required_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv(C.TRAUST_CONFIG_HOME_ENV, str(tmp_path))
    with pytest.raises(C.DeploymentConfigMissing):
        C.config_path("corpus-config.yaml")


def test_optional_returns_none_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv(C.TRAUST_CONFIG_HOME_ENV, str(tmp_path))
    assert C.optional_config_path("budget-policy.yaml") is None
    (tmp_path / "budget-policy.yaml").write_text("budget_policy: {}\n")
    assert C.optional_config_path("budget-policy.yaml") == tmp_path / "budget-policy.yaml"


def test_engine_ships_no_config():
    """The engine owns the resolver's consumers, never the config files."""
    import traust_engine

    data = Path(traust_engine.__file__).parent / "data"
    stray = [
        p
        for p in data.rglob("*")
        if p.suffix in (".yaml", ".yml", ".json") and "secure-code-audit" not in p.parts
    ]
    assert stray == [], stray
