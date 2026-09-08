"""Benchmark release-trigger paths stay aligned with the traust checkout layout."""

from __future__ import annotations

from traust_engine.sweep import benchmark as bench


def test_trigger_paths_include_mono_checkout_prefix():
    assert "traust/harnessing/5-validate/validate-findings/" in bench.TRIGGER_PATHS
    assert "traust/src/traust/cli/build_cumulative.py" in bench.TRIGGER_PATHS


def test_trigger_paths_exclude_removed_layout():
    stale = (
        "harnessing/5-validate/validate-core-ocp/",
        "harnessing/5-validate/validate-operator-live/",
        "harnessing/4-triage/track-findings/scripts/build_cumulative.py",
        "traust-contracts/schemas/v1/validation.schema.json",
    )
    assert not any(p in bench.TRIGGER_PATHS for p in stale)


def test_contracts_trigger_paths_are_repo_relative():
    assert bench.CONTRACTS_TRIGGER_PATHS == ("schemas/v1/validation.schema.json",)
