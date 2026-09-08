"""HarnessEngine client: built from a loaded context, injects locations into ops."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from traust_engine import HarnessEngine

_FIXTURE = Path(__file__).parent / "fixtures" / "config"


def _home_with_progress_tracker(tmp_path: Path, pt: Path) -> Path:
    home = tmp_path / f"cfg-{pt.name}"
    shutil.copytree(_FIXTURE, home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt)}), encoding="utf-8"
    )
    return home


def test_metrics_journal_follows_configured_progress_tracker(tmp_path):
    pt = tmp_path / "estate-pt"
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, pt))

    h.metrics.append("census", {"repos": 812})
    row = h.metrics.append("census", {"repos": 815})

    # the engine received its location from the context — the journal landed under
    # the operator-configured progress-tracker, not a workspace-relative guess.
    assert (pt / "metrics" / "metrics-history.jsonl").is_file()
    assert h.metrics.rows()[-1]["metrics"]["repos"] == 815
    assert h.metrics.previous("census")["row_sha"] == row["row_sha"]
    ok, issues = h.metrics.verify()
    assert ok, issues


def test_corpus_pulls_config_and_results_from_context(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    ar = tmp_path / "analysis-results"
    (ar / "findings").mkdir(parents=True)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    # config + results root both come from the context — no args at the call site.
    assert "findings" in h.corpus.config().trees
    res = h.corpus.resolve()
    assert res.analysis_results == str(ar)


def test_metrics_spend_build_uses_configured_paths(tmp_path):
    pt = tmp_path / "estate-pt"
    ws = tmp_path / "estate-ws"
    ws.mkdir()
    home = _home_with_progress_tracker(tmp_path, pt)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt), "workspace": str(ws)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    out = h.metrics.build_spend_dashboard()
    assert out == pt / "metrics" / "dashboards" / "spend" / "spend-dashboard.md"
    assert out.is_file()


def test_metrics_sla_paths_from_context(tmp_path):
    pt = tmp_path / "estate-pt"
    pt.mkdir()
    (pt / "configs").mkdir(parents=True)
    home = _home_with_progress_tracker(tmp_path, pt)
    h = HarnessEngine.load(config_home=home)
    assert h.metrics.default_sla_policy() == pt / "configs" / "sla-policy.yaml"
    assert h.metrics.sla_dashboard_dir() == pt / "metrics" / "dashboards" / "sla"


def test_two_engines_are_isolated_by_their_context(tmp_path):
    h1 = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "a"))
    h2 = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "b"))
    h1.metrics.append("s", {"x": 1})
    assert h1.metrics.rows() and not h2.metrics.rows()


def test_namespace_ops_are_cached_per_engine(tmp_path):
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "pt"))
    assert h.metrics is h.metrics
    assert h.corpus is h.corpus
    assert h.models is h.models
    assert h.compliance is h.compliance
    assert h.adapters is h.adapters
    assert h.sweep is h.sweep
    assert h.ledger is h.ledger
    assert h.reporting is h.reporting
    assert h.portfolio is h.portfolio
    assert h.toolchain is h.toolchain
    assert h.impact is h.impact


def test_ledger_signing_pubkey_from_context(tmp_path):
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "pt"))
    assert h.ledger.signing_pubkey() == h.ctx.signing_pubkey


def test_engine_loads_without_signing_key(tmp_path):
    """Ledger signing is optional: no ledger-signing-key.pub → signing_pubkey is
    None, load still succeeds, and the pubkey accessors return None rather than
    raising. Signature *verification* is skipped; the ledger still records."""
    home = tmp_path / "cfg"
    shutil.copytree(_FIXTURE, home)
    (home / "ledger-signing-key.pub").unlink()
    h = HarnessEngine.load(config_home=home)
    assert h.ctx.signing_pubkey is None
    assert h.ledger.signing_pubkey() is None
    assert h.reporting.signing_pubkey() is None


def test_models_registry_and_validate_from_context(tmp_path):
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "pt"))
    reg = h.models.registry()
    assert reg is h.ctx.model_registry
    assert h.models.validate() == []
    assert h.models.resolve("fact-judge") == "claude-sonnet-5"


def test_sweep_paths_follow_configured_locations(tmp_path):
    home = tmp_path / "cfg-sweep"
    shutil.copytree(_FIXTURE, home)
    ar = tmp_path / "analysis-results"
    ar.mkdir()
    pt = tmp_path / "progress-tracker"
    ws = tmp_path / "workspace"
    ws.mkdir()
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "analysis_results": str(ar),
                "progress_tracker": str(pt),
                "workspace": str(ws),
            }
        ),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    assert h.sweep._analysis_results() == ar
    assert h.sweep._scan_testing() == ar / "scan-testing"
    assert h.sweep._benchmark_dir() == ar / "scan-testing" / "validation-benchmark"
    assert h.sweep._progress_tracker() == pt
    assert h.sweep._workspace() == ws


def test_corpus_build_findings_db_uses_context_paths(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    ar = tmp_path / "analysis-results"
    rdir = ar / "findings" / "prod-a" / "repo-x"
    rdir.mkdir(parents=True)
    (rdir / "repo-x-security-audit.json").write_text('{"metadata": {}, "findings": []}')
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    counts, out = h.corpus.build_findings_db()
    assert out == ar / "graph" / "findings.db"
    assert out.is_file()
    assert counts["repos"] >= 1


def test_corpus_load_resolution_uses_context_paths(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    ar = tmp_path / "analysis-results"
    (ar / "findings").mkdir(parents=True)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    res = h.corpus.load_resolution(prefer_index=False)
    assert res.analysis_results == str(ar)


def test_corpus_match_findings_is_stateless(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    ar = tmp_path / "analysis-results"
    (ar / "findings").mkdir(parents=True)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    cache = {"components": {}, "fingerprints": {}}
    findings = [{"id": "F-1", "locations": [{"path": "main.go"}]}]
    assert h.corpus.match_findings(cache, findings) == []


def test_compliance_ops_use_configured_paths(tmp_path):
    pt = tmp_path / "pt"
    ar = tmp_path / "analysis-results"
    (ar / "compliance").mkdir(parents=True)
    (ar / "graph").mkdir(parents=True)
    scope_dir = pt / "configs" / "compliance"
    scope_dir.mkdir(parents=True)
    scope_path = scope_dir / "compliance-scope.yaml"
    scope_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "updated": "2026-07-30",
                "boundaries": {
                    "b1": {
                        "frameworks": ["nist-800-53-rev5"],
                        "resolves_via": "explicit",
                        "include": [{"repo": "org/only", "reason": "fixture"}],
                        "declared_by": "test",
                        "declared_at": "2026-07-30",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    graph_path = ar / "graph" / "repo-graph.json"
    graph_path.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")

    home = _home_with_progress_tracker(tmp_path, pt)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)

    assert h.compliance.scope_registry() == scope_path
    assert h.compliance.dashboard_out_dir() == pt / "metrics" / "dashboards" / "compliance"

    doc = h.compliance.build()
    assert doc["metadata"]["artifact"] == "compliance-dashboard"
    assert doc["metadata"]["assessments_found"] == 0

    loaded = h.compliance.load_scope()
    res = h.compliance.resolve(loaded, "b1")
    assert res["repos"] == ["org/only"]


def test_adapters_ops_expose_context_config(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    assert h.adapters.rule_pack_allowlist() is h.ctx.rule_pack_allowlist
    assert h.adapters.safe_exec_profiles() is h.ctx.safe_exec
    allowlist = h.adapters.allowlist_for_opengrep()
    assert allowlist is not None
    assert "argus-observe-rules" in (allowlist.packs or {})
    assert h.adapters.rule_pack_allowlist_path() == home / "rule-pack-allowlist.yaml"
    assert h.adapters.rule_pack_dir().is_dir()

    from traust_engine.adapters.opengrep import load_supplemental_packs

    packs = load_supplemental_packs(allowlist=allowlist)
    assert any(p["name"] == "argus-observe-rules" for p in packs)


def test_portfolio_ops_use_configured_paths(tmp_path):
    ar = tmp_path / "analysis-results"
    (ar / "graph").mkdir(parents=True)
    spine_path = ar / "graph" / "repo-graph.json"
    spine_path.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    explicit_db = tmp_path / "custom" / "portfolio.db"
    explicit_db.parent.mkdir()

    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)

    assert h.portfolio.repo_graph() == spine_path
    assert h.portfolio.portfolio_graph_db() == ar / "graph" / "portfolio-graph.db"
    assert h.portfolio.portfolio_graph_location() == str(ar / "graph" / "portfolio-graph.db")

    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "progress_tracker": str(tmp_path / "pt"),
                "analysis_results": str(ar),
                "portfolio_graph": str(explicit_db),
            }
        ),
        encoding="utf-8",
    )
    h2 = HarnessEngine.load(config_home=home)
    assert h2.portfolio.portfolio_graph_db() == explicit_db
    assert h2.portfolio.portfolio_graph_location() == str(explicit_db)


def test_reporting_ops_signing_pubkey_from_context(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    assert h.reporting.signing_pubkey() == home / "ledger-signing-key.pub"
    assert h.reporting.safe_exec() is h.ctx.safe_exec


def test_toolchain_ops_external_tools_from_context(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    assert h.toolchain.external_tools() is h.ctx.external_tools
    assert h.toolchain.safe_exec() is h.ctx.safe_exec
    pins = h.toolchain.pins()
    assert pins["grype"]["expected"] == "0.115.0"
    assert pins["grype"]["version_cmd"] == ["grype", "--version"]


def test_safe_exec_profiles_from_engine_config_home_not_env(tmp_path, monkeypatch):
    """Profile map on *Ops is scoped to explicit config_home, not $TRAUST_CONFIG_HOME."""
    home_a = _home_with_progress_tracker(tmp_path, tmp_path / "pt-a")
    home_b = _home_with_progress_tracker(tmp_path, tmp_path / "pt-b")
    profiles_yaml = yaml.safe_load((home_b / "safe-exec-profiles.yaml").read_text())
    profiles_yaml["profiles"]["validation-step"]["allow"] = ["echo"]
    (home_b / "safe-exec-profiles.yaml").write_text(yaml.safe_dump(profiles_yaml), encoding="utf-8")

    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home_a))
    h_b = HarnessEngine.load(config_home=home_b)

    profile = h_b.adapters.safe_exec_profile_map()["validation-step"]
    assert profile.allow == frozenset({"echo"})
    assert "curl" not in profile.allow


def test_two_engines_keep_independent_safe_exec_profile_maps(tmp_path):
    """Two HarnessEngine instances in one process do not share a global allowlist."""
    home_a = _home_with_progress_tracker(tmp_path, tmp_path / "pt-a")
    home_b = _home_with_progress_tracker(tmp_path, tmp_path / "pt-b")
    profiles_yaml = yaml.safe_load((home_b / "safe-exec-profiles.yaml").read_text())
    profiles_yaml["profiles"]["validation-step"]["allow"] = ["echo"]
    (home_b / "safe-exec-profiles.yaml").write_text(yaml.safe_dump(profiles_yaml), encoding="utf-8")

    h_a = HarnessEngine.load(config_home=home_a)
    h_b = HarnessEngine.load(config_home=home_b)

    a_allow = h_a.adapters.safe_exec_profile_map()["validation-step"].allow
    b_allow = h_b.adapters.safe_exec_profile_map()["validation-step"].allow
    assert "curl" in a_allow
    assert b_allow == frozenset({"echo"})
    assert a_allow != b_allow


def test_adapters_scan_govulncheck_uses_context_profiles(tmp_path, monkeypatch):
    from traust_engine.adapters import govulncheck as gv

    repo = tmp_path / "mod"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/x\n\ngo 1.21\n", encoding="utf-8")
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    profiles_yaml = yaml.safe_load((home / "safe-exec-profiles.yaml").read_text())
    profiles_yaml["profiles"]["go-scan"]["allow"] = ["govulncheck"]
    (home / "safe-exec-profiles.yaml").write_text(yaml.safe_dump(profiles_yaml), encoding="utf-8")

    captured = {}

    def fake_run(repo, timeout, govulncheck_bin, *, profile_map=None, freeze=True):
        captured["profile_map"] = profile_map
        return 0, "", "", {"version": "v1.0.0"}, []

    monkeypatch.setattr(gv, "_run_govulncheck", fake_run)
    h = HarnessEngine.load(config_home=home)
    h.adapters.scan_govulncheck(repo, timeout=1)

    assert captured["profile_map"] is h.adapters.safe_exec_profile_map()
    assert "govulncheck" in captured["profile_map"]["go-scan"].allow


def test_safe_exec_bind_profiles_match_config_yaml_not_fallback(tmp_path):
    """profiles_from_section matches yaml; module bind is test/CLI legacy only."""
    from traust_contracts import load_context

    from traust_engine._util import safe_exec

    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    ctx = load_context(config_home=home)
    expected = safe_exec.profiles_from_section(ctx.safe_exec)

    safe_exec.reset_profiles()
    safe_exec.bind_profiles(ctx.safe_exec)

    bound = safe_exec.profiles()
    assert bound == expected
    assert "go-fuzz" in bound
    assert bound.keys() != safe_exec._FALLBACK_PROFILES.keys()


def test_impact_ops_use_configured_paths(tmp_path):
    ar = tmp_path / "analysis-results"
    (ar / "graph").mkdir(parents=True)
    db_path = ar / "graph" / "portfolio-graph.db"
    db_path.write_bytes(b"")
    explicit_db = tmp_path / "custom" / "portfolio.db"
    explicit_db.parent.mkdir()
    explicit_db.write_bytes(b"")

    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)

    assert h.impact._analysis_results() == ar
    assert h.impact.results_dir() == ar
    assert h.impact._portfolio_graph_db() == db_path
    assert h.impact.portfolio_graph_path() == db_path
    assert h.impact._portfolio_graph_location() == str(ar / "graph" / "portfolio-graph.db")

    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "progress_tracker": str(tmp_path / "pt"),
                "analysis_results": str(ar),
                "portfolio_graph": str(explicit_db),
            }
        ),
        encoding="utf-8",
    )
    h2 = HarnessEngine.load(config_home=home)
    assert h2.impact._portfolio_graph_db() == explicit_db
    assert h2.impact.portfolio_graph_path() == explicit_db
    assert h2.impact._portfolio_graph_location() == str(explicit_db)
