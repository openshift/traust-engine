"""Tests for traust adapters gitleaks — secret pre-scan candidate generator."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from traust_engine.adapters import gitleaks as rg
from traust_engine.assets import default_gitleaks_config

RULES = default_gitleaks_config().parent

HAVE_GITLEAKS = shutil.which("gitleaks") is not None

FAKE_TOKEN = "sha256~" + "B" * 43


def _run_cli(repo: Path, out: Path, *, mode: str = "dir", config: Path | None = None) -> None:
    cfg = config or default_gitleaks_config()
    raw = rg._run_gitleaks(repo, mode, cfg, 900, "gitleaks")
    candidates = rg.parse_report(raw, repo, mode)
    doc = {
        "metadata": {
            "artifact": "gitleaks-secret-candidates",
            "mode": mode,
            "repository": str(repo),
            "head": rg.repo_head(repo),
            "gitleaks_version": rg.tool_version("gitleaks"),
        },
        "candidates": candidates,
    }
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _mk_repo(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "config.py").write_text(f'token = "{FAKE_TOKEN}"\n')
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "add",
        ],
        check=True,
    )
    return repo


def test_parse_report_is_secret_free():
    findings = [
        {
            "RuleID": "traust-openshift-sha256-token",
            "Description": "OpenShift OAuth access token",
            "File": "config.py",
            "StartLine": 1,
            "EndLine": 1,
            "Secret": FAKE_TOKEN,
            "Match": f'token = "{FAKE_TOKEN}"',
            "Entropy": 4.2,
            "Fingerprint": "config.py:traust:1",
        }
    ]
    cands = rg.parse_report(findings, Path("/nonexistent"), "dir")
    assert len(cands) == 1
    c = cands[0]
    assert c["liveness_class"] == "openshift"
    assert c["evidence"] == "secret_pattern_match"
    assert FAKE_TOKEN not in json.dumps(cands)


def test_history_mode_keeps_author_not_message():
    findings = [
        {
            "RuleID": "aws-access-token",
            "File": "x",
            "Commit": "abc123",
            "Email": "dev@example.com",
            "Date": "2026-01-01T00:00:00Z",
            "Message": "add creds INJECTION-MARKER",
            "Secret": "AKIA" + "X" * 16,
        }
    ]
    c = rg.parse_report(findings, Path("/nonexistent"), "history")[0]
    assert c["commit"] == "abc123"
    assert c["author_email"] == "dev@example.com"
    assert "INJECTION-MARKER" not in json.dumps(c)
    assert c["liveness_class"] == "aws"


def test_unmapped_rule_is_untestable():
    c = rg.parse_report([{"RuleID": "generic-api-key", "File": "x"}], Path("/nonexistent"), "dir")[
        0
    ]
    assert c["liveness_class"] is None


@pytest.mark.integration
@pytest.mark.requires_git
@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not on PATH")
def test_dir_scan_end_to_end(tmp_path):
    repo = _mk_repo(tmp_path)
    out = tmp_path / "out.json"
    _run_cli(repo, out, config=RULES / "gitleaks-default.toml")
    doc = json.loads(out.read_text())
    assert doc["metadata"]["artifact"] == "gitleaks-secret-candidates"
    assert doc["metadata"]["mode"] == "dir"
    rules = [c["rule_id"] for c in doc["candidates"]]
    assert "traust-openshift-sha256-token" in rules
    assert FAKE_TOKEN not in out.read_text()


@pytest.mark.integration
@pytest.mark.requires_git
@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not on PATH")
def test_history_scan_finds_wiped_secret(tmp_path):
    repo = _mk_repo(tmp_path)
    (repo / "config.py").write_text("clean = True\n")
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-aqm",
            "wipe",
        ],
        check=True,
    )
    out = tmp_path / "hist.json"
    _run_cli(
        repo,
        out,
        mode="history",
        config=RULES / "gitleaks-default.toml",
    )
    doc = json.loads(out.read_text())
    hits = [c for c in doc["candidates"] if c["rule_id"] == "traust-openshift-sha256-token"]
    assert hits and hits[0]["commit"]
    # dir mode on the cleaned tree must NOT see it
    out2 = tmp_path / "dir.json"
    _run_cli(repo, out2, config=RULES / "gitleaks-default.toml")
    doc2 = json.loads(out2.read_text())
    assert not [c for c in doc2["candidates"] if c["rule_id"] == "traust-openshift-sha256-token"]


@pytest.mark.integration
@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not on PATH")
def test_every_traust_rule_fires_on_its_fixture():
    """Calibration gate: each traust-* rule must hit fixtures/."""
    import tomllib

    rules = tomllib.loads((RULES / "gitleaks-default.toml").read_text())["rules"]
    traust_ids = {r["id"] for r in rules}
    assert traust_ids, "no traust rules defined"
    proc = subprocess.run(
        [
            "gitleaks",
            "dir",
            str(RULES / "fixtures"),
            "--config",
            str(RULES / "gitleaks-default.toml"),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--exit-code",
            "0",
            "--no-banner",
            "--log-level",
            "error",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    fired = {f["RuleID"] for f in json.loads(proc.stdout or "[]")}
    assert traust_ids <= fired, f"rules without fixture hits: {traust_ids - fired}"


@pytest.mark.integration
@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not on PATH")
def test_no_rule_fires_on_negative_fixture():
    """Calibration gate (negative): placeholder/templated DSN shapes in
    secrets-fixture-negative.txt must not trip any rule — the
    traust-dsn-url-credentials allowlist owns the placeholder cut."""
    proc = subprocess.run(
        [
            "gitleaks",
            "dir",
            str(RULES / "fixtures"),
            "--config",
            str(RULES / "gitleaks-default.toml"),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--exit-code",
            "0",
            "--no-banner",
            "--log-level",
            "error",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    neg_hits = [
        f
        for f in json.loads(proc.stdout or "[]")
        if f["File"].endswith("secrets-fixture-negative.txt")
    ]
    assert not neg_hits, (
        f"negative fixture tripped rules: {[(f['RuleID'], f['StartLine']) for f in neg_hits]}"
    )
