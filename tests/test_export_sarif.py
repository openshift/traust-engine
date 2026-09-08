#!/usr/bin/env python3
"""Tests for traust reporting sarif — the SARIF 2.1.0 projection.

Covers: structural SARIF-subset conformance (the requirements GitHub Code
Scanning documents for uploads), severity/level/security-severity mapping,
line-region parsing, pseudo-path vs file-path location handling,
fingerprint carriage, disposition -> suppression projection, determinism,
and CLI round-trip including default output naming.
"""

import json
import unittest
from pathlib import Path

from traust_engine.reporting import sarif as es


def _finding(**over):
    f = {
        "id": "TEST_WIDGET-abcdef0-001",
        "title": "Token logged at debug level",
        "severity": "high",
        "category": "data-exposure",
        "cwes": ["CWE-532"],
        "fingerprint": "0123456789abcdef",
        "validation_status": "not_verified",
        "locations": [{"path": "pkg/auth/token.go", "lines": "10-20"}],
        "description": "Bearer token written to the debug log.",
        "remediation": "Redact the token before logging.",
    }
    f.update(over)
    return f


def _report(findings=None):
    return {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-07-24",
            "scope": "test",
            "repository": "https://github.com/example/test-widget",
            "commit": "abcdef0123456789abcdef0123456789abcdef01",
            "audit_profile": "code",
            "additional": {"harness_version": "0.164.0-1234567"},
        },
        "findings": findings if findings is not None else [_finding()],
    }


def _assert_sarif_subset(doc):
    """Structural checks mirroring what GitHub's upload endpoint requires."""
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"]
    rules = driver["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))
    for res in run["results"]:
        assert res["message"]["text"]
        assert res["ruleId"] in rule_ids
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note", "none")


class TestExport(unittest.TestCase):
    def test_structure_and_rule_dedup(self):
        rep = _report(
            [
                _finding(),
                _finding(id="TEST_WIDGET-abcdef0-002", category="data-exposure"),
                _finding(id="TEST_WIDGET-abcdef0-003", category="injection"),
            ]
        )
        doc = es.export(rep)
        _assert_sarif_subset(doc)
        run = doc["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(len(run["results"]), 3)
        self.assertEqual(run["tool"]["driver"]["semanticVersion"], "0.164.0")

    def test_severity_mapping(self):
        cases = {
            "critical": ("error", "9.5"),
            "high": ("error", "8.0"),
            "medium": ("warning", "5.0"),
            "low": ("note", "2.0"),
            "informational": ("note", "0.5"),
        }
        for sev, (level, score) in cases.items():
            res = es.export(_report([_finding(severity=sev)]))["runs"][0]["results"][0]
            self.assertEqual(res["level"], level, sev)
            self.assertEqual(res["properties"]["security-severity"], score, sev)

    def test_effective_severity_wins(self):
        res = es.export(_report([_finding(severity="high", effective_severity="low")]))["runs"][0][
            "results"
        ][0]
        self.assertEqual(res["level"], "note")
        self.assertEqual(res["properties"]["harness/severity"], "low")

    def test_region_parsing(self):
        for lines, expect in (
            ("10-20", {"startLine": 10, "endLine": 20}),
            ("7", {"startLine": 7}),
            ("n/a", None),
            (None, None),
        ):
            self.assertEqual(es._region(lines), expect, lines)

    def test_pseudo_paths_are_logical_locations(self):
        rep = _report(
            [
                _finding(
                    locations=[
                        {"path": "pkg:golang/golang.org/x/crypto@v0.1.0"},
                        {"path": "oci-config:User"},
                        {"path": "cmd/main.go", "lines": "3"},
                    ]
                )
            ]
        )
        locs = es.export(rep)["runs"][0]["results"][0]["locations"]
        self.assertIn("logicalLocations", locs[0])
        self.assertIn("logicalLocations", locs[1])
        self.assertEqual(locs[2]["physicalLocation"]["artifactLocation"]["uri"], "cmd/main.go")

    def test_fingerprints(self):
        res = es.export(_report())["runs"][0]["results"][0]
        self.assertEqual(
            res["partialFingerprints"]["harnessFindingId/v1"], "TEST_WIDGET-abcdef0-001"
        )
        self.assertEqual(res["partialFingerprints"]["harnessFingerprint/v1"], "0123456789abcdef")

    def test_disposition_to_suppressions(self):
        fp = _finding(disposition={"validity": "false_positive", "resolution": "open"})
        ra = _finding(
            id="TEST_WIDGET-abcdef0-002",
            disposition={"validity": "confirmed", "resolution": "risk_accepted"},
        )
        plain = _finding(id="TEST_WIDGET-abcdef0-003")
        results = es.export(_report([fp, ra, plain]))["runs"][0]["results"]
        self.assertEqual(len(results[0]["suppressions"]), 1)
        self.assertEqual(len(results[1]["suppressions"]), 1)
        self.assertNotIn("suppressions", results[2])
        # full disposition rides in properties — the ledger stays authoritative
        self.assertEqual(
            results[0]["properties"]["harness/disposition"]["validity"], "false_positive"
        )

    def test_ref_provenance_carried(self):
        rep = _report()
        rep["metadata"]["ref"] = "c10s"
        rep["metadata"]["ref_kind"] = "stream"
        props = es.export(rep)["runs"][0]["properties"]
        self.assertEqual(props["harness/ref"], "c10s")
        self.assertEqual(props["harness/ref_kind"], "stream")

    def test_deterministic(self):
        rep = _report()
        self.assertEqual(json.dumps(es.export(rep)), json.dumps(es.export(rep)))


def _cca_report():
    return {
        "title": "Cloud Config Audit — widget-iac",
        "metadata": {
            "target": "widget-iac",
            "assessment_mode": "declared",
            "harness_version": "0.167.0-abc1234",
            "checkov_version": "3.2.0",
            "facts_ref": "widget-iac-cloud-facts.json",
            "facts_snapshot_id": "0123456789abcdef",
            "deterministic_steps": [{"tool": "checkov", "invocation": "run_checkov.py"}],
        },
        "summary": {
            "facts_total": 3,
            "confirmed": 1,
            "suppressed": 1,
            "needs_review": 1,
            "gaps": 0,
        },
        "findings": [
            {
                "id": "CCA-widget-iac-001",
                "fact_ids": ["cca-aaaaaaaaaaaa"],
                "framework": "kubernetes",
                "provider": "kubernetes",
                "check_id": "CKV_K8S_21",
                "title": "Default namespace used",
                "severity": "high",
                "status": "confirmed",
                "rationale": "Tenant workloads land in default.",
                "cwe": "CWE-1188",
                "control_refs": ["nist:AC-6"],
                "locations": [
                    {
                        "file_path": "deploy/app.yaml",
                        "resource": "Deployment.app",
                        "file_line_range": [4, 12],
                    }
                ],
            },
            {
                "id": "CCA-widget-iac-002",
                "fact_ids": ["cca-bbbbbbbbbbbb"],
                "framework": "kubernetes",
                "provider": "kubernetes",
                "check_id": "CKV_K8S_43",
                "title": "Image not digest-pinned",
                "severity": "low",
                "status": "suppressed",
                "rationale": "Digest pinning handled by the release pipeline.",
                "locations": [{"file_path": "deploy/app.yaml"}],
            },
            {
                "id": "CCA-widget-iac-003",
                "fact_ids": ["cca-cccccccccccc"],
                "framework": "terraform",
                "provider": "aws",
                "check_id": "CKV_AWS_1",
                "title": "Wildcard IAM",
                "severity": "medium",
                "status": "needs_review",
                "rationale": "Scope unclear from declared layer.",
                "locations": [{"file_path": "iam.tf", "file_line_range": [7]}],
            },
        ],
    }


class TestCloudConfigArm(unittest.TestCase):
    def test_detection_and_dispatch(self):
        self.assertTrue(es.is_cloud_config(_cca_report()))
        self.assertFalse(es.is_cloud_config(_report()))
        doc = es.export(_cca_report())
        _assert_sarif_subset(doc)

    def test_check_ids_become_rules(self):
        run = es.export(_cca_report())["runs"][0]
        self.assertEqual(
            [r["id"] for r in run["tool"]["driver"]["rules"]],
            ["CKV_K8S_21", "CKV_K8S_43", "CKV_AWS_1"],
        )
        self.assertEqual(run["results"][0]["ruleId"], "CKV_K8S_21")

    def test_suppressed_status_maps_to_suppression(self):
        results = es.export(_cca_report())["runs"][0]["results"]
        self.assertNotIn("suppressions", results[0])
        self.assertEqual(
            results[1]["suppressions"][0]["justification"],
            "Digest pinning handled by the release pipeline.",
        )
        self.assertEqual(results[2]["properties"]["harness/status"], "needs_review")

    def test_declared_labeling_and_locations(self):
        run = es.export(_cca_report())["runs"][0]
        self.assertEqual(run["properties"]["harness/assessment_mode"], "declared")
        self.assertIn("checkov 3.2.0", run["properties"]["harness/engine"])
        loc = run["results"][0]["locations"][0]
        self.assertEqual(loc["physicalLocation"]["region"], {"startLine": 4, "endLine": 12})
        self.assertEqual(loc["logicalLocations"][0]["fullyQualifiedName"], "Deployment.app")
        single = run["results"][2]["locations"][0]
        self.assertEqual(single["physicalLocation"]["region"], {"startLine": 7})


class TestSweep(unittest.TestCase):
    def _tree(self, td):
        base = Path(td) / "tree"
        a = base / "findings" / "prodA" / "repo1"
        a.mkdir(parents=True)
        (a / "repo1-security-audit.json").write_text(json.dumps(_report()), encoding="utf-8")
        (a / "repo1-findings-current.json").write_text(json.dumps(_report()), encoding="utf-8")
        (a / "repo1-container-audit.json").write_text(json.dumps(_report()), encoding="utf-8")
        b = base / "findings" / "prodB" / "repo2"
        b.mkdir(parents=True)
        (b / "repo2-security-audit.json").write_text(json.dumps(_report()), encoding="utf-8")
        hidden = base / ".verify-tmp"
        hidden.mkdir()
        (hidden / "x-security-audit.json").write_text(json.dumps(_report()), encoding="utf-8")
        return base

    def test_cumulative_supersedes_and_hidden_skipped(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            base = self._tree(td)
            names = sorted(p.name for p in es._sweep(base))
            self.assertEqual(
                names,
                [
                    "repo1-container-audit.json",  # no cumulative of its own
                    "repo1-findings-current.json",  # supersedes the raw audit
                    "repo2-security-audit.json",
                ],
            )

    def test_sweep_cli_mirrors_tree(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            base = self._tree(td)
            out_dir = Path(td) / "out"
            rc = es.export_reports(results_root=base, out_dir=out_dir)
            self.assertEqual(rc, 0)
            self.assertTrue(
                (
                    out_dir / "findings" / "prodA" / "repo1" / "repo1-findings-current.sarif"
                ).is_file()
            )
            self.assertTrue(
                (out_dir / "findings" / "prodB" / "repo2" / "repo2-security-audit.sarif").is_file()
            )
            self.assertFalse(list(base.rglob("*.sarif")), "sweep must not write beside the reports")

    def test_sweep_arg_validation(self):
        self.assertEqual(es.export_reports(results_root=Path("/tmp/x")), 2)
        self.assertEqual(es.export_reports(), 2)


class TestCli(unittest.TestCase):
    def test_default_naming_and_content(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test-widget-security-audit.json"
            p.write_text(json.dumps(_report()), encoding="utf-8")
            self.assertEqual(es.export_reports(reports=[p]), 0)
            out = Path(td) / "test-widget-security-audit.sarif"
            self.assertTrue(out.is_file())
            _assert_sarif_subset(json.loads(out.read_text()))

    def test_rejects_non_report(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "not-a-report.json"
            p.write_text("{}", encoding="utf-8")
            self.assertEqual(es.export_reports(reports=[p]), 1)

    def test_out_flag_multiple_inputs_refused(self):
        self.assertEqual(
            es.export_reports(reports=[Path("a.json"), Path("b.json")], out=Path("x.sarif")), 2
        )


if __name__ == "__main__":
    unittest.main()


def test_resolved_maps_to_baseline_absent():
    report = _report(
        findings=[_finding(disposition={"validity": "confirmed", "resolution": "resolved"})]
    )
    res = es.export(report)["runs"][0]["results"][0]
    assert res["baselineState"] == "absent"


def test_open_finding_has_no_baseline_state():
    report = _report(
        findings=[_finding(disposition={"validity": "confirmed", "resolution": "open"})]
    )
    res = es.export(report)["runs"][0]["results"][0]
    assert "baselineState" not in res


def test_degraded_run_flags_invocation():
    report = _report(findings=[_finding()])
    report["negative_results"] = [{"area": "pre-scan", "note": "opengrep skipped: tool_missing"}]
    run = es.export(report)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False


def test_clean_run_invocation_successful():
    report = _report(findings=[_finding()])
    run = es.export(report)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
