#!/usr/bin/env python3
"""Tests for traust_engine.corpus.precedent — the shared-component
FP-precedent cache (error-correction plan §6, Phase-4 item 1).

Critical properties under test for the tiered population rule
(2026-07-27, supersedes the v0.151.0 human-only rule):

  * human-countersigned adjudications (interactive countersign AND
    Jira-harvest human events) seed strength=human_countersigned;
  * sound machine adjudications (triage protocol; live-validation
    refutations that PASS the Phase-1 soundness gate) seed
    strength=machine_refuted_sound;
  * machine-refuted-UNSOUND refutations (soundness-flagged or
    unresolvable) NEVER seed a precedent — the measured ~70%-unsound
    class stays out, with no fallback;
  * contested (P6 conflict) and stale-disposition findings never seed.
"""

import functools
import json
import operator
import tempfile
import unittest
from pathlib import Path

from traust_engine.corpus import resolver as corpus
from traust_engine.corpus.precedent import (
    build_cache,
    component_signature,
    is_countersigned_refutation,
    is_human_adjudication,
    match_findings,
    normalize_vendor_path,
    signature_of,
)


def _run_precedent_build(analysis: Path, config: Path, out: Path) -> int:
    cfg = corpus.load_config(config)
    cache = build_cache(analysis, cfg)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    return 0


def _run_precedent_match(cache_path: Path, findings_path: Path, json_out: Path | None) -> int:
    if not cache_path.is_file():
        result = {"cache": str(cache_path), "matches": []}
    else:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
        findings = doc if isinstance(doc, list) else (doc.get("findings") or [])
        result = {"cache": str(cache_path), "matches": match_findings(cache, findings)}
    text = json.dumps(result, indent=2) + "\n"
    if json_out:
        json_out.write_text(text, encoding="utf-8")
    return 0


NOW = "2026-07-20T12:00:00+00:00"

CONFIG_YAML = """\
version: 1
trees:
  findings:
    label: Test findings
    ownership: owned
    business_unit: Test BU
"""


def _finding(fid, path, cwe="CWE-79", category="cross-site-scripting"):
    return {
        "id": fid,
        "title": "Reflected XSS in widget template helper",
        "severity": "medium",
        "category": category,
        "cwes": [cwe],
        "locations": [{"path": path, "lines": "42"}],
        "description": "Template helper writes request input unescaped.",
        "remediation": "Escape output.",
        "validation_status": "not_verified",
    }


def _audit(fid, path, repo="https://example.invalid/repo-a", **kw):
    return {
        "title": "Security Assessment — Test",
        "metadata": {
            "date": "2026-07-01",
            "scope": "test",
            "commit": "abc1234def",
            "repository": repo,
        },
        "findings": [_finding(fid, path, **kw)],
        "executive_summary": {"prose": "x" * 60},
    }


def _countersign_event(ref, at="2026-07-10T10:00:00+00:00", identity="jdoe"):
    """Exact shape countersign.py build_human_event records."""
    return {
        "event_id": "e" * 64,
        "finding_ref": ref,
        "recorded_at": at,
        "occurred_at": at,
        "source": {
            "type": "interactive",
            "ref": f"interactive:{at[:10]}",
            "actor": {
                "kind": "human",
                "identity": identity,
                "ldap_verified": True,
                "display_name": "J. Doe",
            },
        },
        "disposition": {"validity": "false_positive"},
        "rationale": "Countersigned: helper output feeds an internal-only "
        "metrics endpoint; template autoescape verified at "
        "widget/parse.go:42.",
    }


def _jira_human_event(
    ref, at="2026-07-27T18:44:30+00:00", ticket="PROJ-12345", validity="false_positive"
):
    """Shape of the 2026-07-27 Jira-harvest countersign batch events."""
    return {
        "event_id": "d" * 64,
        "finding_ref": ref,
        "recorded_at": at,
        "occurred_at": at,
        "source": {
            "type": "jira",
            "ref": f"https://issues.example.invalid/browse/{ticket}",
            "actor": {
                "kind": "human",
                "identity": "hsig@example.invalid",
                "display_name": "H. Sig",
                "ldap_verified": True,
            },
        },
        "disposition": {"validity": validity},
        "rationale": f"[{ticket}] Decision-maker: H. Sig. Not applicable "
        "to this product's consumption closure.",
        "evidence_refs": ["pkg/widget/parse.go:42"],
    }


def _machine_fp_event(
    ref, at="2026-07-09T10:00:00+00:00", auto_accept=False, validity="false_positive"
):
    ev = {
        "event_id": "f" * 64,
        "finding_ref": ref,
        "recorded_at": at,
        "occurred_at": at,
        "source": {
            "type": "triage_report",
            "ref": "TRIAGE.json",
            "actor": {"kind": "machine", "identity": "triage/0.150.0", "ldap_verified": False},
        },
        "disposition": {"validity": validity},
        "rationale": "3-0 FALSE_POSITIVE; rule 14 (framework autoescape).",
        "evidence_refs": ["widget/parse.go:42"],
    }
    if auto_accept:
        ev["auto_accept_tier"] = "unanimous_lint_clean"
    return ev


def _validation_fp_event(ref, report_ref, at="2026-07-25T10:00:00+00:00"):
    return {
        "event_id": "c" * 64,
        "finding_ref": ref,
        "recorded_at": at,
        "occurred_at": at,
        "source": {
            "type": "validation_report",
            "ref": report_ref,
            "actor": {
                "kind": "machine",
                "identity": "validate-findings/0.190.0",
                "ldap_verified": False,
            },
        },
        "disposition": {"validity": "false_positive"},
        "rationale": "live validation: refuted — authz enforced on the probed path.",
        "evidence_refs": ["validations/x/artifacts/step-1.stdout.log"],
    }


def _confirm_event(ref, at="2026-07-11T10:00:00+00:00", kind="human", src_type="interactive"):
    actor = (
        {"kind": "human", "identity": "asmith", "ldap_verified": True}
        if kind == "human"
        else {"kind": "machine", "identity": "validate-findings", "ldap_verified": False}
    )
    return {
        "event_id": "a" * 64,
        "finding_ref": ref,
        "recorded_at": at,
        "occurred_at": at,
        "source": {"type": src_type, "ref": f"{src_type}:{at[:10]}", "actor": actor},
        "disposition": {"validity": "confirmed"},
        "rationale": "Confirmed reachable.",
    }


def _layer(events, audit_name="repo-a-security-audit.json"):
    return {
        "metadata": {
            "audit_report": audit_name,
            "created": "2026-07-01T00:00:00+00:00",
            "harness_version": "0.150.0",
        },
        "events": events,
        "needs_review": [],
    }


class FpPrecedentCacheBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.analysis = self.root / "analysis-results"
        (self.analysis / "findings").mkdir(parents=True)
        cfg_path = self.root / "corpus-config.yaml"
        cfg_path.write_text(CONFIG_YAML, encoding="utf-8")
        self.cfg = corpus.load_config(cfg_path)

    def tearDown(self):
        self._tmp.cleanup()

    def add_repo(self, slug, audit, events):
        d = self.analysis / "findings" / "prod" / slug
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{slug}-security-audit.json").write_text(json.dumps(audit), encoding="utf-8")
        (d / f"{slug}-findings-layer.json").write_text(
            json.dumps(_layer(events, f"{slug}-security-audit.json")), encoding="utf-8"
        )
        return d

    def add_validation_report(
        self,
        rel,
        finding_ref,
        soundness_flag=None,
        observed="authz enforced; request denied with a valid session token",
    ):
        """A validation report at <analysis>/<rel> with one refuted
        entry joined to finding_ref via source_id suffix."""
        p = self.analysis / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        vf = {
            "source_id": f"repo-a-security-audit/{finding_ref}",
            "verdict": "refuted",
            "observed_impact": observed,
            "steps": [
                {"step_id": "s1", "verdict": "refuted", "verb": "http-get", "observed": observed}
            ],
        }
        if soundness_flag:
            vf["soundness_flag"] = soundness_flag
        p.write_text(json.dumps({"validated_findings": [vf]}), encoding="utf-8")
        return rel

    def build(self, taxonomy_path=None):
        return build_cache(self.analysis, self.cfg, taxonomy_path=taxonomy_path)


class TestHumanTier(FpPrecedentCacheBase):
    def test_countersigned_refutation_is_cached_as_human_tier(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_machine_fp_event(ref), _countersign_event(ref)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 1)
        ((sig, entry),) = cache["components"].items()
        self.assertEqual(entry["component"]["paths"], ["github.com/acme/widget/parse.go"])
        (prec,) = entry["precedents"]  # human wins; ONE precedent
        self.assertEqual(prec["strength"], "human_countersigned")
        self.assertEqual(prec["verdict"], "false_positive")
        self.assertTrue(prec["countersigned"])
        self.assertEqual(prec["countersigner"], "jdoe")
        self.assertEqual(prec["countersign_via"], "interactive")
        self.assertEqual(prec["finding_id"], ref)
        self.assertEqual(prec["source_repo"], "repo-a")
        self.assertEqual(prec["date"], "2026-07-10")
        self.assertIn("Countersigned", prec["rationale_excerpt"])
        self.assertTrue(prec["event_id"])
        # fingerprint index points at the component signature
        self.assertIn(sig, functools.reduce(operator.iadd, cache["fingerprints"].values(), []))
        self.assertEqual(cache["metadata"]["population"]["human_countersigned"], 1)

    def test_jira_harvest_human_event_is_human_tier(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_jira_human_event(ref)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 1)
        ((_, entry),) = cache["components"].items()
        (prec,) = entry["precedents"]
        self.assertEqual(prec["strength"], "human_countersigned")
        self.assertEqual(prec["countersign_via"], "jira")
        self.assertEqual(prec["countersigner"], "hsig@example.invalid")
        self.assertEqual(prec["evidence_refs"], ["pkg/widget/parse.go:42"])

    def test_human_hardening_verdict_is_cached(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_jira_human_event(ref, validity="hardening")],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 1)
        ((_, entry),) = cache["components"].items()
        self.assertEqual(entry["precedents"][0]["verdict"], "hardening")

    def test_reopened_countersign_is_excluded_by_disposition_guard(self):
        """A later human `confirmed` (reopen) flips the derived validity —
        the stale countersign must not propagate as precedent."""
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [
                _countersign_event(ref, at="2026-07-10T10:00:00+00:00"),
                _confirm_event(ref, at="2026-07-12T10:00:00+00:00"),
            ],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)
        self.assertEqual(cache["metadata"]["population"]["excluded_stale_disposition"], 1)

    def test_taxonomy_join_on_jira_ticket(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_jira_human_event(ref, ticket="PROJ-12345")],
        )
        tax = self.root / "fp-persistence-analysis.json"
        tax.write_text(
            json.dumps(
                {
                    "countersigned_22": [
                        {
                            "ticket": "PROJ-12345",
                            "phase2_rule": "vendor-applicability",
                            "failure_class": "new-class-scoped-consumer-reachability",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        cache = self.build(taxonomy_path=tax)
        ((_, entry),) = cache["components"].items()
        (prec,) = entry["precedents"]
        self.assertEqual(
            prec["taxonomy"],
            {
                "ticket": "PROJ-12345",
                "phase2_rule": "vendor-applicability",
                "failure_class": "new-class-scoped-consumer-reachability",
            },
        )
        self.assertEqual(cache["metadata"]["taxonomy_source"], str(tax))


class TestMachineTier(FpPrecedentCacheBase):
    def test_triage_refutation_seeds_machine_tier(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_machine_fp_event(ref)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 1)
        ((_, entry),) = cache["components"].items()
        (prec,) = entry["precedents"]
        self.assertEqual(prec["strength"], "machine_refuted_sound")
        self.assertEqual(prec["verdict"], "false_positive")
        self.assertFalse(prec["countersigned"])
        self.assertEqual(prec["source_type"], "triage_report")
        self.assertEqual(prec["adjudicator"], "triage/0.150.0")
        self.assertEqual(cache["metadata"]["population"]["machine_refuted_sound"], 1)

    def test_human_precedent_outranks_machine_for_same_finding(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_machine_fp_event(ref), _countersign_event(ref)],
        )
        cache = self.build()
        ((_, entry),) = cache["components"].items()
        self.assertEqual(len(entry["precedents"]), 1)
        self.assertEqual(entry["precedents"][0]["strength"], "human_countersigned")

    def test_sound_validation_refutation_seeds_machine_tier(self):
        ref = "REPO_A-abc1234-001"
        rel = self.add_validation_report("validations/x/x-validation.json", ref)
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_validation_fp_event(ref, rel)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 1)
        ((_, entry),) = cache["components"].items()
        self.assertEqual(entry["precedents"][0]["strength"], "machine_refuted_sound")
        self.assertEqual(entry["precedents"][0]["source_type"], "validation_report")

    def test_unsound_validation_refutation_never_seeds(self):
        """THE critical exclusion: a soundness-flagged refutation (the
        measured ~70%-unsound class) never becomes a precedent."""
        ref = "REPO_A-abc1234-001"
        rel = self.add_validation_report(
            "validations/x/x-validation.json", ref, soundness_flag="error-signature:forbidden"
        )
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_validation_fp_event(ref, rel)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)
        pop = cache["metadata"]["population"]
        self.assertEqual(pop["excluded_unsound"], 1)
        self.assertEqual(pop["excluded_unsound_reasons"], {"error-signature:forbidden": 1})

    def test_unsound_probe_transcript_is_rederived(self):
        """No explicit flag on the entry — the Phase-1 gate re-derives
        unsoundness from the probe transcript itself."""
        ref = "REPO_A-abc1234-001"
        rel = self.add_validation_report(
            "validations/x/x-validation.json",
            ref,
            observed='Error from server (Forbidden): User "probe" cannot list deployments',
        )
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_validation_fp_event(ref, rel)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)
        self.assertEqual(cache["metadata"]["population"]["excluded_unsound"], 1)

    def test_unresolvable_validation_report_never_seeds(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_validation_fp_event(ref, "validations/gone/gone-validation.json")],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)
        pop = cache["metadata"]["population"]
        self.assertEqual(pop["excluded_unsound"], 1)
        self.assertIn("unresolvable:report-missing", pop["excluded_unsound_reasons"])

    def test_contested_finding_never_seeds_machine_precedent(self):
        """P6 conflict: confirmed + false_positive in evidence routes to
        human adjudication, never to a machine precedent."""
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [
                _machine_fp_event(ref),
                _confirm_event(ref, kind="machine", src_type="validation_report"),
            ],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)

    def test_human_keep_open_blocks_machine_precedent(self):
        """A human confirmed (keep-open) after a machine refutation:
        derived validity is confirmed — no precedent."""
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_machine_fp_event(ref), _confirm_event(ref)],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)

    def test_confirmation_events_alone_are_excluded(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a", _audit(ref, "vendor/github.com/acme/widget/parse.go"), [_confirm_event(ref)]
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)

    def test_empty_corpus_emits_valid_empty_cache(self):
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 0)
        self.assertEqual(cache["components"], {})
        self.assertIn("machine_refuted_sound", cache["metadata"]["population_rule"])
        # round-trips as JSON
        json.loads(json.dumps(cache))


class TestMarkers(unittest.TestCase):
    def test_exact_countersign_markers(self):
        ev = _countersign_event("X-abc1234-001")
        self.assertTrue(is_countersigned_refutation(ev))
        self.assertTrue(is_human_adjudication(ev))

    def test_jira_human_markers(self):
        ev = _jira_human_event("X-abc1234-001")
        self.assertFalse(is_countersigned_refutation(ev))  # not interactive
        self.assertTrue(is_human_adjudication(ev))

    def test_marker_variants_rejected(self):
        base = _countersign_event("X-abc1234-001")
        for mutate in (
            lambda e: e["source"]["actor"].update(kind="machine"),
            lambda e: e["source"]["actor"].update(ldap_verified=False),
            lambda e: e["source"]["actor"].pop("ldap_verified"),
            lambda e: e["source"]["actor"].update(identity=""),
            lambda e: e["disposition"].update(validity="confirmed"),
        ):
            ev = json.loads(json.dumps(base))
            mutate(ev)
            self.assertFalse(is_human_adjudication(ev), ev)


class TestSharedComponentMatching(FpPrecedentCacheBase):
    def test_signature_matches_across_two_vendor_roots(self):
        """Two repos vendoring the same file under different vendor roots
        share one component signature; a countersign in repo A annotates
        repo B's finding."""
        ref_a = "REPO_A-abc1234-001"
        ref_b = "REPO_B-def5678-003"
        self.add_repo(
            "repo-a",
            _audit(
                ref_a,
                "vendor/github.com/acme/widget/parse.go",
                repo="https://example.invalid/repo-a",
            ),
            [_countersign_event(ref_a)],
        )
        self.add_repo(
            "repo-b",
            _audit(
                ref_b,
                "third_party/github.com/acme/widget/parse.go",
                repo="https://example.invalid/repo-b",
            ),
            [],
        )
        cache = self.build()
        self.assertEqual(cache["metadata"]["entries"], 1)
        # repo B's audit finding computes the SAME component signature
        finding_b = _finding(ref_b, "third_party/github.com/acme/widget/parse.go")
        self.assertIn(signature_of(finding_b), cache["components"])
        # ...and the match helper annotates it with repo A's precedent
        matches = match_findings(cache, [finding_b])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["matched_by"], "signature")
        self.assertEqual(matches[0]["max_strength"], "human_countersigned")
        self.assertEqual(matches[0]["precedents"][0]["source_repo"], "repo-a")
        # fingerprints differ (repo-scoped), signatures do not
        self.assertEqual(len(cache["fingerprints"]), 1)

    def test_machine_only_match_reports_machine_max_strength(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_machine_fp_event(ref)],
        )
        cache = self.build()
        finding_b = _finding("REPO_B-def5678-003", "third_party/github.com/acme/widget/parse.go")
        matches = match_findings(cache, [finding_b])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["max_strength"], "machine_refuted_sound")

    def test_match_triage_shape_by_component(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_countersign_event(ref)],
        )
        cache = self.build()
        triage_finding = {
            "id": "f003",
            "file": "third_party/github.com/acme/widget/parse.go",
            "category": "cross-site-scripting",
        }
        matches = match_findings(cache, [triage_finding])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["matched_by"], "component")

    def test_path_only_overlap_never_matches(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_countersign_event(ref)],
        )
        cache = self.build()
        other_class = {
            "id": "f009",
            "file": "vendor/github.com/acme/widget/parse.go",
            "category": "sql-injection",  # different class, same path
        }
        self.assertEqual(match_findings(cache, [other_class]), [])


class TestCli(FpPrecedentCacheBase):
    def test_build_and_match_cli_roundtrip(self):
        ref = "REPO_A-abc1234-001"
        self.add_repo(
            "repo-a",
            _audit(ref, "vendor/github.com/acme/widget/parse.go"),
            [_countersign_event(ref)],
        )
        out = self.root / "fp-precedent-cache.json"
        rc = _run_precedent_build(
            self.analysis,
            self.root / "corpus-config.yaml",
            out,
        )
        self.assertEqual(rc, 0)
        cache = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(cache["metadata"]["entries"], 1)
        self.assertIn("population_rule", cache["metadata"])
        self.assertIn("population", cache["metadata"])

        findings = self.root / "findings-in.json"
        findings.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "f001",
                            "file": "third_party/github.com/acme/widget/parse.go",
                            "category": "cross-site-scripting",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        match_out = self.root / "matches.json"
        rc = _run_precedent_match(out, findings, match_out)
        self.assertEqual(rc, 0)
        result = json.loads(match_out.read_text(encoding="utf-8"))
        self.assertEqual(len(result["matches"]), 1)

    def test_missing_cache_is_clean_noop(self):
        findings = self.root / "findings-in.json"
        findings.write_text(
            json.dumps([{"id": "f001", "file": "a/b.go", "category": "xss"}]), encoding="utf-8"
        )
        match_out = self.root / "matches.json"
        rc = _run_precedent_match(
            self.root / "does-not-exist.json",
            findings,
            match_out,
        )
        self.assertEqual(rc, 0)
        result = json.loads(match_out.read_text(encoding="utf-8"))
        self.assertEqual(result["matches"], [])


class TestVendorNormalization(unittest.TestCase):
    def test_vendor_roots(self):
        for raw in (
            "vendor/github.com/acme/widget/parse.go",
            "third_party/github.com/acme/widget/parse.go",
            "pkg/vendor/github.com/acme/widget/parse.go",
            "node_modules/github.com/acme/widget/parse.go",
        ):
            self.assertEqual(normalize_vendor_path(raw), "github.com/acme/widget/parse.go", raw)

    def test_non_vendored_path_passes_through(self):
        self.assertEqual(normalize_vendor_path("./cmd/main.go"), "cmd/main.go")

    def test_signature_is_class_sensitive(self):
        paths = ["github.com/acme/widget/parse.go"]
        self.assertNotEqual(
            component_signature(paths, "CWE-79", "cross-site-scripting"),
            component_signature(paths, "CWE-89", "sql-injection"),
        )


if __name__ == "__main__":
    unittest.main()
