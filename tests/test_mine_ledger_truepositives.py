#!/usr/bin/env python3
"""mine_ledger_truepositives.py tests — fixture ledger tree."""

import json
import tempfile
import unittest
from pathlib import Path

from traust_engine.assets import default_rule_pack_dir
from traust_engine.sweep import mining as M


def cumulative(repo, findings):
    return {
        "metadata": {"repository": repo, "commit": "a" * 40},
        "findings": findings,
    }


def finding(fid, cwe, path, validity, category="injection"):
    return {
        "id": fid,
        "cwes": [cwe],
        "category": category,
        "severity": "high",
        "title": f"{cwe} in {path}",
        "locations": [{"path": path}],
        "evidence": [{"code": "db.Query(q)"}],
        "disposition": {"validity": validity, "resolution": "open"},
    }


def build_tree(tmp: Path):
    a = tmp / "product" / "repo-a"
    a.mkdir(parents=True)
    (a / "repo-a-findings-current.json").write_text(
        json.dumps(
            cumulative(
                "https://github.com/org/repo-a",
                [
                    finding("A-0000001-001", "CWE-78", "cmd/run.go", "confirmed"),
                    finding("A-0000001-002", "CWE-78", "cmd/run.go", "false_positive"),
                    finding("A-0000001-003", "CWE-306", "pkg/serve.go", "confirmed"),
                    finding("A-0000001-004", "CWE-522", "chart/values.yaml", "confirmed"),
                ],
            )
        )
    )
    (a / "repo-a-security-audit.json").write_text(
        json.dumps(
            {
                "scanner_correlation": [
                    {
                        "tool": "opengrep",
                        "result": "promoted",
                        "rule_id": "traust-go-injection-exec-taint",
                        "location": "cmd/run.go:10",
                        "finding_ids": ["A-0000001-001"],
                    },
                    {
                        "tool": "opengrep",
                        "result": "dismissed",
                        "rule_id": "traust-go-injection-exec-taint",
                        "location": "test/x.go:5",
                        "notes": "test fixture",
                    },
                    {
                        "tool": "opengrep",
                        "result": "dismissed",
                        "rule_id": "traust-go-injection-exec-taint",
                        "location": "pkg/y.go:9",
                        "notes": "argument is a constant",
                    },
                    {"tool": "govulncheck", "result": "0 reachable"},
                ]
            }
        )
    )
    return tmp


PACK_RULES = [
    {"id": "traust-go-injection-exec-taint", "languages": ["go"], "cwes": ["CWE-78"]},
]


class TestMiner(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = build_tree(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_corpus_only_confirmed(self):
        corpus = M.mine_corpus(self.root)
        ids = {t["finding_id"] for t in corpus}
        self.assertEqual(ids, {"A-0000001-001", "A-0000001-003", "A-0000001-004"})
        tp = next(t for t in corpus if t["finding_id"] == "A-0000001-001")
        self.assertEqual(tp["cwe"], "CWE-78")
        self.assertEqual(tp["language"], "go")
        self.assertIn("db.Query", tp["evidence"])

    def test_coverage_split_and_ruleable_filter(self):
        corpus = M.mine_corpus(self.root)
        covered, uncovered = M.cluster_and_cover(corpus, PACK_RULES)
        self.assertEqual([c["cwe"] for c in covered], ["CWE-78"])
        self.assertEqual(covered[0]["covered_by"], ["traust-go-injection-exec-taint"])
        # CWE-306/go is uncovered; CWE-522/yaml is filtered (not rule-able)
        self.assertEqual([c["cwe"] for c in uncovered], ["CWE-306"])

    def test_precision_from_scanner_correlation(self):
        precision = M.mine_precision(self.root)
        t = precision["traust-go-injection-exec-taint"]
        self.assertEqual((t["promoted"], t["dismissed"]), (1, 2))
        self.assertAlmostEqual(t["precision"], 0.333, places=3)
        self.assertNotIn("govulncheck", precision)  # rule_id absent

    def test_worklist_expected_rules(self):
        corpus = M.mine_corpus(self.root)
        covered, _ = M.cluster_and_cover(corpus, PACK_RULES)
        worklist = M.build_worklist(corpus, covered)
        self.assertEqual(len(worklist), 1)
        self.assertEqual(worklist[0]["expected_rules"], ["traust-go-injection-exec-taint"])
        self.assertEqual(worklist[0]["finding_ids"], ["A-0000001-001"])

    def _pack_dir(self, tmp: Path) -> Path:
        pack = tmp / "pack"
        (pack / "go").mkdir(parents=True)
        (pack / "go" / "injection.yaml").write_text(
            "rules:\n  - id: traust-go-a\n  - id: traust-go-b\n"
        )
        (pack / "typescript").mkdir()
        (pack / "typescript" / "xss.yaml").write_text("rules:\n  - id: traust-ts-a\n")
        return pack

    def test_pack_rule_count_per_language_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = self._pack_dir(Path(tmp))
            self.assertEqual(M.pack_rule_count(pack, "go"), 2)
            self.assertEqual(M.pack_rule_count(pack, "typescript"), 1)
            # javascript maps onto the typescript rule directory
            self.assertEqual(M.pack_rule_count(pack, "javascript"), 1)
            self.assertEqual(M.pack_rule_count(pack, "python"), 0)

    def test_language_coverage_rollup(self):
        corpus = M.mine_corpus(self.root)
        covered, uncovered = M.cluster_and_cover(corpus, PACK_RULES)
        with tempfile.TemporaryDirectory() as tmp:
            pack = self._pack_dir(Path(tmp))
            rows = M.language_coverage(corpus, covered, uncovered, pack)
        # sorted by uncovered-TP count descending: go (1) before yaml (0)
        self.assertEqual([r["language"] for r in rows], ["go", "yaml"])
        go = rows[0]
        self.assertEqual(go["confirmed_tps"], 2)
        self.assertEqual(go["covered_clusters"], 1)
        self.assertEqual(go["uncovered_clusters"], 1)
        self.assertEqual(go["uncovered_tps"], 1)
        self.assertEqual(go["pack_rules"], 2)
        # yaml is not rule-able: no uncovered clusters counted against it
        self.assertEqual(rows[1]["uncovered_clusters"], 0)

    def test_main_end_to_end(self):
        with tempfile.TemporaryDirectory() as out:
            rc = M.mine(self.root, out, pack="/nonexistent")
            self.assertEqual(rc, 0)
            result = json.loads(Path(out, "rule-mining.json").read_text())
            self.assertEqual(result["stats"]["confirmed_tps"], 3)
            self.assertEqual([r["language"] for r in result["language_coverage"]], ["go", "yaml"])
            corpus_lines = Path(out, "tp-corpus.jsonl").read_text().strip()
            self.assertEqual(len(corpus_lines.splitlines()), 3)
            md = Path(out, "rule-mining.md").read_text()
            self.assertIn("Ledger Rule-Mining Report", md)
            self.assertIn("## Per-language coverage", md)
            # /nonexistent pack: both go clusters uncovered, zero rules
            self.assertIn("| go | 2 | 0 | 2 | 2 | 0 |", md)

    def test_real_pack_loads(self):
        rules = M.load_pack_rules(default_rule_pack_dir())
        self.assertGreaterEqual(len(rules), 15)
        self.assertTrue(
            all(r["cwes"] for r in rules), "every traust rule must declare metadata.cwe"
        )


if __name__ == "__main__":
    unittest.main()


class TestGuessLanguage(unittest.TestCase):
    """Regression cover for the 2026-08-06 language-guesser fix.

    Both defects were found only because a report claimed the portfolio
    had no C/C++/Rust findings; the corpus label, not the portfolio, was
    wrong.
    """

    @staticmethod
    def _locs(*paths):
        return [{"path": p} for p in paths]

    def test_source_outranks_config(self):
        """146 corpus rows listed app-config.yaml ahead of their .ts
        sources and were labelled yaml; yaml is not in RULEABLE_LANGS,
        so those true positives silently left the mining worklist."""
        self.assertEqual(
            M.guess_language(self._locs("app-config.yaml", "plugins/cpt/src/Query.ts")),
            "typescript",
        )

    def test_config_only_finding_stays_config(self):
        """Source outranking config must not erase genuine yaml findings."""
        self.assertEqual(M.guess_language(self._locs("deploy.yaml", "role.yml")), "yaml")

    def test_cpp_and_csharp_extensions_resolve(self):
        for path, want in (
            (".cc", "cpp"),
            (".cxx", "cpp"),
            (".hpp", "cpp"),
            (".hh", "cpp"),
            (".cs", "csharp"),
        ):
            with self.subTest(ext=path):
                self.assertEqual(M.guess_language(self._locs(f"src/x{path}")), want)

    def test_dominant_language_wins_over_incidental_file(self):
        """One .cs file inside a Rust repo must not flip the label."""
        self.assertEqual(
            M.guess_language(self._locs("src/main.rs", "Provider/P.cs", "src/provider/project.rs")),
            "rust",
        )

    def test_ties_break_toward_first_occurrence(self):
        """Deterministic: the label cannot depend on location ordering
        beyond the documented first-seen tie-break."""
        self.assertEqual(M.guess_language(self._locs("a.go", "b.py")), "go")
        self.assertEqual(M.guess_language(self._locs("b.py", "a.go")), "python")

    def test_unrecognized_extensions_are_unknown(self):
        self.assertEqual(M.guess_language(self._locs("README.md")), "unknown")
        self.assertEqual(M.guess_language([]), "unknown")

    def test_accepts_bare_string_locations(self):
        """The corpus stores locations as strings, reports as dicts."""
        self.assertEqual(M.guess_language(["src/main.rs"]), "rust")
