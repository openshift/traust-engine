"""Tests for traust adapters govulncheck — stream parsing and candidate reduction."""

import json
import unittest
from pathlib import Path
from unittest import mock

from traust_engine.adapters.govulncheck import (
    _run_govulncheck,
    classify,
    iter_records,
    parse_stream,
    scan,
    trace_symbols,
)


def _pretty_stream(*records):
    """govulncheck -json emits a concatenation of pretty-printed objects."""
    return "\n".join(json.dumps(r, indent=2) for r in records)


CONFIG = {
    "config": {
        "scanner_name": "govulncheck",
        "scanner_version": "v1.1.4",
        "go_version": "go1.26.4",
        "db": "https://vuln.go.dev",
        "scan_level": "symbol",
    }
}
OSV = {
    "osv": {
        "id": "GO-2026-0001",
        "aliases": ["CVE-2026-1111"],
        "summary": "Example vulnerability in example.com/dep",
    }
}

MODULE_FINDING = {
    "finding": {
        "osv": "GO-2026-0001",
        "fixed_version": "v1.2.3",
        "trace": [{"module": "example.com/dep", "version": "v1.2.0"}],
    }
}
PACKAGE_FINDING = {
    "finding": {
        "osv": "GO-2026-0001",
        "fixed_version": "v1.2.3",
        "trace": [
            {"module": "example.com/dep", "version": "v1.2.0", "package": "example.com/dep/pkg"}
        ],
    }
}
SYMBOL_FINDING = {
    "finding": {
        "osv": "GO-2026-0001",
        "fixed_version": "v1.2.3",
        "trace": [
            {
                "module": "example.com/dep",
                "version": "v1.2.0",
                "package": "example.com/dep/pkg",
                "function": "Vulnerable",
                "position": {"filename": "pkg/v.go", "line": 10},
            },
            {
                "module": "example.com/target",
                "package": "example.com/target/cmd",
                "function": "main",
                "position": {"filename": "cmd/main.go", "line": 5},
            },
        ],
    }
}


class TestIterRecords(unittest.TestCase):
    def test_parses_concatenated_pretty_objects(self):
        recs = list(iter_records(_pretty_stream(CONFIG, OSV, MODULE_FINDING)))
        self.assertEqual(len(recs), 3)
        self.assertIn("config", recs[0])
        self.assertIn("finding", recs[2])

    def test_parses_jsonl_too(self):
        text = "\n".join(json.dumps(r) for r in (CONFIG, OSV))
        self.assertEqual(len(list(iter_records(text))), 2)

    def test_empty_and_garbage(self):
        self.assertEqual(list(iter_records("")), [])
        self.assertEqual(list(iter_records("not json")), [])


class TestClassify(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(classify(MODULE_FINDING["finding"]), "module_required_not_observed")
        self.assertEqual(classify(PACKAGE_FINDING["finding"]), "package_imported_not_observed")
        self.assertEqual(classify(SYMBOL_FINDING["finding"]), "symbol_reachable")

    def test_empty_trace(self):
        self.assertEqual(classify({"trace": []}), "module_required_not_observed")


class TestParseStream(unittest.TestCase):
    def test_most_specific_evidence_wins(self):
        # govulncheck emits module-, package-, and symbol-level findings for
        # the same OSV; the candidate must surface the most specific level.
        tool, cands = parse_stream(
            _pretty_stream(CONFIG, OSV, MODULE_FINDING, PACKAGE_FINDING, SYMBOL_FINDING)
        )
        self.assertEqual(tool["version"], "v1.1.4")
        self.assertEqual(len(cands), 1)
        c = cands[0]
        self.assertEqual(c["reachability"], "symbol_reachable")
        self.assertEqual(c["aliases"], ["CVE-2026-1111"])
        self.assertEqual(c["fixed_version"], "v1.2.3")
        # caller-first rendering: the target's own main() leads the path
        self.assertIn("main", c["example_trace"][0])
        self.assertIn("Vulnerable", c["example_trace"][-1])

    def test_order_does_not_downgrade(self):
        _, cands = parse_stream(_pretty_stream(CONFIG, OSV, SYMBOL_FINDING, MODULE_FINDING))
        self.assertEqual(cands[0]["reachability"], "symbol_reachable")

    def test_symbol_reachable_ranked_first(self):
        osv2 = {"osv": {"id": "GO-2026-0002", "aliases": [], "summary": "s"}}
        mod2 = {
            "finding": {
                "osv": "GO-2026-0002",
                "trace": [{"module": "example.com/other", "version": "v0.1.0"}],
            }
        }
        _, cands = parse_stream(_pretty_stream(CONFIG, osv2, mod2, OSV, SYMBOL_FINDING))
        self.assertEqual(
            [c["reachability"] for c in cands], ["symbol_reachable", "module_required_not_observed"]
        )

    def test_no_config_means_tool_failure_signal(self):
        tool, cands = parse_stream(_pretty_stream(OSV, MODULE_FINDING))
        self.assertEqual(tool, {})
        self.assertEqual(len(cands), 1)


class TestTraceSymbols(unittest.TestCase):
    def test_receiver_and_position(self):
        trace = [
            {
                "package": "p",
                "function": "F",
                "receiver": "*T",
                "position": {"filename": "a/b.go", "line": 7},
            }
        ]
        self.assertEqual(trace_symbols(trace), ["p.*T.F (a/b.go:7)"])

    def test_frames_without_function_skipped(self):
        trace = [{"module": "m"}, {"package": "p", "function": "F"}]
        self.assertEqual(trace_symbols(trace), ["p.F"])


class TestSafeExecWiring(unittest.TestCase):
    def test_run_govulncheck_passes_profile_map(self):
        repo = Path("/tmp/fake-repo")
        profile_map = {"go-scan": mock.Mock(name="profile")}

        with mock.patch("traust_engine._util.safe_exec.run") as run:
            run.return_value = (0, _pretty_stream(CONFIG), "")
            _run_govulncheck(repo, 30, "govulncheck", profile_map=profile_map)

        self.assertIs(run.call_args.kwargs["profile_map"], profile_map)

    def test_scan_forwards_profile_map(self):
        import tempfile

        profile_map = {"go-scan": mock.Mock(name="profile")}
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "go.mod").write_text("module example.com/x\n\ngo 1.21\n", encoding="utf-8")
            with mock.patch(
                "traust_engine.adapters.govulncheck._run_govulncheck",
                return_value=(0, "", "", {"version": "v1.0.0"}, []),
            ) as run:
                scan(repo, profile_map=profile_map)

        self.assertIs(run.call_args.kwargs["profile_map"], profile_map)


if __name__ == "__main__":
    unittest.main()
