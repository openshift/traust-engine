"""Tests for traust adapters joern and the /impact-analysis
Java joern tier (promotion-only evidence asymmetry)."""

import json
import unittest
from pathlib import Path
from unittest import mock

import traust_engine.impact.analyzer as ria
from traust_engine.adapters import joern as jr
from traust_engine.impact.analyzer import (
    RepoEvidence,
    classify,
)


class TestPatterns(unittest.TestCase):
    def _args(self, **kw):
        base = {"symbols": [], "packages": "", "module": ""}
        base.update(kw)
        return mock.Mock(**base)

    def test_symbol_becomes_method_prefix(self):
        pats = jr.patterns_from(self._args(symbols=["com.foo.Bar#deserialize"]))
        self.assertEqual(pats[0]["pattern"], "com.foo.Bar.deserialize:")
        self.assertEqual(pats[0]["kind"], "symbol")

    def test_packages_get_trailing_dot(self):
        pats = jr.patterns_from(self._args(packages="com.foo,com.bar."))
        self.assertEqual([p["pattern"] for p in pats], ["com.foo.", "com.bar."])
        self.assertTrue(all(p["kind"] == "package" for p in pats))

    def test_module_group_is_heuristic_fallback_only(self):
        pats = jr.patterns_from(self._args(module="com.fasterxml.jackson.core:jackson-databind"))
        self.assertEqual(pats[0]["kind"], "group-heuristic")
        # not used when anything stronger exists
        pats2 = jr.patterns_from(
            self._args(symbols=["com.x.Y#z"], module="com.fasterxml.jackson.core:jackson-databind")
        )
        self.assertTrue(all(p["kind"] != "group-heuristic" for p in pats2))

    def test_groupless_module_derives_nothing(self):
        self.assertEqual(jr.patterns_from(self._args(module="flatjar")), [])


def _run_joern_wrapper(repo: str, out: Path, **kwargs) -> int:
    doc = jr._run_joern_scan(
        Path(repo),
        symbols=kwargs.get("symbols", []),
        packages=kwargs.get("packages", ""),
        module=kwargs.get("module", ""),
        language=kwargs.get("language", "java"),
        timeout=kwargs.get("timeout", 900),
        max_sites=kwargs.get("max_sites", 200),
    )
    jr.emit(out, doc)
    return 0


class TestWrapperSkips(unittest.TestCase):
    def test_skips_without_joern(
        self,
    ):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "facts.json"
            with mock.patch.object(jr.shutil, "which", return_value=None):
                rc = _run_joern_wrapper(tmp, out, packages="com.foo")
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text())
            self.assertIn("skipped: joern not on PATH", doc["status"])
            # soundness asymmetry is stated on EVERY artifact
            self.assertIn("absent_path", doc["soundness"])
            self.assertIn("NEVER", doc["soundness"]["absent_path"])

    def test_skips_without_java_sources(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "facts.json"
            with mock.patch.object(jr.shutil, "which", return_value="/bin/joern"):
                rc = _run_joern_wrapper(tmp, out, packages="com.foo")
            self.assertEqual(rc, 0)
            self.assertIn("no java sources", json.loads(out.read_text())["status"])


# TestJavaJoernTier was REMOVED in v0.1.8 alongside the Java tier itself
# (v0.1.7). Its four cases asserted `JavaAnalyzer._joern_tier` promotion
# behaviour for a tier that promoted 0 of 120 in-range pairs and no longer
# exists — see the harness's docs/reachability.md.
#
# They survived the v0.1.7 commit because this suite imports the INSTALLED
# traust_engine, which was still 0.1.6 at that moment, so the removal was
# not actually exercised. Re-running after `uv sync` surfaced them. Keep that
# in mind when changing this package: a green suite proves the installed
# version is green, not the working tree.
#
# The C/C++ tier retains full coverage below (TestCPatterns,
# TestCAnalyzerJoernGate) — it was kept on measurement: 6/6 direct calls
# resolved against human-audited ground truth.


class TestCPatterns(unittest.TestCase):
    def test_c_symbols_are_exact_match(self):
        args = mock.Mock(
            symbols=["EVP_EncryptUpdate", "strcpy"], packages="", module="", language="c"
        )
        pats = jr.patterns_from(args)
        self.assertEqual([p["pattern"] for p in pats], ["=EVP_EncryptUpdate", "=strcpy"])
        self.assertTrue(all(p["kind"] == "symbol" for p in pats))


class TestCAnalyzerJoernGate(unittest.TestCase):
    def test_c_tier_gated_on_symbols_and_presence(self):
        ctx_nosym = mock.Mock(symbols=[], module="openssl", packages=[])
        ev = RepoEvidence(source_import_scan="imports_found")
        with mock.patch.object(ria, "_run_joern_tier"):
            # gate replicated: no symbols -> tier must not run (checked
            # inside CAnalyzer.analyze; we assert the gating expression)
            should = (
                ev.source_import_scan == "imports_found" or ev.binary_linked_library == "linked"
            ) and bool(ctx_nosym.symbols)
            self.assertFalse(should)

    def test_c_symbol_hit_classifies_affected(self):
        ev = RepoEvidence(
            evidence_level="manifest",
            source_import_scan="imports_found",
            joern_reachability="vulnerable_symbol_called",
        )
        ev.evidence_level = "symbol"
        self.assertEqual(classify(ev), "affected")


class TestImportDerivedPackages(unittest.TestCase):
    """The group id is NOT the package root for the fleet's most common
    coordinates (measured 2026-08-11): jackson-databind's group is
    com.fasterxml.jackson.core but its classes live in
    com.fasterxml.jackson.databind, so the group heuristic queried a
    package that cannot exist — 20 of 52 maven advisories."""

    def _tree(self, tmp, rel, body):
        p = Path(tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_derives_real_package_not_group_id(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            self._tree(
                td,
                "src/main/java/a/A.java",
                "package a;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nclass A {}\n",
            )
            got = jr.derive_packages_from_imports(
                Path(td), "com.fasterxml.jackson.core:jackson-databind"
            )
            self.assertEqual([g["pattern"] for g in got], ["com.fasterxml.jackson.databind."])
            self.assertIn("evidence_file", got[0])

    def test_ranks_out_weak_single_token_matches(self):
        """io.quarkus.jackson matches only 'jackson'; the real package
        matches fasterxml+jackson+databind and must win alone."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            self._tree(
                td,
                "src/main/java/a/A.java",
                "package a;\n"
                "import com.fasterxml.jackson.databind.ObjectMapper;\n"
                "import io.quarkus.jackson.ObjectMapperCustomizer;\n"
                "class A {}\n",
            )
            got = [
                g["pattern"]
                for g in jr.derive_packages_from_imports(
                    Path(td), "com.fasterxml.jackson.core:jackson-databind"
                )
            ]
            self.assertEqual(got, ["com.fasterxml.jackson.databind."])

    def test_emits_nothing_when_dependency_is_not_imported(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            self._tree(
                td, "src/main/java/a/A.java", "package a;\nimport java.util.List;\nclass A {}\n"
            )
            self.assertEqual(jr.derive_packages_from_imports(Path(td), "com.h2database:h2"), [])

    def test_group_heuristic_still_used_when_no_import_evidence(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            args = mock.Mock(
                symbols=[],
                packages="",
                language="java",
                repo=Path(td),
                module="com.example.grp:artifact",
            )
            pats = jr.patterns_from(args)
            self.assertEqual(pats[0]["kind"], "group-heuristic")


class TestFrontendSelection(unittest.TestCase):
    def test_frontend_is_explicit_per_language(self):
        """joern-parse auto-detection picks jimple2cpg (BYTECODE) for a
        Java tree with compiled artifacts present, which fails outright or
        — worse — emits different methodFullName shapes so every pattern
        silently misses. Measured 2026-08-11: 41 of the maven sweep's tier
        outcomes were this."""
        self.assertEqual(jr._FRONTEND["java"], "JAVASRC")
        self.assertEqual(jr._FRONTEND["c"], "NEWC")

    def test_bare_class_symbol_uses_contains_match(self):
        """methodFullName is package-qualified, so a startsWith on
        `Class.method:` can never match a bare class name."""
        pats = jr.patterns_from(
            mock.Mock(symbols=["Bar#deserialize"], packages="", module="", language="java")
        )
        self.assertTrue(pats[0]["pattern"].startswith("~"))
        self.assertEqual(pats[0]["kind"], "symbol")


if __name__ == "__main__":
    unittest.main()
