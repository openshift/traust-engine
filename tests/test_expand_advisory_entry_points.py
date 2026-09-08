"""Tests for traust_engine.impact.expand_advisory_entry_points — the library-side
entry-point expansion added under operator decision 'd' (2026-08-13):
build the mechanism, keep promotion OFF until calibrated."""

import json
import unittest
from pathlib import Path
from unittest import mock

from traust_engine.impact import expand_advisory_entry_points as ep


class TestJdkGate(unittest.TestCase):
    """jimple2cpg cannot read modern class files ('Unsupported class file
    major version 70' on JDK 26). Skipping honestly beats emitting an
    empty result that reads like 'no path exists'."""

    def test_modern_jdk_skips_with_a_named_reason(self):
        with mock.patch.object(ep, "jdk_major", return_value=(26, "26.0.2")):
            out = Path(self.tmp) / "a.json"
            ep.expand_entry_points("g:a", "1", ["x.Y#z"], out=out)
            d = json.loads(out.read_text())
        self.assertTrue(d["status"].startswith("skipped:"))
        self.assertIn("jimple2cpg", d["status"])
        self.assertEqual(d["entry_points"], [])

    def test_supported_jdk_passes_the_gate(self):
        # gate passes, then joern absence stops it — proves ordering
        with (
            mock.patch.object(ep, "jdk_major", return_value=(21, "21.0.12")),
            mock.patch.object(ep.shutil, "which", return_value=None),
        ):
            out = Path(self.tmp) / "b.json"
            ep.expand_entry_points("g:a", "1", ["x.Y#z"], out=out)
            d = json.loads(out.read_text())
        self.assertIn("joern", d["status"])
        self.assertNotIn("class file", d["status"])

    def setUp(self):
        import tempfile

        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()


class TestArtifactContract(unittest.TestCase):
    def _doc(self, **kw):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o.json"
            ep.emit(out, {"status": "ran", "entry_points": [], **kw})
            return json.loads(out.read_text())

    def test_promotion_is_declared_off(self):
        """The whole point of decision 'd': a consumer must not be able to
        read this artifact and promote to `affected`."""
        d = self._doc()
        self.assertIn("OFF", d["soundness"]["promotion"])
        self.assertIn("symbol-usage", d["soundness"]["promotion"])

    def test_two_step_inference_is_stated(self):
        d = self._doc()
        s = d["soundness"]["two_step_inference"]
        self.assertIn("reflection", s)

    def test_depth_is_declared_a_dial(self):
        d = self._doc()
        self.assertIn("depth", d["soundness"]["depth_is_a_dial"].lower())

    def test_empty_never_means_safe(self):
        d = self._doc()
        self.assertIn("UNRESOLVED", d["soundness"]["empty_result"])

    def test_cross_jar_gap_is_named(self):
        """Spring4Shell's DataBinder.bind is in spring-context, not
        spring-beans — single-artifact expansion cannot see it, and the
        artifact must say so rather than implying full coverage."""
        d = self._doc()
        self.assertTrue(any("CROSS-JAR" in g for g in d["coverage_gaps"]))


class TestMavenUrl(unittest.TestCase):
    def test_coordinate_becomes_a_central_path(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            captured = {}

            class _R:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *a):
                    return False

                def read(self_inner):
                    return b"jarbytes"

            def _open(url, timeout=0):
                captured["url"] = url
                return _R()

            with mock.patch.object(ep.urllib.request, "urlopen", _open):
                got = ep.fetch_maven_jar(
                    "org.springframework:spring-beans", "5.3.17", Path(td) / "x.jar"
                )
        self.assertEqual(
            captured["url"],
            "https://repo1.maven.org/maven2/org/springframework/"
            "spring-beans/5.3.17/spring-beans-5.3.17.jar",
        )
        self.assertEqual(got["bytes"], 8)
        self.assertIn("sha256", got)  # artifact identity is citable
