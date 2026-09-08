#!/usr/bin/env python3
"""run_yara.py tests — rule indexing, output normalization, and rules
resolution are pure-python; the end-to-end scan only runs when the yara
binary is on PATH (not exercised here, mirroring test_run_opengrep)."""

import unittest
from pathlib import Path

from traust_engine.adapters import yara as R


class BuildRuleIndex(unittest.TestCase):
    def _pack(self, tmp: Path) -> Path:
        (tmp / "backdoor").mkdir(parents=True)
        (tmp / "ransomware").mkdir(parents=True)
        (tmp / "backdoor" / "Linux.Backdoor.BPFDoor.yara").write_text(
            'rule Linux_Backdoor_BPFDoor : tag1 tag2 {\n  strings: $a = "x"\n  condition: $a\n}\n',
            encoding="utf-8",
        )
        (tmp / "ransomware" / "Win.Ransom.Foo.yara").write_text(
            "private rule Win_Ransom_Foo\n{\n  condition: true\n}\n", encoding="utf-8"
        )
        return tmp

    def test_index_maps_id_to_category_and_family(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            root = self._pack(Path(d))
            files = R.discover_rule_files(root)
            self.assertEqual(len(files), 2)
            idx = R.build_rule_index(files)
            self.assertIn("Linux_Backdoor_BPFDoor", idx)
            self.assertEqual(idx["Linux_Backdoor_BPFDoor"]["category"], "backdoor")
            self.assertEqual(idx["Linux_Backdoor_BPFDoor"]["family"], "BPFDoor")
            # `private rule` modifier is still indexed
            self.assertIn("Win_Ransom_Foo", idx)
            self.assertEqual(idx["Win_Ransom_Foo"]["category"], "ransomware")

    def test_include_index_lists_every_rule_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            root = self._pack(Path(d))
            files = R.discover_rule_files(root)
            idx_file = R.generate_include_index(files, Path(d))
            body = idx_file.read_text(encoding="utf-8")
            self.assertEqual(body.count("include "), 2)
            for f in files:
                self.assertIn(f.as_posix(), body)


class ParseMatches(unittest.TestCase):
    def test_splits_rule_and_path_and_enriches(self):
        target = Path("/tmp/rootfs").resolve()
        idx = {
            "Linux_Backdoor_BPFDoor": {
                "source_file": "/rules/backdoor/x.yara",
                "category": "backdoor",
                "family": "BPFDoor",
            }
        }
        out = f"Linux_Backdoor_BPFDoor {target}/usr/bin/implant\n"
        facts = R.parse_matches(out, target, idx)
        self.assertEqual(len(facts), 1)
        f = facts[0]
        self.assertEqual(f["rule_id"], "Linux_Backdoor_BPFDoor")
        self.assertEqual(f["file"], "usr/bin/implant")
        self.assertEqual(f["category"], "backdoor")
        self.assertEqual(f["family"], "BPFDoor")
        self.assertEqual(f["severity_hint"], "high")
        self.assertFalse(f["carrier_path"])

    def test_carrier_path_flagged(self):
        target = Path("/tmp/rootfs").resolve()
        out = f"Some_Rule {target}/opt/clamav/testdata/eicar.bin\nOther_Rule {target}/app/server\n"
        facts = R.parse_matches(out, target, {})
        by_file = {f["file"]: f["carrier_path"] for f in facts}
        self.assertTrue(by_file["opt/clamav/testdata/eicar.bin"])
        self.assertFalse(by_file["app/server"])

    def test_unknown_rule_id_has_null_family(self):
        target = Path("/tmp/rootfs").resolve()
        facts = R.parse_matches(f"Mystery {target}/x", target, {})
        self.assertIsNone(facts[0]["family"])
        self.assertIsNone(facts[0]["category"])

    def test_blank_and_malformed_lines_skipped(self):
        target = Path("/tmp/rootfs").resolve()
        facts = R.parse_matches("\n   \nNoSpaceLine\n", target, {})
        self.assertEqual(facts, [])


class ResolveRules(unittest.TestCase):
    def test_rejects_movable_ref(self):
        with self.assertRaises(SystemExit):
            R.resolve_rules([f"{R.RL_RULES_REPO}@develop"])

    def test_rejects_short_sha(self):
        with self.assertRaises(SystemExit):
            R.resolve_rules([f"{R.RL_RULES_REPO}@abc123"])

    def test_rejects_non_https(self):
        with self.assertRaises(SystemExit):
            R.resolve_rules(["http://example.com/rules@" + "a" * 40])

    def test_local_path_used_as_is(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.yara").write_text("rule R { condition: true }", encoding="utf-8")
            resolved = R.resolve_rules([d])
            self.assertEqual(len(resolved), 1)
            self.assertEqual(resolved[0]["root"], str(Path(d).resolve()))
            self.assertIsNone(resolved[0]["sha"])

    def test_missing_local_path_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            R.resolve_rules(["/no/such/rules/path/xyz"])
        self.assertEqual(cm.exception.code, 2)

    def test_default_pin_is_immutable_40hex(self):
        import re

        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", R.RL_RULES_SHA))
        self.assertTrue(R.RL_RULES_REPO.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
