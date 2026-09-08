"""Tests for traust_engine.toolchain — freeze, check, parsers, preflight, stamp."""

from traust_engine.toolchain._freeze import freeze_env, freeze_flags
from traust_engine.toolchain._preflight import preflight_failures
from traust_engine.toolchain._stamp import stamp_string
from traust_engine.toolchain._types import DBInfo, ToolCheck


class TestFreeze:
    def test_grype_freeze_env(self):
        env = freeze_env("grype")
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"

    def test_syft_freeze_env(self):
        env = freeze_env("syft")
        assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"

    def test_govulncheck_freeze_env_no_db_dir(self):
        env = freeze_env("govulncheck")
        assert "GOVULNDB" not in env

    def test_govulncheck_freeze_env_with_db_dir(self):
        env = freeze_env("govulncheck", db_dir="/tmp/vulndb")
        assert env["GOVULNDB"] == "file:///tmp/vulndb"

    def test_osv_scanner_freeze_flags(self):
        flags = freeze_flags("osv-scanner")
        assert flags == ["--offline"]

    def test_unknown_tool_returns_empty(self):
        assert freeze_env("unknown-tool") == {}
        assert freeze_flags("unknown-tool") == []


class TestPreflightFailures:
    def test_missing_tool(self):
        results = [ToolCheck(name="grype", installed=False)]
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "not found on PATH" in msgs[0]

    def test_wrong_version(self):
        results = [ToolCheck(name="grype", installed=True, version="0.100.0", version_ok=False)]
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "does not meet pin" in msgs[0]

    def test_missing_db(self):
        results = [
            ToolCheck(
                name="grype",
                installed=True,
                version="0.115.0",
                version_ok=True,
                db=DBInfo(exists=False, path="/tmp/grype/db"),
            )
        ]
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "DB not found" in msgs[0]

    def test_all_ok(self):
        results = [
            ToolCheck(
                name="grype",
                installed=True,
                version="0.115.0",
                version_ok=True,
                db=DBInfo(exists=True, built="2026-08-24"),
            )
        ]
        msgs = preflight_failures(results)
        assert msgs == []

    def test_tool_without_db_ok(self):
        results = [
            ToolCheck(name="opengrep", installed=True, version="1.25.0", version_ok=True, db=None)
        ]
        msgs = preflight_failures(results)
        assert msgs == []


class TestStamp:
    def test_full_stamp(self):
        s = stamp_string("grype", "0.115.0", db_built="2026-08-24", db_schema="5")
        assert s == "grype 0.115.0 (db built 2026-08-24, schema 5)"

    def test_no_db(self):
        assert stamp_string("opengrep", "1.25.0") == "opengrep 1.25.0"

    def test_db_built_only(self):
        s = stamp_string("osv-scanner", "2.4.0", db_built="2026-08-20")
        assert s == "osv-scanner 2.4.0 (db built 2026-08-20)"

    def test_no_version(self):
        assert stamp_string("grype") == "grype"
