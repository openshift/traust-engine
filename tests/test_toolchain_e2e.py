"""E2E tests for traust_engine.toolchain — require external tools on PATH.

Every test skips automatically when its required tool is absent, so this
module is safe to run on any machine. Marked `integration` for selective
pytest invocation.
"""

import shutil
import subprocess

import pytest

from traust_engine.toolchain._check import _version_ge, check_tool, tool_version
from traust_engine.toolchain._freeze import freeze_env, freeze_flags
from traust_engine.toolchain._parsers import db_status
from traust_engine.toolchain._preflight import preflight, preflight_failures
from traust_engine.toolchain._stamp import stamp_string


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


requires_grype = pytest.mark.skipif(not _has("grype"), reason="grype not on PATH")
requires_syft = pytest.mark.skipif(not _has("syft"), reason="syft not on PATH")
requires_osv = pytest.mark.skipif(not _has("osv-scanner"), reason="osv-scanner not on PATH")
requires_govulncheck = pytest.mark.skipif(
    not _has("govulncheck"),
    reason="govulncheck not on PATH",
)
requires_opengrep = pytest.mark.skipif(not _has("opengrep"), reason="opengrep not on PATH")
requires_gitleaks = pytest.mark.skipif(not _has("gitleaks"), reason="gitleaks not on PATH")


# Presence on PATH is not the only precondition. Two tests assert a tool is
# USABLE, and a tool can be installed and still not be: an untagged `go install`
# govulncheck reports v0.0.0 (the manifest warns about exactly this), and
# osv-scanner runs fine with no vulnerability database. Both then fail rather
# than skip, which breaks this module's stated contract -- "safe to run on any
# machine" -- for anyone whose toolchain is not fully provisioned. Gate on the
# real precondition, and name it in the reason so the signal is not lost.
def _govulncheck_is_tagged() -> bool:
    if not _has("govulncheck"):
        return False
    return tool_version(
        "govulncheck",
        version_cmd=["govulncheck", "-version"],
        version_regex=r"govulncheck@v(\d+)\.(\d+)\.(\d+)",
    ) not in (None, "0.0.0")


def _osv_db_present() -> bool:
    return _has("osv-scanner") and bool(db_status("osv-scanner").exists)


requires_tagged_govulncheck = pytest.mark.skipif(
    not _govulncheck_is_tagged(),
    reason="govulncheck is absent or an untagged build (reports v0.0.0) — "
    "reinstall with `go install golang.org/x/vuln/cmd/govulncheck@vX.Y.Z`",
)
requires_osv_db = pytest.mark.skipif(
    not _osv_db_present(),
    reason="osv-scanner vulnerability DB not fetched — "
    "run `osv-scanner --download-offline-databases`",
)

pytestmark = pytest.mark.integration


# -- version_ge --


class TestVersionGe:
    def test_equal(self):
        assert _version_ge("0.115.0", "0.115.0")

    def test_greater_minor(self):
        assert _version_ge("0.116.0", "0.115.0")

    def test_lesser_minor(self):
        assert not _version_ge("0.114.0", "0.115.0")

    def test_greater_major(self):
        assert _version_ge("1.0.0", "0.115.0")

    def test_patch_only(self):
        assert _version_ge("0.115.1", "0.115.0")
        assert not _version_ge("0.115.0", "0.115.1")


# -- tool_version against real binaries --


@requires_grype
class TestGrypeE2E:
    def test_version_detected(self):
        ver = tool_version("grype")
        assert ver is not None
        parts = ver.split(".")
        assert len(parts) == 3

    def test_check_tool(self):
        tc = check_tool("grype", expected="0.100.0")
        assert tc.installed
        assert tc.version_ok
        assert tc.version is not None

    def test_freeze_env_keys(self):
        env = freeze_env("grype")
        assert "GRYPE_DB_AUTO_UPDATE" in env

    def test_db_status(self):
        info = db_status("grype")
        assert info is not None
        # DB may or may not exist depending on whether user has run grype db update

    def test_stamp(self):
        tc = check_tool("grype")
        s = stamp_string(
            "grype",
            tc.version,
            db_built=tc.db.built if tc.db else None,
            db_schema=tc.db.schema_version if tc.db else None,
        )
        assert s.startswith("grype ")


@requires_syft
class TestSyftE2E:
    def test_version_detected(self):
        ver = tool_version("syft")
        assert ver is not None

    def test_check_tool(self):
        tc = check_tool("syft", expected="1.0.0")
        assert tc.installed
        assert tc.version_ok

    def test_freeze_env_keys(self):
        env = freeze_env("syft")
        assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"


@requires_osv
class TestOsvScannerE2E:
    def test_version_detected(self):
        ver = tool_version("osv-scanner")
        assert ver is not None

    def test_freeze_flags(self):
        flags = freeze_flags("osv-scanner")
        assert "--offline" in flags

    def test_db_status_returns_info(self):
        info = db_status("osv-scanner")
        assert info is not None


@requires_govulncheck
class TestGovulncheckE2E:
    def test_version_detected(self):
        ver = tool_version(
            "govulncheck",
            version_cmd=["govulncheck", "-version"],
            version_regex=r"govulncheck@v(\d+)\.(\d+)\.(\d+)",
        )
        assert ver is not None

    @requires_tagged_govulncheck
    def test_check_tool_with_regex(self):
        tc = check_tool(
            "govulncheck",
            expected="1.0.0",
            version_cmd=["govulncheck", "-version"],
            version_regex=r"govulncheck@v(\d+)\.(\d+)\.(\d+)",
        )
        assert tc.installed
        assert tc.version_ok


@requires_opengrep
class TestOpengrepE2E:
    def test_version_detected(self):
        ver = tool_version("opengrep")
        assert ver is not None

    def test_no_db(self):
        info = db_status("opengrep")
        assert info is None


@requires_gitleaks
class TestGitleaksE2E:
    def test_version_detected(self):
        ver = tool_version("gitleaks", version_cmd=["gitleaks", "version"])
        assert ver is not None

    def test_no_db(self):
        info = db_status("gitleaks")
        assert info is None


# -- preflight against real tools --


class TestPreflightE2E:
    def test_missing_tool_fails(self):
        results = preflight(["definitely-not-a-real-tool-xyz"])
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "not found on PATH" in msgs[0]

    @requires_grype
    def test_grype_passes_with_low_pin(self):
        results = preflight(
            ["grype"],
            pins={"grype": {"expected": "0.1.0"}},
        )
        msgs = preflight_failures(results)
        assert msgs == []

    @requires_grype
    def test_grype_fails_with_impossibly_high_pin(self):
        results = preflight(
            ["grype"],
            pins={"grype": {"expected": "999.0.0"}},
        )
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "does not meet pin" in msgs[0]

    @requires_osv
    @requires_osv_db
    @requires_grype
    def test_multi_tool_preflight(self):
        results = preflight(
            ["grype", "osv-scanner"],
            pins={
                "grype": {"expected": "0.1.0"},
                "osv-scanner": {"expected": "1.0.0"},
            },
        )
        msgs = preflight_failures(results)
        assert msgs == []
        assert all(tc.installed for tc in results)
        assert all(tc.version_ok for tc in results)

    def test_mix_of_present_and_missing(self):
        tools = ["definitely-not-a-real-tool-xyz"]
        if _has("grype"):
            tools.insert(0, "grype")
        results = preflight(
            tools,
            pins={"grype": {"expected": "0.1.0"}} if _has("grype") else {},
        )
        msgs = preflight_failures(results)
        assert any("not found on PATH" in m for m in msgs)


# -- freeze env integration: verify subprocess sees the env --


@requires_grype
class TestFreezeIntegration:
    def test_grype_env_suppresses_update_check(self):
        env = freeze_env("grype")
        proc = subprocess.run(
            ["env"],
            capture_output=True,
            text=True,
            env={**dict(__import__("os").environ), **env},
            timeout=5,
        )
        assert "GRYPE_DB_AUTO_UPDATE=false" in proc.stdout
        assert "GRYPE_CHECK_FOR_APP_UPDATE=false" in proc.stdout


class TestUnstampedDetection:
    """An unstamped build is not an old build.

    `go install` from a local clone produces a binary reporting v0.0.0. Read as
    a version it is "ancient", so every floor fails and the operator is told to
    upgrade -- which cannot fix it. Only changing the install method can.
    """

    def test_zero_version_is_flagged_unstamped(self, monkeypatch):
        from traust_engine.toolchain import _check

        monkeypatch.setattr(_check.shutil, "which", lambda n: "/usr/bin/" + n)
        monkeypatch.setattr(_check, "tool_version", lambda *a, **k: "0.0.0")
        tc = _check.check_tool("govulncheck", expected="1.6.0")
        assert tc.unstamped is True
        assert tc.version_ok is False

    def test_a_real_old_version_is_not_unstamped(self, monkeypatch):
        from traust_engine.toolchain import _check

        monkeypatch.setattr(_check.shutil, "which", lambda n: "/usr/bin/" + n)
        monkeypatch.setattr(_check, "tool_version", lambda *a, **k: "1.0.0")
        tc = _check.check_tool("govulncheck", expected="1.6.0")
        assert tc.unstamped is False
        assert tc.version_ok is False

    def test_preflight_names_the_actual_fix(self):
        from traust_engine.toolchain._types import ToolCheck

        msgs = preflight_failures(
            [
                ToolCheck(
                    name="govulncheck",
                    installed=True,
                    version="0.0.0",
                    version_ok=False,
                    unstamped=True,
                )
            ]
        )
        assert len(msgs) == 1
        assert "no version stamp" in msgs[0]
        assert "upgrading will not help" in msgs[0]

    def test_an_ordinary_pin_miss_still_reads_as_a_pin_miss(self):
        from traust_engine.toolchain._types import ToolCheck

        msgs = preflight_failures(
            [ToolCheck(name="grype", installed=True, version="1.0.0", version_ok=False)]
        )
        assert "does not meet pin" in msgs[0]
