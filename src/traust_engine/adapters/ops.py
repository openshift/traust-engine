"""``HarnessEngine.adapters`` — scanner config injection, bound to context.

Adapters stay stateless; this namespace only surfaces typed config from the
injected context (rule-pack allowlist, safe_exec profiles, workspace root).
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import RulePackAllowlist, SafeExecProfiles
from traust_contracts.models import AdapterResult

from traust_engine._ops_base import ContextOps
from traust_engine.adapters import gitleaks as gitleaks_adapter
from traust_engine.adapters import govulncheck as govulncheck_adapter
from traust_engine.adapters import opengrep


class AdaptersOps(ContextOps):
    def rule_pack_allowlist(self) -> RulePackAllowlist | None:
        return self._ctx.rule_pack_allowlist

    def safe_exec_profiles(self) -> SafeExecProfiles:
        return self._ctx.safe_exec

    def allowlist_for_opengrep(self) -> RulePackAllowlist | None:
        """Typed rule-pack allowlist for opengrep supplemental packs."""
        return self._ctx.rule_pack_allowlist

    def rule_pack_allowlist_path(self) -> Path | None:
        """Filesystem path for allowlist YAML when loaded from context."""
        return self._optional_config_path("rule-pack-allowlist.yaml", self._ctx.rule_pack_allowlist)

    def gitleaks_config_path(self) -> Path:
        """Resolved gitleaks TOML: locations → GITLEAKS_CONFIG env → bundled default."""
        return gitleaks_adapter.resolve_gitleaks_config(
            config=None,
            loc=self._loc,
        )

    def rule_pack_dir(self) -> Path:
        """Resolved opengrep rule pack: locations → env → bundled default."""
        return opengrep.resolve_rule_pack_dir(
            pack=None,
            loc=self._loc,
        )

    def scan(
        self,
        target: Path,
        rules: list[str] | None = None,
        timeout: int = 900,
        opengrep_bin: str = "opengrep",
        rule_pack: Path | None = None,
        rule_allow: str | None = None,
    ) -> AdapterResult:
        """Run opengrep with supplemental packs from injected context."""
        return opengrep.scan(
            target,
            rules=rules,
            timeout=timeout,
            opengrep_bin=opengrep_bin,
            rule_pack=rule_pack,
            rule_allow=rule_allow,
            allowlist=self.allowlist_for_opengrep(),
            loc=self._loc,
        )

    def scan_gitleaks(
        self,
        repo: Path,
        mode: str = "dir",
        config: Path | None = None,
        timeout: int = 900,
        gitleaks_bin: str = "gitleaks",
    ) -> AdapterResult:
        """Run gitleaks with config resolved from injected context."""
        return gitleaks_adapter.scan(
            repo,
            mode=mode,
            config=config,
            timeout=timeout,
            gitleaks_bin=gitleaks_bin,
            loc=self._loc,
        )

    def scan_govulncheck(
        self,
        repo: Path,
        timeout: int = 600,
        govulncheck_bin: str = "govulncheck",
        *,
        freeze: bool = True,
    ) -> AdapterResult:
        """Run govulncheck with safe_exec profiles from injected context."""
        return govulncheck_adapter.scan(
            repo,
            timeout=timeout,
            govulncheck_bin=govulncheck_bin,
            freeze=freeze,
            profile_map=self.safe_exec_profile_map(),
        )
