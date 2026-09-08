"""``HarnessEngine.reporting`` — validate, render, lint, SARIF, bound to context.

Signing pubkey and safe_exec come from the injected ``HarnessContext``; callers
use ``h.reporting.validate(...)`` instead of self-fetching config.
"""

from __future__ import annotations

import json
from pathlib import Path

from traust_engine._ops_base import ContextOps
from traust_engine.reporting import lint, render, sarif, validate


class ReportingOps(ContextOps):
    def signing_pubkey(self) -> Path | None:
        return self._ctx.signing_pubkey

    def safe_exec(self):
        return self._ctx.safe_exec

    def validate(
        self,
        path: str | Path,
        *,
        strict: bool = False,
        schema: Path | dict | None = None,
        signing_pubkey: str | Path | None = None,
    ) -> list[validate.ValidationResult]:
        pubkey = signing_pubkey
        if pubkey is None:
            key = self.signing_pubkey()
            pubkey = str(key) if key is not None else None
        elif isinstance(pubkey, Path):
            pubkey = str(pubkey)

        explicit_schema: dict | None = None
        if isinstance(schema, dict):
            explicit_schema = schema
        elif schema is not None:
            explicit_schema = validate.load_schema(Path(schema))

        default_schema = validate.load_schema()
        schema_cache: dict[str, dict] = {}
        registry = validate.build_registry()
        results: list[validate.ValidationResult] = []

        for f in validate.collect_report_files(str(path)):
            if explicit_schema is not None:
                file_schema = explicit_schema
            else:
                detected = validate.detect_schema_path(f)
                if detected is not None:
                    key = str(detected)
                    if key not in schema_cache:
                        schema_cache[key] = validate.load_schema(detected)
                    file_schema = schema_cache[key]
                else:
                    file_schema = default_schema
            results.append(
                validate.validate_report(
                    str(f),
                    file_schema,
                    strict=strict,
                    registry=registry,
                    merkle_pubkey=pubkey,
                )
            )
        return results

    def render(self, path: str | Path) -> str:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        return render.render_report(report)

    def lint(self, path: str | Path, *, strict: bool = False) -> tuple[list[str], list[str]]:
        return lint.lint_file(Path(path), strict=strict)

    def sarif_convert(self, path: str | Path) -> dict:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        return sarif.export(report)
