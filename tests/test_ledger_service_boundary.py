"""LedgerService must stay a thin gateway, not re-accrete ledger logic.

Goal-2 of the ledger→SDK migration: the ledger client and its functional
logic live in the SDK (traust-ledger), and traust-engine only *delegates*.
The failure mode this guards against is logic creeping back in via imports
of traust-ledger internals or reach-ins to the client's private state — the
service docstring's promise ("never through scattered imports of traust-ledger
internals") made mechanical.
"""

from __future__ import annotations

import ast
from pathlib import Path

import traust_engine.ledger as ledger_pkg

PKG_DIR = Path(ledger_pkg.__file__).parent


def _sources() -> list[tuple[Path, str]]:
    return [(p, p.read_text(encoding="utf-8")) for p in PKG_DIR.glob("*.py")]


def test_no_ledger_core_internal_imports() -> None:
    """The gateway consumes only traust_ledger's public surface (api/client)."""
    offenders = []
    for path, src in _sources():
        for node in ast.walk(ast.parse(src)):
            mod = getattr(node, "module", None)
            if isinstance(node, ast.ImportFrom) and mod and "traust_ledger._internal" in mod:
                offenders.append(f"{path.name}:{node.lineno}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "traust_ledger._internal" in alias.name:
                        offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"traust_ledger._internal imports: {offenders}"


def test_no_private_client_reach_ins() -> None:
    """No `self._client._foo` — logic must route through public client verbs."""
    offenders = []
    for path, src in _sources():
        for node in ast.walk(ast.parse(src)):
            # attribute access whose value is itself a private attribute access
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "_client"
                and node.attr.startswith("_")
            ):
                offenders.append(f"{path.name}:{node.lineno} (._client.{node.attr})")
    assert not offenders, f"private client reach-ins: {offenders}"
