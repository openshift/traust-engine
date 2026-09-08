"""Containment for ledger layer paths — one implementation, two writers.

A ledger writer that accepts a bare path writes wherever it is told, including
outside the findings tree and through a symlink. Three of the five writers
already refused that (`emit_triage_ledger_events`, `emit_validation_ledger_events`,
`countersign`); `build_cumulative` and `finding_identity.rebaseline` did not,
which made the asymmetry an oversight rather than a decision (ledger plan, P9b).

This is a library, so it raises rather than exiting: a CLI turns
`LayerPathOutsideRoot` into whatever exit code it documents.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["LayerPathOutsideRoot", "confine_layer_path"]


class LayerPathOutsideRoot(ValueError):
    """A layer path resolved outside every allowed root."""


def confine_layer_path(
    candidate: str | Path,
    roots: list[Path],
    what: str = "layer",
) -> Path:
    """Resolve `candidate` and require it under one of `roots`.

    Resolution is by realpath on both sides, so a symlink pointing out of the
    tree is caught rather than followed. Relative candidates resolve against the
    cwd, matching documented CLI usage.
    """
    resolved = Path(candidate).resolve()
    checked: list[str] = []
    for root in roots:
        root_r = Path(root).resolve()
        checked.append(str(root_r))
        try:
            resolved.relative_to(root_r)
            return resolved
        except ValueError:
            continue
    raise LayerPathOutsideRoot(
        f"{what} path {str(candidate)!r} resolves to {resolved}, outside the "
        f"allowed root(s) {checked} — refusing"
    )
