"""Every _MIGRATED target must resolve to a module that exists.

`load_script` maps a bare name to a module path and hands it to
importlib.import_module, so a mapping to a module that was never written fails
only at the call site, inside whichever skill happens to ask for it.

The entry that prompted this test mapped "validate_employee" to
`traust.cli.validate_employee`, which has never existed in any repo. Employee
verification is supplied by the DEPLOYMENT via `LEDGER_DIRECTORY_COMMAND` —
an operator-provided executable (see traust_ledger.auth.directory) — not by a
harness module, so the mapping could never have resolved.

`_MIGRATED` spans two packages: `traust_engine.*` targets, which this repo
owns and must always import, and `traust.cli.*` targets, which live in the
harness. traust-engine does not depend on the harness, so those are checked
only when it happens to be installed (it is in the harness venv, where the
docs/alignment gates run) and skipped otherwise. A target whose package is
absent is never reported as broken — only one whose package is present and
does not contain it.
"""

from __future__ import annotations

import importlib
import importlib.util

import pytest

from traust_engine._util.script_loader import _MIGRATED


def _root(target: str) -> str:
    return target.split(".", 1)[0]


@pytest.mark.parametrize("name,target", sorted(_MIGRATED.items()))
def test_migrated_target_resolves(name: str, target: str) -> None:
    root = _root(target)
    if root != "traust_engine" and importlib.util.find_spec(root) is None:
        pytest.skip(f"{root} not installed in this environment")
    try:
        importlib.import_module(target)
    except ImportError as exc:  # pragma: no cover - the failure is the point
        pytest.fail(
            f"_MIGRATED[{name!r}] -> {target!r} does not exist ({exc}). "
            "Remove the entry, or point it at a module that does."
        )
