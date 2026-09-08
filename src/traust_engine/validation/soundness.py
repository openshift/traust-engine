"""Refutation-soundness gate for the validate-findings engine.

Phase 1 of the validate-findings error-correction plan:
~70% of historical live-validation refutations rested on probes that
never actually tested the claim — the probe errored out (validator RBAC
Forbidden, tool-not-found, jsonpath failures, target NotFound), or an
RBAC template probe enumerated zero concrete subjects, or the operand
never installed yet the run still emitted ``refuted`` verdicts that
became ledgered false-positive events.

This module makes ``refuted`` deterministically UN-EMITTABLE under any
of those conditions. Gated verdicts downgrade to ``inconclusive`` and
carry a machine-readable ``soundness_flag``.
"""

from __future__ import annotations

import re
from pathlib import Path

INSTALL_FAILURE_FILENAME = "install-failure.yaml"

FLAG_TARGET_NOT_DEPLOYED = "target-not-deployed"
FLAG_RBAC_ZERO_SUBJECTS = "rbac-zero-subjects"
FLAG_RBAC_TEMPLATE = "rbac-template-placeholder"
FLAG_MISSING_CONTROL = "missing-positive-control"
FLAG_FAILED_CONTROL = "failed-positive-control"
FLAG_NON_DISCRIMINATING = "non-discriminating-oracle"
FLAG_MISSING_DIFFERENTIAL = "missing-differential-probe"

ERROR_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    (
        "forbidden",
        re.compile(
            r"Error from server \(Forbidden\)"
            r"|\bforbidden: User\b"
            r"|\bForbidden\b[^\n]{0,160}\bcannot (?:get|list|watch|create"
            r"|update|patch|delete|impersonate|use)\b"
            r"|\bUser \"[^\"]+\" cannot (?:get|list|watch|create|update"
            r"|patch|delete|impersonate|use)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command-not-found",
        re.compile(
            r"command not found|executable file not found"
            r"|not found in \$?PATH",
            re.IGNORECASE,
        ),
    ),
    (
        "jsonpath-error",
        re.compile(
            r"error executing jsonpath|error parsing jsonpath"
            r"|unrecognized identifier",
            re.IGNORECASE,
        ),
    ),
    (
        "not-found",
        re.compile(
            r"Error from server \(NotFound\)"
            r"|the server doesn'?t have a resource type",
            re.IGNORECASE,
        ),
    ),
    ("does-not-exist", re.compile(r"\bdoes not exist\b", re.IGNORECASE)),
    (
        "could-not-connect",
        re.compile(
            r"Could not connect|Unable to connect to the server"
            r"|could not resolve host|no route to host",
            re.IGNORECASE,
        ),
    ),
    (
        "unsubstituted-template",
        re.compile(
            r"system:serviceaccount:\{[^}]*\}"
            r"|\{ns\}:\{sa\}|--as=[^\s\"']*\{[a-z_]+\}"
        ),
    ),
)

_RBAC_TRIED_EMPTY_RE = re.compile(r"^vf-rbac-tried:\s*$", re.MULTILINE)
_RBAC_MARKER_RE = re.compile(r"vf-rbac-")
_RBAC_TEMPLATE_RE = re.compile(r"system:serviceaccount:\{[^}]*\}|\{ns\}:\{sa\}")


def is_rbac_probe(verb: str, observed: str) -> bool:
    """An RBAC-style probe: the ``rbac-can-i`` verb or any transcript
    carrying the harness's ``vf-rbac-*`` markers."""
    return verb == "rbac-can-i" or bool(_RBAC_MARKER_RE.search(observed or ""))


def match_error_signature(observed: str) -> str | None:
    """Name of the first matching error signature in the transcript."""
    text = observed or ""
    for name, pat in ERROR_SIGNATURES:
        if pat.search(text):
            return name
    return None


def soundness_flag(verb: str, observed: str, *, install_failure: bool = False) -> str | None:
    """The soundness flag a ``refuted`` verdict would carry, or None
    when the refutation is emittable. Deterministic; text-only."""
    if install_failure:
        return FLAG_TARGET_NOT_DEPLOYED
    text = observed or ""
    sig = match_error_signature(text)
    if sig:
        return f"error-signature:{sig}"
    if is_rbac_probe(verb, text):
        if _RBAC_TEMPLATE_RE.search(text):
            return FLAG_RBAC_TEMPLATE
        if _RBAC_TRIED_EMPTY_RE.search(text):
            return FLAG_RBAC_ZERO_SUBJECTS
    return None


def gate_verdict(
    verdict: str, verb: str, observed: str, *, install_failure: bool = False
) -> tuple[str, str | None]:
    """Apply the soundness gate to a step verdict.

    Only ``refuted`` is gated (downgrade-not-drop: a gated refutation
    becomes ``inconclusive`` + flag; confirmations and other verdicts
    pass through untouched).
    """
    if verdict != "refuted":
        return verdict, None
    flag = soundness_flag(verb, observed, install_failure=install_failure)
    if flag:
        return "inconclusive", flag
    return verdict, None


def run_install_failed(run_dir: Path | str) -> bool:
    """True when the run directory records an operand install failure."""
    return (Path(run_dir) / INSTALL_FAILURE_FILENAME).is_file()


def controls_flag(vf: dict, *, required: bool = False) -> str | None:
    """P1 assay-validity gate: a refuted verdict must rest on at least
    one PASSING positive control on its refuted steps."""
    if vf.get("verdict") != "refuted":
        return None
    controls = []
    for step in vf.get("steps") or []:
        if step.get("verdict") == "refuted":
            controls.extend(step.get("controls") or [])
    if any(c.get("ok") is False for c in controls):
        return FLAG_FAILED_CONTROL
    if required and not any(c.get("ok") for c in controls):
        return FLAG_MISSING_CONTROL
    return None


def differential_flag(vf: dict, *, required: bool = False) -> str | None:
    """P3 differential gate for authz refutations."""
    if vf.get("verdict") != "refuted":
        return None
    saw_authz_step = False
    saw_discriminating = False
    for step in vf.get("steps") or []:
        if step.get("verdict") != "refuted":
            continue
        diff = step.get("differential")
        if diff is not None:
            if diff.get("discriminated") is False:
                return FLAG_NON_DISCRIMINATING
            if diff.get("discriminated"):
                saw_discriminating = True
        if is_rbac_probe(str(step.get("verb") or ""), str(step.get("observed") or "")):
            saw_authz_step = True
    if required and saw_authz_step and not saw_discriminating:
        return FLAG_MISSING_DIFFERENTIAL
    return None


def flag_validated_finding(
    vf: dict,
    *,
    install_failure: bool = False,
    controls_required: bool = False,
    differential_required: bool = False,
) -> str | None:
    """Retroactive gate over a ``validated_findings[]`` entry from an
    existing (possibly pre-gate) validation report.

    Returns the soundness flag the finding's ``refuted`` verdict falls
    under, or None."""
    explicit = vf.get("soundness_flag")
    if explicit:
        return str(explicit)
    if install_failure and vf.get("verdict") == "refuted":
        return FLAG_TARGET_NOT_DEPLOYED
    if vf.get("verdict") != "refuted":
        return None
    cflag = controls_flag(vf, required=controls_required)
    if cflag:
        return cflag
    dflag = differential_flag(vf, required=differential_required)
    if dflag:
        return dflag
    probes = []
    for step in vf.get("steps") or []:
        if step.get("verdict") == "refuted":
            probes.append((str(step.get("verb") or ""), str(step.get("observed") or "")))
    if not probes and vf.get("observed_impact"):
        probes.append(("", str(vf["observed_impact"])))
    flags = [soundness_flag(verb, obs) for verb, obs in probes]
    flags = [fl for fl in flags if fl]
    if not flags:
        return None
    if len(flags) == len(probes):
        return flags[0]
    return None
