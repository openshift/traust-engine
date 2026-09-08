"""Dependency-CVE candidates via osv-scanner (multi-ecosystem SCA stage).

Runs `osv-scanner` against a pinned target clone and reduces its JSON
output to one candidate per (OSV advisory, package), tagged with the
manifest/lockfile it was declared in. The multi-ecosystem counterpart of
run_govulncheck.py: it covers npm / PyPI / crates.io / Maven / Go and
more from lockfiles alone, but — unlike govulncheck — it has NO
reachability signal: every candidate here is merely *declared*, evidence
class `dependency_declared`.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). A declared vulnerable dependency
is context for the audit/triage agent to weigh — the package may be
unused, dev-only, or the vulnerable code path unexercised. Downstream
consumers may raise a prior on this signal but never auto-emit a finding
from it.

Usage:
    python3 run_osv_scanner.py --repo <clone> [--out <file>]
                               [--timeout SECONDS] [--osv-scanner BIN]

Output defaults to <repo-basename>-osv-scanner.json in the CWD.
Exit 0 on a completed scan (with or without candidates); 1 on tool failure.
"""

import json
import subprocess
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)
from traust_engine.assets import harness_version as engine_harness_version


def harness_version():
    return engine_harness_version()


def repo_head(repo):
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


def fixed_version(vuln: dict, pkg_name: str, ecosystem: str):
    """Best-effort fixed version for pkg from the OSV affected ranges."""
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name") != pkg_name:
            continue
        if ecosystem and p.get("ecosystem") and p["ecosystem"] != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def parse_output(doc: dict, repo: Path) -> list[dict]:
    """Reduce osv-scanner JSON to per-(advisory, package) candidates."""
    candidates: dict[tuple, dict] = {}
    for result in doc.get("results") or []:
        src = result.get("source") or {}
        src_path = src.get("path") or ""
        try:
            src_rel = str(Path(src_path).resolve().relative_to(repo.resolve()))
        except ValueError:
            src_rel = src_path
        for pkg_entry in result.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name") or ""
            eco = pkg.get("ecosystem") or ""
            ver = pkg.get("version") or ""
            sev_by_group = {}
            for grp in pkg_entry.get("groups") or []:
                for vid in grp.get("ids") or []:
                    sev_by_group[vid] = grp.get("max_severity")
            for vuln in pkg_entry.get("vulnerabilities") or []:
                vid = vuln.get("id")
                if not vid:
                    continue
                key = (vid, eco, name)
                cand = candidates.setdefault(
                    key,
                    {
                        "osv_id": vid,
                        "aliases": vuln.get("aliases") or [],
                        "summary": (vuln.get("summary") or (vuln.get("details") or "")[:200]),
                        "ecosystem": eco,
                        "package": name,
                        "found_version": ver,
                        "fixed_version": fixed_version(vuln, name, eco),
                        "max_severity": sev_by_group.get(vid),
                        "evidence": "dependency_declared",
                        "sources": [],
                    },
                )
                if src_rel and src_rel not in cand["sources"]:
                    cand["sources"].append(src_rel)
    return sorted(candidates.values(), key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))


def run_scanner(binary: str, repo: Path, timeout: int, *, freeze: bool = False):
    """Invoke osv-scanner, tolerating both the v2 (`scan source`) and v1
    CLI shapes. Returns (stdout, stderr, returncode) of the first shape
    that produces output, or the last attempt's result.

    When *freeze* is True, ``--offline`` is appended so osv-scanner uses
    only its local DB cache and never phones home mid-scan.
    """
    from traust_engine.toolchain import freeze_flags

    extra = freeze_flags("osv-scanner") if freeze else []
    shapes = [
        [binary, "scan", "source", "--recursive", "--format", "json", *extra, str(repo)],
        [binary, "--recursive", "--format", "json", *extra, str(repo)],
    ]
    last = None
    for cmd in shapes:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        last = (proc, " ".join(cmd))
        if proc.stdout.strip().startswith("{"):
            return proc, " ".join(cmd)
    return last


def _cvss_to_severity(max_severity: str | None) -> str:
    if not max_severity:
        return "medium"
    sev = max_severity.upper()
    if sev in ("CRITICAL",):
        return "critical"
    if sev in ("HIGH", "HIGHEST"):
        return "high"
    if sev in ("MEDIUM", "MODERATE"):
        return "medium"
    if sev in ("LOW",):
        return "low"
    return "medium"


def _candidates_to_findings(candidates: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for cand in candidates:
        locs = []
        for src in cand.get("sources", []):
            loc = Location(path=src) if Location is not None else {"path": src}
            locs.append(loc)
        desc_parts = [
            f"{cand.get('package')}@{cand.get('found_version')}",
            f"ecosystem={cand.get('ecosystem')}",
        ]
        if cand.get("fixed_version"):
            desc_parts.append(f"fixed in {cand['fixed_version']}")
        findings.append(
            {
                "id": cand["osv_id"],
                "title": cand.get("summary") or cand["osv_id"],
                "severity": map_severity(_cvss_to_severity(cand.get("max_severity"))),
                "locations": locs,
                "description": "; ".join(desc_parts),
                "origin": "osv-scanner",
                "source_findings": cand.get("aliases", []),
                "category": cand.get("ecosystem", ""),
            }
        )
    return findings


def scan(
    repo: Path,
    timeout: int = 600,
    *,
    freeze: bool = True,
) -> AdapterResult:
    """Run osv-scanner and return typed scan result.

    *freeze* (default True) prevents osv-scanner from updating its local
    DB cache during the scan (batch consistency / air-gap mode).
    """
    osv_scanner_bin = "osv-scanner"
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"not a directory: {repo}")

    proc, _invocation = run_scanner(osv_scanner_bin, repo, timeout, freeze=freeze)
    scan_doc = json.loads(proc.stdout)
    candidates = parse_output(scan_doc, repo)
    tool_ver = (
        (scan_doc.get("experimental_config") or {}).get("version")
        or _tool_version(osv_scanner_bin)
        or ""
    )
    return build_scan_result(
        str(repo),
        "osv-scanner",
        _candidates_to_findings(candidates),
        scanned_at=utc_now(),
        scanner_version=tool_ver,
    )


def _tool_version(binary: str):
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=15
        ).stdout
        return out.strip().splitlines()[0] if out.strip() else None
    except (subprocess.SubprocessError, OSError):
        return None
