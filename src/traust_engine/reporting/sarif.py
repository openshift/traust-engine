"""Export a harness report to SARIF 2.1.0 — a one-way, read-only projection.

Takes any report.schema.json-conformant report (`*-security-audit.json`
code/rpm profile, `*-container-audit.json`, or the derived
`*-findings-current.json`) and writes `<stem>.sarif` for consumption by
GitHub Code Scanning, SARIF viewers, and downstream aggregators.

Deliberately a projection, never a store:

- The harness report + disposition ledger stay authoritative. Nothing
  here feeds back into reports or ledgers, and the ledger's two-axis
  disposition semantics do not round-trip — false_positive validity and
  risk_accepted resolution become SARIF suppressions; everything else
  rides in property bags.
- Severity maps to SARIF `level` plus the GitHub `security-severity`
  property (critical 9.5 / high 8.0 / medium 5.0 / low 2.0 /
  informational 0.5). `effective_severity` (disposition override) wins
  over the claimed severity when present.
- File-backed locations become physicalLocations with a parsed line
  region; pseudo-paths (`pkg:golang/…`, `oci-config:User`,
  `layer:sha256:…`) become logicalLocations — GitHub renders the
  former inline, the latter list-only.
- `partialFingerprints` carries the campaign finding ID and the
  finding_identity fingerprint, so re-uploads dedup stably.

Cloud-config-audit reports (`*-cloud-config-audit.json`, the declared-
layer IaC schema) export through their own arm (P2): Checkov `check_id`s
become SARIF rules, audit-time `status: suppressed` becomes a
suppression carrying the auditor's rationale, `needs_review` rides in
properties, and the run is labeled declared-configuration — never an
observation claim.

Stdlib only. Usage:

    traust reporting sarif <report.json> [<report.json> ...]
    traust reporting sarif <report.json> -o out.sarif [--compact]
    traust reporting sarif --results-root analysis-results \
        --out-dir analysis-results/sarif    # batch sweep (CI recipe:
                                            # docs/sarif.md); prefers
                                            # findings-current over the
                                            # raw audit when both exist
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from traust_contracts.models import Finding

    HAS_CONTRACTS = True
except ImportError:
    HAS_CONTRACTS = False

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "traust-engine"


def _tool_uri() -> str | None:
    # `informationUri` is stamped into the driver block of EVERY exported SARIF
    # file, so it travels to every downstream consumer (GitHub Code Scanning,
    # viewers, aggregators). A deployment-specific URL is never a shipped
    # default: set ``locations.sarif_tool_uri`` to publish one. Unset, the key is
    # omitted — informationUri is optional in SARIF 2.1.0, and omitting it is
    # preferable to leaking an internal host.
    from traust_engine import locations

    return locations.sarif_tool_uri(locations.configured_locations())


# severity -> (SARIF level, GitHub security-severity property).
# informational maps to note/0.5 — 0.0 reads as "no severity" in some
# consumers and drops the finding from severity-sorted views.
SEVERITY_MAP = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "2.0"),
    "informational": ("note", "0.5"),
}

_LINES_RX = re.compile(r"^\s*(\d+)\s*(?:[-–]\s*(\d+))?\s*$")
# locations[].path values that are not files in the repo checkout
# (container profile pseudo-paths, package URLs)
_PSEUDO_PATH_RX = re.compile(r"^(pkg:|oci-config:|layer:|sha256:)")


def _severity_map(severity: str) -> tuple[str, str]:
    return SEVERITY_MAP.get(severity, ("note", "0.5"))


def findings_to_sarif_results(findings: list[Finding], tool_name: str = TOOL_NAME) -> list[dict]:
    """Convert typed Finding objects to SARIF result entries."""
    if not HAS_CONTRACTS:
        raise ImportError("traust_contracts required")
    del tool_name  # reserved for future run metadata
    results: list[dict] = []
    for f in findings:
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        level, sec_sev = _severity_map(sev)
        result: dict = {
            "ruleId": f.id,
            "message": {"text": f.description or f.title},
            "level": level,
            "properties": {"security-severity": str(sec_sev)},
        }
        if f.locations:
            loc = f.locations[0]
            lines = loc.lines.split("-") if loc.lines else []
            region: dict = {}
            if lines:
                region["startLine"] = int(lines[0]) if lines[0].isdigit() else 1
                if len(lines) > 1 and lines[1].isdigit():
                    region["endLine"] = int(lines[1])
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.path},
                        **({"region": region} if region else {}),
                    }
                }
            ]
        if f.fingerprint:
            result["partialFingerprints"] = {"harness/v1": f.fingerprint}
        results.append(result)
    return results


def _region(lines: str | None) -> dict | None:
    if not lines:
        return None
    m = _LINES_RX.match(lines)
    if not m:
        return None
    start = int(m.group(1))
    region = {"startLine": start}
    if m.group(2):
        region["endLine"] = int(m.group(2))
    return region


def _location(loc: dict) -> dict:
    path = loc.get("path", "")
    if _PSEUDO_PATH_RX.match(path):
        out: dict = {"logicalLocations": [{"fullyQualifiedName": path}]}
    else:
        physical: dict = {"artifactLocation": {"uri": path}}
        region = _region(loc.get("lines"))
        if region:
            physical["region"] = region
        out = {"physicalLocation": physical}
    if loc.get("description"):
        out["message"] = {"text": loc["description"]}
    return out


def _suppressions(finding: dict) -> list[dict]:
    """FP validity / risk_accepted resolution -> SARIF suppressions.

    The full disposition (evidence classes, countersigns, conflicts)
    does NOT round-trip; it rides verbatim in result.properties.
    """
    disp = finding.get("disposition") or {}
    out = []
    if disp.get("validity") == "false_positive":
        out.append(
            {
                "kind": "external",
                "status": "accepted",
                "justification": "harness disposition ledger: validity="
                "false_positive (countersigned per ledger; "
                "see properties.disposition)",
            }
        )
    if disp.get("resolution") == "risk_accepted":
        out.append(
            {
                "kind": "external",
                "status": "accepted",
                "justification": "harness disposition ledger: resolution="
                "risk_accepted (see properties.disposition)",
            }
        )
    return out


def _result(finding: dict, rule_index: dict[str, int]) -> dict:
    category = finding.get("category") or "uncategorized"
    severity = finding.get("effective_severity") or finding.get("severity") or "informational"
    level, sec_sev = SEVERITY_MAP.get(severity, ("note", "0.5"))

    text = finding.get("title", "")
    if finding.get("description"):
        text = f"{text}\n\n{finding['description']}"
    if finding.get("remediation"):
        text = f"{text}\n\nRemediation: {finding['remediation']}"

    properties: dict = {
        "security-severity": sec_sev,
        "harness/severity": severity,
        "harness/validation_status": finding.get("validation_status", "not_verified"),
    }
    if finding.get("cwes"):
        properties["tags"] = ["security", *list(finding["cwes"])]
    if (finding.get("cvss") or {}).get("vector"):
        properties["harness/cvss"] = finding["cvss"]
    if finding.get("disposition"):
        properties["harness/disposition"] = finding["disposition"]

    fingerprints = {"harnessFindingId/v1": finding.get("id", "")}
    if finding.get("fingerprint"):
        fingerprints["harnessFingerprint/v1"] = finding["fingerprint"]

    result = {
        "ruleId": category,
        "ruleIndex": rule_index[category],
        "level": level,
        "message": {"text": text or finding.get("id", "(untitled)")},
        "locations": [_location(loc) for loc in finding.get("locations") or []],
        "partialFingerprints": fingerprints,
        "properties": properties,
    }
    suppressions = _suppressions(finding)
    if suppressions:
        result["suppressions"] = suppressions
    # ledger resolution=resolved -> the finding is gone relative to the
    # audited baseline (baselineState mapping)
    if (finding.get("disposition") or {}).get("resolution") == "resolved":
        result["baselineState"] = "absent"
    return result


def is_cloud_config(report: dict) -> bool:
    md = report.get("metadata") or {}
    return md.get("assessment_mode") == "declared" or "facts_ref" in md


def _cca_result(finding: dict, rule_index: dict[str, int]) -> dict:
    check_id = finding.get("check_id") or "unknown-check"
    severity = finding.get("severity") or "informational"
    level, sec_sev = SEVERITY_MAP.get(severity, ("note", "0.5"))

    text = finding.get("title", "")
    if finding.get("rationale"):
        text = f"{text}\n\n{finding['rationale']}"
    if finding.get("remediation"):
        text = f"{text}\n\nRemediation: {finding['remediation']}"

    locations = []
    for loc in finding.get("locations") or []:
        physical: dict = {"artifactLocation": {"uri": loc.get("file_path", "")}}
        rng = loc.get("file_line_range") or []
        if rng:
            region = {"startLine": rng[0]}
            if len(rng) > 1 and rng[1] >= rng[0]:
                region["endLine"] = rng[1]
            physical["region"] = region
        entry: dict = {"physicalLocation": physical}
        if loc.get("resource"):
            entry["logicalLocations"] = [{"fullyQualifiedName": loc["resource"]}]
        locations.append(entry)

    properties: dict = {
        "security-severity": sec_sev,
        "harness/severity": severity,
        "harness/status": finding.get("status", "confirmed"),
        "harness/assessment_mode": "declared",
    }
    if finding.get("cwe"):
        properties["tags"] = ["security", finding["cwe"]]
    if finding.get("fact_ids"):
        properties["harness/fact_ids"] = finding["fact_ids"]
    if finding.get("control_refs"):
        properties["harness/control_refs"] = finding["control_refs"]

    result = {
        "ruleId": check_id,
        "ruleIndex": rule_index[check_id],
        "level": level,
        "message": {"text": text or finding.get("id", "(untitled)")},
        "locations": locations,
        "partialFingerprints": {"harnessFindingId/v1": finding.get("id", "")},
        "properties": properties,
    }
    if finding.get("status") == "suppressed":
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": finding.get("rationale")
                or "suppressed at audit time (auditor's claim; see the cloud-config-audit report)",
            }
        ]
    return result


def export_cloud_config(report: dict) -> dict:
    findings = report.get("findings") or []
    metadata = report.get("metadata") or {}

    check_ids: list[str] = []
    titles: dict[str, str] = {}
    for f in findings:
        cid = f.get("check_id") or "unknown-check"
        if cid not in check_ids:
            check_ids.append(cid)
            titles[cid] = f.get("title", cid)
    rule_index = {c: i for i, c in enumerate(check_ids)}
    rules = [
        {
            "id": c,
            "shortDescription": {"text": titles[c]},
            "properties": {"tags": ["security", "iac", "declared-configuration"]},
        }
        for c in check_ids
    ]

    version = str(metadata.get("harness_version", ""))
    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                **({"informationUri": _tool_uri()} if _tool_uri() else {}),
                "version": version or "0.0.0",
                "semanticVersion": version.split("-")[0] if version else "0.0.0",
                "rules": rules,
            }
        },
        "columnKind": "utf16CodeUnits",
        "results": [_cca_result(f, rule_index) for f in findings],
        "properties": {
            "harness/report_title": report.get("title", ""),
            "harness/target": metadata.get("target", ""),
            "harness/assessment_mode": "declared",
            "harness/engine": f"checkov {metadata.get('checkov_version', '')}".strip(),
            "harness/authoritative_source": "the cloud-config-audit report; this SARIF file is a "
            "derived one-way projection of DECLARED configuration — "
            "never an observation claim",
        },
    }
    if metadata.get("repository"):
        run["versionControlProvenance"] = [{"repositoryUri": metadata["repository"]}]
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def _degraded(report: dict) -> bool:
    """True when the run's own record says coverage was incomplete:
    an explicit metadata.additional.degraded flag, or any
    negative_results / deterministic_steps entry recording a skipped,
    failed, or unavailable step."""
    additional = (report.get("metadata") or {}).get("additional") or {}
    if additional.get("degraded"):
        return True
    probes = list(report.get("negative_results") or [])
    probes += list(additional.get("deterministic_steps") or [])
    for entry in probes:
        text = json.dumps(entry).lower()
        if any(w in text for w in ("skipped", "unavailable", "not-run", "tool_missing")):
            return True
    return False


def export(report: dict) -> dict:
    if is_cloud_config(report):
        return export_cloud_config(report)
    findings = report.get("findings") or []
    metadata = report.get("metadata") or {}
    additional = metadata.get("additional") or {}

    categories: list[str] = []
    for f in findings:
        c = f.get("category") or "uncategorized"
        if c not in categories:
            categories.append(c)
    rule_index = {c: i for i, c in enumerate(categories)}

    rules = [
        {
            "id": c,
            "name": c.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": f"Harness finding category: {c}"},
            "properties": {"tags": ["security", c]},
        }
        for c in categories
    ]

    version = str(additional.get("harness_version", ""))
    semantic = version.split("-")[0] if version else "0.0.0"

    run_properties = {
        "harness/report_title": report.get("title", ""),
        "harness/audit_profile": metadata.get("audit_profile", "code"),
        "harness/repository": metadata.get("repository", ""),
        "harness/commit": metadata.get("commit", ""),
        "harness/date": metadata.get("date", ""),
        "harness/authoritative_source": (
            "the harness report + disposition ledger; this SARIF file is "
            "a derived one-way projection — never an authoritative store"
        ),
    }
    if metadata.get("ref"):
        run_properties["harness/ref"] = metadata["ref"]
        run_properties["harness/ref_kind"] = metadata.get("ref_kind", "")

    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                **({"informationUri": _tool_uri()} if _tool_uri() else {}),
                "version": version or semantic,
                "semanticVersion": semantic,
                "rules": rules,
            }
        },
        "columnKind": "utf16CodeUnits",
        # degraded-run signal: a run whose
        # deterministic steps were skipped/unavailable is still useful
        # but consumers must not read it as full coverage
        "invocations": [{"executionSuccessful": not _degraded(report)}],
        "results": [_result(f, rule_index) for f in findings],
        "properties": run_properties,
    }
    if metadata.get("repository"):
        run["versionControlProvenance"] = [
            {
                "repositoryUri": metadata["repository"],
                **({"revisionId": metadata["commit"]} if metadata.get("commit") else {}),
            }
        ]

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


SWEEP_SUFFIXES = (
    "-findings-current.json",
    "-security-audit.json",
    "-container-audit.json",
    "-cloud-config-audit.json",
)


def _sweep(root: Path) -> list[Path]:
    """Collect exportable reports under root, one per baseline: the
    disposition-aware findings-current wins over its raw report when
    both exist. Symlink aliases and hidden/state dirs are skipped
    (same hygiene as the corpus walk)."""
    import os

    selected: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and not (Path(dirpath) / d).is_symlink()
        ]
        names = set(filenames)
        for fn in sorted(filenames):
            path = Path(dirpath) / fn
            if path.is_symlink() or not fn.endswith(SWEEP_SUFFIXES):
                continue
            if not fn.endswith("-findings-current.json"):
                stem = fn[: -len(".json")]
                if f"{stem}-findings-current.json" in names:
                    continue  # cumulative supersedes the raw report
                # code/cloud reports pair with the short cumulative name
                for suf in ("-security-audit", "-cloud-config-audit"):
                    if stem.endswith(suf) and (
                        f"{stem[: -len(suf)]}-findings-current.json" in names
                    ):
                        break
                else:
                    selected.append(path)
                    continue
                continue
            selected.append(path)
    return selected


def export_reports(
    reports: list[Path] | None = None,
    *,
    results_root: Path | None = None,
    out_dir: Path | None = None,
    out: Path | None = None,
    compact: bool = False,
) -> int:
    if bool(results_root) == bool(reports):
        print("ERROR: pass report paths OR --results-root, not both/neither", file=sys.stderr)
        return 2
    if results_root and not out_dir:
        print("ERROR: --results-root requires --out-dir", file=sys.stderr)
        return 2
    if out and (len(reports or []) > 1 or results_root):
        print("ERROR: -o/--out requires exactly one input report", file=sys.stderr)
        return 2

    sweep_root = None
    report_paths = list(reports or [])
    if results_root:
        sweep_root = results_root.resolve()
        report_paths = _sweep(sweep_root)
        if not report_paths:
            print(f"no exportable reports under {sweep_root}")
            return 0

    rc = 0
    for report_path in report_paths:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {report_path}: {e}", file=sys.stderr)
            rc = 1
            continue
        if not isinstance(report, dict) or "findings" not in report:
            print(f"ERROR: {report_path}: not a harness report (no findings key)", file=sys.stderr)
            rc = 1
            continue
        sarif = export(report)
        sarif_name = (
            report_path.name[: -len(".json")] + ".sarif"
            if report_path.name.endswith(".json")
            else report_path.name + ".sarif"
        )
        if sweep_root is not None:
            rel = report_path.resolve().parent.relative_to(sweep_root)
            out_path = out_dir / rel / sarif_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            out_path = out or report_path.with_name(sarif_name)
        indent = None if compact else 2
        out_path.write_text(
            json.dumps(sarif, indent=indent, sort_keys=False) + "\n", encoding="utf-8"
        )
        n = len(sarif["runs"][0]["results"])
        print(f"wrote {out_path} ({n} result{'s' if n != 1 else ''})")
    return rc
