"""Deterministic linter for THREAT_MODEL.md artifacts.

Enforces the contract in skills/threat-model/schema.md the same way
validate_report.py gates audit/triage JSON: the /threat-model skill is not
done until this exits 0. Checks structure (sections, tables, enums), the
coverage invariant (every entry point is threatened or explicitly parked),
ID stability, provenance completeness, and evidence-cell hygiene (evidence
holds vuln references, never file:line citations — the litmus-test guard).

Deterministic-tooling invariant: this script routes/gates/validates; it
never concludes. A lint failure means "fix the artifact", not "the threat
is wrong".

Usage:
    python3 -m traust_engine.reporting.lint <path> [<path> ...] [--strict]

Paths may be THREAT_MODEL.md files or directories (searched recursively for
THREAT_MODEL.md and *-threat-model.md). --strict promotes recommended-but-
optional gaps (missing harness_version, missing section 8) to warnings shown
in the summary; they never fail the run, matching validate_report.py --strict.
"""

import re
from pathlib import Path

REQUIRED_SECTIONS = [
    "1. System context",
    "2. Assets",
    "3. Entry points & trust boundaries",
    "4. Threats",
    "5. Deprioritized",
    "6. Open questions",
    "7. Provenance",
]
OPTIONAL_SECTIONS = ["8. Recommended mitigations", "9. Attack scenarios", "10. Tenant boundaries"]

ACTOR_ENUM = {
    "remote_unauth",
    "remote_auth",
    "adjacent_network",
    "local_user",
    "local_admin",
    "supply_chain",
    "insider",
}
IMPACT_ENUM = {"low", "medium", "high", "critical", "existential"}
LIKELIHOOD_ENUM = {"very_rare", "rare", "possible", "likely", "almost_certain"}
STATUS_ENUM = {"unmitigated", "partially_mitigated", "mitigated", "risk_accepted"}
SENSITIVITY_ENUM = {"low", "medium", "high", "critical"}
CLOSES_CLASS_ENUM = {"yes", "partial", "no"}
EFFORT_ENUM = {"XS", "S", "M", "L"}
MODE_ENUM = {"interview", "bootstrap", "bootstrap-then-interview"}

IMPACT_ORDER = ["existential", "critical", "high", "medium", "low"]
LIKELIHOOD_ORDER = ["almost_certain", "likely", "possible", "rare", "very_rare"]

THREATS_COLUMNS = [
    "id",
    "threat",
    "actor",
    "surface",
    "asset",
    "impact",
    "likelihood",
    "status",
    "controls",
    "evidence",
]
# Trailing column: MITRE ATT&CK technique IDs, validated against the
# pinned table in skills/attack-coverage/. DEFAULT for new emissions
# since ATTACK_REFS_SINCE (enforced via section-7 provenance
# harness_version); ten-column legacy models stay valid.
THREATS_COLUMNS_ATTACK = [*THREATS_COLUMNS, "attack_refs"]
ATTACK_REFS_SINCE = (0, 82, 0)
# Trailing OPTIONAL column after attack_refs (PEACH isolation lens Phase 1,
# comma-separated subset of the five isolation-hardening
# dimension keys (shared vocabulary with contracts/schemas/isolation-review.schema.json)
# tagging which dimension a threat stresses. Multi-tenant services only;
# never required — 10- and 11-column tables stay valid.
THREATS_COLUMNS_ISOLATION = [*THREATS_COLUMNS_ATTACK, "isolation_dimensions"]
THREATS_COLUMN_VARIANTS = (THREATS_COLUMNS, THREATS_COLUMNS_ATTACK, THREATS_COLUMNS_ISOLATION)

# Section 10 "Tenant boundaries" (optional; multi-tenant services only).
# Vocabulary is shared with the isolation-review skill: interface kind,
# exposure, complexity, and the five dimension results reuse the enums of
# contracts/schemas/isolation-review.schema.json so boundary rows and full isolation
# reviews line up. PEACH is cited by name/URL only — never adapted text.
BOUNDARY_COLUMNS = [
    "boundary_id",
    "interface",
    "kind",
    "exposure",
    "complexity",
    "privilege",
    "encryption",
    "authentication",
    "connectivity",
    "hygiene",
    "threat_ids",
    "isolation_review_ref",
]
ISOLATION_DIMENSIONS = ["privilege", "encryption", "authentication", "connectivity", "hygiene"]
BOUNDARY_KIND_ENUM = {"api", "data-store", "queue", "ingress", "webhook", "cli", "other"}
BOUNDARY_EXPOSURE_ENUM = {"public", "tenant", "partner", "internal"}
BOUNDARY_COMPLEXITY_ENUM = {"low", "medium", "high"}
DIMENSION_RESULT_ENUM = {"yes", "partial", "no", "na"}
BOUNDARY_ID = re.compile(r"^IF-\d+$")
# empty cell valid; otherwise an analysis-results/isolation/<service-slug>/
# directory (optionally a file inside it)
ISOLATION_REVIEW_REF = re.compile(
    r"^analysis-results/isolation/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]*)*$"
)
ASSETS_COLUMNS = ["asset", "description", "sensitivity"]
ASSETS_OPTIONAL_COLUMNS = ["regulatory_scope", "example_records"]
ENTRY_COLUMNS = ["entry_point", "description", "trust_boundary", "reachable_assets"]
DEPRI_COLUMNS = ["threat", "reason"]
MITIG_COLUMNS = ["mitigation", "threat_ids", "closes_class", "effort"]
UPDATE_HISTORY_COLUMNS = ["date", "changes", "reason"]

# Evidence cells hold references that *instantiate* a threat: CVEs, GHSAs,
# commit hashes, audit finding IDs (FIND-NNN or canonical
# {REPO_SLUG}-{SHORTSHA}-{NNN} as used by the disposition ledger), issue
# URLs, or pentest finding IDs (uppercase code + number).
EVIDENCE_OK = [
    re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    re.compile(r"^GHSA(-[a-z0-9]{4}){3}$", re.IGNORECASE),
    re.compile(r"^[0-9a-f]{7,40}$"),  # commit hash
    re.compile(r"^FIND-\d{3,}$"),  # audit finding id
    re.compile(r"^[A-Z0-9_.]+-[0-9a-f]{7,12}-\d{3}$"),  # canonical ledger id
    re.compile(r"^-\d{3}$"),  # continuation shorthand after a canonical id
    re.compile(r"^https?://\S+$"),  # issue link
    re.compile(r"^[A-Z]{2,}[A-Z0-9]*-\d+$"),  # tracker/pentest id
]


_ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _validate_attack_refs(ids):
    """Validate technique IDs against the pinned ATT&CK table (shared
    attack-coverage module). Falls back to shape-only validation with a
    warning-style message if the table is unavailable (e.g. the linter is
    copied out of the harness tree)."""
    try:
        import attack_refs as _ar

        return _ar.validate_ids(ids)
    except Exception:
        return [
            f"'{t}' is not a well-formed technique ID (pinned table unavailable; shape check only)"
            for t in ids
            if not _ATTACK_ID.match(t)
        ]


def evidence_token_ok(token):
    """True if a single evidence token is a recognized vuln reference.

    Tolerates the prose forms real artifacts use: a "commit "/"commits "
    prefix and a trailing parenthetical annotation ("(exploited in the
    wild)").
    """
    token = re.sub(r"\s*\([^)]*\)\s*$", "", token.strip())
    token = re.sub(r"^commits?\s+", "", token, flags=re.IGNORECASE)
    return any(p.match(token) for p in EVIDENCE_OK)


# file:line citations do not belong in evidence (litmus-test guard).
FILE_LINE = re.compile(r"[\w./-]+\.[A-Za-z]{1,5}:\d+")

THREAT_ID = re.compile(r"^T\d+$")
SCENARIO_HEADING = re.compile(r"^### (T\d+)\b")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_sections(text):
    """Return ordered list of (heading_text, body_lines)."""
    sections = []
    current = None
    for line in text.splitlines():
        m = re.match(r"^## (.+?)\s*$", line)
        if m:
            current = (m.group(1), [])
            sections.append(current)
        elif current is not None:
            current[1].append(line)
    return sections


def split_row(stripped):
    """Split a table row on unescaped pipes only (GFM: `\\|` is a literal)."""
    cells = re.split(r"(?<!\\)\|", stripped)
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return [c.strip() for c in cells]


def parse_table(body_lines):
    """Parse the first markdown table in a section body.

    Returns (columns, rows) where each row is a list of cell strings, or
    (None, []) if no table found.
    """
    columns, rows = None, []
    for line in body_lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if columns is not None and stripped == "":
                break
            continue
        cells = split_row(stripped)
        if columns is None:
            columns = cells
        elif set(stripped) <= {"|", "-", " ", ":"}:
            continue  # separator row
        else:
            rows.append(cells)
    return columns, rows


def parse_provenance(body_lines):
    """Parse `- key: value` bullets from the provenance section."""
    fields = {}
    for line in body_lines:
        m = re.match(r"^\s*-\s*([a-z_ ]+?)\s*:\s*(.*)$", line)
        if m:
            fields[m.group(1).strip()] = m.group(2).strip()
    return fields


def lint_file(path, strict=False):
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8")

    if not re.match(r"^# Threat Model:\s*\S", text.splitlines()[0] if text else ""):
        errors.append("first line must be '# Threat Model: <system name>'")

    sections = parse_sections(text)
    headings = [h for h, _ in sections]

    # -- Section presence and order -------------------------------------
    numbered = [h for h in headings if re.match(r"^\d+\.", h)]
    for i, want in enumerate(REQUIRED_SECTIONS):
        if want not in headings:
            errors.append(f"missing required section '## {want}'")
        elif numbered and want in numbered and numbered.index(want) != i:
            errors.append(f"section '## {want}' out of order")
    for h in numbered:
        if h not in REQUIRED_SECTIONS and h not in OPTIONAL_SECTIONS:
            warnings.append(f"unrecognized numbered section '## {h}'")

    def body(name):
        for h, b in sections:
            if h == name:
                return b
        return None

    # -- Section 2: Assets ----------------------------------------------
    asset_names = []
    b = body("2. Assets")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 2 has no assets table")
        else:
            if cols[:3] != ASSETS_COLUMNS:
                errors.append(f"section 2 columns must start with {ASSETS_COLUMNS}, got {cols[:3]}")
            for extra in cols[3:]:
                if extra not in ASSETS_OPTIONAL_COLUMNS:
                    warnings.append(f"section 2 unexpected column '{extra}'")
            for r in rows:
                if len(r) < 3:
                    errors.append(f"section 2 row too short: {r}")
                    continue
                asset_names.append(r[0])
                if r[2] not in SENSITIVITY_ENUM:
                    errors.append(
                        f"section 2 asset '{r[0]}': sensitivity '{r[2]}' not in {sorted(SENSITIVITY_ENUM)}"
                    )

    # -- Section 3: Entry points -----------------------------------------
    entry_points = []
    b = body("3. Entry points & trust boundaries")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 3 has no entry-points table")
        elif cols != ENTRY_COLUMNS:
            errors.append(f"section 3 columns must be {ENTRY_COLUMNS}, got {cols}")
        for r in rows:
            if r and r[0]:
                entry_points.append(r[0])

    # -- Section 4: Threats -----------------------------------------------
    threat_ids, surface_cells, threat_rows = [], [], []
    threat_cols_seen = None
    b = body("4. Threats")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 4 has no threats table")
        elif cols not in THREATS_COLUMN_VARIANTS:
            errors.append(
                f"section 4 columns must be {THREATS_COLUMNS} "
                f"(optionally + ['attack_refs'], optionally then "
                f"+ ['isolation_dimensions']), got {cols}"
            )
        else:
            threat_cols = threat_cols_seen = cols
            for r in rows:
                if len(r) != len(threat_cols):
                    errors.append(
                        f"section 4 row has {len(r)} cells, expected {len(threat_cols)}: {r[:2]}"
                    )
                    continue
                row = dict(zip(threat_cols, r, strict=False))
                threat_rows.append(row)
                tid = row["id"]
                if not THREAT_ID.match(tid):
                    errors.append(f"section 4 id '{tid}' must match T<number>")
                elif tid in threat_ids:
                    errors.append(f"section 4 duplicate id '{tid}'")
                threat_ids.append(tid)
                surface_cells.append(row["surface"])
                # actor may be a comma-separated list of enum values
                for a in re.split(r",\s*", row["actor"]):
                    if a not in ACTOR_ENUM:
                        errors.append(f"section 4 {tid}: actor '{a}' not in {sorted(ACTOR_ENUM)}")
                for field, enum in (
                    ("impact", IMPACT_ENUM),
                    ("likelihood", LIKELIHOOD_ENUM),
                    ("status", STATUS_ENUM),
                ):
                    if row[field] not in enum:
                        errors.append(
                            f"section 4 {tid}: {field} '{row[field]}' not in {sorted(enum)}"
                        )
                # evidence hygiene
                ev = row["evidence"].strip()
                if ev:
                    if FILE_LINE.search(ev):
                        errors.append(
                            f"section 4 {tid}: evidence contains a file:line citation "
                            f"('{ev}') — evidence holds vuln references (CVE/GHSA/commit/"
                            f"finding ID), never code locations; siblings go in the hand-back"
                        )
                    else:
                        for token in re.split(r"[,;]\s*", ev):
                            token = token.strip()
                            if token and not evidence_token_ok(token):
                                warnings.append(
                                    f"section 4 {tid}: evidence token '{token}' is not a recognized vuln reference"
                                )
                # attack_refs: bounded selection from the pinned ATT&CK table
                ar = (row.get("attack_refs") or "").strip()
                if ar:
                    ids = [t.strip() for t in re.split(r"[,;]\s*", ar) if t.strip()]
                    for msg in _validate_attack_refs(ids):
                        errors.append(f"section 4 {tid}: attack_refs {msg}")
                    if len(ids) > 4:
                        warnings.append(
                            f"section 4 {tid}: {len(ids)} attack_refs — a row needing >4 techniques is usually too broad; consider splitting"
                        )
                # isolation_dimensions: optional subset of the five
                # isolation-hardening dimension keys (empty cell valid)
                iso = (row.get("isolation_dimensions") or "").strip()
                if iso:
                    for d in [t.strip() for t in re.split(r"[,;]\s*", iso) if t.strip()]:
                        if d not in ISOLATION_DIMENSIONS:
                            errors.append(
                                f"section 4 {tid}: isolation_dimensions "
                                f"'{d}' not in {ISOLATION_DIMENSIONS}"
                            )
            # sort order (warning: legacy models predate strict ordering)
            keys = [
                (IMPACT_ORDER.index(r["impact"]), LIKELIHOOD_ORDER.index(r["likelihood"]))
                for r in threat_rows
                if r["impact"] in IMPACT_ENUM and r["likelihood"] in LIKELIHOOD_ENUM
            ]
            if keys != sorted(keys):
                warnings.append("section 4 rows are not sorted by (impact desc, likelihood desc)")

    # -- Section 5: Deprioritized ------------------------------------------
    depri_text = ""
    b = body("5. Deprioritized")
    if b is not None:
        depri_text = "\n".join(b)
        cols, rows = parse_table(b)
        if cols is not None and cols != DEPRI_COLUMNS:
            errors.append(f"section 5 columns must be {DEPRI_COLUMNS}, got {cols}")

    # -- Coverage invariant --------------------------------------------------
    surfaces_joined = " ".join(surface_cells).lower()
    for ep in entry_points:
        if ep.lower() in surfaces_joined:
            continue
        if ep.lower() in depri_text.lower():
            continue
        errors.append(
            f"coverage: entry point '{ep}' has no section 4 threat naming it in "
            f"'surface' and no section 5 row parking it"
        )

    # -- Section 7: Provenance -----------------------------------------------
    b = body("7. Provenance")
    if b is not None:
        prov = parse_provenance(b)
        for key in ("mode", "date", "target", "inputs", "owner"):
            if key not in prov:
                errors.append(f"section 7 missing '{key}'")
        mode = prov.get("mode", "")
        if mode and mode not in MODE_ENUM:
            errors.append(f"section 7 mode '{mode}' not in {sorted(MODE_ENUM)}")
        if prov.get("date") and not DATE_RE.match(prov["date"]):
            errors.append(f"section 7 date '{prov['date']}' must be YYYY-MM-DD")
        if "harness_version" not in prov:
            warnings.append(
                "section 7 missing 'harness_version' (required for new emissions; "
                "legacy artifacts predate it)"
            )
        # attack_refs column is default schema for emissions >= 0.82.0
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", prov.get("harness_version") or "")
        if (
            m
            and tuple(int(g) for g in m.groups()) >= ATTACK_REFS_SINCE
            and threat_cols_seen == THREATS_COLUMNS
        ):
            errors.append(
                "section 4 is missing the attack_refs column — default schema "
                f"for emissions at harness >= "
                f"{'.'.join(map(str, ATTACK_REFS_SINCE))} (this model's "
                f"provenance says {prov['harness_version']}); legacy models "
                "are exempt, new emissions are not"
            )
        # optional update history
        cols, rows = parse_table(b)
        if cols is not None:
            if cols != UPDATE_HISTORY_COLUMNS:
                errors.append(
                    f"section 7 update-history columns must be {UPDATE_HISTORY_COLUMNS}, got {cols}"
                )
            for r in rows:
                if r and r[0] and not DATE_RE.match(r[0]):
                    errors.append(f"section 7 update-history date '{r[0]}' must be YYYY-MM-DD")

    # -- Section 8: Recommended mitigations (optional) -------------------------
    b = body("8. Recommended mitigations")
    if b is None:
        if strict:
            warnings.append(
                "section 8 (Recommended mitigations) absent — recommended for new emissions"
            )
    else:
        cols, rows = parse_table(b)
        if cols is not None:
            if cols != MITIG_COLUMNS:
                errors.append(f"section 8 columns must be {MITIG_COLUMNS}, got {cols}")
            else:
                for r in rows:
                    if len(r) != 4:
                        errors.append(f"section 8 row too short: {r}")
                        continue
                    for tid in re.split(r"[,;]\s*", r[1]):
                        tid = tid.strip()
                        if tid and tid not in threat_ids:
                            errors.append(
                                f"section 8 mitigation '{r[0]}' references unknown threat id '{tid}'"
                            )
                    if r[2] not in CLOSES_CLASS_ENUM:
                        errors.append(
                            f"section 8 '{r[0]}': closes_class '{r[2]}' not in {sorted(CLOSES_CLASS_ENUM)}"
                        )
                    if r[3] not in EFFORT_ENUM:
                        errors.append(
                            f"section 8 '{r[0]}': effort '{r[3]}' not in {sorted(EFFORT_ENUM)}"
                        )

    # -- Section 9: Attack scenarios (optional) ---------------------------------
    b = body("9. Attack scenarios")
    if b is not None:
        scenario_ids = []
        for line in b:
            m = SCENARIO_HEADING.match(line)
            if m:
                scenario_ids.append(m.group(1))
            elif line.startswith("### "):
                errors.append(f"section 9 heading '{line.strip()}' must start '### T<n>'")
        if not scenario_ids:
            errors.append("section 9 present but has no '### T<n>' scenario subsections")
        for sid in scenario_ids:
            if sid not in threat_ids:
                errors.append(f"section 9 scenario '{sid}' references unknown threat id")
        if len(scenario_ids) > 8:
            warnings.append(
                f"section 9 has {len(scenario_ids)} scenarios — keep to the top 3-5 threats"
            )

    # -- Section 10: Tenant boundaries (optional; multi-tenant only) ------------
    b = body("10. Tenant boundaries")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 10 present but has no tenant-boundaries table")
        elif cols != BOUNDARY_COLUMNS:
            errors.append(f"section 10 columns must be {BOUNDARY_COLUMNS}, got {cols}")
        else:
            boundary_ids = []
            for r in rows:
                if len(r) != len(BOUNDARY_COLUMNS):
                    errors.append(
                        f"section 10 row has {len(r)} cells, "
                        f"expected {len(BOUNDARY_COLUMNS)}: {r[:2]}"
                    )
                    continue
                row = dict(zip(BOUNDARY_COLUMNS, r, strict=False))
                bid = row["boundary_id"]
                if not BOUNDARY_ID.match(bid):
                    errors.append(f"section 10 boundary_id '{bid}' must match IF-<number>")
                elif bid in boundary_ids:
                    errors.append(f"section 10 duplicate boundary_id '{bid}'")
                boundary_ids.append(bid)
                for field, enum in (
                    ("kind", BOUNDARY_KIND_ENUM),
                    ("exposure", BOUNDARY_EXPOSURE_ENUM),
                    ("complexity", BOUNDARY_COMPLEXITY_ENUM),
                ):
                    if row[field] not in enum:
                        errors.append(
                            f"section 10 {bid}: {field} '{row[field]}' not in {sorted(enum)}"
                        )
                for dim in ISOLATION_DIMENSIONS:
                    if row[dim] not in DIMENSION_RESULT_ENUM:
                        errors.append(
                            f"section 10 {bid}: {dim} '{row[dim]}' "
                            f"not in {sorted(DIMENSION_RESULT_ENUM)}"
                        )
                for tid in re.split(r"[,;]\s*", row["threat_ids"]):
                    tid = tid.strip()
                    if tid and tid not in threat_ids:
                        errors.append(f"section 10 {bid}: references unknown threat id '{tid}'")
                ref = row["isolation_review_ref"].strip()
                if ref and not ISOLATION_REVIEW_REF.match(ref):
                    errors.append(
                        f"section 10 {bid}: isolation_review_ref '{ref}' must "
                        f"be empty or an analysis-results/isolation/"
                        f"<service-slug>/ path"
                    )

    return errors, warnings


def collect(paths):
    files = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            # Directory sweeps skip pipeline scratch under any artifacts/
            # component (per-worker THREAT_MODEL.md drafts are working
            # files, not portfolio artifacts). Explicit file paths are
            # always linted.
            found = sorted(
                set(list(p.rglob("THREAT_MODEL.md")) + list(p.rglob("*-threat-model.md")))
            )
            files.extend(f for f in found if "artifacts" not in f.relative_to(p).parts)
        else:
            files.append(p)
    return [f for f in files if not f.is_symlink()]
