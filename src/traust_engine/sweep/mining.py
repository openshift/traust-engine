"""Mine the disposition ledger for confirmed true positives (rule mining).

Feeds the traust-authored opengrep rule pack from the campaign's own ground truth.
Three deterministic passes over a findings tree:

1. TP corpus — every finding in a cumulative `*-findings-current.json`
   whose ledger disposition is `validity: confirmed` becomes one JSONL
   record (repo, finding id, primary CWE, category, severity, language
   guess, locations, title, evidence snippet). This is the specification
   material future rules are written against.

2. Pack coverage — the corpus is clustered by (primary CWE, language) and
   matched against the rule pack's `metadata.cwe` + `languages`. Uncovered
   clusters, ranked by confirmed-TP count, are the rule-authoring backlog.
   A per-language rollup (confirmed TPs, covered/uncovered clusters,
   pack rule count per language directory) makes tranche priorities
   data-driven each cycle.

3. Per-rule precision — audits that ran the opengrep pre-scan record each
   judge decision as a structured `scanner_correlation` entry
   (tool `opengrep`, `rule_id`, `result: promoted|dismissed` — see the
   /secure-code-audit SKILL). Tallying those across all
   `*-security-audit.json` reports yields campaign-wide precision per rule;
   rules below the plan's ~50% gate are flagged for tightening.

Also emits a calibration worklist: repos whose confirmed TPs fall in
covered clusters, with the rule ids expected to rediscover them — the
re-scan set for validating pack changes.

This is a CANDIDATE GENERATOR for rule authoring, never a verdict of
record (docs/deterministic-inferential-mix.md). Everything it
emits is re-derived on each run; nothing is stateful.

Usage:
    python3 mine_ledger_truepositives.py --root <findings-tree>
        [--pack <rules-dir>] [--out <dir>]

Outputs (in --out, default ./rule-mining):
    tp-corpus.jsonl        one confirmed TP per line
    rule-mining.json       clusters, coverage, precision, worklist
    rule-mining.md         human summary

Exit 0 on success (even with an empty corpus — stated in the summary).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def _default_pack() -> Path:
    from traust_engine import locations as locs
    from traust_engine.adapters.opengrep import resolve_rule_pack_dir

    return resolve_rule_pack_dir(loc=locs.configured_locations())


EXT_LANG = {
    ".go": "go",
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".rs": "rust",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".php": "php",
    # C++ and C# were absent until 2026-08-06; 11 corpus rows naming only
    # .cc/.cxx/.hpp/.cs files resolved to "unknown" and dropped out of
    # RULEABLE_LANGS, which read as "the portfolio has no C++/C# findings".
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
}
# Config extensions lose to source when a finding names both. Ranked
# separately rather than dropped: a finding that touches only manifests
# is legitimately a yaml finding.
CONFIG_EXTS = {".yaml", ".yml"}
# languages the pack could plausibly cover with taint rules; manifests and
# lockfiles cluster under config tooling instead
RULEABLE_LANGS = {
    "go",
    "python",
    "typescript",
    "javascript",
    "java",
    "ruby",
    "c",
    "cpp",
    "csharp",
    "rust",
    "bash",
    "php",
}
# corpus language -> rule-pack subdirectory (opengrep-rules/<dir>/*.yaml);
# languages not listed map to a same-named directory
PACK_DIR_FOR_LANG = {"javascript": "typescript"}


def guess_language(locations: list[dict]) -> str:
    """Dominant source language across a finding's locations.

    First-match-wins was the original rule, and it made the label depend
    on which file the report happened to list first. Measured on the
    2026-07-29 corpus: 146 rows naming an `app-config.yaml` ahead of
    their `.ts`/`.tsx` sources were labelled `yaml`, and because `yaml`
    is not in RULEABLE_LANGS those TPs were silently excluded from the
    mining worklist. Source outranks config, and the most frequent
    source language wins so one incidental file cannot flip the label.
    """
    source: list[str] = []
    config: list[str] = []
    for loc in locations or []:
        path = loc.get("path", "") if isinstance(loc, dict) else loc
        ext = Path(str(path)).suffix.lower()
        lang = EXT_LANG.get(ext)
        if lang is None:
            continue
        (config if ext in CONFIG_EXTS else source).append(lang)
    for tier in (source, config):
        if tier:
            # Ties break toward the earliest occurrence so the result is
            # stable regardless of how the report ordered its locations.
            return max(tier, key=lambda lang: (tier.count(lang), -tier.index(lang)))
    return "unknown"


def load_pack_rules(pack: Path) -> list[dict]:
    """[{id, languages, cwes}] from every rules yaml in the pack."""
    rules = []
    if yaml is None or not pack.is_dir():
        return rules
    for path in sorted(pack.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        for r in (doc or {}).get("rules", []):
            cwes = (r.get("metadata") or {}).get("cwe") or []
            if isinstance(cwes, str):
                cwes = [cwes]
            rules.append(
                {
                    "id": r.get("id", "?"),
                    "languages": [str(lang).lower() for lang in r.get("languages", [])],
                    "cwes": [str(c).upper() for c in cwes],
                }
            )
    return rules


def pack_rule_count(pack: Path, language: str) -> int:
    """Rules in the pack's per-language directory, counted by `- id:` lines."""
    sub = pack / PACK_DIR_FOR_LANG.get(language, language)
    if not sub.is_dir():
        return 0
    n = 0
    for path in sorted(sub.glob("*.yaml")):
        try:
            text = path.read_text()
        except OSError:
            continue
        n += sum(1 for line in text.splitlines() if line.lstrip().startswith("- id:"))
    return n


def language_coverage(
    corpus: list[dict], covered: list[dict], uncovered: list[dict], pack: Path
) -> list[dict]:
    """Per-language rollup: TPs, cluster coverage, pack rule count —
    sorted by uncovered-TP count descending (the tranche-priority order)."""
    langs = sorted({tp["language"] for tp in corpus})
    rows = []
    for lang in langs:
        rows.append(
            {
                "language": lang,
                "confirmed_tps": sum(1 for tp in corpus if tp["language"] == lang),
                "covered_clusters": sum(1 for c in covered if c["language"] == lang),
                "uncovered_clusters": sum(1 for c in uncovered if c["language"] == lang),
                "uncovered_tps": sum(c["count"] for c in uncovered if c["language"] == lang),
                "pack_rules": pack_rule_count(pack, lang),
            }
        )
    return sorted(rows, key=lambda r: (-r["uncovered_tps"], -r["confirmed_tps"], r["language"]))


def mine_corpus(root: Path) -> list[dict]:
    corpus = []
    for path in sorted(root.rglob("*-findings-current.json")):
        if path.is_symlink():
            continue
        try:
            report = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        meta = report.get("metadata", {})
        repo = meta.get("repository") or path.parent.name
        commit = meta.get("commit")
        for f in report.get("findings", []):
            disp = f.get("disposition") or {}
            if disp.get("validity") != "confirmed":
                continue
            cwes = [str(c).upper() for c in f.get("cwes", [])]
            evidence = ""
            ev = f.get("evidence")
            if isinstance(ev, list) and ev:
                evidence = str(ev[0].get("code", ""))[:400]
            corpus.append(
                {
                    "repo": repo,
                    "commit": commit,
                    "report": str(path.relative_to(root)),
                    "finding_id": f.get("id", "?"),
                    "cwe": cwes[0] if cwes else "CWE-?",
                    "cwes": cwes,
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "language": guess_language(f.get("locations")),
                    "resolution": disp.get("resolution"),
                    "locations": [str(loc.get("path", "")) for loc in f.get("locations", [])][:5],
                    "title": str(f.get("title", ""))[:160],
                    "evidence": evidence,
                }
            )
    return corpus


def cluster_and_cover(corpus: list[dict], rules: list[dict]) -> tuple[list[dict], list[dict]]:
    clusters: dict[tuple[str, str], dict] = {}
    for tp in corpus:
        key = (tp["cwe"], tp["language"])
        c = clusters.setdefault(
            key,
            {
                "cwe": tp["cwe"],
                "language": tp["language"],
                "count": 0,
                "repos": set(),
                "example_findings": [],
            },
        )
        c["count"] += 1
        c["repos"].add(tp["repo"])
        if len(c["example_findings"]) < 5:
            c["example_findings"].append(tp["finding_id"])
    covered, uncovered = [], []
    for c in sorted(clusters.values(), key=lambda x: -x["count"]):
        c["repos"] = len(c["repos"])
        matching = [
            r["id"] for r in rules if c["cwe"] in r["cwes"] and c["language"] in r["languages"]
        ]
        c["covered_by"] = matching
        if matching:
            covered.append(c)
        elif c["language"] in RULEABLE_LANGS:
            uncovered.append(c)
    return covered, uncovered


def mine_precision(root: Path) -> dict[str, dict]:
    tally: dict[str, dict] = defaultdict(lambda: {"promoted": 0, "dismissed": 0, "other": 0})
    for path in sorted(root.rglob("*-security-audit.json")):
        if path.is_symlink():
            continue
        try:
            report = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for e in report.get("scanner_correlation", []) or []:
            if e.get("tool") != "opengrep" or not e.get("rule_id"):
                continue
            result = str(e.get("result", "")).strip().lower()
            bucket = result if result in ("promoted", "dismissed") else "other"
            tally[e["rule_id"]][bucket] += 1
    out = {}
    for rule_id, t in sorted(tally.items()):
        judged = t["promoted"] + t["dismissed"]
        out[rule_id] = {**t, "precision": round(t["promoted"] / judged, 3) if judged else None}
    return out


def build_worklist(corpus: list[dict], covered: list[dict]) -> list[dict]:
    covered_keys = {(c["cwe"], c["language"]): c["covered_by"] for c in covered}
    by_repo: dict[str, dict] = {}
    for tp in corpus:
        rules = covered_keys.get((tp["cwe"], tp["language"]))
        if not rules:
            continue
        w = by_repo.setdefault(
            tp["repo"],
            {
                "repo": tp["repo"],
                "commit": tp["commit"],
                "expected_rules": set(),
                "finding_ids": [],
            },
        )
        w["expected_rules"].update(rules)
        w["finding_ids"].append(tp["finding_id"])
    worklist = []
    for w in by_repo.values():
        w["expected_rules"] = sorted(w["expected_rules"])
        worklist.append(w)
    return sorted(worklist, key=lambda x: -len(x["finding_ids"]))


def render_md(result: dict) -> str:
    s = result["stats"]
    lines = [
        "# Ledger Rule-Mining Report",
        "",
        f"Generated from `{result['root']}` — "
        f"{s['cumulative_reports']} cumulative reports scanned, "
        f"**{s['confirmed_tps']} confirmed true positives** "
        f"({s['ruleable_tps']} in rule-able languages).",
        "",
        "## Uncovered clusters (rule-authoring backlog)",
        "",
        "| CWE | Language | TPs | Repos | Example findings |",
        "|---|---|---|---|---|",
    ]
    for c in result["uncovered_clusters"][:25]:
        lines.append(
            f"| {c['cwe']} | {c['language']} | {c['count']} | "
            f"{c['repos']} | {', '.join(c['example_findings'][:3])} |"
        )
    if not result["uncovered_clusters"]:
        lines.append("| — | — | — | — | all rule-able clusters covered |")
    lines += [
        "",
        "## Per-language coverage",
        "",
        "| Language | Confirmed TPs | Covered clusters | "
        "Uncovered clusters | Uncovered TPs | Pack rules |",
        "|---|---|---|---|---|---|",
    ]
    for lang in result["language_coverage"]:
        lines.append(
            f"| {lang['language']} | {lang['confirmed_tps']} | "
            f"{lang['covered_clusters']} | "
            f"{lang['uncovered_clusters']} | "
            f"{lang['uncovered_tps']} | {lang['pack_rules']} |"
        )
    if not result["language_coverage"]:
        lines.append("| — | — | — | — | — | empty corpus |")
    lines += [
        "",
        "## Covered clusters",
        "",
        "| CWE | Language | TPs | Covered by |",
        "|---|---|---|---|",
    ]
    for c in result["covered_clusters"]:
        lines.append(
            f"| {c['cwe']} | {c['language']} | {c['count']} | {', '.join(c['covered_by'])} |"
        )
    lines += ["", "## Per-rule precision (from audit judge decisions)", ""]
    if result["rule_precision"]:
        lines += ["| Rule | Promoted | Dismissed | Precision |", "|---|---|---|---|"]
        for rid, t in result["rule_precision"].items():
            prec = "n/a" if t["precision"] is None else f"{t['precision']:.0%}"
            lines.append(f"| {rid} | {t['promoted']} | {t['dismissed']} | {prec} |")
    else:
        lines.append(
            "No structured opengrep judge decisions found yet — "
            "audits emit them via scanner_correlation "
            "(see /secure-code-audit, Deterministic semantic "
            "pre-scan)."
        )
    lines += [
        "",
        f"Calibration worklist: {len(result['calibration_worklist'])} "
        "repo(s) with covered-cluster TPs (rule-mining.json).",
        "",
    ]
    return "\n".join(lines)


def mine(root: Path | str, out: Path | str, *, pack: Path | str | None = None) -> int:
    try:
        pack_path = Path(pack) if pack else _default_pack()
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    root = Path(root).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    corpus = mine_corpus(root)
    rules = load_pack_rules(pack_path)
    covered, uncovered = cluster_and_cover(corpus, rules)
    precision = mine_precision(root)
    worklist = build_worklist(corpus, covered)
    languages = language_coverage(corpus, covered, uncovered, pack_path)

    result = {
        "tool": "mine_ledger_truepositives",
        "root": str(root),
        "pack": str(pack_path),
        "pack_rules": len(rules),
        "stats": {
            "cumulative_reports": len(set(t["report"] for t in corpus))
            if corpus
            else sum(1 for _ in root.rglob("*-findings-current.json")),
            "confirmed_tps": len(corpus),
            "ruleable_tps": sum(1 for t in corpus if t["language"] in RULEABLE_LANGS),
        },
        "covered_clusters": covered,
        "uncovered_clusters": uncovered,
        "language_coverage": languages,
        "rule_precision": precision,
        "calibration_worklist": worklist,
    }

    (out / "tp-corpus.jsonl").write_text(
        "\n".join(json.dumps(t, ensure_ascii=False) for t in corpus) + "\n" if corpus else ""
    )
    (out / "rule-mining.json").write_text(json.dumps(result, indent=2))
    (out / "rule-mining.md").write_text(render_md(result))

    print(
        f"mine_ledger_truepositives: {result['stats']['confirmed_tps']} "
        f"confirmed TP(s); {len(uncovered)} uncovered cluster(s), "
        f"{len(covered)} covered; precision data for "
        f"{len(precision)} rule(s); worklist {len(worklist)} repo(s)"
    )
    print(f"  outputs: {out}/tp-corpus.jsonl, rule-mining.json, rule-mining.md")
    return 0
