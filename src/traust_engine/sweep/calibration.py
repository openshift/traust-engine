"""Rule-pack calibration library — corpus selection, scoring, and gate logic.

Answers whether a rule pack's rediscovery gate is reachable for a given
language/CWE slice, and scores pack findings against confirmed-TP ground
truth. This is the library API; the CLI wrapper lives in the harness.
"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

CWE_SETS = {
    "crypto": {
        "CWE-295",
        "CWE-321",
        "CWE-322",
        "CWE-323",
        "CWE-325",
        "CWE-326",
        "CWE-327",
        "CWE-328",
        "CWE-329",
        "CWE-330",
        "CWE-331",
        "CWE-338",
        "CWE-347",
        "CWE-759",
        "CWE-760",
        "CWE-780",
        "CWE-916",
        "CWE-1240",
    },
}

PACK_LANGS = {
    "c",
    "cpp",
    "c++",
    "csharp",
    "c#",
    "go",
    "java",
    "javascript",
    "python",
    "rust",
    "typescript",
}

REDISCOVERY_GATE = 3

_SHA_RX = re.compile(r"^[0-9a-f]{7,40}$")
_CWE_RX = re.compile(r"CWE-\d+")

CACHE_ROOT = Path.home() / ".cache" / "traust" / "calibrate"
_RULES_CACHE_ROOT = CACHE_ROOT.parent


# ---------------------------------------------------------------------------
# corpus selection
# ---------------------------------------------------------------------------


def load_corpus(path: Path | str) -> list[dict]:
    """Load a TP corpus JSONL file. Returns [] if missing or empty."""
    p = Path(path)
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _cwes(row: dict) -> set:
    got = set(row.get("cwes") or [])
    if row.get("cwe"):
        got.add(row["cwe"])
    return got


def pack_cwes(rules_src: str) -> set:
    """CWEs the pack actually has rules for, read from its cached clone.

    Empty set when the pack is not cached or is not a git source."""
    ref = rules_src.rsplit("@", 1)[-1] if "@" in rules_src else ""
    url = rules_src.rsplit("@", 1)[0] if "@" in rules_src else rules_src
    if not ref:
        return set()
    dest = _RULES_CACHE_ROOT / f"{Path(url).name}-{ref[:12]}"
    if not dest.is_dir():
        return set()
    found = set()
    for path in list(dest.rglob("*.yaml")) + list(dest.rglob("*.yml")):
        if "/tests/" in str(path):
            continue
        try:
            found.update(_CWE_RX.findall(path.read_text(errors="ignore")))
        except OSError:
            continue
    return found


def gate_reachability(targets: dict, covered: set | None = None) -> tuple[int, str | None]:
    """-> (max repos sharing one CWE, the CWE) for the selected targets.

    A rule clears the rediscovery gate only by firing in >=3 repos that
    each contain a confirmed TP it could plausibly match."""
    per_cwe: dict = collections.defaultdict(set)
    for (repo, _), meta in targets.items():
        for cwe in meta.get("cwes") or ():
            if covered and cwe not in covered:
                continue
            per_cwe[cwe].add(repo)
    if not per_cwe:
        return 0, None
    cwe, repos = max(per_cwe.items(), key=lambda kv: len(kv[1]))
    return len(repos), cwe


def select_targets(corpus: list[dict], cwe_set: str | None, langs: set | None = None) -> dict:
    """-> {(repo, commit): {locations, cwes, count}}."""
    wanted = CWE_SETS.get(cwe_set or "")
    langs = PACK_LANGS if langs is None else langs
    grouped: dict = collections.defaultdict(
        lambda: {"locations": set(), "cwes": set(), "count": 0, "titles": []}
    )
    for r in corpus:
        if wanted and not (_cwes(r) & wanted):
            continue
        if langs and str(r.get("language", "")).lower() not in langs:
            continue
        repo, commit = r.get("repo"), r.get("commit")
        locs = [loc for loc in (r.get("locations") or []) if loc]
        if not (repo and commit and locs and _SHA_RX.match(str(commit))):
            continue
        g = grouped[(repo, commit)]
        g["locations"].update(locs)
        g["cwes"].update(_cwes(r))
        g["count"] += 1
        if r.get("title"):
            g["titles"].append(r["title"])
    return dict(grouped)


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def _norm_path(p) -> str:
    s = str(p).strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def classify(findings: list[dict], tp_locations: set) -> dict:
    """Split a repo's findings into rediscoveries vs novel, path-level."""
    tp_norm = {_norm_path(p) for p in tp_locations}
    redis, novel = [], []
    for f in findings:
        (redis if _norm_path(f["path"]) in tp_norm else novel).append(f)
    return {"rediscovery": redis, "novel": novel}


def aggregate(per_repo: list[dict]) -> dict:
    """Roll per-repo results into the per-rule gate view."""
    rules: dict = collections.defaultdict(
        lambda: {
            "fires": 0,
            "rediscoveries": 0,
            "novel": 0,
            "repos_fired": set(),
            "repos_rediscovered": set(),
        }
    )
    tot = {"repos": 0, "scanned": 0, "findings": 0, "rediscovery": 0, "novel": 0, "tp_files": 0}
    for r in per_repo:
        tot["repos"] += 1
        if not r.get("scanned"):
            continue
        tot["scanned"] += 1
        tot["tp_files"] += len(r.get("tp_locations") or [])
        for kind in ("rediscovery", "novel"):
            for f in r.get(kind) or []:
                e = rules[f["rule_id"]]
                e["fires"] += 1
                e["repos_fired"].add(r["repo"])
                tot["findings"] += 1
                tot[kind] += 1
                if kind == "rediscovery":
                    e["rediscoveries"] += 1
                    e["repos_rediscovered"].add(r["repo"])
                else:
                    e["novel"] += 1
    out_rules = {}
    for rid, e in rules.items():
        out_rules[rid] = {
            "fires": e["fires"],
            "rediscoveries": e["rediscoveries"],
            "novel": e["novel"],
            "repos_fired": len(e["repos_fired"]),
            "repos_rediscovered": len(e["repos_rediscovered"]),
            "clears_rediscovery_gate": len(e["repos_rediscovered"]) >= REDISCOVERY_GATE,
        }
    return {"totals": tot, "rules": out_rules}


def novel_sample(per_repo: list[dict], n: int = 40) -> list[dict]:
    """A bounded, deterministic slice of novel hits for manual review."""
    rows = []
    for r in sorted(per_repo, key=lambda x: x.get("repo") or ""):
        for f in sorted(r.get("novel") or [], key=lambda x: (x["rule_id"], x["path"])):
            rows.append(
                {
                    "repo": r["repo"],
                    "commit": r.get("commit"),
                    "rule_id": f["rule_id"],
                    "path": f["path"],
                }
            )
    step = max(1, len(rows) // n) if rows else 1
    return rows[::step][:n]


def render(res: dict, rules_src: str, sample: list[dict]) -> str:
    t = res["totals"]
    L = [
        f"# Rule-pack calibration — {rules_src}",
        "",
        "_Stage A: rediscovery and volume against campaign ground truth — "
        "the pre-flight read, before the pack has ever run in an audit. "
        "**Precision is deliberately not computed here**: it accrues "
        "automatically once the pack runs, via the `scanner_correlation` "
        "promoted/dismissed entries every audit records, tallied by "
        "rule calibration against the ~50% gate. No human review required — "
        "the novel sample below is an optional early read, not the "
        "required path._",
        "",
        "_Matching is **path-level**: a rediscovery means the rule fired in "
        "a file where a confirmed TP lives, not that it found that specific "
        "bug. This biases rediscovery counts upward — screening signal, not "
        "proof._",
        "",
        "## Volume",
        "",
        f"- repos targeted: **{t['repos']}** (scanned {t['scanned']})",
        f"- findings emitted: **{t['findings']}**",
        f"- of which rediscoveries: **{t['rediscovery']}** · novel: **{t['novel']}**",
        f"- confirmed-TP files in scope: {t['tp_files']}",
        "",
    ]
    if t["scanned"]:
        L.append(
            f"- **{t['findings'] / t['scanned']:.1f} findings per "
            f"repo** — the triage-cost number; compare against what "
            f"the default pack emits before promoting anything."
        )
        L.append("")
    passing = {k: v for k, v in res["rules"].items() if v["clears_rediscovery_gate"]}
    L += [
        f"## Gate: rules with >= {REDISCOVERY_GATE} repos rediscovered",
        "",
        f"**{len(passing)} of {len(res['rules'])} firing rules clear the "
        f"rediscovery bar.** Clearing it is necessary, not sufficient — "
        f"the precision half of the gate still needs adjudication.",
        "",
        "| Rule | Repos rediscovered | Rediscoveries | Novel | Fires |",
        "|---|---:|---:|---:|---:|",
    ]
    for rid, v in sorted(
        res["rules"].items(), key=lambda kv: (-kv[1]["repos_rediscovered"], -kv[1]["fires"])
    )[:30]:
        mark = "**" if v["clears_rediscovery_gate"] else ""
        L.append(
            f"| {mark}{rid}{mark} | {v['repos_rediscovered']} | "
            f"{v['rediscoveries']} | {v['novel']} | {v['fires']} |"
        )
    L += [
        "",
        "## Novel-hit sample (optional early precision read)",
        "",
        f"_{len(sample)} evenly-spaced novel hits. Spot-checking these "
        f"gives an early precision estimate before the pack has run in "
        f"any audit; once it has, `scanner_correlation` supersedes this "
        f"with campaign-wide judge decisions._",
        "",
        "| Rule | Repo | Path |",
        "|---|---|---|",
    ]
    for s in sample:
        L.append(f"| {s['rule_id']} | {s['repo'].rsplit('/', 1)[-1]} | `{s['path']}` |")
    return "\n".join(L) + "\n"
