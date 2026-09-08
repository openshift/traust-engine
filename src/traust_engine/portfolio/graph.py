"""Portfolio source-code graph builder.

Builds the layered code graph in SQLite. Implemented layers:

  L0 spine — ingests /repo-graph's repo-graph.json (segments, products,
             releases, categories, repos, ships/owns edges).
  L1 deps  — fetches each GitHub repo's go.mod at its default branch
             (cached by repo@sha under ~/.cache/traust-engine/
             portfolio-graph/), parses the module path + require blocks
             (with `// indirect` flags — complete for module-level deps on
             Go >= 1.17), and adds `module` nodes with `declares` and
             `depends_on` edges. Modules whose path maps to a portfolio
             repo are marked internal=1 — those edges are the cross-repo
             coupling that makes blast-radius queries possible.
  L1 refs  — OPT-IN per-release ref enrichment (branch-awareness Phase 3,
             Phase 3): `build --enrich-refs [N|branch,branch]` fetches
             go.mod AT each supported release branch for the spine's
             `repo-ref` nodes (Phase 2, repo-graph v0.124.0) and attaches
             `depends_on_ref` edges FROM the ref node, attributed
             ref=<branch>. Distinct rel by design — every `depends_on`
             consumer (q_blast_radius/q_top_shared/q_internal_coupling
             here, fleet-fix fleet_targets.py) filters rel='depends_on'
             with repo-node sources and would double-count or mis-key ref
             rows. The stage NEVER runs without the flag; default output
             stays byte-identical. Supported set: top-N `release-X.Y`
             branches by ships_ref edge count (bare --enrich-refs → N=3:
             ~the concurrently-supported OpenShift minor streams — newest
             GA + two maintenance — which is where the release-branch
             campaign found shipped exposure concentrates, while bounding
             fetch volume), or an explicit comma-separated branch list.
             Missing branch / missing go.mod at ref = counted skip, never
             a failure.

Layers 2-4 are planned (see the plan doc) and NOT built here yet.

The database is a rebuildable local artifact; committed outputs are the
stats markdown + summary JSON this script writes next to it. Everything is
re-derived on each run; nothing is stateful beyond the fetch cache.

Usage:
    build_portfolio_graph.py build --spine <repo-graph.json> --db <path>
        [--limit N] [--jobs N]           # L0 + L1
        [--enrich-refs [N|branch,branch]]  # opt-in per-release ref deps
    build_portfolio_graph.py stats --db <path> [--out-dir <dir>]
    build_portfolio_graph.py query --db <path> blast-radius <module-path>
    build_portfolio_graph.py query --db <path> top-shared [--limit N]
    build_portfolio_graph.py query --db <path> internal-coupling [--limit N]

Requires: gh CLI authenticated (go.mod fetch); stdlib otherwise.
Exit 0 on success; 1 on tool failure; 2 on usage errors.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from traust_engine.portfolio import parsers as MP

CACHE = Path.home() / ".cache" / "traust-engine" / "portfolio-graph"
DEFAULT_LANG_CACHE = (
    "analysis-results/findings/_manifest/portfolio-lang/gh-languages-cache-merged.jsonl"
)
# The requested-ecosystem universe for the L1 multi-ecosystem layer. "all"
# on the CLI expands to ALL_ECOSYSTEMS; Go is handled by the separate
# build_deps path and is NOT a member here.
#   * LANGUAGE_GATED_ECOSYSTEMS — real package manifests, discovered by
#     BASENAME anywhere in the git tree (subdir-aware).
#   * UNIVERSAL_ECOSYSTEMS — Docker base images / GitHub Actions / Helm
#     charts: dependency SURFACES every repo can carry regardless of its
#     GitHub language, discovered by PATH glob (MP.PATH_GLOB_ECOSYSTEMS).
LANGUAGE_GATED_ECOSYSTEMS = ("npm", "pypi", "maven", "cargo", "ruby", "nuget")
UNIVERSAL_ECOSYSTEMS = ("docker", "actions", "helm")
ALL_ECOSYSTEMS = LANGUAGE_GATED_ECOSYSTEMS + UNIVERSAL_ECOSYSTEMS
EXCLUDE_DIRS = {"vendor", "node_modules", "third_party", "_output", ".git", "testdata"}
# Path segments whose presence anywhere in a discovered manifest path marks
# it vendored/noise and drops it from the L1 multi-ecosystem fetch list.
DISCOVERY_NOISE_DIRS = {
    "vendor",
    "node_modules",
    ".git",
    "testdata",
    "third_party",
    "vendored",
    ".venv",
    "site-packages",
}

# ------------------------------------------- GitHub SECONDARY rate-limit guard
# The /rate_limit endpoint reflects only the PRIMARY (hourly) budget; it is
# BLIND to GitHub's anti-scraping SECONDARY limit — the "you have exceeded a
# secondary rate limit"/"please review our Terms of Service on scraping" 403
# that a wide tree-driven fleet sweep trips. A full backfill once burned
# through ~2,595 repos marking them 'error' during such a ban instead of
# pausing. The fetchers therefore classify that signature as a DISTINCT
# `ratelimited` status (never 'error', never 'absent', never cached), and the
# threaded fetch loop applies error-streak gating: after RATE_LIMIT_STREAK_STOP
# consecutive rate-limited responses it STOPS submitting work and PAUSES with
# exponential backoff, probing a single live call between sleeps; it RESUMES if
# the ban clears, or stops gracefully marking the run rate_limited_incomplete
# (leaving un-fetched repos UNVISITED for a cache-resume re-run) if the ban
# outlasts RATE_LIMIT_MAX_WAIT. Keep jobs low (<=4) on fleet sweeps.
RATE_LIMIT_STREAK_STOP = 5  # consecutive ratelimited results -> pause
RATE_LIMIT_BACKOFF_BASE = 60.0  # first pause, seconds
RATE_LIMIT_BACKOFF_CAP = 900.0  # per-sleep cap, seconds
RATE_LIMIT_MAX_WAIT = 3600.0  # total wait before giving up, seconds

# Case-insensitive substrings that mark a GitHub secondary/abuse rate-limit
# response. The primary-limit "API rate limit exceeded" wording is included
# because on scraping-triggered bans GitHub returns it alongside the Terms of
# Service line — both are the same "back off now" signal to us.
_RATE_LIMIT_SIGNATURES = (
    "you have exceeded a secondary rate limit",
    "secondary rate limit",
    "exceeded a secondary rate",
    "api rate limit exceeded",
    "rate limit exceeded",
    "abuse detection",
    "review our terms of service",
    "terms of service on scraping",
)


def _is_secondary_rate_limit(stderr_or_body: str) -> bool:
    """True when `stderr_or_body` carries GitHub's secondary/anti-scraping
    rate-limit signature — the class the /rate_limit endpoint does NOT
    reflect. Matches (case-insensitive) the known message substrings, or an
    HTTP 403/429 that also carries a retry indication (Retry-After / "please
    wait" / "too many requests"). A plain 404 "Not Found" is NOT a match."""
    if not stderr_or_body:
        return False
    low = stderr_or_body.lower()
    if any(sig in low for sig in _RATE_LIMIT_SIGNATURES):
        return True
    has_status = "403" in low or "429" in low or "too many requests" in low
    has_retry = (
        "retry-after" in low
        or "retry after" in low
        or "please wait" in low
        or "wait a few" in low
        or "please retry" in low
    )
    return has_status and has_retry


def _default_runner(argv, timeout):
    """Default gh call seam: run argv, return (returncode, stdout, stderr).
    Injected as `runner=` by tests so subprocess is never touched off-line."""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def _wait_out_rate_limit(runner, sleep_fn, probe_argv, base=None, cap=None, max_wait=None) -> bool:
    """PAUSE on a secondary-rate-limit ban: sleep (exponential backoff, capped)
    then probe a single live `probe_argv` call; repeat until the ban clears
    (return True) or the cumulative wait exceeds `max_wait` (return False).
    Sleeps go through the injectable `sleep_fn` so tests assert the backoff
    schedule without real waiting."""
    base = RATE_LIMIT_BACKOFF_BASE if base is None else base
    cap = RATE_LIMIT_BACKOFF_CAP if cap is None else cap
    max_wait = RATE_LIMIT_MAX_WAIT if max_wait is None else max_wait
    waited = 0.0
    backoff = base
    while waited < max_wait:
        sleep_fn(backoff)
        waited += backoff
        _rc, out, err = runner(probe_argv, 30)
        if not _is_secondary_rate_limit(f"{err}\n{out}"):
            return True
        backoff = min(backoff * 2, cap)
    return False


SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT, attrs TEXT
);
CREATE TABLE IF NOT EXISTS edges (
  src TEXT NOT NULL, dst TEXT NOT NULL, rel TEXT NOT NULL, attrs TEXT,
  UNIQUE(src, dst, rel)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_rel ON edges(rel);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
"""

REQUIRE_RE = re.compile(r"^\s*([A-Za-z0-9._~\-/]+)\s+(v[^\s/]+)(\s*//\s*indirect)?\s*$")
MODULE_RE = re.compile(r"^\s*module\s+(\S+)\s*$", re.MULTILINE)


def db_connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    return con


# Attr keys added to repo nodes AFTER the spine by later steps (the pqc
# backfeed — scan_pqc_dependencies.py stamps `$.pqc` from each repo's
# readiness verdict); preserved across spine rebuilds. EXTEND this tuple
# when a new post-spine repo-node enrichment is added — adding a key here
# is the only step needed to make that enrichment durable against a
# rebuild. A rebuild re-upserts every repo node from the spine JSON, and a
# whole-blob overwrite silently dropped `$.pqc` (3142 repos -> 41 after one
# rebuild), which zeroed the per-product PQC reports downstream
# (build_pqc_product_reports.py requires json_extract(attrs,'$.pqc') IS NOT
# NULL). upsert_repo_node folds these keys back in; see its docstring.
ENRICHMENT_ATTR_KEYS = ("pqc",)


def upsert_node(con, nid, kind, label=None, **attrs):
    con.execute(
        "INSERT INTO nodes(id, kind, label, attrs) VALUES(?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, "
        "label=excluded.label, attrs=excluded.attrs",
        (nid, kind, label or nid, json.dumps(attrs)),
    )


def upsert_repo_node(con, nid, kind, label, attrs, preserve=ENRICHMENT_ATTR_KEYS):
    """Spine repo-node upsert that PRESERVES declared post-spine enrichment
    keys (`preserve`, default ENRICHMENT_ATTR_KEYS) across a spine rebuild,
    while keeping the spine authoritative for everything it owns.

    Bounded allowlist merge — NOT a blind json_patch:
      * spine keys are authoritative — the new value ALWAYS wins (a
        `preserve` key present in the fresh spine attrs keeps its new
        value; nothing is folded over it);
      * a `preserve` key present on the EXISTING node but absent from the
        fresh spine attrs is folded back in (this is what survives a
        rebuild — the pqc backfeed's `$.pqc`);
      * every OTHER existing key (spine-owned or unknown/foreign) is NOT
        retained — it takes the fresh spine value or disappears, so the
        blob cannot accumulate stray keys across rebuilds (no graph
        growth).

    Used ONLY for the spine repo-node upsert (build_spine). Module /
    package / image / symbol upserts keep the plain overwrite semantics of
    upsert_node — this preserve path is deliberately not global."""
    attrs = dict(attrs or {})
    row = con.execute("SELECT attrs FROM nodes WHERE id=?", (nid,)).fetchone()
    if row and row[0]:
        try:
            existing = json.loads(row[0])
        except (json.JSONDecodeError, ValueError):
            existing = {}
        if isinstance(existing, dict):
            for k in preserve:
                if k in existing and k not in attrs:
                    attrs[k] = existing[k]
    con.execute(
        "INSERT INTO nodes(id, kind, label, attrs) VALUES(?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, "
        "label=excluded.label, attrs=excluded.attrs",
        (nid, kind, label or nid, json.dumps(attrs)),
    )


def upsert_edge(con, src, dst, rel, **attrs):
    con.execute(
        "INSERT INTO edges(src, dst, rel, attrs) VALUES(?,?,?,?) "
        "ON CONFLICT(src, dst, rel) DO UPDATE SET attrs=excluded.attrs",
        (src, dst, rel, json.dumps(attrs)),
    )


# ------------------------------------------------------- spine freshness
def inputs_last_change(inputs_dir: Path) -> str | None:
    """Last-change date (YYYY-MM-DD) of the inventory inputs: git commit
    date when the dir is a checkout, newest CSV mtime otherwise."""
    if not inputs_dir.is_dir():
        return None
    proc = subprocess.run(
        ["git", "-C", str(inputs_dir), "log", "-1", "--format=%cs"], capture_output=True, text=True
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    import datetime

    mtimes = [p.stat().st_mtime for p in inputs_dir.rglob("*.csv")]
    if not mtimes:
        return None
    return datetime.date.fromtimestamp(max(mtimes)).isoformat()


def check_spine_freshness(
    spine_path: Path, inputs_dir: Path | None, max_age_days: int = 30
) -> tuple[bool, list[str]]:
    """The spine is STALE when its inputs changed after it was generated,
    or when it exceeds the age backstop. Deterministic; date-granular
    (the spine records `generated` as YYYY-MM-DD). Note: the spine's own
    `sources` paths are absolute to whichever machine built it — inputs
    are resolved locally, never from those paths."""
    import datetime

    reasons: list[str] = []
    try:
        generated = json.loads(spine_path.read_text()).get("generated")
        gen_date = datetime.date.fromisoformat(str(generated)[:10])
    except (OSError, ValueError, json.JSONDecodeError):
        return False, ["spine has no parseable 'generated' date — regenerate with /repo-graph"]
    today = datetime.date.today()
    age = (today - gen_date).days
    if age > max_age_days:
        reasons.append(f"spine generated {gen_date} is {age} days old (backstop {max_age_days}d)")
    if inputs_dir is not None:
        changed = inputs_last_change(inputs_dir)
        if changed and changed > str(gen_date):
            reasons.append(
                f"inputs last changed {changed}, after the spine was generated ({gen_date})"
            )
    return (not reasons), reasons


def _default_inputs_dir(spine_path: Path) -> Path | None:
    # Optional sibling inputs directory (e.g. <ws>/sibling-inputs); pass
    # --inputs-dir to override.
    candidate = spine_path.resolve().parents[2] / "sibling-inputs"
    return candidate if candidate.is_dir() else None


# ---------------------------------------------------------------- L0 spine
def build_spine(con, spine_path: Path) -> dict:
    g = json.loads(spine_path.read_text())
    for n in g["nodes"]:
        # Repo nodes go through the preserve path so a rebuild cannot
        # clobber the post-spine enrichment keys (ENRICHMENT_ATTR_KEYS,
        # e.g. the pqc backfeed's `$.pqc`); every other kind keeps the
        # plain overwrite semantics of upsert_node.
        if n["type"] == "repo":
            upsert_repo_node(con, n["id"], n["type"], n.get("label"), n.get("attrs") or {})
        else:
            upsert_node(con, n["id"], n["type"], n.get("label"), **(n.get("attrs") or {}))
    for e in g["edges"]:
        attrs = {k: v for k, v in e.items() if k not in ("from", "to", "rel")}
        upsert_edge(con, e["from"], e["to"], e.get("rel", "related"), **attrs)
    con.commit()
    repos = con.execute("SELECT id, attrs FROM nodes WHERE kind='repo'").fetchall()
    return {"nodes": len(g["nodes"]), "edges": len(g["edges"]), "repos": len(repos)}


# ----------------------------------------------------------------- L1 deps
def parse_gomod(text: str) -> tuple[str | None, list[tuple[str, str, bool]]]:
    """(module path, [(require path, version, indirect)])."""
    m = MODULE_RE.search(text)
    module = m.group(1) if m else None
    requires: list[tuple[str, str, bool]] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        candidate = None
        if in_block:
            candidate = stripped
        elif stripped.startswith("require "):
            candidate = stripped[len("require ") :]
        if not candidate:
            continue
        rm = REQUIRE_RE.match(candidate)
        if rm:
            requires.append((rm.group(1), rm.group(2), bool(rm.group(3))))
    return module, requires


def fetch_gomod(org: str, name: str) -> tuple[str, str]:
    """(status, text). status: ok | absent | error. Cached on disk."""
    cache_file = CACHE / "gomod" / f"{org}__{name}.json"
    if cache_file.is_file():
        c = json.loads(cache_file.read_text())
        return c["status"], c.get("text", "")
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{org}/{name}/contents/go.mod",
            "-H",
            "Accept: application/vnd.github.raw",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode == 0:
        status, text = "ok", proc.stdout
    elif "404" in proc.stderr or "Not Found" in proc.stderr:
        status, text = "absent", ""
    else:
        status, text = "error", ""
    if status != "error":  # don't cache transient failures
        cache_file.write_text(json.dumps({"status": status, "text": text}))
    return status, text


def build_deps(con, limit: int | None, jobs: int) -> dict:
    repos = [
        (r[0], json.loads(r[1] or "{}"))
        for r in con.execute("SELECT id, attrs FROM nodes WHERE kind='repo'")
    ]
    gh_repos = [
        (rid, a)
        for rid, a in repos
        if a.get("host") == "github.com" and a.get("org") and a.get("name")
    ]
    skipped_host = len(repos) - len(gh_repos)
    if limit:
        gh_repos = gh_repos[:limit]

    def work(item):
        rid, a = item
        status, text = fetch_gomod(a["org"], a["name"])
        return rid, a, status, text

    stats = {
        "repos": len(gh_repos),
        "go": 0,
        "absent": 0,
        "errors": 0,
        "skipped_host": skipped_host,
        "modules": 0,
        "dep_edges": 0,
    }
    module_owner: dict[str, str] = {}
    results = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for rid, a, status, text in pool.map(work, gh_repos):
            results.append((rid, a, status, text))

    parsed = []
    for rid, _a, status, text in results:
        if status == "error":
            stats["errors"] += 1
            continue
        if status == "absent":
            stats["absent"] += 1
            continue
        module, requires = parse_gomod(text)
        if not module:
            stats["absent"] += 1
            continue
        stats["go"] += 1
        module_owner[module] = rid
        parsed.append((rid, module, requires))

    seen_modules: set[str] = set()
    for rid, module, requires in parsed:
        mid = f"module:{module}"
        if module not in seen_modules:
            upsert_node(con, mid, "module", module, internal=1, owner_repo=rid)
            seen_modules.add(module)
        upsert_edge(con, rid, mid, "declares")
        for dep, version, indirect in requires:
            did = f"module:{dep}"
            if dep not in seen_modules:
                upsert_node(
                    con,
                    did,
                    "module",
                    dep,
                    internal=1 if dep in module_owner else 0,
                    owner_repo=module_owner.get(dep),
                )
                seen_modules.add(dep)
            upsert_edge(con, rid, did, "depends_on", version=version, indirect=int(indirect))
            stats["dep_edges"] += 1
    # second pass: mark internals discovered after first reference. A module
    # whose declared path does not match its owning repo's URL is a
    # sustaining fork of an upstream module (e.g. a sustaining fork may
    # declare `module golang.org/x/net`) — internal in the literal sense,
    # but distinct from portfolio-authored libraries.
    for module, rid in module_owner.items():
        repo_path = rid.removeprefix("repo:")
        fork = 0 if module.startswith(repo_path) else 1
        con.execute(
            "UPDATE nodes SET attrs=json_set(attrs,'$.internal',1,"
            "'$.owner_repo',?,'$.sustaining_fork',?) WHERE id=?",
            (rid, fork, f"module:{module}"),
        )
    con.commit()
    stats["modules"] = len(seen_modules)
    return stats


# ---------------------------------------------- L1 ref enrichment (opt-in)
# Branch-awareness Phase 3 (see
# Branch-awareness Phase 3. Data-gated and
# SELECTIVE: only the supported releases' ref nodes, only when asked.
RELEASE_BRANCH_RE = re.compile(r"^release-\d+\.\d+$")
DEFAULT_SUPPORTED_RELEASES = 3


def _release_sort_key(branch: str) -> tuple:
    m = re.match(r"^release-(\d+)\.(\d+)$", branch)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def select_supported_refs(con, selector: str) -> list[str]:
    """Resolve --enrich-refs into the supported branch set.

    Numeric selector N: the top-N `release-X.Y` branches present as
    repo-ref nodes, ranked by ships_ref edge count (how many shipping
    rows the inventories attribute to that branch), ties broken by
    newest release. Non-numeric: an explicit comma-separated branch
    list, taken verbatim (lets a caller enrich e.g. an openshift-X.Y
    or main branch deliberately)."""
    selector = (selector or "").strip()
    if selector and not selector.isdigit():
        return [b.strip() for b in selector.split(",") if b.strip()]
    n = int(selector) if selector else DEFAULT_SUPPORTED_RELEASES
    rows = con.execute("""
        SELECT json_extract(n.attrs,'$.branch') AS branch, COUNT(*) AS c
        FROM edges e JOIN nodes n ON n.id=e.dst
        WHERE e.rel='ships_ref' AND n.kind='repo-ref'
        GROUP BY branch""").fetchall()
    release = [(b, c) for b, c in rows if b and RELEASE_BRANCH_RE.match(b)]
    release.sort(key=lambda x: (-x[1], tuple(-v for v in _release_sort_key(x[0]))))
    return [b for b, _ in release[:n]]


def fetch_gomod_at_ref(org: str, name: str, ref: str) -> tuple[str, str]:
    """(status, text) for go.mod at a specific ref. status: ok | absent |
    error. `absent` covers both no-go.mod-at-ref and no-such-ref (the
    GitHub contents API 404s for either) — a counted skip, never fatal.
    Cached on disk per repo@ref; transient errors are not cached."""
    import urllib.parse

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", ref)
    cache_file = CACHE / "gomod-ref" / f"{org}__{name}@{safe}.json"
    if cache_file.is_file():
        c = json.loads(cache_file.read_text())
        return c["status"], c.get("text", "")
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{org}/{name}/contents/go.mod?ref={urllib.parse.quote(ref)}",
            "-H",
            "Accept: application/vnd.github.raw",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode == 0:
        status, text = "ok", proc.stdout
    elif "404" in proc.stderr or "Not Found" in proc.stderr:
        status, text = "absent", ""
    else:
        status, text = "error", ""
    if status != "error":  # don't cache transient failures
        cache_file.write_text(json.dumps({"status": status, "text": text}))
    return status, text


def build_ref_deps(con, selector: str, jobs: int) -> dict:
    """Attach `depends_on_ref` edges (ref node → module, attrs
    version/indirect/ref=<branch>) for the supported releases' repo-ref
    nodes. Additive only: module nodes are INSERT OR IGNOREd so
    HEAD-derived attrs (internal/owner_repo) are never overwritten, and
    no default-branch node/edge is touched."""
    branches = select_supported_refs(con, selector)
    stats = {
        "branches": branches,
        "refs": 0,
        "ok": 0,
        "skipped": 0,
        "errors": 0,
        "dep_edges": 0,
        "modules_new": 0,
    }
    if not branches:
        return stats
    qmarks = ",".join("?" * len(branches))
    rows = con.execute(
        f"""
        SELECT e.dst, json_extract(rf.attrs,'$.branch'),
               json_extract(r.attrs,'$.host'),
               json_extract(r.attrs,'$.org'),
               json_extract(r.attrs,'$.name')
        FROM edges e
        JOIN nodes r  ON r.id=e.src AND r.kind='repo'
        JOIN nodes rf ON rf.id=e.dst AND rf.kind='repo-ref'
        WHERE e.rel='has_ref'
          AND json_extract(rf.attrs,'$.branch') IN ({qmarks})
        ORDER BY e.dst""",
        branches,
    ).fetchall()
    targets = [
        (refid, br, org, name)
        for refid, br, host, org, name in rows
        if host == "github.com" and org and name
    ]
    stats["refs"] = len(targets)

    def work(item):
        refid, br, org, name = item
        status, text = fetch_gomod_at_ref(org, name, br)
        return refid, br, status, text

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(work, targets))

    existing = {r[0] for r in con.execute("SELECT label FROM nodes WHERE kind='module'")}
    for refid, br, status, text in results:
        if status == "error":
            stats["errors"] += 1
            continue
        if status == "absent":
            stats["skipped"] += 1
            continue
        module, requires = parse_gomod(text)
        if not module:
            stats["skipped"] += 1
            continue
        stats["ok"] += 1
        for dep, version, indirect in requires:
            did = f"module:{dep}"
            if dep not in existing:
                con.execute(
                    "INSERT OR IGNORE INTO nodes(id,kind,label,attrs) VALUES(?,?,?,?)",
                    (did, "module", dep, json.dumps({"internal": 0, "first_seen_ref": br})),
                )
                existing.add(dep)
                stats["modules_new"] += 1
            upsert_edge(
                con, refid, did, "depends_on_ref", version=version, indirect=int(indirect), ref=br
            )
            stats["dep_edges"] += 1
    con.commit()
    return stats


# ------------------------------------- L1 multi-ecosystem deps (npm/pypi/...)
# Mirrors build_deps/fetch_gomod for the non-Go ecosystems, but discovers
# manifests ANYWHERE in each repo's git tree (subdir-aware) rather than at the
# root only, and ingests three universal dependency SURFACES — Docker base
# images, GitHub Actions, Helm charts — that every repo can carry regardless
# of its GitHub language. Completeness-instrumented: denominator-honest global
# tree stats + per-ecosystem stats, plus a `loud_fail` list naming any
# requested ecosystem where manifests were discovered (repos_with_manifest>0)
# but nothing was extracted (dep_edges==0) — the silently-broken tripwire.
# Package nodes live in a DIFFERENT id space (dep_node_id -> `pkg:<eco>/<name>`)
# from Go modules (`module:<path>`) so the two never collide.
def fetch_tree(
    org: str, name: str, ref: str = "HEAD", runner=None, sleep_ms: int = 0, sleep_fn=None
) -> tuple[str, list[str], bool]:
    """(status, blob_paths, truncated) for a repo's full recursive git tree
    at `ref`. status: ok | absent | error | ratelimited. 404/Not Found ->
    absent; a GitHub SECONDARY rate-limit signature -> `ratelimited` (a
    distinct status the fetch loop reacts to — NOT 'error'); any other failure
    -> error. Only ok/absent are cached; ratelimited/error are transient and
    retried next run. `truncated` echoes the GitHub API flag set on very large
    trees — the caller falls back to root-only candidates for those. Cached on
    disk per repo (delete CACHE/trees/<org>__<name>.json to force a refresh).
    `runner`/`sleep_fn` are injectable seams (default: real gh subprocess /
    time.sleep); `sleep_ms` paces each live call for gentle fleet sweeps."""
    runner = runner or _default_runner
    cache_file = CACHE / "trees" / f"{org}__{name}.json"
    if cache_file.is_file():
        c = json.loads(cache_file.read_text())
        return c["status"], c.get("paths", []), bool(c.get("truncated"))
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    if sleep_ms:
        (sleep_fn or time.sleep)(sleep_ms / 1000.0)
    rc, out, err = runner(["gh", "api", f"repos/{org}/{name}/git/trees/{ref}?recursive=1"], 120)
    if rc == 0:
        try:
            data = json.loads(out)
        except (json.JSONDecodeError, ValueError):
            return "error", [], False  # malformed body — transient, not cached
        paths = [
            e.get("path")
            for e in (data.get("tree") or [])
            if isinstance(e, dict) and e.get("type") == "blob" and e.get("path")
        ]
        truncated = bool(data.get("truncated"))
        cache_file.write_text(json.dumps({"status": "ok", "paths": paths, "truncated": truncated}))
        return "ok", paths, truncated
    combined = f"{err}\n{out}"
    if _is_secondary_rate_limit(combined):
        return "ratelimited", [], False  # ban — not cached, caller pauses
    if "404" in err or "Not Found" in err:
        cache_file.write_text(json.dumps({"status": "absent", "paths": [], "truncated": False}))
        return "absent", [], False
    return "error", [], False  # transient — not cached, retried next run


def _glob_match(path: str, pattern: str) -> bool:
    """fnmatch a repo-relative path against a PATH_GLOB_ECOSYSTEMS pattern.
    A leading `**/` means "match the BASENAME anywhere in the tree"; any
    other pattern is matched against the full path."""
    if pattern.startswith("**/"):
        return fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern[3:])
    return fnmatch.fnmatch(path, pattern)


def _match_ecosystem(path: str, lang_req: set, univ_req: set) -> str | None:
    """The single ecosystem a tree path belongs to, or None. Universal
    surfaces win first (workflow > docker/helm globs), then language-gated
    package manifests by basename / suffix glob (via parser_for)."""
    if "actions" in univ_req and MP.is_workflow_path(path):
        return "actions"
    for eco in ("docker", "helm"):
        if eco in univ_req:
            for pat in MP.PATH_GLOB_ECOSYSTEMS.get(eco, []):
                if _glob_match(path, pat):
                    return eco
    base = path.rsplit("/", 1)[-1]
    for eco in LANGUAGE_GATED_ECOSYSTEMS:
        if eco in lang_req and base in MP.ECOSYSTEM_MANIFESTS.get(eco, []):
            return eco
    pf = MP.parser_for(base)  # resolves *.gemspec/*.csproj/requirements*.txt
    if pf and pf[0] in lang_req:
        return pf[0]
    return None


def discover_manifests(paths, ecosystems) -> list[tuple[str, str]]:
    """[(ecosystem, path)] for every manifest to fetch, given a repo's tree
    `paths` and the requested `ecosystems`. Language-gated ecosystems match
    by basename (or parser_for suffix glob) ANYWHERE in the tree — the
    subdir fix; universal ecosystems match MP.PATH_GLOB_ECOSYSTEMS against
    the full path. Vendored/noise paths (DISCOVERY_NOISE_DIRS) are dropped.
    Parsing is routed later via parser_for_path(path)."""
    ecosystems = set(ecosystems)
    lang_req = ecosystems & set(LANGUAGE_GATED_ECOSYSTEMS)
    univ_req = ecosystems & set(UNIVERSAL_ECOSYSTEMS)
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        if not path:
            continue
        norm = path.replace("\\", "/")
        if set(norm.split("/")) & DISCOVERY_NOISE_DIRS:
            continue
        eco = _match_ecosystem(norm, lang_req, univ_req)
        if eco and (eco, norm) not in seen:
            seen.add((eco, norm))
            out.append((eco, norm))
    return out


def fetch_manifest(
    org: str, name: str, path: str, ecosystem: str, runner=None, sleep_ms: int = 0, sleep_fn=None
) -> tuple[str, str]:
    """(status, text) for a manifest at `path` in a repo's default branch.
    status: ok | absent | error | ratelimited. Cached on disk per repo+path;
    404/Not Found -> absent; a GitHub SECONDARY rate-limit signature ->
    `ratelimited` (distinct, so the fetch loop can pause — NOT 'error'); any
    other failure -> error. Only ok/absent are cached (ratelimited/error are
    transient). `runner`/`sleep_fn`/`sleep_ms` are the same injectable seams as
    fetch_tree."""
    runner = runner or _default_runner
    slug = path.replace("/", "_")
    cache_file = CACHE / "manifests" / ecosystem / f"{org}__{name}__{slug}.json"
    if cache_file.is_file():
        c = json.loads(cache_file.read_text())
        return c["status"], c.get("text", "")
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    if sleep_ms:
        (sleep_fn or time.sleep)(sleep_ms / 1000.0)
    rc, out, err = runner(
        [
            "gh",
            "api",
            f"repos/{org}/{name}/contents/{path}",
            "-H",
            "Accept: application/vnd.github.raw",
        ],
        60,
    )
    if rc == 0:
        status, text = "ok", out
    elif _is_secondary_rate_limit(f"{err}\n{out}"):
        return "ratelimited", ""  # ban — not cached, caller pauses
    elif "404" in err or "Not Found" in err:
        status, text = "absent", ""
    else:
        status, text = "error", ""
    if status != "error":  # don't cache transient failures
        cache_file.write_text(json.dumps({"status": status, "text": text}))
    return status, text


def load_language_cache(path) -> dict:
    """Read the gh-languages jsonl (`{"repo":"org/name","languages":{...}}`
    per line) into {"org/name": {lang: bytes}}. A missing or unreadable file
    returns {} (the caller warns) and malformed lines are skipped — never
    raises."""
    p = Path(path)
    if not p.is_file():
        return {}
    out: dict = {}
    try:
        text = p.read_text()
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        repo = obj.get("repo")
        langs = obj.get("languages")
        if isinstance(repo, str) and isinstance(langs, dict):
            out[repo] = {k: v for k, v in langs.items() if isinstance(v, int)}
    return out


def manifests_for(languages: dict, ecosystems: set) -> list:
    """Ordered (ecosystem, filename) candidates for a repo, derived from its
    present GitHub languages intersected with the requested `ecosystems`.
    Each mapped ecosystem contributes its ECOSYSTEM_MANIFESTS candidates in
    order (lockfile first). [] when no present language maps to a request."""
    present: list = []
    for lang in languages:
        eco = MP.LANGUAGE_ECOSYSTEMS.get(lang)
        if eco and eco in ecosystems and eco not in present:
            present.append(eco)
    out: list = []
    for eco in present:
        for fn in MP.ECOSYSTEM_MANIFESTS.get(eco, []):
            out.append((eco, fn))
    return out


def dep_node_id(name: str, ecosystem: str) -> str:
    """Graph node id for a dependency. Go keeps the legacy `module:<path>`
    id space; every other ecosystem is namespaced `pkg:<eco>/<name>` so a
    package named e.g. `foo` never collides with Go module `module:foo`."""
    if ecosystem in ("Go", "go"):
        return f"module:{name}"
    return f"pkg:{ecosystem}/{name}"


def _fetch_root_candidates(
    org, name, langs, lang_ecos, runner=None, sleep_ms=0, sleep_fn=None
) -> tuple[list, bool]:
    """Truncated-tree fallback: the pre-subdir root-only fetch for the
    language-gated ecosystems. Tries each ecosystem's root candidates in
    order (lockfile first) and keeps the FIRST that resolves ok. Returns
    (candidates, ratelimited) where candidates is a list of
    (eco, path, 'ok', declared, deps) holding only real, resolved manifests —
    absent/error candidates are passed over silently, as the old root-only
    path did (a guessed root filename is not evidence of a manifest, so it
    must not inflate the denominator). `ratelimited` is True if a fetch hit
    the GitHub secondary-rate-limit ban, so the caller can pause and re-run
    later (the repo is left unvisited)."""
    by_eco: dict = {}
    for eco, fn in manifests_for(langs, set(lang_ecos)):
        by_eco.setdefault(eco, []).append(fn)
    out = []
    for eco, filenames in by_eco.items():
        for fn in filenames:
            status, text = fetch_manifest(
                org, name, fn, eco, runner=runner, sleep_ms=sleep_ms, sleep_fn=sleep_fn
            )
            if status == "ratelimited":
                return out, True
            if status == "ok":
                pf = MP.parser_for(fn)
                declared, deps = pf[1](text) if pf else (None, [])
                out.append((eco, fn, "ok", declared, deps))
                break
            if status == "error":
                break
    return out, False


# Cap on the number of source-manifest paths stored on a single edge's
# `manifest` attr. A dep found in more manifests than this (an unusual
# monorepo shape) keeps the first CAP paths (sorted, deterministic) and the
# edge also carries `manifest_truncated: true` so the attr stays bounded
# rather than ballooning into a giant list.
MANIFEST_PATHS_CAP = 20


def _manifest_attr(paths) -> dict:
    """Edge-attr fragment recording source-manifest provenance for a
    dependency/declares edge. `paths` is the set of repo-relative manifest
    paths the dep was found in (or None). Returns {} when there is no path
    (e.g. the Go path, whose provenance is implicitly `go.mod` and never
    stamped here), else {"manifest": [sorted paths]} plus, when the count
    exceeds MANIFEST_PATHS_CAP, {"manifest_truncated": True}. The list type
    is stable — a single source is still a 1-element list."""
    if not paths:
        return {}
    ordered = sorted(set(paths))
    if len(ordered) > MANIFEST_PATHS_CAP:
        return {"manifest": ordered[:MANIFEST_PATHS_CAP], "manifest_truncated": True}
    return {"manifest": ordered}


def build_deps_multi(
    con,
    limit: int | None,
    jobs: int,
    ecosystems,
    lang_cache_path,
    runner=None,
    sleep_fn=None,
    sleep_ms: int = 0,
) -> dict:
    """L1 for the non-Go ecosystems. Enumerates GitHub repos exactly like
    build_deps, fetches each repo's full git tree (threaded), discovers every
    manifest ANYWHERE in the tree (subdir-aware) plus the universal
    docker/actions/helm surfaces, fetches + parses each (threaded),
    AGGREGATES per ecosystem within a repo (union deps by name — first
    non-empty version wins, direct in any manifest wins), and upserts
    `package` nodes + `depends_on`/`declares` edges in the `pkg:` id space.
    Each edge also carries a `manifest` attr — the sorted list of
    repo-relative source-manifest paths the dep/declaration was found in
    (capped at MANIFEST_PATHS_CAP, with `manifest_truncated: true` beyond
    that) — so a dependency finding can be verified against and cite the
    exact manifest it came from without a manual source check.
    Truncated (huge) trees fall back to the old root-only candidate fetch for
    the language-gated ecosystems. Returns denominator-honest global tree
    stats + per-ecosystem completeness stats plus `loud_fail` (requested
    ecosystems where manifests were discovered but zero edges extracted).
    Idempotent/resumable via the on-disk tree + manifest caches; never
    touches the Go `module:` nodes.

    SECONDARY-rate-limit safe: the threaded fetch loop applies error-streak
    gating. After RATE_LIMIT_STREAK_STOP consecutive `ratelimited` fetches it
    STOPS submitting work and PAUSES (exponential backoff, live probe between
    sleeps via `_wait_out_rate_limit`); it RESUMES if the ban clears, or stops
    gracefully setting `rate_limited_incomplete=True` and leaving the not-yet
    -fetched repos UNVISITED (uncached, so a re-run's cache-resume finishes
    them) rather than marking a fleet 'error'. `runner`/`sleep_fn` are the
    injectable gh/sleep seams (default real subprocess / time.sleep); jobs
    should stay <=4 on fleet sweeps and `sleep_ms` paces each live call."""
    ecosystems = set(ecosystems)
    lang_req = ecosystems & set(LANGUAGE_GATED_ECOSYSTEMS)
    runner = runner or _default_runner
    _sleep = sleep_fn or time.sleep
    repos = [
        (r[0], json.loads(r[1] or "{}"))
        for r in con.execute("SELECT id, attrs FROM nodes WHERE kind='repo'")
    ]
    gh_repos = [
        (rid, a)
        for rid, a in repos
        if a.get("host") == "github.com" and a.get("org") and a.get("name")
    ]
    if limit:
        gh_repos = gh_repos[:limit]

    # Language cache is used ONLY for the truncated-tree root fallback now —
    # subdir discovery is by tree path, not by GitHub language.
    lang_cache = load_language_cache(lang_cache_path)

    stats: dict = {
        eco: {
            "repos_with_manifest": 0,
            "manifests_fetched_ok": 0,
            "absent": 0,
            "error": 0,
            "parse_empty": 0,
            "pkg_nodes": 0,
            "dep_edges": 0,
            "manifest_paths_sample": [],
        }
        for eco in sorted(ecosystems)
    }
    glob_stats = {
        "repos_tree_ok": 0,
        "repos_tree_absent": 0,
        "repos_tree_error": 0,
        "repos_truncated": 0,
        "repos_with_any_manifest": 0,
        "repos_with_zero_manifests": 0,
        "truncated_fallback": 0,
        "repos_ratelimited_skipped": 0,
    }

    def work(item):
        rid, a = item
        org, name = a["org"], a["name"]
        tstatus, paths, truncated = fetch_tree(
            org, name, runner=runner, sleep_ms=sleep_ms, sleep_fn=_sleep
        )
        if tstatus == "ratelimited":
            return rid, "ratelimited", False, []
        if tstatus != "ok":
            return rid, tstatus, truncated, []
        if truncated:
            langs = lang_cache.get(f"{org}/{name}", {})
            cands, limited = _fetch_root_candidates(
                org, name, langs, lang_req, runner=runner, sleep_ms=sleep_ms, sleep_fn=_sleep
            )
            if limited:
                return rid, "ratelimited", True, []
            return rid, "ok", True, cands
        manifests = []
        for eco, path in discover_manifests(paths, ecosystems):
            status, text = fetch_manifest(
                org, name, path, eco, runner=runner, sleep_ms=sleep_ms, sleep_fn=_sleep
            )
            if status == "ratelimited":
                # bail the whole repo: ok manifests already fetched are cached,
                # so a re-run finishes this repo cheaply. Leave it unvisited.
                return rid, "ratelimited", False, []
            declared, deps = None, []
            if status == "ok":
                pf = MP.parser_for_path(path)
                if pf:
                    declared, deps = pf[1](text)
            manifests.append((eco, path, status, declared, deps))
        return rid, "ok", False, manifests

    # ---- error-streak-gated threaded fetch loop (resumable pause on a ban) --
    # Submit in submission-order batches of `jobs`; count CONSECUTIVE
    # `ratelimited` results (in submission order — deterministic regardless of
    # thread scheduling). At the streak threshold, stop submitting and pause;
    # give up (incomplete) only if the ban outlasts RATE_LIMIT_MAX_WAIT.
    fetched: list = []
    rate_limited_incomplete = False
    consec_rl = 0
    idx = 0
    batch_size = max(1, jobs)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        while idx < len(gh_repos) and not rate_limited_incomplete:
            batch = gh_repos[idx : idx + batch_size]
            idx += len(batch)
            futs = [pool.submit(work, it) for it in batch]
            paused = False
            for fut in futs:  # submission order -> deterministic streak count
                res = fut.result()
                fetched.append(res)
                if res[1] == "ratelimited":
                    consec_rl += 1
                else:
                    consec_rl = 0
                if consec_rl >= RATE_LIMIT_STREAK_STOP:
                    paused = True
            if not paused:
                continue
            # PAUSE: probe the next un-fetched repo's tree surface (the same
            # scraping surface a ban targets — /rate_limit would be blind).
            probe_item = gh_repos[idx] if idx < len(gh_repos) else batch[-1]
            po, pn = probe_item[1]["org"], probe_item[1]["name"]
            probe_argv = ["gh", "api", f"repos/{po}/{pn}/git/trees/HEAD?recursive=1"]
            cleared = _wait_out_rate_limit(runner, _sleep, probe_argv)
            consec_rl = 0
            if not cleared:
                rate_limited_incomplete = True  # unsubmitted left unvisited

    seen: dict = {eco: set() for eco in ecosystems}
    package_owner: dict = {}  # (eco, name) -> rid  (declared names only)

    def _ensure_node(eco, name):
        nid = dep_node_id(name, eco)
        if nid not in seen[eco]:
            kind = "module" if eco in ("Go", "go") else "package"
            # INSERT OR IGNORE: never clobber attrs an earlier run (or the
            # Go path) may have set; the second pass promotes internals.
            con.execute(
                "INSERT OR IGNORE INTO nodes(id,kind,label,attrs) VALUES(?,?,?,?)",
                (
                    nid,
                    kind,
                    name,
                    json.dumps({"ecosystem": eco, "name": name, "internal": 0, "owner_repo": None}),
                ),
            )
            seen[eco].add(nid)
        return nid

    for rid, tstatus, truncated, manifests in fetched:
        if tstatus == "ratelimited":
            # Hit the ban before this repo completed — uncached, left
            # UNVISITED for a re-run. NEVER an 'error'.
            glob_stats["repos_ratelimited_skipped"] += 1
            continue
        if tstatus == "absent":
            glob_stats["repos_tree_absent"] += 1
            continue
        if tstatus == "error":
            glob_stats["repos_tree_error"] += 1
            continue
        glob_stats["repos_tree_ok"] += 1
        if truncated:
            glob_stats["repos_truncated"] += 1
            if manifests:
                glob_stats["truncated_fallback"] += 1

        # Aggregate per ecosystem within this repo. A dep's version is the
        # first non-empty one seen across the repo's manifests; a dep marked
        # direct in ANY manifest is direct (indirect only when indirect in
        # every manifest). Alongside the aggregate we track, per (eco, name),
        # the SET of manifest paths the dep was found in — the source-manifest
        # provenance stamped onto the edge so a dependency finding names
        # exactly where it was declared (a monorepo dep can appear in more
        # than one manifest, hence a set).
        agg: dict = {}  # eco -> {name: [version, indirect]}
        prov: dict = {}  # eco -> {name: set(manifest paths)}
        declared_by: dict = {}  # eco -> set(declared names)
        declared_prov: dict = {}  # eco -> {declared name: set(paths)}
        present: set = set()  # ecos with >=1 discovered manifest here
        for eco, path, status, declared, deps in manifests:
            present.add(eco)
            st = stats[eco]
            if path not in st["manifest_paths_sample"] and len(st["manifest_paths_sample"]) < 5:
                st["manifest_paths_sample"].append(path)
            if status == "error":
                st["error"] += 1
                continue
            if status == "absent":
                st["absent"] += 1
                continue
            st["manifests_fetched_ok"] += 1
            if not deps and not declared:
                st["parse_empty"] += 1
                continue
            if declared:
                declared_by.setdefault(eco, set()).add(declared)
                declared_prov.setdefault(eco, {}).setdefault(declared, set()).add(path)
            a_eco = agg.setdefault(eco, {})
            p_eco = prov.setdefault(eco, {})
            for dname, version, indirect in deps:
                p_eco.setdefault(dname, set()).add(path)
                if dname in a_eco:
                    ev, eind = a_eco[dname]
                    if not ev and version:
                        ev = version
                    a_eco[dname] = [ev, eind and bool(indirect)]
                else:
                    a_eco[dname] = [version, bool(indirect)]

        for eco in present:
            stats[eco]["repos_with_manifest"] += 1
        if present:
            glob_stats["repos_with_any_manifest"] += 1
        else:
            glob_stats["repos_with_zero_manifests"] += 1

        for eco, a_eco in agg.items():
            p_eco = prov.get(eco, {})
            for dname, (version, indirect) in a_eco.items():
                depid = _ensure_node(eco, dname)
                edge_attrs = {"version": version or "", "indirect": int(indirect), "ecosystem": eco}
                edge_attrs.update(_manifest_attr(p_eco.get(dname)))
                upsert_edge(con, rid, depid, "depends_on", **edge_attrs)
                stats[eco]["dep_edges"] += 1
        for eco, names in declared_by.items():
            dp = declared_prov.get(eco, {})
            for dname in names:
                nid = _ensure_node(eco, dname)
                upsert_edge(con, rid, nid, "declares", **_manifest_attr(dp.get(dname)))
                package_owner[(eco, dname)] = rid

    # second pass: promote declared packages to internal=1 with their owning
    # repo (mirrors build_deps' internal/owner pass, scoped per (eco,name)).
    for (eco, pname), rid in package_owner.items():
        con.execute(
            "UPDATE nodes SET attrs=json_set(attrs,'$.internal',1,'$.owner_repo',?) WHERE id=?",
            (rid, dep_node_id(pname, eco)),
        )
    con.commit()

    # Repos never SUBMITTED because a ban paused the run past max wait are
    # counted skipped too (they are unvisited/uncached, picked up on re-run).
    glob_stats["repos_ratelimited_skipped"] += len(gh_repos) - idx

    for eco in ecosystems:
        stats[eco]["pkg_nodes"] = len(seen[eco])
    # LOUD-FAIL: a requested ecosystem where manifests were DISCOVERED
    # (repos_with_manifest>0) but nothing was extracted (dep_edges==0) — a
    # silently-broken surface. The `repos_with_manifest>0` gate already means
    # "this ecosystem actually had manifests discovered", so a
    # rate_limited_incomplete run never loud-fails an ecosystem it never
    # reached (those keep repos_with_manifest==0 and a repo that hit the ban
    # mid-fetch is bailed before it increments the denominator).
    loud_fail = [
        eco
        for eco in sorted(ecosystems)
        if stats[eco]["repos_with_manifest"] > 0 and stats[eco]["dep_edges"] == 0
    ]
    stats.update(glob_stats)
    stats["loud_fail"] = loud_fail
    stats["rate_limited_incomplete"] = rate_limited_incomplete
    return stats


# ------------------------------------------------------- L2 interfaces
def extract_interfaces(org: str, name: str, timeout: int = 420) -> dict:
    """Shallow-clone, run the hardening scanner's interface extraction,
    cache the signals, delete the clone. Cached per repo (delete the cache
    file to force a refresh)."""
    import shutil
    import tempfile

    cache_file = CACHE / "interfaces" / f"{org}__{name}.json"
    if cache_file.is_file():
        return json.loads(cache_file.read_text())
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=f"{name}-", dir=str(CACHE))
    try:
        # org/name originate in inputs CSVs; scheme pinned by the
        # f-string, transport by GIT_ALLOW_PROTOCOL=https; `--` stops
        # option smuggling via a crafted name
        proc = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--",
                f"https://github.com/{org}/{name}",
                tmp,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
        )
        if proc.returncode != 0:
            return {"status": "clone-error"}  # transient — not cached
        sha = subprocess.run(
            ["git", "-C", tmp, "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        from traust_engine.adapters.checkov import Scanner as K8sScanner

        scanner = K8sScanner(Path(tmp))
        scanner.run()
        keep = (
            "crds_defined",
            "csv_owned_crds",
            "csv_required_crds",
            "webhooks",
            "rbac_grants",
            "api_group_literals",
        )
        out = {"status": "ok", "sha": sha, "interfaces": {k: scanner.signals[k] for k in keep}}
        cache_file.write_text(json.dumps(out))
        return out
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _apigroup(con, group: str) -> str:
    gid = f"apigroup:{group}"
    upsert_node(con, gid, "api-group", group)
    return gid


def build_interfaces(con, limit: int | None, jobs: int) -> dict:
    repos = [
        (r[0], json.loads(r[1] or "{}"))
        for r in con.execute("SELECT id, attrs FROM nodes WHERE kind='repo'")
    ]
    gh = [
        (rid, a)
        for rid, a in repos
        if a.get("host") == "github.com" and a.get("org") and a.get("name")
    ]
    if limit:
        gh = gh[:limit]
    stats = {
        "repos": len(gh),
        "ok": 0,
        "clone_errors": 0,
        "timeouts": 0,
        "crds": 0,
        "owns": 0,
        "requires": 0,
        "intercepts": 0,
        "rbac": 0,
        "consumes": 0,
    }

    def work(item):
        rid, a = item
        return rid, extract_interfaces(a["org"], a["name"])

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(work, gh))

    for rid, res in results:
        status = res.get("status")
        if status in ("clone-error", "extract-error"):
            stats["clone_errors"] += 1
            continue
        if status == "timeout":
            stats["timeouts"] += 1
            continue
        stats["ok"] += 1
        sig = res.get("interfaces", {})
        for crd in sig.get("crds_defined", []):
            group, kind = crd.get("group"), crd.get("kind")
            if not group or not kind:
                continue
            cid = f"crd:{group}/{kind}"
            upsert_node(con, cid, "crd", f"{kind}.{group}", scope=crd.get("scope"))
            upsert_edge(con, cid, _apigroup(con, group), "in_group")
            upsert_edge(con, rid, cid, "owns_crd", via="crd-manifest")
            stats["crds"] += 1
            stats["owns"] += 1
        for key, rel in (("csv_owned_crds", "owns_crd"), ("csv_required_crds", "requires_crd")):
            for c in sig.get(key, []):
                full = c.get("name") or ""
                if "." not in full:
                    continue
                _, group = full.split(".", 1)
                kind = c.get("kind") or full.split(".", 1)[0]
                cid = f"crd:{group}/{kind}"
                upsert_node(con, cid, "crd", f"{kind}.{group}")
                upsert_edge(con, cid, _apigroup(con, group), "in_group")
                upsert_edge(con, rid, cid, rel, via="csv", version=c.get("version"))
                stats["owns" if rel == "owns_crd" else "requires"] += 1
        for wh in sig.get("webhooks", []):
            for rule in wh.get("rules") or []:
                for group in rule.get("groups") or []:
                    gid = _apigroup(con, group if group else "core")
                    upsert_edge(
                        con,
                        rid,
                        gid,
                        "intercepts",
                        mutating=wh.get("mutating"),
                        resources=rule.get("resources"),
                        operations=rule.get("operations"),
                    )
                    stats["intercepts"] += 1
        rbac: dict[str, dict] = {}
        for g in sig.get("rbac_grants", []):
            for group in g.get("api_groups") or []:
                group = group if group else "core"
                agg = rbac.setdefault(group, {"verbs": set(), "wildcard": False})
                agg["verbs"].update(g.get("verbs") or [])
                if "*" in (g.get("verbs") or []) or "*" in (g.get("resources") or []):
                    agg["wildcard"] = True
        for group, agg in rbac.items():
            upsert_edge(
                con,
                rid,
                _apigroup(con, group),
                "rbac_grants",
                verbs=sorted(agg["verbs"]),
                wildcard=int(agg["wildcard"]),
            )
            stats["rbac"] += 1
        consumed: dict[str, int] = {}
        for lit in sig.get("api_group_literals", []):
            v = lit.get("value")
            if v:
                consumed[v] = consumed.get(v, 0) + 1
        for group, count in consumed.items():
            upsert_edge(
                con,
                rid,
                _apigroup(con, group),
                "consumes_group",
                evidence="group-literal",
                count=count,
            )
            stats["consumes"] += 1
    con.commit()
    return stats


# ------------------------------------------------------- L4 symbols
# tree-sitter (MIT; docs/external-dependencies.md, intake 2026-07-17) —
# optional dependency group `graph`. Extraction is exported symbols +
# per-package import aggregation ONLY (no
# cross-repo call resolution). Byte spans are kept so graph nodes can
# round-trip back into source.
TS_LANGS: dict = {}


def _load_ts_langs() -> dict:
    if TS_LANGS:
        return TS_LANGS
    try:
        import tree_sitter as ts
        import tree_sitter_go
        import tree_sitter_javascript
        import tree_sitter_python
        import tree_sitter_typescript
    except ImportError:
        return TS_LANGS
    import tree_sitter as ts

    def mk(lang_fn, symbol_q, import_q):
        lang = ts.Language(lang_fn())
        return {
            "lang": lang,
            "parser": ts.Parser(lang),
            "symbols": ts.Query(lang, symbol_q),
            "imports": ts.Query(lang, import_q),
            "cursor": ts.QueryCursor,
        }

    TS_LANGS[".go"] = mk(
        tree_sitter_go.language,
        """(function_declaration name: (identifier) @func)
           (method_declaration name: (field_identifier) @method)
           (type_declaration (type_spec name: (type_identifier) @type))""",
        "(import_spec path: (interpreted_string_literal) @path)",
    )
    TS_LANGS[".py"] = mk(
        tree_sitter_python.language,
        """(module (function_definition name: (identifier) @func))
           (module (class_definition name: (identifier) @type))
           (module (decorated_definition
             definition: (function_definition name: (identifier) @func)))
           (module (decorated_definition
             definition: (class_definition name: (identifier) @type)))""",
        """(import_statement name: (dotted_name) @path)
           (import_from_statement module_name: (dotted_name) @path)""",
    )
    ts_sym = """(export_statement declaration:
                   (function_declaration name: (identifier) @func))
                (export_statement declaration:
                   (class_declaration name: (type_identifier) @type))
                (export_statement declaration: (lexical_declaration
                   (variable_declarator name: (identifier) @var)))"""
    js_sym = """(export_statement declaration:
                   (function_declaration name: (identifier) @func))
                (export_statement declaration:
                   (class_declaration name: (identifier) @type))
                (export_statement declaration: (lexical_declaration
                   (variable_declarator name: (identifier) @var)))"""
    ts_imp = "(import_statement source: (string) @path)"
    TS_LANGS[".ts"] = mk(tree_sitter_typescript.language_typescript, ts_sym, ts_imp)
    TS_LANGS[".tsx"] = mk(tree_sitter_typescript.language_tsx, ts_sym, ts_imp)
    TS_LANGS[".js"] = mk(tree_sitter_javascript.language, js_sym, ts_imp)
    return TS_LANGS


def _exported(name: str, ext: str) -> bool:
    if ext == ".go":
        return name[:1].isupper()
    if ext == ".py":
        return not name.startswith("_")
    return True  # ts/js queries already match export statements only


MAX_SYMBOL_FILE_BYTES = 1_000_000
MAX_SYMBOL_FILES = 40_000


def extract_symbols_tree(root: Path) -> dict:
    """{files, truncated, symbols[], imports{path: count}} for a checkout."""
    langs = _load_ts_langs()
    out = {"files": 0, "truncated": False, "symbols": [], "imports": {}}
    if not langs:
        out["error"] = "tree-sitter unavailable"
        return out
    for path in sorted(root.rglob("*")):
        ext = path.suffix
        if ext not in langs or not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        parts = set(Path(rel).parts[:-1])
        if parts & EXCLUDE_DIRS:
            continue
        if out["files"] >= MAX_SYMBOL_FILES:
            out["truncated"] = True
            break
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > MAX_SYMBOL_FILE_BYTES:
            continue
        out["files"] += 1
        entry = langs[ext]
        tree = entry["parser"].parse(data)
        caps = entry["cursor"](entry["symbols"]).captures(tree.root_node)
        for kind, nodes in caps.items():
            for n in nodes:
                name = n.text.decode(errors="ignore")
                if not name or not _exported(name, ext):
                    continue
                decl = n.parent or n
                out["symbols"].append(
                    {
                        "name": name,
                        "kind": kind,
                        "file": rel,
                        "line": n.start_point[0] + 1,
                        "start_byte": decl.start_byte,
                        "end_byte": decl.end_byte,
                        "lang": ext.lstrip("."),
                    }
                )
        icaps = entry["cursor"](entry["imports"]).captures(tree.root_node)
        for nodes in icaps.values():
            for n in nodes:
                imp = n.text.decode(errors="ignore").strip("\"'`")
                if not imp or imp.startswith("."):
                    continue
                out["imports"][imp] = out["imports"].get(imp, 0) + 1
    return out


def extract_repo_symbols(org: str, name: str, timeout: int = 420) -> dict:
    import shutil
    import tempfile

    cache_file = CACHE / "symbols" / f"{org}__{name}.json"
    if cache_file.is_file():
        return json.loads(cache_file.read_text())
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=f"{name}-", dir=str(CACHE))
    try:
        # org/name originate in inputs CSVs; scheme pinned by the
        # f-string, transport by GIT_ALLOW_PROTOCOL=https; `--` stops
        # option smuggling via a crafted name
        proc = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--",
                f"https://github.com/{org}/{name}",
                tmp,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
        )
        if proc.returncode != 0:
            return {"status": "clone-error"}
        sha = subprocess.run(
            ["git", "-C", tmp, "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        tree = extract_symbols_tree(Path(tmp))
        if "error" in tree:
            return {"status": "extract-error", "detail": tree["error"]}
        out = {"status": "ok", "sha": sha, **tree}
        cache_file.write_text(json.dumps(out))
        return out
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_symbols(con, limit: int | None, jobs: int) -> dict:
    repos = [
        (r[0], json.loads(r[1] or "{}"))
        for r in con.execute("SELECT id, attrs FROM nodes WHERE kind='repo'")
    ]
    gh = [
        (rid, a)
        for rid, a in repos
        if a.get("host") == "github.com" and a.get("org") and a.get("name")
    ]
    if limit:
        gh = gh[:limit]
    internal_modules = [
        r[0]
        for r in con.execute(
            "SELECT label FROM nodes WHERE kind='module' AND json_extract(attrs,'$.internal')=1"
        )
    ]
    stats = {
        "repos": len(gh),
        "ok": 0,
        "clone_errors": 0,
        "timeouts": 0,
        "truncated": 0,
        "symbols": 0,
        "import_edges": 0,
    }

    def work(item):
        rid, a = item
        return rid, extract_repo_symbols(a["org"], a["name"])

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(work, gh))

    for rid, res in results:
        status = res.get("status")
        if status in ("clone-error", "extract-error"):
            stats["clone_errors"] += 1
            continue
        if status == "timeout":
            stats["timeouts"] += 1
            continue
        stats["ok"] += 1
        if res.get("truncated"):
            stats["truncated"] += 1
        repo_path = rid.removeprefix("repo:")
        node_rows, edge_rows = [], []
        for s in res.get("symbols", []):
            sid = f"symbol:{repo_path}/{s['file']}#{s['name']}:{s['line']}"
            node_rows.append(
                (
                    sid,
                    "symbol",
                    s["name"],
                    json.dumps(
                        {
                            "sym_kind": s["kind"],
                            "lang": s["lang"],
                            "file": s["file"],
                            "line": s["line"],
                            "start_byte": s["start_byte"],
                            "end_byte": s["end_byte"],
                        }
                    ),
                )
            )
            edge_rows.append((rid, sid, "defines", "{}"))
        con.executemany(
            "INSERT OR REPLACE INTO nodes(id,kind,label,attrs) VALUES(?,?,?,?)", node_rows
        )
        con.executemany(
            "INSERT OR REPLACE INTO edges(src,dst,rel,attrs) VALUES(?,?,?,?)", edge_rows
        )
        stats["symbols"] += len(node_rows)
        for imp, count in (res.get("imports") or {}).items():
            owner = next((m for m in internal_modules if imp == m or imp.startswith(m + "/")), None)
            pid = f"srcpkg:{imp}"
            upsert_node(con, pid, "source-package", imp, internal=1 if owner else 0, module=owner)
            upsert_edge(con, rid, pid, "imports_package", count=count)
            stats["import_edges"] += 1
    con.commit()
    return stats


def q_imports_package(con, prefix: str):
    rows = con.execute(
        """
        SELECT n.label, e.src, json_extract(e.attrs,'$.count')
        FROM edges e JOIN nodes n ON n.id=e.dst
        WHERE e.rel='imports_package'
          AND (n.label=? OR n.label LIKE ?)
        ORDER BY 3 DESC""",
        (prefix, prefix + "/%"),
    ).fetchall()
    repos = {}
    for _pkg, rid, count in rows:
        r = repos.setdefault(rid, {"repo": rid, "packages": 0, "import_sites": 0})
        r["packages"] += 1
        r["import_sites"] += count or 0
    return {
        "package_prefix": prefix,
        "importing_repos": sorted(repos.values(), key=lambda x: -x["import_sites"]),
        "distinct_packages": len({p for p, _, _ in rows}),
    }


def q_exports_of(con, repo_path: str):
    rid = repo_path if repo_path.startswith("repo:") else f"repo:github.com/{repo_path}"
    rows = con.execute(
        """
        SELECT json_extract(n.attrs,'$.sym_kind'), COUNT(*)
        FROM edges e JOIN nodes n ON n.id=e.dst
        WHERE e.rel='defines' AND e.src=? GROUP BY 1""",
        (rid,),
    ).fetchall()
    return {"repo": rid, "exported_symbols": dict(rows), "total": sum(c for _, c in rows)}


# ------------------------------------------------------- L3 artifacts
def _repo_id_from_url(url: str) -> str | None:
    m = re.match(r"https?://(github\.com/[^/]+/[^/]+?)(\.git)?/?$", url or "")
    return f"repo:{m.group(1)}" if m else None


def build_artifacts(con, findings_root: Path, sbom_dir: Path | None) -> dict:
    stats = {
        "reports": 0,
        "images": 0,
        "built_from": 0,
        "ships_package": 0,
        "sboms": 0,
        "ships_module": 0,
        "sbom_unmatched": 0,
    }
    for path in sorted(findings_root.rglob("*-container-audit.json")):
        if path.is_symlink():
            continue
        try:
            report = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        meta = report.get("metadata", {})
        digest = str(meta.get("commit", ""))
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            continue
        stats["reports"] += 1
        add = meta.get("additional", {}) or {}
        image_repo = str(meta.get("repository", "")).split("@")[0]
        iid = f"image:sha256:{digest}"
        upsert_node(
            con,
            iid,
            "image",
            image_repo or iid,
            digest=f"sha256:{digest}",
            tag=add.get("image_tag"),
            base_image=add.get("base_image"),
            created=add.get("image_created"),
            platforms=add.get("platforms"),
            report=str(path.relative_to(findings_root)),
        )
        stats["images"] += 1
        vcs = add.get("vcs") or {}
        rid = _repo_id_from_url(vcs.get("url", ""))
        if rid:
            upsert_edge(
                con,
                iid,
                rid,
                "built_from",
                ref=vcs.get("ref"),
                branch=vcs.get("branch"),
                drift=(add.get("source_drift") or {}).get("ahead_by"),
            )
            stats["built_from"] += 1
        for e in (report.get("dependency_audit") or {}).get("entries", []):
            pkg = str(e.get("package", "")).split(" (")[0].strip()
            if not pkg:
                continue
            pid = f"package:{pkg}"
            upsert_node(con, pid, "package", pkg)
            upsert_edge(
                con,
                iid,
                pid,
                "ships_package",
                version=e.get("version"),
                status=e.get("status"),
                via="dependency-audit",
            )
            stats["ships_package"] += 1

    for sbom_path in sorted(sbom_dir.glob("*.cdx.json")) if sbom_dir and sbom_dir.is_dir() else []:
        try:
            sbom = json.loads(sbom_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        stats["sboms"] += 1
        comp = (sbom.get("metadata") or {}).get("component") or {}
        candidates = []
        for text in (comp.get("name", ""), comp.get("version", ""), sbom_path.name):
            m = re.search(r"sha256[:_-]?([a-f0-9]{7,64})", str(text))
            if m:
                candidates.append(m.group(1))
        stem = sbom_path.name.removesuffix(".cdx.json")
        if re.fullmatch(r"[a-f0-9]{7,64}", stem):
            candidates.append(stem)
        iid = None
        for cand in candidates:
            row = con.execute(
                "SELECT id FROM nodes WHERE kind='image' AND id LIKE ?", (f"image:sha256:{cand}%",)
            ).fetchone()
            if row:
                iid = row[0]
                break
        if not iid:
            stats["sbom_unmatched"] += 1
            continue
        for c in sbom.get("components", []):
            purl = c.get("purl") or ""
            if purl.startswith("pkg:golang/"):
                mod = purl.removeprefix("pkg:golang/").split("@")[0]
                mid = f"module:{mod}"
                upsert_node(con, mid, "module", mod)
                upsert_edge(con, iid, mid, "ships_module", version=c.get("version"), via="sbom")
                stats["ships_module"] += 1
            elif purl.startswith(("pkg:npm/", "pkg:rpm/", "pkg:pypi/")):
                pid = f"package:{c.get('name')}"
                upsert_node(con, pid, "package", c.get("name"))
                upsert_edge(
                    con,
                    iid,
                    pid,
                    "ships_package",
                    version=c.get("version"),
                    via="sbom",
                    ecosystem=purl.split("/")[0].split(":")[1],
                )
                stats["ships_package"] += 1
    con.commit()
    return stats


def q_ships_module(con, module_path: str):
    rows = con.execute(
        """
        SELECT n.label, json_extract(e.attrs,'$.version'),
               json_extract(n.attrs,'$.tag')
        FROM edges e JOIN nodes n ON n.id=e.src
        WHERE e.rel='ships_module' AND e.dst=?""",
        (f"module:{module_path}",),
    ).fetchall()
    return {
        "module": module_path,
        "images": [{"image": r[0], "version": r[1], "tag": r[2]} for r in rows],
    }


# ------------------------------------------------------------------ queries
def q_blast_radius(con, module_path: str):
    # Accept either a bare module path (legacy Go callers, wrapped here) or a
    # fully-formed node id (`module:...` / `pkg:<eco>/...`). The display
    # `module` field strips a leading `module:` so the Go path is byte-
    # identical to before.
    node_id = (
        module_path if module_path.startswith(("module:", "pkg:")) else f"module:{module_path}"
    )
    display = node_id[len("module:") :] if node_id.startswith("module:") else node_id
    rows = con.execute(
        """
        SELECT e.src, json_extract(e.attrs,'$.version'),
               json_extract(e.attrs,'$.indirect')
        FROM edges e WHERE e.rel='depends_on' AND e.dst=?
        ORDER BY json_extract(e.attrs,'$.indirect'), e.src
    """,
        (node_id,),
    ).fetchall()
    products = con.execute(
        """
        SELECT DISTINCT p.label FROM edges dep
        JOIN edges ship ON ship.dst = dep.src
             AND ship.rel IN ('ships','contains','includes')
        JOIN nodes p ON p.id = ship.src
        WHERE dep.rel='depends_on' AND dep.dst=?
    """,
        (node_id,),
    ).fetchall()
    return {
        "module": display,
        "requiring_repos": [{"repo": r, "version": v, "indirect": bool(i)} for r, v, i in rows],
        "repo_count": len(rows),
        "product_surfaces": sorted(p[0] for p in products),
    }


def q_top_shared(con, limit: int):
    return [
        {"module": r[0], "dependent_repos": r[1], "internal": bool(r[2]), "ecosystem": r[3]}
        for r in con.execute(
            """
        SELECT n.label, COUNT(DISTINCT e.src),
               json_extract(n.attrs,'$.internal'),
               COALESCE(json_extract(n.attrs,'$.ecosystem'),'Go')
        FROM edges e JOIN nodes n ON n.id=e.dst
        WHERE e.rel='depends_on'
        GROUP BY e.dst ORDER BY 2 DESC LIMIT ?""",
            (limit,),
        )
    ]


def q_crd_consumers(con, group: str):
    """Everyone with a declared or evidenced relationship to an API group:
    the cross-product coupling picture around one interface."""

    def rows(rel):
        return [
            {"repo": r[0], "attrs": json.loads(r[1] or "{}")}
            for r in con.execute(
                "SELECT src, attrs FROM edges WHERE rel=? AND dst=?", (rel, f"apigroup:{group}")
            )
        ]

    owners = [
        {"crd": r[0], "owner": r[1]}
        for r in con.execute(
            """
        SELECT c.label, o.src FROM edges g
        JOIN nodes c ON c.id=g.src
        JOIN edges o ON o.dst=c.id AND o.rel='owns_crd'
        WHERE g.rel='in_group' AND g.dst=?""",
            (f"apigroup:{group}",),
        )
    ]
    return {
        "api_group": group,
        "crd_owners": owners,
        "requires_crd": [
            {"repo": r[0]}
            for r in con.execute(
                """
        SELECT DISTINCT e.src FROM edges e
        JOIN edges g ON g.src=e.dst AND g.rel='in_group'
        WHERE e.rel='requires_crd' AND g.dst=?""",
                (f"apigroup:{group}",),
            )
        ],
        "consumes": rows("consumes_group"),
        "rbac_grants": rows("rbac_grants"),
        "intercepts": rows("intercepts"),
    }


def q_internal_coupling(con, limit: int):
    return [
        {
            "module": r[0],
            "owner_repo": r[1],
            "dependent_repos": r[2],
            "sustaining_fork": bool(r[3]),
            "ecosystem": r[4],
        }
        for r in con.execute(
            """
        SELECT n.label, json_extract(n.attrs,'$.owner_repo'),
               COUNT(DISTINCT e.src),
               COALESCE(json_extract(n.attrs,'$.sustaining_fork'), 0),
               COALESCE(json_extract(n.attrs,'$.ecosystem'),'Go')
        FROM edges e JOIN nodes n ON n.id=e.dst
        WHERE e.rel='depends_on'
          AND json_extract(n.attrs,'$.internal')=1
        GROUP BY e.dst ORDER BY 3 DESC LIMIT ?""",
            (limit,),
        )
    ]


def write_stats(con, out_dir: Path) -> dict:
    kinds = dict(con.execute("SELECT kind, COUNT(*) FROM nodes GROUP BY kind ORDER BY 2 DESC"))
    rels = dict(con.execute("SELECT rel, COUNT(*) FROM edges GROUP BY rel ORDER BY 2 DESC"))
    internal = con.execute(
        "SELECT COUNT(*) FROM nodes WHERE kind='module' AND json_extract(attrs,'$.internal')=1"
    ).fetchone()[0]
    top = q_top_shared(con, 15)
    coupling = q_internal_coupling(con, 15)
    summary = {
        "nodes_by_kind": kinds,
        "edges_by_rel": rels,
        "internal_modules": internal,
        "top_shared_modules": top,
        "top_internal_coupling": coupling,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "portfolio-graph-summary.json").write_text(json.dumps(summary, indent=2))
    lines = [
        "# Portfolio Graph — Stats (L0 spine + L1 dependencies)",
        "",
        "| Node kind | Count |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in kinds.items()]
    lines += ["", "| Edge rel | Count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in rels.items()]
    eco_rows = con.execute(
        "SELECT COALESCE(json_extract(attrs,'$.ecosystem'),'Go') eco, "
        "COUNT(*) FROM edges WHERE rel='depends_on' GROUP BY eco "
        "ORDER BY 2 DESC"
    ).fetchall()
    if eco_rows:
        lines += [
            "",
            "## L1 dependency edges by ecosystem",
            "",
            "| Ecosystem | depends_on edges |",
            "|---|---|",
        ]
        lines += [f"| {e} | {c} |" for e, c in eco_rows]
        lines += [
            "",
            "> Note: `docker` and `helm` are graph / blast-radius "
            "surfaces (base images, chart deps) — they have no OSV CVE "
            "lane; `actions` pins are OSV-mappable.",
        ]
    lines += [
        "",
        f"Internal (portfolio-owned) modules: **{internal}**",
        "",
        "## Top shared modules (by dependent repos)",
        "",
        "| Module | Dependents | Internal |",
        "|---|---|---|",
    ]
    lines += [
        f"| {t['module']} | {t['dependent_repos']} | {'yes' if t['internal'] else ''} |"
        for t in top
    ]
    lines += [
        "",
        "## Top internal coupling (portfolio libs used by portfolio repos)",
        "",
        "| Module | Owner repo | Dependents | Sustaining fork |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {t['module']} | {t['owner_repo'] or '?'} | "
        f"{t['dependent_repos']} | "
        f"{'yes' if t.get('sustaining_fork') else ''} |"
        for t in coupling
    ]
    if kinds.get("api-group"):
        top_groups = con.execute("""
            SELECT n.label, COUNT(DISTINCT e.src) FROM edges e
            JOIN nodes n ON n.id=e.dst
            WHERE e.rel IN ('consumes_group','rbac_grants','intercepts',
                            'requires_crd')
            GROUP BY e.dst ORDER BY 2 DESC LIMIT 15""").fetchall()
        wildcard = con.execute(
            "SELECT COUNT(DISTINCT src) FROM edges WHERE rel='rbac_grants' "
            "AND json_extract(attrs,'$.wildcard')=1"
        ).fetchone()[0]
        lines += [
            "",
            "## Interface layer (L2)",
            "",
            f"CRDs: **{kinds.get('crd', 0)}** across "
            f"**{kinds['api-group']}** API groups; repos with a "
            f"wildcard RBAC grant: **{wildcard}**.",
            "",
            "`owns_crd` edges carry `via`: `csv` = declared "
            "ownership; `crd-manifest` = ships the CRD manifest "
            "(vendoring other projects' CRDs is common — not proof "
            "of ownership).",
            "",
            "| API group | Coupled repos (consume/rbac/intercept/require) |",
            "|---|---|",
        ]
        lines += [f"| {g} | {c} |" for g, c in top_groups]
    if kinds.get("symbol"):
        top_internal_pkgs = con.execute("""
            SELECT n.label, COUNT(DISTINCT e.src),
                   SUM(json_extract(e.attrs,'$.count'))
            FROM edges e JOIN nodes n ON n.id=e.dst
            WHERE e.rel='imports_package'
              AND json_extract(n.attrs,'$.internal')=1
            GROUP BY e.dst ORDER BY 2 DESC LIMIT 12""").fetchall()
        lines += [
            "",
            "## Symbol layer (L4)",
            "",
            f"Exported symbols: **{kinds['symbol']}** with byte-span "
            f"provenance; source packages: "
            f"**{kinds.get('source-package', 0)}** "
            f"(imports_package edges aggregate per repo).",
            "",
            "### Most-imported internal packages (package-level, finer than module deps)",
            "",
            "| Package | Importing repos | Import sites |",
            "|---|---|---|",
        ]
        lines += [f"| {p} | {r} | {s or 0} |" for p, r, s in top_internal_pkgs]
    if kinds.get("image"):
        sbom_edges = con.execute(
            "SELECT COUNT(*) FROM edges WHERE rel IN "
            "('ships_module','ships_package') AND "
            "json_extract(attrs,'$.via')='sbom'"
        ).fetchone()[0]
        lines += [
            "",
            "## Artifact layer (L3)",
            "",
            f"Images: **{kinds['image']}** (from container-audit "
            f"reports); `built_from` edges: "
            f"**{rels.get('built_from', 0)}**; SBOM-backed "
            f"ships_module/ships_package edges: **{sbom_edges}**. "
            f"Accrues as /secure-container-audit runs.",
        ]
    (out_dir / "portfolio-graph-stats.md").write_text("\n".join(lines) + "\n")
    return summary


def _parse_ecosystems(spec: str) -> set:
    """Resolve the --ecosystems flag. "all" -> ALL_ECOSYSTEMS (the six
    language-gated package ecosystems plus the three universal surfaces
    docker/actions/helm); otherwise a comma-separated list taken verbatim."""
    spec = (spec or "all").strip()
    if spec == "all":
        return set(ALL_ECOSYSTEMS)
    return {e.strip() for e in spec.split(",") if e.strip()}


def _deps_multi_stats_path(db_path, stats_out=None) -> Path:
    """Default persistence location for build_deps_multi's return dict:
    deps-multi-stats.json in the db's parent (graph) dir. --stats-out
    overrides. Kept separate so the smoke checker can find it deterministically
    next to the db without re-deriving the convention."""
    if stats_out:
        return Path(stats_out)
    return Path(db_path).resolve().parent / "deps-multi-stats.json"


def _write_deps_multi_stats(stats: dict, db_path, stats_out=None) -> Path:
    """Persist build_deps_multi's per-ecosystem + global stats dict so
    downstream tooling (the harness's smoke_deps_multi.py, under
    harnessing/portfolio-graph/scripts/) can use the honest
    manifest-based coverage denominator (`repos_with_manifest`) instead of the
    language-cache overcount. Does not alter build_deps_multi's logic — just
    serializes what it already returns."""
    out = _deps_multi_stats_path(db_path, stats_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    return out


def _print_deps_multi_report(stats: dict, ecosystems) -> None:
    print(
        f"L1 trees: {stats.get('repos_tree_ok', 0)} ok "
        f"({stats.get('repos_tree_absent', 0)} absent, "
        f"{stats.get('repos_tree_error', 0)} error), "
        f"{stats.get('repos_truncated', 0)} truncated "
        f"({stats.get('truncated_fallback', 0)} root-fallback); "
        f"{stats.get('repos_with_any_manifest', 0)} repos w/ a manifest, "
        f"{stats.get('repos_with_zero_manifests', 0)} with none"
    )
    if stats.get("rate_limited_incomplete") or stats.get("repos_ratelimited_skipped", 0):
        state = "INCOMPLETE" if stats.get("rate_limited_incomplete") else "paused/resumed"
        print(
            f"L1 RATE-LIMIT: run {state} — "
            f"{stats.get('repos_ratelimited_skipped', 0)} repo(s) left "
            f"unvisited (uncached); re-run to resume via the disk cache"
        )
    for eco in sorted(ecosystems):
        st = stats.get(eco)
        if not st:
            continue
        sample = ", ".join(st["manifest_paths_sample"][:3]) or "-"
        print(
            f"L1 {eco}: {st['repos_with_manifest']} repos w/ manifest, "
            f"{st['manifests_fetched_ok']} fetched ok ({st['absent']} "
            f"absent, {st['error']} errors, {st['parse_empty']} "
            f"parse-empty); {st['pkg_nodes']} pkg nodes, {st['dep_edges']} "
            f"depends_on edges [e.g. {sample}]"
        )


def _resolve_portfolio_paths(
    spine: str | None,
    db: str | None,
    *,
    default_spine: Path,
    default_db: Path,
) -> tuple[Path, Path]:
    """CLI default paths when --spine / --db are omitted."""
    return (
        Path(spine) if spine else default_spine,
        Path(db) if db else default_db,
    )


def build(
    spine: Path,
    db: Path,
    *,
    limit: int | None = None,
    jobs: int = 8,
    enrich_refs: str | None = None,
    allow_stale: bool = False,
    max_age_days: int = 30,
    ecosystems: str = "all",
    no_universal: bool = False,
    lang_cache: str = DEFAULT_LANG_CACHE,
    stats_out: str | None = None,
    sleep_ms: int = 0,
) -> dict:
    if not spine.is_file():
        raise FileNotFoundError(f"spine not found: {spine} — run /repo-graph first")
    fresh, reasons = check_spine_freshness(spine, _default_inputs_dir(spine), max_age_days)
    if not fresh and not allow_stale:
        raise ValueError("spine is STALE: " + "; ".join(reasons))
    con = db_connect(db)
    s0 = build_spine(con, spine)
    s1 = build_deps(con, limit, jobs)
    result: dict = {"l0": s0, "l1": s1, "stale": not fresh, "stale_reasons": reasons}
    if enrich_refs is not None:
        result["l1_refs"] = build_ref_deps(con, enrich_refs, jobs)
    requested = _parse_ecosystems(ecosystems)
    if no_universal:
        requested -= set(UNIVERSAL_ECOSYSTEMS)
    non_go = {e for e in requested if e not in ("go", "Go")}
    if non_go:
        sm = build_deps_multi(con, limit, min(jobs, 4), non_go, lang_cache, sleep_ms=sleep_ms)
        result["l1_multi"] = sm
        result["stats_path"] = str(_write_deps_multi_stats(sm, db, stats_out))
    return result


def stats(db: Path, out_dir: Path = Path()) -> dict:
    con = db_connect(db)
    return write_stats(con, out_dir)


def query(
    db: Path,
    name: str,
    arg: str | None = None,
    *,
    limit: int = 20,
    ecosystem: str = "go",
):
    con = db_connect(db)
    if name == "blast-radius":
        if not arg:
            raise ValueError("blast-radius needs a module path")
        return q_blast_radius(con, dep_node_id(arg, ecosystem))
    if name == "crd-consumers":
        if not arg:
            raise ValueError("crd-consumers needs an API group")
        return q_crd_consumers(con, arg)
    if name == "ships-module":
        if not arg:
            raise ValueError("ships-module needs a module path")
        return q_ships_module(con, arg)
    if name == "imports-package":
        if not arg:
            raise ValueError("imports-package needs a package path prefix")
        return q_imports_package(con, arg)
    if name == "exports-of":
        if not arg:
            raise ValueError("exports-of needs a repo (org/name)")
        return q_exports_of(con, arg)
    if name == "top-shared":
        return q_top_shared(con, limit)
    if name == "internal-coupling":
        return q_internal_coupling(con, limit)
    raise ValueError(f"unknown query: {name}")
