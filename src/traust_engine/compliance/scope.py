"""Compliance-boundary scope resolver (Phase 6).

Resolves a declared compliance boundary (progress-tracker/configs/
compliance/compliance-scope.yaml, schema-gated) into the concrete
repo set an assessment run scopes to. Frameworks scope SYSTEMS, not
repos: the registry declares boundaries at service/product level and
this resolver derives membership from the repo-graph product mapping
(`product:* --ships--> repo:*` edges — the same resolution
/isolation-review uses), applies the declared include/exclude edges,
and returns `org/name` repos in the exact shape
`run_compliance_check.py --repos` consumes.

Resolution modes:
  repo-graph      product-mapping edges (organizational assertion)
  deployment-iac  a declared deployment inventory — repos a
                  service-declaration IaC checkout declares as deployed
                  for the service, every row citing its IaC source
                  (adopted after a boundary was withdrawn on the strength
                  of graph edges alone: graph edges are what a product
                  CLAIMS to ship; deployment IaC is evidence of what
                  actually deploys — prefer it whenever the evidence
                  inventory exists)
  explicit        include[] only, for boundaries with neither

Doctrine:
- The graph RESOLVES scope; the registry DECLARES it. Neither stores
  the other's job: a product gaining a repo flows into scope on the
  next resolution; only genuine boundary decisions need registry edits.
- Fail-loud contract: an unknown boundary, an unresolvable product, or
  an exclude that matches nothing in the resolved set (a stale boundary
  claim) is an error, never a silent shrink.
- Draft boundaries (`declared_by: draft:...`) resolve normally but are
  flagged `draft: true` so consumers label their outputs.

Consumers: run_compliance_check.py (--boundary), the compliance
dashboard's in-scope coverage cut, and /compliance-check interview
(Phase 7) which writes the entries this resolves.

Usage:
    python3 resolve_compliance_scope.py --boundary <id>
        [--scope <compliance-scope.yaml>] [--graph <repo-graph.json>]
        [--list] [--json]
Exit 0 with the resolved set; 1 on any resolution failure.
"""

from __future__ import annotations

import json
from pathlib import Path

from traust_engine.locations import (
    configured_locations,
    progress_tracker_dir,
    repo_graph,
)


def default_scope_path(progress_tracker: Path | None = None) -> Path | None:
    pt = (
        progress_tracker
        if progress_tracker is not None
        else progress_tracker_dir(configured_locations())
    )
    return pt / "configs" / "compliance" / "compliance-scope.yaml" if pt else None


def default_graph() -> Path | None:
    """The repo-graph path under the config-owned analysis-results, or None."""
    return repo_graph(configured_locations())


try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


class ScopeError(RuntimeError):
    pass


def load_scope(path: Path) -> dict:
    if yaml is None:
        raise ScopeError("PyYAML required")
    if not path.is_file():
        raise ScopeError(f"scope registry not found: {path}")
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "boundaries" not in doc:
        raise ScopeError(f"not a scope registry (no 'boundaries'): {path}")
    doc["_scope_dir"] = path.parent  # relative deployment inventories
    return doc


def _repo_from_node(node_id: str) -> str | None:
    """repo:github.com/org/name -> org/name (non-github hosts keep
    host prefix stripped only when the org/name shape survives)."""
    if not node_id.startswith("repo:"):
        return None
    rest = node_id[len("repo:") :]
    parts = rest.split("/", 1)
    if len(parts) == 2 and "/" in parts[1]:
        # host/org/name -> org/name
        return parts[1]
    return rest


def graph_product_repos(graph_path: Path, product: str) -> list[str]:
    if not graph_path.is_file():
        raise ScopeError(
            f"repo-graph not found: {graph_path} — build it with /repo-graph before resolving scope"
        )
    g = json.loads(graph_path.read_text(encoding="utf-8"))
    nodes = g.get("nodes") or []
    products = [n for n in nodes if n.get("type") == "product"]
    matches = [n for n in products if n.get("id") == product]
    if not matches:
        by_label = [n for n in products if n.get("label") == product]
        if len(by_label) > 1:
            ids = ", ".join(n["id"] for n in by_label)
            raise ScopeError(
                f"product label {product!r} is ambiguous ({ids}) — "
                f"declare the node id in the registry"
            )
        matches = by_label
    if not matches:
        raise ScopeError(
            f"product {product!r} not found in the repo-graph "
            f"(node id or exact label) — nothing resolved, refusing "
            f"to return an empty boundary"
        )
    pid = matches[0]["id"]
    repos = sorted(
        {
            r
            for e in (g.get("edges") or [])
            if e.get("from") == pid and (r := _repo_from_node(str(e.get("to") or ""))) is not None
        }
    )
    if not repos:
        raise ScopeError(
            f"product {pid!r} has no repo edges — an empty "
            f"boundary is a declaration error, not a result"
        )
    return repos


def resolve(scope_doc: dict, boundary_id: str, graph_path: Path | None = None) -> dict:
    graph_path = graph_path if graph_path is not None else default_graph()
    boundaries = scope_doc.get("boundaries") or {}
    if boundary_id not in boundaries:
        known = ", ".join(sorted(boundaries)) or "(none)"
        raise ScopeError(f"unknown boundary {boundary_id!r} (declared: {known})")
    b = boundaries[boundary_id]
    include = [i["repo"] for i in b.get("include") or []]
    exclude = {i["repo"]: i["reason"] for i in b.get("exclude") or []}

    if b["resolves_via"] == "deployment-iac":
        ev = b.get("deployment_evidence") or {}
        inv_path = Path(ev.get("inventory", ""))
        if not inv_path.is_absolute():
            inv_path = (scope_doc.get("_scope_dir") or Path()) / inv_path
        if not ev.get("service") or not str(ev.get("inventory", "")):
            raise ScopeError(
                f"{boundary_id}: deployment-iac requires deployment_evidence.inventory + .service"
            )
        if not inv_path.is_file():
            raise ScopeError(f"{boundary_id}: deployment inventory not found: {inv_path}")
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        svc = (inv.get("services") or {}).get(ev["service"])
        if svc is None:
            known = ", ".join(sorted(inv.get("services") or {})) or "(none)"
            raise ScopeError(
                f"{boundary_id}: service {ev['service']!r} not in inventory (declared: {known})"
            )
        rows = svc.get("repos") or []
        base, citations = [], {}
        for r in rows:
            url = str(r.get("url") or "")
            m = url.rstrip("/").split("/")
            if len(m) < 2 or not r.get("source"):
                raise ScopeError(
                    f"{boundary_id}: malformed inventory row "
                    f"{r!r} — every repo needs url + source "
                    f"(the IaC citation is the point)"
                )
            repo = "/".join(m[-2:])
            base.append(repo)
            citations[repo] = r["source"]
        if not base:
            raise ScopeError(f"{boundary_id}: inventory declares no repos for {ev['service']!r}")
    elif b["resolves_via"] == "repo-graph":
        if not b.get("product"):
            raise ScopeError(f"{boundary_id}: resolves_via=repo-graph requires 'product'")
        base = graph_product_repos(graph_path, b["product"])
    else:  # explicit
        if not include:
            raise ScopeError(
                f"{boundary_id}: resolves_via=explicit requires a non-empty include list"
            )
        base = []

    resolved = sorted(set(base) | set(include))
    stale = [r for r in exclude if r not in resolved]
    if stale:
        raise ScopeError(
            f"{boundary_id}: exclude entries match nothing in the "
            f"resolved set ({', '.join(stale)}) — stale boundary claim; "
            f"update the registry, don't let it rot"
        )
    final = [r for r in resolved if r not in exclude]
    if not final:
        raise ScopeError(f"{boundary_id}: resolution produced an empty repo set")
    result_extra = {}
    if b["resolves_via"] == "deployment-iac":
        result_extra["evidence"] = [
            {"repo": r, "source": citations[r]} for r in final if r in citations
        ]
    return {
        **result_extra,
        "boundary": boundary_id,
        "frameworks": list(b["frameworks"]),
        "repos": final,
        "excluded": [{"repo": r, "reason": exclude[r]} for r in sorted(exclude)],
        "resolves_via": b["resolves_via"],
        "product": b.get("product"),
        "declared_by": b["declared_by"],
        "declared_at": str(b["declared_at"]),
        "draft": str(b["declared_by"]).startswith("draft:"),
    }
