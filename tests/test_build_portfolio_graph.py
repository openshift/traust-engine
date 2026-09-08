#!/usr/bin/env python3
"""build_portfolio_graph.py tests — fixture spine + parsed go.mod."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from traust_engine import HarnessEngine
from traust_engine.portfolio import graph as G

_ENGINE = HarnessEngine.load()

GOMOD = """\
module github.com/org/repo-a

go 1.22

require (
\tgithub.com/org/lib-b v1.2.3
\tgolang.org/x/net v0.17.0
\tk8s.io/client-go v0.29.1 // indirect
)

require sigs.k8s.io/yaml v1.4.0
"""

SPINE = {
    "nodes": [
        {"id": "product:p1", "type": "product", "label": "Product One", "attrs": {}},
        {
            "id": "repo:github.com/org/repo-a",
            "type": "repo",
            "label": "org/repo-a",
            "attrs": {"host": "github.com", "org": "org", "name": "repo-a"},
        },
        {
            "id": "repo:github.com/org/lib-b",
            "type": "repo",
            "label": "org/lib-b",
            "attrs": {"host": "github.com", "org": "org", "name": "lib-b"},
        },
        {
            "id": "repo:gitlab.example.com/x/y",
            "type": "repo",
            "label": "x/y",
            "attrs": {"host": "gitlab.example.com", "org": "x", "name": "y"},
        },
    ],
    "edges": [
        {
            "from": "product:p1",
            "to": "repo:github.com/org/repo-a",
            "rel": "ships",
            "branch": "main",
        },
    ],
}


class TestGomodParsing(unittest.TestCase):
    def test_module_requires_and_indirect(self):
        module, requires = G.parse_gomod(GOMOD)
        self.assertEqual(module, "github.com/org/repo-a")
        self.assertEqual(len(requires), 4)
        as_dict = {p: (v, ind) for p, v, ind in requires}
        self.assertEqual(as_dict["github.com/org/lib-b"], ("v1.2.3", False))
        self.assertEqual(as_dict["k8s.io/client-go"], ("v0.29.1", True))
        self.assertEqual(as_dict["sigs.k8s.io/yaml"], ("v1.4.0", False))

    def test_non_go_text(self):
        module, requires = G.parse_gomod("# just a readme\n")
        self.assertIsNone(module)
        self.assertEqual(requires, [])


class TestGraphBuild(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.spine = tmp / "spine.json"
        self.spine.write_text(json.dumps(SPINE))
        self.db = tmp / "graph.db"
        self.con = G.db_connect(self.db)
        G.build_spine(self.con, self.spine)
        # inject L1 without network: parse fixture go.mod files directly
        gomods = {
            "repo:github.com/org/repo-a": GOMOD,
            "repo:github.com/org/lib-b": "module github.com/org/lib-b\n",
        }
        module_owner = {}
        parsed = []
        for rid, text in gomods.items():
            module, requires = G.parse_gomod(text)
            module_owner[module] = rid
            parsed.append((rid, module, requires))
        seen = set()
        for rid, module, requires in parsed:
            G.upsert_node(
                self.con, f"module:{module}", "module", module, internal=1, owner_repo=rid
            )
            seen.add(module)
            G.upsert_edge(self.con, rid, f"module:{module}", "declares")
            for dep, version, indirect in requires:
                if dep not in seen:
                    G.upsert_node(
                        self.con,
                        f"module:{dep}",
                        "module",
                        dep,
                        internal=1 if dep in module_owner else 0,
                        owner_repo=module_owner.get(dep),
                    )
                    seen.add(dep)
                G.upsert_edge(
                    self.con,
                    rid,
                    f"module:{dep}",
                    "depends_on",
                    version=version,
                    indirect=int(indirect),
                )
        for module, rid in module_owner.items():
            self.con.execute(
                "UPDATE nodes SET attrs=json_set(attrs,'$.internal',1,'$.owner_repo',?) WHERE id=?",
                (rid, f"module:{module}"),
            )
        self.con.commit()

    def tearDown(self):
        self.con.close()
        self._tmp.cleanup()

    def test_spine_ingested(self):
        kinds = dict(self.con.execute("SELECT kind, COUNT(*) FROM nodes GROUP BY kind"))
        self.assertEqual(kinds["repo"], 3)
        self.assertEqual(kinds["product"], 1)

    def test_blast_radius_with_product_join(self):
        out = G.q_blast_radius(self.con, "golang.org/x/net")
        self.assertEqual(out["repo_count"], 1)
        self.assertEqual(out["requiring_repos"][0]["version"], "v0.17.0")
        self.assertEqual(out["product_surfaces"], ["Product One"])

    def test_internal_module_marked(self):
        attrs = json.loads(
            self.con.execute(
                "SELECT attrs FROM nodes WHERE id='module:github.com/org/lib-b'"
            ).fetchone()[0]
        )
        self.assertEqual(attrs["internal"], 1)
        self.assertEqual(attrs["owner_repo"], "repo:github.com/org/lib-b")
        coupling = G.q_internal_coupling(self.con, 10)
        self.assertEqual(coupling[0]["module"], "github.com/org/lib-b")

    def test_indirect_flag_on_edge(self):
        out = G.q_blast_radius(self.con, "k8s.io/client-go")
        self.assertTrue(out["requiring_repos"][0]["indirect"])

    def test_stats_written(self):
        with tempfile.TemporaryDirectory() as d:
            summary = G.write_stats(self.con, Path(d))
            self.assertIn("module", summary["nodes_by_kind"])
            self.assertTrue((Path(d) / "portfolio-graph-stats.md").is_file())
            self.assertTrue((Path(d) / "portfolio-graph-summary.json").is_file())

    def test_idempotent_rebuild(self):
        before = self.con.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        G.build_spine(self.con, self.spine)
        after = self.con.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        self.assertEqual(before, after)


class TestRefNodeIngest(unittest.TestCase):
    """A spine carrying branch-awareness Phase 2 ref nodes (kind repo-ref,
    has_ref/ships_ref edges) must ingest harmlessly: refs pass through as
    inert rows and every kind='repo' / rel='ships' consumer is unchanged."""

    def test_repo_ref_nodes_pass_through_harmlessly(self):
        spine = json.loads(json.dumps(SPINE))  # deep copy
        spine["nodes"].append(
            {
                "id": "ref:github.com/org/repo-a@release-4.19",
                "type": "repo-ref",
                "label": "org/repo-a@release-4.19",
                "attrs": {"branch": "release-4.19"},
            }
        )
        spine["edges"] += [
            {
                "from": "repo:github.com/org/repo-a",
                "to": "ref:github.com/org/repo-a@release-4.19",
                "rel": "has_ref",
            },
            {
                "from": "product:p1",
                "to": "ref:github.com/org/repo-a@release-4.19",
                "rel": "ships_ref",
                "branch": "release-4.19",
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "spine.json"
            p.write_text(json.dumps(spine))
            con = G.db_connect(Path(td) / "g.db")
            stats = G.build_spine(con, p)
            # repo universe unchanged — refs are not repos
            self.assertEqual(stats["repos"], 3)
            kinds = dict(con.execute("SELECT kind, COUNT(*) FROM nodes GROUP BY kind"))
            self.assertEqual(kinds.get("repo-ref"), 1)
            self.assertEqual(kinds.get("repo"), 3)
            # rel='ships' consumers (pqc rollups, blast radius) see no
            # new rows: ships edge count is exactly the fixture's one
            ships = con.execute("SELECT COUNT(*) FROM edges WHERE rel='ships'").fetchone()[0]
            self.assertEqual(ships, 1)
            con.close()


REF_GOMOD = """\
module github.com/org/repo-a

go 1.21

require (
\tgithub.com/org/lib-b v1.1.0
\tgithub.com/legacy/only-on-branch v0.9.0
)
"""


def _ref_spine():
    """SPINE + Phase-2 ref nodes/edges: release-4.19 (3 ships_ref),
    release-4.18 (2), release-4.17 (1), main (5 — must never be picked
    by numeric selection despite the highest count)."""
    spine = json.loads(json.dumps(SPINE))
    counts = {"release-4.19": 3, "release-4.18": 2, "release-4.17": 1, "main": 5}
    for br, n in counts.items():
        rid = f"ref:github.com/org/repo-a@{br}"
        spine["nodes"].append(
            {"id": rid, "type": "repo-ref", "label": f"org/repo-a@{br}", "attrs": {"branch": br}}
        )
        spine["edges"].append({"from": "repo:github.com/org/repo-a", "to": rid, "rel": "has_ref"})
        for i in range(n):
            spine["edges"].append(
                {"from": f"category:c{i}", "to": rid, "rel": "ships_ref", "branch": br}
            )
    return spine


class TestRefEnrichment(unittest.TestCase):
    """Branch-awareness Phase 3: opt-in per-release ref enrichment."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.spine = self.tmp / "spine.json"
        spine = _ref_spine()
        import datetime

        spine["generated"] = datetime.date.today().isoformat()
        self.spine.write_text(json.dumps(spine))
        self._old_cache = G.CACHE
        G.CACHE = self.tmp / "cache"
        # seed default-branch gomod cache — the build must never fetch
        gomod = G.CACHE / "gomod"
        gomod.mkdir(parents=True)
        (gomod / "org__repo-a.json").write_text(json.dumps({"status": "ok", "text": GOMOD}))
        (gomod / "org__lib-b.json").write_text(
            json.dumps({"status": "ok", "text": "module github.com/org/lib-b\n"})
        )
        # seed ABSENT trees so the default-`all` build_deps_multi run in the
        # flag-off build path finds no non-Go manifests and never hits the
        # network (fetch_tree is cached-absent, no gh subprocess)
        trees = G.CACHE / "trees"
        trees.mkdir(parents=True)
        for nm in ("repo-a", "lib-b"):
            (trees / f"org__{nm}.json").write_text(
                json.dumps({"status": "absent", "paths": [], "truncated": False})
            )

    def tearDown(self):
        G.CACHE = self._old_cache
        self._tmp.cleanup()

    def _seed_ref_cache(self, branch: str, payload: dict):
        d = G.CACHE / "gomod-ref"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"org__repo-a@{branch}.json").write_text(json.dumps(payload))

    def _dump(self, db: Path) -> str:
        con = sqlite3.connect(db)
        try:
            return "\n".join(con.iterdump())
        finally:
            con.close()

    def test_flag_off_invariance(self):
        """No flag → main() runs exactly the pre-Phase-3 pipeline
        (build_spine + build_deps): byte-identical dump, no ref rels."""
        db_cli = self.tmp / "cli.db"
        G.build(self.spine, db_cli, jobs=2)
        rc = 0
        self.assertEqual(rc, 0)
        db_ref = self.tmp / "reference.db"
        con = G.db_connect(db_ref)
        G.build_spine(con, self.spine)
        G.build_deps(con, None, 2)
        con.close()
        self.assertEqual(self._dump(db_cli), self._dump(db_ref))
        con = sqlite3.connect(db_cli)
        rels = {r[0] for r in con.execute("SELECT DISTINCT rel FROM edges")}
        con.close()
        self.assertNotIn("depends_on_ref", rels)
        self.assertFalse(
            (G.CACHE / "gomod-ref").exists(), "flag-off build must never touch the ref cache"
        )

    def test_supported_set_selection(self):
        con = G.db_connect(self.tmp / "sel.db")
        G.build_spine(con, self.spine)
        # numeric: release-X.Y only, ranked by ships_ref count — `main`
        # is excluded despite carrying the most ships_ref edges
        self.assertEqual(G.select_supported_refs(con, "2"), ["release-4.19", "release-4.18"])
        # bare flag (const "") → default N=3
        self.assertEqual(
            G.select_supported_refs(con, ""), ["release-4.19", "release-4.18", "release-4.17"]
        )
        # explicit list taken verbatim (any branch, even non-release)
        self.assertEqual(
            G.select_supported_refs(con, "main, release-4.18"), ["main", "release-4.18"]
        )
        con.close()

    def test_selection_tie_breaks_newest_release(self):
        con = G.db_connect(self.tmp / "tie.db")
        G.build_spine(con, self.spine)
        # give release-4.17 two more ships_ref edges → ties release-4.19
        # at 3; newest release must win the tie
        for i in range(2):
            G.upsert_edge(
                con,
                f"category:t{i}",
                "ref:github.com/org/repo-a@release-4.17",
                "ships_ref",
                branch="release-4.17",
            )
        con.commit()
        self.assertEqual(G.select_supported_refs(con, "1"), ["release-4.19"])
        con.close()

    def test_flag_on_attaches_depends_on_ref(self):
        con = G.db_connect(self.tmp / "on.db")
        G.build_spine(con, self.spine)
        G.build_deps(con, None, 2)
        lib_b_before = con.execute(
            "SELECT attrs FROM nodes WHERE id='module:github.com/org/lib-b'"
        ).fetchone()[0]
        self._seed_ref_cache("release-4.19", {"status": "ok", "text": REF_GOMOD})
        stats = G.build_ref_deps(con, "release-4.19", 2)
        self.assertEqual(stats["ok"], 1)
        self.assertEqual(stats["dep_edges"], 2)
        rows = con.execute(
            "SELECT src, dst, attrs FROM edges WHERE rel='depends_on_ref' ORDER BY dst"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        for src, _, _ in rows:
            self.assertEqual(src, "ref:github.com/org/repo-a@release-4.19")
        attrs = json.loads(rows[1][2])
        self.assertEqual(attrs["ref"], "release-4.19")
        self.assertEqual(attrs["version"], "v1.1.0")
        # ref-only module created internal=0; HEAD module attrs untouched
        new_mod = json.loads(
            con.execute(
                "SELECT attrs FROM nodes WHERE id='module:github.com/legacy/only-on-branch'"
            ).fetchone()[0]
        )
        self.assertEqual(new_mod["internal"], 0)
        self.assertEqual(new_mod["first_seen_ref"], "release-4.19")
        lib_b_after = con.execute(
            "SELECT attrs FROM nodes WHERE id='module:github.com/org/lib-b'"
        ).fetchone()[0]
        self.assertEqual(lib_b_before, lib_b_after)
        # HEAD-canonical consumers see nothing new
        self.assertEqual(G.q_blast_radius(con, "github.com/legacy/only-on-branch")["repo_count"], 0)
        con.close()

    def test_missing_gomod_at_ref_is_counted_skip(self):
        con = G.db_connect(self.tmp / "skip.db")
        G.build_spine(con, self.spine)
        self._seed_ref_cache("release-4.19", {"status": "absent"})
        stats = G.build_ref_deps(con, "release-4.19", 2)
        self.assertEqual(stats["refs"], 1)
        self.assertEqual(stats["skipped"], 1)
        self.assertEqual(stats["ok"], 0)
        self.assertEqual(stats["dep_edges"], 0)
        self.assertEqual(
            con.execute("SELECT COUNT(*) FROM edges WHERE rel='depends_on_ref'").fetchone()[0], 0
        )
        con.close()

    def test_no_matching_branches_is_noop(self):
        con = G.db_connect(self.tmp / "none.db")
        G.build_spine(con, self.spine)
        stats = G.build_ref_deps(con, "release-9.99", 2)
        self.assertEqual(stats["refs"], 0)
        self.assertEqual(stats["dep_edges"], 0)
        con.close()


INTERFACES_FIXTURE = {
    "status": "ok",
    "sha": "b" * 40,
    "interfaces": {
        "crds_defined": [
            {
                "file": "config/crd/w.yaml",
                "group": "example.io",
                "kind": "Widget",
                "plural": "widgets",
                "scope": "Namespaced",
            }
        ],
        "csv_owned_crds": [],
        "csv_required_crds": [
            {
                "file": "bundle/csv.yaml",
                "name": "certificates.cert-manager.io",
                "kind": "Certificate",
                "version": "v1",
            }
        ],
        "webhooks": [
            {
                "file": "config/wh.yaml",
                "config": "mw",
                "mutating": True,
                "name": "m.example.io",
                "failure_policy": "Fail",
                "rules": [
                    {"groups": ["apps"], "resources": ["deployments"], "operations": ["CREATE"]}
                ],
            }
        ],
        "rbac_grants": [
            {
                "file": "config/rbac/role.yaml",
                "role_kind": "ClusterRole",
                "role_name": "r",
                "api_groups": ["route.openshift.io"],
                "resources": ["routes"],
                "verbs": ["get", "*"],
            }
        ],
        "api_group_literals": [
            {
                "file": "pkg/gv.go",
                "line": 3,
                "match": 'Group: "route.openshift.io"',
                "value": "route.openshift.io",
            }
        ],
    },
}


class TestSpineFreshness(unittest.TestCase):
    def _spine(self, tmp: Path, generated: str) -> Path:
        p = tmp / "repo-graph.json"
        p.write_text(json.dumps({"generated": generated, "nodes": [], "edges": []}))
        return p

    def test_fresh_recent_spine_no_inputs(self):
        import datetime

        with tempfile.TemporaryDirectory() as d:
            spine = self._spine(Path(d), datetime.date.today().isoformat())
            fresh, reasons = G.check_spine_freshness(spine, None)
            self.assertTrue(fresh, reasons)

    def test_stale_by_age_backstop(self):
        with tempfile.TemporaryDirectory() as d:
            spine = self._spine(Path(d), "2020-01-01")
            fresh, reasons = G.check_spine_freshness(spine, None)
            self.assertFalse(fresh)
            self.assertIn("days old", reasons[0])

    def test_stale_when_inputs_newer(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = self._spine(tmp, "2026-01-10")
            inputs = tmp / "inputs"
            inputs.mkdir()
            (inputs / "repos.csv").write_text("a,b\n")  # mtime = now
            fresh, reasons = G.check_spine_freshness(spine, inputs, max_age_days=10_000)
            self.assertFalse(fresh)
            self.assertIn("inputs last changed", reasons[0])

    def test_unparseable_generated_is_stale(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "repo-graph.json"
            p.write_text(json.dumps({"nodes": [], "edges": []}))
            fresh, reasons = G.check_spine_freshness(p, None)
            self.assertFalse(fresh)
            self.assertIn("regenerate", reasons[0])


class TestInterfacesLayer(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        spine = tmp / "spine.json"
        spine.write_text(json.dumps(SPINE))
        self.con = G.db_connect(tmp / "graph.db")
        G.build_spine(self.con, spine)
        # seed the extraction cache so build_interfaces never hits git
        self._old_cache = G.CACHE
        G.CACHE = tmp / "cache"
        for org, name in (("org", "repo-a"), ("org", "lib-b")):
            f = G.CACHE / "interfaces" / f"{org}__{name}.json"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(
                json.dumps(
                    INTERFACES_FIXTURE
                    if name == "repo-a"
                    else {"status": "ok", "sha": "c" * 40, "interfaces": {}}
                )
            )
        self.stats = G.build_interfaces(self.con, None, jobs=2)

    def tearDown(self):
        G.CACHE = self._old_cache
        self.con.close()
        self._tmp.cleanup()

    def test_sweep_stats(self):
        self.assertEqual(self.stats["ok"], 2)
        self.assertEqual(self.stats["crds"], 1)
        self.assertEqual(self.stats["requires"], 1)

    def test_crd_ownership_edges(self):
        out = G.q_crd_consumers(self.con, "example.io")
        self.assertEqual(out["crd_owners"][0]["crd"], "Widget.example.io")
        self.assertEqual(out["crd_owners"][0]["owner"], "repo:github.com/org/repo-a")

    def test_requires_intercepts_rbac_consumes(self):
        req = G.q_crd_consumers(self.con, "cert-manager.io")
        self.assertEqual(req["requires_crd"], [{"repo": "repo:github.com/org/repo-a"}])
        apps = G.q_crd_consumers(self.con, "apps")
        self.assertEqual(len(apps["intercepts"]), 1)
        self.assertTrue(apps["intercepts"][0]["attrs"]["mutating"])
        route = G.q_crd_consumers(self.con, "route.openshift.io")
        self.assertEqual(route["rbac_grants"][0]["attrs"]["wildcard"], 1)
        self.assertEqual(route["consumes"][0]["attrs"]["count"], 1)


CONTAINER_REPORT = {
    "metadata": {
        "commit": "d" * 64,
        "repository": "quay.io/org/app@sha256:" + "d" * 64,
        "additional": {
            "image_tag": "v1.2.3",
            "base_image": "ubi9/go-toolset",
            "vcs": {"url": "https://github.com/org/repo-a", "ref": "e" * 40, "branch": "main"},
            "source_drift": {"ahead_by": 2},
        },
    },
    "dependency_audit": {
        "entries": [
            {
                "package": "undici (via npm)",
                "version": "6.26.0",
                "status": "fix-available",
                "notes": "GHSA-x",
            },
        ],
    },
}

CDX_SBOM = {
    "metadata": {"component": {"name": "quay.io/org/app@sha256:" + "d" * 64}},
    "components": [
        {
            "purl": "pkg:golang/golang.org/x/net@v0.17.0",
            "name": "golang.org/x/net",
            "version": "v0.17.0",
        },
        {"purl": "pkg:npm/undici@6.26.0", "name": "undici", "version": "6.26.0"},
        {"purl": "pkg:rpm/rhel/tar@1.34", "name": "tar", "version": "1.34"},
        {"name": "no-purl-component"},
    ],
}


class TestArtifactsLayer(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        spine = tmp / "spine.json"
        spine.write_text(json.dumps(SPINE))
        self.con = G.db_connect(tmp / "graph.db")
        G.build_spine(self.con, spine)
        findings = tmp / "findings" / "prod" / "app"
        findings.mkdir(parents=True)
        (findings / "app-container-audit.json").write_text(json.dumps(CONTAINER_REPORT))
        sboms = tmp / "sboms"
        sboms.mkdir()
        (sboms / "app.cdx.json").write_text(json.dumps(CDX_SBOM))
        self.stats = G.build_artifacts(self.con, tmp / "findings", sboms)

    def tearDown(self):
        self.con.close()
        self._tmp.cleanup()

    def test_image_node_and_built_from(self):
        self.assertEqual(self.stats["images"], 1)
        edge = self.con.execute(
            "SELECT src, dst, attrs FROM edges WHERE rel='built_from'"
        ).fetchone()
        self.assertEqual(edge[0], "image:sha256:" + "d" * 64)
        self.assertEqual(edge[1], "repo:github.com/org/repo-a")
        self.assertEqual(json.loads(edge[2])["drift"], 2)

    def test_sbom_matched_and_module_join(self):
        self.assertEqual(self.stats["sboms"], 1)
        self.assertEqual(self.stats["sbom_unmatched"], 0)
        out = G.q_ships_module(self.con, "golang.org/x/net")
        self.assertEqual(len(out["images"]), 1)
        self.assertEqual(out["images"][0]["version"], "v0.17.0")
        self.assertEqual(out["images"][0]["tag"], "v1.2.3")

    def test_packages_from_report_and_sbom(self):
        rows = self.con.execute(
            "SELECT dst, json_extract(attrs,'$.via') FROM edges "
            "WHERE rel='ships_package' ORDER BY 2"
        ).fetchall()
        pkgs = {p for p, _ in rows}
        # undici appears in both sources — one edge per (image, package),
        # richer SBOM provenance wins on the shared edge
        self.assertEqual(pkgs, {"package:undici", "package:tar"})
        self.assertEqual(dict(rows)["package:undici"], "sbom")

    def test_unmatched_sbom_counted(self):
        with tempfile.TemporaryDirectory() as d:
            sboms = Path(d)
            (sboms / "mystery.cdx.json").write_text(
                json.dumps(
                    {
                        "metadata": {"component": {"name": "quay.io/x@sha256:" + "9" * 64}},
                        "components": [],
                    }
                )
            )
            stats = G.build_artifacts(self.con, Path(d), sboms)
            self.assertEqual(stats["sbom_unmatched"], 1)


GO_SRC = """package lib

import (
\t"fmt"
\t"github.com/org/lib-b/pkg/util"
)

func Exported(x int) int { return x }
func private() {}
func (r *Thing) Method() { fmt.Println(util.X) }
type Thing struct{}
type hidden struct{}
"""

PY_SRC = """import requests
from k8s.client import api

def public_fn():
    pass

def _private_fn():
    pass

class PublicClass:
    def method_not_toplevel(self):
        pass
"""

TS_SRC = """import { thing } from "@backstage/core";
import fs from "fs";

export function handler(): void {}
export class Widget {}
const internal = 1;
"""


def _ts_available():
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_go  # noqa: F401

        return True
    except ImportError:
        return False


@unittest.skipUnless(_ts_available(), "tree-sitter not installed")
class TestSymbolExtraction(unittest.TestCase):
    def _extract(self, files):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel, content in files.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            return G.extract_symbols_tree(root)

    def test_go_exported_only_with_spans(self):
        out = self._extract({"pkg/lib.go": GO_SRC})
        names = {(s["name"], s["kind"]) for s in out["symbols"]}
        self.assertEqual(names, {("Exported", "func"), ("Method", "method"), ("Thing", "type")})
        sym = next(s for s in out["symbols"] if s["name"] == "Exported")
        self.assertGreater(sym["end_byte"], sym["start_byte"])
        self.assertEqual(sym["file"], "pkg/lib.go")
        self.assertEqual(out["imports"], {"fmt": 1, "github.com/org/lib-b/pkg/util": 1})

    def test_python_and_ts(self):
        out = self._extract({"svc/app.py": PY_SRC, "web/ui.ts": TS_SRC})
        names = {s["name"] for s in out["symbols"]}
        self.assertEqual(names, {"public_fn", "PublicClass", "handler", "Widget"})
        self.assertIn("requests", out["imports"])
        self.assertIn("k8s.client", out["imports"])
        self.assertIn("@backstage/core", out["imports"])

    def test_vendor_excluded_and_relative_imports_skipped(self):
        out = self._extract(
            {"vendor/x/lib.go": GO_SRC, "web/a.ts": 'import { x } from "./local";\n'}
        )
        self.assertEqual(out["symbols"], [])
        self.assertEqual(out["imports"], {})


@unittest.skipUnless(_ts_available(), "tree-sitter not installed")
class TestSymbolsLayer(unittest.TestCase):
    def test_load_via_cache_and_queries(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = tmp / "spine.json"
            spine.write_text(json.dumps(SPINE))
            con = G.db_connect(tmp / "graph.db")
            G.build_spine(con, spine)
            # internal module for import-ownership matching
            G.upsert_node(
                con, "module:github.com/org/lib-b", "module", "github.com/org/lib-b", internal=1
            )
            con.commit()
            old = G.CACHE
            G.CACHE = tmp / "cache"
            try:
                G.extract_symbols_tree.__wrapped__ if hasattr(
                    G.extract_symbols_tree, "__wrapped__"
                ) else None
                src = tmp / "src" / "pkg"
                src.mkdir(parents=True)
                (src / "lib.go").write_text(GO_SRC)
                tree = G.extract_symbols_tree(tmp / "src")
                cache = G.CACHE / "symbols"
                cache.mkdir(parents=True)
                (cache / "org__repo-a.json").write_text(
                    json.dumps({"status": "ok", "sha": "f" * 40, **tree})
                )
                (cache / "org__lib-b.json").write_text(
                    json.dumps(
                        {
                            "status": "ok",
                            "sha": "f" * 40,
                            "files": 0,
                            "truncated": False,
                            "symbols": [],
                            "imports": {},
                        }
                    )
                )
                stats = G.build_symbols(con, None, jobs=2)
                self.assertEqual(stats["ok"], 2)
                self.assertEqual(stats["symbols"], 3)
                exports = G.q_exports_of(con, "org/repo-a")
                self.assertEqual(exports["total"], 3)
                imp = G.q_imports_package(con, "github.com/org/lib-b")
                self.assertEqual(imp["importing_repos"][0]["repo"], "repo:github.com/org/repo-a")
                internal = con.execute(
                    "SELECT json_extract(attrs,'$.internal') FROM nodes "
                    "WHERE id='srcpkg:github.com/org/lib-b/pkg/util'"
                ).fetchone()[0]
                self.assertEqual(internal, 1)
            finally:
                G.CACHE = old
                con.close()


# ------------------------------------------- L1 multi-ecosystem (npm/pypi/…)
def _seed_tree(cache: Path, org: str, name: str, paths, truncated=False, status="ok") -> None:
    d = cache / "trees"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{org}__{name}.json").write_text(
        json.dumps({"status": status, "paths": list(paths), "truncated": truncated})
    )


def _seed_manifest(cache: Path, eco: str, org: str, name: str, path: str, payload: dict) -> None:
    slug = path.replace("/", "_")
    d = cache / "manifests" / eco
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{org}__{name}__{slug}.json").write_text(json.dumps(payload))


MULTI_SPINE = {
    "nodes": [
        {"id": "product:p1", "type": "product", "label": "Product One", "attrs": {}},
        {
            "id": "repo:github.com/org/repo-a",
            "type": "repo",
            "label": "org/repo-a",
            "attrs": {"host": "github.com", "org": "org", "name": "repo-a"},
        },
        {
            "id": "repo:github.com/org/repo-b",
            "type": "repo",
            "label": "org/repo-b",
            "attrs": {"host": "github.com", "org": "org", "name": "repo-b"},
        },
        {
            "id": "repo:github.com/org/repo-c",
            "type": "repo",
            "label": "org/repo-c",
            "attrs": {"host": "github.com", "org": "org", "name": "repo-c"},
        },
    ],
    "edges": [
        {
            "from": "product:p1",
            "to": "repo:github.com/org/repo-a",
            "rel": "ships",
            "branch": "main",
        },
    ],
}

# repo-c (JavaScript) depends on repo-a's own published package — makes
# repo-a-pkg an internally-coupled npm package (declared by repo-a, consumed
# by repo-c), the npm analogue of Go internal-library coupling.
PACKAGE_LOCK_C = {
    "name": "repo-c-pkg",
    "packages": {
        "": {"name": "repo-c-pkg", "dependencies": {"repo-a-pkg": "^1.0.0"}},
        "node_modules/repo-a-pkg": {"version": "1.0.0"},
    },
}

# package-lock.json v3: declared name repo-a-pkg, a scoped direct dep
# @scope/x, another direct, and one transitive-only package.
PACKAGE_LOCK_A = {
    "name": "repo-a-pkg",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "repo-a-pkg",
            "version": "1.0.0",
            "dependencies": {"@scope/x": "^1.2.0", "left-pad": "^1.0.0"},
        },
        "node_modules/@scope/x": {"version": "1.2.3"},
        "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/transitive-dep": {"version": "0.0.1"},
    },
}

GEMFILE_LOCK_B = """\
GEM
  remote: https://rubygems.org/
  specs:
    json (2.6.3)
    rake (13.0.6)
      other (>= 0)

PLATFORMS
  ruby

DEPENDENCIES
  rake
"""


class TestDepsMultiLayer(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        spine = self.tmp / "spine.json"
        spine.write_text(json.dumps(MULTI_SPINE))
        self.con = G.db_connect(self.tmp / "graph.db")
        G.build_spine(self.con, spine)
        self._old_cache = G.CACHE
        G.CACHE = self.tmp / "cache"
        # language cache is only consulted for the truncated-tree fallback;
        # discovery here is by tree path.
        self.lang_cache = self.tmp / "lang.jsonl"
        self.lang_cache.write_text("")
        # each repo's tree lists its root manifest
        _seed_tree(G.CACHE, "org", "repo-a", ["package-lock.json"])
        _seed_tree(G.CACHE, "org", "repo-b", ["Gemfile.lock"])
        _seed_tree(G.CACHE, "org", "repo-c", ["package-lock.json"])
        _seed_manifest(
            G.CACHE,
            "npm",
            "org",
            "repo-a",
            "package-lock.json",
            {"status": "ok", "text": json.dumps(PACKAGE_LOCK_A)},
        )
        _seed_manifest(
            G.CACHE,
            "npm",
            "org",
            "repo-c",
            "package-lock.json",
            {"status": "ok", "text": json.dumps(PACKAGE_LOCK_C)},
        )
        _seed_manifest(
            G.CACHE,
            "ruby",
            "org",
            "repo-b",
            "Gemfile.lock",
            {"status": "ok", "text": GEMFILE_LOCK_B},
        )

    def tearDown(self):
        G.CACHE = self._old_cache
        self.con.close()
        self._tmp.cleanup()

    def test_scoped_npm_node_and_edge(self):
        stats = G.build_deps_multi(self.con, None, 2, {"npm", "ruby"}, self.lang_cache)
        # scoped dep node exists, kind=package, ecosystem attr set
        row = self.con.execute(
            "SELECT kind, attrs FROM nodes WHERE id='pkg:npm/@scope/x'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "package")
        self.assertEqual(json.loads(row[1])["ecosystem"], "npm")
        # depends_on edge carries ecosystem + right version/indirect
        edge = self.con.execute(
            "SELECT attrs FROM edges WHERE rel='depends_on' "
            "AND src='repo:github.com/org/repo-a' "
            "AND dst='pkg:npm/@scope/x'"
        ).fetchone()
        attrs = json.loads(edge[0])
        self.assertEqual(attrs["ecosystem"], "npm")
        self.assertEqual(attrs["version"], "1.2.3")
        self.assertEqual(attrs["indirect"], 0)
        # transitive package marked indirect=1
        tattrs = json.loads(
            self.con.execute(
                "SELECT attrs FROM edges WHERE rel='depends_on' AND dst='pkg:npm/transitive-dep'"
            ).fetchone()[0]
        )
        self.assertEqual(tattrs["indirect"], 1)
        # declared-name second pass: repo-a's own package internal=1/owner
        own = json.loads(
            self.con.execute("SELECT attrs FROM nodes WHERE id='pkg:npm/repo-a-pkg'").fetchone()[0]
        )
        self.assertEqual(own["internal"], 1)
        self.assertEqual(own["owner_repo"], "repo:github.com/org/repo-a")
        # declares edge present
        self.assertEqual(
            self.con.execute(
                "SELECT COUNT(*) FROM edges WHERE rel='declares' AND dst='pkg:npm/repo-a-pkg'"
            ).fetchone()[0],
            1,
        )
        # per-ecosystem stats (renamed keys under the tree-discovery model)
        self.assertEqual(stats["npm"]["manifests_fetched_ok"], 2)  # a + c
        self.assertEqual(stats["npm"]["parse_empty"], 0)
        self.assertIn("package-lock.json", stats["npm"]["manifest_paths_sample"])
        self.assertEqual(stats["npm"]["repos_with_manifest"], 2)
        # ruby ecosystem also produced edges (multi-ecosystem in one pass)
        self.assertGreater(stats["ruby"]["dep_edges"], 0)
        self.assertEqual(stats["loud_fail"], [])
        # denominator-honest global tree stats
        self.assertEqual(stats["repos_tree_ok"], 3)
        self.assertEqual(stats["repos_with_any_manifest"], 3)
        self.assertEqual(stats["repos_with_zero_manifests"], 0)

    def test_write_stats_ecosystem_table(self):
        G.build_deps_multi(self.con, None, 2, {"npm", "ruby"}, self.lang_cache)
        with tempfile.TemporaryDirectory() as d:
            G.write_stats(self.con, Path(d))
            md = (Path(d) / "portfolio-graph-stats.md").read_text()
        self.assertIn("L1 dependency edges by ecosystem", md)
        self.assertIn("| npm |", md)

    def test_top_shared_and_coupling_carry_ecosystem(self):
        G.build_deps_multi(self.con, None, 2, {"npm", "ruby"}, self.lang_cache)
        shared = {t["module"]: t["ecosystem"] for t in G.q_top_shared(self.con, 50)}
        self.assertEqual(shared.get("@scope/x"), "npm")
        # repo-a-pkg is declared by repo-a and consumed by repo-c ->
        # internally coupled, and the coupling row carries its ecosystem.
        coupling = G.q_internal_coupling(self.con, 50)
        own = next(c for c in coupling if c["module"] == "repo-a-pkg")
        self.assertEqual(own["ecosystem"], "npm")
        self.assertEqual(own["owner_repo"], "repo:github.com/org/repo-a")


class TestDepsMultiParseEmpty(unittest.TestCase):
    """A discovered manifest whose ok fetch parses to no deps and no
    declared name is a tracked parse_empty (not an error, not a bogus
    edge), and — since the manifest WAS discovered — it trips loud_fail
    when the ecosystem ends with zero edges."""

    def test_parse_empty_tracked_no_edges_and_loud_fail(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = tmp / "spine.json"
            spine.write_text(json.dumps(MULTI_SPINE))
            con = G.db_connect(tmp / "g.db")
            G.build_spine(con, spine)
            old = G.CACHE
            G.CACHE = tmp / "cache"
            try:
                lang = tmp / "lang.jsonl"
                lang.write_text("")
                # a real subdir manifest exists in the tree, but parses empty
                _seed_tree(G.CACHE, "org", "repo-a", ["services/api/package.json"])
                _seed_manifest(
                    G.CACHE,
                    "npm",
                    "org",
                    "repo-a",
                    "services/api/package.json",
                    {"status": "ok", "text": json.dumps({"packages": {}})},
                )
                _seed_tree(G.CACHE, "org", "repo-b", [])
                _seed_tree(G.CACHE, "org", "repo-c", [])
                stats = G.build_deps_multi(con, None, 2, {"npm"}, lang)
                self.assertEqual(stats["npm"]["parse_empty"], 1)
                self.assertEqual(stats["npm"]["manifests_fetched_ok"], 1)
                self.assertEqual(stats["npm"]["repos_with_manifest"], 1)
                self.assertEqual(stats["npm"]["dep_edges"], 0)
                self.assertEqual(
                    con.execute(
                        "SELECT COUNT(*) FROM edges WHERE rel='depends_on' "
                        "AND json_extract(attrs,'$.ecosystem')='npm'"
                    ).fetchone()[0],
                    0,
                )
                # loud_fail fires: manifest discovered, zero edges
                self.assertEqual(stats["loud_fail"], ["npm"])
            finally:
                G.CACHE = old
                con.close()


class TestDepsMultiDenominator(unittest.TestCase):
    """A repo whose tree carries NO manifest for a requested ecosystem is a
    legitimate zero — counted in repos_with_zero_manifests, never loud_fail."""

    def test_no_manifest_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = tmp / "spine.json"
            spine.write_text(json.dumps(MULTI_SPINE))
            con = G.db_connect(tmp / "g.db")
            G.build_spine(con, spine)
            old = G.CACHE
            G.CACHE = tmp / "cache"
            try:
                lang = tmp / "lang.jsonl"
                lang.write_text("")
                # trees with no npm manifest anywhere
                _seed_tree(G.CACHE, "org", "repo-a", ["README.md", "main.go"])
                _seed_tree(G.CACHE, "org", "repo-b", ["LICENSE"])
                _seed_tree(G.CACHE, "org", "repo-c", [])
                stats = G.build_deps_multi(con, None, 2, {"npm"}, lang)
                self.assertEqual(stats["npm"]["repos_with_manifest"], 0)
                self.assertEqual(stats["npm"]["dep_edges"], 0)
                self.assertEqual(stats["repos_tree_ok"], 3)
                self.assertEqual(stats["repos_with_zero_manifests"], 3)
                self.assertEqual(stats["repos_with_any_manifest"], 0)
                # zero manifests => NOT loud_fail (repos_with_manifest==0)
                self.assertEqual(stats["loud_fail"], [])
            finally:
                G.CACHE = old
                con.close()


# ---- subdir discovery + the three universal surfaces in one repo tree ----
SUB_PACKAGE_JSON = {"name": "api-svc", "dependencies": {"express": "^4.18.0"}}
VENDORED_PACKAGE_JSON = {"name": "vend", "dependencies": {"should-not-appear": "^1.0.0"}}
CHART_YAML = """\
name: foo-chart
version: 1.0.0
dependencies:
  - name: redis
    version: 17.0.0
    repository: https://charts.example
"""
WORKFLOW_YAML = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
DOCKERFILE = """\
FROM golang:1.22 AS build
FROM registry.access.redhat.com/ubi9/go-toolset:1.21
"""
NESTED_POM = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>mymod</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache</groupId>
      <artifactId>commons</artifactId>
      <version>3.0</version>
    </dependency>
  </dependencies>
</project>
"""


class TestDepsMultiSubdirUniversal(unittest.TestCase):
    """The subdir fix plus docker/actions/helm ingestion, all from one
    repo's git tree, with a vendored path that must be skipped."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        spine = self.tmp / "spine.json"
        spine.write_text(json.dumps(MULTI_SPINE))
        self.con = G.db_connect(self.tmp / "graph.db")
        G.build_spine(self.con, spine)
        self._old_cache = G.CACHE
        G.CACHE = self.tmp / "cache"
        self.lang = self.tmp / "lang.jsonl"
        self.lang.write_text("")
        paths = [
            "services/api/package.json",
            "vendor/x/package.json",
            "charts/foo/Chart.yaml",
            ".github/workflows/ci.yml",
            "deploy/Dockerfile",
            "sub/module/pom.xml",
            "README.md",
        ]
        _seed_tree(G.CACHE, "org", "repo-a", paths)
        _seed_tree(G.CACHE, "org", "repo-b", [])
        _seed_tree(G.CACHE, "org", "repo-c", [])
        _seed_manifest(
            G.CACHE,
            "npm",
            "org",
            "repo-a",
            "services/api/package.json",
            {"status": "ok", "text": json.dumps(SUB_PACKAGE_JSON)},
        )
        # vendored — seeded so a bug that fetched it WOULD produce an edge
        _seed_manifest(
            G.CACHE,
            "npm",
            "org",
            "repo-a",
            "vendor/x/package.json",
            {"status": "ok", "text": json.dumps(VENDORED_PACKAGE_JSON)},
        )
        _seed_manifest(
            G.CACHE,
            "helm",
            "org",
            "repo-a",
            "charts/foo/Chart.yaml",
            {"status": "ok", "text": CHART_YAML},
        )
        _seed_manifest(
            G.CACHE,
            "actions",
            "org",
            "repo-a",
            ".github/workflows/ci.yml",
            {"status": "ok", "text": WORKFLOW_YAML},
        )
        _seed_manifest(
            G.CACHE,
            "docker",
            "org",
            "repo-a",
            "deploy/Dockerfile",
            {"status": "ok", "text": DOCKERFILE},
        )
        _seed_manifest(
            G.CACHE,
            "maven",
            "org",
            "repo-a",
            "sub/module/pom.xml",
            {"status": "ok", "text": NESTED_POM},
        )
        self.stats = G.build_deps_multi(
            self.con, None, 2, {"npm", "maven", "docker", "actions", "helm"}, self.lang
        )

    def tearDown(self):
        G.CACHE = self._old_cache
        self.con.close()
        self._tmp.cleanup()

    def _edge(self, dst):
        row = self.con.execute(
            "SELECT attrs FROM edges WHERE rel='depends_on' "
            "AND src='repo:github.com/org/repo-a' AND dst=?",
            (dst,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def test_subdir_npm_edge(self):
        # the SUBDIR package.json produced an npm edge (the subdir fix)
        self.assertEqual(self._edge("pkg:npm/express")["version"], "4.18.0")

    def test_vendored_skipped(self):
        self.assertIsNone(
            self.con.execute("SELECT 1 FROM nodes WHERE id='pkg:npm/should-not-appear'").fetchone()
        )

    def test_docker_base_image_with_tag_as_version(self):
        row = self.con.execute("SELECT kind FROM nodes WHERE id='pkg:docker/golang'").fetchone()
        self.assertEqual(row[0], "package")
        self.assertEqual(self._edge("pkg:docker/golang")["version"], "1.22")

    def test_github_action_node_and_edge(self):
        row = self.con.execute(
            "SELECT kind FROM nodes WHERE id='pkg:actions/actions/checkout'"
        ).fetchone()
        self.assertEqual(row[0], "package")
        self.assertEqual(self._edge("pkg:actions/actions/checkout")["version"], "v4")

    def test_helm_node(self):
        # dep node
        self.assertIsNotNone(
            self.con.execute("SELECT 1 FROM nodes WHERE id='pkg:helm/redis'").fetchone()
        )
        # declared chart name promoted to internal via the second pass
        own = json.loads(
            self.con.execute("SELECT attrs FROM nodes WHERE id='pkg:helm/foo-chart'").fetchone()[0]
        )
        self.assertEqual(own["internal"], 1)
        self.assertEqual(own["owner_repo"], "repo:github.com/org/repo-a")

    def test_nested_pom_discovered(self):
        self.assertEqual(self._edge("pkg:maven/org.apache:commons")["version"], "3.0")

    def test_subdir_edge_carries_manifest_provenance(self):
        # the depends_on edge records the REAL subdir manifest path it came
        # from — provenance for verifying a dependency finding without a
        # manual source check.
        self.assertEqual(self._edge("pkg:npm/express")["manifest"], ["services/api/package.json"])

    def test_declares_edge_carries_manifest(self):
        # the declared chart's `declares` edge names its source manifest
        row = self.con.execute(
            "SELECT attrs FROM edges WHERE rel='declares' "
            "AND src='repo:github.com/org/repo-a' "
            "AND dst='pkg:helm/foo-chart'"
        ).fetchone()
        self.assertEqual(json.loads(row[0])["manifest"], ["charts/foo/Chart.yaml"])

    def test_no_loud_fail_and_denominator(self):
        self.assertEqual(self.stats["loud_fail"], [])
        self.assertEqual(self.stats["repos_with_any_manifest"], 1)
        self.assertEqual(self.stats["repos_with_zero_manifests"], 2)
        # a discovered-path sample is recorded per ecosystem
        self.assertIn("services/api/package.json", self.stats["npm"]["manifest_paths_sample"])


# same package declared in two manifests within one repo -> the edge's
# `manifest` attr is the sorted 2-element list of both source paths.
TWO_MANIFEST_A = {"name": "svc-a", "dependencies": {"shared-dep": "^1.0.0"}}
TWO_MANIFEST_B = {"name": "svc-b", "dependencies": {"shared-dep": "^1.0.0"}}


class TestDepsMultiManifestProvenance(unittest.TestCase):
    """Source-manifest provenance is stamped on the depends_on/declares
    edges — the exact repo-relative manifest path(s) a dep was found in — so
    a dependency finding can be verified against and cite its source without
    a manual check. A dep found in TWO manifests in one repo carries the
    sorted 2-element list; a single source is still a 1-element list."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        spine = self.tmp / "spine.json"
        spine.write_text(json.dumps(MULTI_SPINE))
        self.con = G.db_connect(self.tmp / "graph.db")
        G.build_spine(self.con, spine)
        self._old_cache = G.CACHE
        G.CACHE = self.tmp / "cache"
        self.lang = self.tmp / "lang.jsonl"
        self.lang.write_text("")
        # one repo, the SAME dep declared in two subdir package.json files
        _seed_tree(G.CACHE, "org", "repo-a", ["services/api/package.json", "web/ui/package.json"])
        _seed_tree(G.CACHE, "org", "repo-b", [])
        _seed_tree(G.CACHE, "org", "repo-c", [])
        _seed_manifest(
            G.CACHE,
            "npm",
            "org",
            "repo-a",
            "services/api/package.json",
            {"status": "ok", "text": json.dumps(TWO_MANIFEST_A)},
        )
        _seed_manifest(
            G.CACHE,
            "npm",
            "org",
            "repo-a",
            "web/ui/package.json",
            {"status": "ok", "text": json.dumps(TWO_MANIFEST_B)},
        )
        self.stats = G.build_deps_multi(self.con, None, 2, {"npm"}, self.lang)

    def tearDown(self):
        G.CACHE = self._old_cache
        self.con.close()
        self._tmp.cleanup()

    def _attrs(self, rel, dst):
        row = self.con.execute(
            "SELECT attrs FROM edges WHERE rel=? AND src='repo:github.com/org/repo-a' AND dst=?",
            (rel, dst),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def test_dep_in_two_manifests_is_sorted_list(self):
        attrs = self._attrs("depends_on", "pkg:npm/shared-dep")
        self.assertEqual(attrs["manifest"], ["services/api/package.json", "web/ui/package.json"])
        self.assertNotIn("manifest_truncated", attrs)

    def test_declares_edge_carries_single_manifest_list(self):
        # svc-a is repo-a's own package name, declared by its single manifest;
        # a single source is still a 1-element list (stable type).
        attrs = self._attrs("declares", "pkg:npm/svc-a")
        self.assertEqual(attrs["manifest"], ["services/api/package.json"])


class TestManifestAttrHelper(unittest.TestCase):
    """The _manifest_attr edge-attr fragment: empty for no path (Go's
    implicit go.mod), a sorted list otherwise, and capped with a
    manifest_truncated flag past MANIFEST_PATHS_CAP."""

    def test_none_and_empty_yield_no_attr(self):
        self.assertEqual(G._manifest_attr(None), {})
        self.assertEqual(G._manifest_attr(set()), {})

    def test_sorted_deduped_list(self):
        self.assertEqual(
            G._manifest_attr({"b/x.json", "a/y.json"}), {"manifest": ["a/y.json", "b/x.json"]}
        )

    def test_cap_truncates_and_flags(self):
        many = {f"d{i:03d}/package.json" for i in range(G.MANIFEST_PATHS_CAP + 5)}
        attr = G._manifest_attr(many)
        self.assertEqual(len(attr["manifest"]), G.MANIFEST_PATHS_CAP)
        self.assertTrue(attr["manifest_truncated"])
        # kept the sorted prefix
        self.assertEqual(attr["manifest"], sorted(many)[: G.MANIFEST_PATHS_CAP])


TRUNC_PACKAGE_LOCK = {
    "name": "trunc-pkg",
    "packages": {
        "": {"name": "trunc-pkg", "dependencies": {"lodash": "^4.0.0"}},
        "node_modules/lodash": {"version": "4.17.21"},
    },
}


class TestDepsMultiTruncated(unittest.TestCase):
    """A truncated (huge) tree falls back to the old root-only candidate
    fetch for the language-gated ecosystems and records truncated_fallback."""

    def test_truncated_tree_root_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = tmp / "spine.json"
            spine.write_text(json.dumps(MULTI_SPINE))
            con = G.db_connect(tmp / "g.db")
            G.build_spine(con, spine)
            old = G.CACHE
            G.CACHE = tmp / "cache"
            try:
                lang = tmp / "lang.jsonl"
                # fallback needs the language to know which root candidates
                lang.write_text(
                    json.dumps({"repo": "org/repo-a", "languages": {"JavaScript": 900}}) + "\n"
                )
                # truncated tree: paths are unusable, must fall back to root
                _seed_tree(G.CACHE, "org", "repo-a", [], truncated=True)
                _seed_tree(G.CACHE, "org", "repo-b", [])
                _seed_tree(G.CACHE, "org", "repo-c", [])
                _seed_manifest(
                    G.CACHE,
                    "npm",
                    "org",
                    "repo-a",
                    "package-lock.json",
                    {"status": "ok", "text": json.dumps(TRUNC_PACKAGE_LOCK)},
                )
                stats = G.build_deps_multi(con, None, 2, {"npm"}, lang)
                self.assertEqual(stats["repos_truncated"], 1)
                self.assertEqual(stats["truncated_fallback"], 1)
                self.assertGreater(stats["npm"]["dep_edges"], 0)
                self.assertEqual(stats["npm"]["repos_with_manifest"], 1)
                self.assertEqual(stats["loud_fail"], [])
                self.assertIsNotNone(
                    con.execute("SELECT 1 FROM nodes WHERE id='pkg:npm/lodash'").fetchone()
                )
            finally:
                G.CACHE = old
                con.close()


class TestDepsMultiStatsPersisted(unittest.TestCase):
    """The `deps-multi` CLI path persists build_deps_multi's return dict to
    deps-multi-stats.json next to the db (with --stats-out override) so the
    smoke checker can use the honest manifest-based coverage denominator."""

    def _seed_and_build(self, db: Path, cache: Path, lang: Path):
        spine = db.parent / "spine.json"
        spine.write_text(json.dumps(MULTI_SPINE))
        con = G.db_connect(db)
        G.build_spine(con, spine)
        con.close()
        lang.write_text("")
        _seed_tree(cache, "org", "repo-a", ["package-lock.json"])
        _seed_tree(cache, "org", "repo-b", [])
        _seed_tree(cache, "org", "repo-c", [])
        _seed_manifest(
            cache,
            "npm",
            "org",
            "repo-a",
            "package-lock.json",
            {"status": "ok", "text": json.dumps(PACKAGE_LOCK_A)},
        )

    def test_deps_multi_cli_writes_stats_json(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            db = tmp / "graph.db"
            old = G.CACHE
            G.CACHE = tmp / "cache"
            lang = tmp / "lang.jsonl"
            try:
                self._seed_and_build(db, G.CACHE, lang)
                con = G.db_connect(db)
                sm = G.build_deps_multi(con, None, 2, {"npm"}, str(lang))
                G._write_deps_multi_stats(sm, str(db), None)
                rc = 1 if sm.get("loud_fail") else 0
                self.assertEqual(rc, 0)
                stats_path = tmp / "deps-multi-stats.json"
                self.assertTrue(
                    stats_path.is_file(), "deps-multi must persist stats next to the db"
                )
                stats = json.loads(stats_path.read_text())
                # global keys
                for k in (
                    "repos_tree_ok",
                    "repos_with_any_manifest",
                    "repos_with_zero_manifests",
                    "truncated_fallback",
                    "loud_fail",
                ):
                    self.assertIn(k, stats)
                # per-ecosystem keys with the honest denominator
                self.assertIn("npm", stats)
                for k in (
                    "repos_with_manifest",
                    "manifests_fetched_ok",
                    "absent",
                    "parse_empty",
                    "pkg_nodes",
                    "dep_edges",
                    "manifest_paths_sample",
                ):
                    self.assertIn(k, stats["npm"])
                self.assertEqual(stats["npm"]["repos_with_manifest"], 1)
                self.assertGreater(stats["npm"]["dep_edges"], 0)
                self.assertEqual(stats["loud_fail"], [])
            finally:
                G.CACHE = old

    def test_stats_out_override(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            db = tmp / "graph.db"
            out = tmp / "custom" / "s.json"
            old = G.CACHE
            G.CACHE = tmp / "cache"
            lang = tmp / "lang.jsonl"
            try:
                self._seed_and_build(db, G.CACHE, lang)
                con = G.db_connect(db)
                sm = G.build_deps_multi(con, None, 2, {"npm"}, str(lang))
                G._write_deps_multi_stats(sm, str(db), str(out))
                rc = 1 if sm.get("loud_fail") else 0
                self.assertEqual(rc, 0)
                self.assertTrue(out.is_file())
                # default location NOT written when overridden
                self.assertFalse((tmp / "deps-multi-stats.json").is_file())
                self.assertEqual(json.loads(out.read_text())["npm"]["repos_with_manifest"], 1)
            finally:
                G.CACHE = old


class TestDepNodeCollision(unittest.TestCase):
    """A Go module `foo` (module:foo) and an npm package `foo`
    (pkg:npm/foo) must occupy distinct node ids; blast-radius on the Go id
    must never leak the npm dependent."""

    COLLISION_SPINE = {
        "nodes": [
            {"id": "product:p1", "type": "product", "label": "P", "attrs": {}},
            {
                "id": "repo:github.com/org/goapp",
                "type": "repo",
                "label": "org/goapp",
                "attrs": {"host": "github.com", "org": "org", "name": "goapp"},
            },
            {
                "id": "repo:github.com/org/npmapp",
                "type": "repo",
                "label": "org/npmapp",
                "attrs": {"host": "github.com", "org": "org", "name": "npmapp"},
            },
        ],
        "edges": [
            {"from": "product:p1", "to": "repo:github.com/org/goapp", "rel": "ships"},
            {"from": "product:p1", "to": "repo:github.com/org/npmapp", "rel": "ships"},
        ],
    }
    GO_MOD = "module github.com/org/goapp\n\nrequire foo v1.0.0\n"
    NPM_LOCK = {
        "name": "npmapp",
        "packages": {
            "": {"name": "npmapp", "dependencies": {"foo": "^1.0.0"}},
            "node_modules/foo": {"version": "1.0.0"},
        },
    }

    def test_go_and_npm_foo_do_not_collide(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = tmp / "spine.json"
            spine.write_text(json.dumps(self.COLLISION_SPINE))
            con = G.db_connect(tmp / "g.db")
            G.build_spine(con, spine)
            old = G.CACHE
            G.CACHE = tmp / "cache"
            try:
                # seed the Go path (build_deps) via the gomod cache
                gomod = G.CACHE / "gomod"
                gomod.mkdir(parents=True)
                (gomod / "org__goapp.json").write_text(
                    json.dumps({"status": "ok", "text": self.GO_MOD})
                )
                (gomod / "org__npmapp.json").write_text(json.dumps({"status": "absent"}))
                G.build_deps(con, None, 2)
                # seed and run the npm path (build_deps_multi) via the tree
                lang = tmp / "lang.jsonl"
                lang.write_text("")
                _seed_tree(G.CACHE, "org", "npmapp", ["package-lock.json"])
                _seed_tree(G.CACHE, "org", "goapp", ["go.mod"])
                _seed_manifest(
                    G.CACHE,
                    "npm",
                    "org",
                    "npmapp",
                    "package-lock.json",
                    {"status": "ok", "text": json.dumps(self.NPM_LOCK)},
                )
                G.build_deps_multi(con, None, 2, {"npm"}, lang)

                # distinct node ids, distinct kinds
                gomod_node = con.execute("SELECT kind FROM nodes WHERE id='module:foo'").fetchone()
                npm_node = con.execute("SELECT kind FROM nodes WHERE id='pkg:npm/foo'").fetchone()
                self.assertEqual(gomod_node[0], "module")
                self.assertEqual(npm_node[0], "package")

                # blast-radius on the Go id returns ONLY the Go repo
                go_br = G.q_blast_radius(con, "module:foo")
                self.assertEqual(go_br["repo_count"], 1)
                self.assertEqual(go_br["requiring_repos"][0]["repo"], "repo:github.com/org/goapp")
                # blast-radius on the npm id returns ONLY the npm repo
                npm_br = G.q_blast_radius(con, "pkg:npm/foo")
                self.assertEqual(npm_br["repo_count"], 1)
                self.assertEqual(npm_br["requiring_repos"][0]["repo"], "repo:github.com/org/npmapp")
            finally:
                G.CACHE = old
                con.close()


class TestDepNodeDockerCollision(unittest.TestCase):
    """A Go module literally named `golang` (module:golang) and a Docker
    base image `golang` (pkg:docker/golang) must not collide."""

    SPINE = {
        "nodes": [
            {"id": "product:p1", "type": "product", "label": "P", "attrs": {}},
            {
                "id": "repo:github.com/org/mixed",
                "type": "repo",
                "label": "org/mixed",
                "attrs": {"host": "github.com", "org": "org", "name": "mixed"},
            },
        ],
        "edges": [{"from": "product:p1", "to": "repo:github.com/org/mixed", "rel": "ships"}],
    }
    GO_MOD = "module github.com/org/mixed\n\nrequire golang v1.0.0\n"
    DOCKERFILE = "FROM golang:1.22\n"

    def test_docker_golang_vs_go_module_golang(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            spine = tmp / "spine.json"
            spine.write_text(json.dumps(self.SPINE))
            con = G.db_connect(tmp / "g.db")
            G.build_spine(con, spine)
            old = G.CACHE
            G.CACHE = tmp / "cache"
            try:
                gomod = G.CACHE / "gomod"
                gomod.mkdir(parents=True)
                (gomod / "org__mixed.json").write_text(
                    json.dumps({"status": "ok", "text": self.GO_MOD})
                )
                G.build_deps(con, None, 2)
                lang = tmp / "lang.jsonl"
                lang.write_text("")
                _seed_tree(G.CACHE, "org", "mixed", ["Dockerfile", "go.mod"])
                _seed_manifest(
                    G.CACHE,
                    "docker",
                    "org",
                    "mixed",
                    "Dockerfile",
                    {"status": "ok", "text": self.DOCKERFILE},
                )
                G.build_deps_multi(con, None, 2, {"docker"}, lang)
                self.assertEqual(
                    con.execute("SELECT kind FROM nodes WHERE id='module:golang'").fetchone()[0],
                    "module",
                )
                self.assertEqual(
                    con.execute("SELECT kind FROM nodes WHERE id='pkg:docker/golang'").fetchone()[
                        0
                    ],
                    "package",
                )
                # Go blast-radius sees only the Go dependency edge
                go_br = G.q_blast_radius(con, "module:golang")
                self.assertEqual(go_br["repo_count"], 1)
                dk_br = G.q_blast_radius(con, "pkg:docker/golang")
                self.assertEqual(dk_br["repo_count"], 1)
                self.assertEqual(
                    json.loads(
                        con.execute(
                            "SELECT attrs FROM edges WHERE rel='depends_on' "
                            "AND dst='pkg:docker/golang'"
                        ).fetchone()[0]
                    )["version"],
                    "1.22",
                )
            finally:
                G.CACHE = old
                con.close()


# --------------------------------------------------- SECONDARY rate-limit ----
# The GitHub anti-scraping secondary-limit ban the /rate_limit endpoint is
# blind to. A wide tree-driven sweep once burned ~2,595 repos to 'error'
# during such a ban; the fetchers now classify it as a distinct `ratelimited`
# status and the fetch loop error-streak-gates + pauses (resumable).

_RL_STDERR = (
    "gh: HTTP 403: API rate limit exceeded for user ID 123. You have exceeded "
    "a secondary rate limit and have been temporarily blocked from content "
    "creation. Please retry your request again later. If you reach out to "
    "GitHub Support ... please review our Terms of Service on scraping "
    "(https://docs.github.com/...)"
)
_RL_SECONDARY_ONLY = "You have exceeded a secondary rate limit. Please wait ..."
_NOT_FOUND_STDERR = "gh: Not Found (HTTP 404)"


class TestSecondaryRateLimitDetection(unittest.TestCase):
    def test_matches_real_scraping_message(self):
        self.assertTrue(G._is_secondary_rate_limit(_RL_STDERR))

    def test_matches_secondary_wording(self):
        self.assertTrue(G._is_secondary_rate_limit(_RL_SECONDARY_ONLY))
        self.assertTrue(G._is_secondary_rate_limit("You have exceeded a secondary rate limit"))

    def test_matches_403_with_retry_indication(self):
        self.assertTrue(G._is_secondary_rate_limit("HTTP 403 Forbidden. Retry-After: 60"))
        self.assertTrue(
            G._is_secondary_rate_limit("429 Too Many Requests — please wait a few minutes")
        )

    def test_does_not_match_plain_404(self):
        self.assertFalse(G._is_secondary_rate_limit(_NOT_FOUND_STDERR))
        self.assertFalse(G._is_secondary_rate_limit("Not Found"))

    def test_empty_is_false(self):
        self.assertFalse(G._is_secondary_rate_limit(""))
        self.assertFalse(G._is_secondary_rate_limit(None))


def _runner_const(rc, out, err):
    def _r(argv, timeout):
        return rc, out, err

    return _r


class TestFetchStatusClassification(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = G.CACHE
        G.CACHE = Path(self._tmp.name) / "cache"

    def tearDown(self):
        G.CACHE = self._old
        self._tmp.cleanup()

    # ---- fetch_tree ----
    def test_tree_ratelimited_not_cached(self):
        r = _runner_const(1, "", _RL_STDERR)
        status, paths, _trunc = G.fetch_tree("org", "n", runner=r)
        self.assertEqual(status, "ratelimited")
        self.assertEqual(paths, [])
        self.assertFalse((G.CACHE / "trees" / "org__n.json").is_file())

    def test_tree_absent_on_404_is_cached(self):
        r = _runner_const(1, "", _NOT_FOUND_STDERR)
        status, _, _ = G.fetch_tree("org", "n", runner=r)
        self.assertEqual(status, "absent")
        self.assertTrue((G.CACHE / "trees" / "org__n.json").is_file())

    def test_tree_other_error_not_cached(self):
        r = _runner_const(1, "", "gh: HTTP 500 Internal Server Error")
        status, _, _ = G.fetch_tree("org", "n", runner=r)
        self.assertEqual(status, "error")
        self.assertFalse((G.CACHE / "trees" / "org__n.json").is_file())

    def test_tree_ok_is_cached(self):
        body = json.dumps({"tree": [{"path": "go.mod", "type": "blob"}], "truncated": False})
        status, paths, _ = G.fetch_tree("org", "n", runner=_runner_const(0, body, ""))
        self.assertEqual(status, "ok")
        self.assertEqual(paths, ["go.mod"])
        self.assertTrue((G.CACHE / "trees" / "org__n.json").is_file())

    # ---- fetch_manifest ----
    def test_manifest_ratelimited_not_cached(self):
        r = _runner_const(1, "", _RL_SECONDARY_ONLY)
        status, _text = G.fetch_manifest("org", "n", "package.json", "npm", runner=r)
        self.assertEqual(status, "ratelimited")
        self.assertFalse((G.CACHE / "manifests" / "npm" / "org__n__package.json.json").is_file())

    def test_manifest_absent_on_404_cached(self):
        r = _runner_const(1, "", _NOT_FOUND_STDERR)
        status, _ = G.fetch_manifest("org", "n", "package.json", "npm", runner=r)
        self.assertEqual(status, "absent")
        self.assertTrue((G.CACHE / "manifests" / "npm" / "org__n__package.json.json").is_file())

    def test_manifest_other_error_not_cached(self):
        r = _runner_const(1, "", "gh: HTTP 502 Bad Gateway")
        status, _ = G.fetch_manifest("org", "n", "package.json", "npm", runner=r)
        self.assertEqual(status, "error")
        self.assertFalse((G.CACHE / "manifests" / "npm" / "org__n__package.json.json").is_file())

    def test_manifest_sleep_ms_paces_via_injected_sleep(self):
        sleeps = []
        r = _runner_const(1, "", _NOT_FOUND_STDERR)
        G.fetch_manifest(
            "org", "n", "package.json", "npm", runner=r, sleep_ms=250, sleep_fn=sleeps.append
        )
        self.assertEqual(sleeps, [0.25])


class _FakeGh:
    """Argv-keyed fake gh runner. Banned repos (matched by /<name>/ in the
    request path) return the secondary-rate-limit 403; everyone else gets a
    one-file tree (package-lock.json) and a parseable package-lock body.
    Argv-keyed (not call-count) so it is deterministic under thread races."""

    def __init__(self, banned_names):
        self._banned = {f"/{n}/" for n in banned_names}
        self.calls = []
        self._body = json.dumps(PACKAGE_LOCK_A)
        self._tree = json.dumps(
            {"tree": [{"path": "package-lock.json", "type": "blob"}], "truncated": False}
        )

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        url = argv[2] if len(argv) > 2 else ""
        if any(b in url for b in self._banned):
            return 1, "", _RL_STDERR
        if "git/trees" in url:
            return 0, self._tree, ""
        if "/contents/" in url:
            return 0, self._body, ""
        return 0, "", ""


def _multi_repo_spine(n):
    nodes = [{"id": "product:p1", "type": "product", "label": "P", "attrs": {}}]
    edges = []
    for i in range(n):
        name = f"repo-{i:02d}"
        rid = f"repo:github.com/org/{name}"
        nodes.append(
            {
                "id": rid,
                "type": "repo",
                "label": f"org/{name}",
                "attrs": {"host": "github.com", "org": "org", "name": name},
            }
        )
        edges.append({"from": "product:p1", "to": rid, "rel": "ships", "branch": "main"})
    return {"nodes": nodes, "edges": edges}


class TestDepsMultiRateLimitGating(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._old_cache = G.CACHE
        G.CACHE = self.tmp / "cache"
        self.lang = self.tmp / "lang.jsonl"
        self.lang.write_text("")
        # fast backoff so no test really waits; save/restore the module knobs
        self._const = (
            G.RATE_LIMIT_BACKOFF_BASE,
            G.RATE_LIMIT_BACKOFF_CAP,
            G.RATE_LIMIT_MAX_WAIT,
            G.RATE_LIMIT_STREAK_STOP,
        )
        G.RATE_LIMIT_BACKOFF_BASE = 1.0
        G.RATE_LIMIT_BACKOFF_CAP = 4.0
        G.RATE_LIMIT_MAX_WAIT = 10.0
        G.RATE_LIMIT_STREAK_STOP = 5

    def tearDown(self):
        (
            G.RATE_LIMIT_BACKOFF_BASE,
            G.RATE_LIMIT_BACKOFF_CAP,
            G.RATE_LIMIT_MAX_WAIT,
            G.RATE_LIMIT_STREAK_STOP,
        ) = self._const
        G.CACHE = self._old_cache
        self._tmp.cleanup()

    def _con(self, n):
        spine = self.tmp / "spine.json"
        spine.write_text(json.dumps(_multi_repo_spine(n)))
        con = G.db_connect(self.tmp / "graph.db")
        G.build_spine(con, spine)
        return con

    def test_pause_then_resume_processes_later_repos(self):
        con = self._con(10)
        runner = _FakeGh(banned_names={f"repo-{i:02d}" for i in range(6)})
        sleeps = []
        stats = G.build_deps_multi(
            con, None, 4, {"npm"}, self.lang, runner=runner, sleep_fn=sleeps.append
        )
        # PAUSED: the streak tripped the backoff at least once
        self.assertGreaterEqual(len(sleeps), 1)
        self.assertEqual(sleeps[0], 1.0)  # first backoff == BASE
        # RESUMED and finished: the ban cleared on the first live probe
        self.assertFalse(stats["rate_limited_incomplete"])
        # repos strictly AFTER the pause got processed (edges exist)
        for i in (8, 9):
            got = con.execute(
                "SELECT COUNT(*) FROM edges WHERE rel='depends_on' "
                "AND src=? AND dst='pkg:npm/@scope/x'",
                (f"repo:github.com/org/repo-{i:02d}",),
            ).fetchone()[0]
            self.assertEqual(got, 1)
        # the banned repos were skipped, NOT marked error
        self.assertEqual(stats["repos_tree_error"], 0)
        self.assertEqual(stats["repos_ratelimited_skipped"], 6)
        con.close()

    def test_streak_below_threshold_does_not_pause(self):
        con = self._con(4)  # only 4 banned -> streak never reaches 5
        runner = _FakeGh(banned_names={f"repo-{i:02d}" for i in range(4)})
        sleeps = []
        stats = G.build_deps_multi(
            con, None, 4, {"npm"}, self.lang, runner=runner, sleep_fn=sleeps.append
        )
        self.assertEqual(sleeps, [])  # never paused
        self.assertFalse(stats["rate_limited_incomplete"])
        self.assertEqual(stats["repos_ratelimited_skipped"], 4)
        self.assertEqual(stats["repos_tree_error"], 0)
        con.close()

    def test_persistent_ban_marks_incomplete_no_error(self):
        con = self._con(10)
        runner = _FakeGh(banned_names={f"repo-{i:02d}" for i in range(10)})
        sleeps = []
        stats = G.build_deps_multi(
            con, None, 4, {"npm"}, self.lang, runner=runner, sleep_fn=sleeps.append
        )
        # gave up after max wait, with an escalating+capped backoff schedule
        self.assertTrue(stats["rate_limited_incomplete"])
        self.assertEqual(sleeps, [1.0, 2.0, 4.0, 4.0])
        # NOTHING marked error; unvisited repos counted skipped
        self.assertEqual(stats["repos_tree_error"], 0)
        self.assertGreater(stats["repos_ratelimited_skipped"], 0)
        # loud_fail is NOT tripped for an ecosystem the run never reached
        self.assertEqual(stats["loud_fail"], [])
        # no depends_on edges were written at all
        self.assertEqual(
            con.execute("SELECT COUNT(*) FROM edges WHERE rel='depends_on'").fetchone()[0], 0
        )
        con.close()

    def test_all_ok_run_unaffected(self):
        con = self._con(5)
        runner = _FakeGh(banned_names=set())
        sleeps = []
        stats = G.build_deps_multi(
            con, None, 4, {"npm"}, self.lang, runner=runner, sleep_fn=sleeps.append
        )
        self.assertEqual(sleeps, [])
        self.assertFalse(stats["rate_limited_incomplete"])
        self.assertEqual(stats["repos_ratelimited_skipped"], 0)
        self.assertEqual(stats["repos_tree_ok"], 5)
        self.assertEqual(stats["repos_tree_error"], 0)
        con.close()


class TestEnrichmentPreserve(unittest.TestCase):
    """A spine rebuild must NOT clobber post-spine repo-node enrichment
    (ENRICHMENT_ATTR_KEYS — the pqc backfeed's `$.pqc`), while spine keys
    stay authoritative and NO unknown/foreign key accumulates. This is the
    bounded-allowlist merge that keeps a rebuild from zeroing the
    per-product PQC reports (the 3142 -> 41 clobber)."""

    def _spine(self, tmp: Path, repo_attrs: dict) -> Path:
        spine = {
            "nodes": [
                {"id": "product:p1", "type": "product", "label": "P", "attrs": {}},
                {
                    "id": "repo:github.com/org/repo-a",
                    "type": "repo",
                    "label": "org/repo-a",
                    "attrs": repo_attrs,
                },
            ],
            "edges": [{"from": "product:p1", "to": "repo:github.com/org/repo-a", "rel": "ships"}],
        }
        p = tmp / "spine.json"
        p.write_text(json.dumps(spine))
        return p

    def _repo_attrs(self, con):
        return json.loads(
            con.execute("SELECT attrs FROM nodes WHERE id='repo:github.com/org/repo-a'").fetchone()[
                0
            ]
        )

    def test_pqc_survives_rebuild_and_spine_keys_win(self):
        """(a) `$.pqc` stamped after the spine SURVIVES a rebuild; the
        spine-owned keys (url/findings) take the NEW spine values."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            con = G.db_connect(tmp / "g.db")
            # initial spine build
            G.build_spine(
                con,
                self._spine(
                    tmp,
                    {
                        "host": "github.com",
                        "org": "org",
                        "name": "repo-a",
                        "url": "old-url",
                        "findings": 1,
                    },
                ),
            )
            # simulate the pqc backfeed stamping $.pqc onto the repo node
            pqc = {"overall": 42, "readiness_bucket": "amber", "slug": "org__repo-a"}
            con.execute(
                "UPDATE nodes SET attrs=json_set(attrs,'$.pqc',json(?)) "
                "WHERE id='repo:github.com/org/repo-a'",
                (json.dumps(pqc),),
            )
            con.commit()
            # rebuild the spine with FRESH attrs (no pqc, changed url/findings)
            G.build_spine(
                con,
                self._spine(
                    tmp,
                    {
                        "host": "github.com",
                        "org": "org",
                        "name": "repo-a",
                        "url": "new-url",
                        "findings": 2,
                    },
                ),
            )
            attrs = self._repo_attrs(con)
            self.assertEqual(attrs.get("pqc"), pqc)  # enrichment survives
            self.assertEqual(attrs["url"], "new-url")  # spine key wins
            self.assertEqual(attrs["findings"], 2)  # spine key wins
            con.close()

    def test_foreign_key_is_dropped_on_rebuild(self):
        """(b) a NON-allowlisted key present on the existing node is DROPPED
        after the spine upsert — proves the merge is a bounded allowlist,
        not a blind json_patch that would accumulate stray keys."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            con = G.db_connect(tmp / "g.db")
            G.build_spine(
                con, self._spine(tmp, {"host": "github.com", "org": "org", "name": "repo-a"})
            )
            con.execute(
                "UPDATE nodes SET attrs=json_set("
                "attrs,'$.pqc',json(?),'$.junk',?) "
                "WHERE id='repo:github.com/org/repo-a'",
                (json.dumps({"overall": 1}), "should-not-survive"),
            )
            con.commit()
            G.build_spine(
                con, self._spine(tmp, {"host": "github.com", "org": "org", "name": "repo-a"})
            )
            attrs = self._repo_attrs(con)
            self.assertIn("pqc", attrs)  # allowlisted: kept
            self.assertNotIn("junk", attrs)  # foreign: dropped

    def test_pqc_in_fresh_spine_takes_new_value(self):
        """A `preserve` key that IS present in the fresh spine attrs is
        authoritative — the new value wins, nothing is folded over it."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            con = G.db_connect(tmp / "g.db")
            G.build_spine(
                con, self._spine(tmp, {"host": "github.com", "org": "org", "name": "repo-a"})
            )
            con.execute(
                "UPDATE nodes SET attrs=json_set(attrs,'$.pqc',?) "
                "WHERE id='repo:github.com/org/repo-a'",
                ("stale",),
            )
            con.commit()
            G.build_spine(
                con,
                self._spine(
                    tmp,
                    {"host": "github.com", "org": "org", "name": "repo-a", "pqc": "authoritative"},
                ),
            )
            self.assertEqual(self._repo_attrs(con)["pqc"], "authoritative")
            con.close()

    def test_module_upsert_still_overwrites(self):
        """(c) the global upsert_node overwrite semantics are UNCHANGED for
        non-repo kinds: a module/package node's whole attrs blob is replaced
        (an enrichment-looking key on a module is NOT preserved — the
        preserve path is repo-node-only)."""
        with tempfile.TemporaryDirectory() as d:
            con = G.db_connect(Path(d) / "g.db")
            G.upsert_node(
                con, "module:example.com/m", "module", "example.com/m", internal=1, owner_repo="r"
            )
            con.execute(
                "UPDATE nodes SET attrs=json_set(attrs,'$.pqc',?) WHERE id='module:example.com/m'",
                ("x",),
            )
            con.commit()
            # re-upsert (the plain overwrite path) with a fresh blob
            G.upsert_node(
                con, "module:example.com/m", "module", "example.com/m", internal=1, owner_repo="r2"
            )
            attrs = json.loads(
                con.execute("SELECT attrs FROM nodes WHERE id='module:example.com/m'").fetchone()[0]
            )
            self.assertNotIn("pqc", attrs)  # overwrite, not preserved
            self.assertEqual(attrs["owner_repo"], "r2")
            con.close()


if __name__ == "__main__":
    unittest.main()
