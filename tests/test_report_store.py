"""report_store — the seam reports move through (plan §4.4.0 step 2).

The tests that matter here are the two properties the storage move depends on:
`get()` verifies the bytes against the digest the ledger recorded, and the index
reproduces the resolver's walk EXACTLY. The second is the census gate in miniature —
census drift is silent (plan §4.4.13), so parity is asserted rather than assumed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

import pytest
from traust_contracts import CorpusConfig

from traust_engine.corpus.report_store import (
    DigestMismatch,
    LocalBackend,
    MemoryBackend,
    ReportStore,
    load_resolution,
    to_ref,
)
from traust_engine.corpus.resolver import resolve

AUDIT = {
    "title": "t",
    "metadata": {
        "date": "2026-08-19",
        "scope": "s",
        "repository": "https://github.com/org/repo",
        "commit": "a" * 40,
        "harness_version": "0.298.0",
    },
    "findings": [],
}


def _tree(tmp_path: Path) -> tuple[Path, dict]:
    """A findings tree with the shapes the resolver is depth-tolerant about."""
    root = tmp_path / "analysis-results"
    # product/repo/ (deep) and repo/ (shallow — 28 real repos look like this)
    for rel in ("findings/productA/repo1", "findings/repo2"):
        d = root / rel
        d.mkdir(parents=True)
        base = Path(rel).name
        (d / f"{base}-security-audit.json").write_text(json.dumps(AUDIT))
        (d / f"{base}-findings-layer.json").write_text(
            json.dumps(
                {
                    "metadata": {
                        "audit_report": f"{base}-security-audit.json",
                        "repository": "https://github.com/org/repo",
                        "created": "2026-08-19T00:00:00+00:00",
                        "harness_version": "0.298.0",
                    },
                    "events": [],
                    "needs_review": [],
                }
            )
        )
    cfg = CorpusConfig.model_validate(
        {
            "version": 1,
            "trees": {
                "findings": {
                    "label": "Findings",
                    "ownership": "owned",
                    "business_unit": "example_bu",
                }
            },
        }
    )
    return root, cfg


# --- fetching ---------------------------------------------------------------


def test_get_verifies_the_digest_the_ledger_recorded():
    payload = b'{"findings": []}'
    store = ReportStore(MemoryBackend({"r.json": payload}))
    assert store.get("r.json", expect_sha256=hashlib.sha256(payload).hexdigest())


def test_get_refuses_bytes_that_do_not_match():
    """The property a least-privilege front-end needs: prove what you read."""
    store = ReportStore(MemoryBackend({"r.json": b"substituted"}))
    with pytest.raises(DigestMismatch) as e:
        store.get("r.json", expect_sha256="0" * 64)
    assert "not the ones the ledger annotated" in str(e.value)


def test_get_without_a_digest_still_works():
    """Layers predating step 1 record no digest; that is not a failure."""
    store = ReportStore(MemoryBackend({"r.json": b"{}"}))
    assert store.get("r.json") == b"{}"


def test_local_backend_refuses_a_ref_escaping_the_root(tmp_path):
    (tmp_path / "inside").mkdir()
    store = ReportStore(LocalBackend(tmp_path / "inside"))
    with pytest.raises(ValueError):
        store.get("../outside.json")


def test_local_backend_round_trips(tmp_path):
    store = ReportStore(LocalBackend(tmp_path))
    store.put(b'{"a": 1}', "sub/dir/r.json")
    assert store.exists("sub/dir/r.json")
    assert store.get_json("sub/dir/r.json") == {"a": 1}


# --- enumeration ------------------------------------------------------------


def _build_db(root, cfg):
    """findings.db IS the index — build it the way the corpus does."""
    from traust_engine.corpus import findings_db as bdb

    out = root / "graph" / "findings.db"
    out.parent.mkdir(parents=True, exist_ok=True)
    bdb.build(root, out, cfg=cfg)
    return out


def test_load_resolution_from_the_db_matches_the_walk_field_for_field(tmp_path):
    """The acceptance bar for step 2a. `repos` carries every ReportRecord field, so a
    consumer reading it must see exactly what walking the tree would have given —
    otherwise switching a consumer to the db is a behaviour change wearing a
    refactor's clothes, and it shows up as a missing artifact rather than an error.
    """
    root, cfg = _tree(tmp_path)
    walked = resolve(root, cfg)
    _build_db(root, cfg)
    indexed = load_resolution(root, cfg)

    def key(r):
        return (r.tree, r.product or "", r.repo_dir, r.base)

    assert [asdict(r) for r in sorted(walked.records, key=key)] == [
        asdict(r) for r in sorted(indexed.records, key=key)
    ]
    assert walked.trees == indexed.trees


def test_load_resolution_falls_back_to_the_walk_when_there_is_no_db(tmp_path):
    root, cfg = _tree(tmp_path)
    assert len(load_resolution(root, cfg).records) == len(resolve(root, cfg).records)


def test_load_resolution_honours_the_trees_filter(tmp_path):
    root, cfg = _tree(tmp_path)
    _build_db(root, cfg)
    tree = sorted({r.tree for r in resolve(root, cfg).records})[0]
    got = load_resolution(root, cfg, trees=[tree])
    assert {r.tree for r in got.records} == {tree}
    assert set(got.trees) == {tree}


def test_load_resolution_repo_urls_are_opt_in_both_ways(tmp_path):
    """repos always stores repo_url; a caller that did not ask must not see it, or
    db-backed records diverge from walked ones on a field consumers compare."""
    root, cfg = _tree(tmp_path)
    _build_db(root, cfg)
    assert all(r.repo_url is None for r in load_resolution(root, cfg).records)
    walked = {(r.tree, r.base): r.repo_url for r in resolve(root, cfg, with_repo_urls=True).records}
    indexed = {
        (r.tree, r.base): r.repo_url
        for r in load_resolution(root, cfg, with_repo_urls=True).records
    }
    assert walked == indexed


def test_a_db_missing_the_record_columns_is_ignored_rather_than_trusted(tmp_path):
    """A pre-migration database must send the caller back to the walk. Returning its
    rows anyway would hand consumers a population shaped by a schema that no longer
    describes a ReportRecord; returning nothing would make the corpus look empty."""
    import sqlite3

    root, cfg = _tree(tmp_path)
    db = root / "graph" / "findings.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE repos (repo_key TEXT, tree TEXT)")
    con.commit()
    con.close()
    assert len(load_resolution(root, cfg).records) == len(resolve(root, cfg).records)


def test_to_ref_does_not_dereference_symlinks(tmp_path):
    """Found on the real corpus, not here: the ref helper used Path.resolve(), which
    follows links, and rewrote 12 records' companions to their link targets — a
    different artifact identity wearing the same bytes. Symlink aliases are data the
    resolver tracks on purpose (object storage has no symlink), so they must survive.
    """
    root, _cfg = _tree(tmp_path)
    d = root / "findings" / "linked"
    d.mkdir(parents=True)
    target = root / "findings" / "target.json"
    target.write_text("{}")
    (d / "alias.json").symlink_to(target)
    assert to_ref(str(d / "alias.json"), root) == "findings/linked/alias.json"


def test_to_ref_leaves_a_path_outside_the_root_alone(tmp_path):
    assert to_ref("/etc/passwd", tmp_path) == "/etc/passwd"
    assert to_ref(None, tmp_path) is None
