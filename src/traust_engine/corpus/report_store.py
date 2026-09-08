"""One way to reach a report — ledger plan §4.4.0 step 2.

Every consumer today reaches a report by filesystem path, and several derive
meaning from the directory structure around it. That is the coupling stopping
reports from moving to object storage while the ledger stays in git (§4.4.0).
This module is the seam: consumers ask a store for a report, and the store knows
whether that means a file, a bucket object, or something else later.

Two halves, because they fail differently:

**Fetching** is easy and is where step 1 pays off. `get()` takes the digest the
layer recorded (`metadata.audit_report_sha256`) and verifies the bytes it read, so
a consumer proves what it got instead of trusting the store. That is the property
a least-privilege front-end needs, and it works identically against a local file
or a signed URL.

**Enumerating** is the hard half, and measurement (2026-08-19) settled how:
`corpus.resolver.ReportRecord` derives four things from the filesystem that a
bucket listing cannot cheaply reproduce — a nullable `product` segment (28 repos sit
directly at `findings/<repo>/`), records that are *sets* of six co-located artifacts
whose `preferred`/`report_kind` depend on which exist, symlink aliases that object
storage has no equivalent for, and ownership joined on `tree`. So enumeration reads
an **index** built from the resolver itself, and a full listing is the rebuild/verify
path rather than the read path. Building the index from `resolve()` rather than
re-deriving identity is deliberate: a second implementation of identity is the exact
mistake D1/D7 exist to prevent.

Local is byte-identical to today's behaviour on purpose — the seam has to land with
no behaviour change, so that if it is wrong you find out while every file is still
where it always was.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from traust_contracts.config import CorpusConfig

from traust_engine.corpus.resolver import (
    ReportRecord,
    Resolution,
    _flag_nested_duplicate_dirs,
    active_trees,
    resolve,
)

__all__ = [
    "DigestMismatch",
    "LocalBackend",
    "MemoryBackend",
    "ReportStore",
    "load_resolution",
    "to_ref",
]


class DigestMismatch(Exception):
    """The bytes read do not match the digest the caller expected."""


class Backend(Protocol):
    """A place reports live. Refs are opaque strings the backend defines."""

    def read(self, ref: str) -> bytes: ...
    def write(self, ref: str, data: bytes) -> None: ...
    def exists(self, ref: str) -> bool: ...
    def list(self, prefix: str = "") -> Iterable[str]: ...


class LocalBackend:
    """Refs are paths relative to a root — today's layout, unchanged."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path(self, ref: str) -> Path:
        p = (self.root / ref).resolve()
        root = self.root.resolve()
        try:
            p.relative_to(root)
        except ValueError:
            # Same containment rule the ledger writers use: a ref must not
            # escape the root, including via symlink.
            raise ValueError(f"ref {ref!r} resolves outside {root}") from None
        return p

    def read(self, ref: str) -> bytes:
        return self._path(ref).read_bytes()

    def write(self, ref: str, data: bytes) -> None:
        p = self._path(ref)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def exists(self, ref: str) -> bool:
        try:
            return self._path(ref).is_file()
        except ValueError:
            return False

    def list(self, prefix: str = "") -> Iterable[str]:
        base = self.root
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            ref = str(p.relative_to(base))
            if ref.startswith(prefix):
                yield ref


class MemoryBackend:
    """For tests: consumer tests currently need a findings tree on disk."""

    def __init__(self, initial: dict[str, bytes] | None = None) -> None:
        self._data: dict[str, bytes] = dict(initial or {})

    def read(self, ref: str) -> bytes:
        return self._data[ref]

    def write(self, ref: str, data: bytes) -> None:
        self._data[ref] = data

    def exists(self, ref: str) -> bool:
        return ref in self._data

    def list(self, prefix: str = "") -> Iterable[str]:
        return sorted(r for r in self._data if r.startswith(prefix))


class ReportStore:
    """The accessor consumers depend on instead of a path."""

    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def get(self, ref: str, *, expect_sha256: str | None = None) -> bytes:
        data = self.backend.read(ref)
        if expect_sha256:
            actual = hashlib.sha256(data).hexdigest()
            if actual != expect_sha256:
                raise DigestMismatch(
                    f"{ref}: expected {expect_sha256[:12]}…, read {actual[:12]}… — "
                    "the bytes are not the ones the ledger annotated"
                )
        return data

    def get_json(self, ref: str, *, expect_sha256: str | None = None) -> dict:
        return json.loads(self.get(ref, expect_sha256=expect_sha256).decode("utf-8"))

    def put(self, data: bytes, ref: str) -> str:
        self.backend.write(ref, data)
        return ref

    def exists(self, ref: str) -> bool:
        return self.backend.exists(ref)

    def list(self, prefix: str = "") -> list[str]:
        return list(self.backend.list(prefix))


# --- enumeration -------------------------------------------------------------


def to_ref(value: str | None, analysis_results: str | Path) -> str | None:
    """Relativize an artifact path against the corpus root WITHOUT dereferencing links.

    The first version called ``Path(value).resolve()``, which follows symlinks.
    Measured against a real corpus, that rewrote 12 records' `triage_json` /
    `threat_model` to their link *targets* — repo-a's triage became repo-b's file.
    Same bytes today, a different artifact identity,
    and the resolver keeps symlink aliases distinct on purpose (§4.4.0: object storage
    has no symlink analogue, so aliases must survive as data rather than dissolve into
    their targets).

    One implementation on purpose. There were two — this one and a copy inside
    ``findings_db.insert_record`` which still had the bug and had already written it
    into a shipped database: one repo's row cited its triage and threat model under
    a sibling release tree — a different artifact identity entirely.

    The PTH100 suppressions are the point of the fix: ruff wants ``Path.resolve()``,
    which is the call that caused it. ``Path.absolute()`` does not normalize "..", so
    ``os.path.abspath`` is the one that normalizes lexically and leaves links alone.
    """
    if not value:
        return None
    root = Path(analysis_results).resolve()
    root_abs = Path(os.path.abspath(analysis_results))  # noqa: PTH100
    ap = Path(os.path.abspath(value))  # noqa: PTH100
    for base in (root_abs, root):
        try:
            rel = ap.relative_to(base)
        except ValueError:
            continue
        if ".." not in rel.parts:
            return str(rel)
    return value


ARTIFACT_FIELDS = (
    "audit_json",
    "audit_md",
    "findings_current",
    "findings_layer",
    "triage_json",
    "threat_model",
)

REPOS_COLUMNS = (
    "tree",
    "label",
    "ownership",
    "business_unit",
    "product",
    "repo_dir",
    "base",
    "base_slug",
    "ref",
    "ref_kind",
    "ref_source",
    "audit_json",
    "audit_md",
    "findings_current",
    "findings_layer",
    "triage_json",
    "threat_model",
    "preferred",
    "repo_url",
    "report_kind",
)

from traust_engine.locations import FINDINGS_DB_REL as FINDINGS_DB  # noqa: E402


def _records_from_db(db_path: Path, root: Path) -> list[ReportRecord] | None:
    """Rehydrate ReportRecords from findings.db's `repos` table, or None if it cannot.

    `repos` IS the index: one row per report record, carrying every ReportRecord
    field. An earlier version of this module built a second one (report-index.json)
    holding the same facts, which meant two artifacts to keep fresh and two ways for
    them to disagree. Retracted 2026-08-20 — see the ledger plan §4.4.0.

    Returns None rather than raising on a missing or old-shaped database, because
    "no usable index" must mean "walk the tree", never "the corpus is empty".
    """
    if not db_path.is_file():
        return None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        have = {r[1] for r in con.execute("PRAGMA table_info(repos)")}
        if not set(REPOS_COLUMNS) <= have:
            return None  # pre-migration database; the walk is still correct
        rows = con.execute(f"SELECT {', '.join(REPOS_COLUMNS)} FROM repos").fetchall()
    except sqlite3.Error:
        return None
    finally:
        con.close()

    out = []
    for row in rows:
        vals = dict(zip(REPOS_COLUMNS, row, strict=True))
        for f in ARTIFACT_FIELDS:
            ref = vals.get(f)
            if ref and not Path(ref).is_absolute():
                vals[f] = str(root / ref)
        out.append(ReportRecord(**vals))
    return out


def load_resolution(
    analysis_results: Path,
    cfg: CorpusConfig,
    trees: list[str] | None = None,
    with_repo_urls: bool = False,
    *,
    prefer_index: bool = True,
) -> Resolution:
    """Population, from findings.db when it is usable, from the tree when it is not.

    This is the seam that stops discovery depending on directory listing (plan
    §4.4.0 step 2). ``resolve()`` stays the rebuild/verify route and findings.db's
    only source — building the population from anything else would be a second
    implementation of identity, which D1/D7 exist to prevent.
    """
    root = Path(analysis_results)
    records = _records_from_db(root / FINDINGS_DB, root) if prefer_index else None
    if records is None:
        return resolve(root, cfg, trees=trees, with_repo_urls=with_repo_urls)

    selected = active_trees(cfg, root)
    selected = {t: m for t, m in selected.items() if m.ownership != "harness-qa"}
    if trees is not None:
        selected = {t: m for t, m in selected.items() if t in trees}
    records = [r for r in records if r.tree in selected]
    if not with_repo_urls:
        for r in records:  # field-identical to the walk, which leaves it unset
            r.repo_url = None

    res = Resolution(
        analysis_results=str(root),
        records=records,
        aliases=[],
        trees=selected,
        warnings=[],
    )
    _flag_nested_duplicate_dirs(res)
    return res
