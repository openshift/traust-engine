"""traust_engine.storage — URI-addressed locations for large artifacts.

The invariants worth pinning are the ones that would quietly break a
deployment: local must stay zero-cost and dependency-free, a remote URI
must never be mangled into a local path, and a missing backend must fail
with an actionable message instead of an ImportError from deep in a call
stack.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from traust_contracts import Locations

from traust_engine import locations as config
from traust_engine import storage

# --- local: the common path must not change or acquire a dependency ------


@pytest.mark.parametrize("loc", ["/tmp/x/y", "file:///tmp/x/y", Path("/tmp/x/y")])
def test_local_locations_are_not_remote(loc):
    assert storage.is_remote(loc) is False


@pytest.mark.parametrize(
    "uri",
    [
        "s3://bucket/key",
        "gs://bucket/key",
        "gcs://b/k",
        "az://c/k",
        "abfs://c/k",
        "https://host/obj",
    ],
)
def test_remote_schemes_detected(uri):
    assert storage.is_remote(uri) is True


def test_localize_returns_local_path_unchanged(tmp_path):
    f = tmp_path / "graph.db"
    f.write_bytes(b"x")
    assert storage.localize(str(f)) == f
    assert storage.localize(f"file://{f}") == f


def test_localize_never_copies_a_local_file(tmp_path):
    """A 3 GB local graph must not be duplicated into the cache."""
    f = tmp_path / "graph.db"
    f.write_bytes(b"x" * 1024)
    out = storage.localize(str(f))
    assert out == f and out.read_bytes() == b"x" * 1024


def test_local_path_imports_no_backend(tmp_path, monkeypatch):
    """The zero-cost claim, enforced: touching a local location must not
    import fsspec, so an operator with no object store pays nothing."""
    monkeypatch.delitem(sys.modules, "fsspec", raising=False)
    f = tmp_path / "a.db"
    f.write_bytes(b"x")
    storage.localize(str(f))
    storage.exists(str(f))
    storage.read_bytes(str(f))
    assert "fsspec" not in sys.modules


def test_none_in_none_out():
    """Unconfigured is a state the caller handles, not one we default."""
    assert storage.localize(None) is None
    assert storage.exists(None) is False
    assert storage.is_remote(None) is False


# --- join: the mangling bug this module exists to prevent ----------------


def test_join_preserves_a_remote_scheme():
    """`Path("s3://b") / "x"` yields "s3:/b/x" — silently wrong."""
    assert storage.join("s3://b/results", "graph", "g.db") == "s3://b/results/graph/g.db"
    assert storage.join("s3://b/results/", "graph") == "s3://b/results/graph"


def test_join_local_is_ordinary_path_join(tmp_path):
    assert storage.join(str(tmp_path), "graph", "g.db") == str(tmp_path / "graph" / "g.db")


# --- missing backend: actionable, not an ImportError ---------------------


def test_missing_backend_names_the_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "fsspec", None)  # force ImportError
    with pytest.raises(storage.StorageError) as e:
        storage.localize("s3://bucket/graph.db")
    msg = str(e.value)
    assert "traust-engine[remote]" in msg
    assert "s3" in msg


# --- config resolution ---------------------------------------------------


def test_analysis_results_location_reads_config():
    assert (
        config.analysis_results_location(Locations(analysis_results="s3://bucket/results"))
        == "s3://bucket/results"
    )
    assert (
        config.analysis_results_location(Locations(analysis_results="/local/results"))
        == "/local/results"
    )


def test_unconfigured_returns_none():
    assert config.analysis_results_location(None) is None
    assert config.portfolio_graph_location(None) is None


def test_graph_derives_from_results_location_and_keeps_scheme():
    loc = Locations(analysis_results="s3://bucket/results")
    assert config.portfolio_graph_location(loc) == "s3://bucket/results/graph/portfolio-graph.db"


def test_explicit_graph_uri_wins():
    loc = Locations(analysis_results="s3://bucket/results", portfolio_graph="gs://other/g.db")
    assert config.portfolio_graph_location(loc) == "gs://other/g.db"


def test_cache_dir_is_not_a_fixed_tmp_path(monkeypatch):
    """Multi-GB artifacts must survive between job steps, and a fixed
    world-writable /tmp name is the rule-S6 problem banned elsewhere."""
    monkeypatch.delenv("HARNESS_REMOTE_CACHE", raising=False)
    d = storage.cache_dir()
    assert not str(d).startswith("/tmp/")
    monkeypatch.setenv("HARNESS_REMOTE_CACHE", "/mnt/cache")
    assert storage.cache_dir() == Path("/mnt/cache")


# --- remote materialization ----------------------------------------------
# Exercised against a stub filesystem rather than a live bucket: the logic
# worth pinning is ours (cache keying, atomic publish, re-fetch avoidance),
# not fsspec's. A stub also keeps the suite runnable with no extra installed.


class _StubFS:
    """Minimal fsspec-shaped filesystem over a local directory."""

    def __init__(self, root: Path, etag="v1"):
        self.root, self.etag, self.gets = root, etag, 0

    def _p(self, path):
        return self.root / str(path).lstrip("/")

    def info(self, path):
        p = self._p(path)
        return {"ETag": self.etag, "size": p.stat().st_size if p.is_file() else 0}

    def isdir(self, path):
        return self._p(path).is_dir()

    def exists(self, path):
        return self._p(path).exists()

    def get_file(self, path, dest):
        self.gets += 1
        Path(dest).write_bytes(self._p(path).read_bytes())

    def get(self, path, dest, recursive=False):
        self.gets += 1
        import shutil as _sh

        _sh.copytree(self._p(path), dest)


@pytest.fixture()
def stub_remote(tmp_path, monkeypatch):
    src = tmp_path / "bucket"
    (src / "graph").mkdir(parents=True)
    (src / "graph" / "portfolio-graph.db").write_bytes(b"SQLITE" * 100)
    fs = _StubFS(src)
    monkeypatch.setattr(storage, "_fs", lambda uri: (fs, uri.split("://", 1)[1].split("/", 1)[1]))
    monkeypatch.setenv("HARNESS_REMOTE_CACHE", str(tmp_path / "cache"))
    return fs


def test_remote_file_is_materialized_locally(stub_remote):
    out = storage.localize("s3://bucket/graph/portfolio-graph.db")
    assert out.is_file() and out.read_bytes() == b"SQLITE" * 100
    assert stub_remote.gets == 1


def test_second_call_reuses_the_cache(stub_remote):
    """A 3 GB graph must not be re-downloaded on every advisory."""
    a = storage.localize("s3://bucket/graph/portfolio-graph.db")
    b = storage.localize("s3://bucket/graph/portfolio-graph.db")
    assert a == b
    assert stub_remote.gets == 1, "cache miss on an unchanged object"


def test_changed_etag_forces_a_refetch(stub_remote):
    storage.localize("s3://bucket/graph/portfolio-graph.db")
    stub_remote.etag = "v2"
    second = storage.localize("s3://bucket/graph/portfolio-graph.db")
    assert stub_remote.gets == 2
    assert second.is_file()


def test_refresh_flag_bypasses_the_cache(stub_remote):
    storage.localize("s3://bucket/graph/portfolio-graph.db")
    storage.localize("s3://bucket/graph/portfolio-graph.db", refresh=True)
    assert stub_remote.gets == 2


def test_no_partial_artifact_survives_a_failed_fetch(stub_remote, monkeypatch):
    """A truncated 3 GB graph that looks complete would silently produce
    wrong blast-radius answers — worse than no graph at all."""

    def boom(path, dest):
        Path(dest).write_bytes(b"partial")
        raise OSError("connection reset")

    monkeypatch.setattr(stub_remote, "get_file", boom)
    with pytest.raises(storage.StorageError):
        storage.localize("s3://bucket/graph/portfolio-graph.db")
    cached = list((storage.cache_dir()).rglob("portfolio-graph.db"))
    assert cached == [], "a partial download was published to the cache"


def test_remote_exists_does_not_download(stub_remote):
    assert storage.exists("s3://bucket/graph/portfolio-graph.db") is True
    assert storage.exists("s3://bucket/graph/absent.db") is False
    assert stub_remote.gets == 0


# --- S3-compatible endpoints (MinIO / ODF / Ceph RGW) --------------------
# Without an endpoint override, url_to_fs("s3://…") resolves to AWS and the
# failure reads like bad credentials rather than "wrong endpoint" — which is
# why on-cluster object storage is the case this needs explicit tests.


def test_no_endpoint_means_no_options(monkeypatch):
    for v in (
        "HARNESS_S3_ENDPOINT_URL",
        "HARNESS_S3_REGION",
        "HARNESS_S3_CA_BUNDLE",
        "HARNESS_S3_PATH_STYLE",
        "HARNESS_STORAGE_OPTIONS",
    ):
        monkeypatch.delenv(v, raising=False)
    assert storage.storage_options("s3") == {}


def test_endpoint_url_is_passed_to_the_client(monkeypatch):
    monkeypatch.delenv("HARNESS_STORAGE_OPTIONS", raising=False)
    monkeypatch.setenv("HARNESS_S3_ENDPOINT_URL", "https://minio.apps.example:9000")
    opts = storage.storage_options("s3")
    assert opts["client_kwargs"]["endpoint_url"] == "https://minio.apps.example:9000"


def test_private_ca_bundle_is_verify_not_disable(monkeypatch):
    """A CA bundle is offered; a verify=False switch deliberately is not."""
    monkeypatch.delenv("HARNESS_STORAGE_OPTIONS", raising=False)
    monkeypatch.setenv("HARNESS_S3_CA_BUNDLE", "/etc/pki/ca.crt")
    opts = storage.storage_options("s3")
    assert opts["client_kwargs"]["verify"] == "/etc/pki/ca.crt"
    assert "verify=False" not in str(opts)


def test_path_style_addressing_for_stores_without_wildcard_dns(monkeypatch):
    monkeypatch.delenv("HARNESS_STORAGE_OPTIONS", raising=False)
    monkeypatch.setenv("HARNESS_S3_PATH_STYLE", "true")
    opts = storage.storage_options("s3")
    assert opts["config_kwargs"]["s3"]["addressing_style"] == "path"


def test_escape_hatch_merges_over_derived_options(monkeypatch):
    monkeypatch.setenv("HARNESS_S3_ENDPOINT_URL", "https://a")
    monkeypatch.setenv("HARNESS_STORAGE_OPTIONS", '{"anon": true, "key": "k"}')
    opts = storage.storage_options("s3")
    assert opts["anon"] is True and opts["key"] == "k"
    assert opts["client_kwargs"]["endpoint_url"] == "https://a"


def test_bad_escape_hatch_json_is_actionable(monkeypatch):
    monkeypatch.setenv("HARNESS_STORAGE_OPTIONS", "{not json")
    with pytest.raises(storage.StorageError, match="HARNESS_STORAGE_OPTIONS"):
        storage.storage_options("s3")


def test_s3_options_do_not_leak_to_other_schemes(monkeypatch):
    monkeypatch.delenv("HARNESS_STORAGE_OPTIONS", raising=False)
    monkeypatch.setenv("HARNESS_S3_ENDPOINT_URL", "https://minio:9000")
    assert storage.storage_options("gs") == {}
