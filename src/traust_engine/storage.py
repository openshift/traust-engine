"""URI-addressed storage for the harness's large read-mostly artifacts.

WHY
    The analyzer and the graph builders were written against local POSIX
    paths: `ANALYSIS_RESULTS_DIR / "graph" / "sboms"`, `sqlite3.connect(
    f"file:{db}?mode=ro")`. That is correct for an operator workstation and
    wrong for the deployment this suite is heading toward — a scheduled job
    on an orchestrator, with findings and a multi-gigabyte portfolio graph
    in object storage. Both locations were "configurable" only in the narrow
    sense that they were parameterized; both were still typed and consumed
    as local paths.

DESIGN
    Local is the zero-cost path. A bare path or a `file://` URI takes a
    branch that imports nothing, allocates nothing, and behaves exactly as
    before — the overwhelmingly common case must not pay for the rare one,
    and an operator with no object store must not acquire a dependency.

    Remote MATERIALIZES to a local cache rather than streaming. This is a
    deliberate choice, not a shortcut: the portfolio graph is a ~3 GB SQLite
    file with `idx_edges_{src,dst,rel}`, and one impact analysis issues
    thousands of small indexed reads against it. Object stores have no
    random-access read semantics, so a VFS shim would turn each index probe
    into a ranged GET. Fetching once per job and querying locally is both
    simpler and orders of magnitude faster. The cache is keyed on the
    remote's own validators (etag, else size+mtime), so a re-run with an
    unchanged artifact pays nothing.

    Remote backends come from `fsspec` behind the `remote` extra, imported
    lazily. A missing extra raises a StorageError naming the install, not an
    ImportError from six frames down.

USAGE
    from traust_engine import storage
    db = storage.localize(cfg.portfolio_graph_uri())   # -> local Path
    if storage.exists(results_uri / "graph/sboms"): ...
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

__all__ = [
    "StorageError",
    "cache_dir",
    "exists",
    "is_remote",
    "localize",
    "read_bytes",
    "storage_options",
]

#: Schemes we hand to fsspec. `file` is handled locally and never appears.
_REMOTE_SCHEMES = ("s3://", "gs://", "gcs://", "az://", "abfs://", "http://", "https://")


class StorageError(RuntimeError):
    """A storage location is unusable, or its backend is not installed."""


def is_remote(loc: str | os.PathLike | None) -> bool:
    """True for a URI this module must fetch rather than open directly."""
    if loc is None:
        return False
    return str(loc).startswith(_REMOTE_SCHEMES)


def _strip_file_scheme(loc: str) -> str:
    return loc[7:] if loc.startswith("file://") else loc


def cache_dir() -> Path:
    """Where materialized remote artifacts land.

    `HARNESS_REMOTE_CACHE`, else `~/.cache/traust-engine/remote`. NOT a
    fixed `/tmp` path: these are multi-gigabyte artifacts that must survive
    between job steps, and a world-writable fixed name is the rule-S6
    problem the harness already bans elsewhere.
    """
    val = os.environ.get("HARNESS_REMOTE_CACHE")
    if val:
        return Path(val)
    return Path.home() / ".cache" / "traust-engine" / "remote"


def storage_options(scheme: str) -> dict:
    """Backend kwargs for a scheme, from the environment.

    S3-COMPATIBLE STORES ARE THE POINT OF THIS. MinIO, OpenShift Data
    Foundation and Ceph RGW all speak the S3 API at a private endpoint, so
    `url_to_fs("s3://…")` with no options resolves to AWS and fails in a way
    that reads like a credentials problem. `HARNESS_S3_ENDPOINT_URL` is the
    one knob that makes on-cluster object storage work at all.

    `HARNESS_STORAGE_OPTIONS` is the escape hatch for anything not covered:
    a JSON object merged over the derived options, so an unanticipated
    backend kwarg never requires a code change here.
    """
    import json as _json

    opts: dict = {}
    if scheme in ("s3", "s3a"):
        endpoint = os.environ.get("HARNESS_S3_ENDPOINT_URL")
        if endpoint:
            # s3fs passes client_kwargs through to botocore.
            opts["client_kwargs"] = {"endpoint_url": endpoint}
            region = os.environ.get("HARNESS_S3_REGION")
            if region:
                opts["client_kwargs"]["region_name"] = region
        # Most on-cluster deployments terminate TLS with a private CA; opt in
        # to a CA bundle rather than ever offering a verify=False switch.
        ca = os.environ.get("HARNESS_S3_CA_BUNDLE")
        if ca:
            opts.setdefault("client_kwargs", {})["verify"] = ca
        if os.environ.get("HARNESS_S3_PATH_STYLE", "").lower() in ("1", "true", "yes"):
            # MinIO and Ceph RGW commonly need path-style addressing; virtual
            # host style requires wildcard DNS the cluster may not have.
            opts.setdefault("config_kwargs", {})["s3"] = {"addressing_style": "path"}
    raw = os.environ.get("HARNESS_STORAGE_OPTIONS")
    if raw:
        try:
            opts.update(_json.loads(raw))
        except ValueError as e:
            raise StorageError(f"HARNESS_STORAGE_OPTIONS is not valid JSON: {e}") from e
    return opts


def _fs(uri: str):
    """The fsspec filesystem for a remote URI, or a StorageError."""
    try:
        import fsspec
    except ImportError as e:  # pragma: no cover - exercised via the error path
        scheme = uri.split("://", 1)[0]
        raise StorageError(
            f"remote storage location {uri!r} needs the optional backend: "
            f"pip install 'traust-engine[remote]' (and the {scheme} driver, "
            f"e.g. s3fs / gcsfs). Local paths and file:// need nothing."
        ) from e
    scheme = uri.split("://", 1)[0]
    return fsspec.core.url_to_fs(uri, **storage_options(scheme))


def _validator(uri: str) -> str:
    """A cache key for the remote object's current content.

    Prefers the store's own etag; falls back to size+mtime. Never hashes the
    object — the whole point is to avoid downloading 3 GB to decide whether
    we need to download 3 GB.
    """
    fs, path = _fs(uri)
    try:
        info = fs.info(path)
    except Exception as e:
        raise StorageError(f"cannot stat {uri!r}: {e}") from e
    tag = info.get("ETag") or info.get("etag") or info.get("checksum")
    if not tag:
        tag = f"{info.get('size', '?')}-{info.get('mtime', info.get('LastModified', '?'))}"
    return hashlib.sha256(f"{uri}\0{tag}".encode()).hexdigest()[:32]


def localize(loc: str | os.PathLike | None, *, refresh: bool = False) -> Path | None:
    """Return a LOCAL path for `loc`, fetching it first when remote.

    None in, None out — an unconfigured location is a normal state that the
    caller decides how to handle, not an error this function invents a
    default for.

    A local path is returned unchanged and is never copied.
    """
    if loc is None:
        return None
    s = str(loc)
    if not is_remote(s):
        return Path(_strip_file_scheme(s))

    key = _validator(s)
    dest = cache_dir() / key / Path(s.rstrip("/")).name
    if dest.exists() and not refresh:
        return dest

    fs, path = _fs(s)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        if fs.isdir(path):
            # get() with recursive writes the tree; a partial dir is worse
            # than none, so build beside the target and rename.
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)
            fs.get(path.rstrip("/") + "/", str(tmp), recursive=True)
        else:
            fs.get_file(path, str(tmp))
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True) if tmp.is_dir() else tmp.unlink(missing_ok=True)
        raise StorageError(f"fetch failed for {s!r}: {e}") from e
    # Atomic publish: a reader either sees no cache entry or a complete one.
    tmp.replace(dest)
    return dest


def exists(loc: str | os.PathLike | None) -> bool:
    """Existence check that does not download."""
    if loc is None:
        return False
    s = str(loc)
    if not is_remote(s):
        return Path(_strip_file_scheme(s)).exists()
    fs, path = _fs(s)
    try:
        return bool(fs.exists(path))
    except Exception:
        return False


def read_bytes(loc: str | os.PathLike) -> bytes:
    """Read a single object. For anything queried repeatedly use localize()."""
    s = str(loc)
    if not is_remote(s):
        return Path(_strip_file_scheme(s)).read_bytes()
    fs, path = _fs(s)
    try:
        with fs.open(path, "rb") as fh:
            return fh.read()
    except Exception as e:
        raise StorageError(f"read failed for {s!r}: {e}") from e


def join(loc: str | os.PathLike, *parts: str) -> str:
    """Join under a location, preserving a remote URI's scheme.

    `Path(...) / x` silently mangles `s3://bucket` into `s3:/bucket`, which
    is the shape of bug this module exists to prevent.
    """
    s = str(loc).rstrip("/")
    if not is_remote(s):
        return str(Path(_strip_file_scheme(s)).joinpath(*parts))
    return "/".join([s, *(p.strip("/") for p in parts)])
