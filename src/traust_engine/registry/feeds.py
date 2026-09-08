"""Consumer API for cached external reference feeds (read-only)."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from traust_contracts import DeploymentConfigMissing

from traust_engine.locations import configured_locations, feeds_cache_dir

# Example URL only — operators must point fetch_feeds at a real registry
# endpoint via deployment config; nothing VPN-only ships by default.
FEEDS = {
    "product-definitions": {
        "url": "https://example.com/product-definitions/products.json",
        "file": "product_definitions.json",
        "max_age_hours": 24.0 * 30,
        "internal": False,
    },
}

PRODUCT_DEFINITIONS_KEYS = ("ps_products", "ps_modules", "ps_update_streams")


def default_cache_dir() -> Path:
    """The configured feeds-cache directory, or raise when unset."""
    cache = feeds_cache_dir(configured_locations())
    if cache is None:
        raise DeploymentConfigMissing(
            "feeds-cache not configured — set `feeds_cache` in $TRAUST_CONFIG_HOME/locations.yaml."
        )
    return cache


def _read_meta(cache: Path) -> dict:
    try:
        return json.loads((cache / "feeds-meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _age_hours(meta_entry: dict) -> float | None:
    try:
        t = datetime.datetime.strptime(
            meta_entry["retrieved_at"],
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=datetime.UTC)
    except (KeyError, ValueError):
        return None
    return (datetime.datetime.now(datetime.UTC) - t).total_seconds() / 3600


def feed_status(cache: Path, max_age_hours: float | None = None) -> dict:
    meta = _read_meta(cache)
    out = {}
    for name, spec in FEEDS.items():
        entry = meta.get(name) or {}
        present = (cache / spec["file"]).is_file()
        age = _age_hours(entry) if present else None
        threshold = max_age_hours if max_age_hours is not None else spec["max_age_hours"]
        out[name] = {
            "present": present,
            "retrieved_at": entry.get("retrieved_at"),
            "feed_version": entry.get("feed_version"),
            "age_hours": None if age is None else round(age, 1),
            "max_age_hours": threshold,
            "internal": bool(spec.get("internal")),
            "stale": not present or age is None or age > threshold,
        }
    return out


def load_product_definitions(cache: Path) -> dict:
    doc = json.loads((cache / FEEDS["product-definitions"]["file"]).read_text(encoding="utf-8"))
    missing = [k for k in PRODUCT_DEFINITIONS_KEYS if not isinstance(doc.get(k), dict)]
    if missing:
        raise ValueError(
            f"product-definitions cache is missing/malformed top-level key(s): {', '.join(missing)}"
        )
    return doc
