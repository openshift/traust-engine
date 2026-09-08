"""``HarnessEngine.models`` — model registry and product-catalog ops."""

from __future__ import annotations

from pathlib import Path

from traust_contracts import ModelRegistry

from traust_engine import locations
from traust_engine._ops_base import ContextOps
from traust_engine.registry import feeds as feed_ops
from traust_engine.registry.models import cost_usd, resolve, spend_row, stamp, validate


class ModelsOps(ContextOps):
    def registry(self) -> ModelRegistry:
        return self._ctx.model_registry

    def validate(self) -> list[str]:
        return validate(self._ctx.model_registry)

    def resolve(self, role: str, tier: str | None = None) -> str:
        return resolve(self._ctx.model_registry, role, tier)

    def stamp(self, role: str, model: str) -> dict:
        return stamp(self._ctx.model_registry, role, model)

    def cost_usd(
        self,
        model: str,
        tok_in: int,
        tok_out: int,
        cache_read: int = 0,
        cache_creation: int = 0,
    ) -> float | None:
        return cost_usd(
            self._ctx.model_registry, model, tok_in, tok_out, cache_read, cache_creation
        )

    def spend_row(
        self,
        model: str,
        tok_in: int,
        tok_out: int,
        cache_read: int = 0,
        cache_creation: int = 0,
        repo: str | None = None,
        loc: int | None = None,
    ) -> dict:
        return spend_row(
            self._ctx.model_registry,
            model,
            tok_in,
            tok_out,
            cache_read,
            cache_creation,
            repo=repo,
            loc=loc,
        )

    def _feeds_cache(self) -> Path:
        return locations.require(locations.feeds_cache_dir(self._loc), "feeds_cache")

    def feeds_cache(self) -> Path:
        return self._feeds_cache()

    def feed_status(self, max_age_hours: float | None = None) -> dict:
        return feed_ops.feed_status(self._feeds_cache(), max_age_hours=max_age_hours)

    def load_product_definitions(self) -> dict:
        return feed_ops.load_product_definitions(self._feeds_cache())

    def packages_dir(self) -> Path | None:
        pt = locations.progress_tracker_dir(self._loc)
        return (pt / "processed-results") if pt else None
