"""Model registry loader/resolver — multi-model-strategy-plan M0/M1.

config/model-registry.yaml is the ONLY place vendor/model identifiers
live (alignment rule A11 enforces this). This tool is how everything
else consults it:

  validate                       schema-validate the registry (CI/pre-commit)
  list                           roles with floor/approved models
  resolve ROLE [--tier T]        print the model to use for a role —
                                 first approved model at the role floor
                                 (or an explicit escalation --tier)
  stamp ROLE MODEL               emit the metadata.additional.model_routing
                                 JSON block (role, model, registry sha)
  spend --skill S --model M --tokens-in N --tokens-out N [--batch B]
                                 append a spend row to the hash-chained
                                 metrics ledger (source model-spend:<skill>)
                                 with cost computed when the registry has
                                 prices

Exit 0 ok; 1 validation/resolution failure; 2 usage.
"""

from __future__ import annotations

from traust_contracts import ModelRegistry

_TIER_ORDER = ["haiku-class", "sonnet-class", "opus-class", "mythos-class"]


def validate(reg: ModelRegistry) -> list[str]:
    """Semantic cross-checks beyond the JSON schema (which load_context
    already applied): tier membership and floor/approved consistency."""
    errors: list[str] = []
    models = reg.all_models()
    tiers = set(reg.tiers)
    for mid, m in models.items():
        if m.tier not in tiers:
            errors.append(f"model {mid}: unknown tier {m.tier}")
    for role, r in reg.roles.items():
        if r.floor not in tiers:
            errors.append(f"role {role}: unknown floor {r.floor}")
        for mid in r.approved + r.candidates:
            if mid not in models:
                errors.append(f"role {role}: model {mid} not in any provider")
        for mid in r.approved:
            if mid in models and _TIER_ORDER.index(models[mid].tier) < _TIER_ORDER.index(r.floor):
                errors.append(
                    f"role {role}: approved model {mid} "
                    f"({models[mid].tier}) is below the floor {r.floor}"
                )
    return errors


def resolve(reg: ModelRegistry, role: str, tier: str | None = None) -> str:
    r = reg.roles.get(role)
    if r is None:
        raise KeyError(f"unknown role '{role}' — roles: {sorted(reg.roles)}")
    want = tier or r.floor
    if want not in _TIER_ORDER:
        raise KeyError(f"unknown tier '{want}'")
    if _TIER_ORDER.index(want) < _TIER_ORDER.index(r.floor):
        raise ValueError(
            f"tier {want} is below role '{role}' floor {r.floor} — "
            f"tier-downs below the floor are never allowed"
        )
    models = reg.all_models()
    for mid in r.approved:
        m = models.get(mid)
        if m is not None and m.tier == want:
            return mid
    # escalation request above floor with no exact-tier approval: take the
    # lowest approved tier >= requested
    ranked = sorted(
        (mid for mid in r.approved if mid in models),
        key=lambda mid: _TIER_ORDER.index(models[mid].tier),
    )
    for mid in ranked:
        if _TIER_ORDER.index(models[mid].tier) >= _TIER_ORDER.index(want):
            return mid
    raise ValueError(f"role '{role}': no approved model at or above {want}")


def stamp(reg: ModelRegistry, role: str, model: str) -> dict:
    r = reg.roles.get(role)
    return {
        "role": role,
        "model": model,
        "registry_sha": reg.source_sha,
        "floor": r.floor if r is not None else None,
    }


CACHE_READ_MULT = 0.1  # published cache pricing relative to input
CACHE_WRITE_MULT = 1.25


def cost_usd(
    reg: ModelRegistry,
    model: str,
    tok_in: int,
    tok_out: int,
    cache_read: int = 0,
    cache_creation: int = 0,
) -> float | None:
    """Cache-aware cost from registry list prices; None when unpriced."""
    m = reg.all_models().get(model)
    if m is None:
        return None
    pin, pout = m.price_per_mtok_in, m.price_per_mtok_out
    if pin is None or pout is None:
        return None
    return round(
        tok_in / 1e6 * pin
        + tok_out / 1e6 * pout
        + cache_read / 1e6 * pin * CACHE_READ_MULT
        + cache_creation / 1e6 * pin * CACHE_WRITE_MULT,
        4,
    )


def spend_row(
    reg: ModelRegistry,
    model: str,
    tok_in: int,
    tok_out: int,
    cache_read: int = 0,
    cache_creation: int = 0,
    repo: str | None = None,
    loc: int | None = None,
) -> dict:
    row = {
        "model": model,
        "tokens_in": tok_in,
        "tokens_out": tok_out,
        "cost_usd": cost_usd(reg, model, tok_in, tok_out, cache_read, cache_creation),
        "registry_sha": reg.source_sha,
    }
    if cache_read or cache_creation:
        row["cache_read"] = cache_read
        row["cache_creation"] = cache_creation
    # per-repo attribution — the calibration tuple (spend, repo, size)
    # estimate_scan fits against (estimate-calibration-analysis.md F5)
    if repo:
        row["repo"] = repo
    if loc is not None:
        row["loc"] = loc
    return row
