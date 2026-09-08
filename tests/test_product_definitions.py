#!/usr/bin/env python3
"""Unit tests for traust_engine.registry.products (ownership resolver).

Fixture-driven, no network and no VPN.
"""

import datetime
import json

import pytest

from traust_engine.registry import products as pd

_ENGINE = None


@pytest.fixture(autouse=True)
def _bind_engine():
    global _ENGINE
    from traust_engine import HarnessEngine

    _ENGINE = HarnessEngine.load()
    yield
    _ENGINE = None


def _run_products(cache, *, mapfile=None, **kwargs):
    return pd.resolve_queries(
        cache_dir=cache,
        map_path=mapfile or (cache / "nonexistent.yaml"),
        json_only=True,
        engine=_ENGINE,
        **kwargs,
    )


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _dates():
    today = datetime.datetime.now(datetime.UTC).date()
    return (
        (today - datetime.timedelta(days=800)).isoformat(),
        (today - datetime.timedelta(days=30)).isoformat(),
        (today + datetime.timedelta(days=400)).isoformat(),
    )


def _fixture():
    past, recent, future = _dates()
    return {
        "ps_products": {
            "widget": {"name": "Example Widget", "ps_modules": ["widget-1"]},
            "gizmo": {"name": "Example Gizmo", "ps_modules": ["gizmo-1"]},
            "relic": {"name": "Example Relic", "ps_modules": ["relic-1"]},
            "future-thing": {"name": "Example Future Thing", "ps_modules": ["future-1"]},
        },
        "ps_modules": {
            "widget-1": {
                "public_description": "SECRET FREE TEXT MARKER",
                "ps_update_streams": ["widget-1-default"],
                "private_tracker_cc": ["embargoperson", "+unexpanded"],
                "component_cc": {"widget-core": ["componentperson"]},
                "default_cc": ["publicperson", "embargoperson"],
                "bts": {"name": "jboss", "key": "WIDGET"},
                "cpe": ["cpe:/a:redhat:widget:1"],
                "errata_product_tags": ["WIDGET"],
                "team": "legacy-team",
                "lifecycle": {"supported_from": recent, "supported_until": None},
            },
            "gizmo-1": {
                "ps_update_streams": ["gizmo-1-default"],
                "default_cc": ["gizmoperson"],
                "lifecycle": {"supported_from": recent, "supported_until": None},
            },
            "relic-1": {
                "ps_update_streams": [],
                "default_cc": ["relicperson"],
                "lifecycle": {"supported_from": past, "supported_until": recent},
            },
            "future-1": {
                "ps_update_streams": [],
                "default_cc": ["futureperson"],
                "lifecycle": {"supported_from": future, "supported_until": None},
            },
        },
        "ps_update_streams": {
            "widget-1-default": {
                "version": "1",
                "managed_service_components": [
                    {"name": "widget-api", "git_repo_url": "https://github.com/acme/widget-api"},
                ],
            },
            "gizmo-1-default": {"version": "1"},
        },
        "cc_list_aliases": {},
        "cc_groups": {},
        "contacts": {},
        "ps_components": {},
    }


@pytest.fixture()
def cache(tmp_path):
    d = tmp_path / "feeds"
    d.mkdir()
    (d / "product_definitions.json").write_text(json.dumps(_fixture()))
    now = datetime.datetime.now(datetime.UTC)
    (d / "feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": _iso(now)}})
    )
    return d


def _out(capsys, rc):
    assert rc == 0, "resolver must always exit 0"
    return json.loads(capsys.readouterr().out)


def _only(doc):
    assert len(doc["results"]) == 1
    return doc["results"][0]


class TestRepoUrlTier:
    def test_joins_stream_to_module_to_contacts(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, repo_urls=["https://github.com/acme/widget-api"]))
        r = _only(doc)
        assert doc["source_status"] == "ok"
        assert r["match_tier"] == "repo-url"
        assert r["ps_modules"] == ["widget-1"]
        assert r["ps_products"] == ["widget"]
        assert r["evidence"]["components"] == ["widget-api"]

    def test_url_normalisation(self, cache, capsys):
        for variant in (
            "https://github.com/acme/widget-api.git",
            "https://github.com/acme/widget-api/",
            "HTTPS://GitHub.com/ACME/Widget-API",
        ):
            doc = _out(capsys, _run_products(cache, repo_urls=[variant]))
            assert _only(doc)["match_tier"] == "repo-url", variant

    def test_unknown_repo_is_none_not_error(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, repo_urls=["https://github.com/acme/nope"]))
        assert _only(doc)["match_tier"] == "none"


class TestContactLadder:
    def test_tiers_and_embargo_flags(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        by_id = {c["kerberos_id"]: c for c in _only(doc)["contacts"]}
        assert by_id["embargoperson"]["tier"] == 1
        assert by_id["embargoperson"]["embargo_cleared"] is True
        assert by_id["componentperson"]["tier"] == 2
        assert by_id["publicperson"]["tier"] == 3

    def test_default_cc_is_never_embargo_cleared(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        for c in _only(doc)["contacts"]:
            if c["field"] == "default_cc":
                assert c["embargo_cleared"] is False, (
                    "CC'ing a public-bug list on an embargoed finding would be a disclosure event"
                )

    def test_best_tier_wins_on_duplicate(self, cache, capsys):
        """embargoperson is in both private_tracker_cc and default_cc."""
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        hits = [c for c in _only(doc)["contacts"] if c["kerberos_id"] == "embargoperson"]
        assert len(hits) == 1
        assert hits[0]["field"] == "private_tracker_cc"

    def test_embargo_cc_presence_flag(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        assert _only(doc)["embargo_cc"] == "present"
        doc = _out(capsys, _run_products(cache, products=["gizmo"]))
        assert _only(doc)["embargo_cc"] == "absent"

    def test_unexpanded_alias_is_dropped_and_recorded(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        r = _only(doc)
        assert "+unexpanded" not in [c["kerberos_id"] for c in r["contacts"]]
        dropped = {d["value"]: d for d in r["dropped_contacts"]}
        assert dropped["+unexpanded"]["reason"] == "unexpanded_alias"


class TestAllowlist:
    FORBIDDEN_KEYS = frozenset(
        (
            "bts",
            "cpe",
            "errata_product_tags",
            "team",
            "business_unit",
            "public_description",
            "brew_tags",
            "components",
        )
    )

    @staticmethod
    def _keys(node):
        """Every mapping key anywhere in the payload."""
        if isinstance(node, dict):
            for k, v in node.items():
                yield k
                yield from TestAllowlist._keys(v)
        elif isinstance(node, list):
            for v in node:
                yield from TestAllowlist._keys(v)

    def test_no_tracker_fields_leak(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        leaked = self.FORBIDDEN_KEYS & set(self._keys(doc))
        assert not leaked, f"outside the ownership allowlist: {leaked}"

    def test_no_free_text_reaches_the_caller(self, cache, capsys):
        """public_description must never enter the agent's context."""
        _run_products(cache, products=["widget"])
        assert "SECRET FREE TEXT MARKER" not in capsys.readouterr().out


class TestLifecycle:
    def test_past_supported_until_is_eol(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["relic"]))
        assert _only(doc)["lifecycle"]["state"] == "eol"

    def test_future_supported_from_is_unreleased(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["future-thing"]))
        assert _only(doc)["lifecycle"]["state"] == "unreleased"

    def test_open_ended_window_is_supported(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["widget"]))
        assert _only(doc)["lifecycle"]["state"] == "supported"


class TestMappedOutranksSlug:
    def test_slug_match_is_flagged_advisory(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, packages=["widget"]))
        r = _only(doc)
        assert r["match_tier"] == "slug"
        assert "advisory" in r["evidence"]["advisory_only"]

    def test_mapped_wins_over_slug(self, cache, capsys, tmp_path):
        pytest.importorskip("yaml")
        mapfile = tmp_path / "map.yaml"
        # 'widget' would slug-match ps_product 'widget'; the map sends it
        # to 'gizmo' instead, and the map must win.
        mapfile.write_text("mappings:\n  packages:\n    widget: gizmo\n  repos: {}\n")
        doc = _out(capsys, _run_products(cache, packages=["widget"], mapfile=mapfile))
        r = _only(doc)
        assert r["match_tier"] == "mapped"
        assert r["ps_products"] == ["gizmo"]

    def test_findings_suffix_is_optional(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, packages=["widget-findings"]))
        assert _only(doc)["ps_products"] == ["widget"]

    def test_unknown_package_is_none(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, packages=["no-such-pkg"]))
        assert _only(doc)["match_tier"] == "none"


class TestUnavailableIsNotNoMatch:
    def test_missing_cache_reports_unavailable_and_exits_zero(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        doc = _out(capsys, _run_products(empty, products=["widget"]))
        assert doc["source_status"] == "unavailable"
        assert doc["results"] == []
        assert any("optional" in w for w in doc["warnings"])

    def test_unavailable_is_distinguishable_from_none(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["no-such-id"]))
        assert doc["source_status"] == "ok"
        assert _only(doc)["match_tier"] == "none"

    def test_malformed_cache_is_unavailable_not_empty_result(self, tmp_path, capsys):
        d = tmp_path / "bad"
        d.mkdir()
        # ps_modules missing entirely — an upstream shape change must not
        # read as "this product has no contacts"
        (d / "product_definitions.json").write_text(
            json.dumps({"ps_products": {}, "ps_update_streams": {}})
        )
        doc = _out(capsys, _run_products(d, products=["widget"]))
        assert doc["source_status"] == "unavailable"
        assert "ps_modules" in doc["source"]["detail"]


class TestShapeGate:
    def test_identity_re_matches_countersign_discipline(self):
        assert pd.IDENTITY_RE.match("adinn")
        assert pd.IDENTITY_RE.match("eric.wittmann")
        assert not pd.IDENTITY_RE.match("+alias")
        assert not pd.IDENTITY_RE.match("Has Space")
        assert not pd.IDENTITY_RE.match("UPPER")
        assert not pd.IDENTITY_RE.match("x" * 65)

    def test_email_local_part_is_taken(self, cache, capsys):
        doc = _out(capsys, _run_products(cache, products=["gizmo"]))
        assert [c["kerberos_id"] for c in _only(doc)["contacts"]] == ["gizmoperson"]
