"""Tests for traust adapters osv — multi-ecosystem SCA candidates."""

from pathlib import Path

from traust_engine.adapters import osv as ros

FIXTURE = {
    "results": [
        {
            "source": {"path": "/repo/requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                    "groups": [
                        {
                            "ids": ["GHSA-x84v-xcm2-53pg"],
                            "aliases": ["CVE-2018-18074"],
                            "max_severity": "9.1",
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-x84v-xcm2-53pg",
                            "aliases": ["CVE-2018-18074"],
                            "summary": "Credentials leak on redirect",
                            "affected": [
                                {
                                    "package": {"name": "requests", "ecosystem": "PyPI"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        {
            "source": {"path": "/repo/ui/package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"},
                    "groups": [],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-jf85-cpcp-j695",
                            "aliases": ["CVE-2019-10744"],
                            "summary": "Prototype pollution in defaultsDeep",
                            "affected": [
                                {
                                    "package": {"name": "lodash", "ecosystem": "npm"},
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [{"introduced": "0"}, {"fixed": "4.17.12"}],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    ],
}


def test_parse_output_candidates():
    cands = ros.parse_output(FIXTURE, Path("/repo"))
    assert len(cands) == 2
    py = next(c for c in cands if c["ecosystem"] == "PyPI")
    assert py["osv_id"] == "GHSA-x84v-xcm2-53pg"
    assert py["package"] == "requests"
    assert py["found_version"] == "2.19.0"
    assert py["fixed_version"] == "2.20.0"
    assert py["max_severity"] == "9.1"
    assert py["evidence"] == "dependency_declared"
    assert py["sources"] == ["requirements.txt"]
    js = next(c for c in cands if c["ecosystem"] == "npm")
    assert js["fixed_version"] == "4.17.12"
    assert js["max_severity"] is None  # no group entry
    assert js["sources"] == ["ui/package-lock.json"]


def test_parse_output_dedupes_across_sources():
    doc = {
        "results": [
            FIXTURE["results"][0],
            {
                **FIXTURE["results"][0],
                "source": {"path": "/repo/dev-requirements.txt", "type": "lockfile"},
            },
        ]
    }
    cands = ros.parse_output(doc, Path("/repo"))
    assert len(cands) == 1
    assert sorted(cands[0]["sources"]) == ["dev-requirements.txt", "requirements.txt"]


def test_parse_output_empty():
    assert ros.parse_output({"results": []}, Path("/repo")) == []


def test_fixed_version_wrong_package_ignored():
    vuln = FIXTURE["results"][0]["packages"][0]["vulnerabilities"][0]
    assert ros.fixed_version(vuln, "other-package", "PyPI") is None
