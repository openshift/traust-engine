#!/usr/bin/env python3
"""Tests for traust_engine.adapters.crypto_probe — provider census probing.

Uses temporary golden-file repos per probe function to verify correct
fact emission.  Also tests _pqc_capable_version() from pqc_facts.py.
"""

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

import pytest

from traust_engine.adapters import crypto_probe

try:
    import pqc_facts  # harness-only helper; optional for traust-engine
except ImportError:
    pqc_facts = None


class _GoldenBase(unittest.TestCase):
    """Base with a temp repo dir for golden-file tests."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write(self, rel: str, content: str):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))


class TestProbeGo(_GoldenBase):
    def test_go_mod_version(self):
        self._write(
            "go.mod",
            """\
            module example.com/foo
            go 1.24
            require golang.org/x/crypto v0.32.0
        """,
        )
        facts = crypto_probe.probe_go(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].probe_id, "CRYPTO_GO_TOOLCHAIN")
        self.assertEqual(facts[0].version, "1.24")
        self.assertEqual(facts[0].provider, "go")

    def test_vendor_excluded(self):
        self._write("vendor/submod/go.mod", "module x\ngo 1.22\n")
        facts = crypto_probe.probe_go(self.repo)
        self.assertEqual(facts, [])


class TestProbeDockerfiles(_GoldenBase):
    def test_base_image_and_pkg_install(self):
        self._write(
            "Dockerfile",
            """\
            FROM registry.access.redhat.com/ubi9:latest AS builder
            RUN dnf install -y openssl-devel
            FROM builder
            COPY . /app
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        base_facts = [f for f in facts if f.probe_id == "CRYPTO_BASE_IMAGE"]
        install_facts = [f for f in facts if f.probe_id == "CRYPTO_OPENSSL_INSTALL"]
        self.assertEqual(len(base_facts), 1)
        self.assertIn("ubi9", base_facts[0].detail)
        self.assertEqual(len(install_facts), 1)
        self.assertIn("openssl", install_facts[0].detail)

    def test_apt_get_detected(self):
        self._write(
            "Dockerfile",
            """\
            FROM ubuntu:22.04
            RUN apt-get install -y libssl-dev
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        install_facts = [f for f in facts if f.probe_id == "CRYPTO_OPENSSL_INSTALL"]
        self.assertEqual(len(install_facts), 1)

    def test_apk_detected(self):
        self._write(
            "Dockerfile",
            """\
            FROM alpine:3.19
            RUN apk add openssl-dev
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        install_facts = [f for f in facts if f.probe_id == "CRYPTO_OPENSSL_INSTALL"]
        self.assertEqual(len(install_facts), 1)


class TestProbeNode(_GoldenBase):
    def test_nvmrc(self):
        self._write(".nvmrc", "v22.4.0\n")
        facts = crypto_probe.probe_node(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "22.4.0")

    def test_engines_semver(self):
        self._write("package.json", json.dumps({"name": "test", "engines": {"node": ">=18.0.0"}}))
        facts = crypto_probe.probe_node(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "18.0.0")

    def test_engines_caret(self):
        self._write("package.json", json.dumps({"name": "test", "engines": {"node": "^20"}}))
        facts = crypto_probe.probe_node(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "20")


class TestProbePython(_GoldenBase):
    def test_python_version_file(self):
        self._write(".python-version", "3.12.1\n")
        facts = crypto_probe.probe_python(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].probe_id, "CRYPTO_PYTHON_VERSION")
        self.assertEqual(facts[0].version, "3.12.1")

    def test_requirements_txt(self):
        self._write(
            "requirements.txt",
            """\
            flask==2.3.0
            cryptography==42.0.5
            pyopenssl>=23.3.0
        """,
        )
        facts = crypto_probe.probe_python(self.repo)
        crypto_deps = [f for f in facts if f.probe_id == "CRYPTO_PYTHON_CRYPTO_DEP"]
        self.assertGreaterEqual(len(crypto_deps), 1)
        names = {f.extra.get("package") for f in crypto_deps}
        self.assertIn("cryptography", names)

    def test_pyproject_toml(self):
        self._write(
            "pyproject.toml",
            """\
            [project]
            name = "myapp"
            requires-python = ">=3.10"
        """,
        )
        facts = crypto_probe.probe_python(self.repo)
        ver_facts = [f for f in facts if f.probe_id == "CRYPTO_PYTHON_VERSION"]
        self.assertEqual(len(ver_facts), 1)
        self.assertEqual(ver_facts[0].version, "3.10")


class TestProbeJdk(_GoldenBase):
    def test_pom_xml(self):
        self._write(
            "pom.xml",
            """\
            <project>
              <properties>
                <java.version>21</java.version>
              </properties>
            </project>
        """,
        )
        facts = crypto_probe.probe_jdk(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "21")

    def test_gradle(self):
        self._write(
            "build.gradle",
            """\
            java {
                sourceCompatibility = 17
            }
        """,
        )
        facts = crypto_probe.probe_jdk(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "17")


class TestProbeRust(_GoldenBase):
    def test_rustls_backend(self):
        self._write(
            "Cargo.toml",
            """\
            [package]
            name = "myapp"
            rust-version = "1.75"

            [dependencies]
            rustls = {version = "0.23.27", features = ["ring"]}
        """,
        )
        facts = crypto_probe.probe_rust(self.repo)
        ver = [f for f in facts if f.probe_id == "CRYPTO_RUST_VERSION"]
        tls = [f for f in facts if f.probe_id == "CRYPTO_RUST_TLS_BACKEND"]
        self.assertEqual(len(ver), 1)
        self.assertEqual(ver[0].version, "1.75")
        self.assertGreaterEqual(len(tls), 1)
        providers = {f.provider for f in tls}
        self.assertIn("rustls", providers)

    def test_ring_and_aws_lc(self):
        self._write(
            "Cargo.toml",
            """\
            [package]
            name = "crypto-app"

            [dependencies]
            ring = "0.17.8"
            aws-lc-rs = {version = "1.8.0"}
        """,
        )
        facts = crypto_probe.probe_rust(self.repo)
        tls = [f for f in facts if f.probe_id == "CRYPTO_RUST_TLS_BACKEND"]
        providers = {f.provider for f in tls}
        self.assertIn("ring", providers)
        self.assertIn("aws-lc-rs", providers)


class TestProbeDotnet(_GoldenBase):
    def test_csproj(self):
        self._write(
            "App.csproj",
            """\
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net8.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="System.Security.Cryptography.Algorithms" Version="4.3.1" />
              </ItemGroup>
            </Project>
        """,
        )
        facts = crypto_probe.probe_dotnet(self.repo)
        tfm = [f for f in facts if f.probe_id == "CRYPTO_DOTNET_TFM"]
        pkg = [f for f in facts if f.probe_id == "CRYPTO_DOTNET_CRYPTO_PKG"]
        self.assertEqual(len(tfm), 1)
        self.assertEqual(tfm[0].version, "8.0")
        self.assertEqual(len(pkg), 1)

    def test_global_json(self):
        self._write("global.json", json.dumps({"sdk": {"version": "9.0.100"}}))
        facts = crypto_probe.probe_dotnet(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "9.0.100")


class TestProbeRuby(_GoldenBase):
    def test_ruby_version(self):
        self._write(".ruby-version", "3.3.0\n")
        facts = crypto_probe.probe_ruby(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].version, "3.3.0")

    def test_gemfile(self):
        self._write(
            "Gemfile",
            """\
            source 'https://rubygems.org'
            gem 'openssl', '~> 3.2'
            gem 'bcrypt', '~> 3.1'
        """,
        )
        facts = crypto_probe.probe_ruby(self.repo)
        gems = [f for f in facts if f.probe_id == "CRYPTO_RUBY_CRYPTO_GEM"]
        self.assertGreaterEqual(len(gems), 1)
        names = {f.extra.get("gem") for f in gems}
        self.assertIn("openssl", names)


class TestBuilderImageDetection(_GoldenBase):
    def test_base_image_emits_raw_name(self):
        """Probe emits raw image name — no pre-classification."""
        self._write(
            "Dockerfile",
            """\
            FROM registry.example.com/custom-go-toolset:1.21 AS builder
            COPY . /app
            FROM alpine:3.19
            COPY --from=builder /app/bin /usr/local/bin
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        base_facts = [f for f in facts if f.probe_id == "CRYPTO_BASE_IMAGE"]
        self.assertEqual(len(base_facts), 2)
        details = [f.detail for f in base_facts]
        self.assertTrue(any("custom-go-toolset" in d for d in details))
        self.assertTrue(any("alpine" in d for d in details))

    def test_goexperiment_boringcrypto(self):
        self._write(
            "Dockerfile",
            """\
            FROM golang:1.22
            ENV GOEXPERIMENT=boringcrypto
            ENV CGO_ENABLED=1
            RUN go build -o /app .
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        directives = [f for f in facts if f.probe_id == "CRYPTO_DOCKERFILE_DIRECTIVE"]
        goexp = [f for f in directives if "GOEXPERIMENT" in f.detail]
        [f for f in directives if "CGO_ENABLED" not in f.detail or "cgo" in f.detail.lower()]
        self.assertGreaterEqual(len(goexp), 1)
        self.assertEqual(goexp[0].extra["key"], "GOEXPERIMENT")

    def test_fips_env_vars(self):
        self._write(
            "Dockerfile",
            """\
            FROM ubuntu:22.04
            ARG OPENSSL_FORCE_FIPS_MODE=1
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        directives = [f for f in facts if f.probe_id == "CRYPTO_DOCKERFILE_DIRECTIVE"]
        self.assertEqual(len(directives), 1)
        self.assertEqual(directives[0].extra["key"], "OPENSSL_FORCE_FIPS_MODE")

    def test_label_with_crypto_keyword(self):
        self._write(
            "Dockerfile",
            """\
            FROM ubuntu:22.04
            LABEL description="golang-fips-container"
        """,
        )
        facts = crypto_probe.probe_dockerfiles(self.repo)
        labels = [
            f
            for f in facts
            if f.probe_id == "CRYPTO_DOCKERFILE_DIRECTIVE"
            and f.extra.get("directive_type") == "label"
        ]
        self.assertEqual(len(labels), 1)
        self.assertIn("golang-fips", labels[0].detail)


class TestGoFipsBackend(_GoldenBase):
    def test_golang_fips_in_gomod(self):
        self._write(
            "go.mod",
            """\
            module example.com/app
            go 1.22
            require github.com/golang-fips/openssl v0.0.0
        """,
        )
        facts = crypto_probe.probe_go(self.repo)
        fips = [f for f in facts if f.probe_id == "CRYPTO_GO_FIPS_BACKEND"]
        self.assertEqual(len(fips), 1)
        self.assertTrue(fips[0].extra.get("crypto_backend_swap"))

    def test_goexperiment_in_makefile(self):
        self._write(
            "Makefile",
            """\
            build:
            \tGOEXPERIMENT=opensslcrypto go build -o app .
        """,
        )
        facts = crypto_probe.probe_env_and_policy(self.repo)
        directives = [f for f in facts if f.probe_id == "CRYPTO_DOCKERFILE_DIRECTIVE"]
        self.assertGreaterEqual(len(directives), 1)


class TestProbeC(_GoldenBase):
    def test_cmake_find_package(self):
        self._write(
            "CMakeLists.txt",
            """\
            cmake_minimum_required(VERSION 3.14)
            find_package(OpenSSL REQUIRED)
            find_package(GnuTLS)
        """,
        )
        facts = crypto_probe.probe_c(self.repo)
        providers = {f.provider for f in facts}
        self.assertIn("openssl", providers)
        self.assertIn("gnutls", providers)


class TestProbeEnvPolicy(_GoldenBase):
    def test_godebug_killswitch(self):
        self._write("run.sh", "GODEBUG=tlsmlkem=0 ./myapp\n")
        facts = crypto_probe.probe_env_and_policy(self.repo)
        ks = [f for f in facts if f.probe_id == "CRYPTO_GODEBUG_TLS_KILLSWITCH"]
        self.assertEqual(len(ks), 1)

    def test_crypto_policy(self):
        self._write("entrypoint.sh", "#!/bin/bash\nupdate-crypto-policies --set FIPS\n")
        facts = crypto_probe.probe_env_and_policy(self.repo)
        pol = [f for f in facts if f.probe_id == "CRYPTO_POLICY_SET"]
        self.assertEqual(len(pol), 1)


class TestProbeRepo(_GoldenBase):
    """Integration: probe_repo aggregates all probes."""

    def test_multi_stack(self):
        self._write("go.mod", "module x\ngo 1.24\n")
        self._write("package.json", json.dumps({"engines": {"node": ">=20"}}))
        self._write(".python-version", "3.12\n")
        self._write("Dockerfile", "FROM ubi9:latest\nRUN dnf install openssl\n")
        facts = crypto_probe.probe_repo(self.repo)
        probe_ids = {f.probe_id for f in facts}
        self.assertIn("CRYPTO_GO_TOOLCHAIN", probe_ids)
        self.assertIn("CRYPTO_NODE_VERSION", probe_ids)
        self.assertIn("CRYPTO_PYTHON_VERSION", probe_ids)
        self.assertIn("CRYPTO_BASE_IMAGE", probe_ids)
        self.assertIn("CRYPTO_OPENSSL_INSTALL", probe_ids)


@pytest.mark.skipif(pqc_facts is None, reason="pqc_facts not in traust-engine")
class TestPqcCapableVersion(unittest.TestCase):
    """Tests for pqc_facts._pqc_capable_version()."""

    def test_go_124_capable(self):
        self.assertTrue(pqc_facts._pqc_capable_version("go", "1.24"))

    def test_go_123_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("go", "1.23"))

    def test_openssl_35_capable(self):
        self.assertTrue(pqc_facts._pqc_capable_version("openssl", "3.5"))

    def test_openssl_34_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("openssl", "3.4"))

    def test_jdk_27_capable(self):
        # matrix v2 (JEP 527): JDK PQC KEX default lands in 27, not 24
        self.assertTrue(pqc_facts._pqc_capable_version("jdk", "27"))
        self.assertFalse(pqc_facts._pqc_capable_version("jdk", "24"))

    def test_jdk_21_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("jdk", "21"))

    def test_node_22_20_capable(self):
        # matrix v2: Node inherits bundled OpenSSL 3.5 from 22.20+
        self.assertTrue(pqc_facts._pqc_capable_version("node", "22.20"))
        self.assertFalse(pqc_facts._pqc_capable_version("node", "22"))

    def test_node_20_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("node", "20"))

    def test_rustls_02327_capable(self):
        self.assertTrue(pqc_facts._pqc_capable_version("rustls", "0.23.27"))

    def test_rustls_02326_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("rustls", "0.23.26"))

    def test_rustls_100_capable(self):
        self.assertTrue(pqc_facts._pqc_capable_version("rustls", "1.0.0"))

    def test_gnutls_38_capable(self):
        self.assertTrue(pqc_facts._pqc_capable_version("gnutls", "3.8"))

    def test_gnutls_37_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("gnutls", "3.7"))

    def test_nss_3105_capable(self):
        self.assertTrue(pqc_facts._pqc_capable_version("nss", "3.105"))

    def test_nss_3104_not_capable(self):
        self.assertFalse(pqc_facts._pqc_capable_version("nss", "3.104"))

    def test_unknown_provider(self):
        self.assertIsNone(pqc_facts._pqc_capable_version("unknown-lib", "1.0"))

    def test_none_version(self):
        self.assertIsNone(pqc_facts._pqc_capable_version("go", None))


@pytest.mark.skipif(pqc_facts is None, reason="pqc_facts not in traust-engine")
class TestProbeToRuleMapping(unittest.TestCase):
    """Ensure all crypto_probe probe_ids have a mapping in pqc_facts."""

    def test_all_probes_mapped(self):
        repo_probes = set()
        for name in dir(crypto_probe):
            if name.startswith("probe_") and name != "probe_repo":
                fn = getattr(crypto_probe, name)
                if callable(fn):
                    src = fn.__code__.co_consts
                    for c in src:
                        if isinstance(c, str) and c.startswith("CRYPTO_"):
                            repo_probes.add(c)
        mapped = set(pqc_facts._PROBE_TO_RULE.keys())
        unmapped = repo_probes - mapped - {"CRYPTO_SBOM_COMPONENT"}
        self.assertEqual(unmapped, set(), f"Probe IDs without HP_CHAIN mapping: {unmapped}")


if __name__ == "__main__":
    unittest.main()
