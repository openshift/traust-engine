#!/usr/bin/env python3
"""traust_engine.portfolio.parsers tests — one realistic fixture per parser,
plus the ecosystem-semantics edge cases (scoped npm packages, package-lock
v3 root vs node_modules, Maven property resolution / omitted version /
default xmlns, requirements.txt marker+include+PEP 503, Gemfile.lock spec
vs sub-dep indent, NuGet Direct vs Transitive, malformed -> (None, []))."""

import json
import unittest

from traust_engine.portfolio import parsers as M


def _deps(parsed):
    """sorted dep tuples for order-independent assertions."""
    return sorted(parsed[1])


# ------------------------------------------------------------------- npm
PACKAGE_LOCK = """\
{
  "name": "my-app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {"lodash": "^4.17.20"},
      "devDependencies": {"@scope/pkg": "^2.0.0"}
    },
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/@scope/pkg": {"version": "2.1.0"},
    "node_modules/transitive-dep": {"version": "0.5.0"}
  }
}
"""

PACKAGE_JSON = """\
{
  "name": "web-ui",
  "dependencies": {"@backstage/core": "^1.2.3", "react": "18.2.0"},
  "devDependencies": {"jest": "~29.0.0"}
}
"""


class TestNpm(unittest.TestCase):
    def test_package_lock_v3_root_and_node_modules(self):
        declared, _ = M.parse_package_lock(PACKAGE_LOCK)
        self.assertEqual(declared, "my-app")
        self.assertEqual(
            _deps(M.parse_package_lock(PACKAGE_LOCK)),
            sorted(
                [
                    ("@scope/pkg", "2.1.0", False),  # scoped, root devDep -> direct
                    ("lodash", "4.17.21", False),  # root dep -> direct
                    ("transitive-dep", "0.5.0", True),  # only in node_modules
                ]
            ),
        )

    def test_package_json_scoped_and_range_strip(self):
        declared, _ = M.parse_package_json(PACKAGE_JSON)
        self.assertEqual(declared, "web-ui")
        self.assertEqual(
            _deps(M.parse_package_json(PACKAGE_JSON)),
            sorted(
                [
                    ("@backstage/core", "1.2.3", False),
                    ("react", "18.2.0", False),
                    ("jest", "29.0.0", False),
                ]
            ),
        )

    def test_package_lock_malformed(self):
        self.assertEqual(M.parse_package_lock("{not json"), (None, []))

    def test_npm_alias_resolved_in_package_lock(self):
        # Regression: an npm alias (`"legacy-swc-helpers":
        # "npm:@swc/helpers@=0.4.14"`) must resolve to the REAL package
        # (@swc/helpers), never the alias name — the alias name-matched a
        # malicious-package advisory (MAL-2024-7969) and produced a false
        # positive (2026-08-05). npm records the real name in `name`.
        lock = json.dumps(
            {
                "name": "aliased-app",
                "packages": {
                    "": {
                        "name": "aliased-app",
                        "dependencies": {"legacy-swc-helpers": "npm:@swc/helpers@=0.4.14"},
                    },
                    "node_modules/legacy-swc-helpers": {
                        "name": "@swc/helpers",
                        "version": "0.4.14",
                    },
                },
            }
        )
        _declared, deps = M.parse_package_lock(lock)
        names = [d[0] for d in deps]
        self.assertIn("@swc/helpers", names)
        self.assertNotIn("legacy-swc-helpers", names)
        # resolved as a direct dep (the alias key is a root dependency)
        self.assertIn(("@swc/helpers", "0.4.14", False), deps)

    def test_npm_alias_resolved_in_package_json(self):
        pj = json.dumps(
            {
                "name": "aliased-app",
                "dependencies": {
                    "legacy-swc-helpers": "npm:@swc/helpers@=0.4.14",
                    "react": "^18.2.0",
                },
            }
        )
        deps = _deps(M.parse_package_json(pj))
        self.assertEqual(
            deps,
            sorted(
                [
                    ("@swc/helpers", "0.4.14", False),  # alias -> real package
                    ("react", "18.2.0", False),
                ]
            ),
        )

    def test_resolve_npm_alias_helper(self):
        self.assertEqual(
            M._resolve_npm_alias("npm:@swc/helpers@=0.4.14"), ("@swc/helpers", "0.4.14")
        )
        self.assertEqual(M._resolve_npm_alias("npm:left-pad@^1.3.0"), ("left-pad", "1.3.0"))
        self.assertEqual(M._resolve_npm_alias("npm:some-pkg"), ("some-pkg", ""))
        self.assertIsNone(M._resolve_npm_alias("^1.2.3"))
        self.assertIsNone(M._resolve_npm_alias("2.5.3"))


PNPM_LOCK = """\
lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
  '@scope/util':
    specifier: ^1.0.0
    version: 1.0.5

devDependencies:
  typescript:
    specifier: ^5.0.0
    version: 5.1.6

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-xxx}
    dev: false

  /@scope/util@1.0.5:
    resolution: {integrity: sha512-yyy}
    dev: false

  /@babel/core@7.22.0(supports-color@8.1.1):
    resolution: {integrity: sha512-zzz}
    dependencies:
      lodash: 4.17.21
    dev: true

  /typescript@5.1.6:
    resolution: {integrity: sha512-www}
    dev: true
"""

# npm-shrinkwrap.json is byte-for-byte the package-lock schema
NPM_SHRINKWRAP = PACKAGE_LOCK


class TestPnpmAndShrinkwrap(unittest.TestCase):
    def test_pnpm_direct_vs_transitive(self):
        declared, deps = M.parse_pnpm_lock(PNPM_LOCK)
        self.assertIsNone(declared)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("lodash", "4.17.21", False),  # under dependencies:
                    ("@scope/util", "1.0.5", False),  # scoped direct
                    ("typescript", "5.1.6", False),  # under devDependencies:
                    ("@babel/core", "7.22.0", True),  # only in packages: -> tr.
                ]
            ),
        )

    def test_npm_shrinkwrap_delegates_to_package_lock(self):
        self.assertEqual(
            M.parse_npm_shrinkwrap(NPM_SHRINKWRAP), M.parse_package_lock(NPM_SHRINKWRAP)
        )


# ------------------------------------------------------------------- PyPI
REQUIREMENTS = """\
# top-level comment
-r base.txt
-e .
Foo.Bar_Baz==1.2.3
requests>=2.20.0  # inline comment
urllib3==1.26.5 ; python_version < "3.9"
"""

PYPROJECT_621 = """\
[project]
name = "my-pkg"
dependencies = ["requests>=2.20", "PyYAML"]

[project.optional-dependencies]
dev = ["pytest>=7.0"]
"""

PYPROJECT_POETRY = """\
[tool.poetry]
name = "poetry-pkg"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28.0"
click = {version = "8.1.3", optional = false}

[tool.poetry.group.dev.dependencies]
pytest = "^7.2"
"""

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.28.1"

[[package]]
name = "urllib3"
version = "1.26.12"
"""

PIPFILE_LOCK = """\
{
  "default": {"cryptography": {"version": "==41.0.3"}},
  "develop": {"pytest": {"version": "==7.4.0"}}
}
"""


class TestPyPI(unittest.TestCase):
    def test_requirements_markers_includes_normalization(self):
        declared, _ = M.parse_requirements_txt(REQUIREMENTS)
        self.assertIsNone(declared)
        self.assertEqual(
            _deps(M.parse_requirements_txt(REQUIREMENTS)),
            sorted(
                [
                    ("foo-bar-baz", "1.2.3", False),  # PEP 503 normalized
                    ("requests", "2.20.0", False),  # inline comment stripped
                    ("urllib3", "1.26.5", False),  # env marker ignored
                ]
            ),
        )

    def test_pyproject_pep621(self):
        declared, _ = M.parse_pyproject_deps(PYPROJECT_621)
        self.assertEqual(declared, "my-pkg")
        self.assertEqual(
            _deps(M.parse_pyproject_deps(PYPROJECT_621)),
            sorted(
                [
                    ("requests", ">=2.20", False),
                    ("pyyaml", "", False),
                    ("pytest", ">=7.0", False),
                ]
            ),
        )

    def test_pyproject_poetry(self):
        declared, deps = M.parse_pyproject_deps(PYPROJECT_POETRY)
        self.assertEqual(declared, "poetry-pkg")
        names = {d[0] for d in deps}
        self.assertNotIn("python", names)  # poetry python pin excluded
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("requests", "^2.28.0", False),
                    ("click", "8.1.3", False),
                    ("pytest", "^7.2", False),
                ]
            ),
        )

    def test_poetry_lock_all_indirect(self):
        declared, deps = M.parse_poetry_lock(POETRY_LOCK)
        self.assertIsNone(declared)
        self.assertTrue(all(d[2] for d in deps))
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("requests", "2.28.1", True),
                    ("urllib3", "1.26.12", True),
                ]
            ),
        )

    def test_pipfile_lock_strip_eq(self):
        self.assertEqual(
            _deps(M.parse_pipfile_lock(PIPFILE_LOCK)),
            sorted(
                [
                    ("cryptography", "41.0.3", True),
                    ("pytest", "7.4.0", True),
                ]
            ),
        )


SETUP_PY = """\
from setuptools import setup, find_packages

setup(
    name="my-tool",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.20",
        "PyYAML",
        "click==8.1.3",
    ],
)
"""

CONSTRAINTS = """\
requests==2.28.1
urllib3==1.26.5
"""

ENVIRONMENT_YML = """\
name: myenv
channels:
  - conda-forge
dependencies:
  - python=3.10
  - numpy=1.24.0
  - pandas==2.0.0
  - pip
  - pip:
    - requests>=2.28
    - flask
"""


class TestPyPIExtra(unittest.TestCase):
    def test_setup_py_install_requires(self):
        declared, deps = M.parse_setup_py(SETUP_PY)
        self.assertEqual(declared, "my-tool")
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("requests", ">=2.20", False),
                    ("pyyaml", "", False),  # PEP 503 normalized, no version
                    ("click", "==8.1.3", False),
                ]
            ),
        )

    def test_constraints_delegates_to_requirements(self):
        self.assertEqual(
            M.parse_constraints_txt(CONSTRAINTS), M.parse_requirements_txt(CONSTRAINTS)
        )
        self.assertEqual(
            _deps(M.parse_constraints_txt(CONSTRAINTS)),
            sorted(
                [
                    ("requests", "2.28.1", False),
                    ("urllib3", "1.26.5", False),
                ]
            ),
        )

    def test_environment_yml_conda_and_pip(self):
        declared, deps = M.parse_environment_yml(ENVIRONMENT_YML)
        self.assertIsNone(declared)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("python", "3.10", False),  # conda name=version
                    ("numpy", "1.24.0", False),  # conda name=version
                    ("pandas", "2.0.0", False),  # conda name==version
                    ("pip", "", False),  # bare conda pip package
                    ("requests", ">=2.28", False),  # nested pip: list (PEP 508)
                    ("flask", "", False),  # nested pip: list
                ]
            ),
        )


# ------------------------------------------------------------------- Maven
POM = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>my-service</artifactId>
  <version>3.1.0</version>
  <properties>
    <jackson.version>2.15.2</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.managed</groupId>
      <artifactId>no-version-here</artifactId>
    </dependency>
  </dependencies>
</project>
"""

POM_NS = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.ns</groupId>
  <artifactId>ns-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.36</version>
    </dependency>
  </dependencies>
</project>
"""

POM_DEPMGMT = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""

POM_AGGREGATOR = """\
<project>
  <groupId>com.example</groupId>
  <artifactId>aggregator</artifactId>
  <version>1.0.0</version>
  <modules>
    <module>core</module>
    <module>api</module>
  </modules>
</project>
"""

GRADLE_LOCKFILE = """\
# This is a Gradle generated file for dependency locking.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.7.36=runtimeClasspath
empty=annotationProcessor
"""

BUILD_GRADLE = """\
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.12.0'
    api "com.google.guava:guava:31.1-jre"
    testImplementation 'junit:junit:4.13.2'
}
"""


class TestMaven(unittest.TestCase):
    def test_pom_property_projectversion_and_omitted(self):
        declared, deps = M.parse_pom_xml(POM)
        self.assertEqual(declared, "com.example:my-service")
        names = {d[0] for d in deps}
        # the version-less dependency is omitted, not emitted with a bogus
        # or empty version
        self.assertNotIn("org.managed:no-version-here", names)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("com.fasterxml.jackson.core:jackson-databind", "2.15.2", False),
                    ("com.example:sibling", "3.1.0", False),  # ${project.version}
                ]
            ),
        )

    def test_pom_default_namespace(self):
        declared, deps = M.parse_pom_xml(POM_NS)
        self.assertEqual(declared, "org.ns:ns-app")
        self.assertEqual(deps, [("org.slf4j:slf4j-api", "1.7.36", False)])

    def test_gradle_lockfile(self):
        declared, deps = M.parse_gradle_lockfile(GRADLE_LOCKFILE)
        self.assertIsNone(declared)
        self.assertTrue(all(d[2] for d in deps))  # lockfile -> indirect
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("com.google.guava:guava", "31.1-jre", True),
                    ("org.slf4j:slf4j-api", "1.7.36", True),
                ]
            ),
        )

    def test_build_gradle(self):
        self.assertEqual(
            _deps(M.parse_build_gradle(BUILD_GRADLE)),
            sorted(
                [
                    ("org.apache.commons:commons-lang3", "3.12.0", False),
                    ("com.google.guava:guava", "31.1-jre", False),
                    ("junit:junit", "4.13.2", False),
                ]
            ),
        )

    def test_pom_dependency_management_read(self):
        declared, deps = M.parse_pom_xml(POM_DEPMGMT)
        self.assertEqual(declared, "com.example:parent")
        # version pinned only under <dependencyManagement> is now read
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("org.springframework:spring-core", "5.3.20", False),
                ]
            ),
        )

    def test_pom_aggregator_modules_only_is_legit_empty(self):
        # root/aggregator pom with only <modules> -> (declared, []) is
        # correct, not an error
        declared, deps = M.parse_pom_xml(POM_AGGREGATOR)
        self.assertEqual(declared, "com.example:aggregator")
        self.assertEqual(deps, [])

    def test_pom_malformed(self):
        self.assertEqual(M.parse_pom_xml("<project><oops"), (None, []))


# ------------------------------------------------------------------- Cargo
CARGO_LOCK = """\
[[package]]
name = "serde"
version = "1.0.152"

[[package]]
name = "libc"
version = "0.2.139"
"""

CARGO_TOML = """\
[package]
name = "my-crate"
version = "0.3.0"

[dependencies]
serde = "1.0"
tokio = {version = "1.25", features = ["full"]}

[dev-dependencies]
criterion = "0.4"
"""


class TestCargo(unittest.TestCase):
    def test_cargo_lock_all_indirect(self):
        declared, deps = M.parse_cargo_lock(CARGO_LOCK)
        self.assertIsNone(declared)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("serde", "1.0.152", True),
                    ("libc", "0.2.139", True),
                ]
            ),
        )

    def test_cargo_toml_string_and_table(self):
        declared, deps = M.parse_cargo_toml(CARGO_TOML)
        self.assertEqual(declared, "my-crate")
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("serde", "1.0", False),
                    ("tokio", "1.25", False),  # table form
                    ("criterion", "0.4", False),
                ]
            ),
        )


# ----------------------------------------------------------------- RubyGems
GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (6.1.4)
      actionview (= 6.1.4)
      rack (~> 2.0)
    rack (2.2.3)

PLATFORMS
  ruby

DEPENDENCIES
  rails
"""

GEMSPEC = """\
Gem::Specification.new do |spec|
  spec.name = "my-gem"
  spec.version = "1.0.0"
  spec.add_dependency "activesupport", ">= 6.0"
  spec.add_runtime_dependency("nokogiri", "~> 1.13")
  spec.add_development_dependency "rspec", "~> 3.12"
end
"""

GEMFILE = """\
source "https://rubygems.org"
gem "rails", "~> 6.1.4"
gem "puma", "~> 5.0"
gem "bootsnap", require: false
"""


class TestRuby(unittest.TestCase):
    def test_gemfile_lock_spec_vs_subdep(self):
        declared, deps = M.parse_gemfile_lock(GEMFILE_LOCK)
        self.assertIsNone(declared)
        # 4-space specs kept with pinned versions; deeper sub-deps
        # (actionview/rack constraints) skipped
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("actionpack", "6.1.4", True),
                    ("rack", "2.2.3", True),
                ]
            ),
        )

    def test_gemspec(self):
        declared, deps = M.parse_gemspec(GEMSPEC)
        self.assertEqual(declared, "my-gem")
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("activesupport", ">= 6.0", False),
                    ("nokogiri", "~> 1.13", False),
                    ("rspec", "~> 3.12", False),
                ]
            ),
        )

    def test_gemfile(self):
        declared, deps = M.parse_gemfile(GEMFILE)
        self.assertIsNone(declared)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("rails", "~> 6.1.4", False),
                    ("puma", "~> 5.0", False),
                    ("bootsnap", "", False),  # no version arg
                ]
            ),
        )


# ------------------------------------------------------------------- NuGet
PACKAGES_LOCK = """\
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
      "System.Text.Json": {"type": "Transitive", "resolved": "6.0.0"},
      "MyProject.Lib": {"type": "Project"}
    }
  }
}
"""

CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="2.12.0" />
    <PackageReference Include="Dapper" Version="2.0.123" />
  </ItemGroup>
</Project>
"""


class TestNuGet(unittest.TestCase):
    def test_packages_lock_direct_vs_transitive(self):
        declared, deps = M.parse_packages_lock_json(PACKAGES_LOCK)
        self.assertIsNone(declared)
        # Project-type entry has no "resolved" -> skipped
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("newtonsoft.json", "13.0.1", False),  # Direct
                    ("system.text.json", "6.0.0", True),  # Transitive
                ]
            ),
        )

    def test_csproj(self):
        declared, deps = M.parse_csproj(CSPROJ)
        self.assertIsNone(declared)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("Serilog", "2.12.0", False),
                    ("Dapper", "2.0.123", False),
                ]
            ),
        )


# ------------------------------------------------------------------- Docker
DOCKERFILE = """\
# syntax=docker/dockerfile:1
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
RUN go build -o app

FROM scratch
COPY --from=builder /app /app

FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:abc123 AS runtime
COPY --from=builder /src/app /usr/bin/app

FROM ${BASE_IMAGE}

FROM builder
"""


class TestDocker(unittest.TestCase):
    def test_dockerfile_multistage(self):
        declared, deps = M.parse_dockerfile(DOCKERFILE)
        self.assertIsNone(declared)
        # scratch, the ${ARG} image, and the `FROM builder` stage-alias
        # reference are all skipped; tag AND @sha256 digest captured
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("golang", "1.21", False),
                    ("registry.access.redhat.com/ubi9/ubi-minimal", "sha256:abc123", False),
                ]
            ),
        )

    def test_dockerfile_untagged_is_latest(self):
        self.assertEqual(M.parse_dockerfile("FROM alpine")[1], [("alpine", "latest", False)])

    def test_dockerfile_malformed(self):
        self.assertEqual(M.parse_dockerfile("\x00 not a dockerfile"), (None, []))


# ------------------------------------------------------- GitHub Actions
WORKFLOW = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup
        uses: actions/setup-node@v3.8.1
      - uses: ./.github/actions/local-setup
      - uses: docker://alpine:3.18
      - uses: aws-actions/configure-aws-credentials@v2
      - uses: monorepo/tools/sub-action@abc123def
"""


class TestGithubWorkflow(unittest.TestCase):
    def test_workflow_uses_extraction(self):
        declared, deps = M.parse_github_workflow(WORKFLOW)
        self.assertIsNone(declared)
        # local ./ and docker:// skipped; owner/repo canonicalized (subdir
        # dropped for monorepo/tools/sub-action)
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("actions/checkout", "v4", False),
                    ("actions/setup-node", "v3.8.1", False),
                    ("aws-actions/configure-aws-credentials", "v2", False),
                    ("monorepo/tools", "abc123def", False),
                ]
            ),
        )

    def test_workflow_malformed(self):
        self.assertEqual(M.parse_github_workflow("not: a: workflow: ["), (None, []))


# ------------------------------------------------------------------- Helm
CHART_YAML = """\
apiVersion: v2
name: my-chart
description: A Helm chart
version: 0.1.0
appVersion: "1.16.0"
dependencies:
  - name: postgresql
    version: "11.6.12"
    repository: https://charts.bitnami.com/bitnami
  - name: redis
    version: 16.8.0
    repository: "@bitnami"
"""

REQUIREMENTS_YAML = """\
dependencies:
  - name: nginx-ingress
    version: 1.41.3
    repository: https://helm.nginx.com/stable
"""


class TestHelm(unittest.TestCase):
    def test_chart_yaml_name_and_dependencies(self):
        declared, deps = M.parse_helm_chart(CHART_YAML)
        self.assertEqual(declared, "my-chart")
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("postgresql", "11.6.12", False),
                    ("redis", "16.8.0", False),
                ]
            ),
        )

    def test_requirements_yaml_legacy_no_name(self):
        declared, deps = M.parse_helm_chart(REQUIREMENTS_YAML)
        self.assertIsNone(declared)  # legacy requirements.yaml has no name
        self.assertEqual(
            _deps((declared, deps)),
            sorted(
                [
                    ("nginx-ingress", "1.41.3", False),
                ]
            ),
        )

    def test_helm_malformed(self):
        self.assertEqual(M.parse_helm_chart(":::broken"), (None, []))


# --------------------------------------------------------------- dispatch
class TestDispatch(unittest.TestCase):
    def test_parser_for_exact_and_globs(self):
        self.assertEqual(M.parser_for("package-lock.json")[0], "npm")
        self.assertIs(M.parser_for("deep/dir/pom.xml")[1], M.parse_pom_xml)
        self.assertEqual(M.parser_for("my-gem.gemspec"), ("ruby", M.parse_gemspec))
        self.assertEqual(M.parser_for("Foo.csproj"), ("nuget", M.parse_csproj))
        self.assertEqual(M.parser_for("requirements-dev.txt"), ("pypi", M.parse_requirements_txt))
        self.assertIsNone(M.parser_for("unknown.file"))

    def test_parser_for_new_filenames_and_globs(self):
        self.assertEqual(M.parser_for("pnpm-lock.yaml"), ("npm", M.parse_pnpm_lock))
        self.assertEqual(M.parser_for("npm-shrinkwrap.json"), ("npm", M.parse_npm_shrinkwrap))
        self.assertEqual(M.parser_for("setup.py"), ("pypi", M.parse_setup_py))
        self.assertEqual(M.parser_for("constraints.txt"), ("pypi", M.parse_constraints_txt))
        self.assertEqual(M.parser_for("environment.yml"), ("pypi", M.parse_environment_yml))
        self.assertEqual(M.parser_for("Chart.yaml"), ("helm", M.parse_helm_chart))
        self.assertEqual(M.parser_for("requirements.yaml"), ("helm", M.parse_helm_chart))
        self.assertEqual(M.parser_for("Dockerfile"), ("docker", M.parse_dockerfile))
        self.assertEqual(M.parser_for("Dockerfile.dev"), ("docker", M.parse_dockerfile))
        self.assertEqual(M.parser_for("app.Dockerfile"), ("docker", M.parse_dockerfile))

    def test_parser_for_path_workflow_routing(self):
        self.assertEqual(
            M.parser_for_path(".github/workflows/ci.yml"), ("actions", M.parse_github_workflow)
        )
        self.assertEqual(
            M.parser_for_path("repo/.github/workflows/release.yaml"),
            ("actions", M.parse_github_workflow),
        )
        self.assertTrue(M.is_workflow_path(".github/workflows/ci.yml"))
        # a non-workflow yaml path falls back to basename dispatch
        self.assertEqual(M.parser_for_path("charts/foo/Chart.yaml"), ("helm", M.parse_helm_chart))
        self.assertEqual(M.parser_for_path("deep/dir/Dockerfile"), ("docker", M.parse_dockerfile))
        # a Chart.yaml is not a workflow even though it is yaml
        self.assertFalse(M.is_workflow_path("charts/foo/Chart.yaml"))

    def test_ecosystem_manifests_ordering(self):
        # lockfile precedes manifest fallback for each ecosystem
        self.assertEqual(M.ECOSYSTEM_MANIFESTS["npm"][0], "package-lock.json")
        self.assertEqual(M.ECOSYSTEM_MANIFESTS["cargo"], ["Cargo.lock", "Cargo.toml"])
        self.assertEqual(M.ECOSYSTEM_MANIFESTS["pypi"][0], "poetry.lock")
        self.assertIn("Chart.yaml", M.ECOSYSTEM_MANIFESTS["helm"])
        self.assertEqual(M.ECOSYSTEM_MANIFESTS["actions"], [])  # path-based

    def test_universal_ecosystems_and_globs(self):
        self.assertEqual(M.UNIVERSAL_ECOSYSTEMS, {"docker", "actions", "helm"})
        # universal ecosystems are NOT language-gated
        self.assertNotIn("docker", set(M.LANGUAGE_ECOSYSTEMS.values()))
        self.assertNotIn("helm", set(M.LANGUAGE_ECOSYSTEMS.values()))
        self.assertNotIn("actions", set(M.LANGUAGE_ECOSYSTEMS.values()))
        # each universal ecosystem carries discovery globs
        for eco in M.UNIVERSAL_ECOSYSTEMS:
            self.assertTrue(M.PATH_GLOB_ECOSYSTEMS.get(eco))

    def test_language_ecosystems(self):
        self.assertEqual(M.LANGUAGE_ECOSYSTEMS["TypeScript"], "npm")
        self.assertEqual(M.LANGUAGE_ECOSYSTEMS["C#"], "nuget")
        self.assertEqual(M.LANGUAGE_ECOSYSTEMS["Kotlin"], "maven")


class TestMalformedNeverRaises(unittest.TestCase):
    def test_garbage_returns_empty(self):
        self.assertEqual(M.parse_package_json("\x00not{json"), (None, []))
        self.assertEqual(M.parse_cargo_toml("this is = not [valid toml"), (None, []))
        self.assertEqual(M.parse_pyproject_deps("[[[broken"), (None, []))
        self.assertEqual(M.parse_packages_lock_json("<xml/>"), (None, []))
        self.assertEqual(M.parse_pnpm_lock("\x00: :["), (None, []))
        self.assertEqual(M.parse_environment_yml("\x00garbage"), (None, []))
        self.assertEqual(M.parse_setup_py("nonsense without a call"), (None, []))
        self.assertEqual(M.parse_dockerfile("\x00 random bytes"), (None, []))
        self.assertEqual(M.parse_github_workflow("not: a: workflow"), (None, []))
        self.assertEqual(M.parse_helm_chart("::: broken :::"), (None, []))
        # empty input across every parser -> clean (None|declared, [])
        for fn in (
            M.parse_package_lock,
            M.parse_package_json,
            M.parse_npm_shrinkwrap,
            M.parse_pnpm_lock,
            M.parse_requirements_txt,
            M.parse_pyproject_deps,
            M.parse_poetry_lock,
            M.parse_pipfile_lock,
            M.parse_pom_xml,
            M.parse_setup_py,
            M.parse_constraints_txt,
            M.parse_environment_yml,
            M.parse_gradle_lockfile,
            M.parse_build_gradle,
            M.parse_cargo_lock,
            M.parse_cargo_toml,
            M.parse_gemfile_lock,
            M.parse_gemspec,
            M.parse_gemfile,
            M.parse_packages_lock_json,
            M.parse_csproj,
            M.parse_dockerfile,
            M.parse_github_workflow,
            M.parse_helm_chart,
        ):
            _declared, deps = fn("")
            self.assertEqual(deps, [], fn.__name__)


if __name__ == "__main__":
    unittest.main()
