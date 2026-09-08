"""Per-ecosystem dependency-manifest parsers for the portfolio graph (L1).

Each parser mirrors the `parse_gomod` contract in build_portfolio_graph.py:

    def parse_<x>(text: str) -> tuple[str | None, list[tuple[str, str, bool]]]:
        \"\"\"(declared_name | None, [(dep_name, version, indirect)]).\"\"\"

  * The first element is the manifest's OWN declared package/module name,
    or None when the manifest format does not state one (lockfiles, bare
    requirements.txt, Gemfile, build.gradle).
  * Each dep tuple is (canonical_dep_name, version_string, is_indirect).
    indirect=False marks a direct/root dependency; indirect=True marks a
    transitive one. Only lockfiles distinguish the two — a bare manifest
    lists directs only, so it marks everything indirect=False. Lockfiles
    whose format does not cleanly separate direct from transitive
    (poetry.lock, Pipfile.lock, Cargo.lock, gradle.lockfile, Gemfile.lock)
    conservatively mark every entry indirect=True; the caller derives the
    `declares` edge for the root from the companion manifest (Cargo.toml,
    pyproject.toml, ...).

Parsers NEVER raise on malformed input: on any parse failure they return
(None, []). Callers treat an ok-fetch-but-empty-parse as a tracked
"parse_empty" signal, so a clean empty result is correct behaviour, not an
error.

`tomllib` is imported lazily inside the parsers that need it (precedent:
traust.cli.check_content_licenses) so import time never breaks the declared
Python 3.10 floor — tomllib is stdlib only since 3.11.

Dispatch: `parser_for(filename)` maps a manifest filename to
(ecosystem, parser_callable); `parser_for_path(path)` is the path-aware
variant the graph builder should prefer (it routes GitHub Actions
workflow files, which are ordinary *.yml/*.yaml distinguished only by
living under .github/workflows/, via `is_workflow_path(path)` before
falling back to basename dispatch). `ECOSYSTEM_MANIFESTS` lists the
candidate filenames per ecosystem (lockfile first, manifest fallback);
`LANGUAGE_ECOSYSTEMS` maps a GitHub language name to a language-gated
ecosystem. `UNIVERSAL_ECOSYSTEMS` ({'docker','actions','helm'}) are
NOT language-gated — a repo in any language ships Dockerfiles, workflows,
and Helm charts — and are discovered by path via the globs in
`PATH_GLOB_ECOSYSTEMS`, fetched for every repo regardless of language.

Docker base images, GitHub Actions, and Helm charts are dependency
SURFACES rather than package manifests: their parsers emit
(None, [(name, version, False)]) — declared None (except Chart.yaml, whose
top-level `name:` is a real declared chart name), all directs. The three
YAML surfaces (pnpm-lock, workflow, Helm/Chart) use minimal hand YAML
scans, not a YAML library, because the stdlib ships none.
"""

from __future__ import annotations

import json
import re

Dep = tuple[str, str, bool]
Parsed = tuple[str | None, list[Dep]]


# --------------------------------------------------------------- shared bits
def _pep503(name: str) -> str:
    """PEP 503 normalized project name: lowercase, runs of [-_.] -> '-'."""
    return re.sub(r"[-_.]+", "-", name).strip("-").lower()


def _localname(tag: str) -> str:
    """XML tag local name with any {namespace} prefix stripped."""
    return tag.rpartition("}")[2]


def _child(elem, name: str):
    for c in elem:
        if _localname(c.tag) == name:
            return c
    return None


def _children(elem, name: str) -> list:
    return [c for c in elem if _localname(c.tag) == name]


def _eltext(elem) -> str:
    return (elem.text or "").strip() if elem is not None else ""


# ------------------------------------------------------------------- npm
def _resolve_npm_alias(spec: str) -> tuple[str, str] | None:
    """An npm alias dependency value is `npm:<realpkg>@<version>` (e.g.
    `npm:@swc/helpers@=0.4.14`). Resolve it to the REAL registry package
    name + version so a locally-aliased legit package is never reported
    (or advisory-matched) under its alias name. Returns None if `spec`
    is not an npm: alias."""
    if not isinstance(spec, str) or not spec.startswith("npm:"):
        return None
    body = spec[len("npm:") :]
    # The version separator is the first '@' AFTER any leading scope '@'.
    idx = body.find("@", 1) if body.startswith("@") else body.find("@")
    if idx == -1:
        return (body, "") if body else None
    name = body[:idx]
    version = body[idx + 1 :].lstrip("^~=")
    return (name, version) if name else None


def parse_package_lock(text: str) -> Parsed:
    """package-lock.json v2/v3 `packages` map. Root key "" -> declared
    name + its direct deps (indirect=False); node_modules/<name> keys ->
    resolved versions, indirect=True unless the name is a root direct.
    npm ALIASES (`"alias": "npm:realpkg@ver"`) are resolved to the real
    package: npm records the real name in the entry's `name` field, which
    is preferred over the node_modules directory (the alias)."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return None, []
    declared = None
    directs: set[str] = set()
    root = packages.get("")
    if isinstance(root, dict):
        declared = root.get("name") or None
        for sect in ("dependencies", "devDependencies"):
            m = root.get(sect)
            if isinstance(m, dict):
                directs.update(m.keys())
    if not declared:
        declared = data.get("name") or None
    deps: list[Dep] = []
    for path, spec in packages.items():
        if path == "" or not isinstance(spec, dict):
            continue
        alias_key = path.rpartition("node_modules/")[2]
        # For an aliased install npm records the real package in `name`;
        # prefer it over the node_modules directory (which is the alias).
        real_name = spec.get("name") or alias_key
        version = spec.get("version")
        if not real_name or not isinstance(version, str) or not version:
            continue
        # direct/indirect is decided by the alias key (what the root
        # `dependencies` map lists), but the emitted name is the real one.
        deps.append((real_name, version, alias_key not in directs))
    return declared, deps


def parse_package_json(text: str) -> Parsed:
    """package.json: top-level "name" declared; dependencies +
    devDependencies as directs (indirect=False), leading ^~ stripped from
    the best-effort range string."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    declared = data.get("name") or None
    deps: list[Dep] = []
    for sect in ("dependencies", "devDependencies"):
        m = data.get(sect)
        if isinstance(m, dict):
            for name, rng in m.items():
                if not isinstance(name, str):
                    continue
                alias = _resolve_npm_alias(rng)
                if alias:
                    # `"x": "npm:realpkg@ver"` -> report the real package.
                    deps.append((alias[0], alias[1], False))
                else:
                    ver = rng.lstrip("^~") if isinstance(rng, str) else ""
                    deps.append((name, ver, False))
    return declared, deps


def parse_npm_shrinkwrap(text: str) -> Parsed:
    """npm-shrinkwrap.json: byte-for-byte the same schema as
    package-lock.json (publishable variant), so it delegates to
    parse_package_lock."""
    return parse_package_lock(text)


_PNPM_DEP_HEADERS = ("dependencies:", "devDependencies:", "optionalDependencies:")


def _pnpm_split_key(key: str) -> tuple[str, str] | None:
    """Split a pnpm `packages:` key into (name, version). Handles the v6+
    `name@version` / scoped `@scope/name@version` form (optionally with a
    trailing `(peer@x)` peer-dep suffix). Returns None when the key is not a
    resolvable name@version — notably the legacy v5 `name/version` key form
    (no `@`) is deliberately skipped rather than mis-split (precision over
    recall: no bogus entries)."""
    key = key.split("(", 1)[0]
    name, sep, version = key.rpartition("@")
    if not sep or not name or not version:
        return None
    return name, version


def parse_pnpm_lock(text: str) -> Parsed:
    """pnpm-lock.yaml (minimal hand YAML scan — stdlib ships no YAML lib).
    Package keys under the top-level `packages:` map
    (`/name@version:` / `/@scope/name@version:`) are resolved deps; a name
    that also appears under a `dependencies:` / `devDependencies:` /
    `optionalDependencies:` block (top-level or under `importers:`) is a
    direct (indirect=False), everything else transitive (indirect=True).
    declared None — the companion package.json carries the root name.
    Lossy: legacy v5 `/name/version` package keys are skipped."""
    directs: set[str] = set()
    entries: list[tuple[str, str]] = []
    in_packages = False
    pkg_indent: int | None = None
    sect_indent: int | None = None
    child_indent: int | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if indent == 0:
            in_packages = content == "packages:"
            pkg_indent = None
            child_indent = None
            sect_indent = indent if content in _PNPM_DEP_HEADERS else None
            continue
        if in_packages:
            if pkg_indent is None:
                pkg_indent = indent
            if indent != pkg_indent or not content.endswith(":"):
                continue
            key = content[:-1].strip().strip("'\"")
            if key.startswith("/"):
                key = key[1:]
            split = _pnpm_split_key(key)
            if split:
                entries.append(split)
            continue
        if content in _PNPM_DEP_HEADERS:
            sect_indent = indent
            child_indent = None
            continue
        if sect_indent is not None:
            if indent <= sect_indent:
                sect_indent = None
                child_indent = None
                continue
            if child_indent is None:
                child_indent = indent
            if indent == child_indent:
                name = content.split(":", 1)[0].strip().strip("'\"")
                if name:
                    directs.add(name)
    deps = [(n, v, n not in directs) for n, v in entries]
    return None, deps


# ------------------------------------------------------------------- PyPI
_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:===|==|>=|<=|~=|!=|<|>)\s*([^\s;,]+)"
)


def parse_requirements_txt(text: str) -> Parsed:
    """requirements.txt: `name<op>ver` lines. Comments, -r/-e/--flag
    lines, and env markers after ';' are ignored; names are PEP 503
    normalized. requirements.txt has no self name -> declared None."""
    deps: list[Dep] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            deps.append((_pep503(m.group(1)), m.group(2).strip(), False))
    return None, deps


_PEP508_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def _parse_pep508(req) -> tuple[str, str] | None:
    """(normalized name, best-effort version constraint) from a PEP 508
    requirement string, or None if it has no name."""
    if not isinstance(req, str):
        return None
    s = req.split(";", 1)[0].strip()
    m = _PEP508_RE.match(s)
    if not m:
        return None
    return _pep503(m.group(1)), m.group(2).strip().strip("()").strip()


def _poetry_version(spec) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and isinstance(spec.get("version"), str):
        return spec["version"]
    return ""


def parse_pyproject_deps(text: str) -> Parsed:
    """pyproject.toml: PEP 621 [project].dependencies +
    [project.optional-dependencies], plus poetry [tool.poetry.dependencies]
    / dev-dependencies / group.*.dependencies. Declared from [project].name
    or [tool.poetry].name. All entries are directs (indirect=False)."""
    try:
        import tomllib
    except ModuleNotFoundError:  # <3.11 without a backport
        return None, []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    declared: str | None = None
    deps: list[Dep] = []

    project = data.get("project")
    if isinstance(project, dict):
        declared = project.get("name") or None
        reqs = project.get("dependencies")
        if isinstance(reqs, list):
            for r in reqs:
                p = _parse_pep508(r)
                if p:
                    deps.append((p[0], p[1], False))
        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for group in opt.values():
                if isinstance(group, list):
                    for r in group:
                        p = _parse_pep508(r)
                        if p:
                            deps.append((p[0], p[1], False))

    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        if not declared:
            declared = poetry.get("name") or None
        sections = []
        for sect in ("dependencies", "dev-dependencies"):
            if isinstance(poetry.get(sect), dict):
                sections.append(poetry[sect])
        grp = poetry.get("group")
        if isinstance(grp, dict):
            for g in grp.values():
                if isinstance(g, dict) and isinstance(g.get("dependencies"), dict):
                    sections.append(g["dependencies"])
        for m in sections:
            for name, spec in m.items():
                if not isinstance(name, str) or name.lower() == "python":
                    continue
                deps.append((_pep503(name), _poetry_version(spec), False))
    return declared, deps


def parse_poetry_lock(text: str) -> Parsed:
    """poetry.lock: [[package]] name+version tables. The lock does not
    separate direct from transitive -> all indirect=True; declared None."""
    try:
        import tomllib
    except ModuleNotFoundError:
        return None, []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return None, []
    deps: list[Dep] = []
    pkgs = data.get("package") if isinstance(data, dict) else None
    if isinstance(pkgs, list):
        for p in pkgs:
            if isinstance(p, dict):
                n, v = p.get("name"), p.get("version")
                if isinstance(n, str) and isinstance(v, str):
                    deps.append((_pep503(n), v, True))
    return None, deps


def parse_pipfile_lock(text: str) -> Parsed:
    """Pipfile.lock (JSON): default + develop objects. Version strings are
    often "==x.y.z" -> leading "==" stripped. Resolved deps are not split
    direct/transitive -> all indirect=True; declared None."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    deps: list[Dep] = []
    for sect in ("default", "develop"):
        m = data.get(sect)
        if isinstance(m, dict):
            for name, spec in m.items():
                if not isinstance(name, str):
                    continue
                ver = ""
                if isinstance(spec, dict) and isinstance(spec.get("version"), str):
                    ver = spec["version"].lstrip("=")
                deps.append((_pep503(name), ver, True))
    return None, deps


_SETUP_NAME_RE = re.compile(r"""\bname\s*=\s*['"]([^'"]+)['"]""")
_INSTALL_REQUIRES_RE = re.compile(r"install_requires\s*=\s*\[(.*?)\]", re.S)
_STR_LITERAL_RE = re.compile(r"""['"]([^'"]+)['"]""")


def parse_setup_py(text: str) -> Parsed:
    """setup.py: best-effort regex over the `install_requires=[...]` list
    literal — each quoted PEP 508 requirement becomes a direct
    (indirect=False). Declared from the first `name="..."` kwarg. Dynamic
    (computed) install_requires values cannot be read statically and yield
    no deps — a legitimate empty."""
    m = _SETUP_NAME_RE.search(text)
    declared = m.group(1) if m else None
    deps: list[Dep] = []
    im = _INSTALL_REQUIRES_RE.search(text)
    if im:
        for sm in _STR_LITERAL_RE.finditer(im.group(1)):
            p = _parse_pep508(sm.group(1))
            if p:
                deps.append((p[0], p[1], False))
    return declared, deps


def parse_constraints_txt(text: str) -> Parsed:
    """constraints.txt: identical grammar to requirements.txt (pinned
    version constraints), so it delegates to parse_requirements_txt."""
    return parse_requirements_txt(text)


def parse_environment_yml(text: str) -> Parsed:
    """environment.yml / environment.yaml (conda; minimal hand YAML scan).
    The `dependencies:` list holds conda specs (`name=version`,
    `name==version`, channel-prefixed `chan::name=ver`, or bare `name`) and
    an optional nested `pip:` list of PEP 508 requirements. Everything is
    emitted as ecosystem 'pypi' best-effort (conda names approximate PyPI
    names). All entries are directs (indirect=False). declared None — the
    env name is not a distributable package name."""
    deps: list[Dep] = []
    in_deps = False
    deps_header_indent = 0
    pip_marker_indent: int | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if content == "dependencies:":
            in_deps = True
            deps_header_indent = indent
            pip_marker_indent = None
            continue
        if not in_deps:
            continue
        if not content.startswith("-"):
            if indent <= deps_header_indent:
                in_deps = False
            continue
        item = content[1:].strip()
        if pip_marker_indent is not None and indent <= pip_marker_indent:
            pip_marker_indent = None
        if pip_marker_indent is None and (item == "pip:" or item.startswith("pip:")):
            pip_marker_indent = indent
            continue
        if pip_marker_indent is not None:
            p = _parse_pep508(item)
            if p:
                deps.append((p[0], p[1], False))
            continue
        c = _parse_conda_spec(item)
        if c:
            deps.append((c[0], c[1], False))
    return None, deps


_CONDA_SPEC_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:(?:==|>=|<=|!=|~=|=)\s*([^\s=]+))?"
)


def _parse_conda_spec(item: str) -> tuple[str, str] | None:
    """(normalized name, best-effort version) from a conda dependency spec,
    or None. Channel prefix (`chan::pkg`) and trailing build string
    (`=py310h...`) are stripped; a bare `name` yields version ''."""
    item = item.split("::", 1)[-1]
    item = item.split("#", 1)[0].strip()
    if not item:
        return None
    m = _CONDA_SPEC_RE.match(item)
    if not m:
        return None
    return _pep503(m.group(1)), (m.group(2) or "").strip()


# ------------------------------------------------------------------- Maven
_PROP_RE = re.compile(r"\$\{([^}]+)\}")


def _resolve_prop(value: str, props: dict[str, str]) -> str:
    """Resolve ${prop} references from `props`. Returns "" when the value
    is empty or any reference is unresolvable — the caller then SKIPS the
    dependency rather than emit a bogus version."""
    if not value:
        return ""
    cur = value
    for _ in range(10):
        if "${" not in cur:
            break
        nxt = _PROP_RE.sub(lambda m: props.get(m.group(1), ""), cur)
        if nxt == cur:
            break
        cur = nxt
    if "${" in cur or not cur:
        return ""
    return cur


def parse_pom_xml(text: str) -> Parsed:
    """pom.xml (xml.etree, namespace-agnostic). Declared =
    groupId:artifactId of the project (groupId/version inherited from
    <parent> when absent). Deps -> "groupId:artifactId" with ${prop} and
    ${project.version} resolved from <properties>; a dep whose version is
    absent or unresolvable is OMITTED. Directs -> indirect=False.

    Both <dependencies> and <dependencyManagement><dependencies> are read
    (many parent/BOM poms pin versions only under dependencyManagement).
    Legitimate empties: a root/aggregator pom carrying only <modules> and no
    dependency section correctly yields (declared, []) — the caller records
    that as a tracked parse_empty, not an error."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None, []

    proj_group = _eltext(_child(root, "groupId"))
    proj_art = _eltext(_child(root, "artifactId"))
    proj_ver = _eltext(_child(root, "version"))
    parent = _child(root, "parent")
    if parent is not None:
        if not proj_group:
            proj_group = _eltext(_child(parent, "groupId"))
        if not proj_ver:
            proj_ver = _eltext(_child(parent, "version"))
    declared = f"{proj_group}:{proj_art}" if proj_group and proj_art else None

    props: dict[str, str] = {}
    pel = _child(root, "properties")
    if pel is not None:
        for c in pel:
            props[_localname(c.tag)] = (c.text or "").strip()
    if proj_ver:
        props.setdefault("project.version", proj_ver)

    deps: list[Dep] = []
    containers = []
    top = _child(root, "dependencies")
    if top is not None:
        containers.append(top)
    dm = _child(root, "dependencyManagement")
    if dm is not None:
        dmc = _child(dm, "dependencies")
        if dmc is not None:
            containers.append(dmc)
    for container in containers:
        for dep in _children(container, "dependency"):
            g = _eltext(_child(dep, "groupId"))
            a = _eltext(_child(dep, "artifactId"))
            v = _resolve_prop(_eltext(_child(dep, "version")), props)
            if g and a and v:
                deps.append((f"{g}:{a}", v, False))
    # dedupe (a coord may sit in both <dependencies> and
    # <dependencyManagement>) while preserving first-seen order
    seen: set[Dep] = set()
    uniq: list[Dep] = []
    for d in deps:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return declared, uniq


def parse_gradle_lockfile(text: str) -> Parsed:
    """gradle.lockfile: `group:artifact:version=conf,conf` lines -> name
    "group:artifact", version the 3rd colon field. Lockfile of resolved
    deps -> all indirect=True; declared None."""
    deps: list[Dep] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        coord = line.split("=", 1)[0].strip()
        parts = coord.split(":")
        if len(parts) >= 3 and parts[0] and parts[1] and parts[2]:
            deps.append((f"{parts[0]}:{parts[1]}", parts[2], True))
    return None, deps


_GRADLE_DEP_RE = re.compile(
    r"\b(?:implementation|api|compile|compileOnly|runtimeOnly|"
    r"testImplementation|testCompile|testRuntimeOnly|annotationProcessor|"
    r"kapt|classpath)\b[^\n'\"]*['\"]"
    r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+)['\"]"
)


def parse_build_gradle(text: str) -> Parsed:
    """build.gradle[.kts]: best-effort regex over `impl/api/compile ...
    'group:artifact:version'` string-literal deps. Directs ->
    indirect=False; declared None."""
    deps: list[Dep] = []
    for m in _GRADLE_DEP_RE.finditer(text):
        deps.append((f"{m.group(1)}:{m.group(2)}", m.group(3), False))
    return None, deps


# ------------------------------------------------------------------- Cargo
def parse_cargo_lock(text: str) -> Parsed:
    """Cargo.lock: [[package]] name+version tables. The root/workspace
    package cannot be reliably told from deps here -> all indirect=True;
    the caller's `declares` edge comes from Cargo.toml. Declared None."""
    try:
        import tomllib
    except ModuleNotFoundError:
        return None, []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return None, []
    deps: list[Dep] = []
    pkgs = data.get("package") if isinstance(data, dict) else None
    if isinstance(pkgs, list):
        for p in pkgs:
            if isinstance(p, dict):
                n, v = p.get("name"), p.get("version")
                if isinstance(n, str) and isinstance(v, str):
                    deps.append((n, v, True))
    return None, deps


def _cargo_version(spec) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and isinstance(spec.get("version"), str):
        return spec["version"]
    return ""


def parse_cargo_toml(text: str) -> Parsed:
    """Cargo.toml: [package].name declared; [dependencies] +
    [dev-dependencies] as directs (indirect=False). A dep value may be a
    version string or a table carrying "version"."""
    try:
        import tomllib
    except ModuleNotFoundError:
        return None, []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    declared = None
    pkg = data.get("package")
    if isinstance(pkg, dict):
        declared = pkg.get("name") or None
    deps: list[Dep] = []
    for sect in ("dependencies", "dev-dependencies"):
        m = data.get(sect)
        if isinstance(m, dict):
            for name, spec in m.items():
                if isinstance(name, str):
                    deps.append((name, _cargo_version(spec), False))
    return declared, deps


# ----------------------------------------------------------------- RubyGems
_GEM_SPEC_RE = re.compile(r"^    ([A-Za-z0-9._-]+) \(([0-9][A-Za-z0-9._+-]*)\)\s*$")


def parse_gemfile_lock(text: str) -> Parsed:
    """Gemfile.lock: inside a `specs:` block, 4-space-indent
    `name (x.y.z)` lines are resolved specs with pinned versions; deeper
    indents are sub-deps carrying constraints (not concrete pins) and are
    skipped. Lockfile does not cleanly separate direct -> all
    indirect=True; declared None."""
    deps: list[Dep] = []
    in_specs = False
    for raw in text.splitlines():
        if raw and not raw[0].isspace():
            in_specs = False
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        m = _GEM_SPEC_RE.match(raw)
        if m:
            deps.append((m.group(1), m.group(2), True))
    return None, deps


_GEMSPEC_DEP_RE = re.compile(
    r"\.add(?:_runtime|_development)?_dependency\s*\(?\s*"
    r"['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?"
)
_GEMSPEC_NAME_RE = re.compile(r"\.name\s*=\s*['\"]([^'\"]+)['\"]")


def parse_gemspec(text: str) -> Parsed:
    """*.gemspec: best-effort regex over add_dependency /
    add_runtime_dependency / add_development_dependency 'name',
    'constraint'. Declared from `.name = "..."` if present. Directs ->
    indirect=False."""
    m = _GEMSPEC_NAME_RE.search(text)
    declared = m.group(1) if m else None
    deps: list[Dep] = []
    for dm in _GEMSPEC_DEP_RE.finditer(text):
        deps.append((dm.group(1), dm.group(2) or "", False))
    return declared, deps


_GEMFILE_RE = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", re.M)


def parse_gemfile(text: str) -> Parsed:
    """Gemfile: `gem "name", "version"` lines (the version arg is
    optional). Directs -> indirect=False; declared None."""
    deps: list[Dep] = []
    for m in _GEMFILE_RE.finditer(text):
        deps.append((m.group(1), m.group(2) or "", False))
    return None, deps


# ------------------------------------------------------------------- NuGet
def parse_packages_lock_json(text: str) -> Parsed:
    """packages.lock.json: dependencies.<framework>.<name>.resolved =
    version. type "Direct" -> indirect=False; "Transitive"/"Project" ->
    indirect=True. Name lowercased for a canonical id; declared None."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    deps: list[Dep] = []
    frameworks = data.get("dependencies")
    if isinstance(frameworks, dict):
        for pkgs in frameworks.values():
            if not isinstance(pkgs, dict):
                continue
            for name, spec in pkgs.items():
                if not isinstance(name, str) or not isinstance(spec, dict):
                    continue
                ver = spec.get("resolved")
                if not isinstance(ver, str) or not ver:
                    continue
                typ = str(spec.get("type") or "").lower()
                deps.append((name.lower(), ver, typ != "direct"))
    return None, deps


def parse_csproj(text: str) -> Parsed:
    """*.csproj (xml.etree, namespace-agnostic): <PackageReference
    Include=.. Version=..> (Version may also be a child element). Directs
    -> indirect=False; declared None."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None, []
    deps: list[Dep] = []
    for el in root.iter():
        if _localname(el.tag) != "PackageReference":
            continue
        name = el.get("Include") or el.get("Update")
        if not name:
            continue
        ver = el.get("Version")
        if ver is None:
            vc = _child(el, "Version")
            ver = _eltext(vc) if vc is not None else ""
        deps.append((name, ver or "", False))
    return None, deps


# ------------------------------------------------------------------- Docker
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE
)


def _split_docker_ref(ref: str) -> tuple[str, str]:
    """(image, version) from a docker image ref. `@sha256:...` digest wins;
    else a `:tag` where the tail carries no `/` (guards `host:port/img`);
    else an untagged ref -> 'latest'."""
    if "@" in ref:
        image, _, digest = ref.partition("@")
        return image, digest
    if ":" in ref:
        head, _, tail = ref.rpartition(":")
        if "/" not in tail:
            return head, tail
    return ref, "latest"


def parse_dockerfile(text: str) -> Parsed:
    """Dockerfile: every external base image from a `FROM <ref> [AS name]`
    directive (case-insensitive). version = the `:tag` or `@sha256:` digest
    ('latest' when untagged). declared None; all indirect=False. Skipped
    (emit nothing bogus): `FROM scratch`, a FROM that references a prior
    build-stage `AS` alias, and unresolved `${ARG}`-templated images. Each
    distinct external (image, version) is emitted once."""
    deps: list[Dep] = []
    stages: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _FROM_RE.match(line)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        ref_is_stage = ref.lower() in stages
        if alias:
            stages.add(alias.lower())
        if ref_is_stage or ref.lower() == "scratch" or "${" in ref or ref.startswith("$"):
            continue
        image, version = _split_docker_ref(ref)
        key = (image, version)
        if key in seen:
            continue
        seen.add(key)
        deps.append((image, version, False))
    return None, deps


# ------------------------------------------------------- GitHub Actions
_USES_RE = re.compile(r"""(?m)^\s*(?:-\s*)?uses\s*:\s*['"]?([^\s'"#]+)""")


def parse_github_workflow(text: str) -> Parsed:
    """GitHub Actions workflow YAML: every `uses: owner/repo[/subdir]@ref`
    reference. action name canonicalized to `owner/repo` (any subdir path
    dropped for the OSV coordinate); version = the `@ref` (tag / branch /
    sha). Skipped: local `uses: ./...` and `uses: docker://...`, and any
    ref without an `@`. declared None; all indirect=False. Each distinct
    (action, ref) is emitted once."""
    deps: list[Dep] = []
    seen: set[tuple[str, str]] = set()
    for m in _USES_RE.finditer(text):
        ref = m.group(1)
        if ref.startswith((".", "/")) or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            continue
        path, _, version = ref.rpartition("@")
        if not version:
            continue
        parts = path.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        action = f"{parts[0]}/{parts[1]}"
        key = (action, version)
        if key in seen:
            continue
        seen.add(key)
        deps.append((action, version, False))
    return None, deps


# ------------------------------------------------------------------- Helm
def _yaml_scalar(v: str) -> str:
    """Best-effort scalar value: strip a matching quote pair, else strip a
    trailing ` # inline comment`."""
    v = v.strip()
    if v and v[0] in "\"'":
        q = v[0]
        end = v.find(q, 1)
        return v[1:end] if end != -1 else v[1:]
    return re.split(r"\s+#", v, maxsplit=1)[0].strip()


def _helm_kv(s: str, cur: dict[str, str]) -> None:
    m = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", s)
    if not m:
        return
    key, val = m.group(1), _yaml_scalar(m.group(2))
    if key in ("name", "version") and val:
        cur[key] = val


def parse_helm_chart(text: str) -> Parsed:
    """Chart.yaml / legacy requirements.yaml (minimal hand YAML scan). The
    top-level `name:` is the declared chart name (None for the nameless
    legacy requirements.yaml). Each item under `dependencies:` (a list of
    {name, version, repository} mappings) is emitted as (name, version,
    False); the repository field is ignored for the OSV coordinate."""
    declared: str | None = None
    deps: list[Dep] = []
    in_deps = False
    deps_indent = 0
    cur: dict[str, str] = {}

    def flush() -> None:
        nonlocal cur
        n = cur.get("name")
        if n:
            deps.append((n, cur.get("version", ""), False))
        cur = {}

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if not in_deps:
            if content == "dependencies:":
                in_deps = True
                deps_indent = indent
                continue
            if declared is None and indent == 0:
                m = re.match(r"^name\s*:\s*(.+)$", content)
                if m:
                    declared = _yaml_scalar(m.group(1)) or None
            continue
        if indent <= deps_indent and not content.startswith("-"):
            flush()
            in_deps = False
            if declared is None and indent == 0:
                m = re.match(r"^name\s*:\s*(.+)$", content)
                if m:
                    declared = _yaml_scalar(m.group(1)) or None
            continue
        if content.startswith("-"):
            flush()
            item = content[1:].strip()
            if item:
                _helm_kv(item, cur)
            continue
        _helm_kv(content, cur)
    flush()
    return declared, deps


# --------------------------------------------------------------- dispatch
# ecosystem -> ordered candidate filenames (lockfile first, manifest
# fallback). Two manifests are globs, not fixed filenames, so they are not
# listed here: *.gemspec (ruby, repo-root glob) and *.csproj (nuget, glob).
# parser_for() resolves those by suffix.
ECOSYSTEM_MANIFESTS: dict[str, list[str]] = {
    "npm": ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "package.json"],
    "pypi": [
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "constraints.txt",
        "environment.yml",
    ],
    "maven": ["gradle.lockfile", "pom.xml", "build.gradle", "build.gradle.kts"],
    "cargo": ["Cargo.lock", "Cargo.toml"],
    "ruby": ["Gemfile.lock", "Gemfile"],  # + *.gemspec (repo-root glob)
    "nuget": ["packages.lock.json"],  # + *.csproj (glob)
    # Path-discovered universal ecosystems (see UNIVERSAL_ECOSYSTEMS /
    # PATH_GLOB_ECOSYSTEMS below) — not language-gated.
    "docker": ["Dockerfile"],  # + Dockerfile.* / *.Dockerfile (glob)
    "actions": [],  # path-based only: .github/workflows/*.y*ml
    "helm": ["Chart.yaml", "requirements.yaml"],
}

# GitHub language name -> ecosystem, for language-gated manifest selection.
# NOTE: docker/actions/helm are intentionally absent — they are discovered
# by PATH for every repo regardless of language (UNIVERSAL_ECOSYSTEMS).
LANGUAGE_ECOSYSTEMS: dict[str, str] = {
    "JavaScript": "npm",
    "TypeScript": "npm",
    "Python": "pypi",
    "Java": "maven",
    "Kotlin": "maven",
    "Scala": "maven",
    "Groovy": "maven",
    "Rust": "cargo",
    "Ruby": "ruby",
    "C#": "nuget",
}

# Ecosystems discovered by PATH, not by GitHub language: a Go (or any-lang)
# repo still ships Dockerfiles, GitHub Actions workflows, and Helm charts.
# The graph builder fetches these for EVERY repo regardless of language,
# using PATH_GLOB_ECOSYSTEMS (not LANGUAGE_ECOSYSTEMS).
UNIVERSAL_ECOSYSTEMS: set[str] = {"docker", "actions", "helm"}

# ecosystem -> discovery globs (relative to repo root) for the universal,
# path-discovered surfaces. 'actions' is strictly the workflows dir.
PATH_GLOB_ECOSYSTEMS: dict[str, list[str]] = {
    "docker": ["**/Dockerfile*", "**/*.Dockerfile"],
    "actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
    "helm": ["**/Chart.yaml", "**/requirements.yaml"],
}

# exact manifest filename -> (ecosystem, parser callable)
PARSER_BY_FILENAME: dict[str, tuple[str, callable]] = {
    "package-lock.json": ("npm", parse_package_lock),
    "npm-shrinkwrap.json": ("npm", parse_npm_shrinkwrap),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock),
    "package.json": ("npm", parse_package_json),
    "poetry.lock": ("pypi", parse_poetry_lock),
    "Pipfile.lock": ("pypi", parse_pipfile_lock),
    "requirements.txt": ("pypi", parse_requirements_txt),
    "pyproject.toml": ("pypi", parse_pyproject_deps),
    "setup.py": ("pypi", parse_setup_py),
    "constraints.txt": ("pypi", parse_constraints_txt),
    "environment.yml": ("pypi", parse_environment_yml),
    "environment.yaml": ("pypi", parse_environment_yml),
    "gradle.lockfile": ("maven", parse_gradle_lockfile),
    "pom.xml": ("maven", parse_pom_xml),
    "build.gradle": ("maven", parse_build_gradle),
    "build.gradle.kts": ("maven", parse_build_gradle),
    "Cargo.lock": ("cargo", parse_cargo_lock),
    "Cargo.toml": ("cargo", parse_cargo_toml),
    "Gemfile.lock": ("ruby", parse_gemfile_lock),
    "Gemfile": ("ruby", parse_gemfile),
    "packages.lock.json": ("nuget", parse_packages_lock_json),
    "Dockerfile": ("docker", parse_dockerfile),
    "Chart.yaml": ("helm", parse_helm_chart),
    "requirements.yaml": ("helm", parse_helm_chart),
}


def parser_for(filename: str):
    """(ecosystem, parser) for a manifest filename, or None if unknown.
    Accepts a bare name or a path (basename is used) and resolves the glob
    manifests by suffix: *.gemspec -> ruby, *.csproj -> nuget,
    requirements*.txt -> pypi, and Dockerfile.* / *.Dockerfile -> docker.

    NOTE: GitHub Actions workflows are PATH-based (they are ordinary
    *.yml/*.yaml files distinguished only by living under
    .github/workflows/), so they are NOT routed here — use parser_for_path()
    (or is_workflow_path()) when a full path is available."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    hit = PARSER_BY_FILENAME.get(base)
    if hit:
        return hit
    if base.endswith(".gemspec"):
        return ("ruby", parse_gemspec)
    if base.endswith(".csproj"):
        return ("nuget", parse_csproj)
    if base.startswith("requirements") and base.endswith(".txt"):
        return ("pypi", parse_requirements_txt)
    if base.startswith("Dockerfile.") or base.endswith(".Dockerfile"):
        return ("docker", parse_dockerfile)
    return None


def is_workflow_path(path: str) -> bool:
    """True when `path` is a GitHub Actions workflow file — a *.yml/*.yaml
    directly under a .github/workflows/ directory (anywhere in the tree)."""
    p = path.replace("\\", "/")
    if not (p.endswith(".yml") or p.endswith(".yaml")):
        return False
    return "/.github/workflows/" in p or p.startswith(".github/workflows/")


def parser_for_path(path: str):
    """Path-aware dispatch the graph builder should prefer when it has a
    full repo-relative path: routes .github/workflows/*.y{,a}ml to the
    workflow parser first, otherwise falls back to basename parser_for()."""
    if is_workflow_path(path):
        return ("actions", parse_github_workflow)
    return parser_for(path)
