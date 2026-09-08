"""crypto_probe.py — General-purpose crypto posture probing for a repository.

Deterministic static analysis of build files, Dockerfiles, lock files, and
source to discover what crypto stack a repository uses.  This is a **provider
census** tool — it identifies which crypto stacks are present and their
versions.  TLS configuration details (cipher suites, protocol versions) and
code-level crypto API usage are handled by pqc-scan / opengrep rules.

Each fact is a dict with at minimum:
    probe_id  — what was detected (CRYPTO_* namespace)
    file      — relative path within the repo
    line      — 1-based line number (0 if not applicable)
    detail    — human-readable description (max 200 chars)
    provider  — crypto stack identifier (go, openssl, jdk, node, rustls, ...)

Optional per-probe fields:
    version   — detected version string
    extra     — dict of probe-specific metadata

Usage:
    crypto_probe.py --repo-dir DIR [--json]
    python -c 'import crypto_probe; print(crypto_probe.probe_repo(Path("...")))'
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

VENDOR_RX = re.compile(
    r"(^|/)(vendor|node_modules|third_party|_vendor|3rdparty|third-party|"
    r"bundled|external|site-packages|\.gomodcache)(/|$)"
)

GO_DIRECTIVE_RX = re.compile(r"(?m)^go\s+(\d+)\.(\d+)")
FROM_RX = re.compile(r"(?mi)^\s*FROM\s+(\S+)")
FROM_ALIAS_RX = re.compile(r"(?mi)^\s*FROM\s+\S+\s+AS\s+(\S+)")
PKG_INSTALL_OPENSSL_RX = re.compile(
    r"(?mi)\b(dnf|yum|microdnf|apt-get|apt|apk)\b[^\n]*"
    r"(?:install|add)[^\n]*\b(openssl\S*|libssl\S*|gnutls\S*|libnss\S*)"
)
GOEXPERIMENT_RX = re.compile(
    r"(?mi)GOEXPERIMENT\s*[=:]\s*(\S*(?:boringcrypto|opensslcrypto|cngcrypto)\S*)"
)
CGO_FIPS_RX = re.compile(r"(?mi)CGO_ENABLED\s*[=:]\s*1")
GODEBUG_TLS_RX = re.compile(r"GODEBUG\s*[=:].{0,80}?tls(mlkem|kyber)=0")
GODEBUG_FIPS_RX = re.compile(r"GODEBUG\s*[=:].{0,80}?fips140\s*=\s*(on|only)")
CRYPTO_POLICY_RX = re.compile(
    r"update-crypto-policies\s+--set\s+(\S+)|\bFIPS[:=\s]*(mode|true|enabled)", re.I
)
NEVRA_CRYPTO_RX = re.compile(
    r"(?m)(openssl(?:-libs|-fips-provider)?|crypto-policies|gnutls|nss)"
    r"[^\n]{0,40}?(\d+[.:][\w.\-]+)"
)
CARGO_TLS_RX = re.compile(
    r"(?m)(rustls|native-tls|openssl|ring|aws-lc-rs)\s*=\s*\{[^}]*"
    r'version\s*=\s*"([^"]+)"'
)
CARGO_SIMPLE_RX = re.compile(r'(?m)(rustls|native-tls|ring|aws-lc-rs)\s*=\s*"([^"]+)"')
GRADLE_JAVA_RX = re.compile(
    r"(?:sourceCompatibility|targetCompatibility|toolchain\s*\{[^}]*"
    r"languageVersion\.set\(JavaLanguageVersion\.of\()\s*[=( ]*(\d+)"
)
PYTHON_CRYPTO_DEPS_RX = re.compile(
    r"(?mi)^(cryptography|pyopenssl|pycryptodome|pynacl|paramiko|"
    r"python-jose|pyjwt|certifi)(?:\[[\w,]+\])?\s*[=~><!]+\s*([\d.]+)"
)
NODE_SEMVER_RX = re.compile(r"(\d+)(?:\.(\d+))?")
CSPROJ_TFM_RX = re.compile(r"<TargetFramework>net(\d+)\.(\d+)")
CSPROJ_PKG_CRYPTO_RX = re.compile(
    r'<PackageReference\s+Include="(System\.Security\.Cryptography\S*|'
    r'BouncyCastle\S*|NSec\S*|Portable\.BouncyCastle)"'
    r'\s+Version="([^"]+)"',
    re.I,
)
JVM_TLS_PROPS_RX = re.compile(
    r"(?m)^(jdk\.tls\.namedGroups|jdk\.tls\.disabledAlgorithms|"
    r"jdk\.tls\.ephemeralDHKeySize)\s*=\s*(.+)"
)

GOLANG_FIPS_RX = re.compile(
    r"(?m)(golang\.org/x/crypto/internal/boring"
    r"|github\.com/golang-fips/"
    r"|go-toolset-.*-openssl-fips"
    r"|openssl-fips-provider)"
)
DOCKERFILE_ARG_ENV_RX = re.compile(r"(?mi)^\s*(?:ARG|ENV)\s+(\w+)\s*=\s*(\S+)")
DOCKERFILE_LABEL_RX = re.compile(r'(?mi)^\s*LABEL\s+(\S+)\s*=\s*"?([^"\n]+)')
CRYPTO_KEYWORDS = frozenset(
    (
        "fips",
        "crypto",
        "openssl",
        "gnutls",
        "nss",
        "tls",
        "ssl",
        "boringcrypto",
        "opensslcrypto",
        "cngcrypto",
        "boring",
        "goexperiment",
        "cgo_enabled",
        "golang-fips",
    )
)

TEXT_EXTS = {
    ".go",
    ".py",
    ".sh",
    ".yaml",
    ".yml",
    ".env",
    ".conf",
    ".md",
    ".just",
    ".properties",
    ".toml",
    ".cfg",
    ".rb",
    ".cs",
    ".csproj",
    ".json",
    "",
}

MAX_FILE_SIZE = 1_000_000


@dataclass
class CryptoFact:
    probe_id: str
    file: str
    line: int
    detail: str
    provider: str
    version: str | None = None
    extra: dict = field(default_factory=dict)


def _rfiles(repo, pattern):
    """rglob that never follows file symlinks out of the untrusted
    checkout — excerpts flow into committed facts (audit B5, plan P1.7)."""
    return [
        p for p in sorted(repo.rglob(pattern)) if not p.is_symlink() and (p.is_file() or p.is_dir())
    ]


def _is_vendor(rel: str) -> bool:
    return bool(VENDOR_RX.search(rel))


def _extract_min_semver(constraint: str) -> str | None:
    """Extract the minimum version from a semver constraint like '>=18.0.0' or '^20'."""
    m = re.search(r"[>=^~]*\s*(\d+(?:\.\d+)*)", constraint)
    return m.group(1) if m else None


# ---------- Go ----------


def probe_go(repo: Path) -> list[CryptoFact]:
    facts = []
    for gm in _rfiles(repo, "go.mod"):
        rel = str(gm.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = gm.read_text(errors="replace")
        m = GO_DIRECTIVE_RX.search(text)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_GO_TOOLCHAIN",
                    file=rel,
                    line=1,
                    detail=f"go {major}.{minor}",
                    provider="go",
                    version=f"{major}.{minor}",
                )
            )
        if GOLANG_FIPS_RX.search(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_GO_FIPS_BACKEND",
                    file=rel,
                    line=1,
                    detail="golang-fips or boring crypto dependency in go.mod",
                    provider="go-fips",
                    extra={
                        "crypto_backend_swap": True,
                        "note": "Go stdlib crypto replaced by OpenSSL via CGo",
                    },
                )
            )
    for gs in _rfiles(repo, "go.sum"):
        rel = str(gs.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = gs.read_text(errors="replace")
        if GOLANG_FIPS_RX.search(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_GO_FIPS_BACKEND",
                    file=rel,
                    line=1,
                    detail="golang-fips or boring crypto dependency in go.sum",
                    provider="go-fips",
                    extra={"crypto_backend_swap": True},
                )
            )
    return facts


# ---------- Dockerfiles ----------


def probe_dockerfiles(repo: Path) -> list[CryptoFact]:
    facts = []
    for name in ("Dockerfile", "Containerfile"):
        for df in _rfiles(repo, f"{name}*"):
            rel = str(df.relative_to(repo))
            if _is_vendor(rel) or not df.is_file():
                continue
            try:
                text = df.read_text(errors="replace")
            except OSError:
                continue

            aliases = {a.lower() for a in FROM_ALIAS_RX.findall(text)}
            for m in FROM_RX.finditer(text):
                img = m.group(1)
                if img.lower() in aliases or img.lower() == "scratch":
                    continue
                line = text[: m.start()].count("\n") + 1
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_BASE_IMAGE",
                        file=rel,
                        line=line,
                        detail=img,
                        provider="base-image",
                    )
                )

            for m in PKG_INSTALL_OPENSSL_RX.finditer(text):
                line = text[: m.start()].count("\n") + 1
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_OPENSSL_INSTALL",
                        file=rel,
                        line=line,
                        detail=m.group(0)[:200],
                        provider="openssl",
                    )
                )

            for m in DOCKERFILE_ARG_ENV_RX.finditer(text):
                key, val = m.group(1), m.group(2)
                combined = f"{key}={val}".lower()
                if any(kw in combined for kw in CRYPTO_KEYWORDS):
                    line = text[: m.start()].count("\n") + 1
                    facts.append(
                        CryptoFact(
                            probe_id="CRYPTO_DOCKERFILE_DIRECTIVE",
                            file=rel,
                            line=line,
                            detail=f"{key}={val}"[:200],
                            provider="container-build",
                            extra={"directive_type": "env", "key": key, "value": val},
                        )
                    )

            for m in DOCKERFILE_LABEL_RX.finditer(text):
                key, val = m.group(1), m.group(2).strip()
                combined = f"{key}={val}".lower()
                if any(kw in combined for kw in CRYPTO_KEYWORDS):
                    line = text[: m.start()].count("\n") + 1
                    facts.append(
                        CryptoFact(
                            probe_id="CRYPTO_DOCKERFILE_DIRECTIVE",
                            file=rel,
                            line=line,
                            detail=f"{key}={val}"[:200],
                            provider="container-build",
                            extra={"directive_type": "label", "key": key, "value": val},
                        )
                    )
    return facts


# ---------- Node.js ----------


def probe_node(repo: Path) -> list[CryptoFact]:
    facts = []
    for nv in _rfiles(repo, ".nvmrc"):
        rel = str(nv.relative_to(repo))
        if _is_vendor(rel):
            continue
        ver = nv.read_text(errors="replace").strip().lstrip("v")
        m = re.match(r"(\d+(?:\.\d+)*)", ver)
        if m:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_NODE_VERSION",
                    file=rel,
                    line=1,
                    detail=f"node {ver}",
                    provider="node",
                    version=m.group(1),
                )
            )
    for pj in _rfiles(repo, "package.json"):
        rel = str(pj.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            eng = (json.loads(pj.read_text(errors="replace")).get("engines") or {}).get("node")
        except (json.JSONDecodeError, AttributeError):
            continue
        if eng:
            ver = _extract_min_semver(str(eng))
            if ver:
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_NODE_VERSION",
                        file=rel,
                        line=1,
                        detail=f"engines.node {eng}",
                        provider="node",
                        version=ver,
                    )
                )
    return facts


# ---------- JDK ----------


def probe_jdk(repo: Path) -> list[CryptoFact]:
    facts = []
    for pom in _rfiles(repo, "pom.xml"):
        rel = str(pom.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = pom.read_text(errors="replace")
        m = re.search(
            r"<(?:maven\.compiler\.(?:release|source)|"
            r"java\.version)>\s*(\d+)",
            text,
        )
        if m:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_JDK_VERSION",
                    file=rel,
                    line=1,
                    detail=f"jdk {m.group(1)}",
                    provider="jdk",
                    version=m.group(1),
                )
            )
    for bg in _rfiles(repo, "build.gradle*"):
        rel = str(bg.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = bg.read_text(errors="replace")
        m = GRADLE_JAVA_RX.search(text)
        if m:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_JDK_VERSION",
                    file=rel,
                    line=1,
                    detail=f"jdk {m.group(1)}",
                    provider="jdk",
                    version=m.group(1),
                )
            )
    for sec in _rfiles(repo, "java.security"):
        rel = str(sec.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            text = sec.read_text(errors="replace")
        except OSError:
            continue
        for m in JVM_TLS_PROPS_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_JVM_SECURITY_PROPERTY",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"{m.group(1)}={m.group(2)[:150]}",
                    provider="jdk",
                )
            )
    return facts


# ---------- Python ----------


def probe_python(repo: Path) -> list[CryptoFact]:
    facts = []
    for pv in _rfiles(repo, ".python-version"):
        rel = str(pv.relative_to(repo))
        if _is_vendor(rel):
            continue
        ver = pv.read_text(errors="replace").strip()
        m = re.match(r"(\d+(?:\.\d+)*)", ver)
        if m:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_PYTHON_VERSION",
                    file=rel,
                    line=1,
                    detail=f"python {ver}",
                    provider="python",
                    version=m.group(1),
                )
            )

    for reqfile in ("requirements.txt", "requirements-dev.txt", "requirements-security.txt"):
        for rf in _rfiles(repo, reqfile):
            rel = str(rf.relative_to(repo))
            if _is_vendor(rel):
                continue
            try:
                text = rf.read_text(errors="replace")
            except OSError:
                continue
            for m in PYTHON_CRYPTO_DEPS_RX.finditer(text):
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_PYTHON_CRYPTO_DEP",
                        file=rel,
                        line=text[: m.start()].count("\n") + 1,
                        detail=f"{m.group(1)}=={m.group(2)}",
                        provider="python",
                        version=m.group(2),
                        extra={"package": m.group(1)},
                    )
                )

    for pp in _rfiles(repo, "pyproject.toml"):
        rel = str(pp.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            text = pp.read_text(errors="replace")
        except OSError:
            continue
        pyver = re.search(r'requires-python\s*=\s*"([^"]+)"', text)
        if pyver:
            ver = _extract_min_semver(pyver.group(1))
            if ver:
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_PYTHON_VERSION",
                        file=rel,
                        line=text[: pyver.start()].count("\n") + 1,
                        detail=f"requires-python {pyver.group(1)}",
                        provider="python",
                        version=ver,
                    )
                )
        for m in PYTHON_CRYPTO_DEPS_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_PYTHON_CRYPTO_DEP",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"{m.group(1)}=={m.group(2)}",
                    provider="python",
                    version=m.group(2),
                    extra={"package": m.group(1)},
                )
            )

    for pf in _rfiles(repo, "Pipfile"):
        rel = str(pf.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            text = pf.read_text(errors="replace")
        except OSError:
            continue
        pyver = re.search(r'python_version\s*=\s*"([^"]+)"', text)
        if pyver:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_PYTHON_VERSION",
                    file=rel,
                    line=text[: pyver.start()].count("\n") + 1,
                    detail=f"python_version {pyver.group(1)}",
                    provider="python",
                    version=pyver.group(1),
                )
            )
    return facts


# ---------- Rust ----------


def probe_rust(repo: Path) -> list[CryptoFact]:
    facts = []
    for ct in _rfiles(repo, "Cargo.toml"):
        rel = str(ct.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = ct.read_text(errors="replace")
        rv = re.search(r'(?m)^rust-version\s*=\s*"([^"]+)"', text)
        if rv:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_RUST_VERSION",
                    file=rel,
                    line=1,
                    detail=f"rust {rv.group(1)}",
                    provider="rust",
                    version=rv.group(1),
                )
            )
        for m in CARGO_TLS_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_RUST_TLS_BACKEND",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"{m.group(1)} {m.group(2)}",
                    provider=m.group(1),
                    version=m.group(2),
                )
            )
        for m in CARGO_SIMPLE_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_RUST_TLS_BACKEND",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"{m.group(1)} {m.group(2)}",
                    provider=m.group(1),
                    version=m.group(2),
                )
            )
    return facts


# ---------- C/C++ ----------


def probe_c(repo: Path) -> list[CryptoFact]:
    """Probe C/C++ projects for TLS library linkage."""
    facts = []
    for cmake in _rfiles(repo, "CMakeLists.txt"):
        rel = str(cmake.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = cmake.read_text(errors="replace")
        for lib in ("OpenSSL", "GnuTLS", "MbedTLS", "wolfSSL"):
            if re.search(rf"find_package\(\s*{lib}", text, re.I):
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_C_TLS_LIBRARY",
                        file=rel,
                        line=1,
                        detail=f"find_package({lib})",
                        provider=lib.lower(),
                    )
                )
        for m in re.finditer(
            r"pkg_check_modules\([^)]*\b(openssl|gnutls|"
            r"mbedtls|wolfssl)\b",
            text,
            re.I,
        ):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_C_TLS_LIBRARY",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"pkg_check_modules {m.group(1)}",
                    provider=m.group(1).lower(),
                )
            )
    for conf in _rfiles(repo, "configure.ac"):
        rel = str(conf.relative_to(repo))
        if _is_vendor(rel):
            continue
        text = conf.read_text(errors="replace")
        for lib in ("openssl", "gnutls", "mbedtls"):
            if re.search(rf"AC_CHECK_LIB\(\[?{lib}", text, re.I):
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_C_TLS_LIBRARY",
                        file=rel,
                        line=1,
                        detail=f"AC_CHECK_LIB({lib})",
                        provider=lib,
                    )
                )
    return facts


# ---------- .NET / C# ----------


def probe_dotnet(repo: Path) -> list[CryptoFact]:
    facts = []
    for gj in _rfiles(repo, "global.json"):
        rel = str(gj.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            doc = json.loads(gj.read_text(errors="replace"))
            ver = (doc.get("sdk") or {}).get("version")
            if ver:
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_DOTNET_SDK",
                        file=rel,
                        line=1,
                        detail=f"dotnet sdk {ver}",
                        provider="dotnet",
                        version=ver,
                    )
                )
        except (json.JSONDecodeError, AttributeError):
            continue
    for csproj in _rfiles(repo, "*.csproj"):
        rel = str(csproj.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            text = csproj.read_text(errors="replace")
        except OSError:
            continue
        m = CSPROJ_TFM_RX.search(text)
        if m:
            ver = f"{m.group(1)}.{m.group(2)}"
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_DOTNET_TFM",
                    file=rel,
                    line=1,
                    detail=f"net{ver}",
                    provider="dotnet",
                    version=ver,
                )
            )
        for m in CSPROJ_PKG_CRYPTO_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_DOTNET_CRYPTO_PKG",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"{m.group(1)} {m.group(2)}",
                    provider="dotnet",
                    version=m.group(2),
                    extra={"package": m.group(1)},
                )
            )
    return facts


# ---------- Ruby ----------


def probe_ruby(repo: Path) -> list[CryptoFact]:
    facts = []
    for rv in _rfiles(repo, ".ruby-version"):
        rel = str(rv.relative_to(repo))
        if _is_vendor(rel):
            continue
        ver = rv.read_text(errors="replace").strip()
        m = re.match(r"(\d+(?:\.\d+)*)", ver)
        if m:
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_RUBY_VERSION",
                    file=rel,
                    line=1,
                    detail=f"ruby {ver}",
                    provider="ruby",
                    version=m.group(1),
                )
            )
    ruby_crypto_rx = re.compile(
        r"(?m)^\s*gem\s+['\"]("
        r"openssl|rbnacl|bcrypt|ed25519|jwt|jose|rsa"
        r")['\"](?:\s*,\s*['\"]([~>=<!\s\d.]+)['\"])?"
    )
    for gf in _rfiles(repo, "Gemfile"):
        rel = str(gf.relative_to(repo))
        if _is_vendor(rel):
            continue
        try:
            text = gf.read_text(errors="replace")
        except OSError:
            continue
        for m in ruby_crypto_rx.finditer(text):
            ver = _extract_min_semver(m.group(2)) if m.group(2) else None
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_RUBY_CRYPTO_GEM",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"gem {m.group(1)}{' ' + m.group(2) if m.group(2) else ''}",
                    provider="ruby",
                    version=ver,
                    extra={"gem": m.group(1)},
                )
            )
    return facts


# ---------- RPM locks ----------


def probe_rpm_locks(repo: Path) -> list[CryptoFact]:
    facts = []
    for lock in _rfiles(repo, "rpms.lock.yaml"):
        rel = str(lock.relative_to(repo))
        text = lock.read_text(errors="replace")
        seen: set[tuple[str, str]] = set()
        for m in NEVRA_CRYPTO_RX.finditer(text):
            key = (m.group(1), m.group(2))
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_RPM_NEVRA",
                    file=rel,
                    line=1,
                    detail=f"{m.group(1)} {m.group(2)}",
                    provider=m.group(1),
                    version=m.group(2),
                )
            )
    return facts


# ---------- Environment / policy ----------


def probe_env_and_policy(repo: Path) -> list[CryptoFact]:
    """Scan text files for GODEBUG TLS kill-switches, crypto-policy refs,
    and JVM security properties."""
    facts = []
    for f in _rfiles(repo, "*"):
        if not f.is_file() or f.suffix not in TEXT_EXTS:
            continue
        rel = str(f.relative_to(repo))
        if _is_vendor(rel) or f.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for m in GODEBUG_TLS_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_GODEBUG_TLS_KILLSWITCH",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=m.group(0)[:200],
                    provider="go",
                )
            )
        for m in GODEBUG_FIPS_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_FIPS140_GODEBUG",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"GODEBUG fips140={m.group(1)}",
                    provider="go",
                    extra={"fips_mode": m.group(1)},
                )
            )
        for m in GOEXPERIMENT_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_DOCKERFILE_DIRECTIVE",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=f"GOEXPERIMENT={m.group(1)}",
                    provider="container-build",
                    extra={"directive_type": "env", "key": "GOEXPERIMENT", "value": m.group(1)},
                )
            )
        for m in CRYPTO_POLICY_RX.finditer(text):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_POLICY_SET",
                    file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    detail=m.group(0)[:200],
                    provider="crypto-policies",
                )
            )
        if f.name == "java.security" or f.suffix == ".properties":
            for m in JVM_TLS_PROPS_RX.finditer(text):
                facts.append(
                    CryptoFact(
                        probe_id="CRYPTO_JVM_SECURITY_PROPERTY",
                        file=rel,
                        line=text[: m.start()].count("\n") + 1,
                        detail=f"{m.group(1)}={m.group(2)[:150]}",
                        provider="jdk",
                    )
                )
    return facts


# ---------- SBOM ----------


def probe_sbom(sbom_path: Path) -> list[CryptoFact]:
    """Extract crypto-relevant components from a CycloneDX SBOM."""
    doc = json.loads(sbom_path.read_text())
    comps = doc.get("components") or []
    facts = []
    crypto_keywords = (
        "openssl",
        "crypto-policies",
        "gnutls",
        "libssh",
        "nss",
        "bouncycastle",
        "jose",
        "golang.org/x/crypto",
        "pycryptodome",
        "cryptography",
        "ring",
        "rustls",
        "mbedtls",
        "wolfssl",
        "aws-lc",
        "pyopenssl",
        "pynacl",
        "bcrypt",
    )
    for c in comps:
        name = (c.get("name") or "").lower()
        ver = c.get("version") or ""
        if any(k in name for k in crypto_keywords):
            facts.append(
                CryptoFact(
                    probe_id="CRYPTO_SBOM_COMPONENT",
                    file=f"sbom:{c.get('purl') or name}",
                    line=0,
                    detail=f"{c.get('name')} {ver}"[:200],
                    provider=_sbom_provider(name),
                    version=ver,
                )
            )
    return facts


def _sbom_provider(name: str) -> str:
    """Map SBOM component name to a provider key."""
    if "openssl" in name or "libssl" in name:
        return "openssl"
    if "gnutls" in name:
        return "gnutls"
    if "nss" in name:
        return "nss"
    if "rustls" in name:
        return "rustls"
    if "ring" in name or "aws-lc" in name:
        return "aws-lc-rs"
    if "bouncycastle" in name:
        return "bouncycastle"
    if "cryptography" in name or "pyopenssl" in name:
        return "python-openssl"
    return name.split("/")[-1].split("-")[0]


# ---------- Orchestration ----------


def probe_repo(repo: Path) -> list[CryptoFact]:
    """Run all static probes against a repository directory."""
    facts = []
    facts.extend(probe_go(repo))
    facts.extend(probe_dockerfiles(repo))
    facts.extend(probe_node(repo))
    facts.extend(probe_jdk(repo))
    facts.extend(probe_python(repo))
    facts.extend(probe_rust(repo))
    facts.extend(probe_c(repo))
    facts.extend(probe_dotnet(repo))
    facts.extend(probe_ruby(repo))
    facts.extend(probe_rpm_locks(repo))
    facts.extend(probe_env_and_policy(repo))
    return facts
