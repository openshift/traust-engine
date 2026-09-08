#!/usr/bin/env python3
"""Expand an advisory's vulnerable symbol into the library's PUBLIC entry
points — the missing hop that keeps dependency reachability at the
manifest ceiling.

WHY THIS EXISTS (measured 2026-08-11/13, harness v0.264.0). A full
52-advisory Maven sweep promoted 0 of 120 in-range pairs to `affected`
even after every tier defect was fixed. Cause: the first-party CPG holds
only the audited repo's sources, while advisories name the library's
INTERNAL methods. Spring4Shell's symbol
(`CachedIntrospectionResults#introspectInterfaces`) sits THREE hops below
the nearest public API, inside spring-beans — no application calls it
directly, so the call site cannot exist in a first-party graph.

This script closes that hop on the LIBRARY side, once per advisory,
globally reusable:

    advisory -> vulnerable symbol -> library JAR (registry, pinned)
             -> CPG of the library alone -> transitive PUBLIC callers

Measured on Spring4Shell (spring-beans 5.3.17): depth 3 yields 2 public
entry points (`BeanUtils.getPropertyDescriptors`,
`BeanUtils.getPropertyDescriptor`); depth 5 yields 17, including the much
broader `BeanUtils.copyProperties` and reflection-mediated frames
(`findPropertyForMethod(java.lang.reflect.Method)`). Depth is therefore a
PRECISION DIAL, not a constant — the entry-point set widens and weakens
as it grows, which is why `--depth` defaults low and why promotion is
calibration-gated (see below).

PROMOTION IS OFF BY DESIGN (operator decision "d", 2026-08-13). This
script only emits facts. /impact-analysis records an entry-point hit as
`symbol-usage` (ceiling `likely_affected`) with the entry-point evidence
attached, NEVER as `symbol`/`affected`, until a calibration run measures
precision and coverage and an owner turns promotion on. Rationale: the
evidence is a two-step inference — "your code calls X" (solid) plus "X
reaches the vulnerable method inside the library" (a static call graph
over bytecode, with reflection and config-gated paths unmeasured). Same
posture as the B4 taint enumerator: routing weight granted in proportion
to measured agreement, never assumed.

KNOWN LIMIT — CROSS-JAR PATHS. Expansion sees only the artifact it
downloaded. Spring4Shell's canonical entry point (`DataBinder.bind`)
lives in spring-context, a DIFFERENT jar, so single-artifact expansion
cannot reach it. Coverage is therefore partial by construction; the
`coverage_gaps` block says so on every artifact. Adding the library's own
dependencies to the CPG is the obvious extension and is deliberately not
attempted here.

JDK CONSTRAINT. jimple2cpg's bundled Soot/ASM cannot read modern class
files ("Unsupported class file major version 70" on JDK 26). Point
`JIMPLE_JAVA_HOME` at a JDK <= 21 (verified on Temurin 21.0.12+8). The
script validates this up front and skips honestly rather than emitting a
misleading empty result.

Usage:
    python3 -m traust_engine.impact.expand_advisory_entry_points \
        --module org.springframework:spring-beans --version 5.3.17 \
        --symbols 'org.springframework.beans.CachedIntrospectionResults#introspectInterfaces' \
        [--advisory CVE-2022-22965] [--depth 3] [--ecosystem maven] \
        [--cache-dir DIR] [--out FILE]

Exit 0 always writes an artifact: status "ran", "skipped: <reason>", or
"error: <reason>" — the deterministic_steps honesty convention.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

MAVEN_CENTRAL = "https://repo1.maven.org/maven2"
# jimple2cpg ships inside the joern install; joern-parse cannot select it
# for a bare .jar, so it is invoked directly.
JIMPLE_REL = "libexec/jimple2cpg"
MAX_JDK_MAJOR = 21

QUERY_SC = r"""
@main def exec(cpgFile: String, symbolsFile: String, outFile: String,
               maxDepth: Int) = {
  importCpg(cpgFile)
  val targets = scala.io.Source.fromFile(symbolsFile).getLines()
    .filter(_.nonEmpty).toList
  val sb = new StringBuilder
  for (t <- targets) {
    // t is a bare `Class.method` or fully-qualified prefix; match on
    // methodFullName containing it so a caller need not know the exact
    // signature the frontend produced.
    var frontier = cpg.method.filter(_.fullName.contains(t)).l
    sb.append(List("TARGETS", t, frontier.size.toString).mkString("\t")).append("\n")
    var seen = frontier.map(_.fullName).toSet
    var depth = 0
    while (frontier.nonEmpty && depth < maxDepth) {
      depth += 1
      val callers = frontier.flatMap(_.caller)
        .filterNot(m => seen.contains(m.fullName)).dedup.l
      seen = seen ++ callers.map(_.fullName)
      for (c <- callers.filter(_.isPublic.nonEmpty)) {
        sb.append(List("EP", t, depth.toString, c.fullName,
                       c.filename).mkString("\t")).append("\n")
      }
      sb.append(List("DEPTH", t, depth.toString, callers.size.toString)
        .mkString("\t")).append("\n")
      frontier = callers
    }
  }
  val w = new java.io.PrintWriter(outFile)
  w.write(sb.toString); w.close()
}
"""


def emit(out: Path | None, doc: dict) -> int:
    doc.setdefault(
        "soundness",
        {
            "promotion": "OFF by design — an entry-point hit is `symbol-usage` "
            "(ceiling `likely_affected`), never `symbol`/"
            "`affected`, until a calibration run measures "
            "precision/coverage and an owner enables it",
            "two_step_inference": "'first-party code calls the entry point' is "
            "solid; 'the entry point reaches the "
            "vulnerable method' is a static call graph "
            "over library bytecode — reflection and "
            "config-gated paths inside the library are "
            "NOT modelled",
            "depth_is_a_dial": "the entry-point set widens and weakens with "
            "depth (Spring4Shell: 2 at depth 3, 17 at depth "
            "5 incl. reflection frames) — a consumer must "
            "record the depth it used",
            "empty_result": "means UNRESOLVED, never 'no path exists'",
        },
    )
    doc.setdefault(
        "coverage_gaps",
        [
            "CROSS-JAR: only the downloaded artifact is in the CPG, so an entry "
            "point in a sibling artifact is invisible (Spring4Shell's canonical "
            "DataBinder.bind lives in spring-context, not spring-beans)",
            "the library's own transitive dependencies are not analysed",
            "non-maven ecosystems are not implemented (npm/pypi would fetch the "
            "tarball/wheel and use jssrc2cpg/pysrc2cpg)",
        ],
    )
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(
        f"entry-points: {doc['status']} "
        f"({len(doc.get('entry_points') or [])} entry point(s))" + (f" → {out}" if out else "")
    )
    return 0


def jdk_major(java_home: str | None) -> tuple[int | None, str]:
    """(major version, raw) of the JDK that will run jimple2cpg."""
    java = (Path(java_home) / "bin" / "java") if java_home else None
    exe = str(java) if java and java.is_file() else shutil.which("java")
    if not exe:
        return None, "java not found"
    try:
        p = subprocess.run(
            [exe, "-version"], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL
        )
    except (subprocess.SubprocessError, OSError):
        return None, "java -version failed"
    raw = (p.stderr or p.stdout).strip().splitlines()[:1]
    raw = raw[0] if raw else ""
    m = re.search(r'version "?(\d+)', raw)
    return (int(m.group(1)) if m else None), raw


def fetch_maven_jar(module: str, version: str, dest: Path) -> dict:
    """Download group:artifact:version from Maven Central. Returns facts
    (url, sha256, bytes) — the artifact identity a consumer cites."""
    group, _, artifact = module.partition(":")
    url = f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar"
    try:
        with urllib.request.urlopen(url, timeout=180) as fh:
            blob = fh.read()
    except (urllib.error.URLError, OSError) as e:
        return {"error": f"download failed: {type(e).__name__}", "url": url}
    dest.write_bytes(blob)
    return {"url": url, "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}


def build_cpg(jar: Path, cpg: Path, java_home: str | None, timeout: int) -> str | None:
    """Build a CPG of the jar via jimple2cpg. Returns an error string or
    None. Cached by the caller — a CPG is per artifact@version, never per
    advisory or per repo."""
    joern = shutil.which("joern")
    if not joern:
        return "joern not on PATH"
    jimple = Path(joern).resolve().parent.parent / JIMPLE_REL
    if not jimple.is_file():
        # brew layout: .../Cellar/joern/<ver>/libexec/jimple2cpg
        cand = list(Path(joern).resolve().parent.parent.glob("**/jimple2cpg"))
        if not cand:
            return "jimple2cpg not found in the joern install"
        jimple = cand[0]
    env = {**os.environ}
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"
    try:
        p = subprocess.run(
            [str(jimple), str(jar), "--output", str(cpg)],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.SubprocessError as e:
        return f"jimple2cpg {type(e).__name__}"
    if not cpg.is_file():
        tail = (p.stderr or p.stdout or "").strip()[-300:]
        return f"jimple2cpg produced no CPG: {tail}"
    return None


def query_entry_points(
    cpg: Path, symbols: list[str], depth: int, workdir: Path, java_home: str | None, timeout: int
) -> tuple[list[dict], dict, str | None]:
    joern = shutil.which("joern")
    script = workdir / "ep.sc"
    script.write_text(QUERY_SC, encoding="utf-8")
    symfile = workdir / "targets.txt"
    # the CPG holds Class.method shapes; accept `Class#method` input
    symfile.write_text("\n".join(s.replace("#", ".") for s in symbols) + "\n", encoding="utf-8")
    tsv = workdir / "ep.tsv"
    env = {**os.environ}
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"
    try:
        p = subprocess.run(
            [
                joern,
                "--script",
                str(script),
                "--param",
                f"cpgFile={cpg}",
                "--param",
                f"symbolsFile={symfile}",
                "--param",
                f"outFile={tsv}",
                "--param",
                f"maxDepth={depth}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=str(workdir),
        )
    except subprocess.SubprocessError as e:
        return [], {}, f"joern query {type(e).__name__}"
    if not tsv.is_file():
        return [], {}, ("joern query failed: " + (p.stderr or p.stdout or "").strip()[-300:])
    eps: list[dict] = []
    stats: dict = {"targets_matched": {}, "callers_per_depth": {}}
    seen = set()
    for row in tsv.read_text(encoding="utf-8").splitlines():
        parts = row.split("\t")
        if parts[0] == "TARGETS" and len(parts) == 3:
            stats["targets_matched"][parts[1]] = int(parts[2])
        elif parts[0] == "DEPTH" and len(parts) == 4:
            stats["callers_per_depth"].setdefault(parts[1], {})[parts[2]] = int(parts[3])
        elif parts[0] == "EP" and len(parts) == 5:
            _, target, d, full, fname = parts
            if full in seen:
                continue
            seen.add(full)
            eps.append({"entry_point": full, "depth": int(d), "from_symbol": target, "file": fname})
    eps.sort(key=lambda e: (e["depth"], e["entry_point"]))
    return eps, stats, None


def expand_entry_points(
    module: str,
    version: str,
    symbols: list[str],
    *,
    advisory: str | None = None,
    ecosystem: str = "maven",
    depth: int = 3,
    cache_dir: Path | None = None,
    java_home: str | None = None,
    timeout: int = 1800,
    out: Path | None = None,
) -> int:
    cache_dir = cache_dir or Path(
        os.environ.get("TRAUST_CPG_CACHE", str(Path.home() / ".cache" / "traust-library-cpg"))
    )
    java_home = java_home if java_home is not None else os.environ.get("JIMPLE_JAVA_HOME")

    joern_ver = "unknown"
    joern = shutil.which("joern")
    if joern:
        cellar = re.search(r"/joern/([0-9.]+)/", str(Path(joern).resolve()))
        if cellar:
            joern_ver = cellar.group(1)

    base = {
        "artifact": "advisory-entry-points",
        "tool": "expand_advisory_entry_points.py",
        "advisory": advisory,
        "module": module,
        "library_version": version,
        "ecosystem": ecosystem,
        "vulnerable_symbols": symbols,
        "depth_bound": depth,
        "joern_version": joern_ver,
        "promotion": "disabled (calibration-gated; operator decision 'd', 2026-08-13)",
    }

    major, raw = jdk_major(java_home)
    base["jdk"] = raw
    if major is None:
        return emit(out, {**base, "status": "skipped: no usable JDK", "entry_points": []})
    if major > MAX_JDK_MAJOR:
        return emit(
            out,
            {
                **base,
                "status": f"skipped: jimple2cpg cannot read class files from "
                f"JDK {major} (max {MAX_JDK_MAJOR}) — set "
                f"JIMPLE_JAVA_HOME to a JDK <= {MAX_JDK_MAJOR}",
                "entry_points": [],
            },
        )
    if not joern:
        return emit(out, {**base, "status": "skipped: joern not on PATH", "entry_points": []})

    cache = cache_dir
    cache.mkdir(parents=True, exist_ok=True)
    slug = module.replace(":", "_").replace(".", "_") + "-" + version + "-joern" + joern_ver
    cpg = cache / f"{slug}.cpg.bin"
    jar = cache / f"{slug}.jar"

    if not cpg.is_file():
        if not jar.is_file():
            fetched = fetch_maven_jar(module, version, jar)
            if "error" in fetched:
                return emit(
                    out,
                    {
                        **base,
                        "status": f"error: {fetched['error']}",
                        "library_artifact": fetched,
                        "entry_points": [],
                    },
                )
            base["library_artifact"] = fetched
        err = build_cpg(jar, cpg, java_home, timeout)
        if err:
            return emit(out, {**base, "status": f"error: {err}", "entry_points": []})
        base["cpg_cache"] = "built"
    else:
        base["cpg_cache"] = "hit"
    base["cpg_path"] = str(cpg)

    eps, stats, err = query_entry_points(cpg, symbols, depth, cache, java_home, timeout)
    if err:
        return emit(out, {**base, "status": f"error: {err}", "entry_points": []})
    if not any(stats.get("targets_matched", {}).values()):
        return emit(
            out,
            {
                **base,
                "status": "ran: vulnerable symbol not found in the library CPG "
                "(wrong artifact, or the symbol is in a sibling jar)",
                "expansion": stats,
                "entry_points": [],
            },
        )
    return emit(out, {**base, "status": "ran", "expansion": stats, "entry_points": eps})
