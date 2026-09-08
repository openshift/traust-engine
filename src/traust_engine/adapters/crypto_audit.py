# DESIGN: This tool collects raw crypto-relevant data. It never interprets
# whether data is "good", "bad", "PQC-capable", or "compliant". Consumer
# skills (pqc-readiness, compliance-check, etc.) own all interpretation.
# If you're adding a pattern/threshold/classification here, it belongs in a skill.
"""crypto_audit.py — Unopinionated crypto data collector.

Three tiers of structural data extraction:

    source   — repository/build-time provider census (crypto_probe.py)
    image    — container image structural data (libs, packages, certs, policy)
    cluster  — runtime state via oc exec (TLS negotiation, crypto-policy)

All subcommands emit crypto-audit/v1 JSON with a ``tier`` field.

Usage:
    crypto_audit.py source /path/to/repo [--component NAME] [--output facts.json]
    crypto_audit.py image registry.example.com/app:tag [--no-pull] [-o facts.json]
    crypto_audit.py cluster --context ctx [--namespaces ns1 ns2] [--discover]
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_engine._util.elf import ElfAnalyzer
from traust_engine.adapters import crypto_probe

SCHEMA = "crypto-audit/v1"

_TLS_CONNECT_TIMEOUT = 3


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _summary(facts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total_facts": len(facts),
        "probe_ids": sorted({f["probe_id"] for f in facts}),
        "providers": sorted({f["provider"] for f in facts}),
    }


def build_output(
    *,
    tier: str,
    target: str,
    facts: list[dict[str, Any]],
    errors: list[str],
    component: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "tier": tier,
        "target": target,
        "timestamp": _utc_now(),
        "metadata": metadata or {},
        "facts": facts,
        "errors": errors,
        "summary": _summary(facts),
    }
    if component:
        out["component"] = component
    return out


def _write_output(payload: dict[str, Any], output_path: str, quiet: bool) -> None:
    text = json.dumps(payload, indent=2)
    if output_path:
        Path(output_path).write_text(text)
        if not quiet:
            print(f"[crypto-audit] written to {output_path}", file=sys.stderr)
    else:
        print(text)


# ---------------------------------------------------------------------------
# Container runtime (minimal)
# ---------------------------------------------------------------------------


class ContainerRuntime:
    def __init__(self, runtime: str = "auto", platform: str = "") -> None:
        if runtime == "auto" or not runtime:
            self.runtime = self._detect()
        else:
            self.runtime = runtime
        if not self.runtime:
            raise RuntimeError("Neither podman nor docker found in PATH")
        self.platform = platform

    @staticmethod
    def _detect() -> str:
        for rt in ("podman", "docker"):
            if shutil.which(rt):
                return rt
        return ""

    def _cmd(self) -> list[str]:
        return [self.runtime]

    def _plat(self) -> list[str]:
        return ["--platform", self.platform] if self.platform else []

    @staticmethod
    def _run(cmd, *, timeout=120, **kw) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)

    def pull(self, image: str, *, timeout=300) -> bool:
        return (
            self._run([*self._cmd(), "pull", *self._plat(), image], timeout=timeout).returncode == 0
        )

    def create(self, image: str) -> str:
        r = self._run([*self._cmd(), "create", *self._plat(), image, "/bin/true"])
        if r.returncode != 0:
            raise RuntimeError(f"create failed: {r.stderr.strip()}")
        return r.stdout.strip()[:64]

    def cp_out(self, cid: str, src: str, dst: str) -> bool:
        return self._run([*self._cmd(), "cp", f"{cid}:{src}", dst]).returncode == 0

    def inspect(self, image: str):
        r = self._run([*self._cmd(), "inspect", image, "--format", "json"])
        if r.returncode != 0:
            return None
        try:
            data = json.loads(r.stdout)
            return data[0] if isinstance(data, list) else data
        except (json.JSONDecodeError, IndexError):
            return None

    def run_cmd(self, image: str, cmd: list[str], *, entrypoint: str | None = None, timeout=30):
        c = [*self._cmd(), "run", "--rm", *self._plat()]
        if entrypoint:
            c += ["--entrypoint", entrypoint]
        c.append(image)
        return self._run(c + cmd, timeout=timeout)

    def remove(self, cid: str) -> None:
        self._run([*self._cmd(), "rm", "-f", cid], timeout=30)


# ---------------------------------------------------------------------------
# Source tier
# ---------------------------------------------------------------------------


def _source_fact_to_dict(fact: crypto_probe.CryptoFact) -> dict[str, Any]:
    source = fact.file if fact.line <= 0 else f"{fact.file}:{fact.line}"
    row: dict[str, Any] = {
        "probe_id": fact.probe_id,
        "detail": fact.detail,
        "provider": fact.provider,
        "source": source,
    }
    if fact.version:
        row["version"] = fact.version
    extra = dict(fact.extra) if fact.extra else {}
    if fact.line > 0:
        extra.update(file=fact.file, line=fact.line)
    if extra:
        row["extra"] = extra
    return row


def run_source(
    repo_path: Path,
    *,
    sbom_path: Path | None = None,
    component: str = "",
) -> dict[str, Any]:
    facts = crypto_probe.probe_repo(repo_path)
    if sbom_path:
        facts.extend(crypto_probe.probe_sbom(sbom_path))
    fact_dicts = [_source_fact_to_dict(f) for f in facts]
    metadata: dict[str, Any] = {"repo_dir": str(repo_path)}
    if sbom_path:
        metadata["sbom"] = str(sbom_path)
    return build_output(
        tier="source",
        target=str(repo_path),
        facts=fact_dicts,
        errors=[],
        component=component,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Image tier — structural data only
# ---------------------------------------------------------------------------


def _collect_image_metadata(rt: ContainerRuntime, image: str) -> tuple[list[dict], dict]:
    """Collect env vars, labels, architecture from image inspect."""
    facts: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    data = rt.inspect(image)
    if not data:
        return facts, metadata

    config = data.get("Config") or data.get("config") or {}
    labels = config.get("Labels") or {}
    env_list = config.get("Env") or []
    entrypoint = config.get("Entrypoint") or []

    metadata["architecture"] = data.get("Architecture") or data.get("architecture") or "unknown"
    metadata["os"] = data.get("Os") or data.get("os") or "unknown"
    metadata["entrypoint"] = entrypoint
    metadata["labels"] = labels

    for env_entry in env_list:
        facts.append(
            {
                "probe_id": "IMG_ENV",
                "detail": env_entry[:200],
                "provider": "image-metadata",
                "source": "image inspect env",
                "extra": {"env": env_entry},
            }
        )

    for key, val in labels.items():
        facts.append(
            {
                "probe_id": "IMG_LABEL",
                "detail": f"{key}={val}"[:200],
                "provider": "image-metadata",
                "source": "image inspect labels",
                "extra": {"key": key, "value": val},
            }
        )

    return facts, metadata


def _collect_linked_libs(rt: ContainerRuntime, cid: str, tmpdir: str) -> list[dict]:
    """Extract ELF binaries and report their linked libraries."""
    facts: list[dict[str, Any]] = []
    bin_dirs = ["usr/bin", "usr/sbin", "usr/local/bin", "bin", "sbin"]
    dst_base = Path(tmpdir) / "bins"
    dst_base.mkdir(parents=True, exist_ok=True)

    for d in bin_dirs:
        dst = dst_base / d
        dst.mkdir(parents=True, exist_ok=True)
        rt.cp_out(cid, f"/{d}/.", str(dst))

    for bin_path in sorted(dst_base.rglob("*")):
        if not bin_path.is_file() or bin_path.stat().st_size < 10_000:
            continue
        try:
            data = bin_path.read_bytes()
        except OSError:
            continue
        if not ElfAnalyzer.is_elf(data):
            continue
        libs = ElfAnalyzer.linked_libraries_from_bytes(data)
        if libs:
            lib_names = [lib.name for lib in libs]
            rel = bin_path.relative_to(dst_base)
            facts.append(
                {
                    "probe_id": "IMG_LINKED_LIBS",
                    "detail": ", ".join(lib_names)[:200],
                    "provider": "elf",
                    "source": f"/{rel}",
                    "extra": {"binary": f"/{rel}", "libs": lib_names},
                }
            )
    return facts


def _collect_packages(rt: ContainerRuntime, image: str) -> list[dict]:
    """Get installed package list via rpm/dpkg/apk."""
    facts: list[dict[str, Any]] = []

    r = rt.run_cmd(
        image,
        ["-qa", "--queryformat", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n"],
        entrypoint="rpm",
        timeout=30,
    )
    if r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.splitlines():
            line = line.strip()
            if line:
                facts.append(
                    {
                        "probe_id": "IMG_PACKAGES",
                        "detail": line[:200],
                        "provider": "rpm",
                        "source": "rpm -qa",
                        "extra": {"format": "rpm", "nevra": line},
                    }
                )
        return facts

    r = rt.run_cmd(
        image,
        ["-W", "-f", "${Package} ${Version}\\n"],
        entrypoint="dpkg-query",
        timeout=30,
    )
    if r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.splitlines():
            line = line.strip()
            if line:
                facts.append(
                    {
                        "probe_id": "IMG_PACKAGES",
                        "detail": line[:200],
                        "provider": "dpkg",
                        "source": "dpkg-query",
                        "extra": {"format": "deb"},
                    }
                )
        return facts

    r = rt.run_cmd(image, ["list", "--installed"], entrypoint="apk", timeout=30)
    if r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.splitlines():
            line = line.strip()
            if line:
                facts.append(
                    {
                        "probe_id": "IMG_PACKAGES",
                        "detail": line[:200],
                        "provider": "apk",
                        "source": "apk list",
                        "extra": {"format": "apk"},
                    }
                )
    return facts


def _collect_certs(rt: ContainerRuntime, cid: str, tmpdir: str) -> list[dict]:
    """List certificate files from /etc/pki and /etc/ssl."""
    facts: list[dict[str, Any]] = []
    cert_dst = Path(tmpdir) / "certs"
    cert_dst.mkdir(parents=True, exist_ok=True)

    for src_dir in ("/etc/pki", "/etc/ssl/certs"):
        rt.cp_out(cid, src_dir, str(cert_dst / src_dir.lstrip("/")))

    for cert_file in sorted(cert_dst.rglob("*")):
        if cert_file.is_file() and cert_file.suffix.lower() in (
            ".pem",
            ".crt",
            ".cert",
            ".key",
        ):
            rel = cert_file.relative_to(cert_dst)
            facts.append(
                {
                    "probe_id": "IMG_CERT_FILES",
                    "detail": f"/{rel}",
                    "provider": "filesystem",
                    "source": "cp /etc/pki + /etc/ssl",
                    "extra": {"path": f"/{rel}", "size": cert_file.stat().st_size},
                }
            )
    return facts


def _collect_crypto_files(rt: ContainerRuntime, cid: str, tmpdir: str) -> list[dict]:
    """Check for crypto-policy and FIPS indicator files."""
    facts: list[dict[str, Any]] = []
    policy_dst = Path(tmpdir) / "crypto-policies"
    policy_dst.mkdir(parents=True, exist_ok=True)

    if rt.cp_out(cid, "/etc/crypto-policies/state/current", str(policy_dst / "current")):
        current = (policy_dst / "current").read_text(errors="replace").strip()
        if current:
            facts.append(
                {
                    "probe_id": "IMG_CRYPTO_POLICY",
                    "detail": current,
                    "provider": "crypto-policies",
                    "source": "/etc/crypto-policies/state/current",
                    "extra": {"policy": current},
                }
            )

    fips_dst = Path(tmpdir) / "fips"
    fips_dst.mkdir(parents=True, exist_ok=True)
    if rt.cp_out(cid, "/etc/system-fips", str(fips_dst / "system-fips")):
        facts.append(
            {
                "probe_id": "IMG_FIPS_MARKER",
                "detail": "/etc/system-fips present",
                "provider": "fips",
                "source": "/etc/system-fips",
            }
        )

    for fips_path in (
        "/usr/lib64/ossl-modules/fips.so",
        "/usr/lib/ossl-modules/fips.so",
    ):
        check_dst = fips_dst / Path(fips_path).name
        if rt.cp_out(cid, fips_path, str(check_dst)):
            facts.append(
                {
                    "probe_id": "IMG_FIPS_MODULE",
                    "detail": f"FIPS module at {fips_path}",
                    "provider": "openssl-fips",
                    "source": fips_path,
                }
            )
            break

    return facts


def run_image(
    image: str,
    *,
    runtime: str = "",
    platform: str = "",
    no_pull: bool = False,
    component: str = "",
) -> dict[str, Any]:
    errors: list[str] = []
    facts: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"image": image}
    tmpdir = tempfile.mkdtemp(prefix="crypto-audit-image-")

    try:
        rt = ContainerRuntime(runtime=runtime or "auto", platform=platform)
    except RuntimeError as e:
        errors.append(str(e))
        return build_output(
            tier="binary",
            target=image,
            facts=facts,
            errors=errors,
            component=component,
            metadata=metadata,
        )

    try:
        if not no_pull and not rt.pull(image):
            errors.append("pull failed")
            return build_output(
                tier="binary",
                target=image,
                facts=facts,
                errors=errors,
                component=component,
                metadata=metadata,
            )

        meta_facts, img_meta = _collect_image_metadata(rt, image)
        facts.extend(meta_facts)
        metadata.update(img_meta)

        cid = rt.create(image)
        metadata["container_id"] = cid[:12]

        try:
            facts.extend(_collect_linked_libs(rt, cid, tmpdir))
            facts.extend(_collect_packages(rt, image))
            facts.extend(_collect_certs(rt, cid, tmpdir))
            facts.extend(_collect_crypto_files(rt, cid, tmpdir))
        finally:
            rt.remove(cid)

    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return build_output(
        tier="binary",
        target=image,
        facts=facts,
        errors=errors,
        component=component,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Cluster tier — raw TLS + system state collection
# ---------------------------------------------------------------------------


def _oc_cmd(context: str, args: list[str]) -> list[str]:
    cmd = ["oc"]
    if context:
        cmd += ["--context", context]
    cmd += args
    return cmd


def _run_oc(
    context: str, args: list[str], *, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(_oc_cmd(context, args), capture_output=True, text=True, timeout=timeout)


def _oc_exec(context: str, namespace: str, pod: str, shell_cmd: str, *, timeout: int = 30):
    r = _run_oc(
        context,
        ["exec", "-n", namespace, pod, "--", "sh", "-c", shell_cmd],
        timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def _find_apiserver_pod(context: str) -> tuple[str, str] | None:
    for ns in ("openshift-kube-apiserver", "kube-system"):
        r = _run_oc(
            context,
            [
                "get",
                "pods",
                "-n",
                ns,
                "-o",
                'jsonpath={range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\\n"}{end}',
            ],
            timeout=30,
        )
        if r.returncode == 0:
            for pod in r.stdout.splitlines():
                pod = pod.strip()
                if pod and ("apiserver" in pod or "guard" in pod):
                    return ns, pod
    return None


def _list_running_pods(context: str, namespace: str) -> list[str]:
    r = _run_oc(
        context,
        [
            "get",
            "pods",
            "-n",
            namespace,
            "-o",
            'jsonpath={range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\\n"}{end}',
        ],
        timeout=30,
    )
    if r.returncode != 0:
        return []
    return [p.strip() for p in r.stdout.splitlines() if p.strip()]


def _parse_tls_output(raw: str) -> dict[str, Any]:
    """Parse full openssl s_client output into structured negotiation data."""
    result: dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Protocol") and ":" in line:
            result["protocol"] = line.split(":", 1)[-1].strip()
        elif line.startswith("Ciphersuite"):
            result["ciphersuite"] = line.split(":", 1)[-1].strip()
        elif "Cipher is" in line:
            result.setdefault("ciphersuite", line.split("Cipher is")[-1].strip())
        elif line.startswith("Cipher") and ":" in line and "is" not in line.lower():
            result.setdefault("ciphersuite", line.split(":", 1)[-1].strip())
        elif "Negotiated TLS1.3 group" in line:
            result["key_exchange_group"] = line.split(":", 1)[-1].strip()
        elif line.startswith(("Server Temp Key", "Peer Temp Key")):
            result.setdefault("key_exchange_group", line.split(":", 1)[-1].strip())
        elif "Peer signature type" in line or line.startswith("Signature type"):
            result["peer_signature_type"] = line.split(":", 1)[-1].strip()
        elif "Peer signing digest" in line or line.startswith("Hash used"):
            result["peer_signature_digest"] = line.split(":", 1)[-1].strip()
        elif "Server public key is" in line:
            m = re.search(r"(\d+)\s*bit", line)
            if m:
                result["server_cert_key_bits"] = int(m.group(1))
        elif line.startswith("subject="):
            result["server_cert_subject"] = line.split("=", 1)[-1].strip()[:200]
        elif line.startswith("issuer="):
            result["server_cert_issuer"] = line.split("=", 1)[-1].strip()[:200]
        elif "ALPN protocol" in line:
            result["alpn"] = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif "New," in line and "Cipher is" in line:
            result.setdefault("protocol", line.split(",")[0].replace("New", "").strip())
    return result


def _tls_probe(
    context: str,
    ns: str,
    pod: str,
    host: str,
    port: int,
    *,
    groups: str = "",
    timeout: int = _TLS_CONNECT_TIMEOUT,
) -> dict[str, Any] | None:
    cmd = f"echo | timeout {timeout} openssl s_client -connect {host}:{port}"
    if groups:
        cmd += f" -groups {groups}"
    cmd += " 2>&1"
    rc, out, _ = _oc_exec(context, ns, pod, cmd, timeout=timeout + 10)
    if rc != 0 and not out.strip():
        return None
    parsed = _parse_tls_output(out)
    if not parsed.get("protocol") and not parsed.get("ciphersuite"):
        return None
    return parsed


def _classify_port(port_name: str, port_number: int) -> str:
    name_lower = (port_name or "").lower()
    if any(kw in name_lower for kw in ("metrics", "health", "readiness")):
        return "observability"
    if any(kw in name_lower for kw in ("https", "tls", "secure")):
        return "service"
    if port_number in (443, 8443, 6443, 9093):
        return "service"
    return "unknown"


def _discover_services(context: str, namespace: str, errors: list[str]) -> list[dict[str, Any]]:
    r = _run_oc(context, ["get", "svc", "-n", namespace, "-o", "json"], timeout=30)
    if r.returncode != 0:
        errors.append(f"oc get svc -n {namespace} failed: {r.stderr.strip()[:200]}")
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        errors.append(f"svc JSON parse error in {namespace}: {e}")
        return []

    endpoints: list[dict[str, Any]] = []
    for item in data.get("items", []):
        spec = item.get("spec", {})
        svc_name = item.get("metadata", {}).get("name", "")
        cluster_ip = spec.get("clusterIP", "")
        if not cluster_ip or cluster_ip == "None":
            continue
        for port_entry in spec.get("ports", []):
            port_num = port_entry.get("port")
            port_name = port_entry.get("name", "")
            if not port_num:
                continue
            endpoints.append(
                {
                    "service": svc_name,
                    "namespace": namespace,
                    "host": f"{svc_name}.{namespace}.svc",
                    "port": port_num,
                    "port_name": port_name,
                    "port_class": _classify_port(port_name, port_num),
                }
            )
    return endpoints


def _probe_pod_crypto(
    context: str,
    namespace: str,
    pod: str,
    errors: list[str],
) -> list[dict[str, Any]]:
    """Collect crypto-policy, openssl version, go version from a pod."""
    facts: list[dict[str, Any]] = []
    source_prefix = f"{namespace}/{pod}"

    policy_cmd = (
        "cat /etc/crypto-policies/state/current 2>/dev/null; "
        "echo '---'; "
        "cat /proc/sys/crypto/fips_enabled 2>/dev/null; "
        "echo '---'; "
        "openssl version 2>/dev/null"
    )
    rc, out, _ = _oc_exec(context, namespace, pod, policy_cmd)
    if rc == 0 and out.strip():
        parts = out.split("---")
        policy = parts[0].strip() if len(parts) > 0 else ""
        fips = parts[1].strip() if len(parts) > 1 else ""
        openssl_ver = parts[2].strip() if len(parts) > 2 else ""

        if policy:
            facts.append(
                {
                    "probe_id": "CLUSTER_CRYPTO_POLICY",
                    "detail": policy,
                    "provider": "crypto-policies",
                    "source": source_prefix,
                    "extra": {
                        "namespace": namespace,
                        "pod": pod,
                        "policy": policy,
                        "fips_enabled": fips == "1",
                    },
                }
            )
        if openssl_ver:
            ver_m = re.search(r"(OpenSSL|LibreSSL|BoringSSL)\s+([\d.]+\S*)", openssl_ver, re.I)
            facts.append(
                {
                    "probe_id": "CLUSTER_OPENSSL_VERSION",
                    "detail": openssl_ver[:200],
                    "provider": "openssl",
                    "source": source_prefix,
                    "version": ver_m.group(2) if ver_m else None,
                    "extra": {"namespace": namespace, "pod": pod},
                }
            )

    go_cmd = (
        "go version /proc/1/exe 2>/dev/null || "
        "strings -n 12 /proc/1/exe 2>/dev/null | grep -m1 '^go1\\.' || true"
    )
    rc, out, _ = _oc_exec(context, namespace, pod, go_cmd)
    if rc == 0 and out.strip():
        go_m = re.search(r"go(1\.\d+(?:\.\d+)?)", out)
        if go_m:
            facts.append(
                {
                    "probe_id": "CLUSTER_GO_VERSION",
                    "detail": out.strip()[:200],
                    "provider": "go",
                    "source": source_prefix,
                    "version": go_m.group(1),
                    "extra": {"namespace": namespace, "pod": pod},
                }
            )

    return facts


def run_cluster(
    context: str,
    namespaces: list[str],
    *,
    component: str = "",
    discover: bool = False,
    groups: str = "",
) -> dict[str, Any]:
    errors: list[str] = []
    facts: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"context": context, "namespaces": namespaces}

    if not shutil.which("oc"):
        errors.append("oc not found in PATH")
        return build_output(
            tier="runtime",
            target=context,
            facts=facts,
            errors=errors,
            component=component,
            metadata=metadata,
        )

    apiserver = _find_apiserver_pod(context)

    if discover:
        metadata["mode"] = "discover"
        discovery_meta: dict[str, Any] = {"namespaces": {}}
        for namespace in namespaces:
            endpoints = _discover_services(context, namespace, errors)
            ns_meta = {
                "services_enumerated": len({e["service"] for e in endpoints}),
                "endpoints_total": len(endpoints),
                "tls_endpoints": 0,
                "plaintext_endpoints": 0,
            }

            exec_pod = None
            pods = _list_running_pods(context, namespace)
            if pods:
                exec_pod = (namespace, pods[0])
            elif apiserver:
                exec_pod = apiserver
            if not exec_pod:
                errors.append(f"no exec pod for namespace {namespace}")
                discovery_meta["namespaces"][namespace] = ns_meta
                continue

            for ep in endpoints:
                negotiation = _tls_probe(
                    context,
                    exec_pod[0],
                    exec_pod[1],
                    ep["host"],
                    ep["port"],
                    groups=groups,
                )
                if not negotiation:
                    ns_meta["plaintext_endpoints"] += 1
                    continue
                ns_meta["tls_endpoints"] += 1
                detail = (
                    f"{ep['host']}:{ep['port']} "
                    f"{negotiation.get('protocol', '?')} "
                    f"{negotiation.get('ciphersuite', '?')} "
                    f"{negotiation.get('key_exchange_group', '?')}"
                )
                facts.append(
                    {
                        "probe_id": "CLUSTER_TLS_NEGOTIATION",
                        "detail": detail[:200],
                        "provider": "tls",
                        "source": f"oc exec {exec_pod[1]} -> {ep['host']}:{ep['port']}",
                        "extra": {
                            "service": ep["service"],
                            "namespace": ep["namespace"],
                            "host": ep["host"],
                            "port": ep["port"],
                            "port_name": ep["port_name"],
                            "port_class": ep["port_class"],
                            "negotiation": negotiation,
                        },
                    }
                )

            discovery_meta["namespaces"][namespace] = ns_meta
        metadata["discovery"] = discovery_meta

    else:
        metadata["mode"] = "default"
        if apiserver:
            ns, pod = apiserver
            default_targets = [
                ("kubernetes.default.svc", 443, "kubernetes-api"),
                ("oauth-openshift.openshift-authentication.svc", 443, "oauth"),
                ("etcd-client.openshift-etcd.svc", 2379, "etcd"),
                ("image-registry.openshift-image-registry.svc", 5000, "image-registry"),
            ]
            for host, port, service in default_targets:
                negotiation = _tls_probe(context, ns, pod, host, port, groups=groups)
                if not negotiation:
                    errors.append(f"TLS probe failed for {host}:{port}")
                    continue
                detail = (
                    f"{host}:{port} "
                    f"{negotiation.get('protocol', '?')} "
                    f"{negotiation.get('ciphersuite', '?')} "
                    f"{negotiation.get('key_exchange_group', '?')}"
                )
                facts.append(
                    {
                        "probe_id": "CLUSTER_TLS_NEGOTIATION",
                        "detail": detail[:200],
                        "provider": "tls",
                        "source": f"oc exec {pod} -> {host}:{port}",
                        "extra": {
                            "service": service,
                            "namespace": host.split(".")[1] if "." in host else "",
                            "host": host,
                            "port": port,
                            "port_name": "",
                            "port_class": _classify_port("", port),
                            "negotiation": negotiation,
                        },
                    }
                )
        else:
            errors.append("no running kube-apiserver pod found")

    for namespace in namespaces:
        pods = _list_running_pods(context, namespace)
        if not pods:
            errors.append(f"no running pods in namespace {namespace}")
            continue
        facts.extend(_probe_pod_crypto(context, namespace, pods[0], errors))

    return build_output(
        tier="runtime",
        target=context,
        facts=facts,
        errors=errors,
        component=component,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Typed dispatch (app owns CLI)
# ---------------------------------------------------------------------------


def audit_source(
    path: Path | str,
    *,
    from_sbom: Path | str | None = None,
    component: str = "",
    output: Path | str | None = None,
    quiet: bool = False,
) -> int:
    repo = Path(path).resolve()
    if not repo.is_dir():
        print(f"error: not a directory: {repo}", file=sys.stderr)
        return 1
    sbom = Path(from_sbom).resolve() if from_sbom else None
    if sbom and not sbom.is_file():
        print(f"error: SBOM not found: {sbom}", file=sys.stderr)
        return 1
    if not quiet:
        print(f"[crypto-audit] source tier: {repo}", file=sys.stderr)
    payload = run_source(repo, sbom_path=sbom, component=component)
    if not quiet:
        print(
            f"[crypto-audit] {payload['summary']['total_facts']} facts, "
            f"{len(payload['errors'])} errors",
            file=sys.stderr,
        )
    _write_output(payload, str(output) if output else "", quiet)
    return 0


def audit_image(
    image: str,
    *,
    runtime: str = "",
    platform: str = "",
    no_pull: bool = False,
    component: str = "",
    output: Path | str | None = None,
    quiet: bool = False,
) -> int:
    if not quiet:
        print(f"[crypto-audit] image tier: {image}", file=sys.stderr)
    payload = run_image(
        image,
        runtime=runtime,
        platform=platform,
        no_pull=no_pull,
        component=component,
    )
    if not quiet:
        print(
            f"[crypto-audit] {payload['summary']['total_facts']} facts, "
            f"{len(payload['errors'])} errors",
            file=sys.stderr,
        )
    _write_output(payload, str(output) if output else "", quiet)
    return 0


def audit_cluster(
    context: str,
    namespaces: list[str],
    *,
    targets: Path | str,
    discover: bool = False,
    groups: str = "",
    component: str = "",
    output: Path | str | None = None,
    quiet: bool = False,
) -> int:
    if not targets:
        raise ValueError("targets file is required for cluster audit")

    import datetime as _dt

    from traust_engine.validation.scope import Action as _Action
    from traust_engine.validation.scope import Scope as _Scope

    scope = _Scope.from_targets_file(Path(targets))

    audit_path = (Path(output).parent if output else Path.cwd()) / "crypto-audit-scope.jsonl"
    allowed, denied = [], []
    for ns in namespaces:
        ok, reason = scope.is_in_scope(
            _Action(adapter="k8s", verb="exec", context=context, namespace=ns)
        )
        with audit_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "ts": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "action": f"k8s/exec ctx={context} ns={ns}",
                        "scope_allowed": ok,
                        "scope_reason": reason,
                    }
                )
                + "\n"
            )
        (allowed if ok else denied).append((ns, reason))
    if denied and not quiet:
        for ns, reason in denied:
            print(f"[crypto-audit] SCOPE DENIED ns={ns}: {reason}", file=sys.stderr)
    if not allowed:
        print(
            "[crypto-audit] no in-scope namespaces — nothing to probe (fail-closed)",
            file=sys.stderr,
        )
        payload = {
            "schema": "crypto-audit/v1",
            "tier": "runtime",
            "component": component or "",
            "facts": [],
            "errors": [f"scope denied: {ns} — {r}" for ns, r in denied],
            "summary": {"total_facts": 0},
        }
    else:
        if not quiet:
            print(
                f"[crypto-audit] cluster tier: "
                f"context={context} "
                f"namespaces={','.join(ns for ns, _ in allowed)} "
                f"mode={'discover' if discover else 'default'}",
                file=sys.stderr,
            )
        payload = run_cluster(
            context,
            [ns for ns, _ in allowed],
            component=component,
            discover=discover,
            groups=groups,
        )
        payload.setdefault("errors", []).extend(f"scope denied: {ns} — {r}" for ns, r in denied)

    if not quiet:
        print(
            f"[crypto-audit] {payload['summary']['total_facts']} facts, "
            f"{len(payload['errors'])} errors",
            file=sys.stderr,
        )
    _write_output(payload, str(output) if output else "", quiet)
    return 0
