"""safe_exec — validate and run target-derived commands without a shell.

Two jobs:

  1. VALIDATE an argv or a PoC-derived command string against a named
     profile (config/safe-exec-profiles.yaml — policy as data).
  2. RUN the validated command — single argv or an allowlisted pipeline —
     via subprocess chaining with a scrubbed environment. No shell is
     ever involved, so shell metacharacters have no interpreter.

Deny layers (validation order):
  raw-pattern denies (string form)   → substitution, expansion, /dev/tcp
  shell operators (string form)      → only `|` permitted, as a pipeline
  hard-deny binaries                 → never grantable by any profile
  shells                             → never grantable (pipelines are
                                       executed natively, no shell needed)
  profile allowlist                  → basename (or explicit ./path head)
  git hardening (when git is allowed)→ network subcommands denied;
                                       dangerous -c/--config-env keys denied
  protected env assignments          → PATH/LD_PRELOAD/GIT_SSH_COMMAND/…
  recursion cap                      → safe_exec cannot re-enter itself

Modes: the library tells the truth unconditionally; enforcement policy
belongs to the caller. The CLI honors SAFE_EXEC_MODE=warn|enforce
(default enforce) — warn reports the verdict and exits 0 so batch lanes
can calibrate. SAFE_EXEC_DISABLED=<reason> bypasses `run` but shouts to
stderr and appends to a per-user 0700 bypass log — never silent, and
library callers (validate-findings adapters) do not honor it.

Usage:
  safe_exec.py check --profile validation-step -- oc get pods -A
  safe_exec.py check --profile validation-step --string 'oc get po | grep x'
  safe_exec.py run   --profile go-fuzz --timeout 900 -- make build
  safe_exec.py list-profiles
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from traust_contracts import SafeExecProfiles

_log = logging.getLogger(__name__)
RECURSION_ENV = "SAFE_EXEC_DEPTH"
MAX_RECURSION = 3
BYPASS_LOG_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
BYPASS_LOG = BYPASS_LOG_DIR / "traust-engine" / "safe-exec-bypass.log"

# ---------------------------------------------------------------------------
# Deny tables. HARD entries are never grantable: a profile that lists one
# is a configuration error, refused at load.
# ---------------------------------------------------------------------------

HARD_DENY_BINARIES = frozenset(
    {
        # privilege / system mutation
        "sudo",
        "su",
        "doas",
        "chown",
        "chgrp",
        "dd",
        "mkfs",
        "mount",
        "umount",
        "systemctl",
        "service",
        "crontab",
        "launchctl",
        "reboot",
        "shutdown",
        "insmod",
        "rmmod",
        "sysctl",
        # process/host tampering
        "kill",
        "pkill",
        "killall",
        "renice",
        "nohup",
        # raw network tools (profiles needing egress use scoped tools, not these)
        "nc",
        "ncat",
        "netcat",
        "socat",
        "telnet",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "wget",
        # package managers (runtime installs are S7 territory, never build steps)
        "pip",
        "pip3",
        "dnf",
        "yum",
        "apt",
        "apt-get",
        "brew",
        "gem",
        "cargo-install",
    }
)

SHELLS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "ksh",
        "dash",
        "fish",
        "csh",
        "tcsh",
    }
)

# Interpreters are deny-by-default but PROFILE-grantable (python-test
# legitimately runs python3/pytest). Shells are not.
INTERPRETERS = frozenset(
    {
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "deno",
        "lua",
        "php",
        "awk",
        "gawk",
        "mawk",
        "xargs",
        "env",
        "eval",
        "exec",
        "command",
        "time",
        "timeout",
        "nice",
        "setsid",
        "script",
    }
)

GIT_NETWORK_SUBCOMMANDS = frozenset(
    {
        "push",
        "pull",
        "fetch",
        "clone",
        "remote",
        "submodule",
        "ls-remote",
    }
)

# Dangerous `git -c key=value` / `--config-env` keys: each is a code-exec
# or credential-theft primitive. Matched case-insensitively; entries
# ending in "." are prefixes.
GIT_DANGEROUS_C_KEYS = (
    "core.pager",
    "core.editor",
    "core.sshcommand",
    "core.hookspath",
    "core.fsmonitor",
    "core.askpass",
    "core.alternateobjectdirectories",
    "credential.",
    "filter.",
    "diff.external",
    "difftool.",
    "mergetool.",
    "merge.",
    "remote.",
    "http.proxy",
    "http.sslcainfo",
    "http.sslcert",
    "http.sslkey",
    "protocol.",
    "sendemail.",
    "alias.",
    "gpg.program",
    "ssh.variant",
    "uploadpack.",
    "sshcommand",
)

PROTECTED_ENV_VARS = frozenset(
    {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PERL5LIB",
        "NODE_OPTIONS",
        "RUBYOPT",
        "BASH_ENV",
        "ENV",
        "IFS",
        "SHELL",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_ASKPASS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "JAVA_TOOL_OPTIONS",
        "MAVEN_OPTS",
        "GRADLE_OPTS",
        "_JAVA_OPTIONS",
        "SAFE_EXEC_MODE",
        "SAFE_EXEC_DISABLED",
        RECURSION_ENV,
    }
)

# Raw denies applied to STRING-form commands before tokenization.
RAW_DENY_PATTERNS = (
    (re.compile(r"`"), "backtick command substitution"),
    (re.compile(r"\$\("), "command substitution $( )"),
    (re.compile(r"\$\{"), "parameter expansion ${ }"),
    (re.compile(r"[<>]\("), "process substitution"),
    (re.compile(r"\$'"), "ANSI-C quoting"),
    (re.compile(r"/dev/(tcp|udp)/"), "raw socket via /dev/tcp|udp"),
    # NB: no newline deny — nothing here ever reaches a shell, so a
    # quoted newline is printf data and an unquoted one is whitespace;
    # either way every resulting token passes the vetting below.
)

# Environment kept when run() scrubs (plus profile keep_env).
BASE_KEEP_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TERM",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
)

_ENV_PREFIX_RX = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    description: str
    allow: frozenset
    allowed_path_heads: frozenset
    allow_pipelines: bool
    keep_env: tuple

    def permits(self, head: str) -> bool:
        if "/" in head:
            return head in self.allowed_path_heads
        return head in self.allow


@dataclasses.dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str = ""
    # tokenized pipeline segments (only for string-form validation)
    segments: tuple = ()


# Embedded fallback so library consumers (validate-findings adapters)
# keep functioning if the config file is absent in a stripped checkout.
# The YAML file is authoritative; keep this entry in sync with it
# (tests/test_safe_exec.py::test_fallback_matches_config enforces).
_FALLBACK_PROFILES = {
    "validation-step": Profile(
        name="validation-step",
        description="embedded fallback — see config/safe-exec-profiles.yaml",
        allow=frozenset(
            {
                "curl",
                "oc",
                "kubectl",
                "jq",
                "grep",
                "base64",
                "head",
                "tail",
                "tr",
                "wc",
                "cat",
                "sleep",
                "echo",
                "printf",
            }
        ),
        allowed_path_heads=frozenset(),
        allow_pipelines=True,
        # VF_OAUTH_TOKEN kept for probe soundness (F15) — lab-scoped,
        # short-TTL; see config/safe-exec-profiles.yaml
        keep_env=("KUBECONFIG", "VF_OAUTH_TOKEN"),
    ),
}


def profiles_from_section(section: SafeExecProfiles) -> dict:
    out = {}
    for name, spec in (section.profiles or {}).items():
        allow = frozenset(spec.get("allow") or [])
        bad = sorted(allow & (HARD_DENY_BINARIES | SHELLS))
        if bad:
            raise ValueError(
                f"profile {name!r} grants hard-denied binaries {bad} — "
                "hard denies are never grantable; fix "
                "safe-exec-profiles.yaml"
            )
        out[name] = Profile(
            name=name,
            description=str(spec.get("description", "")),
            allow=allow,
            allowed_path_heads=frozenset(spec.get("allowed_path_heads") or []),
            allow_pipelines=bool(spec.get("allow_pipelines", False)),
            keep_env=tuple(spec.get("keep_env") or ()),
        )
    return out


_profiles_from_section = profiles_from_section  # tests / legacy alias


_PROFILE_CACHE: dict | None = None


def bind_profiles(section: SafeExecProfiles | None) -> None:
    """Seed the module-global cache (tests and standalone CLI only).

    Engine callers should use ``ContextOps.safe_exec_profile_map()`` — it is
    scoped to one ``HarnessEngine`` instance and does not clobber other contexts
    in the same process.
    """
    global _PROFILE_CACHE
    if section is None:
        _PROFILE_CACHE = dict(_FALLBACK_PROFILES)
        return
    _PROFILE_CACHE = profiles_from_section(section)


def reset_profiles() -> None:
    """Clear the module-global cache (tests only)."""
    global _PROFILE_CACHE
    _PROFILE_CACHE = None


def profiles(*, profile_map: dict | None = None) -> dict:
    if profile_map is not None:
        return profile_map
    global _PROFILE_CACHE
    if _PROFILE_CACHE is None:
        _log.warning(
            "safe_exec profiles not bound — falling back to built-in profiles. "
            "This is a security-policy fallback: the operator's allowlists are "
            "NOT in effect. Pass profile_map= or bind via HarnessEngine."
        )
        _PROFILE_CACHE = dict(_FALLBACK_PROFILES)
    return _PROFILE_CACHE


def get_profile(name: str, *, profile_map: dict | None = None) -> Profile:
    p = profiles(profile_map=profile_map).get(name)
    if p is None:
        raise KeyError(
            f"unknown safe_exec profile {name!r}; "
            "known: {sorted(profiles(profile_map=profile_map))} "
            "(see safe-exec-profiles.yaml in $TRAUST_CONFIG_HOME)"
        )
    return p


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def _check_git_argv(argv: list) -> str:
    """Extra hardening when the head binary is git. Returns deny reason
    or ''."""
    i = 1
    subcommand = None
    while i < len(argv):
        tok = argv[i]
        if tok in ("-c", "--config-env"):
            if i + 1 < len(argv):
                key = argv[i + 1].split("=", 1)[0].strip().lower()
                for danger in GIT_DANGEROUS_C_KEYS:
                    if key == danger or (danger.endswith(".") and key.startswith(danger)):
                        return f"git config key {key!r} is a code-exec/credential primitive"
                i += 2
                continue
            return "dangling git -c"
        if tok == "-C":
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        subcommand = tok
        break
    if subcommand in GIT_NETWORK_SUBCOMMANDS:
        return (
            f"git network subcommand {subcommand!r} is denied under "
            "safe_exec (clones/fetches belong to S3-gated skill "
            "steps, not target-derived commands)"
        )
    return ""


# curl hardening (assessment 2026-07-31 live-F5): the validation-step
# profile legitimately probes lab endpoints, but upload/file-read/config
# forms turn a "safe" probe into arbitrary local-file exfiltration.
# Host allowlisting is the P1 follow-up; these flags are never needed.
CURL_DENY_FLAGS = frozenset(
    {
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "--config",
        "-K",
        "--netrc",
        "-n",
        "--netrc-file",
        "--output-dir",
        "--create-dirs",
    }
)


def _check_curl_argv(argv: list) -> str:
    for tok in argv[1:]:
        flag = tok.split("=", 1)[0]
        if flag in CURL_DENY_FLAGS:
            return (
                f"curl flag {flag!r} is denied under safe_exec "
                "(local-file read/upload/config — exfiltration "
                "primitives; assessment 2026-07-31 F5)"
            )
        if tok.startswith(("-d@", "--data@")):
            return "curl -d@<file> is denied under safe_exec"
        if flag in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode"):
            idx = argv.index(tok)
            if "=" in tok:
                val = tok.split("=", 1)[1]
            else:
                val = argv[idx + 1] if idx + 1 < len(argv) else ""
            if val.startswith("@"):
                return "curl --data @<file> is denied under safe_exec"
        if tok.startswith("file://"):
            return "curl file:// scheme is denied under safe_exec"
    return ""


# kube hardening (assessment 2026-07-31 live-F1/F2 defense-in-depth):
# cluster/credential override flags never belong in target-derived
# commands — the adapter supplies context and kubeconfig. The execute
# layer denies these too; this is the second fence.
KUBE_DENY_FLAGS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "--cluster",
        "--user",
        "--server",
        "-s",
        "--token",
        "--as",
        "--as-group",
        "--as-uid",
        "--insecure-skip-tls-verify",
        "--tls-server-name",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--username",
        "--password",
    }
)


def _check_kube_argv(argv: list) -> str:
    for tok in argv[1:]:
        flag = tok.split("=", 1)[0]
        if flag in KUBE_DENY_FLAGS:
            return (
                f"kubectl/oc flag {flag!r} is denied under safe_exec "
                "— target-derived commands run only against the "
                "engagement-pinned context (assessment 2026-07-31 F2)"
            )
    return ""


def validate_argv(argv, profile: Profile) -> Verdict:
    """Validate one command (no pipeline) as an argv list."""
    if not argv:
        return Verdict(False, "empty command")
    if int(os.environ.get(RECURSION_ENV, "0")) >= MAX_RECURSION:
        return Verdict(False, f"safe_exec recursion depth cap ({MAX_RECURSION}) reached")
    head = None
    for tok in argv:
        m = _ENV_PREFIX_RX.match(tok)
        if m and head is None:
            var = m.group(1)
            if var.upper() in PROTECTED_ENV_VARS or var.upper().startswith("GIT_"):
                return Verdict(False, f"assignment to protected env var {var!r}")
            continue
        head = tok
        break
    if head is None:
        return Verdict(False, "command has no executable head")
    base = head if "/" in head else Path(head).name
    name = Path(base).name
    if name in HARD_DENY_BINARIES:
        return Verdict(False, f"{name!r} is hard-denied (never grantable)")
    if name in SHELLS:
        return Verdict(
            False, f"shell {name!r} is never grantable — pipelines run natively under safe_exec"
        )
    if name in ("safe_exec", "safe_exec.py"):
        return Verdict(False, "safe_exec may not re-invoke itself")
    if not profile.permits(head if "/" in head else name):
        if name in INTERPRETERS:
            return Verdict(False, f"interpreter {name!r} not granted by profile {profile.name!r}")
        return Verdict(
            False,
            f"binary {head!r} not in profile {profile.name!r} allowlist {sorted(profile.allow)}",
        )
    if name == "git":
        reason = _check_git_argv([head, *list(argv[argv.index(head) + 1 :])])
        if reason:
            return Verdict(False, reason)
    if name == "curl":
        reason = _check_curl_argv(list(argv[argv.index(head) :]))
        if reason:
            return Verdict(False, reason)
    if name in ("kubectl", "oc"):
        reason = _check_kube_argv(list(argv[argv.index(head) :]))
        if reason:
            return Verdict(False, reason)
    return Verdict(True)


def vet_command_string(cmd: str, profile: Profile) -> Verdict:
    """Vet a PoC-derived command STRING. On success, `segments` holds the
    tokenized pipeline (one tuple per `|` segment)."""
    for rx, why in RAW_DENY_PATTERNS:
        if rx.search(cmd or ""):
            return Verdict(False, f"{why} not allowed in step text")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError as e:
        return Verdict(False, f"unparseable step command: {e}")
    if not tokens:
        return Verdict(False, "empty step command")
    for t in tokens:
        if t and all(c in ";&<>|()" for c in t) and t != "|":
            return Verdict(False, f"shell operator {t!r} not allowed in step text")
    segments: list = [[]]
    for t in tokens:
        if t == "|":
            segments.append([])
        else:
            segments[-1].append(t)
    if len(segments) > 1 and not profile.allow_pipelines:
        return Verdict(False, f"profile {profile.name!r} does not allow pipelines")
    for seg in segments:
        v = validate_argv(seg, profile)
        if not v.ok:
            return v
    return Verdict(True, segments=tuple(tuple(s) for s in segments))


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------


def _scrubbed_env(profile: Profile, extra_env: dict | None = None) -> dict:
    env = {k: os.environ[k] for k in (*BASE_KEEP_ENV, *profile.keep_env) if k in os.environ}
    env[RECURSION_ENV] = str(int(os.environ.get(RECURSION_ENV, "0")) + 1)
    if extra_env:
        for k, v in extra_env.items():
            if k.upper() in PROTECTED_ENV_VARS:
                raise ValueError(f"extra_env may not set protected {k!r}")
            env[k] = v
    return env


def run_segments(
    segments,
    profile: Profile,
    *,
    timeout: int = 120,
    cwd=None,
    input_: str | None = None,
    extra_env: dict | None = None,
):
    """Execute validated pipeline segments via subprocess chaining —
    no shell. Returns (rc, stdout, stderr); rc/stderr come from the
    final segment, non-zero upstream rcs are appended to stderr."""
    env = _scrubbed_env(profile, extra_env)
    if len(segments) == 1:
        try:
            proc = subprocess.run(
                list(segments[0]),
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_,
                cwd=cwd,
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            out = (
                e.stdout
                if isinstance(e.stdout, str)
                else (e.stdout or b"").decode(errors="replace")
            )
            err = (
                e.stderr
                if isinstance(e.stderr, str)
                else (e.stderr or b"").decode(errors="replace")
            )
            return 124, out, err + f"\n[timeout after {timeout}s]"
        except OSError as e:
            return 127, "", f"[exec failed: {e}]"
        return proc.returncode, proc.stdout, proc.stderr
    procs = []
    prev_stdout = subprocess.PIPE if input_ is not None else None
    try:
        for _i, seg in enumerate(segments):
            stdin = procs[-1].stdout if procs else prev_stdout
            procs.append(
                subprocess.Popen(
                    list(seg),
                    stdin=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd,
                    env=env,
                )
            )
            if procs[:-1]:
                # let upstream see SIGPIPE naturally
                procs[-2].stdout.close()
        if input_ is not None:
            procs[0].stdin.write(input_)
            procs[0].stdin.close()
        out, err = procs[-1].communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        for p in procs:
            p.kill()
        return 124, "", f"[pipeline timeout after {timeout}s]"
    except OSError as e:
        for p in procs:
            p.kill()
        return 127, "", f"[exec failed: {e}]"
    rc = procs[-1].returncode
    tail_err = err or ""
    for i, p in enumerate(procs[:-1]):
        p.wait(timeout=5)
        if p.returncode not in (0, None):
            tail_err += f"\n[pipeline segment {i} exited {p.returncode}]"
    return rc, out, tail_err


def run(
    cmd,
    profile_name: str,
    *,
    timeout: int = 120,
    cwd=None,
    input_: str | None = None,
    extra_env: dict | None = None,
    honor_bypass: bool = False,
    profile_map: dict | None = None,
):
    """Validate then execute. `cmd` is an argv list or a command string.
    Library callers default to NOT honoring SAFE_EXEC_DISABLED."""
    profile = get_profile(profile_name, profile_map=profile_map)
    bypass = os.environ.get("SAFE_EXEC_DISABLED", "").strip()
    if bypass and honor_bypass:
        _log_bypass(cmd, profile_name, bypass)
        segments = (
            [tuple(cmd)]
            if not isinstance(cmd, str)
            else vet_command_string(cmd, profile).segments or [tuple(shlex.split(cmd))]
        )
        return run_segments(
            segments, profile, timeout=timeout, cwd=cwd, input_=input_, extra_env=extra_env
        )
    if isinstance(cmd, str):
        v = vet_command_string(cmd, profile)
        segments = v.segments
    else:
        v = validate_argv(list(cmd), profile)
        segments = (tuple(cmd),)
    if not v.ok:
        return 126, "", f"[safe_exec blocked: {v.reason}]"
    return run_segments(
        segments, profile, timeout=timeout, cwd=cwd, input_=input_, extra_env=extra_env
    )


def _log_bypass(cmd, profile_name: str, reason: str) -> None:
    line = f"SAFE_EXEC BYPASS profile={profile_name} reason={reason!r} cmd={cmd!r}"
    print(f"*** {line}", file=sys.stderr)
    try:
        BYPASS_LOG.parent.mkdir(parents=True, exist_ok=True)
        BYPASS_LOG.parent.chmod(0o700)
        with BYPASS_LOG.open("a", encoding="utf-8") as fh:
            import datetime

            fh.write(f"{datetime.datetime.now().astimezone().isoformat()} {line}\n")
    except OSError:
        pass  # the stderr shout already happened


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def check_command(
    profile: str,
    cmd: str | list[str],
    *,
    timeout: int = 120,
    cwd: str | None = None,
) -> int:
    profile_obj = get_profile(profile)
    mode = os.environ.get("SAFE_EXEC_MODE", "enforce").lower()
    if isinstance(cmd, str):
        verdict = vet_command_string(cmd, profile_obj)
    else:
        verdict = validate_argv(cmd, profile_obj)
    if verdict.ok:
        print("OK")
        return 0
    if mode == "warn":
        print(f"WARN (would block): {verdict.reason}")
        return 0
    print(f"BLOCK: {verdict.reason}")
    return 1


def execute_command(
    profile: str,
    cmd: str | list[str],
    *,
    timeout: int = 120,
    cwd: str | None = None,
) -> int:
    profile_obj = get_profile(profile)
    mode = os.environ.get("SAFE_EXEC_MODE", "enforce").lower()
    if isinstance(cmd, str):
        verdict = vet_command_string(cmd, profile_obj)
    else:
        verdict = validate_argv(cmd, profile_obj)
    if not verdict.ok and mode == "warn":
        print(f"WARN (would block, running anyway — warn mode): {verdict.reason}", file=sys.stderr)
        segs = verdict.segments or (
            [tuple(shlex.split(cmd))] if isinstance(cmd, str) else [tuple(cmd)]
        )
        rc, out, err = run_segments(segs, profile_obj, timeout=timeout, cwd=cwd)
    else:
        rc, out, err = run(cmd, profile, timeout=timeout, cwd=cwd, honor_bypass=True)
    sys.stdout.write(out or "")
    sys.stderr.write(err or "")
    return rc


def list_profiles_cmd() -> int:
    for name, p in sorted(profiles().items()):
        print(f"{name:18s} allow={sorted(p.allow)} pipelines={p.allow_pipelines} — {p.description}")
    return 0
