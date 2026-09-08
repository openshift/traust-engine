#!/usr/bin/env python3
"""CI gates: conventional-commit lint, semver bump hints, release readiness.

Used by:
  - .githooks/commit-msg  (subject validation)
  - .gitlab-ci.yml        (range, mr commands)
  - release.py            (bump_level import)
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# --- Conventional commit patterns ---

HEADER_RE = re.compile(
    r"^(?P<type>build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)"
    r"(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?: (?P<subject>.+)$"
)
MERGE_RE = re.compile(r"^Merge (branch|commit|remote-tracking branch|pull request) ")
REVERT_RE = re.compile(r"^Revert ")
HINT = "expected: type(scope): subject  (e.g. feat(adapters): add joern cache)"

VERSION_FILE = "VERSION"
CHANGELOG_FILE = "CHANGELOG.md"
CHANGELOG_SECTION_RE = re.compile(r"^## \[(?P<version>\d+\.\d+\.\d+)\]", re.MULTILINE)


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str
    body: str


class GitError(Exception):
    pass


# --- Git helpers ---


def _git(*args: str, cwd: Path | None = None) -> str:
    try:
        return subprocess.run(
            ("git", *args), cwd=cwd, check=True, text=True, capture_output=True
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise GitError(f"git {' '.join(args)} failed") from exc


def _resolve(ref: str, *, cwd: Path | None = None) -> None:
    _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", cwd=cwd)


def _log(range_spec: str, *, cwd: Path | None = None) -> list[Commit]:
    commits: list[Commit] = []
    for entry in _git("log", "--format=%H%x1f%s%x1f%b%x1e", range_spec, cwd=cwd).split("\x1e"):
        entry = entry.strip("\n")
        if not entry:
            continue
        sha, subject, body = entry.split("\x1f", 2)
        commits.append(Commit(sha=sha, subject=subject, body=body))
    return commits


# --- Conventional commit validation ---


def validate_subject(subject: str) -> str | None:
    """Return error message if subject is non-conventional, else None."""
    if MERGE_RE.match(subject) or REVERT_RE.match(subject):
        return None
    if not HEADER_RE.match(subject):
        return f"non-conventional subject: {subject!r}"
    return None


def validate_range(base: str, head: str, *, cwd: Path | None = None) -> str | None:
    """Validate all commit subjects in base..head. Returns first error or None."""
    _resolve(base, cwd=cwd)
    _resolve(head, cwd=cwd)
    for commit in _log(f"{base}..{head}", cwd=cwd):
        if err := validate_subject(commit.subject):
            return f"{commit.sha[:8]}: {err}"
    return None


# --- Semver bump ---


def bump_level(commits: Iterable[Commit]) -> str | None:
    """Determine required semver bump from commit list: major > minor > patch > None."""
    level: str | None = None
    for commit in commits:
        if MERGE_RE.match(commit.subject) or REVERT_RE.match(commit.subject):
            continue
        match = HEADER_RE.match(commit.subject)
        if not match:
            continue
        if match.group("breaking") or "BREAKING CHANGE" in commit.body:
            return "major"
        typ = match.group("type")
        if typ == "feat":
            level = "minor"
        elif typ in {"fix", "perf"} and level is None:
            level = "patch"
    return level


def bump_between(base: str, head: str, *, cwd: Path | None = None) -> str | None:
    """Bump level for commits in base..head."""
    return bump_level(_log(f"{base}..{head}", cwd=cwd))


# --- Release readiness (VERSION + CHANGELOG gate) ---


def _semver_tuple(version: str) -> tuple[int, int, int]:
    return tuple(map(int, version.split(".")))


def _version_at_ref(ref: str, *, cwd: Path) -> str:
    return _git("show", f"{ref}:{VERSION_FILE}", cwd=cwd).strip()


def check_release_mr(base: str, head: str, *, cwd: Path | None = None) -> str | None:
    """Validate VERSION bump and CHANGELOG entry for an MR. Returns error or None."""
    root = Path(cwd) if cwd else Path.cwd()
    _resolve(base, cwd=root)
    _resolve(head, cwd=root)

    needed = bump_between(base, head, cwd=root)
    base_version = _version_at_ref(base, cwd=root)
    head_version = (root / VERSION_FILE).read_text(encoding="utf-8").strip()

    if needed is None:
        if _semver_tuple(head_version) > _semver_tuple(base_version) and not _changelog_has(
            head_version, cwd=root
        ):
            return (
                f"VERSION bumped to {head_version} but "
                f"CHANGELOG.md has no ## [{head_version}] section"
            )
        return None

    if _semver_tuple(head_version) <= _semver_tuple(base_version):
        return (
            f"release-worthy commits since {base} (expected {needed} bump) but "
            f"VERSION is still {head_version}; bump from {base_version} in this MR"
        )

    if not _changelog_has(head_version, cwd=root):
        return f"VERSION is {head_version} but CHANGELOG.md has no ## [{head_version}] section"

    return None


def _changelog_has(version: str, *, cwd: Path) -> bool:
    path = cwd / CHANGELOG_FILE
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    return any(m.group("version") == version for m in CHANGELOG_SECTION_RE.finditer(text))


# --- CLI ---


def _fail_commit(message: str) -> int:
    print("conventional-commit check failed:", file=sys.stderr)
    print(f"  {message}", file=sys.stderr)
    print(f"  {HINT}", file=sys.stderr)
    return 1


def _fail_release(message: str) -> int:
    print("release check failed:", file=sys.stderr)
    print(f"  {message}", file=sys.stderr)
    print("  fix: make bump patch|minor|major and add ## [X.Y.Z] to CHANGELOG.md", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: gates.py {subject|range|bump|mr} ...", file=sys.stderr)
        return 2

    match args[0]:
        case "subject":
            if len(args) < 2:
                print("usage: gates.py subject <message-file>", file=sys.stderr)
                return 2
            text = Path(args[1]).read_text(encoding="utf-8")
            subject = text.splitlines()[0].strip() if text else ""
            if err := validate_subject(subject):
                return _fail_commit(err)
            return 0

        case "range":
            if len(args) < 3:
                print("usage: gates.py range <base> <head>", file=sys.stderr)
                return 2
            try:
                if err := validate_range(args[1], args[2]):
                    return _fail_commit(err)
            except GitError as exc:
                print(f"gates: {exc}", file=sys.stderr)
                return 1
            return 0

        case "bump":
            if len(args) < 3:
                print("usage: gates.py bump <base> <head>", file=sys.stderr)
                return 2
            try:
                print(bump_between(args[1], args[2]) or "none")
            except GitError as exc:
                print(f"gates: {exc}", file=sys.stderr)
                return 1
            return 0

        case "mr":
            if len(args) < 3:
                print("usage: gates.py mr <base> <head> [--root DIR]", file=sys.stderr)
                return 2
            root = None
            if len(args) >= 5 and args[3] == "--root":
                root = Path(args[4])
            try:
                if err := check_release_mr(args[1], args[2], cwd=root):
                    return _fail_release(err)
            except GitError as exc:
                print(f"gates: {exc}", file=sys.stderr)
                return 1
            print(f"ok: release metadata for {args[1]}..{args[2]}")
            return 0

        case _:
            print(f"unknown command: {args[0]}", file=sys.stderr)
            print("usage: gates.py {subject|range|bump|mr} ...", file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main())
