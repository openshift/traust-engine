#!/usr/bin/env bash
# CI-only: uv sync into .ci-venv with git-tag sibling deps from pyproject.toml.
set -euo pipefail

root="${CI_PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

# Forge host from the CI environment, not a literal: an internal hostname
# compiled into a tracked file is a disclosure, and the value is deployment
# identity that GitLab already provides. Fail closed rather than rewrite
# nothing and fail later on an opaque auth error.
#
# This assumes the sibling deps in uv.lock are hosted on the same GitLab as
# this pipeline, which is what makes one variable serve as both the
# insteadOf source and its target. If a dep ever moves to another forge,
# that URL needs its own rewrite -- it will not be covered by this one.
: "${CI_SERVER_HOST:?CI_SERVER_HOST is unset -- this script is CI-only}"

git config --global \
  url."https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/".insteadOf \
  "ssh://git@${CI_SERVER_HOST}/"

ca=""
for candidate in "${CI_SERVER_TLS_CA_FILE:-}" /etc/gitlab-runner/certs/ca.crt; do
  [[ -n "$candidate" && -f "$candidate" ]] || continue
  ca="$candidate"
  break
done
[[ -n "$ca" ]] || {
  echo "GitLab CA unavailable (CI_SERVER_TLS_CA_FILE or /etc/gitlab-runner/certs/ca.crt)" >&2
  exit 1
}

export GIT_SSL_CAINFO="$ca"
git config --global http.sslCAInfo "$ca"

venv="/tmp/ci-venv-${CI_JOB_ID:-local}"
export UV_PROJECT_ENVIRONMENT="$venv"
uv venv "$venv" --python python3.12
uv sync
export PATH="${venv}/bin:${PATH}"
