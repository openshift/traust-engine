# traust-engine

Self-contained processing library for Traust. Deterministic workflow code
(disposition merge, validation gates, rule calibration) lives here—not in the
app CLI. Import as `traust_engine`.

## Architecture

| Module | Role |
|---|---|
| `traust_engine.corpus.disposition` | Disposition merge engine |
| `traust_engine.validation` | Scope enforcement and soundness gates |
| `traust_engine.sweep.calibration` | Rule-pack calibration library API |
| `traust_engine.adapters` | Scanner adapters (gitleaks, opengrep, …) |
| `traust_engine.reporting` | Report validation, SARIF, render |

Rule packs ship under `data/secure-code-audit/` (`opengrep-rules/`,
`gitleaks-rules/`). This library ships **no configuration files and never loads
config itself — it is a pure consumer.** A caller builds the context once
(`traust_contracts.load_context()`, done for you by
`HarnessEngine.load(config_home=…)`) and the engine receives it *injected*: the
ops namespaces (`h.metrics`, `h.corpus`, …) hold the frozen `HarnessContext` and
derive paths from it; stateless functions take already-resolved arguments. No
environment overrides, no cwd or workspace-shaped guessing; a required-but-absent
file fails closed with `DeploymentConfigMissing` at the entry point. The config
ownership model (contract / resolution / consumer) is documented in
`traust/docs/architecture.md` → *Configuration & context*; the runtime paths this
engine reads from `locations.yaml` are in *Runtime configuration* below.

## Install

Private Git (after tags are published):

```bash
uv add "traust-engine @ git+ssh://git@<your-forge>/<namespace>/traust-engine.git@v0.1.0"
```

With library dependencies pinned the same way:

```toml
[project]
dependencies = [
    "traust-engine>=0.12.1",
    "traust-ledger>=0.19.4",
    "traust-contracts>=1.0.0,<2",
]

[tool.uv.sources]
traust-engine = { git = "git@<your-forge>:<namespace>/traust-engine.git", tag = "v0.12.1" }
traust-ledger = { git = "git@<your-forge>:<namespace>/traust-ledger.git", tag = "v0.20.0" }
traust-contracts = { git = "git@<your-forge>:<namespace>/traust-contracts.git", tag = "v1.2.0" }
```

Local mono-checkout (sibling repos):

```bash
cd traust-engine && make setup && make test
```

`make setup` runs `uv sync` and enables `.githooks/`. Before opening an MR that
ships user-facing changes, run `make bump patch|minor|major`, add a
`## [X.Y.Z]` section to `CHANGELOG.md`, and `make check-release` (same gate as
CI `release:check-mr`). On merge to `main`, CI tags when `VERSION` is ahead of
the latest tag.

## Optional extras

```bash
uv sync --extra graph --extra signing
```

## Runtime configuration

Runtime configuration is **config-owned** — there are no environment overrides for
deployment values. One directory, `$TRAUST_CONFIG_HOME` (default `~/.traust/config`),
holds every config file; edit them there (the AWS/SSH model).

| Config | Purpose |
|---|---|
| `$TRAUST_CONFIG_HOME` | The one config directory (corpus-config, model-registry, feeds, external-tools, safe-exec profiles, product map, budget policy, rule-pack allowlist, hardening weights, dist-git watch, internal vocabulary, optional signing pubkey). Default `~/.traust/config`; else `DeploymentConfigMissing`. |
| `locations.yaml` → `workspace` | Workspace root the harness reads repos from |
| `locations.yaml` → `analysis_results` | Findings-side artifact root (local path or `file://`/`s3://`… URI) |
| `locations.yaml` → `progress_tracker` | Metrics journal + dashboard output root |
| `locations.yaml` → `feeds_cache` | Feed cache directory |
| `locations.yaml` → `portfolio_graph` | Portfolio graph DB (defaults under `analysis_results`) |
| `locations.yaml` → `gitleaks_config` | Gitleaks TOML (overrides the bundled default) |
| `locations.yaml` → `opengrep_rules` | Opengrep rule pack dir (overrides the bundled default) |
| `locations.yaml` → `product_definitions` | Product/ownership registry endpoint (optional) |
| `locations.yaml` → `sarif_tool_uri` | SARIF `informationUri` (optional; omitted when unset) |

Secrets and OS/tool standards stay environment-driven (`GITHUB_TOKEN`, signing key
material, `XDG_*`, `JAVA_OPTS`, `SAFE_EXEC_DISABLED`).

No config ships in the wheel. Templates for every operational file live in the
harness repo as `config/*.example.*`; `install_traust` copies them into
`$TRAUST_CONFIG_HOME`.

## Development

After clone:

```bash
make setup    # uv sync + enable .githooks
make lint
make test
```

Manual equivalents:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -m "not integration" -q   # unit tests (no external binaries)
uv run pytest -q                        # full suite; integration skips when gitleaks/opengrep absent
uv build
```

Tests use minimal scanner fixtures under `tests/fixtures/` — no sibling
`traust` checkout required.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
