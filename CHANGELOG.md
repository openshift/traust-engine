# Changelog

All notable changes to traust-engine are documented here.

## [0.2.1]

Harden `safe_exec` validation of target-derived curl commands: options are
now vetted by a full option walk (unknown options denied), URLs restricted
to http/https. Adds optional `curl_allowed_hosts` and `keep_env_heads`
profile fields. See SECURITY.md for reporting details.

Introduces a security posture framework (`restricted`, `baseline`, `privileged`,
with `high`, `medium`, `low` aliases) set per profile or file-wide via
`defaults.posture`. `restricted` enforces fail-closed behavior (curl denied unless
hosts are allowlisted, redirects denied, env scoping required on pipelines).
`baseline` permits public http/https egress while denying private IP ranges
(RFC 1918, loopback, link-local/cloud metadata) and internal domains unless
allowlisted. `privileged` retains permissive fail-open behavior.
`run(honor_bypass=True)` threads `allowed_hosts` when recovering segments,
so a bypassed pipeline still splits instead of collapsing into one argv.

## [0.2.0]

## Changes

- delegate countersign/whoami/stamp_event_identities to the engine

## [0.1.1]

## Changes

- Adopt traust-contracts 0.1.1 and traust-ledger 0.1.1, which enforce RFC
  3339 on `LayerEvent.recorded_at` / `.occurred_at`. No engine code changes
  were needed — dependency pins only.

### Upgrading

Contracts 0.1.1 validates timestamps on read as well as write, so a corpus
holding non-conforming values must be migrated before this release is used
against it (`python3 -m traust.migrations.fix_event_timestamps <root>
--apply`). `traust_engine.reporting.validate` also asserts `format:
date-time` now that the format assertor ships as a declared dependency.

## [0.1.0]

Self-contained processing library for Traust: deterministic workflow code
for disposition merge, validation gates, and rule calibration — the
`traust_engine` package consumed by the app CLI and other components.
