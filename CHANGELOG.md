# Changelog

## [0.12.7] — 2026-09-08

### Fixed
- `tests/test_redact.py` assembles the PEM private-key markers at runtime
  instead of carrying a literal `-----BEGIN RSA PRIVATE KEY-----` block that
  tripped the public forge's secret-scanning "RSA private key" detector
  (openshift/traust-engine alert #1). The body was the dummy string
  `MIIsecretsecret`, never key material; test behaviour unchanged.

## [0.12.6] — 2026-09-08

### Added
- README License section and `license = "Apache-2.0"` in package metadata,
  matching `LICENSE`.

## [0.12.5] — 2026-09-08

### Changed
- `CODEOWNERS` names the `@openshift/traust-maintainers` team instead of
  individual accounts.

## [0.12.4] — 2026-09-08

### Changed
- Three over-long comment/docstring lines wrapped to the repo's 100-column
  ruff limit (`corpus/resolver.py`, `portfolio/graph.py`, `reporting/validate.py`);
  `ruff check` is clean.

## [0.12.3] — 2026-09-08

### Added
- `LedgerService.actor()` — passthrough to `LedgerClient.actor()` (traust-ledger
  0.21.0): the verified actor after the optional employee-directory
  cross-check, so harness CLIs that record human decisions can refuse up
  front instead of at submit.

### Changed
- Pin traust-ledger v0.21.0.

## [0.12.2] — 2026-09-07

### Fixed
- The corpus resolver's docstring named a deployment's engagement tree by its
  codename. It now describes the rule (any `<name>-findings` entry in
  corpus-config activates when present). The last estate name in this repo.

## [0.12.1] — 2026-09-07

### Fixed
- **Stale paths from the 2026-08-13 restructure, swept.** A workspace-wide
  check after the project renames found one rename residue (a comment naming
  `ai-security-harness/docs/…`) and ~80 references to `scripts/*.py` files that
  moved into this package or into the harness's `traust` CLI. Usage
  docstrings, runtime hints, and the precedent-cache `"builder"` stamp now
  name the `traust <group> <op>` subcommands (`traust sweep collect`,
  `traust corpus findings-db`, `traust reporting validate`, `traust metrics
  attribute-spend`, …) or the module path (`traust_engine._util.redact`, …).
  Four pointers to harness docs that no longer exist now name their
  successors (`docs/deterministic-inferential-mix.md`, `docs/reachability.md`,
  `docs/sarif.md`). The README consumer pin block, still at
  engine v0.1.0 / ledger v0.1.1 / contracts v0.2.0, mirrors `pyproject.toml`.
  The CI header comment names `ci/setup-uv.sh`, the script that exists.
  No code change.

## [0.12.0] — 2026-09-06

### Changed
- harness engine now acts like the library it should be, config is inject in and computation is all that happens here
- bumped to use config loader from traust-contracts
- properly handle entry by providing a facade for harness callers

## [0.11.2] — 2026-09-06

### Fixed
- **Rule lane finds the harness checkout under its renamed directory.** The
  `emit_rule_drafts` locator tries `<workspace>/traust/` first, then the
  pre-rename `traust/` name, then the workspace root. Without this
  a workspace whose harness clone is named `traust` (the default since the
  GitLab project rename) silently skipped rule-draft emission.

## [0.11.1] — 2026-09-06

### Changed
- **Sibling dependency URLs follow the project renames.** `traust-contracts`
  is pinned from `hybrid-platforms-sec/traust-contracts.git` (same tag `v1.0.0`)
  and `traust-ledger` from `hybrid-platforms-sec/traust-ledger.git`, bumped to
  `v0.19.7` — the first traust-ledger release whose own contracts pin uses the
  renamed path, which is what lets `uv lock` resolve a single contracts source.
  No code change; the docs commits since 0.11.0 ride along.

## [0.11.0] — 2026-09-04

### Changed
- **`TRAUST_CONFIG_HOME` replaces `HARNESS_CONFIG_DIR`.** One variable names
  the operational config directory; default `~/.traust/config` when it
  exists. Workspace-sibling `.harness-config` marker discovery is removed.
- **No config files ship in the wheel.** `data/config/` is gone, including
  `model-registry.yaml`; `registry.models` resolves it through
  `config_path()` — the harness repo's shipped `config/` copy, unless the
  adopter places one in `$TRAUST_CONFIG_HOME`. `config.CONFIG_DIR` is
  removed; `harness_config_dir()` locates the harness's `config/` when the
  harness package is installed.
- `DeploymentConfigMissing` now points at `scripts/install_traust`.
- (Restores nothing from 803e10f: the five files re-added there are removed
  again, this time with no code path that could read them.)

## [0.10.0] — 2026-09-03

### Changed
- **Deployment-specific config no longer ships in the wheel.**
  `data/config/` kept copies of `corpus-config.yaml`,
  `product-definitions-map.yaml`, `budget-policy.yaml`,
  `rule-pack-allowlist.yaml` and `safe-exec-profiles.yaml` — one estate's
  corpus registry, product mappings and spend policy compiled into a
  package meant to be published. Removed; only `model-registry.yaml`
  (estate-neutral) remains bundled.
- **New resolver: `traust_engine.config.config_path(name)`.** Resolves a
  config file from the deployment config directory first
  (`$HARNESS_CONFIG_DIR`, else a workspace sibling `*/config/` carrying a
  `.harness-config` marker), then the bundled/estate-neutral fallback, and
  otherwise raises `DeploymentConfigMissing` naming every location searched
  and the template to copy. `strict=False` returns the deployment candidate
  for import-time defaults. `metrics.spend`, `_util.safe_exec`,
  `corpus.resolver`, `adapters.opengrep`, `sweep.rule_lane`,
  `registry.products` and `reporting.validate` all resolve through it;
  `validate` no longer imports `traust.paths` or probes
  `cwd/config` for the signing key.
- Tests that audit the deployment's own allowlist/signing key now resolve
  it via `config_path` and skip when the checkout has no deployment dir.

## [0.9.13] — 2026-09-03

### Fixed
- **`ci/setup-uv.sh` no longer hardcodes the forge hostname.** The
  `insteadOf` rewrite that maps `uv.lock`'s `ssh://` sibling-dep URLs to
  authenticated HTTPS now takes the host from `$CI_SERVER_HOST`, which
  GitLab sets on every job, instead of a literal. An internal hostname
  compiled into a tracked file is a disclosure, and the value is
  deployment identity the environment already carries.
  The script is CI-only (it already requires `$CI_JOB_TOKEN` and a
  runner CA), so it now fails closed when `$CI_SERVER_HOST` is unset
  rather than installing a rewrite that matches nothing and failing later
  on an opaque auth error. Assumes the sibling deps live on the same
  GitLab as the pipeline — noted in the script, because a dep on another
  forge would need its own rewrite.
- Reformatted `toolchain/_check.py`, `toolchain/_preflight.py` and
  `tests/test_toolchain_e2e.py`. They were already unformatted on `main`
  under the locked ruff 0.16.2, so `lint:ruff` fails for any MR that does
  not carry the fix. Byte-identical to the same repair in !3, so whichever
  lands first makes it a no-op for the other.

## [0.9.6] — 2026-09-01

### Changed
- **SDK boundary enforcement.** All `LedgerService` write methods now delegate
  to `LedgerClient` — `patch_layer_file`, `stamp_report_file`, `ensure_layer_file`,
  and the `submit_events` report branch. `_write_layer_file` is deleted.
- **Added `store_layer(path, layer)`** — public method for persisting a complete
  layer dict through the backend before signing.
- **Zero `traust_ledger._internal` imports.** `SigningConfig` and `review_item_key`
  no longer imported from internals; `LedgerClient` resolves signing config
  internally, `review_item_key` is inlined.
- **`stamp_merkle_metadata` removed from `traust_engine.ledger` exports.**
  Stamping is internal to `LedgerClient.sign()`.
- Pin traust-ledger ≥0.18.7.

## [0.9.5] — 2026-08-31

### Added
- **`traust_engine.toolchain` package** — freeze, preflight, fetch-dbs, stamp,
  check, and parser modules for deterministic scanner operation.
- **Grype adapter** (`traust_engine.adapters.grype`) with freeze support.
- **DB freeze defaults on** — osv, govulncheck, grype adapters now default
  `freeze=True` to prevent mid-scan DB updates.
- **`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` pinning** in fetch-dbs to normalize
  cache location across osv-scanner v2.x.

### Removed
- Stale `external-tools.yaml` copy in traust-engine (SSOT is
  `traust/config/`).

## [0.9.4] — 2026-08-31

### Fixed
- **SARIF exports leaked an internal host into every artifact.** `TOOL_URI` was
  hardcoded to `[internal-gitlab]/traust-engine` and
  written to the driver block's `informationUri` on every exported file, so it
  travelled with the artifact to GitHub Code Scanning and any downstream viewer
  — not just to readers of this source tree. A deployment-specific URL is never
  a shipped default: `TOOL_URI` now reads `HARNESS_SARIF_TOOL_URI`, and the key
  is omitted when unset (`informationUri` is optional in SARIF 2.1.0, and
  omitting it beats emitting an internal host).

### Changed
- **OpenGrep rule pack no longer ships internal ticket references.** Four Python
  rules carried internal ticket ids in `metadata.references`, a field meant for links a
  reader can follow. OpenGrep emits rule metadata into scan output, so the key
  propagated into every finding those rules fired and onward into reports and
  SARIF exports. Provenance is kept (`seeded: language-coverage plan W1a`), the
  internal id dropped. Mirrored in the traust copy of the pack.

## [0.9.3] — 2026-08-31

### Fixed
- **`LedgerService.sign()` destroyed valid signatures instead of renewing them.**
  `LedgerClient` defaults `signing_config=None` and wires a signer only when one
  is supplied; `ServiceConfig` is a plain `BaseModel` that deliberately does not
  auto-load env. So constructing `LedgerClient(data_dir=...)` without a config
  left `sign()` with no signer: it re-stamped the Merkle root, correctly dropped
  the now-void signature, and wrote the layer **unsigned** — raising nothing,
  even with `LAAS_SIGNING_REQUIRED=true`, because that guard lives in the config
  that was never read.

  Measured on the current stack (traust-engine 0.9.2 + traust-ledger 0.18.6),
  same key and layer: `fmt=4 sig=True` → `fmt=None sig=False`. A
  `backfill_event_fingerprints` pass unsigned 112 corpus layers this way on
  2026-08-31; they have been re-signed.

  `LedgerService` now passes `SigningConfig.from_env()`, which is a no-op where
  no key is configured, so environments without signing are unaffected.

  Tested at both levels: that a config is passed, and — with a real key, skipped
  otherwise — that a layer arriving signed still carries a signature after its
  root moves. The second is the property; the first is only its plumbing.

## [0.9.2] — 2026-08-31

### Changed
- **traust-ledger pin → v0.18.6.** `LedgerClient` now resolves auth from env
  automatically when `token` is omitted, so `LedgerService` simplifies to
  `LedgerClient(data_dir=...)` — no more manual `resolve_env_token()` ceremony.

## [0.9.1] — 2026-08-28

### Fixed
- **`LedgerService(data_dir=...)` could not authenticate.** It read
  `os.environ["LAAS_TOKEN"]` alone, so a developer who had run
  `ledger auth local` held a valid credential on disk that the harness refused
  to consult, and every write failed with `token is required` — blocking all 25
  harness call sites. It now uses `traust_ledger.client.resolve_env_token()`, the
  same chain as `ledger auth token` (`LAAS_TOKEN` → `LEDGER_TOKEN_PATH` →
  `LEDGER_TOKEN` → stored login → local mint), and a missing token now names
  the remedy instead of only reporting absence.

### Changed
- traust-ledger pin → v0.17.3, which makes `traust-ledger` installable without the
  `cli` extra (PyJWT promoted to a core dependency, `httpx2` imported lazily).

## [0.9.0] — 2026-08-27

### Added
- **`traust_engine.ledger` — LedgerService gateway.** Single entry point
  for all ledger I/O: `submit_events`, `sign`, `verify`,
  `resolve_review_item`, and layer file operations (`ensure_layer_file`,
  `patch_layer_file`, `read_layer_file`, `stamp_report_file`). Re-exports
  pure SDK functions (`fingerprint`, `compute_event_id`,
  `derive_disposition`, `stamp_merkle_metadata`, `verify_merkle_integrity`).

### Changed
- Pin `traust-ledger>=0.17.1` (hardened identity verification, dedup fix).

## [0.8.1] — 2026-08-27

### Added
- **S3-compatible endpoint support** (`HARNESS_S3_ENDPOINT_URL`,
  `HARNESS_S3_REGION`, `HARNESS_S3_PATH_STYLE`, `HARNESS_S3_CA_BUNDLE`).
  0.8.0 shipped `s3://` support that only worked against AWS: `url_to_fs`
  was called with no `storage_options`, so MinIO, OpenShift Data Foundation
  and Ceph RGW — the on-cluster stores this feature exists for — resolved to
  AWS and failed in a way that reads like bad credentials rather than a
  wrong endpoint.
  - Path-style addressing is opt-in because virtual-host style needs
    wildcard DNS a cluster may not have.
  - A private CA is supplied as a bundle. There is deliberately **no
    verify-off switch**, and a test asserts one never appears in the
    derived options.
  - `HARNESS_STORAGE_OPTIONS` takes a JSON object merged over the derived
    options, so an unanticipated backend kwarg needs no code change.
  - S3 options do not leak to other schemes (tested).


## [0.8.0] — 2026-08-27

### Added
- **`traust_engine.storage` — URI-addressed locations for the large
  read-mostly artifacts.** `ANALYSIS_RESULTS_URI` and `PORTFOLIO_GRAPH_URI`
  accept a bare path, `file://`, or an object-store URI (`s3://`, `gs://`,
  `az://`, `abfs://`, `https://`). Findings and a multi-gigabyte portfolio
  graph can now live in object storage, which is how a scheduled
  orchestrator deployment will run them.
  - **Local stays zero-cost and dependency-free.** A bare path or `file://`
    takes a branch that imports nothing and copies nothing; a test asserts
    `fsspec` is never imported on that path. An operator workstation
    acquires no dependency for a deployment feature.
  - **Remote materializes to a local cache rather than streaming.** The
    graph is a ~3 GB SQLite file with `idx_edges_{src,dst,rel}`, and one
    impact analysis issues thousands of small indexed reads. Object stores
    have no random-access read semantics, so a VFS shim would turn each
    index probe into a ranged GET. The cache is keyed on the store's own
    validators (ETag, else size+mtime), so an unchanged artifact costs one
    `info()` call.
  - Fetches publish atomically via `os.replace`: a failed transfer leaves no
    cache entry. A truncated 3 GB graph that looked complete would produce
    silently wrong blast-radius answers — worse than no graph.
  - Backends are the optional `remote` / `s3` / `gcs` extras, imported
    lazily. A missing extra raises `StorageError` naming the install, not an
    `ImportError` from six frames down.
  - `storage.join()` preserves a remote scheme: `Path("s3://b") / "x"`
    silently yields `s3:/b/x`, which is the class of bug this replaces.

### Fixed
- **An unset `ANALYSIS_RESULTS_DIR` silently downgraded every impact deep
  scan to `inconclusive`.** `sbom_cross_check` computed
  `ANALYSIS_RESULTS_DIR / "graph" / "sboms"` on a value config types
  `Path | None`; the `TypeError` was caught per-repo by `analyze_repo`'s
  executor and the repo fell through to `inconclusive`, indistinguishable
  in the artifact from "scanned and found nothing". Measured 2026-08-26: a
  265-advisory sweep reported `ok=265, failed=0` while moving 743 repos out
  of `affected` and changing 5,710 classifications. Both unguarded use
  sites (`sbom_cross_check`, `_resolve_image_binary`) now handle `None`, and
  the SBOM tier records *why* it was skipped rather than skipping silently.
- **A scan tier that fails for every repo is now fatal.** `analyze_repo`
  errors are accumulated; if every scanned repo raised, the analyzer prints
  the first failure and exits 2 instead of writing an artifact whose
  evidence is uniformly absent for a reason unrelated to the code analysed.

## [0.7.9] — 2026-08-25

### Changed
- traust-ledger pin v0.15.0 -> **v0.15.1** — pluggable identity provider registry,
  machine claim fix, dead code removal, RFC 6750 WWW-Authenticate headers.

## [0.7.8] — 2026-08-25

### Changed
- traust-ledger pin v0.14.0 -> **v0.15.0** — the employee-directory adapter no
  longer reports a refused or unreachable directory as `not_found`.

## [0.7.7] — 2026-08-25

### Changed
- traust-ledger pin v0.13.2 -> **v0.14.0** — `resolve_review_item`, so a caller that
  owns its own write can close a review item under the same rules.

## [0.7.6] — 2026-08-25

### Fixed
- Skill paths now resolve whether a skill sits at `harnessing/<skill>/` or one
  level deeper under a workflow stage directory,
  `harnessing/<N>-<stage>/<skill>/` (harness skill-usability plan 1.2). The
  harness nests 34 of its skills that way and leaves the other 24 at the root;
  two places here assumed exactly one level.
- `script_loader`'s `_SKILL_LOCAL` lookup built `harnessing/<skill>/<sub>/`, so
  every `load_script("compliance_assert", …)` against a staged checkout raised
  `FileNotFoundError`. The flat path is tried first and the nested one second,
  so an older harness checkout keeps working.
- `attribute_spend`'s `SKILL.md` regex and `known_skills()` walked a single
  level, which failed silently and was the worse of the two: `known_skills()`
  returned only the root skills, `valid` rejected every staged lane, and the
  spend for those lanes landed in `unattributed` with no error. Both spellings
  now match, since old transcripts recorded the flat path and are never
  rewritten. `known_skills()` descends only into directories that are not
  themselves skills, so a `SKILL.md` bundled inside a skill is not counted as a
  skill of its own.

## [0.7.5] — 2026-08-25

### Changed
- traust-ledger pin v0.13.1 -> **v0.13.2** — resolve_needs_review reaches a pending
  item shadowed by a resolved twin.

## [0.7.4] — 2026-08-25

### Changed
- traust-ledger pin v0.12.1 -> **v0.13.1** — `LedgerWriter.resolve_needs_review`,
  the missing exit from the review queue. (v0.13.0 is skipped: its tag carries a
  pyproject reading 0.12.1 and cannot satisfy the constraint.)

## [0.7.3] — 2026-08-25

### Changed
- traust-ledger pin v0.12.0 -> **v0.12.1** — restores the `HARNESS_SIGNING_*` env
  names, which 0.11.0 renamed with no alias. Without it, anything in this stack
  exporting `HARNESS_SIGNING_KEY_PATH` configured no signer and wrote unsigned
  layers, with `HARNESS_SIGNING_REQUIRED=1` no longer read either.

## [0.7.2] — 2026-08-25

### Changed
- contracts pin v0.6.0 -> **v0.7.0**, traust-ledger pin v0.10.0 -> **v0.12.0**.
  Carries the `needs_identity` queue reason and the receiver-side quarantine that
  replaced traust-ledger 0.11.0's server-side fingerprint backstop, plus the
  corrected `finding.fingerprint` / `fingerprint_algo` schema descriptions from
  contracts 0.6.1.
- Rolled here first, and as one commit, because uv resolves the sibling deps by
  exact git tag: a split tag across the workspace fails the resolve with
  "conflicting URLs for package `traust-ledger`". Same rule as 0.4.1 and 0.6.5.

## [0.7.1] — 2026-08-24

### Fixed
- Every "Fix:" line the report validator prints for a fingerprint problem
  named `python3 scripts/finding_identity.py`, which has not existed since
  the code moved into this package — the operator who hit the error got
  "No such file or directory" from the remedy. Four message strings and the
  module's own CLI docstring now name the runnable form,
  `python3 -m traust_engine._util.finding_identity`, via a single
  `_IDENTITY_CMD` constant so they cannot drift apart again.

### Removed
- `strict_checks` no longer re-scans for missing fingerprints.
  `check_finding_identity` has ERRORED on an absent stamp on the default
  path since the P6 flip (2026-08-13, once the corpus reached 100%
  stamped), so the strict pass reported the same defect a second time. Its
  comment — "advisory by default and an ERROR under --strict" — had
  outlived the behaviour it described, which is how the claim reached
  traust `docs/skills.md` and stayed there. Strict mode is
  unchanged for every other check; a report that would have failed still
  fails, once instead of twice.

### Notes
- The `VERSION` file said 0.6.5 while `pyproject.toml` said 0.7.0 — the 0.7.0
  release bumped one and not the other, so `make bump` refused to run. Both
  now read 0.7.1. There is no `## [0.7.0]` section in this file for the same
  reason; it is not backfilled here because the intent of that release is not
  mine to reconstruct.

## [0.6.5] — 2026-08-21

### Changed
- traust-ledger pin v0.8.3 -> v0.9.0. Same rule as 0.4.1: uv resolves the
  sibling deps by exact git tag, so a split tag across the workspace fails
  the resolve with "conflicting URLs for package `traust-ledger`". This is
  what took traust CI red once it moved to v0.9.0.

### Fixed
- `tests/test_config.py` had two leading blank lines, which failed
  `ruff format --check` and had `lint:ruff` red on main since 0.6.3 —
  blocking test:pytest and release:tag behind it.

## [0.6.0] — 2026-08-20

### Added
- `provenance` table in `findings.db` — projects
  `layer_metadata.external_refs` (contracts >= 0.5.4): which external
  identifier a finding became, with confidence and how the link was
  derived. Lets first-discovery metrics be a query instead of a walk over
  every layer.

## [0.4.1] — 2026-08-20

### Changed
- contracts pin v0.5.3 -> v0.5.4, traust-ledger pin v0.7.1 -> v0.8.1.
  Keeps one contracts tag across the workspace: uv resolves it by exact
  git tag, so a split fails with conflicting URLs.

## [0.4.0] — 2026-08-20

### Added
- `repos` gains the six per-record artifact refs — `audit_json`, `audit_md`,
  `findings_current`, `findings_layer`, `triage_json`, `threat_model` — stored
  **root-relative**, not absolute. These were the only fields
  `corpus-manifest.json` carried that this table did not, and adding them is what
  lets that artifact be retired. Root-relative because an absolute path is
  meaningless once reports leave the checkout (ledger plan §4.4.0): a ref resolves
  through `report_store` against a local tree or a bucket alike.
- `corpus.resolver.build_manifest` marked **deprecated** — kept for on-demand
  snapshots via `resolve --out`, no longer written on a schedule.

## [0.3.3] — 2026-08-19

**Disposition merge lives in traust-ledger** — single source of truth for validity,
assurance, resolution, and conflict derivation.

### Changed
- `corpus.disposition` delegates `derive_disposition` to `traust_ledger.disposition`;
  removed ~170 lines of duplicated merge logic from traust-engine.
- `_util.actor.is_actor_verified` re-exported from `traust_ledger.disposition`.
- Pin `traust-contracts` to `v0.5.3`, `traust-ledger` to `v0.7.1`.

## [0.3.2] — 2026-08-19

**Embargo validation uses `_actor_is_verified`.** The 0.3.0 embargo rule still
checked `ldap_verified` directly while false-positive and severity already used the
shared helper — OIDC-era actors with `identity_verified: true` passed FP/severity but
failed embargo.

### Fixed
- `cross_validate_layer` rule 3a3: human embargo assertions now call
  `_actor_is_verified` (same contract as rules 3 and 3a2).

## [0.3.1] — 2026-08-19

**Identity model sync** — align readers with traust-ledger 0.7.0 and contracts 0.5.2.

### Added
- `_util.actor.is_actor_verified` — checks `identity_verified` first, falls back to
  legacy `ldap_verified` for pre-refactor events. Shared by disposition, precedent,
  and validate readers (same contract as traust-ledger's `_is_actor_verified`).

### Changed
- Adopt `traust-ledger>=0.7.0` and `traust-contracts>=0.5.2` (OIDC-era actor
  identity stamps). Engine code unchanged beyond the shared reader helper.

## [0.3.0] — 2026-08-19

**`disposition.embargo` is enforced.** The contract has carried the field since
traust-contracts 0.4.0, and its schema description asserts that "the validator
rejects machine actors carrying disposition.embargo" — but nothing performed that
check. The rule existed briefly in the harness's own `validate_report.py` and was lost
when that module was deleted in the C8 restructure. Re-landed here, where validation
now lives.

### Added
- `cross_validate_layer` rule 3a3: `disposition.embargo` is HUMAN-only, on the same
  footing as `disposition.severity`. A machine actor may not set it; a human event
  setting it needs an LDAP-verified identity and a rationale. Whether a finding
  warrants embargoed handling is a disclosure-risk judgement, never a machine verdict.
- Four tests, verified to **fail when the rule is reverted** — the previous incarnation
  of this gap was a check that existed but did not enforce, so "the test passes" was
  not evidence.

### Notes
- Immediately caught 4 real defects in the 20 existing embargo events: human
  assertions carrying `ldap_verified: false` on sample operator repos (removed
  internal ticket refs). Those are data to reconcile, not rule
  bugs — the attribution decision belongs to the ledger owner.
- Existing severity/false-positive rules are unchanged.

## [0.2.0] — 2026-08-19

**`corpus.report_store` — the seam reports move through** (ledger plan §4.4.0 step 2,
first increment). No consumer is converted yet: the seam lands with zero behavioural
change so that if it is wrong, it is wrong while every file is still where it was.

### Added
- `ReportStore.get(ref, expect_sha256=...)` **verifies the bytes** against the digest
  the layer recorded in step 1, raising `DigestMismatch`. That is the property a
  least-privilege front-end needs — prove what you read — and it works identically
  against a local file or a signed URL.
- `LocalBackend` (refs are paths relative to a root, today's layout unchanged, and it
  refuses a ref that escapes the root including via symlink) and `MemoryBackend`, so
  consumer tests stop needing a findings tree on disk.
- `build_index` / `write_index` / `index_records` — enumeration reads an index built
  by **serializing `resolve()`'s own output**, never a second identity implementation.
  Measurement decided this over a prefix convention: `product` is nullable (28 repos
  sit directly at `findings/<repo>/`), a record is the *set* of six co-located
  artifacts whose `preferred`/`report_kind` depend on which exist, symlink aliases
  have no object-storage equivalent, and ownership joins on `tree`.

### Verified against the real corpus
`resolve()` walk vs index rehydration: **8,604 records, identical record sets, zero
field-level differences**, 6,512 aliases captured, 0 warnings, 6 trees. Parity is the
acceptance bar because census drift is silent (plan §4.4.13), so it is asserted by test
as well as measured.

## [0.1.17] — 2026-08-18

### Changed
- Adopt `traust-ledger>=0.6.0` — **signature format 3**, which binds
  `audit_report_sha256` into the signed payload (plan §4.4.0a). Format 2 still
  verifies during the corpus re-sign. Engine code unchanged; 802 tests pass.

## [0.1.16] — 2026-08-18

### Changed
- Adopt `traust-ledger>=0.5.0` (`traust_ledger.reports`: content-addressed report
  reference) and `traust-contracts>=0.5.1` (the two fields it records). Engine
  code unchanged; 802 tests pass.

## [0.1.15] — 2026-08-18

### Changed
- Adopt `traust-contracts>=0.5.0,<0.6` and `traust-ledger>=0.4.1` — the shared
  golden-vector suite and `paths.vectors_dir()` are gone (plan D7: only the harness
  computes identity), and the recipe's regression fixtures now live in traust-ledger.
- `_util/finding_identity.py`: the module docstring described the recipe as a
  cross-language contract "pinned by a golden-vector oracle" and pointed at four
  paths, three of which no longer exist (`contracts/vectors/…`,
  `contracts/tests/test_compat.py`, `gen_identity_golden_vectors.py`). Rewritten to
  state D7 and point at the fixtures' real home, plus the v2 re-stamp worklist.

802 tests pass; no engine behaviour change.

## [0.1.14] — 2026-08-18

### Changed
- Depend on `traust-contracts>=0.4.5` and `traust-ledger>=0.3.1` — the
  location-path rule, the `repo-scope-path` vocabulary, and
  `fingerprint(strict=True)`, which refuses a finding whose every location
  canonicalizes to empty. Engine code unchanged; 802 tests pass. Strict mode is
  opt-in until the corpus migration, so nothing here changes behaviour yet.

## [0.1.13] — 2026-08-18

### Changed
- Depend on `traust-ledger>=0.2.0` — fingerprint `algo_version` **v2** (D8): a
  location path canonicalizing to empty is dropped from the hashed set. Engine
  code unchanged; 802 tests pass. Note for consumers: `check_finding_identity`
  recomputes and compares, so the 364 corpus findings whose value moves under v2
  will report as mismatched until the deferred re-stamp runs (plan P8 → item 3).

## [0.1.12] — 2026-08-18

### Fixed
- **P9 — `finding_identity.rebaseline()` now stamps before writing.** It mutated
  the layer and wrote with a plain `json.dumps`, leaving the declared
  `merkle_root` stale — an ERROR since traust-ledger 0.1.3, and the last writer
  outside the `stamp_and_sign` contract. It also surfaces
  `SignAttempt.warning()`, so a dropped or failed signature is not silent here
  either.
- **P9b — `rebaseline()` confines the layer path.** It accepted a bare path and
  wrote wherever it was told, including outside the findings tree and through a
  symlink. New `findings_root` argument; default roots are the new baseline's
  directory and the cwd.

### Added
- `traust_engine._util.layer_paths.confine_layer_path` — realpath containment
  shared by the writers that lacked it, raising `LayerPathOutsideRoot` rather
  than exiting, so each CLI keeps its own exit contract.

## [0.1.11] — 2026-08-18

### Changed
- Depend on `traust-ledger>=0.1.7`, which drops a `merkle_root_signature` the
  recomputed root has invalidated instead of leaving a signature that verifies
  against nothing. Engine code unchanged; 798 tests pass.

## [0.1.9] — 2026-08-17

### Changed
- Depend on `traust-contracts>=0.4.3,<0.5` and `traust-ledger>=0.1.5`.
  0.4.3 declares `event.fingerprint` / `event.fingerprint_algo`, so
  `traust_engine.reporting.validate` stops rejecting every layer file whose
  events carry an identity stamp — 49 files / 198 events at the time of the
  fix. Engine code unchanged; 798 tests pass.

## [0.1.8] — 2026-08-17

### Changed
- Depend on `traust-contracts>=0.4.2,<0.5` and `traust-ledger>=0.1.4`, with
  both git source pins advanced to match. Second link in the release train for
  `disposition.embargo`: contracts 0.4.0 carried the schema, but this package's
  `<0.4` constraint and its `tag = "v0.3.0"` source kept the harness pinned to
  0.3.x and made `uv lock` fail with conflicting URLs for one package.

### Added
- Six joern tests adopted from `traust`, where they were orphaned
  by the package restructure (35995ad).

No engine behaviour change: 798 tests pass unmodified against the new schemas.

## [0.1.7] — 2026-08-14

### Removed
- **Java joern reachability tier** (`impact.analyzer.JavaAnalyzer._joern_tier`).
  It never promoted a finding: **0 of 120** in-range pairs across the first
  full Maven sweep, and still 0 after three real defects in it were fixed
  (wrong frontend, wrong package prefix, absent `--symbols`). Its only output
  was `package_api_called` -> `evidence_level: symbol-usage`, which the cheap
  textual scan already reaches and which shares the `likely_affected` ceiling
  with `manifest` — so it changed no classification, no SLA clock, no routing.
  The blocker is **interface dispatch**: advisories name library-internal
  methods, applications call interfaces, the implementation binds at runtime.
  A 5-JAR Spring closure links correctly (732 cross-JAR edges, DataBinder
  present) and the path still does not resolve —
  `CALLS_TO BeanWrapperImpl.getPropertyDescriptor = 0` vs
  `CALLS_TO BeanWrapper.getPropertyDescriptor = 5`. Fixing it needs
  devirtualization (CHA/VTA), which joern has no pass for and which would make
  precision worse. Full finding, including four eliminated hypotheses:
  `traust/docs/joern-reachability-finding.md`.

  **Artifact-shape change for consumers**: Java repos in
  `*-impact-analysis.json` no longer carry `evidence.joern_reachability` /
  `joern_witness`, and `joern_reachability` no longer appears in `tiers_run`.
  Classifications are unchanged, because the tier never changed one.

### Fixed
- **C++ symbol matching in `adapters.joern`** — our bug, not joern's. Exact
  mode compared the whole `methodFullName`, but c2cpg emits
  `<unresolvedNamespace>.ConsumeFieldMessage:<unresolvedSignature>` for C++
  member calls and never qualifies with `::`, so **every C++ member query
  failed by construction**. Measured on protobuf `text_format.cc`: 3325 calls,
  0 matches, 0 names containing `::`. Exact mode now compares the callee name
  after stripping the signature at `:` and the namespace at the last `.`.
  After: `ConsumeFieldMessage` 3 sites, `TryConsume` 15, `ConsumeFieldValue` 3,
  with fully-qualified callers
  (`google.protobuf.TextFormat.Parser.ParserImpl.ParseField`). Plain C is
  unchanged (netty `memcpy` still 7 sites), so short C identifiers still do
  not over-match — which is why exact mode exists.

### Kept
- **C/C++ joern tier**, on measurement rather than assumption: 6 of 6 direct
  calls resolved against human-audited ground truth, each landing in the exact
  function the audit flagged — lz4-java (`XXH32_createState` @ XXHashJNI.c:92,
  `XXH32_reset` :93, `XXH64_createState` :202, `LZ4_decompress_fast` @
  LZ4JNI.c:169) and netty (`memcpy` @ :889 in `bindDomainSocket`, :921 in
  `connectDomainSocket`, against an audit flagging 885/917). C has no interface
  dispatch; only function-pointer dispatch hides edges (`(*env)->` JNI table
  calls correctly returned 0), which the wrapper's soundness block already
  declares.

### Note
- `VERSION` had drifted to 0.1.5 while `pyproject.toml` and the `v0.1.6` tag
  said 0.1.6; both are resynced here. There is no gate in this repo comparing
  them, unlike the consumer harness.

## [0.1.5] — 2026-08-14

### Fixed
- **`traust_engine.sweep.rule_lane`**: auto-discover
  `harnessing/mine-ledger/scripts/emit_rule_drafts.py` under the campaign
  workspace (`$WS/traust/...` or `$WS/...` when the harness is
  the workspace root). Regression-draft staging no longer skips when
  `EMIT_RULE_DRAFTS_SCRIPT` is unset; explicit flag and env still override.

### Changed
- Lane delta report and module docstring reference
  `python3 -m traust_engine.sweep.rule_lane` instead of the retired
  `scripts/run_rule_mining_lane.py` path.

## [0.1.2] — 2026-08-12

### Fixed
- Preserve `skipped_frameworks` through Pydantic round-trip in
  `compliance/dashboard.py` `collect_assessments()`.

## [0.1.1] — 2026-08-12

### Fixed
- Ship bundled data (config, opengrep/gitleaks rules) inside the wheel package.
  Data moved from repo-root `data/` to `src/traust_engine/data/`; `config.py`
  resolves paths from `__file__.parent` instead of `parents[2]`. Fixes
  `FileNotFoundError` for `CONFIG_DIR` in non-editable installs.

## [0.1.0] — 2026-08-12

**Initial release.** Extracted processing core from traust v0.261.0.

### Included
- Adapter layer (gitleaks, opengrep, checkov, pqc-scan)
- Sweep/calibration engine
- Reporting (SARIF, validate, lint)
- Compliance, impact, validation modules
- Metrics/ledger integration
- Corpus management
- Config and data assets (budget-policy, model-registry, opengrep/gitleaks rules)
