# Traust Opengrep Rule Pack

Traust-authored opengrep rules — the default ruleset for `run_opengrep.py`.
Shipped with the traust engine and safe to vendor or redistribute.

## Layout

One YAML per language and category (`go/injection.yaml`, …). Each rule file
has a same-basename test fixture (`go/injection.go`, `yaml/foo.test.yaml`)
using standard `// ruleid: <id>` / `// ok: <id>` annotations (or YAML
`# ruleid:` / `# ok:` comments).

```
opengrep-rules/
  go/           # Go rules + .go fixtures
  python/       # Python rules + .py fixtures
  java/         # Java rules + .java fixtures
  typescript/   # TypeScript/JavaScript rules + .ts fixtures
  bash/         # Shell rules + .sh fixtures
  yaml/         # YAML config-default rules + .test.yaml fixtures
```

YAML-language rules use `.test.yaml` fixture files because the rule files
themselves are `.yaml`.

## Running tests

From the `traust-engine` package root, with [opengrep](https://github.com/opengrep/opengrep) on `PATH`:

```bash
opengrep test src/traust_engine/data/secure-code-audit/opengrep-rules/<lang>
```

Run every language directory, or target one (`go`, `python`, `yaml`, …).

`opengrep test` evaluates every fixture whose name extends the rule file's
basename (`data-exposure.nocred.sh` pairs with `data-exposure.yaml`) but
**ignores** `paths:` filters — path exclusions are exercised at scan time
only. File-level co-occurrence constraints (`pattern-inside: pattern-regex:`
with an anchored lookahead) scan comments too; fixtures must not name the
lexicon words they test.

The pytest suite also exercises the pack end-to-end when opengrep is
available:

```bash
pytest tests/test_run_opengrep.py -q
```

## Rule conventions

- **ids:** `traust-<lang>-<category>-<slug>` where `<category>` is a kebab-case
  security category (`injection`, `ssrf`, `cryptography`, `data-exposure`, …).
- **metadata:** `cwe` (primary CWE first — feeds finding fingerprints),
  `category`, `asvs` chapter ref, `confidence`, and optional `references`
  naming the vulnerability pattern cluster (CWE-oriented, no repo slugs).
- **taint mode:** prefer `mode: taint` for data-flow rules; pattern-only
  rules should carry an honest `confidence` tier.
- **messages:** original wording; framework and standard citations by ID only
  (e.g. SEI CERT rule IDs in `metadata.cert` for Java rules).

## Companion gitleaks pack

DSN URLs with embedded credentials are detected by the gitleaks extension in
`../gitleaks-rules/gitleaks-default.toml` (gitleaks reads every file type — `.env`,
`toml`, `properties`, not just code). The yaml tranche here covers the same
miss class in helm values, docker-compose, and operator CR samples.
