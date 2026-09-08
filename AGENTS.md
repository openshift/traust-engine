# traust-engine

Python 3.11+ library (`traust_engine`).

- **Before done:** `make lint-fix` then `make test` — CI enforces both; do not skip
- **Lint:** line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF (`pyproject.toml`) — `Path` not `os.path`, no bare `except: pass`
- **Commits:** conventional `type(scope): subject` (`feat`, `fix`, `perf`, `chore`, `ci`, …)
- **Releases:** `feat`/`fix`/`perf`/breaking MRs need `make check-release`, `VERSION` + `CHANGELOG.md` bump
- **Scope:** smallest diff; match existing style; skip `data/secure-code-audit/` unless asked
- **Setup:** `make setup` once per clone (hooks). More: [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md)
