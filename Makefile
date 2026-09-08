PYTHON ?= python3
RELEASE := ./release.py
BUMP_PARTS := patch minor major

.PHONY: help setup sync hooks lint lint-fix test check-release status bump $(BUMP_PARTS)

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       - ruff --fix"
	@echo "  make test           — pytest unit tests (no integration)"
	@echo "  make check-release  — VERSION + CHANGELOG gate for current branch vs main"
	@echo "  make status         — current version, tag, git state"
	@echo "  make bump patch|minor|major — bump VERSION + pyproject.toml"

setup: sync hooks
	@echo "ready — local hooks enabled (.githooks). Bypass: git commit --no-verify"

sync:
	uv sync

hooks:
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest tests/ -q -m "not integration"

check-release:
	@base="$${RELEASE_BASE:-origin/main}"; \
	head="$${RELEASE_HEAD:-HEAD}"; \
	$(PYTHON) ci/gates.py mr "$$base" "$$head"

$(BUMP_PARTS):
	@:

status:
	$(PYTHON) $(RELEASE) status

bump:
	@part="$(filter $(BUMP_PARTS),$(MAKECMDGOALS))"; \
	if [ -z "$$part" ]; then \
		echo "usage: make bump patch|minor|major" >&2; \
		exit 1; \
	fi; \
	$(PYTHON) $(RELEASE) bump $$part
