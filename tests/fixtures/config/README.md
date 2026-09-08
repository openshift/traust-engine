# Test fixture: estate-neutral `TRAUST_CONFIG_HOME`

Minimal configs for the traust-engine test suite. No operational data, no
prose copied from deployment templates, and no vendor-specific feed entries.
`tests/conftest.py` points `TRAUST_CONFIG_HOME` here.

When shipped templates change upstream, refresh only the fields tests depend on
(corpus trees, model ids, tool pins, rule-pack shape) — do not re-copy comment
blocks from production config.
