"""External scanner wrappers — subprocess adapters for security tools.

Each adapter checks for the tool binary on PATH and raises ToolNotFound
if absent. Missing tools don't break other adapters or the test suite.

Library API: each adapter exposes a scan() function returning a typed
AdapterResult (from traust_contracts) when contracts are installed,
or a plain dict otherwise.
"""
