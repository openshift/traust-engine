"""Format provenance stamp strings for metadata.tools."""

from __future__ import annotations


def stamp_string(
    tool: str, version: str | None = None, db_built: str | None = None, db_schema: str | None = None
) -> str:
    """Format a structured provenance string for ``ReportMetadata.tools``.

    Examples::

        >>> stamp_string("grype", "0.115.0", db_built="2026-08-24", db_schema="5")
        'grype 0.115.0 (db built 2026-08-24, schema 5)'
        >>> stamp_string("opengrep", "1.25.0")
        'opengrep 1.25.0'
    """
    parts = [tool]
    if version:
        parts.append(version)
    qualifiers = []
    if db_built:
        qualifiers.append(f"db built {db_built}")
    if db_schema:
        qualifiers.append(f"schema {db_schema}")
    if qualifiers:
        parts.append(f"({', '.join(qualifiers)})")
    return " ".join(parts)
