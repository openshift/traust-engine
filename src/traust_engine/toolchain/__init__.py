"""Toolchain management — freeze, check, stamp, and populate external tool DBs.

Public API for the harness runtime to manage the opinionated set of
external security scanners declared in external-tools.yaml.
"""

from traust_engine.toolchain._check import check_tool, tool_version
from traust_engine.toolchain._fetch_dbs import POPULATABLE_TOOLS, populate
from traust_engine.toolchain._freeze import freeze_env, freeze_flags
from traust_engine.toolchain._parsers import db_status
from traust_engine.toolchain._preflight import preflight, preflight_failures
from traust_engine.toolchain._stamp import stamp_string
from traust_engine.toolchain._types import DBInfo, ToolCheck

__all__ = [
    "POPULATABLE_TOOLS",
    "DBInfo",
    "ToolCheck",
    "check_tool",
    "db_status",
    "freeze_env",
    "freeze_flags",
    "populate",
    "preflight",
    "preflight_failures",
    "stamp_string",
    "tool_version",
]
