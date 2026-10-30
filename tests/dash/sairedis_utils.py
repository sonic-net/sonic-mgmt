"""
DASH-facing re-export of shared sairedis helpers.

Implementation lives in tests.common.helpers.sairedis_utils so common plugins
(e.g. fidelity) can import without a cross-feature dependency on tests.dash.
"""

from tests.common.helpers.sairedis_utils import (  # noqa: F401
    DEFAULT_EXCLUDE_OPS,
    DEFAULT_REC_PATH,
    OPERATION_MAP,
    SaiObjectChange,
    SaiRedisChanges,
    get_sairedis_line_count,
    iter_changes,
    parse_sairedis_changes,
    parse_sairedis_text,
    sairedis_rec_paths,
)

__all__ = [
    "DEFAULT_EXCLUDE_OPS",
    "DEFAULT_REC_PATH",
    "OPERATION_MAP",
    "SaiObjectChange",
    "SaiRedisChanges",
    "get_sairedis_line_count",
    "iter_changes",
    "parse_sairedis_changes",
    "parse_sairedis_text",
    "sairedis_rec_paths",
]
