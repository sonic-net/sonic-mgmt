"""Static configuration for ``presearch_filter``.

Kept in its own module so the blocklist can be edited / generated without
touching the filter logic.  Long-term we want this driven from a Kusto
query (e.g. nightly job populates a ``PRBinarySearchBlocklist`` table);
for now it is a curated static set, re-evaluated quarterly with the
following query::

    PRBinarySearchResult
    | where UploadTime > ago(30d) and SearchCompleted == true
    | summarize Bad = countif(RootCauseType == 'bad_commit'),
                Unknown = countif(RootCauseType == 'unknown')
        by TestCase, CheckerType
    | where Bad == 0 and Unknown >= 8
    | order by Unknown desc
"""
from __future__ import annotations

# (TestCase, CheckerType) — tests with >=8 unknown searches and 0
# bad_commit findings over the trailing 30 days, confirmed by the
# historical replay in tests/replay_presearch_filter.py.
STATIC_BLOCKLIST: set[tuple[str, str]] = {
    ("test_counterpoll_queue_watermark_pg_drop", "t1-multi-asic_checker"),
    ("test_bgp_router_id_set_without_loopback", "t1_checker"),
    ("test_iface_namingmode", "t1_checker"),
    ("test_vxlan_underlay_ecmp", "t1_checker"),
}
