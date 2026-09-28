#!/usr/bin/env python3
"""
Standalone unit tests for SAI fidelity tier_engine + sairedis parsing.

Avoids importing tests.common (pulls scapy). Run with:

    python3 tests/common/plugins/fidelity/unit_test/unit_test_tier_engine.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from dataclasses import dataclass, field
from typing import Dict

# Import plugin modules by path — do NOT import tests.common / tests.dash packages
HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.dirname(HERE)  # tests/common/plugins/fidelity
# tests/dash (four levels up from unit_test/: fidelity -> plugins -> common -> tests)
DASH_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "dash"))

sys.path.insert(0, PLUGIN_DIR)
sys.path.insert(0, DASH_DIR)

import tier_engine  # noqa: E402
import sairedis_utils  # noqa: E402


SAMPLE_REC = os.path.join(HERE, "sample_sairedis.rec")
TIER_YML = os.path.join(PLUGIN_DIR, "tier.yml")


@dataclass
class FakeChange:
    timestamp: str = ""
    operation: str = ""
    object_type: str = ""
    object_id: str = ""
    attributes: Dict[str, str] = field(default_factory=dict)
    raw_line: str = ""


class TestParseSairedisText(unittest.TestCase):
    def setUp(self):
        with open(SAMPLE_REC) as fh:
            self.text = fh.read()

    def test_default_excludes_get_stats_notify(self):
        changes = sairedis_utils.parse_sairedis_text(self.text)
        # create: route + 2 neigh (bulk) + acl_table + acl_entry + unknown = 6
        # get/stats/notify excluded by default
        self.assertEqual(len(changes.created), 6)
        self.assertEqual(len(changes.edited), 1)
        self.assertEqual(len(changes.removed), 1)
        self.assertEqual(len(changes.queried), 0)
        self.assertEqual(len(changes.stats), 0)

    def test_include_ops_keeps_get_and_stats(self):
        changes = sairedis_utils.parse_sairedis_text(
            self.text,
            include_ops=("create", "remove", "set", "get", "stats", "clearstats"),
        )
        self.assertEqual(len(changes.queried), 2)  # switch get + queue watermark get
        self.assertEqual(len(changes.stats), 1)    # port stats
        self.assertEqual(len(changes.created), 6)
        # notify still not in include_ops
        flat = sairedis_utils.iter_changes(changes)
        self.assertTrue(all(c.operation != "notify" for c in flat))

    def test_bulk_separator(self):
        changes = sairedis_utils.parse_sairedis_text(self.text)
        neigh = [
            c for c in changes.created
            if c.object_type == "SAI_OBJECT_TYPE_NEIGHBOR_ENTRY"
        ]
        self.assertEqual(len(neigh), 2)


class TestTierEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = tier_engine.load_tiers(TIER_YML)
        with open(SAMPLE_REC) as fh:
            cls.text = fh.read()
        cls.changes = sairedis_utils.parse_sairedis_text(
            cls.text,
            include_ops=("create", "remove", "set", "get", "stats", "clearstats"),
        )
        cls.flat = sairedis_utils.iter_changes(cls.changes)

    def test_weights_and_default(self):
        self.assertEqual(self.table.weights[1], 1.0)
        self.assertEqual(self.table.weights[2], 0.5)
        self.assertEqual(self.table.weights[3], 0.0)
        self.assertEqual(self.table.default_tier, 3)

    def test_route_create_tier1(self):
        change = FakeChange(
            operation="create",
            object_type="SAI_OBJECT_TYPE_ROUTE_ENTRY",
        )
        tier, rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 1)
        self.assertIn("ROUTE_ENTRY", rule)

    def test_acl_create_tier2(self):
        change = FakeChange(
            operation="create",
            object_type="SAI_OBJECT_TYPE_ACL_TABLE",
        )
        tier, rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 2)

    def test_stats_op_tier3(self):
        change = FakeChange(
            operation="stats",
            object_type="SAI_OBJECT_TYPE_PORT",
            attributes={"SAI_PORT_STAT_IF_IN_OCTETS": ""},
        )
        tier, rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 3)
        self.assertTrue(rule.startswith("op:") or "STAT" in rule)

    def test_get_op_tier3_even_on_switch(self):
        change = FakeChange(
            operation="get",
            object_type="SAI_OBJECT_TYPE_SWITCH",
            attributes={"SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID": ""},
        )
        tier, rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 3)

    def test_unknown_object_default_tier3(self):
        change = FakeChange(
            operation="create",
            object_type="SAI_OBJECT_TYPE_DOES_NOT_EXIST_YET",
        )
        with self.assertLogs("tier_engine", level="WARNING") as cm:
            tier, rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 3)
        self.assertEqual(rule, "default:unknown")
        self.assertTrue(any("default:unknown" in m for m in cm.output))

    def test_notify_skipped(self):
        change = FakeChange(
            operation="notify",
            object_type="SAI_OBJECT_TYPE_FDB_ENTRY",
        )
        tier, rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 0)
        self.assertEqual(rule, "skip:notify")

    def test_worst_tier_wins_attr_override(self):
        # PORT create is tier 1; PORT with STAT attr is tier 3
        change = FakeChange(
            operation="set",
            object_type="SAI_OBJECT_TYPE_PORT",
            attributes={"SAI_PORT_STAT_IF_IN_OCTETS": "1"},
        )
        tier, _rule = tier_engine.classify(change, self.table)
        self.assertEqual(tier, 3)

    def test_count_and_score_from_sample(self):
        counts = tier_engine.count_tiers(self.flat, self.table)
        n1, n2, n3 = counts[1], counts[2], counts[3]
        total = n1 + n2 + n3
        # Expected from sample (notify excluded):
        # route create T1
        # 2 neighbor creates T1
        # port set (ADMIN_STATE) T1
        # nexthop remove T1
        # acl table T2, acl entry T2
        # port stats T3 (op)
        # switch get T3 (op)
        # queue watermark get T3 (op)
        # unknown create T3 (default)
        # => n1=5, n2=2, n3=4, total=11
        self.assertEqual(total, 11)
        self.assertEqual(n1, 5)
        self.assertEqual(n2, 2)
        self.assertEqual(n3, 4)

        score = tier_engine.calc_score(n1, n2, n3, weights=self.table.weights)
        # (1.0*5 + 0.5*2 + 0.0*4) / 11 = 6/11 ≈ 0.5454
        self.assertIsNotNone(score)
        self.assertAlmostEqual(score, 6.0 / 11.0, places=4)

        summary = tier_engine.format_summary(n1, n2, n3, score)
        self.assertIn("11 SAI calls", summary)
        self.assertIn("5 tier 1", summary)
        self.assertIn("2 tier 2", summary)
        self.assertIn("4 tier 3", summary)
        self.assertIn("score 0.55", summary)

    def test_zero_calls_score_none(self):
        self.assertIsNone(tier_engine.calc_score(0, 0, 0))
        summary = tier_engine.format_summary(0, 0, 0, None)
        self.assertIn("no SAI activity", summary)

    def test_breakdown_includes_unknown(self):
        rows = tier_engine.object_type_breakdown(self.flat, self.table, top_n=20)
        types = {r["object_type"] for r in rows}
        self.assertIn("SAI_OBJECT_TYPE_DOES_NOT_EXIST_YET", types)
        self.assertIn("SAI_OBJECT_TYPE_ROUTE_ENTRY", types)


if __name__ == "__main__":
    unittest.main()
