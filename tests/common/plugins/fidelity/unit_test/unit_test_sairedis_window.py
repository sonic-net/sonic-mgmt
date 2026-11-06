#!/usr/bin/env python3
"""
Standalone unit tests for inode-aware sairedis windowing.

Run with:
    python3 tests/common/plugins/fidelity/unit_test/unit_test_sairedis_window.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.dirname(HERE)
sys.path.insert(0, PLUGIN_DIR)

import sairedis_window as sw  # noqa: E402


class TestCollectDeltaLocal(unittest.TestCase):
    def test_ok_same_inode_tail(self):
        active = "/var/log/swss/sairedis.rec"
        text0 = "a\nb\nc\n"
        text1 = "a\nb\nc\nd\ne\n"
        snap = sw.RecSnapshot(path=active, inode=100, size=len(text0), lines=3)
        family = [
            sw.FileMeta(path=active, inode=100, size=len(text1), rot_index=0),
        ]
        readers = {active: text1}
        result = sw.collect_delta_local(snap, family=family, readers=readers)
        self.assertEqual(result.status, sw.STATUS_OK)
        self.assertEqual(result.text, "d\ne\n")

    def test_stitched_after_rotate(self):
        active = "/var/log/swss/sairedis.rec"
        old = "/var/log/swss/sairedis.rec.1"
        # Started with 2 lines on inode 100
        snap = sw.RecSnapshot(path=active, inode=100, size=10, lines=2)
        # After rotate: inode 100 is .1 (has lines a,b,c), active inode 200 (d,e)
        old_text = "a\nb\nc\n"
        new_text = "d\ne\n"
        family = [
            sw.FileMeta(path=active, inode=200, size=len(new_text), rot_index=0),
            sw.FileMeta(path=old, inode=100, size=len(old_text), rot_index=1),
        ]
        readers = {active: new_text, old: old_text}
        result = sw.collect_delta_local(snap, family=family, readers=readers)
        self.assertEqual(result.status, sw.STATUS_STITCHED)
        self.assertEqual(result.text, "c\nd\ne\n")

    def test_history_lost(self):
        active = "/var/log/swss/sairedis.rec"
        snap = sw.RecSnapshot(path=active, inode=100, size=10, lines=5)
        family = [
            sw.FileMeta(path=active, inode=999, size=20, rot_index=0),
        ]
        readers = {active: "x\ny\n"}
        result = sw.collect_delta_local(snap, family=family, readers=readers)
        self.assertEqual(result.status, sw.STATUS_HISTORY_LOST)

    def test_recorder_reset(self):
        active = "/var/log/swss/sairedis.rec"
        snap = sw.RecSnapshot(path=active, inode=100, size=10, lines=5)
        family = [
            sw.FileMeta(path=active, inode=999, size=50, rot_index=0),
        ]
        readers = {
            active: "2024-01-01.00:00:00.000000|#|recording on: /var/log/swss/sairedis.rec\n"
        }
        result = sw.collect_delta_local(snap, family=family, readers=readers)
        self.assertEqual(result.status, sw.STATUS_RECORDER_RESET)

    def test_truncated(self):
        active = "/var/log/swss/sairedis.rec"
        snap = sw.RecSnapshot(path=active, inode=100, size=100, lines=10)
        family = [
            sw.FileMeta(path=active, inode=100, size=5, rot_index=0),
        ]
        readers = {active: "a\nb\n"}
        result = sw.collect_delta_local(snap, family=family, readers=readers)
        self.assertEqual(result.status, sw.STATUS_TRUNCATED)

    def test_two_rotates_stitch(self):
        active = "/var/log/swss/sairedis.rec"
        r1 = active + ".1"
        r2 = active + ".2"
        snap = sw.RecSnapshot(path=active, inode=50, size=10, lines=1)
        # inode 50 now at .2; .1 and active are newer
        family = [
            sw.FileMeta(path=active, inode=70, size=10, rot_index=0),
            sw.FileMeta(path=r1, inode=60, size=10, rot_index=1),
            sw.FileMeta(path=r2, inode=50, size=10, rot_index=2),
        ]
        readers = {
            r2: "old0\nold1\n",
            r1: "mid0\n",
            active: "new0\n",
        }
        result = sw.collect_delta_local(snap, family=family, readers=readers)
        self.assertEqual(result.status, sw.STATUS_STITCHED)
        self.assertEqual(result.text, "old1\nmid0\nnew0\n")

    def test_unreliable_empty_set(self):
        self.assertIn(sw.STATUS_HISTORY_LOST, sw.UNRELIABLE_EMPTY)
        self.assertNotIn(sw.STATUS_OK, sw.UNRELIABLE_EMPTY)
        self.assertNotIn(sw.STATUS_STITCHED, sw.UNRELIABLE_EMPTY)

    def test_rotation_index(self):
        active = "/var/log/swss/sairedis.rec"
        self.assertEqual(sw.rotation_index(active, active), 0)
        self.assertEqual(sw.rotation_index(active, active + ".1"), 1)
        self.assertEqual(sw.rotation_index(active, active + ".2.gz"), 2)


class TestCollectDeltaOnDisk(unittest.TestCase):
    def test_ok_and_stitched_with_real_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            active = os.path.join(tmp, "sairedis.rec")
            with open(active, "w") as fh:
                fh.write("l0\nl1\nl2\n")
            st = os.stat(active)
            snap = sw.RecSnapshot(
                path=active, inode=st.st_ino, size=st.st_size, lines=2
            )
            # Append more lines (same inode)
            with open(active, "a") as fh:
                fh.write("l3\n")
            result = sw.collect_delta_local(snap)
            self.assertEqual(result.status, sw.STATUS_OK)
            self.assertEqual(result.text, "l2\nl3\n")

            # Simulate rotate: rename to .1, new active
            old = active + ".1"
            os.rename(active, old)
            with open(active, "w") as fh:
                fh.write("new0\nnew1\n")
            # snap still points at old inode (now .1), lines=2
            # After rename, .1 has l0,l1,l2 — wait we had appended l3 before rename
            # File at rename time had l0,l1,l2,l3. snap.lines=2 → remainder l2,l3 + new
            result2 = sw.collect_delta_local(snap)
            self.assertEqual(result2.status, sw.STATUS_STITCHED)
            self.assertIn("l2\n", result2.text)
            self.assertIn("l3\n", result2.text)
            self.assertIn("new0\n", result2.text)


if __name__ == "__main__":
    unittest.main()
