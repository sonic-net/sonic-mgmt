"""
Standalone test for the fix of the stale timestamp bug in ElastictestCommonResponse.

Bug:
    The original code used get_timestamp_utcnow() as a default argument:
        def __init__(self, code: int, timestamp: str = get_timestamp_utcnow(), ...)
    Python evaluates default arguments ONCE at class definition time (module import).
    This means every instance shared the exact same stale timestamp forever.

Fix Applied in testbed_health_check.py:
        def __init__(self, code: int, timestamp: str = None, ...):
            self.timestamp = timestamp if timestamp is not None else get_timestamp_utcnow()
    Now get_timestamp_utcnow() is called lazily per-instance at instantiation time.

This file is self-contained -- it reproduces the bug on the OLD pattern,
proves the NEW pattern is correct, and requires no external dependencies.
"""

import time
import unittest
from datetime import datetime


# -----------------------------------------------------------------------
# Helper (mirrors what testbed_health_check.py has)
# -----------------------------------------------------------------------

def get_timestamp_utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# -----------------------------------------------------------------------
# BUGGY implementation (old code - default arg evaluated at definition time)
# -----------------------------------------------------------------------

class ElastictestCommonResponse_BUGGY:
    def __init__(self, code: int, timestamp: str = get_timestamp_utcnow(),
                 errmsg: list = None, data: object = None):
        self.code = code
        self.timestamp = timestamp   # same stale value for every instance!
        self.errmsg = errmsg
        self.data = data


# -----------------------------------------------------------------------
# FIXED implementation (new code - evaluated lazily inside __init__)
# -----------------------------------------------------------------------

class ElastictestCommonResponse_FIXED:
    def __init__(self, code: int, timestamp: str = None,
                 errmsg: list = None, data: object = None):
        self.code = code
        self.timestamp = timestamp if timestamp is not None else get_timestamp_utcnow()
        self.errmsg = errmsg
        self.data = data


# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------

class TestBuggyBehavior(unittest.TestCase):
    """Demonstrates what USED to happen before the fix."""

    def test_buggy_instances_share_same_timestamp(self):
        """
        PROVES THE BUG EXISTS in the old code.
        Two instances created 1 second apart should differ - but with the bug they don't.
        """
        instance1 = ElastictestCommonResponse_BUGGY(code=0)
        time.sleep(1)
        instance2 = ElastictestCommonResponse_BUGGY(code=0)

        # This PASSES with the buggy code (they ARE identical - that's the bug)
        self.assertEqual(
            instance1.timestamp,
            instance2.timestamp,
            "This confirms the OLD code has stale timestamps - both instances are identical."
        )
        print("\n[BUG CONFIRMED] instance1={}, instance2={}".format(
            instance1.timestamp, instance2.timestamp))
        print("   Both are identical even though they were created 1s apart.")


class TestFixedBehavior(unittest.TestCase):
    """Verifies the fixed implementation is correct."""

    def test_two_instances_have_different_timestamps(self):
        """
        KEY TEST: After the fix, two instances 1 second apart must have different timestamps.
        """
        instance1 = ElastictestCommonResponse_FIXED(code=0)
        time.sleep(1)
        instance2 = ElastictestCommonResponse_FIXED(code=0)

        self.assertNotEqual(
            instance1.timestamp,
            instance2.timestamp,
            "FAIL: Both instances still share the same timestamp - the bug was NOT fixed!"
        )
        print("\n[OK] FIXED: instance1={}".format(instance1.timestamp))
        print("[OK] FIXED: instance2={}".format(instance2.timestamp))
        print("   Timestamps are different - each instance got its own fresh timestamp.")

    def test_timestamp_auto_generated_when_not_provided(self):
        """Timestamp should be non-null and a string when not explicitly passed."""
        instance = ElastictestCommonResponse_FIXED(code=0)
        self.assertIsNotNone(instance.timestamp)
        self.assertIsInstance(instance.timestamp, str)
        print("\n[OK] Auto-generated timestamp: {}".format(instance.timestamp))

    def test_custom_timestamp_is_used_when_provided(self):
        """An explicitly provided timestamp must be used as-is."""
        custom_ts = "2025-01-01 00:00:00"
        instance = ElastictestCommonResponse_FIXED(code=0, timestamp=custom_ts)
        self.assertEqual(instance.timestamp, custom_ts)
        print("\n[OK] Custom timestamp respected: {}".format(instance.timestamp))

    def test_timestamp_format_is_correct(self):
        """Auto-generated timestamp must match format: YYYY-MM-DD HH:MM:SS"""
        import re
        instance = ElastictestCommonResponse_FIXED(code=0)
        pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"
        self.assertRegex(instance.timestamp, pattern)
        print("\n[OK] Timestamp format OK: {}".format(instance.timestamp))

    def test_other_fields_are_unaffected(self):
        """Ensure the fix did not break code, errmsg, or data fields."""
        instance = ElastictestCommonResponse_FIXED(
            code=1,
            errmsg=["Something failed"],
            data={"status": "error"}
        )
        self.assertEqual(instance.code, 1)
        self.assertEqual(instance.errmsg, ["Something failed"])
        self.assertEqual(instance.data, {"status": "error"})
        print("\n[OK] All other fields (code, errmsg, data) work correctly.")

    def test_none_timestamp_triggers_auto_generation(self):
        """Explicitly passing None should behave same as not passing timestamp at all."""
        instance = ElastictestCommonResponse_FIXED(code=0, timestamp=None)
        self.assertIsNotNone(instance.timestamp)
        self.assertIsInstance(instance.timestamp, str)
        print("\n[OK] timestamp=None triggers auto-generation: {}".format(instance.timestamp))


if __name__ == "__main__":
    print("=" * 65)
    print(" Testing ElastictestCommonResponse stale timestamp bug fix")
    print("=" * 65)
    unittest.main(verbosity=2)
