"""Unit tests for tests/common/portstat_utilities counter helpers.

Run with:
    python3 -m pytest --noconftest tests/common/unit_tests/unit_test_portstat_utilities.py -v
"""
import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "common/portstat_utilities.py"


def _load_target_module():
    """Load portstat_utilities by path; importing tests.common pulls in paramiko."""
    spec = importlib.util.spec_from_file_location("portstat_utilities_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_portstat = _load_target_module()
counter_value = _portstat.counter_value
sum_ifaces_counts = _portstat.sum_ifaces_counts


COUNTERS = {
    "Ethernet0": {"rx_ok": "1,234", "rx_drp": "N/A", "tx_ok": "0"},
    "Ethernet4": {"rx_ok": "6", "tx_ok": "5"},
}


@pytest.mark.parametrize("iface,column,expected", [
    ("Ethernet0", "rx_ok", 1234),      # thousands separators are stripped
    ("Ethernet0", "tx_ok", 0),         # zero is a value, not "missing"
    ("Ethernet0", "rx_drp", None),     # no COUNTERS_DB entry yet
])
def test_counter_value(iface, column, expected):
    assert counter_value(COUNTERS, iface, column) == expected


@pytest.mark.parametrize("ifaces,column,expected", [
    (["Ethernet0", "Ethernet4"], "tx_ok", 5),
    (["Ethernet4"], "rx_ok", 6),
    ([], "tx_ok", 0),                 # nothing to sum is zero, not unpublished
    (["Ethernet0"], "rx_drp", None),  # one unpublished interface makes the sum unknown
])
def test_sum_ifaces_counts(ifaces, column, expected):
    assert sum_ifaces_counts(COUNTERS, ifaces, column) == expected
