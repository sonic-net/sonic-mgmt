"""Focused tests for the FDB MAC-move storm sender."""

import importlib.util
from pathlib import Path

import pytest


pytestmark = [pytest.mark.topology("any")]

MODULE_PATH = Path(__file__).resolve().parents[1] / "files" / "fdb_mac_move_storm.py"
SPEC = importlib.util.spec_from_file_location("fdb_mac_move_storm", MODULE_PATH)
STORM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORM)


def test_rate_limit_sets_time_between_interface_bursts():
    assert STORM.side_period_seconds(num_macs=4, pps=400, side_dwell=0) == 0.01


def test_side_dwell_extends_rate_period_for_scanned_fdb():
    assert STORM.side_period_seconds(num_macs=4, pps=400, side_dwell=0.02) == 0.02


def test_unlimited_mode_has_no_implicit_dwell():
    assert STORM.side_period_seconds(num_macs=4, pps=0, side_dwell=0) == 0
