"""Unit tests for HFT InfluxDB utilities.

Run with::

    python3 -m pytest --noconftest \
        tests/common/unit_tests/fixtures/unit_test_hft_utilities.py -v
"""

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3]
               / "high_frequency_telemetry" / "utilities.py")


def _load_target_module():
    ptf = types.ModuleType("ptf")
    ptf.testutils = types.ModuleType("ptf.testutils")

    natsort = types.ModuleType("natsort")
    natsort.natsorted = sorted

    assertions = types.ModuleType("tests.common.helpers.assertions")

    def pytest_assert(condition, message=None):
        if not condition:
            pytest.fail(str(message))

    assertions.pytest_assert = pytest_assert

    common_utilities = types.ModuleType("tests.common.utilities")
    common_utilities.wait_until = lambda *args, **kwargs: True

    stubs = {
        "ptf": ptf,
        "ptf.testutils": ptf.testutils,
        "natsort": natsort,
        "tests.common.helpers.assertions": assertions,
        "tests.common.utilities": common_utilities,
    }
    originals = {name: sys.modules.get(name) for name in stubs}
    try:
        sys.modules.update(stubs)
        spec = importlib.util.spec_from_file_location(
            "unit_target_hft_utilities", MODULE_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in originals.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


@pytest.fixture(scope="module")
def hft_utilities():
    return _load_target_module()


class FakeClock:
    """Deterministic stand-in for the time functions used while draining."""

    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _draining_sink(hft_utilities, monkeypatch, totals):
    """Return a sink whose stored sample totals follow ``totals``."""
    sink = hft_utilities.InfluxDbSink(ptfhost=None, bucket="hft_test_1")
    remaining = iter(totals)
    state = {"total": None}

    def total_points():
        # Keep reporting the last total once the sequence is exhausted.
        state["total"] = next(remaining, state["total"])
        return state["total"]

    monkeypatch.setattr(sink, "total_points", total_points)
    clock = FakeClock()
    monkeypatch.setattr(hft_utilities, "time", clock)
    return sink, clock


def test_drain_returns_once_no_sample_arrives_for_quiet_period(
        hft_utilities, monkeypatch):
    sink, clock = _draining_sink(hft_utilities, monkeypatch, [5, 9, 12])

    assert sink.wait_until_drained(
        quiet_period=3, timeout=30, poll_interval=1
    ) == 12
    # The last new sample arrives at t=2, so the database settles at t=5.
    assert clock.now == 5


def test_drain_accepts_a_database_that_never_receives_samples(
        hft_utilities, monkeypatch):
    sink, clock = _draining_sink(hft_utilities, monkeypatch, [0])

    assert sink.wait_until_drained(
        quiet_period=3, timeout=30, poll_interval=1
    ) == 0
    assert clock.now == 3


def test_drain_times_out_while_samples_keep_arriving(
        hft_utilities, monkeypatch):
    sink, clock = _draining_sink(hft_utilities, monkeypatch, range(100))

    with pytest.raises(AssertionError, match="did not drain within 10s"):
        sink.wait_until_drained(quiet_period=3, timeout=10, poll_interval=1)
    assert clock.now == 10


def test_total_points_counts_every_measurement(hft_utilities, monkeypatch):
    sink = hft_utilities.InfluxDbSink(ptfhost=None, bucket="hft_test_1")
    measurements = ["SAI_QUEUE_STAT_BYTES", "SAI_PORT_STAT_IF_IN_OCTETS"]
    counts = {
        "SAI_PORT_STAT_IF_IN_OCTETS": 7,
        "SAI_QUEUE_STAT_BYTES": 5,
    }
    queries = []

    def query(statement):
        queries.append(statement)
        if statement == "SHOW MEASUREMENTS":
            return {"results": [{"series": [{
                "name": "measurements",
                "columns": ["name"],
                "values": [[name] for name in measurements],
            }]}]}
        return {"results": [
            {"series": [{
                "name": name,
                "columns": ["time", "sample_count"],
                "values": [["1970-01-01T00:00:00Z", count]],
            }]}
            for name, count in sorted(counts.items())
        ]}

    monkeypatch.setattr(sink, "_query", query)

    assert sink.total_points() == 12
    assert queries[1] == ";".join(
        f'SELECT COUNT("gauge") AS "sample_count" FROM "{name}"'
        for name in sorted(counts)
    )


def test_total_points_of_an_empty_database_is_zero(hft_utilities, monkeypatch):
    sink = hft_utilities.InfluxDbSink(ptfhost=None, bucket="hft_test_1")
    query = MagicMock(return_value={"results": [{"statement_id": 0}]})
    monkeypatch.setattr(sink, "_query", query)

    assert sink.total_points() == 0
    query.assert_called_once_with("SHOW MEASUREMENTS")
