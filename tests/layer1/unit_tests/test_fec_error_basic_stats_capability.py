"""Regression tests for the Layer-1 FEC basic-statistics override."""

import pytest

from tests.layer1 import test_fec_error


pytestmark = [pytest.mark.topology("any")]


class _FakeDut:
    def __init__(self, rows):
        self._rows = rows
        self.commands = []

    def get_speed(self, interface):
        return "400000"

    def show_and_parse(self, command):
        self.commands.append(command)
        assert command == "show interfaces counters fec-stats"
        return self._rows


def _run_stats_test(monkeypatch, row, port_attrs):
    duthost = _FakeDut([row])
    waits = []
    monkeypatch.setattr(
        test_fec_error,
        "get_fec_candidate_interfaces",
        lambda unused_dut: {"Ethernet0": "400G"},
    )
    monkeypatch.setattr(
        test_fec_error,
        "clear_interface_counters_and_wait",
        lambda unused_dut, wait_time=60: waits.append(wait_time),
    )

    test_fec_error.test_verify_fec_stats_counters(
        {"dut": duthost},
        "dut",
        port_attrs,
    )
    return duthost, waits


def _false_basic_stats_attrs():
    return {
        "Ethernet0": {
            "FEC_ATTRIBUTES": {
                "basic_fec_stats_supported": False,
            }
        }
    }


def test_basic_stats_false_ignores_only_basic_counters(monkeypatch):
    duthost, waits = _run_stats_test(
        monkeypatch,
        {
            "iface": "Ethernet0",
            "fec_corr": "invalid",
            "fec_uncorr": "invalid",
            "fec_symbol_err": "invalid",
            "flr(o)": "0",
            "flr(p) (accuracy)": "0",
        },
        _false_basic_stats_attrs(),
    )

    assert duthost.commands == ["show interfaces counters fec-stats"]
    assert waits == [60]


def test_basic_stats_false_does_not_mask_flr_validation(monkeypatch):
    with pytest.raises(
        pytest.fail.Exception,
        match="fec_flr is not a valid float",
    ):
        _run_stats_test(
            monkeypatch,
            {
                "iface": "Ethernet0",
                "fec_corr": "invalid",
                "fec_uncorr": "invalid",
                "fec_symbol_err": "invalid",
                "flr(o)": "invalid",
                "flr(p) (accuracy)": "0",
            },
            _false_basic_stats_attrs(),
        )


def test_omitted_override_preserves_basic_stats_validation(monkeypatch):
    with pytest.raises(
        pytest.fail.Exception,
        match="FEC stat counters are not valid integers",
    ):
        _run_stats_test(
            monkeypatch,
            {
                "iface": "Ethernet0",
                "fec_corr": "invalid",
                "fec_uncorr": "0",
                "fec_symbol_err": "0",
                "flr(o)": "0",
                "flr(p) (accuracy)": "0",
            },
            {},
        )
