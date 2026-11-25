"""Regression tests for the platform FEC basic-statistics override."""

import pytest

from tests.platform_tests import test_intf_fec


pytestmark = [pytest.mark.topology("any")]


class _FakeDut:
    def __init__(self, rows, platform="x86_64-nvidia"):
        self.facts = {"platform": platform, "platform_asic": "cisco-8000"}
        self._rows = rows
        self.commands = []

    def get_speed(self, interface):
        return "400000"

    def show_and_parse(self, command):
        self.commands.append(command)
        assert command == "show interfaces counters fec-stats"
        return self._rows


def _port_attrs(enabled):
    return {
        "Ethernet0": {
            "FEC_ATTRIBUTES": {
                "basic_fec_stats_supported": enabled,
            }
        }
    }


def _run_stats_test(monkeypatch, row, enabled=False, platform="x86_64-nvidia"):
    duthost = _FakeDut([row], platform=platform)
    waits = []
    monkeypatch.setattr(
        test_intf_fec,
        "get_fec_candidate_interfaces",
        lambda unused_dut: {"Ethernet0": "400G"},
    )
    monkeypatch.setattr(
        test_intf_fec,
        "clear_interface_counters_and_wait",
        lambda unused_dut, wait_time=60: waits.append(wait_time),
    )

    test_intf_fec.test_verify_fec_stats_counters(
        {"dut": duthost},
        "dut",
        _port_attrs(enabled),
    )
    return duthost, waits


def test_basic_stats_false_ignores_only_basic_counters(monkeypatch):
    duthost, waits = _run_stats_test(
        monkeypatch,
        {
            "iface": "Ethernet0",
            "fec_corr": "invalid",
            "fec_uncorr": "invalid",
            "fec_symbol_err": "invalid",
            "fec_pre_ber": "0",
            "fec_post_ber": "0",
        },
    )

    assert duthost.commands == ["show interfaces counters fec-stats"]
    assert waits == [60]


def test_basic_stats_false_does_not_mask_ber_validation(monkeypatch):
    with pytest.raises(
        pytest.fail.Exception,
        match="Pre-FEC and Post-FEC BER are not valid floats",
    ):
        _run_stats_test(
            monkeypatch,
            {
                "iface": "Ethernet0",
                "fec_corr": "invalid",
                "fec_uncorr": "invalid",
                "fec_symbol_err": "invalid",
                "fec_pre_ber": "invalid",
                "fec_post_ber": "0",
            },
        )


def test_basic_stats_false_does_not_enroll_unsupported_platform(monkeypatch):
    duthost = _FakeDut([], platform="unsupported-platform")
    monkeypatch.setattr(
        test_intf_fec,
        "get_fec_candidate_interfaces",
        lambda unused_dut: pytest.fail("candidate discovery must not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="test is not supported"):
        test_intf_fec.test_verify_fec_stats_counters(
            {"dut": duthost},
            "dut",
            _port_attrs(False),
        )
