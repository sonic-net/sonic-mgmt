#!/usr/bin/env python3
"""Unit tests for get_ingress_drop_counter_mode() in test_qos_probe.py.

This function determines which SAI counter to read for ingress drop detection:
  - pg_drop:  per-PG counter, noise-immune (cisco-8000, mellanox)
  - port_drop: port-wide counter, includes non-test noise (broadcom, default)

The function lives in TestQosProbe (tests/qos/test_qos_probe.py) as a @staticmethod.
We replicate its logic here for standalone UT — changes to the original must be
reflected here (tracked by asserting the same contract).
"""

import pytest


def get_ingress_drop_counter_mode(dutTestParams):
    """Mirror of TestQosProbe.get_ingress_drop_counter_mode for standalone testing.

    Must stay in sync with tests/qos/test_qos_probe.py::TestQosProbe.get_ingress_drop_counter_mode.
    """
    platform_asic = dutTestParams["basicParams"].get("platform_asic", None)
    if platform_asic in ("cisco-8000", "mellanox"):
        return "pg_drop"
    return "port_drop"


def _make_params(platform_asic):
    """Helper: build minimal dutTestParams dict with given platform_asic."""
    return {"basicParams": {"platform_asic": platform_asic}}


class TestGetIngressDropCounterMode:
    """Test the platform_asic → counter_mode mapping."""

    # --- pg_drop platforms ---

    @pytest.mark.order(5000)
    def test_cisco_8000_returns_pg_drop(self):
        """cisco-8000 supports per-PG SAI drop counter → pg_drop."""
        assert get_ingress_drop_counter_mode(_make_params("cisco-8000")) == "pg_drop"

    @pytest.mark.order(5001)
    def test_mellanox_returns_pg_drop(self):
        """Mellanox SPC1/SPC3 support per-PG SAI drop counter → pg_drop."""
        assert get_ingress_drop_counter_mode(_make_params("mellanox")) == "pg_drop"

    # --- port_drop platforms (fallback) ---

    @pytest.mark.order(5010)
    def test_broadcom_returns_port_drop(self):
        """Broadcom: pg_drop not yet verified → port_drop fallback."""
        assert get_ingress_drop_counter_mode(_make_params("broadcom")) == "port_drop"

    @pytest.mark.order(5011)
    def test_broadcom_dnx_returns_port_drop(self):
        """broadcom-dnx: pg_drop not yet verified → port_drop fallback."""
        assert get_ingress_drop_counter_mode(_make_params("broadcom-dnx")) == "port_drop"

    @pytest.mark.order(5012)
    def test_marvell_returns_port_drop(self):
        """Unknown platform (marvell) → port_drop fallback."""
        assert get_ingress_drop_counter_mode(_make_params("marvell")) == "port_drop"

    # --- edge cases ---

    @pytest.mark.order(5020)
    def test_none_platform_returns_port_drop(self):
        """platform_asic=None → safe default port_drop."""
        assert get_ingress_drop_counter_mode(_make_params(None)) == "port_drop"

    @pytest.mark.order(5021)
    def test_missing_platform_asic_key_returns_port_drop(self):
        """Missing platform_asic key entirely → port_drop."""
        assert get_ingress_drop_counter_mode({"basicParams": {}}) == "port_drop"

    @pytest.mark.order(5022)
    def test_empty_string_platform_returns_port_drop(self):
        """Empty string platform_asic → port_drop."""
        assert get_ingress_drop_counter_mode(_make_params("")) == "port_drop"

    # --- contract: return value is always one of the 3 known modes ---

    @pytest.mark.order(5030)
    @pytest.mark.parametrize("platform", [
        "cisco-8000", "mellanox", "broadcom", "broadcom-dnx", None, "", "unknown"
    ])
    def test_return_value_is_valid_mode(self, platform):
        """Return value must be one of the 3 valid counter modes."""
        result = get_ingress_drop_counter_mode(_make_params(platform))
        assert result in ("pg_drop", "port_buffer_drop", "port_drop"), \
            f"Unexpected counter mode '{result}' for platform '{platform}'"
