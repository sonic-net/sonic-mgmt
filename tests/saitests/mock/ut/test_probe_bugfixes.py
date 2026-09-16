"""
Unit tests for probe bug fixes:
  1. HeadroomPoolProbe: updateTestPortIdIp positional-arg fix (qosParams keyword)
  2. EgressDropProbe: lossy_queue fallback to dutQosConfig["param"] level

These tests validate the fix logic in isolation without importing the full
TestQosProbe class (which requires heavy fixtures from QosSaiBase).
"""
import pytest


# ---------------------------------------------------------------------------
# Fix 1: updateTestPortIdIp positional-arg
# ---------------------------------------------------------------------------
# The function signature is:
#   updateTestPortIdIp(self, dutConfig, get_src_dst_asic_and_duts,
#                      portSpeedCableLength=None, qosParams=None)
#
# Bug: the call site passed qosConfig["hdrm_pool_size"] as the 3rd positional
#      arg, binding it to portSpeedCableLength instead of qosParams.
# Fix: use keyword arg qosParams=qosConfig["hdrm_pool_size"]

def _simulate_updateTestPortIdIp(portSpeedCableLength=None, qosParams=None):
    """Simulate the function to verify which parameter receives the value."""
    return {"portSpeedCableLength": portSpeedCableLength, "qosParams": qosParams}


class TestPositionalArgFix:
    """Verify that hdrm_pool_size dict reaches qosParams, not portSpeedCableLength."""

    def test_buggy_positional_call(self):
        """OLD code: 3rd positional arg goes to portSpeedCableLength (wrong)."""
        hdrm_data = {"src_port_ids": [0, 1], "dst_port_id": 2}
        result = _simulate_updateTestPortIdIp(hdrm_data)  # positional
        assert result["portSpeedCableLength"] == hdrm_data, \
            "Positional call should bind to portSpeedCableLength (the bug)"
        assert result["qosParams"] is None

    def test_fixed_keyword_call(self):
        """NEW code: keyword arg goes to qosParams (correct)."""
        hdrm_data = {"src_port_ids": [0, 1], "dst_port_id": 2}
        result = _simulate_updateTestPortIdIp(qosParams=hdrm_data)  # keyword
        assert result["qosParams"] == hdrm_data, \
            "Keyword call should bind to qosParams (the fix)"
        assert result["portSpeedCableLength"] is None

    def test_both_params_independent(self):
        """Both parameters can be set independently."""
        result = _simulate_updateTestPortIdIp(
            portSpeedCableLength="100000_3m", qosParams={"key": "val"})
        assert result["portSpeedCableLength"] == "100000_3m"
        assert result["qosParams"] == {"key": "val"}

    def test_no_args_defaults(self):
        """Both default to None."""
        result = _simulate_updateTestPortIdIp()
        assert result["portSpeedCableLength"] is None
        assert result["qosParams"] is None


# ---------------------------------------------------------------------------
# Fix 2: EgressDropProbe lossy_queue fallback
# ---------------------------------------------------------------------------
# Replicate the fixed lookup logic from testQosEgressDropProbe:
#   1) Look in speed-specific qosConfig (dutQosConfig["param"][speedCableLen])
#   2) If not found, fall back to dutQosConfig["param"] (top-level)
#   3) If still not found, pytest.skip
#
# Keep in sync with: tests/qos/test_qos_probe.py :: testQosEgressDropProbe

def _resolve_lossy_profile(dutQosConfig, portSpeedCableLength, lossyProfile):
    """Replicate the fixed lossy profile lookup logic.

    Returns (qosConfig_dict, skipped_reason_or_None).
    """
    qosConfig = dutQosConfig["param"][portSpeedCableLength]
    if lossyProfile not in qosConfig:
        qosConfig = dutQosConfig["param"]
        if lossyProfile not in qosConfig:
            return None, f"{lossyProfile} is not defined in QoS config"
    return qosConfig, None


class TestLossyQueueFallback:
    """Verify lossy_queue_1 lookup with 2-level fallback."""

    @pytest.fixture
    def broadcom_config(self):
        """Broadcom: lossy_queue_1 is inside the speed-specific sub-dict."""
        return {
            "param": {
                "100000_3m": {
                    "lossy_queue_1": {"dscp": 8, "ecn": 1, "pg": 0},
                    "other_key": "value",
                },
            }
        }

    @pytest.fixture
    def mellanox_config(self):
        """Mellanox: lossy_queue_1 is at the top-level param dict,
        not inside the per-speed sub-dict."""
        return {
            "param": {
                "100000_3m": {
                    "headroom_pool_size": "1024",
                },
                "lossy_queue_1": {"dscp": 8, "ecn": 1, "pg": 0},
            }
        }

    @pytest.fixture
    def missing_config(self):
        """Neither level has lossy_queue_1."""
        return {
            "param": {
                "100000_3m": {
                    "headroom_pool_size": "1024",
                },
            }
        }

    def test_broadcom_direct_lookup(self, broadcom_config):
        """Broadcom: found in speed-specific sub-dict (no fallback needed)."""
        cfg, skip = _resolve_lossy_profile(broadcom_config, "100000_3m", "lossy_queue_1")
        assert skip is None
        assert "lossy_queue_1" in cfg
        assert cfg is broadcom_config["param"]["100000_3m"]

    def test_mellanox_fallback_to_param(self, mellanox_config):
        """Mellanox: NOT in speed sub-dict, found at param level (fallback)."""
        cfg, skip = _resolve_lossy_profile(mellanox_config, "100000_3m", "lossy_queue_1")
        assert skip is None
        assert "lossy_queue_1" in cfg
        assert cfg is mellanox_config["param"]

    def test_missing_skip(self, missing_config):
        """Neither level has lossy_queue_1 → skip."""
        cfg, skip = _resolve_lossy_profile(missing_config, "100000_3m", "lossy_queue_1")
        assert cfg is None
        assert "not defined" in skip

    def test_mellanox_speed_dict_untouched(self, mellanox_config):
        """Verify fallback doesn't modify the speed-specific dict."""
        speed_dict_before = dict(mellanox_config["param"]["100000_3m"])
        _resolve_lossy_profile(mellanox_config, "100000_3m", "lossy_queue_1")
        assert mellanox_config["param"]["100000_3m"] == speed_dict_before

    def test_custom_profile_name(self):
        """Fallback works for any profile name, not just lossy_queue_1."""
        config = {
            "param": {
                "50000_1m": {},
                "custom_lossy": {"dscp": 10},
            }
        }
        cfg, skip = _resolve_lossy_profile(config, "50000_1m", "custom_lossy")
        assert skip is None
        assert cfg["custom_lossy"]["dscp"] == 10

    def test_profile_in_both_levels_prefers_speed(self):
        """If profile exists in BOTH levels, speed-specific takes precedence."""
        config = {
            "param": {
                "100000_3m": {
                    "lossy_queue_1": {"dscp": 8, "source": "speed"},
                },
                "lossy_queue_1": {"dscp": 8, "source": "param"},
            }
        }
        cfg, skip = _resolve_lossy_profile(config, "100000_3m", "lossy_queue_1")
        assert skip is None
        assert cfg["lossy_queue_1"]["source"] == "speed", \
            "Speed-specific config should take precedence over param-level"


class TestLossyQueueEdgeCases:
    """Edge cases for the fallback logic."""

    def test_empty_speed_dict(self):
        """Speed dict is empty → falls back to param level."""
        config = {
            "param": {
                "100000_3m": {},
                "lossy_queue_1": {"dscp": 8},
            }
        }
        cfg, skip = _resolve_lossy_profile(config, "100000_3m", "lossy_queue_1")
        assert skip is None
        assert cfg is config["param"]

    def test_empty_param_dict_skips(self):
        """Param-level also has nothing → skip."""
        config = {
            "param": {
                "100000_3m": {},
            }
        }
        _, skip = _resolve_lossy_profile(config, "100000_3m", "lossy_queue_1")
        assert skip is not None

    def test_breakout_sku_scenario(self):
        """Simulates breakout SKU where config comes from ["breakout"] sub-key.
        The fallback still applies the same way."""
        config = {
            "param": {
                "100000_3m": {
                    "breakout": {
                        # In real code, qosConfig = this breakout dict
                    }
                },
                "lossy_queue_1": {"dscp": 8},
            }
        }
        # Simulating: qosConfig = config["param"]["100000_3m"]["breakout"]
        breakout_config = config["param"]["100000_3m"]["breakout"]
        if "lossy_queue_1" not in breakout_config:
            fallback = config["param"]
            assert "lossy_queue_1" in fallback
