"""
Unit tests for PfcXonProbing class (orchestrator).

Tests PfcXonProbing by directly instantiating the class and setting attributes manually.
Mirrors test_pfc_xoff_probing.py pattern.
"""

import pytest
import sys
from unittest.mock import Mock, MagicMock

# Mock PTF and SAI dependencies before importing
sys.modules['ptf'] = MagicMock()
sys.modules['ptf.testutils'] = MagicMock()
sys.modules['switch'] = MagicMock()
sys.modules['sai_qos_tests'] = MagicMock()
sys.modules['stream_manager'] = MagicMock()
sys.modules['buffer_occupancy_controller'] = MagicMock()

# CRITICAL: Match test_pfc_xoff_probing.py pattern - use object as base
mock_sai_base = MagicMock()
mock_sai_base.ThriftInterfaceDataPlane = object
sys.modules['sai_base_test'] = mock_sai_base

from pfc_xon_probing import PfcXonProbing  # noqa: E402
from probing_base import ProbeConfig  # noqa: E402


class TestPfcXonProbingInstance(PfcXonProbing):
    """Test-friendly PfcXonProbing without PTF dependencies."""

    def __init__(self):
        # Don't call super().__init__() to avoid PTF initialization
        self.test_params = {}
        self.pg = 3
        self.dscp = 3
        self.ecn = 1
        self.probing_port_ids = [24, 28, 29]
        self.dataplane = Mock()
        self.dst_client = Mock()
        self.asic_type = 'broadcom'
        self.test_port_ips = {0: {0: {
            24: {"peer_addr": "10.0.0.1", "vlan_id": 100},
            28: {"peer_addr": "10.0.0.2", "vlan_id": 100},
            29: {"peer_addr": "10.0.0.3", "vlan_id": 100},
        }}}
        self.stream_mgr = Mock()
        self.cnt_pg_idx = None
        self.pfcxoff_point = 0
        self.enable_xon_range_probe = False
        self.xon_step_max_iter = 50
        self.xon_binary_range_limit = 32
        self.xon_binary_max_iter = 20
        self.xon_binary_step_max_iter = 50
        self.xon_verification_attempts = 2
        self.EXECUTOR_ENV = 'sim'
        self.router_mac = "00:11:22:33:44:55"
        self.is_dualtor = False
        self.def_vlan_mac = None

        def mock_get_rx_port(src_port, dst_port):
            return dst_port
        self.get_rx_port = mock_get_rx_port


class TestPfcXonProbingParameterParsing:
    """Test parse_param parses PfcXon-specific params."""

    @pytest.mark.order(1300)
    def test_parse_param_sets_cnt_pg_idx(self):
        """parse_param sets cnt_pg_idx = pg + 2."""
        pfc = TestPfcXonProbingInstance()
        pfc.pg = 3
        pfc.test_params = {"pfcxoff_point": 1000}
        pfc.parse_param()
        assert pfc.cnt_pg_idx == 5

    @pytest.mark.order(1301)
    def test_parse_param_reads_pfcxoff_point(self):
        """parse_param reads pfcxoff_point from test_params."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {"pfcxoff_point": 1500}
        pfc.parse_param()
        assert pfc.pfcxoff_point == 1500

    @pytest.mark.order(1302)
    def test_parse_param_step_algo_default(self):
        """parse_param defaults enable_xon_range_probe to False (step algo)."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {"pfcxoff_point": 1000}
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is False

    @pytest.mark.order(1303)
    def test_parse_param_binary_algo_when_flag_true(self):
        """parse_param sets binary algo when enable_xon_range_probe=True."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {"pfcxoff_point": 1000, "enable_xon_range_probe": True}
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is True

    @pytest.mark.order(1304)
    def test_parse_param_tunables(self):
        """parse_param applies user-supplied tunables."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "xon_step_max_iter": 30,
            "xon_binary_range_limit": 16,
            "xon_binary_max_iter": 25,
            "xon_binary_step_max_iter": 80,
            "xon_verification_attempts": 3,
        }
        pfc.parse_param()
        assert pfc.xon_step_max_iter == 30
        assert pfc.xon_binary_range_limit == 16
        assert pfc.xon_binary_max_iter == 25
        assert pfc.xon_binary_step_max_iter == 80
        assert pfc.xon_verification_attempts == 3


class TestPfcXonProbingConfiguration:
    """Test get_probe_config + get_expected_threshold."""

    @pytest.mark.order(1310)
    def test_get_probe_config_returns_probeconfig(self):
        """get_probe_config returns ProbeConfig with right fields."""
        pfc = TestPfcXonProbingInstance()
        pfc.probing_port_ids = [24, 28, 29]
        cfg = pfc.get_probe_config()
        assert isinstance(cfg, ProbeConfig)
        assert cfg.probing_port_ids == [24, 28, 29]
        assert cfg.asic_type == 'broadcom'

    @pytest.mark.order(1311)
    def test_get_expected_threshold_when_set(self):
        """get_expected_threshold returns tuple when expected_xon_offset present."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {"expected_xon_offset": 18}
        result = pfc.get_expected_threshold()
        assert result == (18, "XOn offset")

    @pytest.mark.order(1312)
    def test_get_expected_threshold_when_unset(self):
        """get_expected_threshold returns None when no expected value."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {}
        result = pfc.get_expected_threshold()
        assert result is None


class TestPfcXonProbingTrafficSetup:
    """Test setup_traffic input validation."""

    @pytest.mark.order(1320)
    def test_setup_traffic_skips_when_insufficient_ports(self):
        """setup_traffic returns early when fewer than 3 probing ports
        (1 src + dst_A + dst_B is the minimum)."""
        pfc = TestPfcXonProbingInstance()
        pfc.probing_port_ids = [24, 28]  # only 2 ports — need 3
        # Should return without raising and without setting up flows
        # (cannot strictly assert on stream_mgr because it was Mock from __init__)
        try:
            pfc.setup_traffic()
        except Exception as e:
            pytest.fail(f"setup_traffic should not raise on insufficient ports: {e}")


class TestPfcXonProbingProbeAttributes:
    """Test probe() reads tunables correctly (without exercising algorithm calls)."""

    @pytest.mark.order(1330)
    def test_probe_reads_step_tunables(self):
        """parse_param + step path: tunables are stored on instance."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "enable_xon_range_probe": False,
            "xon_step_max_iter": 30,
            "xon_verification_attempts": 3,
        }
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is False
        assert pfc.xon_step_max_iter == 30
        assert pfc.xon_verification_attempts == 3

    @pytest.mark.order(1331)
    def test_probe_reads_binary_tunables(self):
        """parse_param + binary path: tunables stored."""
        pfc = TestPfcXonProbingInstance()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "xon_binary_range_limit": 16,
            "xon_binary_max_iter": 25,
            "xon_binary_step_max_iter": 80,
        }
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is True
        assert pfc.xon_binary_range_limit == 16
        assert pfc.xon_binary_max_iter == 25
        assert pfc.xon_binary_step_max_iter == 80
