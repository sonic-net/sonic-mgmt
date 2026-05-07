"""
Unit tests for PfcXonProbing class (orchestrator).

Tests PfcXonProbing by directly instantiating the class and setting attributes manually.
Mirrors test_pfc_xoff_probing.py pattern.
"""

import pytest
import sys
from unittest.mock import Mock, MagicMock, patch

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


class _PfcXonProbingFixture(PfcXonProbing):
    """Test-friendly PfcXonProbing without PTF dependencies.

    Renamed from TestPfcXonProbingInstance per r5 finding R2 to avoid
    PytestCollectionWarning (Test* prefix triggers auto-collection).
    """

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
        pfc = _PfcXonProbingFixture()
        pfc.pg = 3
        pfc.test_params = {"pfcxoff_point": 1000}
        pfc.parse_param()
        assert pfc.cnt_pg_idx == 5

    @pytest.mark.order(1301)
    def test_parse_param_reads_pfcxoff_point(self):
        """parse_param reads pfcxoff_point from test_params."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {"pfcxoff_point": 1500}
        pfc.parse_param()
        assert pfc.pfcxoff_point == 1500

    @pytest.mark.order(1302)
    def test_parse_param_step_algo_default(self):
        """parse_param defaults enable_xon_range_probe to False (step algo)."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {"pfcxoff_point": 1000}
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is False

    @pytest.mark.order(1303)
    def test_parse_param_binary_algo_when_flag_true(self):
        """parse_param sets binary algo when enable_xon_range_probe=True."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {"pfcxoff_point": 1000, "enable_xon_range_probe": True}
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is True

    @pytest.mark.order(1304)
    def test_parse_param_tunables(self):
        """parse_param applies user-supplied tunables."""
        pfc = _PfcXonProbingFixture()
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
        pfc = _PfcXonProbingFixture()
        pfc.probing_port_ids = [24, 28, 29]
        cfg = pfc.get_probe_config()
        assert isinstance(cfg, ProbeConfig)
        assert cfg.probing_port_ids == [24, 28, 29]
        assert cfg.asic_type == 'broadcom'

    @pytest.mark.order(1311)
    def test_get_expected_threshold_when_set(self):
        """get_expected_threshold returns tuple when expected_xon_offset present."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {"expected_xon_offset": 18}
        result = pfc.get_expected_threshold()
        assert result == (18, "XOn offset")

    @pytest.mark.order(1312)
    def test_get_expected_threshold_when_unset(self):
        """get_expected_threshold returns None when no expected value."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {}
        result = pfc.get_expected_threshold()
        assert result is None


class TestPfcXonProbingTrafficSetup:
    """Test setup_traffic input validation."""

    @pytest.mark.order(1320)
    def test_setup_traffic_skips_when_insufficient_ports(self):
        """setup_traffic returns early when fewer than 3 probing ports
        (1 src + dst_A + dst_B is the minimum)."""
        pfc = _PfcXonProbingFixture()
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
        pfc = _PfcXonProbingFixture()
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
        pfc = _PfcXonProbingFixture()
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


class TestPfcXonProbingDispatch:
    """Test probe() dispatches to correct algorithm and forwards args correctly.

    Per r5 finding R1: covers the orchestrator's central dispatch logic that was
    previously only validated by physical-testbed runs.

    Patches imported names within pfc_xon_probing module — does NOT conflict with
    sys.modules reset (orchestrator module is loaded once by test file's top-level
    import; conftest's reset list operates on dependencies; the orchestrator's
    already-bound import names are independently patchable).
    """

    @pytest.mark.order(1340)
    def test_probe_dispatches_to_step_when_flag_false(self):
        """probe() routes to XonDrainStepAlgorithm when enable_xon_range_probe=False."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {"pfcxoff_point": 1000, "enable_xon_range_probe": False}
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.XonDrainBinaryAlgorithm') as mock_binary, \
                patch('pfc_xon_probing.ThresholdResult') as mock_result, \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        mock_step.assert_called_once()
        mock_binary.assert_not_called()
        # Verify run() received correct args: (src=24, dst_a=28, dst_b=29, pg=3)
        mock_step.return_value.run.assert_called_once_with(24, 28, 29, pg=3)
        # Verify ThresholdResult.from_bounds got (lower, upper) in correct order
        mock_result.from_bounds.assert_called_once_with(5, 6)

    @pytest.mark.order(1341)
    def test_probe_dispatches_to_binary_when_flag_true(self):
        """probe() routes to XonDrainBinaryAlgorithm when enable_xon_range_probe=True."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {"pfcxoff_point": 100000, "enable_xon_range_probe": True}
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.XonDrainBinaryAlgorithm') as mock_binary, \
                patch('pfc_xon_probing.ThresholdResult') as mock_result, \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_binary.return_value.run.return_value = (3244, 3245, 0.5)
            pfc.probe()

        mock_binary.assert_called_once()
        mock_step.assert_not_called()
        mock_binary.return_value.run.assert_called_once_with(24, 28, 29, pg=3)
        mock_result.from_bounds.assert_called_once_with(3244, 3245)

    @pytest.mark.order(1342)
    def test_probe_passes_step_tunables_to_algorithm(self):
        """probe() forwards tunables to StepAlgorithm constructor."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "enable_xon_range_probe": False,
            "xon_step_max_iter": 30,
            "xon_verification_attempts": 3,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.XonDrainBinaryAlgorithm'), \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        kwargs = mock_step.call_args.kwargs
        assert kwargs['max_iter'] == 30
        assert kwargs['verification_attempts'] == 3

    @pytest.mark.order(1343)
    def test_probe_passes_binary_tunables_to_algorithm(self):
        """probe() forwards tunables to BinaryAlgorithm constructor."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "xon_binary_range_limit": 16,
            "xon_binary_max_iter": 25,
            "xon_binary_step_max_iter": 80,
            "xon_verification_attempts": 3,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.XonDrainStepAlgorithm'), \
                patch('pfc_xon_probing.XonDrainBinaryAlgorithm') as mock_binary, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_binary.return_value.run.return_value = (3244, 3245, 0.5)
            pfc.probe()

        kwargs = mock_binary.call_args.kwargs
        assert kwargs['range_limit'] == 16
        assert kwargs['binary_max_iter'] == 25
        assert kwargs['step_max_iter'] == 80
        assert kwargs['verification_attempts'] == 3
