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
        # Step 1+2 chain default = True per design v3 (added 2026-05-09); UT
        # fixtures default to False so existing dispatch / parsing tests don't
        # need to mock the 4-phase PfcXoff probe. Tests that DO exercise the
        # chain explicitly flip this to True.
        self.enable_xoff_chain_probe = False
        self.xon_step_max_iter = 50
        self.xon_binary_range_limit = 32
        self.xon_binary_max_iter = 20
        self.xon_binary_step_max_iter = 50
        self.xon_verification_attempts = 2
        self.EXECUTOR_ENV = 'sim'
        self.router_mac = "00:11:22:33:44:55"
        self.is_dualtor = False
        self.def_vlan_mac = None
        # ENABLE_PRECISE_DETECTION = True is set in setUp() per design v3 §2 Step 2
        # (precise xoff_point detection); fixture matches that since dispatch tests
        # exercise probe() which would have already run setUp.
        self.ENABLE_PRECISE_DETECTION = True
        self.PRECISE_DETECTION_RANGE_LIMIT = 100

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
        # enable_xoff_chain_probe=False -> skip Step 1+2 chain (existing tests
        # cover dispatch of Step 3 / Step 2.5+3 only; Step 1+2 chain has
        # dedicated tests in TestPfcXonProbingXoffChain).
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": False,
        }
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
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "enable_xoff_chain_probe": False,
        }
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
            "enable_xoff_chain_probe": False,
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
            "enable_xoff_chain_probe": False,
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


class TestPfcXonProbingXoffChain:
    """Test Step 1+2 chain (PfcXoff range probe + exact point) per design v3.

    Per L020 NON-REGRESSION (2026-05-09 PfcXon design conformance fix):
    pfc_xon_probing.PfcXonProbing.probe() MUST run a 4-phase PfcXoff probe
    BEFORE the XOn drain phase whenever enable_xoff_chain_probe is True
    (the default). The measured xoff_point overrides the yaml hint, so the
    XOn drain phase consumes a precise hardware-measured threshold instead
    of yaml's nominal value.

    Coverage:
      1360 — chain disabled: yaml hint flows through unchanged
      1361 — chain succeeds: self.pfcxoff_point updated to measured value
      1362 — chain Phase 1 fails: falls back to yaml hint
      1363 — chain Phase 4 skipped (range too wide): uses range_upper
    """

    @pytest.mark.order(1360)
    def test_probe_skips_chain_when_disabled(self):
        """enable_xoff_chain_probe=False -> no PfcXoff algorithms instantiated;
        yaml hint flows directly to the XOn drain phase."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 12345,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": False,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # No PfcXoff phase algorithms should be instantiated at all
        mock_upper.assert_not_called()
        mock_lower.assert_not_called()
        mock_range.assert_not_called()
        mock_point.assert_not_called()
        # pfcxoff_point unchanged from yaml hint
        assert pfc.pfcxoff_point == 12345

    @pytest.mark.order(1361)
    def test_probe_chain_overrides_yaml_when_phase4_succeeds(self):
        """enable_xoff_chain_probe=True + all 4 phases succeed:
        self.pfcxoff_point updates to the Phase 4 measured value."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 20035,  # yaml hint
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        pfc.get_pool_size = MagicMock(return_value=1000000)

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            # Each phase returns a value; final answer is point_upper = 20037
            # (matches the TH2 7260CX3 observation: yaml says 20035, real hw 20037).
            mock_upper.return_value.run.return_value = (40000, 0.1)
            mock_lower.return_value.run.return_value = (10000, 0.1)
            mock_range.return_value.run.return_value = (20000, 20040, 0.1)
            mock_point.return_value.run.return_value = (20036, 20037, 0.1)
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # All 4 phases ran exactly once
        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_called_once()
        mock_range.return_value.run.assert_called_once()
        mock_point.return_value.run.assert_called_once()
        # pfcxoff_point updated from yaml 20035 to measured 20037
        assert pfc.pfcxoff_point == 20037

    @pytest.mark.order(1362)
    def test_probe_chain_falls_back_to_yaml_when_phase1_fails(self):
        """If Phase 1 (UpperBound) returns None, the chain aborts and the
        yaml hint is preserved (no late-stage corruption of pfcxoff_point)."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 8800,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        pfc.get_pool_size = MagicMock(return_value=1000000)

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            # Phase 1 fails -> chain aborts
            mock_upper.return_value.run.return_value = (None, 0.1)
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # Phase 1 ran; later phases never reached
        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_not_called()
        mock_range.return_value.run.assert_not_called()
        mock_point.return_value.run.assert_not_called()
        # pfcxoff_point preserved from yaml
        assert pfc.pfcxoff_point == 8800

    @pytest.mark.order(1363)
    def test_probe_chain_uses_range_upper_when_phase4_skipped(self):
        """If the range_upper - range_lower window is wider than the precise-
        detection limit, Phase 4 (Point) is skipped; range_upper is used as
        the xoff_point approximation. Still a substantial improvement over
        the yaml hint."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 388047,  # Cisco-scale yaml hint
            "enable_xon_range_probe": True,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        pfc.get_pool_size = MagicMock(return_value=1500000)
        # PRECISE_DETECTION_RANGE_LIMIT inherited as 100 from ProbingBase
        pfc.PRECISE_DETECTION_RANGE_LIMIT = 100

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainBinaryAlgorithm') as mock_binary, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (500000, 0.1)
            mock_lower.return_value.run.return_value = (300000, 0.1)
            # Range width 200 > precise_detection_range_limit 100 -> Phase 4 skipped
            mock_range.return_value.run.return_value = (388000, 388200, 0.1)
            mock_binary.return_value.run.return_value = (3244, 3245, 0.5)
            pfc.probe()

        # Phase 4 should NOT run because range width > limit
        mock_point.return_value.run.assert_not_called()
        # pfcxoff_point updated to range_upper as approximation
        assert pfc.pfcxoff_point == 388200

    @pytest.mark.order(1364)
    def test_probe_chain_falls_back_to_yaml_when_phase2_fails(self):
        """If Phase 2 (LowerBound) returns None, the chain aborts BEFORE
        Phase 3/4 and the yaml hint is preserved. Mirrors 1362's pattern
        for Phase 1, but tests the second-phase failure branch (a distinct
        code path in _run_pfcxoff_chain)."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 8800,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        pfc.get_pool_size = MagicMock(return_value=1000000)

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            # Phase 2 fails -> chain aborts
            mock_lower.return_value.run.return_value = (None, 0.1)
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_called_once()
        mock_range.return_value.run.assert_not_called()
        mock_point.return_value.run.assert_not_called()
        # pfcxoff_point preserved from yaml
        assert pfc.pfcxoff_point == 8800

    @pytest.mark.order(1365)
    def test_probe_chain_falls_back_to_yaml_when_phase3_fails(self):
        """If Phase 3 (ThresholdRange) returns (None, None), the chain
        aborts BEFORE Phase 4 and yaml hint is preserved."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 8800,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        pfc.get_pool_size = MagicMock(return_value=1000000)

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            mock_lower.return_value.run.return_value = (10000, 0.1)
            # Phase 3 fails -> chain aborts
            mock_range.return_value.run.return_value = (None, None, 0.1)
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_called_once()
        mock_range.return_value.run.assert_called_once()
        mock_point.return_value.run.assert_not_called()
        # pfcxoff_point preserved from yaml
        assert pfc.pfcxoff_point == 8800

    @pytest.mark.order(1366)
    def test_probe_chain_uses_range_upper_when_phase4_invoked_but_fails(self):
        """If Phase 4 IS invoked (range width <= limit) but returns
        (None, None) due to noise, falls back to range_upper rather than
        further degrading to yaml. Distinct from 1363 (Phase 4 SKIPPED
        because range too wide -- never invoked)."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 8800,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        pfc.get_pool_size = MagicMock(return_value=1000000)
        pfc.PRECISE_DETECTION_RANGE_LIMIT = 100

        with patch('pfc_xon_probing.UpperBoundProbingAlgorithm') as mock_upper, \
                patch('pfc_xon_probing.LowerBoundProbingAlgorithm') as mock_lower, \
                patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            mock_lower.return_value.run.return_value = (10000, 0.1)
            # Range width = 50 <= 100 limit -> Phase 4 invoked
            mock_range.return_value.run.return_value = (20020, 20070, 0.1)
            # Phase 4 invoked but fails (noise)
            mock_point.return_value.run.return_value = (None, None, 0.1)
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        mock_point.return_value.run.assert_called_once()
        # pfcxoff_point updated to range_upper as 2-tier fallback
        assert pfc.pfcxoff_point == 20070

    @pytest.mark.order(1367)
    def test_probe_chain_falls_back_to_yaml_when_measured_xoff_zero(self):
        """Defensive guard: if chain returns 0 or negative (theoretically
        impossible but a sanity check against pathological algorithm
        states), preserve yaml hint rather than corrupting pfcxoff_point
        with the bad value. Tests the `if measured_xoff is not None and
        measured_xoff > 0` predicate in probe()."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 8800,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        # Force chain to return 0 by making Phase 4 return (0, 0).
        pfc._run_pfcxoff_chain = MagicMock(return_value=0)

        with patch('pfc_xon_probing.XonDrainStepAlgorithm') as mock_step, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_step.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # measured_xoff=0 -> guard rejects -> yaml preserved
        assert pfc.pfcxoff_point == 8800
