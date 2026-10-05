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
            "xon_verification_attempts": 3,
        }
        pfc.parse_param()
        assert pfc.xon_verification_attempts == 3

    @pytest.mark.order(1305)
    def test_parse_param_rejects_zero_pause_observation_window(self):
        """Per r2 N2: pause_observation_window must be > 0; 0 silently
        breaks 2-sample counter-stop detection (no real wait between
        reads -> growth=0 -> always reads xon_fired=True at every D)."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "pause_observation_window": 0.0,
        }
        with pytest.raises(ValueError, match="pause_observation_window must be > 0"):
            pfc.parse_param()

    @pytest.mark.order(1306)
    def test_parse_param_rejects_zero_pause_stop_tolerance(self):
        """Per r2 N2: pause_stop_tolerance must be > 0; 0 makes
        `growth < tolerance` always False -> xon never detected ->
        algorithm exhausts max_iter and returns None."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "pause_stop_tolerance": 0,
        }
        with pytest.raises(ValueError, match="pause_stop_tolerance must be > 0"):
            pfc.parse_param()


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
        (1 src + dst_drain + dst_holder is the minimum)."""
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
    def test_probe_reads_verification_attempts(self):
        """parse_param stores xon_verification_attempts on instance."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "enable_xon_range_probe": False,
            "xon_verification_attempts": 3,
        }
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is False
        assert pfc.xon_verification_attempts == 3

    @pytest.mark.order(1331)
    def test_probe_reads_range_probe_flag(self):
        """parse_param stores enable_xon_range_probe flag."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
        }
        pfc.parse_param()
        assert pfc.enable_xon_range_probe is True


class TestPfcXonProbingDispatch:
    """Test probe() dispatches to standard Range+Point algorithms per design v3.

    After C3 refactor: probe() no longer dispatches to custom XonDrainStep/Binary
    algorithms. Instead it uses framework-standard ThresholdRangeProbingAlgorithm
    (optional) + ThresholdPointProbingAlgorithm (mandatory, always_full_cycle=True).

    The patches target the imported names within pfc_xon_probing module.
    """

    @pytest.mark.order(1340)
    def test_probe_point_only_when_range_disabled(self):
        """enable_xon_range_probe=False -> Point runs, Range skipped."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 1000,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": False,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult') as mock_result, \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_point.return_value.run.return_value = (10, 12, 0.5)
            pfc.probe()

        # Range NOT called (enable_xon_range_probe=False)
        mock_range.assert_not_called()
        # Point called with bounds [0, 1000] (known from xoff_point)
        mock_point.assert_called_once()
        point_kwargs = mock_point.call_args.kwargs
        assert point_kwargs['always_full_cycle'] is True
        assert point_kwargs['step_size'] == 1
        assert point_kwargs['verification_attempts'] == 1
        # Point.run() called with correct args
        run_kwargs = mock_point.return_value.run.call_args
        assert run_kwargs.kwargs['lower_bound'] == 0
        assert run_kwargs.kwargs['upper_bound'] == 1000
        # Result built from Point output
        mock_result.from_bounds.assert_called_once_with(10, 12)

    @pytest.mark.order(1341)
    def test_probe_range_then_point_when_range_enabled(self):
        """enable_xon_range_probe=True -> Range narrows, then Point refines."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "enable_xoff_chain_probe": False,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult') as mock_result, \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_range.return_value.run.return_value = (12900, 13100, 1.2)
            mock_point.return_value.run.return_value = (12985, 12986, 0.8)
            pfc.probe()

        # Both Range and Point called
        mock_range.assert_called_once()
        mock_point.assert_called_once()
        # Range receives full bounds [0, 100000]
        range_run_args = mock_range.return_value.run.call_args
        assert range_run_args[0][2] == 0       # lower_bound
        assert range_run_args[0][3] == 100000  # upper_bound
        # Point receives narrowed bounds from Range
        point_run_kwargs = mock_point.return_value.run.call_args.kwargs
        assert point_run_kwargs['lower_bound'] == 12900
        assert point_run_kwargs['upper_bound'] == 13100
        # Final result from Point
        mock_result.from_bounds.assert_called_once_with(12985, 12986)

    @pytest.mark.order(1342)
    def test_probe_point_uses_full_bounds_when_range_fails(self):
        """If Range returns (None, None), Point falls back to full [0, xoff_point]."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "enable_xoff_chain_probe": False,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult') as mock_result, \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_range.return_value.run.return_value = (None, None, 1.0)
            mock_point.return_value.run.return_value = (12985, 12986, 5.0)
            pfc.probe()

        # Point receives full bounds since Range failed
        point_run_kwargs = mock_point.return_value.run.call_args.kwargs
        assert point_run_kwargs['lower_bound'] == 0
        assert point_run_kwargs['upper_bound'] == 100000
        mock_result.from_bounds.assert_called_once_with(12985, 12986)

    @pytest.mark.order(1343)
    def test_probe_uses_range_bounds_when_point_fails(self):
        """If Point returns (None, None), result falls back to Range bounds."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "enable_xoff_chain_probe": False,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult') as mock_result, \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_range.return_value.run.return_value = (12900, 13100, 1.2)
            mock_point.return_value.run.return_value = (None, None, 0.5)
            pfc.probe()

        # Result falls back to Range bounds
        mock_result.from_bounds.assert_called_once_with(12900, 13100)


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
        yaml hint flows directly to the XOn Step 5 phase."""
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            # Step 5d Point (the only algo that runs when chain+range disabled)
            mock_point.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # No PfcXoff chain algorithms should be instantiated
        mock_upper.assert_not_called()
        mock_lower.assert_not_called()
        # Range not called (enable_xon_range_probe=False)
        mock_range.assert_not_called()
        # Point IS called (Step 5d mandatory) — but only once (no chain Point)
        assert mock_point.call_count == 1
        # pfcxoff_point unchanged from yaml hint
        assert pfc.pfcxoff_point == 12345

    @pytest.mark.order(1361)
    def test_probe_chain_overrides_yaml_when_phase4_succeeds(self):
        """enable_xoff_chain_probe=True + all 4 phases succeed:
        self.pfcxoff_point updates to the Phase 4 measured value.
        Note: ThresholdPointProbingAlgorithm is called twice — once in the
        chain (Step 4) and once for XOn Step 5d."""
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            mock_lower.return_value.run.return_value = (10000, 0.1)
            mock_range.return_value.run.return_value = (20000, 20040, 0.1)
            # Point called twice: chain Step 4 returns (20036, 20037);
            # XOn Step 5d returns (10, 12). Use side_effect for sequential calls.
            point_instance_1 = MagicMock()
            point_instance_1.run.return_value = (20036, 20037, 0.1)
            point_instance_2 = MagicMock()
            point_instance_2.run.return_value = (10, 12, 0.5)
            mock_point.side_effect = [point_instance_1, point_instance_2]
            pfc.probe()

        # All 4 chain phases ran exactly once
        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_called_once()
        # Range called once (in chain only; enable_xon_range_probe=False)
        assert mock_range.call_count == 1
        # Point called twice (chain + Step 5d)
        assert mock_point.call_count == 2
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            # Phase 1 fails -> chain aborts
            mock_upper.return_value.run.return_value = (None, 0.1)
            # Step 5d Point still runs after chain fallback
            mock_point.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # Phase 1 ran; later chain phases never reached
        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_not_called()
        mock_range.assert_not_called()
        # Point called once (Step 5d only, not chain Step 4)
        assert mock_point.call_count == 1
        # pfcxoff_point preserved from yaml
        assert pfc.pfcxoff_point == 8800

    @pytest.mark.order(1363)
    def test_probe_chain_uses_range_upper_when_phase4_skipped(self):
        """If the range_upper - range_lower window is wider than the precise-
        detection limit, Phase 4 (Point) is skipped in the chain; range_upper
        is used as the xoff_point approximation."""
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (500000, 0.1)
            mock_lower.return_value.run.return_value = (300000, 0.1)
            # Range width 200 > precise_detection_range_limit 100 -> chain Phase 4 skipped
            mock_range.return_value.run.return_value = (388000, 388200, 0.1)
            # XOn Step 5: Range runs, then Point runs
            # Range called twice (chain + Step 5c); Point called once (Step 5d only)
            range_instance_chain = MagicMock()
            range_instance_chain.run.return_value = (388000, 388200, 0.1)
            range_instance_xon = MagicMock()
            range_instance_xon.run.return_value = (12900, 13100, 1.0)
            mock_range.side_effect = [range_instance_chain, range_instance_xon]
            mock_point.return_value.run.return_value = (12985, 12986, 0.5)
            pfc.probe()

        # pfcxoff_point updated to range_upper as approximation
        assert pfc.pfcxoff_point == 388200

    @pytest.mark.order(1364)
    def test_probe_chain_falls_back_to_yaml_when_phase2_fails(self):
        """If Phase 2 (LowerBound) returns None, the chain aborts BEFORE
        Phase 3/4 and the yaml hint is preserved."""
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            # Phase 2 fails -> chain aborts
            mock_lower.return_value.run.return_value = (None, 0.1)
            # Step 5d Point still runs
            mock_point.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_called_once()
        mock_range.assert_not_called()
        # Point called once (Step 5d only)
        assert mock_point.call_count == 1
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            mock_lower.return_value.run.return_value = (10000, 0.1)
            # Phase 3 fails -> chain aborts
            mock_range.return_value.run.return_value = (None, None, 0.1)
            # Step 5d Point still runs
            mock_point.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        mock_upper.return_value.run.assert_called_once()
        mock_lower.return_value.run.assert_called_once()
        mock_range.return_value.run.assert_called_once()
        # Point called once (Step 5d only, chain Phase 4 not reached)
        assert mock_point.call_count == 1
        # pfcxoff_point preserved from yaml
        assert pfc.pfcxoff_point == 8800

    @pytest.mark.order(1366)
    def test_probe_chain_uses_range_upper_when_phase4_invoked_but_fails(self):
        """If Phase 4 IS invoked (range width <= limit) but returns
        (None, None) due to noise, falls back to range_upper."""
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
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_upper.return_value.run.return_value = (40000, 0.1)
            mock_lower.return_value.run.return_value = (10000, 0.1)
            # Range width = 50 <= 100 limit -> Phase 4 invoked
            mock_range.return_value.run.return_value = (20020, 20070, 0.1)
            # Phase 4 invoked but fails (noise); then Step 5d Point runs
            point_instance_chain = MagicMock()
            point_instance_chain.run.return_value = (None, None, 0.1)
            point_instance_xon = MagicMock()
            point_instance_xon.run.return_value = (5, 6, 0.1)
            mock_point.side_effect = [point_instance_chain, point_instance_xon]
            pfc.probe()

        # Point called twice (chain Phase 4 + Step 5d)
        assert mock_point.call_count == 2
        # pfcxoff_point updated to range_upper as 2-tier fallback
        assert pfc.pfcxoff_point == 20070

    @pytest.mark.order(1367)
    def test_probe_chain_falls_back_to_yaml_when_measured_xoff_zero(self):
        """Defensive guard: if chain returns 0 or negative, preserve yaml
        hint rather than corrupting pfcxoff_point."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 8800,
            "enable_xon_range_probe": False,
            "enable_xoff_chain_probe": True,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        # Force chain to return 0 by mocking _run_pfcxoff_chain directly.
        pfc._run_pfcxoff_chain = MagicMock(return_value=0)

        with patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_point.return_value.run.return_value = (5, 6, 0.1)
            pfc.probe()

        # measured_xoff=0 -> guard rejects -> yaml preserved
        assert pfc.pfcxoff_point == 8800


class TestPfcXonDesignParamConformance:
    """Verify probe() passes design-conformant parameters to algorithms.

    Per design v3, Step 5:
    - Range (5c): precision_target_ratio=PRECISION_TARGET_RATIO,
          verification_attempts=xon_verification_attempts (DEFAULT=2),
          enable_precise_detection=True,
          precise_detection_range_limit=PRECISE_DETECTION_RANGE_LIMIT
    - Point (5d): always_full_cycle=True, verification_attempts=1,
          step_size=POINT_PROBING_STEP_SIZE
    - Observers: range iteration_prefix=22, point iteration_prefix=23
    """

    def _make_pfc_with_range(self):
        """Build fixture with enable_xon_range_probe=True."""
        pfc = _PfcXonProbingFixture()
        pfc.test_params = {
            "pfcxoff_point": 100000,
            "enable_xon_range_probe": True,
            "enable_xoff_chain_probe": False,
        }
        pfc.parse_param()
        pfc.create_executor = MagicMock(return_value=MagicMock())
        return pfc

    @pytest.mark.order(1370)
    def test_range_algo_receives_design_params(self):
        """Range constructor kwargs match design v3 section 5c."""
        pfc = self._make_pfc_with_range()

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_range.return_value.run.return_value = (12900, 13100, 1.2)
            mock_point.return_value.run.return_value = (12985, 12986, 0.8)
            pfc.probe()

        range_kwargs = mock_range.call_args.kwargs
        assert range_kwargs['precision_target_ratio'] == pfc.PRECISION_TARGET_RATIO
        assert range_kwargs['verification_attempts'] == pfc.xon_verification_attempts
        assert range_kwargs['enable_precise_detection'] is True
        assert range_kwargs['precise_detection_range_limit'] == pfc.PRECISE_DETECTION_RANGE_LIMIT

    @pytest.mark.order(1371)
    def test_range_verification_attempts_default_is_two(self):
        """Range uses xon_verification_attempts which defaults to 2."""
        pfc = self._make_pfc_with_range()

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver'):
            mock_range.return_value.run.return_value = (12900, 13100, 1.2)
            mock_point.return_value.run.return_value = (12985, 12986, 0.8)
            pfc.probe()

        range_kwargs = mock_range.call_args.kwargs
        assert range_kwargs['verification_attempts'] == 2

    @pytest.mark.order(1372)
    def test_observer_iteration_prefix_allocation(self):
        """Range observer prefix=22, Point observer prefix=23."""
        pfc = self._make_pfc_with_range()

        with patch('pfc_xon_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
                patch('pfc_xon_probing.ThresholdPointProbingAlgorithm') as mock_point, \
                patch('pfc_xon_probing.ThresholdResult'), \
                patch('pfc_xon_probing.ProbingObserver') as mock_obs_cls:
            mock_range.return_value.run.return_value = (12900, 13100, 1.2)
            mock_point.return_value.run.return_value = (12985, 12986, 0.8)
            pfc.probe()

        # Extract iteration_prefix per observer name from constructor calls
        prefixes = {}
        for call in mock_obs_cls.call_args_list:
            kw = call.kwargs
            if 'name' in kw and 'iteration_prefix' in kw:
                prefixes[kw['name']] = kw['iteration_prefix']
        assert prefixes.get("xon_range") == 22, f"Range prefix: {prefixes}"
        assert prefixes.get("xon_point") == 23, f"Point prefix: {prefixes}"
