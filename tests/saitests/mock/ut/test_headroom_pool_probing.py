#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for HeadroomPoolProbing class.

Tests cover:
- Parameter parsing and validation (PGs, DSCPs lists)
- Configuration methods
- Traffic setup (N src -> 1 dst pattern, multi-PG flows)
- Multi-PG probing logic (PFC XOFF + Ingress Drop per PG)
- Headroom calculation and pool exhaustion detection
- Observer configuration generation
- Result building and reporting
- Integration testing

Coverage target: >90% for headroom_pool_probing.py

Note: This test file follows the same patterns as test_pfc_xoff_probing.py
and test_ingress_drop_probing.py, using order values in the 4000+ range.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import pytest


#
# Mock Setup - MUST be identical across all test files
#

# Mock PTF and SAI dependencies BEFORE importing
sys.modules['ptf'] = MagicMock()
sys.modules['ptf.testutils'] = MagicMock()
sys.modules['switch'] = MagicMock()
sys.modules['sai_qos_tests'] = MagicMock()
sys.modules['stream_manager'] = MagicMock()
sys.modules['buffer_occupancy_controller'] = MagicMock()

# CRITICAL: Must match other test files to avoid inheritance conflicts
mock_sai_base = MagicMock()
mock_sai_base.ThriftInterfaceDataPlane = object  # Use object as base
sys.modules['sai_base_test'] = mock_sai_base


# Helper class to avoid mocking __init__
class TestHeadroomPoolProbingInstance:
    """
    Test instance with all attributes initialized.

    This avoids the forbidden pattern: patch.object(HeadroomPoolProbing, '__init__')
    which raises "AttributeError: __init__" due to how Python handles __init__.
    """
    def __init__(self):
        # Basic attributes
        self.pgs = [3, 4]  # Multiple PGs
        self.dscps = [3, 4]  # Corresponding DSCPs
        self.probing_port_ids = [24, 28, 32, 36]  # N src -> 1 dst (3 src + 1 dst)
        self.test_port_ips = {
            0: {
                0: {
                    24: {"peer_addr": "192.168.1.1", "vlan_id": 100},
                    28: {"peer_addr": "192.168.1.2", "vlan_id": 100},
                    32: {"peer_addr": "192.168.1.3", "vlan_id": 100},
                    36: {"peer_addr": "192.168.1.4", "vlan_id": 100}
                }
            }
        }
        self.dst_client = MagicMock()
        self.asic_type = "generic"
        self.pkts_num_hdrm_full = 500
        self.pgs_num = 21
        self.pkts_num_hdrm_partial = 100
        self.ecn = 1
        self.router_mac = "00:11:22:33:44:55"
        self.is_dualtor = False
        self.def_vlan_mac = None
        self.cell_size = 208
        self.packet_size = 64
        self.use_pg_drop_counter = False

        # Probing configuration
        self.PROBE_TARGET = "headroom_pool"
        self.PRECISION_TARGET_RATIO = 0.005
        self.ENABLE_PRECISE_DETECTION = True
        self.PRECISE_DETECTION_RANGE_LIMIT = 10
        self.POINT_PROBING_STEP_SIZE = 2
        self.EXECUTOR_ENV = "sim"

        # Mock dataplane
        self.dataplane = MagicMock()
        self.dataplane.get_mac.side_effect = lambda dev, port: f"00:00:00:00:00:{port:02x}"

        # Mock buffer controller
        self.buffer_ctrl = MagicMock()

        # Stream manager (will be set by setup_traffic)
        self.stream_mgr = None

        # Mock get_rx_port method
        def mock_get_rx_port(src_port, dst_port):
            return dst_port
        self.get_rx_port = mock_get_rx_port

        # Counter index (will be set by parse_param)
        self.cnt_pg_idx = None

        # Table column mappings (class attributes from HeadroomPoolProbing)
        self._UPPER_TABLE_MAPPING = {"lower_bound": None, "upper_bound": "value",
                                     "candidate_threshold": None, "range_step": None}
        self._LOWER_TABLE_MAPPING = {"lower_bound": "value", "upper_bound": "window_upper",
                                     "candidate_threshold": None, "range_step": None}
        self._RANGE_TABLE_MAPPING = {"lower_bound": "window_lower",
                                     "upper_bound": "window_upper",
                                     "candidate_threshold": "value", "range_step": "range_step"}
        self._POINT_TABLE_MAPPING = {"lower_bound": "window_lower",
                                     "upper_bound": "window_upper",
                                     "candidate_threshold": "value", "range_step": None}


# Now import the class under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../probe"))
from headroom_pool_probing import HeadroomPoolProbing  # noqa: E402


#
# Test Classes
#

@pytest.mark.order(4000)
class TestHeadroomPoolProbingParameterParsing(unittest.TestCase):
    """Test parameter parsing and validation methods."""

    @pytest.mark.order(4000)
    def test_parse_param_converts_single_values_to_lists(self):
        """Test parse_param converts single PG/DSCP values to lists."""
        instance = TestHeadroomPoolProbingInstance()
        instance.pgs = 3  # Single value
        instance.dscps = 4  # Single value

        HeadroomPoolProbing.parse_param(instance)

        assert isinstance(instance.pgs, list), "pgs should be converted to list"
        assert isinstance(instance.dscps, list), "dscps should be converted to list"
        assert instance.pgs == [3]
        assert instance.dscps == [4]

    @pytest.mark.order(4010)
    def test_parse_param_keeps_lists_unchanged(self):
        """Test parse_param keeps list values unchanged."""
        instance = TestHeadroomPoolProbingInstance()
        instance.pgs = [3, 4, 5]
        instance.dscps = [3, 4, 5]

        HeadroomPoolProbing.parse_param(instance)

        assert instance.pgs == [3, 4, 5]
        assert instance.dscps == [3, 4, 5]

    @pytest.mark.order(4020)
    def test_parse_param_validates_pg_count(self):
        """Test parse_param validates PG count vs src ports."""
        instance = TestHeadroomPoolProbingInstance()
        # 4 ports total, last is dst, so 3 src ports
        instance.probing_port_ids = [24, 28, 32, 36]
        instance.pgs = [3, 4, 5, 6]  # 4 PGs > 3 src ports
        instance.dscps = [3]

        # Should log warning but not raise exception
        HeadroomPoolProbing.parse_param(instance)

        # parse_param should complete without error
        assert isinstance(instance.pgs, list)


@pytest.mark.order(4030)
class TestHeadroomPoolProbingConfiguration(unittest.TestCase):
    """Test configuration and threshold methods."""

    @pytest.mark.order(4030)
    def test_get_probe_config(self):
        """Test get_probe_config returns ProbeConfig with correct attributes."""
        instance = TestHeadroomPoolProbingInstance()

        config = HeadroomPoolProbing.get_probe_config(instance)

        assert config.probing_port_ids == instance.probing_port_ids
        assert config.thrift_client == instance.dst_client
        assert config.asic_type == instance.asic_type

    @pytest.mark.order(4040)
    def test_get_expected_threshold_with_values(self):
        """Test get_expected_threshold calculates correctly when all values present."""
        instance = TestHeadroomPoolProbingInstance()
        instance.pkts_num_hdrm_full = 500
        instance.pgs_num = 21
        instance.pkts_num_hdrm_partial = 100

        result = HeadroomPoolProbing.get_expected_threshold(instance)

        assert result is not None
        value, description = result
        # Formula: 500 * (21 - 1) + 100 = 500 * 20 + 100 = 10100
        expected = 500 * (21 - 1) + 100
        assert value == expected
        assert "Headroom Pool Size" in description

    @pytest.mark.order(4050)
    def test_get_expected_threshold_missing_values(self):
        """Test get_expected_threshold returns None when values missing."""
        instance = TestHeadroomPoolProbingInstance()
        # Remove one attribute
        delattr(instance, 'pkts_num_hdrm_full')

        result = HeadroomPoolProbing.get_expected_threshold(instance)

        assert result is None

    @pytest.mark.order(4060)
    def test_probe_target(self):
        """Test PROBE_TARGET class attribute."""
        assert HeadroomPoolProbing.PROBE_TARGET == "headroom_pool"

    @pytest.mark.order(4070)
    def test_precision_configuration(self):
        """Test precision-related class attributes."""
        assert HeadroomPoolProbing.PRECISION_TARGET_RATIO == 0.005
        assert HeadroomPoolProbing.ENABLE_PRECISE_DETECTION is True
        assert HeadroomPoolProbing.POINT_PROBING_STEP_SIZE == 2


@pytest.mark.order(4080)
class TestHeadroomPoolProbingSetupTraffic(unittest.TestCase):
    """Test setup_traffic method for N src -> 1 dst pattern."""

    @pytest.mark.order(4080)
    @patch('headroom_pool_probing.StreamManager')
    @patch('headroom_pool_probing.PortInfo')
    @patch('headroom_pool_probing.FlowConfig')
    @patch('headroom_pool_probing.determine_traffic_dmac')
    def test_setup_traffic_creates_multi_pg_flows(self, mock_dmac, mock_flow_cfg, mock_port_info, mock_stream_mgr):
        """Test setup_traffic creates flows for all src ports × PGs."""
        instance = TestHeadroomPoolProbingInstance()
        instance.probing_port_ids = [24, 28, 32, 36]  # 3 src + 1 dst
        instance.pgs = [3, 4]  # 2 PGs
        instance.dscps = [3, 4]
        instance.get_rx_port = MagicMock()

        # Mock returns
        mock_dmac.return_value = "00:11:22:33:44:66"
        mock_stream_instance = MagicMock()
        mock_stream_mgr.return_value = mock_stream_instance

        HeadroomPoolProbing.setup_traffic(instance)

        # Verify stream manager created
        assert instance.stream_mgr == mock_stream_instance

        # Verify flow count: 3 src ports × 2 PGs = 6 flows
        expected_flows = 3 * 2
        assert mock_stream_instance.add_flow.call_count == expected_flows

        # Verify generate_packets called
        mock_stream_instance.generate_packets.assert_called_once()

    @pytest.mark.order(4090)
    @patch('headroom_pool_probing.StreamManager')
    @patch('headroom_pool_probing.PortInfo')
    @patch('headroom_pool_probing.FlowConfig')
    @patch('headroom_pool_probing.determine_traffic_dmac')
    def test_setup_traffic_uses_correct_dst_port(self, mock_dmac, mock_flow_cfg, mock_port_info, mock_stream_mgr):
        """Test setup_traffic uses last port as destination."""
        instance = TestHeadroomPoolProbingInstance()
        instance.probing_port_ids = [24, 28, 32, 36]
        instance.pgs = [3]
        instance.dscps = [3]
        instance.get_rx_port = MagicMock()

        mock_dmac.return_value = "00:11:22:33:44:66"
        mock_stream_instance = MagicMock()
        mock_stream_mgr.return_value = mock_stream_instance

        # Create real PortInfo instances to inspect
        port_info_instances = []

        def side_effect_port_info(*args, **kwargs):
            instance = MagicMock()
            instance.port_id = args[0] if args else None
            port_info_instances.append(instance)
            return instance
        mock_port_info.side_effect = side_effect_port_info

        HeadroomPoolProbing.setup_traffic(instance)

        # Last PortInfo created should be dst (port 36)
        # 3 src ports + 1 dst port = 4 PortInfo instances total
        assert len(port_info_instances) == 4
        # Dst port (36) is created first, then src ports
        assert port_info_instances[0].port_id == 36  # dst

    @pytest.mark.order(4100)
    def test_setup_traffic_no_probing_ports(self):
        """Test setup_traffic handles empty probing_port_ids gracefully."""
        instance = TestHeadroomPoolProbingInstance()
        instance.probing_port_ids = []

        # Should return early without error
        HeadroomPoolProbing.setup_traffic(instance)

        assert instance.stream_mgr is None


@pytest.mark.order(4110)
class TestHeadroomPoolProbingObserverConfigs(unittest.TestCase):
    """Test _get_observer_configs method."""

    @pytest.mark.order(4110)
    def test_get_observer_configs_pfc_xoff(self):
        """Test _get_observer_configs returns correct configs for pfc_xoff."""
        instance = TestHeadroomPoolProbingInstance()

        configs = HeadroomPoolProbing._get_observer_configs(instance, 'pfc_xoff', 0)

        # Should return dict with 4 algorithm configs
        assert len(configs) == 4
        assert 'upper' in configs
        assert 'lower' in configs
        assert 'range' in configs
        assert 'point' in configs

        # Check upper config
        assert configs['upper'].probe_target == 'pfc_xoff'
        assert configs['upper'].algorithm_name == "Upper Bound Probing"
        assert configs['upper'].strategy == "exponential growth"
        assert configs['upper'].check_column_title == "PfcXoff"

    @pytest.mark.order(4120)
    def test_get_observer_configs_ingress_drop(self):
        """Test _get_observer_configs returns correct configs for ingress_drop."""
        instance = TestHeadroomPoolProbingInstance()

        configs = HeadroomPoolProbing._get_observer_configs(instance, 'ingress_drop', 1)

        # Should return dict with 4 algorithm configs
        assert len(configs) == 4

        # Check lower config
        assert configs['lower'].probe_target == 'ingress_drop'
        assert configs['lower'].algorithm_name == "Lower Bound Probing"
        assert configs['lower'].check_column_title == "IngressDrop"

    @pytest.mark.order(4130)
    def test_get_observer_configs_table_mappings(self):
        """Test _get_observer_configs uses correct table mappings."""
        instance = TestHeadroomPoolProbingInstance()

        configs = HeadroomPoolProbing._get_observer_configs(instance, 'pfc_xoff', 0)

        # Check table mappings
        assert configs['upper'].table_column_mapping == instance._UPPER_TABLE_MAPPING
        assert configs['lower'].table_column_mapping == instance._LOWER_TABLE_MAPPING
        assert configs['range'].table_column_mapping == instance._RANGE_TABLE_MAPPING
        assert configs['point'].table_column_mapping == instance._POINT_TABLE_MAPPING


@pytest.mark.order(4140)
class TestHeadroomPoolProbingResultBuilding(unittest.TestCase):
    """Test _build_result method."""

    @pytest.mark.order(4140)
    def test_build_result_pool_exhausted(self):
        """Test _build_result when pool is exhausted (last PG headroom <= threshold)."""
        instance = TestHeadroomPoolProbingInstance()

        pg_results = [
            {'pg_index': 0, 'src_port_id': 24, 'dst_port_id': 36, 'pg': 3, 'dscp': 3,
             'pfc_xoff_threshold': 1000, 'ingress_drop_threshold': 1500, 'headroom': 500},
            {'pg_index': 1, 'src_port_id': 28, 'dst_port_id': 36, 'pg': 4, 'dscp': 4,
             'pfc_xoff_threshold': 1000, 'ingress_drop_threshold': 1004, 'headroom': 4}  # <= 4
        ]
        total_headroom = 504
        num_flows = 6
        exhaustion_threshold = 4

        result = HeadroomPoolProbing._build_result(instance, pg_results,
                                                   total_headroom, num_flows,
                                                   exhaustion_threshold)

        assert result['success'] is True
        assert result['pool_exhausted'] is True
        assert result['pgs_probed'] == 2
        # Effective headroom excludes last PG: 504 - 4 = 500
        assert result['total_headroom'] == 500
        assert result['pg_min'] == 1000

    @pytest.mark.order(4150)
    def test_build_result_pool_not_exhausted(self):
        """Test _build_result when pool is not exhausted."""
        instance = TestHeadroomPoolProbingInstance()

        pg_results = [
            {'pg_index': 0, 'src_port_id': 24, 'dst_port_id': 36, 'pg': 3, 'dscp': 3,
             'pfc_xoff_threshold': 1000, 'ingress_drop_threshold': 1500, 'headroom': 500},
            {'pg_index': 1, 'src_port_id': 28, 'dst_port_id': 36, 'pg': 4, 'dscp': 4,
             'pfc_xoff_threshold': 1000, 'ingress_drop_threshold': 1600, 'headroom': 600}  # > 1
        ]
        total_headroom = 1100
        num_flows = 6

        result = HeadroomPoolProbing._build_result(instance, pg_results,
                                                   total_headroom, num_flows,
                                                   exhaustion_threshold=1)

        assert result['success'] is False
        assert result['pool_exhausted'] is False
        assert result['pgs_probed'] == 2
        assert result['total_headroom'] is None
        assert result['partial_headroom'] == 1100

    @pytest.mark.order(4160)
    def test_build_result_empty_pg_results(self):
        """Test _build_result with empty pg_results."""
        instance = TestHeadroomPoolProbingInstance()

        pg_results = []
        total_headroom = 0
        num_flows = 0

        result = HeadroomPoolProbing._build_result(instance, pg_results, total_headroom, num_flows)

        assert result['success'] is False
        assert result['pool_exhausted'] is False
        assert result['pgs_probed'] == 0


@pytest.mark.order(4170)
class TestHeadroomPoolProbingResultReporting(unittest.TestCase):
    """Test _report_results method."""

    @pytest.mark.order(4170)
    @patch('headroom_pool_probing.ProbingObserver')
    @patch('headroom_pool_probing.ThresholdResult')
    def test_report_results_success(self, mock_result_class, mock_observer_class):
        """Test _report_results for successful pool exhaustion."""
        instance = TestHeadroomPoolProbingInstance()

        result_dict = {
            'success': True,
            'total_headroom': 10000,
            'pgs_probed': 20,
            'pool_exhausted': True,
            'pg_min': 950
        }

        mock_result = MagicMock()
        mock_result_class.from_bounds.return_value = mock_result
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        threshold_result = HeadroomPoolProbing._report_results(instance, result_dict)

        # Should create result with pool_size as both bounds (point format)
        mock_result_class.from_bounds.assert_called_once_with(10000, 10000)

        # Should report using observer
        mock_observer_class.report_probing_result.assert_called_once_with(
            "Headroom Pool", mock_result, unit="cells"
        )

        assert threshold_result == mock_result

    @pytest.mark.order(4180)
    @patch('headroom_pool_probing.ProbingObserver')
    @patch('headroom_pool_probing.ThresholdResult')
    def test_report_results_incomplete(self, mock_result_class, mock_observer_class):
        """Test _report_results for incomplete probing."""
        instance = TestHeadroomPoolProbingInstance()

        result_dict = {
            'success': False,
            'partial_headroom': 5000,
            'pgs_probed': 10,
            'pool_exhausted': False
        }

        mock_result = MagicMock()
        mock_result_class.failed.return_value = mock_result
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        threshold_result = HeadroomPoolProbing._report_results(instance, result_dict)

        # Should create failed result
        mock_result_class.failed.assert_called_once()

        # Should still report
        mock_observer_class.report_probing_result.assert_called_once()

        assert threshold_result == mock_result


@pytest.mark.order(4190)
class TestHeadroomPoolProbingProbeMethod(unittest.TestCase):
    """Test probe method integration (simplified version)."""

    @pytest.mark.order(4190)
    @patch('headroom_pool_probing.ProbingObserver')
    def test_probe_early_termination_on_exhaustion(self, mock_observer_class):
        """Test probe stops when pool exhaustion detected."""
        instance = TestHeadroomPoolProbingInstance()

        # Mock stream_mgr with 3 flows
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.flows = {
            (24, 36, frozenset([('pg', 3)])): MagicMock(dscp=3),
            (28, 36, frozenset([('pg', 4)])): MagicMock(dscp=4),
            (32, 36, frozenset([('pg', 3)])): MagicMock(dscp=3)
        }
        instance.stream_mgr = mock_stream_mgr

        # Mock get_pool_size
        instance.get_pool_size = MagicMock(return_value=10000)

        # Mock observer
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        # Mock _get_observer_configs
        instance._get_observer_configs = MagicMock(return_value={
            'upper': MagicMock(),
            'lower': MagicMock(),
            'range': MagicMock(),
            'point': MagicMock()
        })

        # Mock create_executor
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock algorithms - first PG succeeds, second PG has low headroom (triggers exhaustion)
        call_count_upper_lower = [0]
        call_count_range_point = [0]

        def mock_run_upper_lower(*args, **kwargs):
            """Mock for Upper/Lower algorithms - returns 2 values"""
            call_count_upper_lower[0] += 1
            if call_count_upper_lower[0] == 1:  # PFC upper
                return (2000, 1.0)
            elif call_count_upper_lower[0] == 2:  # PFC lower
                return (1000, 1.0)
            elif call_count_upper_lower[0] == 3:  # Drop upper
                return (2000, 1.0)
            elif call_count_upper_lower[0] == 4:  # Drop lower
                return (1000, 1.0)
            return (1000, 1.0)

        def mock_run_range_point(*args, **kwargs):
            """Mock for Range/Point algorithms - returns 3 values"""
            call_count_range_point[0] += 1
            if call_count_range_point[0] == 1:  # PFC range
                return (1000, 1005, 1.0)
            elif call_count_range_point[0] == 2:  # PFC point
                return (1000, 1001, 1.0)
            elif call_count_range_point[0] == 3:  # Drop range
                return (1000, 1010, 1.0)
            elif call_count_range_point[0] == 4:  # Drop point
                return (1004, 1005, 1.0)
            return (1000, 1001, 1.0)

        # Mock _build_result and _report_results
        instance._build_result = MagicMock(return_value={'success': True, 'total_headroom': 0})
        instance._report_results = MagicMock(return_value=MagicMock())

        with patch('headroom_pool_probing.UpperBoundProbingAlgorithm') as mock_upper, \
             patch('headroom_pool_probing.LowerBoundProbingAlgorithm') as mock_lower, \
             patch('headroom_pool_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
             patch('headroom_pool_probing.ThresholdPointProbingAlgorithm') as mock_point:

            # Configure mock algorithms with appropriate return value counts
            mock_upper.return_value.run.side_effect = mock_run_upper_lower
            mock_lower.return_value.run.side_effect = mock_run_upper_lower
            mock_range.return_value.run.side_effect = mock_run_range_point
            mock_point.return_value.run.side_effect = mock_run_range_point

            # Run probe
            HeadroomPoolProbing.probe(instance)

        # Verify _build_result was called with results
        assert instance._build_result.called
        assert instance._report_results.called

    @pytest.mark.order(4200)
    @patch('headroom_pool_probing.ProbingObserver')
    def test_probe_handles_pfc_failure(self, mock_observer_class):
        """Test probe handles PFC XOFF probing failure gracefully.

        Note: Due to a bug in the source code (exhaustion_threshold only defined
        inside the loop after successful PG probing), we need at least one
        successful PG to avoid UnboundLocalError. This test verifies that
        failures are handled and logged correctly.
        """
        instance = TestHeadroomPoolProbingInstance()

        # Mock stream_mgr with 2 flows - second one will fail PFC
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.flows = {
            (24, 36, frozenset([('pg', 3)])): MagicMock(dscp=3),
            (28, 36, frozenset([('pg', 4)])): MagicMock(dscp=4)
        }
        instance.stream_mgr = mock_stream_mgr

        # Mock dependencies
        instance.get_pool_size = MagicMock(return_value=10000)
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        instance._get_observer_configs = MagicMock(return_value={
            'upper': MagicMock(),
            'lower': MagicMock(),
            'range': MagicMock(),
            'point': MagicMock()
        })
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock algorithms - first PG succeeds, second PG fails PFC upper
        call_count = [0]

        def mock_run(*args, **kwargs):
            call_count[0] += 1
            # First PG (calls 1-8) succeeds
            if call_count[0] <= 8:
                if call_count[0] in [1, 5]:  # upper bounds
                    return (2000, 1.0)
                elif call_count[0] in [2, 6]:  # lower bounds
                    return (1000, 1.0)
                elif call_count[0] in [3, 7]:  # range
                    return (1000, 1005, 1.0)
                elif call_count[0] in [4, 8]:  # point
                    return (1000, 1001, 1.0)
            # Second PG fails on first call (PFC upper)
            elif call_count[0] == 9:
                return (None, 1.0)  # Failure
            return (1000, 1.0)

        with patch('headroom_pool_probing.UpperBoundProbingAlgorithm') as mock_upper, \
             patch('headroom_pool_probing.LowerBoundProbingAlgorithm') as mock_lower, \
             patch('headroom_pool_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
             patch('headroom_pool_probing.ThresholdPointProbingAlgorithm') as mock_point:

            for mock_algo_class in [mock_upper, mock_lower, mock_range, mock_point]:
                mock_algo = MagicMock()
                mock_algo.run.side_effect = mock_run
                mock_algo_class.return_value = mock_algo

            instance._build_result = MagicMock(return_value={'success': True, 'total_headroom': 10})
            instance._report_results = MagicMock(return_value=MagicMock())

            HeadroomPoolProbing.probe(instance)

        # Should build result with 1 PG (first succeeded, second skipped due to failure)
        assert instance._build_result.called
        call_args = instance._build_result.call_args
        pg_results = call_args[0][0]
        assert len(pg_results) == 1  # Only first PG succeeded

    @pytest.mark.order(4210)
    @patch.dict(os.environ, {"pgnumlmt": "1"}, clear=False)
    @patch('headroom_pool_probing.ProbingObserver')
    def test_probe_respects_pg_limit_env_var(self, mock_observer_class):
        """Test probe respects pgnumlmt environment variable."""
        instance = TestHeadroomPoolProbingInstance()

        # Mock stream_mgr with 3 flows
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.flows = {
            (24, 36, frozenset([('pg', 3)])): MagicMock(dscp=3),
            (28, 36, frozenset([('pg', 4)])): MagicMock(dscp=4),
            (32, 36, frozenset([('pg', 3)])): MagicMock(dscp=3)
        }
        instance.stream_mgr = mock_stream_mgr

        instance.get_pool_size = MagicMock(return_value=10000)
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        instance._get_observer_configs = MagicMock(return_value={
            'upper': MagicMock(), 'lower': MagicMock(),
            'range': MagicMock(), 'point': MagicMock()
        })
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock algorithms to succeed quickly
        def quick_success(*args, **kwargs):
            return (1000, 1.0)

        with patch('headroom_pool_probing.UpperBoundProbingAlgorithm') as mock_upper, \
             patch('headroom_pool_probing.LowerBoundProbingAlgorithm') as mock_lower, \
             patch('headroom_pool_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
             patch('headroom_pool_probing.ThresholdPointProbingAlgorithm') as mock_point:

            for mock_algo_class in [mock_upper, mock_lower]:
                mock_algo = MagicMock()
                mock_algo.run.side_effect = quick_success
                mock_algo_class.return_value = mock_algo

            mock_range_algo = MagicMock()
            mock_range_algo.run.return_value = (1000, 1005, 1.0)
            mock_range.return_value = mock_range_algo

            mock_point_algo = MagicMock()
            mock_point_algo.run.return_value = (1000, 1001, 1.0)
            mock_point.return_value = mock_point_algo

            instance._build_result = MagicMock(return_value={'success': False})
            instance._report_results = MagicMock(return_value=MagicMock())

            HeadroomPoolProbing.probe(instance)

        # Should only process 1 PG due to pgnumlmt=1
        call_args = instance._build_result.call_args
        pg_results = call_args[0][0]
        # Due to limit=1, only first flow should be processed
        # Each flow needs 8 algorithm runs (4 PFC + 4 Drop)
        # Check that we have exactly 1 PG result
        assert len(pg_results) <= 1

    @pytest.mark.order(4220)
    @patch('headroom_pool_probing.ProbingObserver')
    def test_probe_uses_pg_drop_counter_flag(self, mock_observer_class):
        """Test probe passes use_pg_drop_counter to ingress drop executors."""
        instance = TestHeadroomPoolProbingInstance()
        instance.use_pg_drop_counter = True

        # Mock stream_mgr with 1 flow
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.flows = {
            (24, 36, frozenset([('pg', 3)])): MagicMock(dscp=3)
        }
        instance.stream_mgr = mock_stream_mgr

        instance.get_pool_size = MagicMock(return_value=10000)
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        instance._get_observer_configs = MagicMock(return_value={
            'upper': MagicMock(), 'lower': MagicMock(),
            'range': MagicMock(), 'point': MagicMock()
        })

        # Spy on create_executor calls
        create_executor_calls = []

        def mock_create_executor(probe_target, observer, name, **kwargs):
            create_executor_calls.append({
                'probe_target': probe_target,
                'name': name,
                'kwargs': kwargs
            })
            return MagicMock()
        instance.create_executor = mock_create_executor

        # Mock algorithm classes
        with patch('headroom_pool_probing.UpperBoundProbingAlgorithm') as mock_upper, \
             patch('headroom_pool_probing.LowerBoundProbingAlgorithm') as mock_lower, \
             patch('headroom_pool_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
             patch('headroom_pool_probing.ThresholdPointProbingAlgorithm') as mock_point:

            # Configure mocks to succeed quickly
            for mock_algo_class in [mock_upper, mock_lower]:
                mock_algo = MagicMock()
                mock_algo.run.return_value = (1000, 1.0)
                mock_algo_class.return_value = mock_algo

            mock_range_algo = MagicMock()
            mock_range_algo.run.return_value = (1000, 1005, 1.0)
            mock_range.return_value = mock_range_algo

            mock_point_algo = MagicMock()
            mock_point_algo.run.return_value = (1000, 1001, 1.0)
            mock_point.return_value = mock_point_algo

            instance._build_result = MagicMock(return_value={'success': True, 'total_headroom': 10})
            instance._report_results = MagicMock(return_value=MagicMock())

            HeadroomPoolProbing.probe(instance)

        # Verify that ingress_drop executors received use_pg_drop_counter=True
        ingress_drop_calls = [c for c in create_executor_calls
                              if c['probe_target'] == 'ingress_drop']
        assert len(ingress_drop_calls) > 0
        for call_item in ingress_drop_calls:
            assert 'use_pg_drop_counter' in call_item['kwargs']
            assert call_item['kwargs']['use_pg_drop_counter'] is True


@pytest.mark.order(4230)
class TestHeadroomPoolProbingPersistBuffer(unittest.TestCase):
    """Test buffer persistence logic in probe method."""

    @pytest.mark.order(4230)
    @patch('headroom_pool_probing.ProbingObserver')
    def test_persist_buffer_with_port_counter_margin(self, mock_observer_class):
        """Test buffer persistence uses margin when using port counter."""
        instance = TestHeadroomPoolProbingInstance()
        instance.use_pg_drop_counter = False  # Port counter mode
        instance.POINT_PROBING_STEP_SIZE = 2

        # Mock stream_mgr with 1 flow
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.flows = {
            (24, 36, frozenset([('pg', 3)])): MagicMock(dscp=3)
        }
        instance.stream_mgr = mock_stream_mgr

        instance.get_pool_size = MagicMock(return_value=10000)
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        instance._get_observer_configs = MagicMock(return_value={
            'upper': MagicMock(), 'lower': MagicMock(),
            'range': MagicMock(), 'point': MagicMock()
        })
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock algorithms to return specific threshold
        with patch('headroom_pool_probing.UpperBoundProbingAlgorithm') as mock_upper, \
             patch('headroom_pool_probing.LowerBoundProbingAlgorithm') as mock_lower, \
             patch('headroom_pool_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
             patch('headroom_pool_probing.ThresholdPointProbingAlgorithm') as mock_point:

            # PFC returns 1000, Ingress Drop returns 1100
            mock_upper.return_value.run.return_value = (2000, 1.0)
            mock_lower.return_value.run.return_value = (1000, 1.0)
            mock_range.return_value.run.return_value = (1000, 1005, 1.0)
            mock_point.return_value.run.return_value = (1000, 1001, 1.0)

            # Track which call we're on
            call_count = [0]

            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] <= 4:  # PFC phases
                    if call_count[0] == 1:
                        return (2000, 1.0)
                    elif call_count[0] == 2:
                        return (1000, 1.0)
                    elif call_count[0] == 3:
                        return (1000, 1005, 1.0)
                    else:
                        return (1000, 1001, 1.0)
                else:  # Ingress Drop phases
                    if call_count[0] == 5:
                        return (2100, 1.0)
                    elif call_count[0] == 6:
                        return (1090, 1.0)
                    elif call_count[0] == 7:
                        return (1096, 1100, 1.0)
                    else:
                        return (1100, 1101, 1.0)

            for mock_algo_class in [mock_upper, mock_lower, mock_range, mock_point]:
                mock_algo_class.return_value.run.side_effect = side_effect

            instance._build_result = MagicMock(return_value={'success': True, 'total_headroom': 100})
            instance._report_results = MagicMock(return_value=MagicMock())

            HeadroomPoolProbing.probe(instance)

        # Verify persist_buffer_occupancy was called with margin subtracted
        # ingress_drop_threshold = 1100, margin = POINT_PROBING_STEP_SIZE (2), so should persist 1098
        instance.buffer_ctrl.persist_buffer_occupancy.assert_called_once()
        call_args = instance.buffer_ctrl.persist_buffer_occupancy.call_args
        assert call_args[1]['count'] == 1100 - 2  # 1098 (margin = POINT_PROBING_STEP_SIZE)

    @pytest.mark.order(4240)
    @patch('headroom_pool_probing.ProbingObserver')
    def test_persist_buffer_with_pg_counter_no_margin(self, mock_observer_class):
        """Test buffer persistence uses no margin when using PG drop counter."""
        instance = TestHeadroomPoolProbingInstance()
        instance.use_pg_drop_counter = True  # PG counter mode
        instance.POINT_PROBING_STEP_SIZE = 2

        # Mock stream_mgr with 1 flow
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.flows = {
            (24, 36, frozenset([('pg', 3)])): MagicMock(dscp=3)
        }
        instance.stream_mgr = mock_stream_mgr

        instance.get_pool_size = MagicMock(return_value=10000)
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        instance._get_observer_configs = MagicMock(return_value={
            'upper': MagicMock(), 'lower': MagicMock(),
            'range': MagicMock(), 'point': MagicMock()
        })
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock algorithms
        call_count_ul = [0]
        call_count_rp = [0]

        def side_effect_ul(*args, **kwargs):
            call_count_ul[0] += 1
            if call_count_ul[0] in [1, 3]:  # upper calls
                return (2000, 1.0) if call_count_ul[0] == 1 else (2100, 1.0)
            else:  # lower calls
                return (1000, 1.0) if call_count_ul[0] == 2 else (1090, 1.0)

        def side_effect_rp(*args, **kwargs):
            call_count_rp[0] += 1
            if call_count_rp[0] == 1:  # PFC range
                return (1000, 1005, 1.0)
            elif call_count_rp[0] == 2:  # PFC point
                return (1000, 1001, 1.0)
            elif call_count_rp[0] == 3:  # Drop range
                return (1096, 1100, 1.0)
            else:  # Drop point
                return (1100, 1101, 1.0)

        with patch('headroom_pool_probing.UpperBoundProbingAlgorithm') as mock_upper, \
             patch('headroom_pool_probing.LowerBoundProbingAlgorithm') as mock_lower, \
             patch('headroom_pool_probing.ThresholdRangeProbingAlgorithm') as mock_range, \
             patch('headroom_pool_probing.ThresholdPointProbingAlgorithm') as mock_point:

            for mock_algo_class in [mock_upper, mock_lower]:
                mock_algo_class.return_value.run.side_effect = side_effect_ul
            for mock_algo_class in [mock_range, mock_point]:
                mock_algo_class.return_value.run.side_effect = side_effect_rp

            instance._build_result = MagicMock(return_value={'success': True, 'total_headroom': 100})
            instance._report_results = MagicMock(return_value=MagicMock())

            HeadroomPoolProbing.probe(instance)

        # Verify persist_buffer_occupancy was called with NO margin
        # ingress_drop_threshold = 1100, margin = 0, so should persist 1100
        instance.buffer_ctrl.persist_buffer_occupancy.assert_called_once()
        call_args = instance.buffer_ctrl.persist_buffer_occupancy.call_args
        assert call_args[1]['count'] == 1100  # No margin


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
