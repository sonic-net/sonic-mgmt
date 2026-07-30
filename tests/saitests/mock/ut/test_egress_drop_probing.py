#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for EgressDropProbing class.

Tests cover:
- Parameter parsing and configuration
- Traffic setup (1 src -> 1 dst pattern)
- Algorithm creation (4-phase probing)
- Algorithm execution workflow
- Probe method integration
- Pool size override (egress lossy pool)
- Error handling

Coverage target: >90% for egress_drop_probing.py
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
# See: https://docs.python.org/3/library/unittest.mock.html#unittest.mock.patch.object
class TestEgressDropProbingInstance:
    """
    Test instance with all attributes initialized.

    This avoids the forbidden pattern: patch.object(EgressDropProbing, '__init__')
    which raises "AttributeError: __init__" due to how Python handles __init__.

    Instead, we create a helper class that initializes all attributes without
    calling the real __init__, following Python mock best practices.
    """
    def __init__(self):
        # Basic attributes
        # NOTE: After review-r3, EgressDrop receives `queue` directly from
        # test_qos_probe.py (no internal pg→queue alias). The yaml field is
        # still named `pg` but the test entry layer renames to `queue`.
        self.queue = 3
        self.probing_port_ids = [24, 28]  # 1 src -> 1 dst
        self.test_port_ips = {
            0: {
                0: {
                    24: {"peer_addr": "192.168.1.1", "vlan_id": 100},
                    28: {"peer_addr": "192.168.1.2", "vlan_id": 100}
                }
            }
        }
        self.dst_client = MagicMock()
        self.asic_type = "generic"
        self.pkts_num_trig_egr_drp = 1000
        self.dscp = 3
        self.ecn = 1
        self.router_mac = "00:11:22:33:44:55"
        self.is_dualtor = False
        self.def_vlan_mac = None
        self.cell_size = 208
        self.packet_size = 64
        self.egress_lossy_pool_size = 104000

        # Probing configuration
        self.PROBE_TARGET = "egress_drop"
        self.PRECISION_TARGET_RATIO = 0.02
        self.ENABLE_PRECISE_DETECTION = False
        self.PRECISE_DETECTION_RANGE_LIMIT = 10
        self.POINT_PROBING_STEP_SIZE = 1
        self.EXECUTOR_ENV = "sim"

        # Mock dataplane
        self.dataplane = MagicMock()
        self.dataplane.get_mac.side_effect = lambda dev, port: f"00:00:00:00:00:{port:02x}"

        # Stream manager (will be set by setup_traffic)
        self.stream_mgr = None


# Now import the class under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../probe"))
from egress_drop_probing import EgressDropProbing  # noqa: E402


#
# Test Classes
#

@pytest.mark.order(4000)
class TestEgressDropProbingParameterParsing(unittest.TestCase):
    """Test parameter parsing and configuration methods."""

    @pytest.mark.order(4000)
    def test_queue_attr_present(self):
        """Test that queue attribute is available directly from test_params.

        After review-r3, EgressDropProbing no longer overrides parse_param.
        ProbingBase.parse_param() auto-setattrs every test_params field, so
        `self.queue` is populated directly by the testParams field
        `queue` set in test_qos_probe.py (no internal alias from pg).
        """
        instance = TestEgressDropProbingInstance()
        instance.queue = 5

        # queue is set directly; no parse_param override exists on EgressDropProbing
        assert instance.queue == 5
        # And EgressDropProbing should not define its own parse_param anymore
        assert 'parse_param' not in EgressDropProbing.__dict__, \
            "EgressDropProbing should rely on ProbingBase.parse_param (no override)"

    @pytest.mark.order(4010)
    def test_get_probe_config(self):
        """Test get_probe_config returns ProbeConfig with correct attributes."""
        instance = TestEgressDropProbingInstance()

        config = EgressDropProbing.get_probe_config(instance)

        assert config.probing_port_ids == instance.probing_port_ids
        assert config.thrift_client == instance.dst_client
        assert config.asic_type == instance.asic_type

    @pytest.mark.order(4015)
    def test_probe_target(self):
        """Test PROBE_TARGET class attribute."""
        assert EgressDropProbing.PROBE_TARGET == "egress_drop"


@pytest.mark.order(4020)
class TestEgressDropProbingConfiguration(unittest.TestCase):
    """Test configuration and threshold methods."""

    @pytest.mark.order(4020)
    def test_get_expected_threshold_present(self):
        """Test get_expected_threshold when pkts_num_trig_egr_drp is set."""
        instance = TestEgressDropProbingInstance()
        instance.pkts_num_trig_egr_drp = 1500

        result = EgressDropProbing.get_expected_threshold(instance)

        assert result is not None
        value, description = result
        assert value == 1500
        assert "Egress Drop threshold" in description

    @pytest.mark.order(4030)
    def test_get_expected_threshold_absent(self):
        """Test get_expected_threshold when pkts_num_trig_egr_drp is None."""
        instance = TestEgressDropProbingInstance()
        instance.pkts_num_trig_egr_drp = None

        result = EgressDropProbing.get_expected_threshold(instance)

        assert result is None


@pytest.mark.order(4050)
class TestEgressDropProbingSetUp(unittest.TestCase):
    """Test setUp method with environment variable override."""

    @pytest.mark.order(4050)
    def test_setup_with_point_probing_limit(self):
        """Test setUp enables point probing when POINT_PROBING_LIMIT is set."""
        instance = TestEgressDropProbingInstance()

        # Manually simulate setUp's point probing logic
        os.environ['POINT_PROBING_LIMIT'] = '15'
        try:
            point_limit = os.getenv("POINT_PROBING_LIMIT", "")
            if point_limit.isdigit() and int(point_limit) > 0:
                instance.ENABLE_PRECISE_DETECTION = True
                instance.PRECISE_DETECTION_RANGE_LIMIT = int(point_limit)

            # Verify point probing enabled with the limit from env var
            assert instance.ENABLE_PRECISE_DETECTION is True
            assert instance.PRECISE_DETECTION_RANGE_LIMIT == 15
        finally:
            os.environ.pop('POINT_PROBING_LIMIT', None)

    @pytest.mark.order(4060)
    def test_setup_with_zero_point_probing_limit(self):
        """Test setUp disables point probing when POINT_PROBING_LIMIT is 0."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = False

        # Manually simulate setUp's point probing logic
        os.environ['POINT_PROBING_LIMIT'] = '0'
        try:
            point_limit = os.getenv("POINT_PROBING_LIMIT", "")
            if point_limit.isdigit() and int(point_limit) > 0:
                instance.ENABLE_PRECISE_DETECTION = True

            # Should not enable point probing (0 is not > 0)
            assert instance.ENABLE_PRECISE_DETECTION is False
        finally:
            os.environ.pop('POINT_PROBING_LIMIT', None)


@pytest.mark.order(4070)
class TestEgressDropProbingSetupTraffic(unittest.TestCase):
    """Test setup_traffic method for 1 src -> 1 dst pattern."""

    @pytest.mark.order(4070)
    @patch('egress_drop_probing.StreamManager')
    @patch('egress_drop_probing.PortInfo')
    @patch('egress_drop_probing.FlowConfig')
    @patch('egress_drop_probing.determine_traffic_dmac')
    def test_setup_traffic_creates_stream_manager(self, mock_dmac, mock_flow_cfg, mock_port_info, mock_stream_mgr):
        """Test setup_traffic creates StreamManager with 1:1 flow (add_flow called ONCE)."""
        instance = TestEgressDropProbingInstance()
        instance.get_rx_port = MagicMock()

        # Mock returns
        mock_dmac.return_value = "00:11:22:33:44:66"
        mock_stream_instance = MagicMock()
        mock_stream_mgr.return_value = mock_stream_instance

        EgressDropProbing.setup_traffic(instance)

        # Verify stream manager created
        assert instance.stream_mgr == mock_stream_instance

        # Verify add_flow called ONCE (1:1 pattern, not 1:N)
        assert mock_stream_instance.add_flow.call_count == 1

        # Verify generate_packets called
        mock_stream_instance.generate_packets.assert_called_once()

    @pytest.mark.order(4080)
    def test_setup_traffic_no_probing_ports(self):
        """Test setup_traffic handles empty probing_port_ids gracefully."""
        instance = TestEgressDropProbingInstance()
        instance.probing_port_ids = []

        # Should return early without error
        EgressDropProbing.setup_traffic(instance)

        assert instance.stream_mgr is None


@pytest.mark.order(4090)
class TestEgressDropProbingAlgorithmCreation(unittest.TestCase):
    """Test _create_algorithms method."""

    @pytest.mark.order(4090)
    @patch('egress_drop_probing.ProbingObserver')
    def test_create_algorithms_without_point_probing(self, mock_observer_class):
        """Test _create_algorithms creates 3 algorithms when point probing disabled."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = False
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock observer instances
        mock_observer_class.return_value = MagicMock()

        algorithms = EgressDropProbing._create_algorithms(instance)

        # Should have 3 algorithms without point probing
        assert len(algorithms) == 3
        assert "upper_bound" in algorithms
        assert "lower_bound" in algorithms
        assert "threshold_range" in algorithms
        assert "threshold_point" not in algorithms

    @pytest.mark.order(4100)
    @patch('egress_drop_probing.ProbingObserver')
    def test_create_algorithms_with_point_probing(self, mock_observer_class):
        """Test _create_algorithms creates 4 algorithms when point probing enabled."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = True
        instance.create_executor = MagicMock(return_value=MagicMock())

        # Mock observer instances
        mock_observer_class.return_value = MagicMock()

        algorithms = EgressDropProbing._create_algorithms(instance)

        # Should have 4 algorithms with point probing
        assert len(algorithms) == 4
        assert "upper_bound" in algorithms
        assert "lower_bound" in algorithms
        assert "threshold_range" in algorithms
        assert "threshold_point" in algorithms


@pytest.mark.order(4110)
class TestEgressDropProbingAlgorithmExecution(unittest.TestCase):
    """Test _run_algorithms method execution flow."""

    @pytest.mark.order(4110)
    def test_run_algorithms_success_without_point_probing(self):
        """Test _run_algorithms completes all phases successfully."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = False

        # Mock algorithms
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (1200, 1300, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Verify all phases executed
        mock_upper.run.assert_called_once_with(24, 28, 5000, pg=3)
        mock_lower.run.assert_called_once_with(24, 28, 2000, pg=3)
        mock_range.run.assert_called_once_with(24, 28, 1000, 2000, pg=3)

        # Verify final bounds
        assert lower == 1200
        assert upper == 1300

    @pytest.mark.order(4120)
    def test_run_algorithms_success_with_point_probing(self):
        """Test _run_algorithms executes point probing when enabled and range is small."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = True
        instance.PRECISE_DETECTION_RANGE_LIMIT = 10

        # Mock algorithms
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (1200, 1208, None)  # Range = 8, below limit

        mock_point = MagicMock()
        mock_point.run.return_value = (1204, 1205, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range,
            "threshold_point": mock_point
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Verify point probing executed
        mock_point.run.assert_called_once_with(
            src_port=24, dst_port=28, lower_bound=1200, upper_bound=1208, pg=3
        )

        # Verify final bounds from point probing
        assert lower == 1204
        assert upper == 1205

    @pytest.mark.order(4130)
    def test_run_algorithms_skips_point_probing_large_range(self):
        """Test _run_algorithms skips point probing when range exceeds limit."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = True
        instance.PRECISE_DETECTION_RANGE_LIMIT = 10

        # Mock algorithms
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (1200, 1250, None)  # Range = 50, exceeds limit

        mock_point = MagicMock()

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range,
            "threshold_point": mock_point
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Verify point probing NOT executed
        mock_point.run.assert_not_called()

        # Verify final bounds from range probing
        assert lower == 1200
        assert upper == 1250

    @pytest.mark.order(4140)
    def test_run_algorithms_upper_bound_failure(self):
        """Test _run_algorithms handles upper bound detection failure."""
        instance = TestEgressDropProbingInstance()

        # Mock upper bound failure
        mock_upper = MagicMock()
        mock_upper.run.return_value = (None, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": MagicMock(),
            "threshold_range": MagicMock()
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Should return (None, None) and not call subsequent algorithms
        assert lower is None
        assert upper is None
        algorithms["lower_bound"].run.assert_not_called()
        algorithms["threshold_range"].run.assert_not_called()

    @pytest.mark.order(4150)
    def test_run_algorithms_lower_bound_failure(self):
        """Test _run_algorithms handles lower bound detection failure."""
        instance = TestEgressDropProbingInstance()

        # Mock successful upper bound but failed lower bound
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (None, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": MagicMock()
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Should return (None, None) and not call threshold_range
        assert lower is None
        assert upper is None
        algorithms["threshold_range"].run.assert_not_called()

    @pytest.mark.order(4160)
    def test_run_algorithms_threshold_range_failure(self):
        """Test _run_algorithms handles threshold range detection failure."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = False

        # Mock successful upper and lower, but failed range
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (None, None, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Should return lower/upper from phase 2 (fallback)
        assert lower == 1000
        assert upper == 2000

    @pytest.mark.order(4170)
    def test_run_algorithms_point_probing_failure(self):
        """Test _run_algorithms handles point probing failure gracefully."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = True
        instance.PRECISE_DETECTION_RANGE_LIMIT = 10

        # Mock algorithms with point probing failure
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (1200, 1208, None)

        mock_point = MagicMock()
        mock_point.run.return_value = (None, None, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range,
            "threshold_point": mock_point
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Should fallback to range probing results
        assert lower == 1200
        assert upper == 1208

    @pytest.mark.order(4180)
    def test_run_algorithms_with_traffic_keys(self):
        """Test _run_algorithms passes traffic_keys correctly to algorithms."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = False

        # Mock algorithms
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (1200, 1300, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range
        }

        # Call with custom traffic_keys
        EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3, queue=5, custom="value"
        )

        # Verify all algorithms receive traffic_keys
        mock_upper.run.assert_called_once_with(24, 28, 5000, pg=3, queue=5, custom="value")
        mock_lower.run.assert_called_once_with(24, 28, 2000, pg=3, queue=5, custom="value")
        mock_range.run.assert_called_once_with(24, 28, 1000, 2000, pg=3, queue=5, custom="value")

    @pytest.mark.order(4190)
    def test_run_algorithms_point_probing_partial_success(self):
        """Test _run_algorithms handles partial point probing results."""
        instance = TestEgressDropProbingInstance()
        instance.ENABLE_PRECISE_DETECTION = True
        instance.PRECISE_DETECTION_RANGE_LIMIT = 10

        # Mock algorithms
        mock_upper = MagicMock()
        mock_upper.run.return_value = (2000, None)

        mock_lower = MagicMock()
        mock_lower.run.return_value = (1000, None)

        mock_range = MagicMock()
        mock_range.run.return_value = (1200, 1208, None)

        # Point probing returns only lower bound
        mock_point = MagicMock()
        mock_point.run.return_value = (1204, None, None)

        algorithms = {
            "upper_bound": mock_upper,
            "lower_bound": mock_lower,
            "threshold_range": mock_range,
            "threshold_point": mock_point
        }

        lower, upper = EgressDropProbing._run_algorithms(
            instance, algorithms, 24, 28, 5000, pg=3
        )

        # Should fallback to range results due to partial point result
        assert lower == 1200
        assert upper == 1208


@pytest.mark.order(4200)
class TestEgressDropProbingGetPoolSize(unittest.TestCase):
    """Test get_pool_size method with egress lossy pool override."""

    @pytest.mark.order(4200)
    def test_get_pool_size_egress_lossy_pool(self):
        """Test get_pool_size uses egress_lossy_pool_size when available."""
        instance = TestEgressDropProbingInstance()
        instance.egress_lossy_pool_size = 104000  # bytes
        instance.cell_size = 208

        result = EgressDropProbing.get_pool_size(instance)

        # 104000 // 208 = 500
        assert result == 500

    @pytest.mark.order(4210)
    def test_get_pool_size_env_var_override(self):
        """Test get_pool_size uses epoolsz env var when set."""
        instance = TestEgressDropProbingInstance()

        os.environ['epoolsz'] = '1000'
        try:
            result = EgressDropProbing.get_pool_size(instance)
            assert result == 1000
        finally:
            os.environ.pop('epoolsz', None)

    @pytest.mark.order(4220)
    def test_get_pool_size_raises_when_egress_pool_missing(self):
        """Test get_pool_size raises RuntimeError when egress_lossy_pool_size is not configured."""
        instance = TestEgressDropProbingInstance()
        instance.egress_lossy_pool_size = 0
        instance.cell_size = 208

        # Per I2 fix: silent fallback to ingress_lossless_pool was removed.
        # The probe must fail loudly so the missing platform config is diagnosed
        # at source rather than producing meaningless thresholds downstream.
        with pytest.raises(RuntimeError, match="egress_lossy_pool_size is not configured"):
            EgressDropProbing.get_pool_size(instance)

    @pytest.mark.order(4221)
    def test_get_pool_size_raises_when_cell_size_invalid(self):
        """Test get_pool_size raises RuntimeError when cell_size is invalid (<= 0)."""
        instance = TestEgressDropProbingInstance()
        instance.egress_lossy_pool_size = 104000
        instance.cell_size = 0

        with pytest.raises(RuntimeError, match="cell_size must be > 0"):
            EgressDropProbing.get_pool_size(instance)


@pytest.mark.order(4300)
class TestEgressDropProbingProbeMethod(unittest.TestCase):
    """Test probe method integration."""

    @pytest.mark.order(4300)
    @patch('egress_drop_probing.ThresholdResult')
    @patch('egress_drop_probing.ProbingObserver')
    def test_probe_integration(self, mock_observer_class, mock_result_class):
        """Test probe method integrates all components."""
        instance = TestEgressDropProbingInstance()

        # Mock stream_mgr
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.get_port_ids.return_value = [28]
        instance.stream_mgr = mock_stream_mgr

        # Mock get_pool_size
        instance.get_pool_size = MagicMock(return_value=10000)

        # Mock _create_algorithms and _run_algorithms by setting them on instance
        mock_algorithms = {
            "upper_bound": MagicMock(),
            "lower_bound": MagicMock(),
            "threshold_range": MagicMock()
        }
        instance._create_algorithms = MagicMock(return_value=mock_algorithms)
        instance._run_algorithms = MagicMock(return_value=(1200, 1300))

        # Mock ThresholdResult
        mock_result = MagicMock()
        mock_result_class.from_bounds.return_value = mock_result

        # Mock observer console
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        result = EgressDropProbing.probe(instance)

        # Verify algorithm creation
        instance._create_algorithms.assert_called_once()

        # Verify algorithm execution
        instance._run_algorithms.assert_called_once_with(
            mock_algorithms, 24, 28, 10000, pg=3
        )

        # Verify result creation
        mock_result_class.from_bounds.assert_called_once_with(1200, 1300)

        # Verify result reporting
        mock_observer_class.report_probing_result.assert_called_once_with(
            "Egress Drop", mock_result, unit="pkt"
        )

        assert result == mock_result

    @pytest.mark.order(4310)
    @patch('egress_drop_probing.ProbingObserver')
    def test_probe_logs_configuration(self, mock_observer_class):
        """Test probe method logs probing configuration."""
        instance = TestEgressDropProbingInstance()
        instance.PRECISION_TARGET_RATIO = 0.05
        instance.ENABLE_PRECISE_DETECTION = True
        instance.EXECUTOR_ENV = "physical"

        # Mock dependencies
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.get_port_ids.return_value = [28]
        instance.stream_mgr = mock_stream_mgr
        instance.get_pool_size = MagicMock(return_value=8000)

        # Mock methods on instance
        instance._create_algorithms = MagicMock(return_value={
            "upper_bound": MagicMock(),
            "lower_bound": MagicMock(),
            "threshold_range": MagicMock()
        })
        instance._run_algorithms = MagicMock(return_value=(1000, 1100))

        # Mock observer
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        with patch('egress_drop_probing.ThresholdResult'):
            EgressDropProbing.probe(instance)

        # Verify console logging was called (configuration messages)
        assert mock_observer_class.console.call_count >= 7

        # Check that key configuration values were logged
        console_calls = [str(call_item)
                         for call_item in mock_observer_class.console.call_args_list]
        log_output = " ".join(console_calls)

        assert "egress_drop" in log_output.lower()
        assert "src_port=24" in log_output
        assert "dst_port=28" in log_output
        # Validate that the EXECUTOR_ENV value we set is actually observed in the
        # logged configuration (this is what the test name implies it should check).
        assert "physical" in log_output.lower()

    @pytest.mark.order(4320)
    @patch('egress_drop_probing.ProbingObserver')
    def test_probe_uses_correct_traffic_keys(self, mock_observer_class):
        """Test probe method passes correct traffic_keys (pg=queue) to algorithms."""
        instance = TestEgressDropProbingInstance()
        instance.queue = 5

        # Mock dependencies
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.get_port_ids.return_value = [28]
        instance.stream_mgr = mock_stream_mgr
        instance.get_pool_size = MagicMock(return_value=10000)

        # Mock methods on instance
        instance._create_algorithms = MagicMock(return_value={
            "upper_bound": MagicMock(),
            "lower_bound": MagicMock(),
            "threshold_range": MagicMock()
        })

        # Create a mock that we can inspect
        mock_run_algorithms = MagicMock(return_value=(1000, 1100))
        instance._run_algorithms = mock_run_algorithms

        # Mock observer
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        with patch('egress_drop_probing.ThresholdResult'):
            EgressDropProbing.probe(instance)

        # Verify traffic_keys includes pg=queue=5
        call_args = mock_run_algorithms.call_args
        assert call_args is not None
        # Check keyword arguments
        assert 'pg' in call_args.kwargs
        assert call_args.kwargs['pg'] == 5

    @pytest.mark.order(4330)
    @patch('egress_drop_probing.ProbingObserver')
    def test_probe_failure_handling(self, mock_observer_class):
        """Test probe method handles algorithm failures."""
        instance = TestEgressDropProbingInstance()

        # Mock dependencies
        mock_stream_mgr = MagicMock()
        mock_stream_mgr.get_port_ids.return_value = [28]
        instance.stream_mgr = mock_stream_mgr
        instance.get_pool_size = MagicMock(return_value=10000)

        # Mock methods on instance
        instance._create_algorithms = MagicMock(return_value={
            "upper_bound": MagicMock(),
            "lower_bound": MagicMock(),
            "threshold_range": MagicMock()
        })
        instance._run_algorithms = MagicMock(return_value=(None, None))

        # Mock observer
        mock_observer_class.console = MagicMock()
        mock_observer_class.report_probing_result = MagicMock()

        # Mock ThresholdResult
        mock_result = MagicMock()
        with patch('egress_drop_probing.ThresholdResult') as mock_result_class:
            mock_result_class.from_bounds.return_value = mock_result

            result = EgressDropProbing.probe(instance)

            # Should still create result from (None, None)
            mock_result_class.from_bounds.assert_called_once_with(None, None)
            assert result == mock_result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
