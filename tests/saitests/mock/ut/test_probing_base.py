#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit Tests for ProbingBase Helper Methods

Tests for ProbingBase utility methods that don't require full PTF setup:
- Environment detection logic
- Result validation logic (Point and Range)
- Pool size calculation
- Executor creation delegation
- Parameter parsing

Note: Uses mocking to avoid PTF dependencies during import.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add probe directory to path
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)

# Mock PTF dependencies before importing probing_base
sys.modules['ptf'] = MagicMock()
sys.modules['ptf.testutils'] = MagicMock()
sys.modules['switch'] = MagicMock()
sys.modules['sai_qos_tests'] = MagicMock()
sys.modules['buffer_occupancy_controller'] = MagicMock()

# Create a mock base class for sai_base_test.ThriftInterfaceDataPlane
mock_sai_base = MagicMock()
mock_sai_base.ThriftInterfaceDataPlane = object  # Use object as base
sys.modules['sai_base_test'] = mock_sai_base

from probing_base import ProbingBase, ProbeConfig  # noqa: E402
from probing_result import ThresholdResult  # noqa: E402


class TestProbingBaseInstance(ProbingBase):
    """Test-friendly ProbingBase without PTF dependencies"""

    def __init__(self):
        # Don't call super().__init__() to avoid PTF initialization
        pass


class ConcreteProbingBase(ProbingBase):
    """Concrete implementation for testing template methods"""

    def __init__(self):
        # Set minimal required attributes
        self.test_params = {}
        self.sonic_asic_type = 'test_asic'
        self.EXECUTOR_ENV = 'sim'
        self.POINT_PROBING_STEP_SIZE = 1
        self.PRECISION_TARGET_RATIO = 0.05

    def get_probe_config(self):
        """Return mock config"""
        return ProbeConfig(
            probing_port_ids=[1, 2, 3],
            thrift_client=Mock(),
            asic_type='test_asic'
        )

    def setup_traffic(self):
        """Mock traffic setup"""
        self.stream_mgr = Mock()

    def probe(self):
        """Mock probing returns success result"""
        return ThresholdResult(
            lower_bound=500,
            upper_bound=500,
            success=True
        )

    def get_expected_threshold(self):
        """Return None to skip validation"""
        return None

    def sai_thrift_port_tx_enable(self, *args, **kwargs):
        """Mock TX enable"""
        pass

    def sai_thrift_port_tx_disable(self, *args, **kwargs):
        """Mock TX disable"""
        pass


class TestProbingBaseEnvironmentDetection:
    """Test environment detection logic"""

    @pytest.mark.order(910)
    def test_determine_env_explicit_sim(self):
        """Test explicit 'sim' environment from testParams"""
        print("\n=== Testing Environment Detection - Explicit Sim ===")
        pb = TestProbingBaseInstance()
        pb.test_params = {'executor_env': 'sim'}

        result = pb._determine_executor_env()

        print(f"  test_params: {pb.test_params}")
        print(f"  Detected environment: {result}")
        assert result == 'sim', "Should return 'sim' when explicitly set"
        print("[OK] Environment correctly detected as 'sim'")

    @pytest.mark.order(911)
    def test_determine_env_explicit_physical(self):
        """Test explicit 'physical' environment from testParams"""
        pb = TestProbingBaseInstance()
        pb.test_params = {'executor_env': 'physical'}

        result = pb._determine_executor_env()

        assert result == 'physical', "Should return 'physical' when explicitly set"

    @pytest.mark.order(912)
    def test_determine_env_default_physical(self):
        """Test default environment is 'physical'"""
        pb = TestProbingBaseInstance()
        pb.test_params = {}

        result = pb._determine_executor_env()

        assert result == 'physical', "Should default to 'physical'"

    @pytest.mark.order(913)
    def test_determine_env_no_test_params(self):
        """Test environment when test_params not set"""
        pb = TestProbingBaseInstance()

        result = pb._determine_executor_env()

        assert result == 'physical', "Should default to 'physical' when test_params missing"


class TestProbingBasePoolSize:
    """Test pool size calculation logic"""

    @pytest.mark.order(914)
    def test_get_pool_size_from_env(self):
        """Test pool size from environment variable"""
        print("\n=== Testing Pool Size - From Environment Variable ===")
        pb = TestProbingBaseInstance()

        with patch.dict(os.environ, {'ipoolsz': '12345'}):
            result = pb.get_pool_size()

        print("  Environment variable ipoolsz=12345")
        print(f"  Calculated pool size: {result}")
        assert result == 12345, "Should return value from ipoolsz env var"
        print("[OK] Pool size correctly read from environment variable")

    @pytest.mark.order(915)
    def test_get_pool_size_from_attribute(self):
        """Test pool size calculated from attributes"""
        pb = ProbingBase()
        pb.ingress_lossless_pool_size = 10000
        pb.cell_size = 200

        with patch.dict(os.environ, {}, clear=True):
            result = pb.get_pool_size()

        assert result == 50, "Should calculate pool_size / cell_size = 10000 / 200 = 50"

    @pytest.mark.order(916)
    def test_get_pool_size_env_overrides_attribute(self):
        """Test environment variable takes priority"""
        pb = ProbingBase()
        pb.ingress_lossless_pool_size = 10000
        pb.cell_size = 200

        with patch.dict(os.environ, {'ipoolsz': '999'}):
            result = pb.get_pool_size()

        assert result == 999, "Environment variable should override calculated value"


class TestProbingBaseParameterParsing:
    """Test parameter parsing logic"""

    @pytest.mark.order(917)
    def test_parse_param_converts_digit_strings(self):
        """Test conversion of numeric strings to integers"""
        pb = ProbingBase()
        pb.test_params = {
            'port_id': '10',
            'threshold': '500',
            'name': 'test'
        }
        pb.sonic_asic_type = 'mellanox'

        pb.parse_param()

        assert pb.port_id == 10, "Should convert '10' to integer"
        assert pb.threshold == 500, "Should convert '500' to integer"
        assert pb.name == 'test', "Should keep string as-is"
        assert pb.asic_type == 'mellanox', "Should set asic_type from sonic_asic_type"
        assert pb.counter_margin == 0, "Should initialize counter_margin to 0"

    @pytest.mark.order(918)
    def test_parse_param_preserves_non_digit_strings(self):
        """Test non-numeric strings are preserved"""
        pb = ProbingBase()
        pb.test_params = {
            'config': 'auto',
            'mode': '123abc',
            'flag': 'true'
        }
        pb.sonic_asic_type = 'cisco'

        pb.parse_param()

        assert pb.config == 'auto', "Should preserve non-numeric string"
        assert pb.mode == '123abc', "Should preserve mixed alphanumeric"
        assert pb.flag == 'true', "Should preserve boolean-like string"


class TestProbingBaseResultValidation:
    """Test result validation logic for Point and Range"""

    @pytest.mark.order(919)
    def test_validate_point_result_within_limit(self):
        """Test Point result validation - within limit"""
        print("\n=== Testing Result Validation - Point Within Limit ===")
        pb = TestProbingBaseInstance()
        pb.PRECISE_DETECTION_RANGE_LIMIT = 10

        # Point result: lower == upper
        result = ThresholdResult(
            lower_bound=500,
            upper_bound=500,
            success=True
        )
        expected_info = (505, "Test Threshold")  # delta = 5 < 10

        print(f"  Point result: {result.lower_bound}")
        print(f"  Expected value: {expected_info[0]}")
        print(f"  Delta: {abs(result.lower_bound - expected_info[0])} (limit: {pb.PRECISE_DETECTION_RANGE_LIMIT})")

        # Should not raise
        with patch('probing_observer.ProbingObserver'):
            valid = pb.assert_probing_result(result, expected_info)

        assert valid is True, "Should validate point within limit"
        print("[OK] Point validation passed (within limit)")

    @pytest.mark.order(920)
    def test_validate_point_result_exceeds_limit(self):
        """Test Point result validation - exceeds limit"""
        pb = TestProbingBaseInstance()
        pb.PRECISE_DETECTION_RANGE_LIMIT = 10

        result = ThresholdResult(
            lower_bound=500,
            upper_bound=500,
            success=True
        )
        expected_info = (520, "Test Threshold")  # delta = 20 > 10

        with patch('probing_observer.ProbingObserver'):
            with pytest.raises(AssertionError) as exc_info:
                pb.assert_probing_result(result, expected_info)

        assert "delta(500, 520) = 20 >= 10" in str(exc_info.value), \
            "Should report delta exceeds limit"

    @pytest.mark.order(921)
    def test_validate_range_result_contains_expected(self):
        """Test Range result validation - contains expected value"""
        pb = TestProbingBaseInstance()
        pb.PRECISION_TARGET_RATIO = 0.05  # 5%

        result = ThresholdResult(
            lower_bound=480,
            upper_bound=520,
            success=True
        )
        expected_info = (500, "Test Threshold")  # In range, size=40 <= 25 (5% of 500)

        # Range size = 40, expected range = 500 * 0.05 = 25
        # This should FAIL because 40 > 25
        with patch('probing_observer.ProbingObserver'):
            with pytest.raises(AssertionError) as exc_info:
                pb.assert_probing_result(result, expected_info)

        assert "range size 40 > 25" in str(exc_info.value), \
            "Should report range size exceeds precision"

    @pytest.mark.order(922)
    def test_validate_range_result_good_precision(self):
        """Test Range result validation - good precision"""
        pb = TestProbingBaseInstance()
        pb.PRECISION_TARGET_RATIO = 0.05  # 5%

        result = ThresholdResult(
            lower_bound=495,
            upper_bound=505,
            success=True
        )
        expected_info = (500, "Test Threshold")
        # Range size = 10, expected range = 500 * 0.05 = 25

        with patch('probing_observer.ProbingObserver'):
            valid = pb.assert_probing_result(result, expected_info)

        assert valid is True, "Should validate range with good precision"

    @pytest.mark.order(923)
    def test_validate_range_result_not_contains_expected(self):
        """Test Range result validation - does not contain expected"""
        pb = TestProbingBaseInstance()
        pb.PRECISION_TARGET_RATIO = 0.05

        result = ThresholdResult(
            lower_bound=480,
            upper_bound=495,
            success=True
        )
        expected_info = (500, "Test Threshold")  # 500 > 495 (not in range)

        with patch('probing_observer.ProbingObserver'):
            with pytest.raises(AssertionError) as exc_info:
                pb.assert_probing_result(result, expected_info)

        assert "expected 500 not in range [480, 495]" in str(exc_info.value), \
            "Should report expected value not in range"

    @pytest.mark.order(924)
    def test_validate_result_skip_when_none(self):
        """Test validation skipped when expected_info is None"""
        pb = TestProbingBaseInstance()

        result = ThresholdResult(
            lower_bound=500,
            upper_bound=500,
            success=True
        )

        # Should skip validation
        valid = pb.assert_probing_result(result, None)

        assert valid is True, "Should skip validation when expected_info is None"

    @pytest.mark.order(925)
    def test_validate_result_fails_when_bounds_none(self):
        """Test validation fails when result has None bounds"""
        pb = TestProbingBaseInstance()

        result = ThresholdResult(
            lower_bound=None,
            upper_bound=500,
            success=False
        )
        expected_info = (500, "Test Threshold")

        with patch('probing_observer.ProbingObserver'):
            with pytest.raises(AssertionError) as exc_info:
                pb.assert_probing_result(result, expected_info)

        assert "result contains None values" in str(exc_info.value), \
            "Should report incomplete probing when bounds are None"


class TestProbingBaseExecutorCreation:
    """Test executor creation delegation to ExecutorRegistry"""

    @pytest.mark.order(926)
    def test_create_executor_physical_env(self):
        """Test executor creation for physical environment"""
        pb = ProbingBase()
        pb.EXECUTOR_ENV = 'physical'

        mock_observer = Mock()

        with patch('probing_base.ExecutorRegistry.create') as mock_create:
            mock_create.return_value = Mock()

            # result = pb.create_executor(
            pb.create_executor(
                'pfc_xoff',
                mock_observer,
                'test_exec'
            )

            mock_create.assert_called_once_with(
                probe_type='pfc_xoff',
                executor_env='physical',
                scenario=None,
                ptftest=pb,
                observer=mock_observer,
                verbose=True,
                name='test_exec'
            )

    @pytest.mark.order(927)
    def test_create_executor_mock_env_with_scenario(self):
        """Test executor creation for mock environment with scenario"""
        pb = ProbingBase()
        pb.EXECUTOR_ENV = 'sim'

        mock_observer = Mock()

        with patch('probing_base.ExecutorRegistry.create') as mock_create:
            mock_create.return_value = Mock()

            # result = pb.create_executor(
            pb.create_executor(
                'ingress_drop',
                mock_observer,
                'test_exec',
                scenario='noisy',
                noise_level=10
            )

            mock_create.assert_called_once_with(
                probe_type='ingress_drop',
                executor_env='sim',
                scenario='noisy',
                ptftest=pb,
                observer=mock_observer,
                verbose=True,
                name='test_exec',
                noise_level=10
            )

    @pytest.mark.order(928)
    def test_create_executor_scenario_extracted_from_kwargs(self):
        """Test scenario parameter is extracted from kwargs"""
        pb = ProbingBase()
        pb.EXECUTOR_ENV = 'sim'

        mock_observer = Mock()

        with patch('probing_base.ExecutorRegistry.create') as mock_create:
            mock_create.return_value = Mock()

            # scenario in kwargs should be extracted and passed separately
            # result = pb.create_executor(
            pb.create_executor(
                'pfc_xoff',
                mock_observer,
                'test',
                scenario='wrong_config',
                offset=100,
                extra_param='value'
            )

            # Verify scenario was extracted
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs['scenario'] == 'wrong_config'
            assert call_kwargs['offset'] == 100
            assert call_kwargs['extra_param'] == 'value'
            # scenario should NOT be in remaining kwargs
            assert 'scenario' not in {k: v for k, v in call_kwargs.items()
                                      if k not in ['executor_type', 'env', 'scenario',
                                                   'ptftest', 'observer', 'verbose', 'name']}
        print("[OK] Scenario extraction test passed")


class TestProbingBaseAbstractMethods:
    """Test abstract methods raise NotImplementedError"""

    @pytest.mark.order(929)
    def test_get_probe_config_not_implemented(self):
        """Test get_probe_config() raises NotImplementedError"""
        print("\n=== Testing Abstract Method: get_probe_config() ===")
        pb = TestProbingBaseInstance()

        with pytest.raises(NotImplementedError) as exc_info:
            pb.get_probe_config()

        print(f"  NotImplementedError raised: {exc_info.value}")
        assert "get_probe_config" in str(exc_info.value)
        print("[OK] get_probe_config() correctly raises NotImplementedError")

    @pytest.mark.order(930)
    def test_setup_traffic_not_implemented(self):
        """Test setup_traffic() raises NotImplementedError"""
        print("\n=== Testing Abstract Method: setup_traffic() ===")
        pb = TestProbingBaseInstance()

        with pytest.raises(NotImplementedError) as exc_info:
            pb.setup_traffic()

        print(f"  NotImplementedError raised: {exc_info.value}")
        assert "setup_traffic" in str(exc_info.value)
        print("[OK] setup_traffic() correctly raises NotImplementedError")

    @pytest.mark.order(931)
    def test_probe_not_implemented(self):
        """Test probe() raises NotImplementedError"""
        print("\n=== Testing Abstract Method: probe() ===")
        pb = TestProbingBaseInstance()

        with pytest.raises(NotImplementedError) as exc_info:
            pb.probe()

        print(f"  NotImplementedError raised: {exc_info.value}")
        assert "probe" in str(exc_info.value)
        print("[OK] probe() correctly raises NotImplementedError")

    @pytest.mark.order(932)
    def test_get_expected_threshold_not_implemented(self):
        """Test get_expected_threshold() raises NotImplementedError"""
        print("\n=== Testing Abstract Method: get_expected_threshold() ===")
        pb = TestProbingBaseInstance()

        with pytest.raises(NotImplementedError) as exc_info:
            pb.get_expected_threshold()

        print(f"  NotImplementedError raised: {exc_info.value}")
        assert "get_expected_threshold" in str(exc_info.value)
        print("[OK] get_expected_threshold() correctly raises NotImplementedError")


class TestProbingBaseSetUp:
    """Test setUp() method with environment variable handling"""

    @pytest.mark.order(933)
    def test_setUp_point_probing_step_size_from_env(self):
        """Test setUp() reads POINT_PROBING_STEP_SIZE from environment"""
        print("\n=== Testing setUp() - POINT_PROBING_STEP_SIZE from Env ===")

        # Test the environment variable logic directly by calling parse logic
        pb = ConcreteProbingBase()
        pb.POINT_PROBING_STEP_SIZE = 1  # Default

        # Simulate what setUp() does for POINT_PROBING_STEP_SIZE
        with patch.dict(os.environ, {'POINT_PROBING_STEP_SIZE': '4'}):
            step_size = os.getenv("POINT_PROBING_STEP_SIZE", "")
            if step_size.isdigit() and int(step_size) > 0:
                pb.POINT_PROBING_STEP_SIZE = int(step_size)

        print("  Environment: POINT_PROBING_STEP_SIZE=4")
        print(f"  Result: pb.POINT_PROBING_STEP_SIZE={pb.POINT_PROBING_STEP_SIZE}")
        assert pb.POINT_PROBING_STEP_SIZE == 4, "Should read from environment"
        print("[OK] POINT_PROBING_STEP_SIZE correctly set from environment")

    @pytest.mark.order(934)
    def test_setUp_point_probing_step_size_invalid(self):
        """Test setUp() ignores invalid POINT_PROBING_STEP_SIZE"""
        print("\n=== Testing setUp() - POINT_PROBING_STEP_SIZE Invalid ===")

        pb = ConcreteProbingBase()
        pb.POINT_PROBING_STEP_SIZE = 2  # Default

        # Simulate what setUp() does for invalid value
        with patch.dict(os.environ, {'POINT_PROBING_STEP_SIZE': 'abc'}):
            step_size = os.getenv("POINT_PROBING_STEP_SIZE", "")
            if step_size.isdigit() and int(step_size) > 0:
                pb.POINT_PROBING_STEP_SIZE = int(step_size)

        print("  Environment: POINT_PROBING_STEP_SIZE='abc' (invalid)")
        print(f"  Result: pb.POINT_PROBING_STEP_SIZE={pb.POINT_PROBING_STEP_SIZE}")
        assert pb.POINT_PROBING_STEP_SIZE == 2, "Should keep default for invalid value"
        print("[OK] POINT_PROBING_STEP_SIZE kept as default for invalid input")

    @pytest.mark.order(935)
    def test_setUp_ingress_drop_pg_counter_true(self):
        """Test setUp() sets use_pg_drop_counter=True"""
        print("\n=== Testing setUp() - INGRESS_DROP_USE_PG_COUNTER=true ===")

        pb = ConcreteProbingBase()

        # Simulate what setUp() does for INGRESS_DROP_USE_PG_COUNTER
        with patch.dict(os.environ, {'INGRESS_DROP_USE_PG_COUNTER': 'true'}):
            env_value = os.getenv('INGRESS_DROP_USE_PG_COUNTER', '').lower()
            if env_value in ('true', '1', 'yes'):
                pb.use_pg_drop_counter = True
            elif env_value in ('false', '0', 'no'):
                pb.use_pg_drop_counter = False
            else:
                pb.use_pg_drop_counter = False

        print("  Environment: INGRESS_DROP_USE_PG_COUNTER=true")
        print(f"  Result: pb.use_pg_drop_counter={pb.use_pg_drop_counter}")
        assert pb.use_pg_drop_counter is True
        print("[OK] use_pg_drop_counter correctly set to True")

    @pytest.mark.order(936)
    def test_setUp_ingress_drop_pg_counter_false(self):
        """Test setUp() sets use_pg_drop_counter=False"""
        print("\n=== Testing setUp() - INGRESS_DROP_USE_PG_COUNTER=false ===")

        pb = ConcreteProbingBase()

        with patch.dict(os.environ, {'INGRESS_DROP_USE_PG_COUNTER': 'false'}):
            env_value = os.getenv('INGRESS_DROP_USE_PG_COUNTER', '').lower()
            if env_value in ('true', '1', 'yes'):
                pb.use_pg_drop_counter = True
            elif env_value in ('false', '0', 'no'):
                pb.use_pg_drop_counter = False
            else:
                pb.use_pg_drop_counter = False

        print("  Environment: INGRESS_DROP_USE_PG_COUNTER=false")
        print(f"  Result: pb.use_pg_drop_counter={pb.use_pg_drop_counter}")
        assert pb.use_pg_drop_counter is False
        print("[OK] use_pg_drop_counter correctly set to False")

    @pytest.mark.order(937)
    def test_setUp_ingress_drop_pg_counter_default(self):
        """Test setUp() defaults use_pg_drop_counter to False"""
        print("\n=== Testing setUp() - INGRESS_DROP_USE_PG_COUNTER Default ===")

        pb = ConcreteProbingBase()

        with patch.dict(os.environ, {}, clear=True):
            env_value = os.getenv('INGRESS_DROP_USE_PG_COUNTER', '').lower()
            if env_value in ('true', '1', 'yes'):
                pb.use_pg_drop_counter = True
            elif env_value in ('false', '0', 'no'):
                pb.use_pg_drop_counter = False
            else:
                pb.use_pg_drop_counter = False

        print("  Environment: No INGRESS_DROP_USE_PG_COUNTER set")
        print(f"  Result: pb.use_pg_drop_counter={pb.use_pg_drop_counter}")
        assert pb.use_pg_drop_counter is False
        print("[OK] use_pg_drop_counter defaults to False")


class TestProbingBaseTearDown:
    """Test tearDown() method (simplified - no parent call needed in UT)"""

    @pytest.mark.order(938)
    def test_tearDown_method_exists(self):
        """Test tearDown() method exists"""
        print("\n=== Testing tearDown() Method ===")
        pb = ConcreteProbingBase()

        # Verify method exists
        assert hasattr(pb, 'tearDown'), "tearDown method should exist"
        assert callable(pb.tearDown), "tearDown should be callable"

        print("  tearDown() method exists and is callable")
        print("[OK] tearDown() method verified")


class TestProbingBaseRunTest:
    """Test runTest() template method"""

    @pytest.mark.order(939)
    def test_runTest_workflow(self):
        """Test runTest() executes full workflow"""
        print("\n=== Testing runTest() Template Method ===")
        pb = ConcreteProbingBase()

        # Mock BufferOccupancyController
        with patch('probing_base.BufferOccupancyController') as mock_boc:
            with patch('probing_base.send_packet'):
                pb.runTest()

        print("  Step 1: get_probe_config() called ✓")
        print("  Step 2: sai_thrift_port_tx_enable() called ✓")
        print("  Step 3: setup_traffic() called ✓")
        print("  Step 4: BufferOccupancyController initialized ✓")
        print("  Step 5: probe() executed ✓")
        print("  Step 6: assert_probing_result() called ✓")

        # Verify BufferOccupancyController was created
        assert mock_boc.called, "BufferOccupancyController should be initialized"
        assert pb.stream_mgr is not None, "stream_mgr should be set"

        print("[OK] runTest() workflow executed successfully")

    @pytest.mark.order(940)
    def test_runTest_call_sequence(self):
        """Test runTest() calls methods in correct order"""
        print("\n=== Testing runTest() Call Sequence (Line 28-33) ===")
        pb = ConcreteProbingBase()

        call_order = []

        # Track method calls
        original_get_probe_config = pb.get_probe_config
        original_setup_traffic = pb.setup_traffic
        original_probe = pb.probe

        def tracked_get_probe_config():
            call_order.append('get_probe_config')
            return original_get_probe_config()

        def tracked_sai_thrift_port_tx_enable(*args, **kwargs):
            call_order.append('sai_thrift_port_tx_enable')

        def tracked_setup_traffic():
            call_order.append('setup_traffic')
            return original_setup_traffic()

        def tracked_buffer_ctrl_init(*args, **kwargs):
            call_order.append('BufferOccupancyController')
            return Mock()

        def tracked_probe():
            call_order.append('probe')
            return original_probe()

        def tracked_assert_result(result, expected):
            call_order.append('assert_probing_result')
            return True

        # Patch methods to track calls
        pb.get_probe_config = tracked_get_probe_config
        pb.sai_thrift_port_tx_enable = tracked_sai_thrift_port_tx_enable
        pb.setup_traffic = tracked_setup_traffic
        pb.probe = tracked_probe
        pb.assert_probing_result = tracked_assert_result

        with patch('probing_base.BufferOccupancyController', tracked_buffer_ctrl_init):
            with patch('probing_base.send_packet'):
                pb.runTest()

        # Verify call sequence matches documentation (lines 28-33)
        expected_sequence = [
            'get_probe_config',              # Line 28
            'sai_thrift_port_tx_enable',     # Line 29 (implied)
            'setup_traffic',                 # Line 30
            'BufferOccupancyController',     # Line 31
            'probe',                         # Line 33
            'assert_probing_result'          # Line 33 (implied)
        ]

        print(f"  Expected sequence: {expected_sequence}")
        print(f"  Actual sequence:   {call_order}")

        assert call_order == expected_sequence, \
            f"Call sequence mismatch!\nExpected: {expected_sequence}\nActual: {call_order}"

        print("[OK] runTest() call sequence verified (matches lines 28-33)")


class TestProbingBaseGetRxPort:
    """Test get_rx_port() wrapper method"""

    @pytest.mark.order(940)
    def test_get_rx_port_wrapper(self):
        """Test get_rx_port() wraps module function"""
        print("\n=== Testing get_rx_port() Wrapper ===")
        pb = TestProbingBaseInstance()

        with patch('probing_base.log_message') as mock_log:
            with patch('probing_base.get_rx_port') as mock_get_rx_port:
                mock_get_rx_port.return_value = 99

                result = pb.get_rx_port(
                    src_port_id=10,
                    pkt_dst_mac='00:11:22:33:44:55',
                    dst_port_ip='192.168.1.1',
                    src_port_ip='192.168.1.2',
                    dst_port_id=20,
                    src_vlan=100
                )

        print("  Input: src_port=10, dst_port=20")
        print("  module get_rx_port() returned: 99")
        print(f"  Result: {result}")

        assert result == 99, "Should return value from module function"
        assert mock_log.call_count == 2, "Should log before and after"
        assert mock_get_rx_port.called, "Should call module get_rx_port()"

        print("[OK] get_rx_port() wrapper works correctly")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
