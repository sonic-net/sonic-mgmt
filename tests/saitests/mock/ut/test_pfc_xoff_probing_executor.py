"""
Unit tests for PfcXoffProbingExecutor (Physical Executor)

Tests initialization, parameter handling, and logic flow of the physical
executor using mocked PTF dependencies.

Test Categories:
- Initialization and parameter validation
- Prepare method with mocked buffer_ctrl
- Check method logic with mocked PTF dependencies
- Multi-attempt verification with consistency checking
- Error handling and edge cases
"""

import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, r'c:\ws\repo\sonic-mgmt-int\sonic-mgmt-int\tests\saitests\probe')

from observer_config import ObserverConfig  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


class TestPfcXoffProbingExecutor:
    """Test suite for PfcXoffProbingExecutor (Physical)"""

    def setup_method(self):
        """Set up test fixtures"""
        config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Xoff",
            table_column_mapping={}
        )
        self.observer = ProbingObserver("test", 1, observer_config=config)

        # Create mock ptftest
        self.mock_ptftest = MagicMock()
        self.mock_ptftest.buffer_ctrl = MagicMock()
        self.mock_ptftest.src_client = MagicMock()
        self.mock_ptftest.asic_type = "broadcom"
        self.mock_ptftest.cnt_pg_idx = 5  # PFC counter index for PG 3

    @pytest.mark.order(8700)
    def test_init_with_default_parameters(self):
        """Test initialization with default parameters"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        assert executor.ptftest is self.mock_ptftest
        assert executor.observer is self.observer
        assert executor.verbose is False
        assert executor.name == ""

    @pytest.mark.order(8701)
    def test_init_with_custom_name(self):
        """Test initialization with custom executor name"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            name="threshold_point",
            verbose=True
        )

        assert executor.name == "threshold_point"
        assert executor.verbose is True

    @pytest.mark.order(8702)
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_prepare_calls_buffer_ctrl(self, mock_sleep):
        """Test prepare() calls buffer_ctrl correctly"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        executor.prepare(src_port=24, dst_port=28)

        # Verify buffer_ctrl was called
        self.mock_ptftest.buffer_ctrl.drain_buffer.assert_called_once_with([28])
        self.mock_ptftest.buffer_ctrl.hold_buffer.assert_called_once_with([28])
        # Verify sleep was called (PORT_TX_CTRL_DELAY)
        assert mock_sleep.call_count == 2

    @pytest.mark.order(8703)
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_prepare_with_verbose_logging(self, mock_sleep):
        """Test prepare() with verbose logging enabled"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            verbose=True
        )

        executor.prepare(24, 28)
        # Should not raise exceptions
        assert True

    @pytest.mark.order(8704)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_below_threshold(self, mock_sleep, mock_read_counters):
        """Test check() when value is below PFC threshold"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        # Mock counter: cnt_pg_idx=5, base[5]=0, curr[5]=0 (no PFC)
        base_counters = [0] * 20
        curr_counters = [0] * 20

        mock_read_counters.side_effect = [
            (base_counters, [0] * 10),
            (curr_counters, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 500, attempts=1)

        assert success is True
        assert detected is False
        # Verify traffic was sent
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called_once_with(24, 28, 500)

    @pytest.mark.order(8705)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_above_threshold(self, mock_sleep, mock_read_counters):
        """Test check() when value triggers PFC Xoff"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        # Mock PFC trigger: cnt_pg_idx=5, base[5]=0, curr[5]=3
        base_counters = [0] * 20
        curr_counters = [0] * 20
        curr_counters[5] = 3  # PFC triggered

        mock_read_counters.side_effect = [
            (base_counters, [0] * 10),
            (curr_counters, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 2000, attempts=1)

        assert success is True
        assert detected is True

    @pytest.mark.order(8706)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_single_attempt(self, mock_sleep, mock_read_counters):
        """Test check() with attempts=1 (single verification)"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        base = [0] * 20
        curr = [0] * 20
        curr[5] = 1

        mock_read_counters.side_effect = [(base, [0] * 10), (curr, [0] * 10)]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 1500, attempts=1)

        assert success is True
        assert detected is True
        # Single attempt: direct result

    @pytest.mark.order(8707)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_multiple_attempts_all_true(self, mock_sleep, mock_read_counters):
        """Test check() with consistent detection across 3 attempts"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        # All attempts detect PFC
        base = [0] * 20
        triggered = [0] * 20
        triggered[5] = 1

        mock_read_counters.side_effect = [
            (base, [0] * 10), (triggered, [0] * 10),  # Attempt 1
            (base, [0] * 10), (triggered, [0] * 10),  # Attempt 2
            (base, [0] * 10), (triggered, [0] * 10),  # Attempt 3
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 2000, attempts=3)

        assert success is True
        assert detected is True

    @pytest.mark.order(8708)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_multiple_attempts_all_false(self, mock_sleep, mock_read_counters):
        """Test check() with consistent no-detection across attempts"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        # All attempts: no PFC
        base = [0] * 20
        no_pfc = [0] * 20

        mock_read_counters.side_effect = [
            (base, [0] * 10), (no_pfc, [0] * 10),  # Attempt 1
            (base, [0] * 10), (no_pfc, [0] * 10),  # Attempt 2
            (base, [0] * 10), (no_pfc, [0] * 10),  # Attempt 3
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 500, attempts=3)

        assert success is True
        assert detected is False

    @pytest.mark.order(8709)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_inconsistent_attempts(self, mock_sleep, mock_read_counters):
        """Test check() with inconsistent results (noise detection)"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        # Attempt 1: PFC, Attempt 2: no PFC
        base = [0] * 20
        with_pfc = [0] * 20
        with_pfc[5] = 1
        no_pfc = [0] * 20

        mock_read_counters.side_effect = [
            (base, [0] * 10), (with_pfc, [0] * 10),  # Attempt 1: detected
            (base, [0] * 10), (no_pfc, [0] * 10),     # Attempt 2: not detected
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 1000, attempts=2)

        assert success is False  # Inconsistent results
        assert detected is False

    @pytest.mark.order(8710)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_drain_buffer_true(self, mock_sleep, mock_read_counters):
        """Test check() with drain_buffer=True (default behavior)"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        executor.check(24, 28, 1000, drain_buffer=True)

        # Verify buffer operations were called
        assert self.mock_ptftest.buffer_ctrl.drain_buffer.called
        assert self.mock_ptftest.buffer_ctrl.hold_buffer.called

    @pytest.mark.order(8711)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_drain_buffer_false(self, mock_sleep, mock_read_counters):
        """Test check() with drain_buffer=False (incremental probing)"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        executor.check(24, 28, 100, drain_buffer=False)

        # drain/hold should NOT be called inside check loop
        # (only initial prepare would call them)
        # Check that send_traffic was called
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called()

    @pytest.mark.order(8712)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_zero_value(self, mock_sleep, mock_read_counters):
        """Test check() with value=0 (no traffic sent)"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 0)

        # send_traffic should NOT be called when value=0
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_not_called()
        assert detected is False

    @pytest.mark.order(8713)
    def test_check_requires_observer(self):
        """Test check() raises error without observer (Step3.3.6)"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=None
        )

        with pytest.raises(AssertionError, match="Observer is required"):
            executor.check(24, 28, 1000)

    @pytest.mark.order(8714)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_traffic_keys(self, mock_sleep, mock_read_counters):
        """Test check() passes traffic_keys to send_traffic"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        executor.check(24, 28, 1000, pg=3, queue=5, vlan=100)

        # Verify traffic_keys were passed
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called_with(
            24, 28, 1000, pg=3, queue=5, vlan=100
        )

    @pytest.mark.order(8715)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_verbose_logging(self, mock_sleep, mock_read_counters):
        """Test check() with verbose=True logs detailed information"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        base = [0] * 20
        triggered = [0] * 20
        triggered[5] = 2

        mock_read_counters.side_effect = [
            (base, [0] * 10),
            (triggered, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            verbose=True
        )

        success, detected = executor.check(24, 28, 1500)

        # Should not raise exceptions with verbose logging
        assert success is True
        assert detected is True

    @pytest.mark.order(8716)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_iteration_parameter(self, mock_sleep, mock_read_counters):
        """Test check() accepts iteration parameter for observer metrics"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        # Should accept iteration parameter
        success, detected = executor.check(24, 28, 1000, iteration=5)

        assert success is True

    @pytest.mark.order(8717)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_exception_handling(self, mock_sleep, mock_read_counters):
        """Test check() handles exceptions gracefully"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        # Simulate hardware error
        mock_read_counters.side_effect = Exception("Hardware failure")

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            verbose=True
        )

        success, detected = executor.check(24, 28, 1000)

        assert success is False
        assert detected is False

    @pytest.mark.order(8718)
    @patch('pfc_xoff_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xoff_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xoff_probing_executor.time.sleep')
    def test_check_with_very_large_value(self, mock_sleep, mock_read_counters):
        """Test check() with very large packet count"""
        from pfc_xoff_probing_executor import PfcXoffProbingExecutor

        base = [0] * 20
        triggered = [0] * 20
        triggered[5] = 100

        mock_read_counters.side_effect = [
            (base, [0] * 10),
            (triggered, [0] * 10)
        ]

        executor = PfcXoffProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 10**6)

        assert success is True
        assert detected is True
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called_with(24, 28, 10**6)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
