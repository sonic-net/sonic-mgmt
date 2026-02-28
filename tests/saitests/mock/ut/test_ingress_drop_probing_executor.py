"""
Unit tests for IngressDropProbingExecutor (Physical Executor)

Tests initialization, parameter handling, and logic flow of the physical
executor using mocked PTF dependencies.

Test Categories:
- Initialization and parameter validation
- Counter strategy selection (PG vs Port)
- Prepare method with mocked buffer_ctrl
- Check method logic with mocked PTF dependencies
- Error handling and edge cases
"""

import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, r'c:\ws\repo\sonic-mgmt-int\sonic-mgmt-int\tests\saitests\probe')

from observer_config import ObserverConfig  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


class TestIngressDropProbingExecutor:
    """Test suite for IngressDropProbingExecutor (Physical)"""

    def setup_method(self):
        """Set up test fixtures - called before each test method"""
        config = ObserverConfig(
            probe_target="ingress_drop",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Dropped",
            table_column_mapping={}
        )
        self.observer = ProbingObserver("test", 1, observer_config=config)

        # Create mock ptftest
        self.mock_ptftest = MagicMock()
        self.mock_ptftest.buffer_ctrl = MagicMock()
        self.mock_ptftest.src_client = MagicMock()
        self.mock_ptftest.asic_type = "broadcom"
        self.mock_ptftest.cnt_pg_idx = 5  # PG 3 + 2

    @pytest.mark.order(8800)
    def test_init_with_default_parameters(self):
        """Test initialization with default parameters"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        assert executor.ptftest is self.mock_ptftest
        assert executor.observer is self.observer
        assert executor.verbose is False
        assert executor.name == ""
        assert executor.use_pg_drop_counter is False  # Default to Port counter

    @pytest.mark.order(8801)
    def test_init_with_pg_counter_enabled(self):
        """Test initialization with PG counter strategy"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            use_pg_drop_counter=True,
            verbose=True
        )

        assert executor.use_pg_drop_counter is True
        assert executor.verbose is True

    @pytest.mark.order(8802)
    def test_init_with_custom_name(self):
        """Test initialization with custom executor name"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            name="upper_bound"
        )

        assert executor.name == "upper_bound"

    @pytest.mark.order(8803)
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_prepare_calls_buffer_ctrl(self, mock_sleep):
        """Test prepare() calls buffer_ctrl.drain_buffer and hold_buffer"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        executor.prepare(src_port=24, dst_port=28)

        # Verify buffer_ctrl was called correctly
        self.mock_ptftest.buffer_ctrl.drain_buffer.assert_called_once_with([28])
        self.mock_ptftest.buffer_ctrl.hold_buffer.assert_called_once_with([28])
        # Verify sleep was called (PORT_TX_CTRL_DELAY)
        assert mock_sleep.call_count == 2

    @pytest.mark.order(8804)
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_prepare_verbose_logging(self, mock_sleep):
        """Test prepare() with verbose logging"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            verbose=True
        )

        executor.prepare(24, 28)
        # Should not raise any exceptions
        assert True

    @pytest.mark.order(8805)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_port_counter_below_threshold(self, mock_sleep, mock_read_counters):
        """Test check() using Port counter strategy - below threshold"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # Mock counter readings: base=0, curr=0 (no drop detected)
        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),  # Baseline
            ([0] * 20, [0] * 10)   # Current (no change)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            use_pg_drop_counter=False  # Use Port counter
        )

        success, detected = executor.check(24, 28, 500, attempts=1)

        assert success is True
        assert detected is False
        # Verify traffic was sent
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called_once_with(24, 28, 500)

    @pytest.mark.order(8806)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_port_counter_above_threshold(self, mock_sleep, mock_read_counters):
        """Test check() using Port counter - above threshold (INGRESS_DROP triggered)"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # INGRESS_DROP = 1, INGRESS_PORT_BUFFER_DROP = 12
        # Mock: base[1]=0, curr[1]=10 (drop detected)
        base_counters = [0] * 20
        curr_counters = [0] * 20
        curr_counters[1] = 10  # INGRESS_DROP counter increased

        mock_read_counters.side_effect = [
            (base_counters, [0] * 10),
            (curr_counters, [0] * 10)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            use_pg_drop_counter=False
        )

        success, detected = executor.check(24, 28, 2000, attempts=1)

        assert success is True
        assert detected is True

    @pytest.mark.order(8807)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_buffer_drop_counter(self, mock_sleep, mock_read_counters):
        """Test check() detecting INGRESS_PORT_BUFFER_DROP"""
        # Import and ensure constants are correct values, not mocks
        import ingress_drop_probing_executor
        ingress_drop_probing_executor.INGRESS_DROP = 2
        ingress_drop_probing_executor.INGRESS_PORT_BUFFER_DROP = 12

        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # Reset mock to ensure clean state
        mock_read_counters.reset_mock()

        # Test INGRESS_PORT_BUFFER_DROP (index 12) trigger
        base_counters = [0] * 20
        curr_counters = [0] * 20
        curr_counters[12] = 5  # INGRESS_PORT_BUFFER_DROP increased

        mock_read_counters.side_effect = [
            (base_counters, [0] * 10),
            (curr_counters, [0] * 10)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            use_pg_drop_counter=False
        )

        success, detected = executor.check(24, 28, 1500)

        assert success is True, f"Expected success=True, got {success}"
        assert detected is True, f"Expected detected=True, got {detected}"

    @pytest.mark.order(8808)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_pg_drop_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_pg_counter_strategy(self, mock_sleep, mock_read_pg):
        """Test check() using PG drop counter strategy"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # Mock PG drop counters: 8 PGs, PG3=5 drops
        base_pg = [0] * 8
        curr_pg = [0] * 8
        curr_pg[3] = 5  # PG 3 has drops

        mock_read_pg.side_effect = [base_pg, curr_pg]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            use_pg_drop_counter=True  # Enable PG counter
        )

        success, detected = executor.check(24, 28, 1000, pg=3)

        assert success is True
        assert detected is True
        # Verify PG counter was read
        assert mock_read_pg.call_count == 2

    @pytest.mark.order(8809)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_multiple_attempts_consistent(self, mock_sleep, mock_read_counters):
        """Test check() with multiple attempts returning consistent results"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # All attempts return same result (no drop)
        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),  # Attempt 1 base
            ([0] * 20, [0] * 10),  # Attempt 1 curr
            ([0] * 20, [0] * 10),  # Attempt 2 base
            ([0] * 20, [0] * 10),  # Attempt 2 curr
            ([0] * 20, [0] * 10),  # Attempt 3 base
            ([0] * 20, [0] * 10),  # Attempt 3 curr
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 500, attempts=3)

        assert success is True  # Consistent results
        assert detected is False  # All attempts show no drop

    @pytest.mark.order(8810)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_inconsistent_attempts(self, mock_sleep, mock_read_counters):
        """Test check() with inconsistent results across attempts"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # Inconsistent results: attempt1=no drop, attempt2=drop
        base = [0] * 20
        no_drop = [0] * 20
        with_drop = [0] * 20
        with_drop[1] = 10

        mock_read_counters.side_effect = [
            (base, [0] * 10),       # Attempt 1 base
            (no_drop, [0] * 10),    # Attempt 1 curr (no drop)
            (base, [0] * 10),       # Attempt 2 base
            (with_drop, [0] * 10),  # Attempt 2 curr (drop detected)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 1000, attempts=2)

        assert success is False  # Inconsistent = failure
        assert detected is False

    @pytest.mark.order(8811)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_drain_buffer_false(self, mock_sleep, mock_read_counters):
        """Test check() with drain_buffer=False (incremental probing)"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 100, drain_buffer=False)

        # drain_buffer/hold_buffer should NOT be called
        self.mock_ptftest.buffer_ctrl.drain_buffer.assert_not_called()
        self.mock_ptftest.buffer_ctrl.hold_buffer.assert_not_called()
        # But send_traffic should still be called
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called_once()

    @pytest.mark.order(8812)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_zero_value(self, mock_sleep, mock_read_counters):
        """Test check() with value=0 (no traffic sent)"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        success, detected = executor.check(24, 28, 0)

        # send_traffic should NOT be called when value=0
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_not_called()
        assert detected is False

    @pytest.mark.order(8813)
    def test_check_without_observer_raises_error(self):
        """Test check() requires observer (Step3.3.6)"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=None  # No observer
        )

        with pytest.raises(AssertionError, match="Observer is required"):
            executor.check(24, 28, 1000)

    @pytest.mark.order(8814)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_with_traffic_keys(self, mock_sleep, mock_read_counters):
        """Test check() passes traffic_keys correctly"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([0] * 20, [0] * 10)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer
        )

        executor.check(24, 28, 1000, pg=3, queue=5, vlan=100)

        # Verify traffic_keys were passed to send_traffic
        self.mock_ptftest.buffer_ctrl.send_traffic.assert_called_once_with(
            24, 28, 1000, pg=3, queue=5, vlan=100
        )

    @pytest.mark.order(8815)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_verbose_logging(self, mock_sleep, mock_read_counters):
        """Test check() with verbose=True logs detailed info"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        mock_read_counters.side_effect = [
            ([0] * 20, [0] * 10),
            ([5] * 20, [0] * 10)
        ]

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            verbose=True
        )

        success, detected = executor.check(24, 28, 1500)

        # Should not raise errors with verbose logging
        assert success is True
        assert detected is True

    @pytest.mark.order(8816)
    @patch('ingress_drop_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('ingress_drop_probing_executor.sai_thrift_read_port_counters')
    @patch('ingress_drop_probing_executor.time.sleep')
    def test_check_exception_handling(self, mock_sleep, mock_read_counters):
        """Test check() handles exceptions gracefully"""
        from ingress_drop_probing_executor import IngressDropProbingExecutor

        # Simulate exception in counter reading
        mock_read_counters.side_effect = Exception("Hardware error")

        executor = IngressDropProbingExecutor(
            ptftest=self.mock_ptftest,
            observer=self.observer,
            verbose=True
        )

        success, detected = executor.check(24, 28, 1000)

        assert success is False
        assert detected is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
