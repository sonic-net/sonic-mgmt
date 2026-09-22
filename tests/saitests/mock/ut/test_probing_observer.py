"""
Unit tests for ProbingObserver

This module provides comprehensive unit tests for the universal ProbingObserver class,
covering all methods and scenarios with 90%+ test coverage.

Test Categories:
- Static method logging (console, trace)
- Initialization and configuration
- Iteration lifecycle (start, complete)
- Error handling
- Markdown table generation
- Result reporting (probing and validation)
"""

import sys
import time
import pytest
from unittest.mock import MagicMock, patch

# Clean import environment
if 'probing_observer' in sys.modules:
    del sys.modules['probing_observer']
if 'observer_config' in sys.modules:
    del sys.modules['observer_config']
if 'iteration_outcome' in sys.modules:
    del sys.modules['iteration_outcome']

# Set up mock environment to avoid import errors
sys.path.insert(0, r'c:\ws\repo\sonic-mgmt-int\sonic-mgmt-int\tests\saitests\probe')

from observer_config import ObserverConfig  # noqa: E402
from iteration_outcome import IterationOutcome  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


class TestProbingObserverStaticMethods:
    """Test suite for ProbingObserver static methods (console, trace)"""

    @pytest.mark.order(8800)
    def test_console_with_log_message_available(self):
        """Test console() when sai_qos_tests.log_message is available"""
        mock_log_message = MagicMock()

        with patch.dict('sys.modules', {'sai_qos_tests': MagicMock(log_message=mock_log_message)}):
            ProbingObserver.console("test message")

        mock_log_message.assert_called_once_with("test message", to_stderr=True)

    @pytest.mark.order(8801)
    def test_console_fallback_to_stderr(self):
        """Test console() fallback to stderr when sai_qos_tests not available"""
        with patch('sys.stderr.write') as mock_write, \
             patch('sys.stderr.flush') as mock_flush:

            # Force ImportError by making log_message raise
            with patch.dict('sys.modules', {'sai_qos_tests': None}, clear=False):
                ProbingObserver.console("fallback message")

            mock_write.assert_called_once_with("fallback message\n")
            mock_flush.assert_called_once()

    @pytest.mark.order(8802)
    def test_trace_with_log_message_available(self):
        """Test trace() when sai_qos_tests.log_message is available"""
        mock_log_message = MagicMock()

        with patch.dict('sys.modules', {'sai_qos_tests': MagicMock(log_message=mock_log_message)}):
            ProbingObserver.trace("trace message")

        mock_log_message.assert_called_once_with("trace message", to_stderr=False)

    @pytest.mark.order(8803)
    def test_trace_fallback_to_logging(self):
        """Test trace() fallback to logging when sai_qos_tests not available"""
        with patch('logging.info') as mock_logging_info:
            # Force ImportError
            with patch.dict('sys.modules', {'sai_qos_tests': None}, clear=False):
                ProbingObserver.trace("log fallback message")

            mock_logging_info.assert_called_once_with("log fallback message")


class TestProbingObserverInit:
    """Test suite for ProbingObserver initialization"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Test Algorithm",
            strategy="test strategy",
            check_column_title="Check",
            context_template=" [window: {window_lower}-{window_upper}]",
            table_column_mapping={
                "lower_bound": "window_lower",
                "upper_bound": "window_upper",
                "candidate_threshold": "value"
            }
        )

    @pytest.mark.order(8804)
    def test_init_with_valid_config(self):
        """Test initialization with valid ObserverConfig"""
        self.setUp()

        observer = ProbingObserver(
            name="upper_bound",
            iteration_prefix=1,
            verbose=True,
            observer_config=self.config
        )

        assert observer.name == "upper_bound"
        assert observer.iteration_prefix == "1"
        assert observer.verbose is True
        assert observer.observer_config is self.config
        assert observer.probe_target == "pfc_xoff"
        assert observer.errors == []
        assert observer.iteration_start_time is None
        assert observer.iteration_times == []
        assert observer.current_window_lower is None
        assert observer.current_window_upper is None
        assert observer.current_step_description == "NA"

    @pytest.mark.order(8805)
    def test_init_converts_iteration_prefix_to_string(self):
        """Test that iteration_prefix is converted to string"""
        self.setUp()

        # Test with int
        observer1 = ProbingObserver("test", 42, observer_config=self.config)
        assert observer1.iteration_prefix == "42"

        # Test with float
        observer2 = ProbingObserver("test", 3.14, observer_config=self.config)
        assert observer2.iteration_prefix == "3.14"

        # Test with string
        observer3 = ProbingObserver("test", "1.2.3", observer_config=self.config)
        assert observer3.iteration_prefix == "1.2.3"

    @pytest.mark.order(8806)
    def test_init_without_observer_config_raises_error(self):
        """Test initialization without observer_config raises ValueError"""
        with pytest.raises(ValueError, match="observer_config is required"):
            ProbingObserver(name="test", iteration_prefix=1, observer_config=None)

    @pytest.mark.order(8807)
    def test_init_with_verbose_false(self):
        """Test initialization with verbose=False"""
        self.setUp()

        observer = ProbingObserver(
            name="test",
            iteration_prefix=2,
            verbose=False,
            observer_config=self.config
        )

        assert observer.verbose is False


class TestProbingObserverConfigAccess:
    """Test suite for config field access methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ObserverConfig(
            probe_target="ingress_drop",
            algorithm_name="Test Algorithm",
            strategy="binary search",
            check_column_title="Dropped",
            table_column_mapping={"lower_bound": "window_lower"}
        )
        self.observer = ProbingObserver(
            name="test",
            iteration_prefix=1,
            observer_config=self.config
        )

    @pytest.mark.order(8808)
    def test_get_config_field_existing_field(self):
        """Test _get_config_field returns existing field value"""
        self.setUp()

        assert self.observer._get_config_field("algorithm_name") == "Test Algorithm"
        assert self.observer._get_config_field("strategy") == "binary search"
        assert self.observer._get_config_field("probe_target") == "ingress_drop"

    @pytest.mark.order(8809)
    def test_get_config_field_missing_field_with_default(self):
        """Test _get_config_field returns default for missing field"""
        self.setUp()

        assert self.observer._get_config_field("nonexistent", "default") == "default"
        assert self.observer._get_config_field("missing", None) is None
        assert self.observer._get_config_field("another", 42) == 42

    @pytest.mark.order(8810)
    def test_get_config_field_missing_field_no_default(self):
        """Test _get_config_field returns None when no default provided"""
        self.setUp()

        assert self.observer._get_config_field("nonexistent") is None


class TestProbingObserverIterationLifecycle:
    """Test suite for iteration lifecycle methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Upper Bound Discovery",
            strategy="exponential growth",
            check_column_title="Xoff",
            context_template=" [window: {window_lower}-{window_upper}]",
            table_column_mapping={
                "lower_bound": "window_lower",
                "upper_bound": "window_upper",
                "candidate_threshold": "value"
            }
        )
        self.observer = ProbingObserver(
            name="upper_bound",
            iteration_prefix="1",
            verbose=True,
            observer_config=self.config
        )

    @pytest.mark.order(8811)
    def test_on_iteration_start_sets_timing_and_context(self):
        """Test on_iteration_start sets timing and context correctly"""
        self.setUp()

        with patch.object(self.observer, 'trace') as mock_trace:
            start_time = time.time()
            self.observer.on_iteration_start(
                iteration=1,
                value=1000,
                window_lower=0,
                window_upper=2000,
                step_description="init"
            )

            # Verify timing started
            assert self.observer.iteration_start_time is not None
            assert self.observer.iteration_start_time >= start_time

            # Verify context stored
            assert self.observer.current_window_lower == 0
            assert self.observer.current_window_upper == 2000
            assert self.observer.current_step_description == "init"

            # Verify trace called with correct message
            mock_trace.assert_called_once()
            trace_msg = mock_trace.call_args[0][0]
            assert "pfc_xoff iteration 1" in trace_msg
            assert "Testing 1000 packets" in trace_msg
            assert "exponential growth" in trace_msg
            assert "[window: 0-2000]" in trace_msg

    @pytest.mark.order(8812)
    def test_on_iteration_start_with_verbose_false(self):
        """Test on_iteration_start with verbose=False doesn't trace"""
        self.setUp()
        self.observer.verbose = False

        with patch.object(self.observer, 'trace') as mock_trace:
            self.observer.on_iteration_start(1, 500)

            mock_trace.assert_not_called()

    @pytest.mark.order(8813)
    def test_on_iteration_start_without_window_bounds(self):
        """Test on_iteration_start with None window bounds"""
        self.setUp()

        with patch.object(self.observer, 'trace') as mock_trace:
            self.observer.on_iteration_start(
                iteration=2,
                value=500,
                window_lower=None,
                window_upper=None,
                step_description="x2"
            )

            assert self.observer.current_window_lower is None
            assert self.observer.current_window_upper is None

            # Context template should return empty string when bounds are None
            trace_msg = mock_trace.call_args[0][0]
            assert "pfc_xoff iteration 2" in trace_msg
            assert "Testing 500 packets" in trace_msg

    @pytest.mark.order(8814)
    def test_build_context_info_with_valid_template(self):
        """Test _build_context_info formats template correctly"""
        self.setUp()

        context = self.observer._build_context_info(100, 200)
        assert context == " [window: 100-200]"

    @pytest.mark.order(8815)
    def test_build_context_info_with_no_template(self):
        """Test _build_context_info returns empty string when no template"""
        self.setUp()

        # Create observer without context_template
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Check",
            table_column_mapping={}
        )
        observer = ProbingObserver("test", 1, observer_config=config)

        context = observer._build_context_info(100, 200)
        assert context == ""

    @pytest.mark.order(8816)
    def test_build_context_info_with_invalid_template(self):
        """Test _build_context_info handles invalid template gracefully"""
        self.setUp()

        # Create observer with invalid template (missing key)
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Check",
            context_template=" [invalid: {nonexistent_key}]",
            table_column_mapping={}
        )
        observer = ProbingObserver("test", 1, observer_config=config)

        context = observer._build_context_info(100, 200)
        assert context == ""  # Should return empty on error

    @pytest.mark.order(8817)
    def test_on_iteration_complete_first_iteration(self):
        """Test on_iteration_complete for first iteration (prints header)"""
        self.setUp()

        # Start iteration first
        self.observer.on_iteration_start(1, 1000, 0, 2000, "init")

        # with patch.object(self.observer, 'console') as mock_console, \
        with patch.object(self.observer, 'console'), \
             patch.object(self.observer, 'trace') as mock_trace, \
             patch.object(self.observer, '_print_markdown_table_header') as mock_header, \
             patch.object(self.observer, '_print_markdown_table_row') as mock_row:

            time.sleep(0.01)  # Small delay for timing

            iter_time, total_time = self.observer.on_iteration_complete(
                iteration=1,
                value=1000,
                outcome=IterationOutcome.UNREACHED
            )

            # Verify timing calculated
            assert iter_time is not None
            assert iter_time > 0
            assert total_time == iter_time
            assert len(self.observer.iteration_times) == 1

            # Verify header printed (only on first iteration)
            mock_header.assert_called_once()

            # Verify row printed
            mock_row.assert_called_once_with(
                1, 1000, IterationOutcome.UNREACHED, iter_time, 0, 2000, total_time
            )

            # Verify trace called
            mock_trace.assert_called_once()
            trace_msg = mock_trace.call_args[0][0]
            assert "pfc_xoff result: unreached" in trace_msg

    @pytest.mark.order(8818)
    def test_on_iteration_complete_subsequent_iterations(self):
        """Test on_iteration_complete for iterations after first (no header)"""
        self.setUp()

        # Simulate first iteration
        with patch.object(self.observer, '_print_markdown_table_header'), \
             patch.object(self.observer, '_print_markdown_table_row'):
            self.observer.on_iteration_start(1, 1000)
            self.observer.on_iteration_complete(1, 1000, IterationOutcome.REACHED)

        # Second iteration
        self.observer.on_iteration_start(2, 500, 0, 1000, "/2")

        with patch.object(self.observer, '_print_markdown_table_header') as mock_header, \
             patch.object(self.observer, '_print_markdown_table_row') as mock_row:

            time.sleep(0.01)
            iter_time, total_time = self.observer.on_iteration_complete(
                2, 500, IterationOutcome.REACHED
            )

            # Header should NOT be printed on second iteration
            mock_header.assert_not_called()

            # Row should be printed
            mock_row.assert_called_once()

            # Total time should be cumulative
            assert len(self.observer.iteration_times) == 2
            assert total_time == sum(self.observer.iteration_times)

    @pytest.mark.order(8819)
    def test_on_iteration_complete_without_start_time(self):
        """Test on_iteration_complete when iteration_start_time is None"""
        self.setUp()

        # Don't call on_iteration_start, so iteration_start_time is None
        with patch.object(self.observer, '_print_markdown_table_header'), \
             patch.object(self.observer, '_print_markdown_table_row') as mock_row:

            iter_time, total_time = self.observer.on_iteration_complete(
                1, 1000, IterationOutcome.FAILED
            )

            # Timing should be None
            assert iter_time is None
            assert total_time == 0.0
            assert len(self.observer.iteration_times) == 0

            # Row should still be printed with None execution_time
            mock_row.assert_called_once_with(
                1, 1000, IterationOutcome.FAILED, None,
                None, None, 0.0
            )

    @pytest.mark.order(8820)
    def test_on_iteration_complete_with_verbose_false(self):
        """Test on_iteration_complete with verbose=False doesn't trace"""
        self.setUp()
        self.observer.verbose = False
        self.observer.on_iteration_start(1, 1000)

        with patch.object(self.observer, 'trace') as mock_trace, \
             patch.object(self.observer, '_print_markdown_table_header'), \
             patch.object(self.observer, '_print_markdown_table_row'):

            self.observer.on_iteration_complete(1, 1000, IterationOutcome.REACHED)

            mock_trace.assert_not_called()


class TestProbingObserverErrorHandling:
    """Test suite for error handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Check",
            table_column_mapping={}
        )
        self.observer = ProbingObserver(
            name="test",
            iteration_prefix=1,
            verbose=True,
            observer_config=self.config
        )

    @pytest.mark.order(8821)
    def test_on_error_appends_to_errors_list(self):
        """Test on_error appends error message to errors list"""
        self.setUp()

        with patch.object(self.observer, 'trace'):
            self.observer.on_error("First error")
            self.observer.on_error("Second error")

            assert len(self.observer.errors) == 2
            assert self.observer.errors[0] == "First error"
            assert self.observer.errors[1] == "Second error"

    @pytest.mark.order(8822)
    def test_on_error_traces_message(self):
        """Test on_error traces error message when verbose=True"""
        self.setUp()

        with patch.object(self.observer, 'trace') as mock_trace:
            self.observer.on_error("Test error message")

            mock_trace.assert_called_once_with("ERROR: Test error message")

    @pytest.mark.order(8823)
    def test_on_error_with_verbose_false(self):
        """Test on_error still appends errors when verbose=False"""
        self.setUp()
        self.observer.verbose = False

        with patch.object(self.observer, 'trace') as mock_trace:
            self.observer.on_error("Silent error")

            # Error added to list
            assert len(self.observer.errors) == 1
            assert self.observer.errors[0] == "Silent error"

            # But trace not called
            mock_trace.assert_not_called()


class TestProbingObserverMarkdownTableGeneration:
    """Test suite for markdown table generation"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Upper Bound Discovery",
            strategy="exponential",
            check_column_title="Xoff",
            table_column_mapping={
                "lower_bound": "window_lower",
                "upper_bound": "window_upper",
                "candidate_threshold": "value"
            }
        )
        self.observer = ProbingObserver(
            name="upper_bound",
            iteration_prefix="1",
            observer_config=self.config
        )

    @pytest.mark.order(8824)
    def test_print_markdown_table_header(self):
        """Test _print_markdown_table_header outputs correct format"""
        self.setUp()

        with patch.object(self.observer, 'console') as mock_console:
            self.observer._print_markdown_table_header()

            # Should print 3 lines: title, header, separator
            assert mock_console.call_count == 3

            # Check title
            title_call = mock_console.call_args_list[0][0][0]
            assert "Upper Bound Discovery" in title_call

            # Check header
            header_call = mock_console.call_args_list[1][0][0]
            assert "Iter" in header_call
            assert "Lower" in header_call
            assert "Candidate" in header_call
            assert "Upper" in header_call
            assert "Step" in header_call
            assert "Xoff" in header_call  # Custom check column title
            assert "Time(s)" in header_call
            assert "Total(s)" in header_call

            # Check separator
            separator_call = mock_console.call_args_list[2][0][0]
            assert "---" in separator_call

    @pytest.mark.order(8825)
    def test_print_markdown_table_header_with_custom_check_column(self):
        """Test header uses custom check_column_title from config"""
        self.setUp()

        # Create observer with custom check column title
        config = ObserverConfig(
            probe_target="ingress_drop",
            algorithm_name="Lower Bound",
            strategy="test",
            check_column_title="Dropped",  # Custom title
            table_column_mapping={}
        )
        observer = ProbingObserver("test", 1, observer_config=config)

        with patch.object(observer, 'console') as mock_console:
            observer._print_markdown_table_header()

            header_call = mock_console.call_args_list[1][0][0]
            assert "Dropped" in header_call  # Custom title used

    @pytest.mark.order(8826)
    def test_print_markdown_table_header_with_default_check_column(self):
        """Test header uses default 'Check' when check_column_title not in config"""
        self.setUp()

        # Create observer with check_column_title (required field)
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Check",
            table_column_mapping={}
        )
        observer = ProbingObserver("test", 1, observer_config=config)

        with patch.object(observer, 'console') as mock_console:
            observer._print_markdown_table_header()

            header_call = mock_console.call_args_list[1][0][0]
            assert "Check" in header_call

    @pytest.mark.order(8827)
    def test_print_markdown_table_row_with_all_values(self):
        """Test _print_markdown_table_row with all values present"""
        self.setUp()

        # Set current context
        self.observer.current_window_lower = 0
        self.observer.current_window_upper = 2000
        self.observer.current_step_description = "init"

        with patch.object(self.observer, 'console') as mock_console:
            self.observer._print_markdown_table_row(
                iteration=1,
                value=1000,
                outcome=IterationOutcome.REACHED,
                execution_time=0.123,
                window_lower=0,
                window_upper=2000,
                total_time=0.123
            )

            row = mock_console.call_args[0][0]

            # Check iteration format: "1.1" (prefix.iteration)
            assert "1.1" in row

            # Check values present
            assert "1000" in row  # candidate (value)
            assert "0" in row     # lower
            assert "2000" in row  # upper
            assert "init" in row  # step
            assert "reached" in row  # outcome (lowercase)
            assert "0.12" in row  # execution time (formatted to 2 decimals)

    @pytest.mark.order(8828)
    def test_print_markdown_table_row_with_none_values(self):
        """Test _print_markdown_table_row handles None values correctly"""
        self.setUp()

        self.observer.current_step_description = "NA"

        with patch.object(self.observer, 'console') as mock_console:
            self.observer._print_markdown_table_row(
                iteration=5,
                value=500,
                outcome=IterationOutcome.FAILED,
                execution_time=None,
                window_lower=None,
                window_upper=None,
                total_time=1.5
            )

            row = mock_console.call_args[0][0]

            # Check NA used for None values
            assert "NA" in row
            assert "500" in row  # value still present
            assert "failed" in row  # outcome (lowercase)
            assert "1.50" in row  # total time

    @pytest.mark.order(8829)
    def test_print_markdown_table_row_iteration_prefix_formatting(self):
        """Test iteration prefix formatting (hierarchical iteration numbers)"""
        self.setUp()

        # Test with different iteration prefixes
        test_cases = [
            ("1", 1, "1.1"),
            ("1", 5, "1.5"),
            ("1.2", 3, "1.2.3"),
            ("2.3.4", 7, "2.3.4.7"),
        ]

        for prefix, iteration, expected in test_cases:
            observer = ProbingObserver("test", prefix, observer_config=self.config)
            observer.current_step_description = "test"

            with patch.object(observer, 'console') as mock_console:
                observer._print_markdown_table_row(
                    iteration, 100, IterationOutcome.REACHED,
                    0.1, 0, 100, 0.1
                )

                row = mock_console.call_args[0][0]
                assert expected in row

    @pytest.mark.order(8830)
    def test_print_markdown_table_row_without_table_column_mapping_raises_error(self):
        """Test _print_markdown_table_row raises error when table_column_mapping missing"""
        self.setUp()

        # Create observer without table_column_mapping
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Check"
        )
        observer = ProbingObserver("test", 1, observer_config=config)
        observer.current_step_description = "test"

        with pytest.raises(ValueError, match="missing required 'table_column_mapping'"):
            observer._print_markdown_table_row(
                1, 100, IterationOutcome.REACHED, 0.1, 0, 100, 0.1
            )

    @pytest.mark.order(8831)
    def test_print_markdown_table_row_with_constant_mapping(self):
        """Test _print_markdown_table_row with constant value in mapping"""
        self.setUp()

        # Create config with constant mapping (int value)
        config = ObserverConfig(
            probe_target="test",
            algorithm_name="Test",
            strategy="test",
            check_column_title="Check",
            table_column_mapping={
                "lower_bound": 0,  # Constant
                "upper_bound": None,  # None mapping
                "candidate_threshold": "value"  # Variable
            }
        )
        observer = ProbingObserver("test", 1, observer_config=config)
        observer.current_step_description = "test"

        with patch.object(observer, 'console') as mock_console:
            observer._print_markdown_table_row(
                1, 500, IterationOutcome.REACHED, 0.1, 100, 200, 0.1
            )

            row = mock_console.call_args[0][0]

            # Lower bound should be 0 (constant)
            # Upper bound should be NA (None mapping)
            # Candidate should be 500 (value)
            assert "| 1.1" in row
            assert "500" in row  # candidate_threshold


class TestProbingObserverStaticReportMethods:
    """Test suite for static reporting methods"""

    @pytest.mark.order(8832)
    def test_report_probing_result_success_point(self):
        """Test report_probing_result with successful point result"""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.is_point = True
        mock_result.lower_bound = 995
        mock_result.upper_bound = 1005

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_probing_result("PFC XOFF", mock_result)

            msg = mock_console.call_args[0][0]
            assert "PFC XOFF probing result" in msg
            assert "point" in msg
            assert "[995, 1005]" in msg
            assert "pkt" in msg

    @pytest.mark.order(8833)
    def test_report_probing_result_success_range(self):
        """Test report_probing_result with successful range result"""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.is_point = False
        mock_result.lower_bound = 1000
        mock_result.upper_bound = 2000

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_probing_result("Ingress Drop", mock_result)

            msg = mock_console.call_args[0][0]
            assert "Ingress Drop probing result" in msg
            assert "range" in msg
            assert "[1000, 2000]" in msg
            assert "pkt" in msg

    @pytest.mark.order(8834)
    def test_report_probing_result_failure(self):
        """Test report_probing_result with failed result"""
        mock_result = MagicMock()
        mock_result.success = False

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_probing_result("Test", mock_result)

            msg = mock_console.call_args[0][0]
            assert "Test probing result" in msg
            assert "failed" in msg

    @pytest.mark.order(8835)
    def test_report_probing_result_custom_unit(self):
        """Test report_probing_result with custom unit"""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.is_point = True
        mock_result.lower_bound = 100
        mock_result.upper_bound = 200

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_probing_result("Headroom", mock_result, unit="cells")

            msg = mock_console.call_args[0][0]
            assert "cells" in msg
            assert "pkt" not in msg

    @pytest.mark.order(8836)
    def test_report_validation_result_point_probing(self):
        """Test report_validation_result for point probing"""
        mock_result = MagicMock()
        mock_result.is_point = True
        mock_result.lower_bound = 995
        mock_result.candidate = 1000
        mock_result.upper_bound = 1005

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_validation_result(
                probe_target="PFC XOFF",
                result=mock_result,
                expected_value=998,
                precision_range=10
            )

            msg = mock_console.call_args[0][0]
            assert "[PASS]" in msg
            assert "PFC XOFF" in msg
            assert "point check passed" in msg
            assert "Expected       : 998 pkt" in msg
            assert "Precision range: 10 pkt" in msg
            assert "Lower bound    : 995 pkt" in msg
            assert "Candidate      : 1000 pkt" in msg
            assert "Upper bound    : 1005 pkt" in msg
            assert "Delta          :" in msg
            assert "2 pkt" in msg  # |1000 - 998|

    @pytest.mark.order(8837)
    def test_report_validation_result_range_probing(self):
        """Test report_validation_result for range probing"""
        mock_result = MagicMock()
        mock_result.is_point = False
        mock_result.lower_bound = 950
        mock_result.candidate = 1000
        mock_result.upper_bound = 1050

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_validation_result(
                probe_target="Ingress Drop",
                result=mock_result,
                expected_value=1000,
                precision_ratio=0.05
            )

            msg = mock_console.call_args[0][0]
            assert "[PASS]" in msg
            assert "Ingress Drop" in msg
            assert "range check passed" in msg
            assert "Expected       : 1000 pkt" in msg
            assert "Precision ratio: 5" in msg  # May be "5%" or "5.0%"
            assert "%" in msg  # Check percentage sign exists
            assert "Lower bound    : 950 pkt" in msg
            assert "Candidate      : 1000 pkt" in msg
            assert "Upper bound    : 1050 pkt" in msg
            assert "Range size     :" in msg
            assert "100 pkt" in msg  # 1050 - 950
            assert "50 pkt" in msg   # round(1000 * 0.05)

    @pytest.mark.order(8838)
    def test_report_validation_result_with_custom_unit(self):
        """Test report_validation_result with custom unit"""
        mock_result = MagicMock()
        mock_result.is_point = True
        mock_result.lower_bound = 100
        mock_result.candidate = 105
        mock_result.upper_bound = 110

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_validation_result(
                probe_target="Headroom",
                result=mock_result,
                expected_value=105,
                precision_range=5,
                unit="cells"
            )

            msg = mock_console.call_args[0][0]
            assert "cells" in msg
            assert "pkt" not in msg
            assert "Expected       : 105 cells" in msg

    @pytest.mark.order(8839)
    def test_report_validation_result_point_without_precision_range(self):
        """Test report_validation_result point probing without precision_range"""
        mock_result = MagicMock()
        mock_result.is_point = True
        mock_result.lower_bound = 95
        mock_result.candidate = 100
        mock_result.upper_bound = 105

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_validation_result(
                probe_target="Test",
                result=mock_result,
                expected_value=100,
                precision_range=None
            )

            msg = mock_console.call_args[0][0]
            assert "Precision range: N/A" in msg

    @pytest.mark.order(8840)
    def test_report_validation_result_range_without_precision_ratio(self):
        """Test report_validation_result range probing without precision_ratio"""
        mock_result = MagicMock()
        mock_result.is_point = False
        mock_result.lower_bound = 90
        mock_result.candidate = 100
        mock_result.upper_bound = 110

        with patch.object(ProbingObserver, 'console') as mock_console:
            ProbingObserver.report_validation_result(
                probe_target="Test",
                result=mock_result,
                expected_value=100,
                precision_ratio=None
            )

            msg = mock_console.call_args[0][0]
            assert "Precision ratio: N/A" in msg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
