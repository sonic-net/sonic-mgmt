"""
Unified Probing Observer - Universal Observer for All Probe Types

This module provides a single unified observer implementation that works for all probing scenarios:
- PFC Xoff threshold probing
- Ingress Drop threshold probing
- Future probe types (extensible design)

Design Pattern:
- Single observer class driven entirely by ObserverConfig dataclass
- No hardcoded probe-type-specific logic
- Configuration determines all terminology and behavior
- Unified markdown table generation

Benefits over separate observer classes:
- Eliminates code duplication (PfcxoffProbingObserver vs IngressDropProbingObserver)
- Single source of truth for observer logic
- Easier to maintain and test
- Extensible to new probe types without code changes

Usage:
    from probe.observer_config import ObserverConfig
    from probe.probing_observer import ProbingObserver

    observer = ProbingObserver(
        name="upper_bound",
        phase_number=1,
        observer_config=ObserverConfig(
            probe_target="pfc_xoff",
            algorithm_name="Upper Bound Discovery",
            strategy="exponential growth",
            ...
        )
    )
"""

import time
from typing import Any, List, Optional, TYPE_CHECKING

from iteration_outcome import IterationOutcome

if TYPE_CHECKING:
    from observer_config import ObserverConfig


class ProbingObserver:
    """
    Universal Probing Observer for All Probe Types

    Configuration-driven observer that adapts to any probing scenario through
    ObserverConfig injection. Supports PFC Xoff, Ingress Drop, and future probe types.
    """

    @staticmethod
    def console(message: str):
        """
        Console log: Output to console + trace file

        This is a static method that can be called both:
        - Via class name: ProbingObserver.console("...")
        - Via instance: self.observer.console("...")

        Args:
            message: Log message to output
        """
        # Import here to avoid circular dependency
        try:
            from sai_qos_tests import log_message
            log_message(message, to_stderr=True)
        except (ImportError, ModuleNotFoundError):
            # Fallback for UT environment: output to stderr
            import sys
            sys.stderr.write(message + '\n')
            sys.stderr.flush()

    @staticmethod
    def trace(message: str):
        """
        Trace log: Output to trace file only

        This is a static method that can be called both:
        - Via class name: ProbingObserver.trace("...")
        - Via instance: self.observer.trace("...")

        Args:
            message: Log message to output
        """
        # Import here to avoid circular dependency
        try:
            from sai_qos_tests import log_message
            log_message(message, to_stderr=False)
        except (ImportError, ModuleNotFoundError):
            # Fallback for UT environment: output to logging
            import logging
            logging.info(message)

    def __init__(
        self,
        name: str,
        iteration_prefix,  # Union[int, str] - flexible prefix for iteration column
        verbose: bool = True,
        observer_config: Optional["ObserverConfig"] = None,
    ):
        """
        Initialize universal observer with observer-specific configuration

        Args:
            name: Phase identifier ("upper_bound", "lower_bound", "threshold_range", "threshold_point")
            iteration_prefix: Prefix for iteration display. Can be int (1, 2, 3) or str ("1.1", "2.3.4").
                            Observer appends ".{iteration}" to this prefix.
                            Examples: 1 -> "1.1", "1.2"; "1.1" -> "1.1.1", "1.1.2"; "2.3.4" -> "2.3.4.1", "2.3.4.2"
            verbose: Enable verbose logging
            observer_config: Observer configuration (ObserverConfig dataclass, required)
        """
        self.name = name
        self.iteration_prefix = str(iteration_prefix)  # Convert to string for flexible formatting
        self.verbose = verbose

        # Observer configuration (required)
        if observer_config is None:
            raise ValueError("observer_config is required and must be provided by the caller")

        # Cache original observer_config directly (no transformation)
        # This keeps data flow clean: external input -> internal cache -> usage
        self.observer_config = observer_config

        # Extract probe_target for quick access (used frequently)
        self.probe_target = observer_config.probe_target

        # State tracking
        self.errors: List[str] = []

        # Iteration timing (using Python time module)
        self.iteration_start_time: Optional[float] = None
        self.iteration_times: List[float] = []

        # Track current iteration window and step for markdown table
        self.current_window_lower: Optional[int] = None
        self.current_window_upper: Optional[int] = None
        self.current_step_description: str = "NA"

    def _get_config_field(self, field_name: str, default: Any = None) -> Any:
        """
        Accessor for observer config fields with default value support

        Args:
            field_name: Field name in ObserverConfig (e.g., 'algorithm_name', 'strategy')
            default: Default value if field not found

        Returns:
            Field value or default
        """
        return getattr(self.observer_config, field_name, default)

    def on_iteration_start(self, iteration: int, value: int,
                           window_lower: Optional[int] = None,
                           window_upper: Optional[int] = None,
                           step_description: str = "NA") -> None:
        """
        Called when an iteration starts with search window information

        Args:
            iteration: Current iteration number (1-based)
            value: Current test value (packet count)
            window_lower: Optional lower bound of current search window
            window_upper: Optional upper bound of current search window
            step_description: Step description (e.g., "init", "x2", "/2", "+1", "L->M", "M<-H")
        """
        self.iteration_start_time = time.time()

        # Store current window and step for markdown table generation
        self.current_window_lower = window_lower
        self.current_window_upper = window_upper
        self.current_step_description = step_description

        if self.verbose:
            context_info = self._build_context_info(window_lower, window_upper)
            strategy = self._get_config_field("strategy", "unknown strategy")
            self.trace(f"{self.probe_target} iteration {iteration}: Testing {value} packets ({strategy}){context_info}")

    def _build_context_info(self, window_lower: Optional[int], window_upper: Optional[int]) -> str:
        """Build context information string from config template"""
        context_template = self._get_config_field("context_template")
        if not context_template:
            return ""

        # Format template with available variables
        try:
            return context_template.format(
                probe_target=self.probe_target,
                window_lower=window_lower,
                window_upper=window_upper,
            )
        except (KeyError, ValueError):
            # Return empty string if template formatting fails
            return ""

    def on_iteration_complete(self, iteration: int, value: int,
                              outcome: IterationOutcome) -> tuple:
        """
        Called when a detection iteration completes

        Args:
            iteration: Current iteration number (1-based)
            value: Test value used in this iteration
            outcome: The outcome of this iteration (REACHED, UNREACHED, FAILED, or SKIPPED)

        Returns:
            tuple: (iteration_time, phase_cumulative_time)
                - iteration_time: Time for this iteration in seconds
                - phase_cumulative_time: Cumulative time for entire phase so far
        """
        execution_time = None
        if self.iteration_start_time is not None:
            execution_time = time.time() - self.iteration_start_time
            self.iteration_times.append(execution_time)

        # Calculate cumulative total time
        total_time_so_far = sum(self.iteration_times)

        # Output table header after first iteration (when we know all executor metrics)
        if iteration == 1:
            self._print_markdown_table_header()

        # Immediately print markdown table row (streaming output)
        self._print_markdown_table_row(
            iteration, value, outcome, execution_time,
            self.current_window_lower, self.current_window_upper, total_time_so_far
        )

        if self.verbose:
            time_str = f" ({execution_time:.3f}s)" if execution_time else ""
            self.trace(f"  {self.probe_target} result: {outcome.value}{time_str}")

        return (execution_time, total_time_so_far)

    def on_error(self, error_message: str) -> None:
        """
        Called when an error occurs during probing

        Args:
            error_message: Description of the error
        """
        self.errors.append(error_message)

        if self.verbose:
            self.trace(f"ERROR: {error_message}")

    def _print_markdown_table_header(self) -> None:
        """
        Print markdown table header and separator for streaming output

        Uses observer config to determine algorithm title and executor metrics columns.
        """
        # Use algorithm name as header title
        algorithm_name = self._get_config_field("algorithm_name", "Unknown Algorithm")

        self.console(f"\n{algorithm_name}\n")

        # Get check column title from observer config
        check_column_title = self._get_config_field("check_column_title", "Check")

        # Build header with fixed widths
        header_parts = [
            "Iter".ljust(8),
            "Lower".ljust(9),
            "Candidate".ljust(9),
            "Upper".ljust(9),
            "Step".ljust(5),
            check_column_title.ljust(12),
            "Time(s)".ljust(8),
            "Total(s)".ljust(9)
        ]

        # Build separator
        separator_parts = ["-" * 10, "-" * 11, "-" * 11, "-" * 11, "-" * 7, "-" * 14, "-" * 10, "-" * 11]

        # Print header
        header = "| " + " | ".join(header_parts) + " |"
        separator = "|" + "|".join(separator_parts) + "|"

        self.console(header)
        self.console(separator)

    def _print_markdown_table_row(self, iteration: int, value: int,
                                  outcome: IterationOutcome,
                                  execution_time: float,
                                  window_lower: Optional[int],
                                  window_upper: Optional[int],
                                  total_time: float) -> None:
        """
        Print a single markdown table row for streaming output

        Uses table_column_mapping from observer config to determine column display.
        """
        # Format iteration: append iteration to iteration_prefix
        # Examples: "1" + iter -> "1.1"; "1.1" + iter -> "1.1.1"; "2.3.4" + iter -> "2.3.4.1"
        iter_str = f"{self.iteration_prefix}.{iteration}"

        # Use outcome value directly as check status column
        threshold_reached = outcome.value

        # Get column mapping from observer config (required)
        mapping = self._get_config_field("table_column_mapping")
        if not mapping:
            raise ValueError(f"Phase '{self.name}' missing required 'table_column_mapping' in observer_config")

        # Build local context for mapping evaluation
        range_size = (window_upper - window_lower) if (window_upper is not None and window_lower is not None) else None
        local_vars = {
            "value": value,
            "window_lower": window_lower,
            "window_upper": window_upper,
            "range_size": range_size,
        }

        # Apply mapping to resolve column values
        def resolve_value(mapping_value):
            """Resolve a mapping value to actual data"""
            if mapping_value is None:
                return None
            elif isinstance(mapping_value, int):
                return mapping_value  # Constant value
            elif isinstance(mapping_value, str):
                return local_vars.get(mapping_value)  # Variable lookup
            else:
                return mapping_value

        lower_bound = resolve_value(mapping.get("lower_bound"))
        upper_bound = resolve_value(mapping.get("upper_bound"))
        candidate_threshold = resolve_value(mapping.get("candidate_threshold"))

        # Use step_description passed from algorithm
        step_description = getattr(self, 'current_step_description', 'NA')

        # Format fields
        lower_str = str(lower_bound) if lower_bound is not None else "NA"
        upper_str = str(upper_bound) if upper_bound is not None else "NA"
        candidate_str = str(candidate_threshold) if candidate_threshold is not None else "NA"
        step_str = str(step_description) if step_description else "NA"
        time_str = f"{execution_time:.2f}" if execution_time is not None else "NA"
        total_str = f"{total_time:.2f}"

        # Build row with fixed column widths
        parts = [
            iter_str.ljust(8),
            lower_str.ljust(9),
            candidate_str.ljust(9),
            upper_str.ljust(9),
            step_str.ljust(5),
            threshold_reached.ljust(12),
            time_str.ljust(8),
            total_str.ljust(9)
        ]

        line = "| " + " | ".join(parts) + " |"
        self.console(line)

    @staticmethod
    def report_probing_result(probe_target: str, result, unit: str = "pkt"):
        """
        Report final probing result in unified format.

        Args:
            probe_target: Probe target name (e.g., "PFC XOFF", "Ingress Drop")
            result: ThresholdResult object
            unit: Unit string (default: "pkt", or "cells" for Headroom Pool)
        """
        result_str = "failed"
        if result.success:
            result_str = (f'{"point" if result.is_point else "range"} '
                          f'[{result.lower_bound}, {result.upper_bound}] {unit}')
        ProbingObserver.console(f"{probe_target} probing result: {result_str}")

    @staticmethod
    def report_validation_result(probe_target: str, result, expected_value: int,
                                 precision_ratio: Optional[float] = None,
                                 precision_range: Optional[int] = None,
                                 unit: str = "pkt"):
        """
        Report validation result in unified format.

        Args:
            probe_target: Probe target name (e.g., "PFC XOFF", "Ingress Drop")
            result: ThresholdResult object
            expected_value: Expected threshold value
            precision_ratio: Precision ratio (e.g., 0.05 for 5%), used for range probing
            precision_range: Precision range (e.g., 66 pkt), used for point probing
            unit: Unit string (default: "pkt", or "cells" for Headroom Pool)
        """
        if result.is_point:
            # Point probing validation
            precision_range_str = f"{precision_range} {unit}" if precision_range else "N/A"

            ProbingObserver.console(
                f"[PASS] {probe_target}, point check passed:\n"
                f"  Expected       : {expected_value} {unit}\n"
                f"  Precision range: {precision_range_str}\n"
                f"  Lower bound    : {result.lower_bound} {unit}\n"
                f"  Candidate      : {result.candidate} {unit}\n"
                f"  Upper bound    : {result.upper_bound} {unit}\n"
                f"  Delta          : |Candidate - Expected| = "
                f"{abs(result.candidate - expected_value)} {unit} < "
                f"{precision_range_str} (precision range)"
            )
        else:
            # Range probing validation
            expected_range = round(expected_value * precision_ratio if precision_ratio else 0)
            precision_pct = f"{precision_ratio * 100}%" if precision_ratio else "N/A"

            ProbingObserver.console(
                f"[PASS] {probe_target}, range check passed:\n"
                f"  Expected       : {expected_value} {unit}\n"
                f"  Precision ratio: {precision_pct}\n"
                f"  Lower bound    : {result.lower_bound} {unit}\n"
                f"  Candidate      : {result.candidate} {unit}\n"
                f"  Upper bound    : {result.upper_bound} {unit}\n"
                f"  Range size     : (Upper bound - Lower bound) = "
                f"{result.upper_bound - result.lower_bound} {unit} <= "
                f"{expected_range} {unit} (Expected * Precision ratio)"
            )
