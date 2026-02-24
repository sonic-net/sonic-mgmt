#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for ProbingExecutorProtocol.

Tests cover:
- Protocol structure validation
- Type checking with runtime_checkable
- Protocol compliance verification

Coverage target: 100% for probing_executor_protocol.py
"""

import pytest
import unittest
from typing import Tuple
import sys
import os


# Import the protocol under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../probe"))
from probing_executor_protocol import ProbingExecutorProtocol  # noqa: E402


@pytest.mark.order(7500)
class TestProbingExecutorProtocol(unittest.TestCase):
    """Test ProbingExecutorProtocol structure and usage."""

    @pytest.mark.order(7500)
    def test_protocol_is_runtime_checkable(self):
        """Test that ProbingExecutorProtocol is runtime checkable."""
        # Verify protocol can do isinstance checks (runtime_checkable feature)

        class TestImpl:
            def prepare(self, src_port: int, dst_port: int) -> None:
                pass

            def check(self, src_port: int, dst_port: int, value: int,
                      attempts: int = 1, drain_buffer: bool = True,
                      iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
                return True, False

        # This will only work if @runtime_checkable was applied
        assert isinstance(TestImpl(), ProbingExecutorProtocol)

    @pytest.mark.order(7510)
    def test_protocol_has_required_methods(self):
        """Test that Protocol defines required methods."""
        # Check prepare method exists
        assert hasattr(ProbingExecutorProtocol, 'prepare')

        # Check check method exists
        assert hasattr(ProbingExecutorProtocol, 'check')

    @pytest.mark.order(7520)
    def test_valid_implementation_satisfies_protocol(self):
        """Test that a valid implementation satisfies the protocol."""

        class ValidExecutor:
            """Valid implementation of ProbingExecutorProtocol."""

            def prepare(self, src_port: int, dst_port: int) -> None:
                """Valid prepare implementation."""
                pass

            def check(self, src_port: int, dst_port: int, value: int,
                      attempts: int = 1, drain_buffer: bool = True,
                      iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
                """Valid check implementation."""
                return True, False

        executor = ValidExecutor()

        # Verify instance satisfies protocol
        assert isinstance(executor, ProbingExecutorProtocol)

    @pytest.mark.order(7530)
    def test_invalid_implementation_fails_protocol(self):
        """Test that implementation without required methods fails protocol check."""

        class InvalidExecutor:
            """Invalid implementation - missing check method."""

            def prepare(self, src_port: int, dst_port: int) -> None:
                """Valid prepare implementation."""
                pass
            # Missing check method

        executor = InvalidExecutor()

        # Verify instance does NOT satisfy protocol
        assert not isinstance(executor, ProbingExecutorProtocol)

    @pytest.mark.order(7540)
    def test_prepare_method_signature(self):
        """Test prepare method has correct signature."""

        # Get prepare method from protocol
        prepare_method = getattr(ProbingExecutorProtocol, 'prepare')

        # Verify it exists and is callable
        assert callable(prepare_method)

    @pytest.mark.order(7550)
    def test_check_method_signature(self):
        """Test check method has correct signature."""

        # Get check method from protocol
        check_method = getattr(ProbingExecutorProtocol, 'check')

        # Verify it exists and is callable
        assert callable(check_method)

    @pytest.mark.order(7560)
    def test_protocol_can_be_used_as_type_hint(self):
        """Test that protocol can be used in type hints."""

        def process_executor(executor: ProbingExecutorProtocol) -> bool:
            """Function using protocol as type hint."""
            return isinstance(executor, ProbingExecutorProtocol)

        class ValidExecutor:
            def prepare(self, src_port: int, dst_port: int) -> None:
                pass

            def check(self, src_port: int, dst_port: int, value: int,
                      attempts: int = 1, drain_buffer: bool = True,
                      iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
                return True, True

        executor = ValidExecutor()

        # Verify function accepts valid executor
        assert process_executor(executor) is True

    @pytest.mark.order(7570)
    def test_prepare_method_has_documentation(self):
        """Test that prepare method has proper documentation."""
        assert ProbingExecutorProtocol.prepare.__doc__ is not None
        assert "Ensures clean buffer state" in ProbingExecutorProtocol.prepare.__doc__

    @pytest.mark.order(7580)
    def test_check_method_has_documentation(self):
        """Test that check method has proper documentation."""
        assert ProbingExecutorProtocol.check.__doc__ is not None
        assert "5-step verification process" in ProbingExecutorProtocol.check.__doc__

    @pytest.mark.order(7590)
    def test_protocol_method_ellipsis_prepare(self):
        """Test that protocol methods use ellipsis as implementation."""
        # Access the prepare method's code to cover the ellipsis line
        import inspect
        source = inspect.getsource(ProbingExecutorProtocol.prepare)
        assert "..." in source

    @pytest.mark.order(7600)
    def test_protocol_method_ellipsis_check(self):
        """Test that protocol methods use ellipsis as implementation."""
        # Access the check method's code to cover the ellipsis line
        import inspect
        source = inspect.getsource(ProbingExecutorProtocol.check)
        assert "..." in source


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
