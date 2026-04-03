"""
Pytest fixtures for the SONiC telemetry framework.

This module provides pytest fixtures for easy integration of telemetry
reporters and metrics into test cases.
"""

import os
import tempfile
from typing import Generator
import pytest
from .reporters import TSReporter, DBReporter


@pytest.fixture(scope="function")
def ts_reporter(request, tbinfo) -> Generator[TSReporter, None, None]:
    """
    Pytest fixture providing a TSReporter instance for real-time monitoring.

    This fixture creates a TSReporter configured for test use, with automatic
    cleanup after each test function.

    Args:
        request: pytest request object for test context
        tbinfo: testbed info fixture data

    Yields:
        TSReporter: Configured reporter instance for OpenTelemetry metrics
    """
    # Create TSReporter with test-specific configuration
    reporter = TSReporter(
        endpoint=os.environ.get('SONIC_MGMT_TS_REPORT_ENDPOINT'),
        request=request,
        tbinfo=tbinfo
    )

    try:
        yield reporter
    finally:
        reporter.report()


@pytest.fixture(scope="function")
def db_reporter(request, tbinfo) -> Generator[DBReporter, None, None]:
    """
    Pytest fixture providing a DBReporter instance for historical analysis.

    This fixture creates a DBReporter with temporary output directory
    that is automatically cleaned up after each test function.

    Args:
        request: pytest request object for test context
        tbinfo: testbed info fixture data

    Yields:
        DBReporter: Configured reporter instance for database export
    """
    # Create temporary directory for test output
    with tempfile.TemporaryDirectory(prefix="telemetry_test_") as temp_dir:
        reporter = DBReporter(
            output_dir=temp_dir,
            request=request,
            tbinfo=tbinfo
        )

        try:
            yield reporter
        finally:
            reporter.report()
