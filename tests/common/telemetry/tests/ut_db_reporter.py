"""
Tests for DBReporter (Database Reporter) using baseline validation.

This module focuses on testing the DBReporter implementation using baseline
JSON files for validation. When SONIC_MGMT_GENERATE_BASELINE=1, it generates
new baseline files instead of testing.
"""

import tempfile
from unittest.mock import Mock

import pytest

# Import the telemetry framework
from common.telemetry import (
    GaugeMetric, HistogramMetric
)
from common.telemetry.reporters.db_reporter import DBReporter
from .common_utils import validate_db_reporter_output

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


class TestDBReporter:
    """Test suite for database reporter using baseline validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_request = Mock()
        self.mock_request.node.name = "test_db_reporter"
        self.mock_request.node.fspath.strpath = "/test/path/test_example.py"
        self.mock_request.node.callspec = Mock()
        self.mock_request.node.callspec.params = {}
        self.mock_tbinfo = {"conf-name": "vlab-testbed-01", "duts": ["dut-01"]}

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_db_reporter_basic_functionality(self):
        """Test basic DB reporter functionality with gauge metrics."""
        # Set test-specific file path
        self.mock_request.node.fspath.strpath = "/test/path/test_basic_functionality.py"

        # Create DB reporter
        db_reporter = DBReporter(
            output_dir=self.temp_dir,
            request=self.mock_request,
            tbinfo=self.mock_tbinfo
        )

        # Create test metrics and record values
        metric = GaugeMetric(
            name="test.basic.metric1",
            description="First test metric",
            unit="percent",
            reporter=db_reporter
        )

        # Record values with different labels
        metric.record(75.5, {"device.id": "dut-01", "iteration": "1"})
        metric.record(82.3, {"device.id": "dut-01", "iteration": "2"})

        # Gather metrics and generate report with fixed timestamp
        db_reporter.report(timestamp=1234567890000000000)  # Fixed timestamp for consistent baselines

        # Validate against baseline
        validate_db_reporter_output(db_reporter)

    def test_db_reporter_histogram_metrics(self):
        """Test DB reporter with histogram metrics."""
        # Set test-specific file path
        self.mock_request.node.fspath.strpath = "/test/path/test_histogram_metrics.py"

        # Create DB reporter
        db_reporter = DBReporter(
            output_dir=self.temp_dir,
            request=self.mock_request,
            tbinfo=self.mock_tbinfo
        )

        # Create histogram metric
        histogram_metric = HistogramMetric(
            name="test.histogram.response_time",
            description="API response time distribution",
            unit="milliseconds",
            reporter=db_reporter,
            buckets=[1.0, 2.0, 5.0, 10.0]
        )

        # Record histogram data
        response_times = [1, 3, 8]
        histogram_metric.record_bucket_counts(response_times, {"endpoint": "/api/v1/data"})

        # Gather metrics and generate report with fixed timestamp
        db_reporter.report(timestamp=1234567890000000000)  # Fixed timestamp for consistent baselines

        # Validate against baseline
        validate_db_reporter_output(db_reporter)


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
