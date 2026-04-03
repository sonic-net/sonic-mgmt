"""
Common utilities for telemetry testing.

This module contains shared mock classes and fixtures for testing telemetry
metrics collections and reporters.
"""

import json
import os

from common.telemetry.base import Reporter
from common.telemetry.reporters.db_reporter import DBReporter


class MockReporter(Reporter):
    """Mock reporter that logs all metrics for testing."""

    def __init__(self, request=None, tbinfo=None):
        super().__init__("mock", request, tbinfo)
        self.report_called = False

    def _report(self, timestamp: float):
        """Mark that report was called."""
        self.report_called = True


def validate_recorded_metrics(reporter: Reporter, collection_name: str):
    """
    Common validation function to compare mock reporter results with expected records from JSON baseline.

    If SONIC_MGMT_GENERATE_BASELINE=1, generates new baseline files from actual recorded data.

    Args:
        reporter: The reporter that recorded metrics
        collection_name: Name of the collection to load baseline data for
    """
    reporter.gather_all_recorded_metrics()

    # Serialize recorded metrics as-is without any assumptions about structure
    actual_data = []
    for record in reporter.recorded_metrics:
        # Convert to serializable format
        record_data = {
            "metric": {
                "name": record.metric.name,
                "metric_type": record.metric.metric_type,
                "description": record.metric.description,
                "unit": record.metric.unit
            },
            "data": record.data,
            "labels": record.labels
        }
        actual_data.append(record_data)

    # Sort by metric name for consistent comparison
    actual_data.sort(key=lambda x: x["metric"]["name"])

    baseline_dir = os.path.join(os.path.dirname(__file__), 'baselines')
    baseline_file = os.path.join(baseline_dir, f'{collection_name}.json')

    # Check if we should generate baseline
    if os.environ.get("SONIC_MGMT_GENERATE_BASELINE") == "1":
        # Ensure baseline directory exists
        os.makedirs(baseline_dir, exist_ok=True)

        # Write actual data as new baseline
        with open(baseline_file, 'w') as f:
            json.dump(actual_data, f, indent=2, sort_keys=True)

        print(f"Generated baseline file: {baseline_file}")
        return

    # Load expected data from JSON baseline for validation
    with open(baseline_file, 'r') as f:
        expected_data = json.load(f)

    # Sort expected data by metric name for consistent comparison
    expected_data.sort(key=lambda x: x["metric"]["name"])

    # Deep comparison
    assert actual_data == expected_data, \
        f"Recorded metrics data does not match baseline for {collection_name}"


def validate_db_reporter_output(db_reporter: DBReporter):
    """
    Common validation function to compare DB reporter output files with expected baseline files.

    If SONIC_MGMT_GENERATE_BASELINE=1, copies the actual output files to baseline folder.
    Otherwise, compares the output files with baseline files.

    The baseline file path is determined from the reporter's test context.

    Args:
        db_reporter: The DB reporter that wrote output files
    """
    import shutil

    # Get output files from reporter
    output_files = db_reporter.get_output_files()
    assert len(output_files) == 1, f"Expected 1 output file, got {len(output_files)}"

    actual_file = output_files[0]

    # Extract test file name from reporter's test context to determine baseline path
    test_file = db_reporter.test_context.get('test.file', 'unknown')
    if test_file.endswith('.py'):
        test_file = test_file[:-3]  # Remove .py extension

    baseline_dir = os.path.join(os.path.dirname(__file__), 'baselines', 'db_reporter')
    baseline_file = os.path.join(baseline_dir, f'{test_file}.metrics.json')

    # Check if we should generate baseline
    if os.environ.get("SONIC_MGMT_GENERATE_BASELINE") == "1":
        # Ensure baseline directory exists
        os.makedirs(baseline_dir, exist_ok=True)

        # Copy the actual output file to baseline
        shutil.copy2(actual_file, baseline_file)
        print(f"Generated DB reporter baseline file: {baseline_file}")
        return

    # Load and compare files directly (no need to normalize timestamps since we use fixed ones)
    with open(actual_file, 'r') as f:
        actual_output = json.load(f)

    with open(baseline_file, 'r') as f:
        expected_output = json.load(f)

    # Sort records by metric_name for consistent comparison
    def sort_records(data):
        """Sort records by metric_name if available."""
        if isinstance(data, dict) and "records" in data:
            sorted_data = data.copy()
            sorted_data["records"] = sorted(data["records"], key=lambda x: x.get("metric_name", ""))
            return sorted_data
        return data

    sorted_actual = sort_records(actual_output)
    sorted_expected = sort_records(expected_output)

    # Deep comparison
    assert sorted_actual == sorted_expected, \
        f"DB reporter output does not match baseline for {test_file}"


def validate_ts_reporter_output(ts_reporter, exported_metrics_list):
    """
    Common validation function to compare TS reporter OTLP output with expected baseline JSON.

    If SONIC_MGMT_GENERATE_BASELINE=1, generates new baseline files from actual OTLP output.
    Otherwise, compares the OTLP output with baseline files.

    The baseline file path is determined from the reporter's test context.

    Args:
        ts_reporter: The TS reporter that exported metrics
        exported_metrics_list: List of exported MetricsData objects from mock exporter
    """
    # Convert any object to JSON-serializable format using recursive approach
    def obj_to_dict(obj):
        """Convert any object to dictionary for JSON serialization.

        Skips non-serializable fields by testing JSON serializability.
        """
        import json

        # Handle primitive types
        if obj is None or isinstance(obj, (str, int, float, bool)):
            return obj

        # Test if the object can be JSON serialized as-is
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            pass

        # Handle collections
        if isinstance(obj, dict):
            return {k: v for k, v in ((k, obj_to_dict(v)) for k, v in obj.items()) if v is not None}

        if isinstance(obj, (list, tuple)):
            return [item for item in (obj_to_dict(x) for x in obj) if item is not None]

        # Extract key-value pairs from object
        def get_object_items(obj):
            """Get key-value pairs from object."""
            if hasattr(obj, '__dict__'):
                return vars(obj).items()
            elif hasattr(obj, '__slots__'):
                return ((slot, getattr(obj, slot, None)) for slot in obj.__slots__)
            else:
                # Fallback: get public attributes
                return ((attr, getattr(obj, attr)) for attr in dir(obj)
                        if not attr.startswith('_') and not callable(getattr(obj, attr, None)))

        # Convert object to dict
        result = {}
        for k, v in get_object_items(obj):
            serialized_value = obj_to_dict(v)
            if serialized_value is not None:
                result[k] = serialized_value

        return result if result else None

    # Convert all exported metrics to dictionaries
    actual_data = []
    for metrics_data in exported_metrics_list:
        actual_data.append(obj_to_dict(metrics_data))

    # Sort data for consistent comparison (no need to normalize timestamps since we use fixed ones)
    def sort_ts_data(data_list):
        """Sort OTLP data for consistent comparison."""
        sorted_data = []
        for data in data_list:
            sorted_data_item = json.loads(json.dumps(data))  # Deep copy

            # Sort for consistent comparison
            for resource_metrics in sorted_data_item["resource_metrics"]:
                for scope_metrics in resource_metrics["scope_metrics"]:
                    for metric in scope_metrics["metrics"]:
                        # Sort data points by attributes for consistent comparison
                        metric["data"]["data_points"].sort(key=lambda x: str(x.get("attributes", {})))

                    # Sort metrics by name
                    scope_metrics["metrics"].sort(key=lambda x: x["name"])

            sorted_data.append(sorted_data_item)

        return sorted_data

    sorted_actual = sort_ts_data(actual_data)

    # Extract test file name from reporter's test context to determine baseline path
    test_file = ts_reporter.test_context.get('test.file', 'unknown')
    if test_file.endswith('.py'):
        test_file = test_file[:-3]  # Remove .py extension

    baseline_dir = os.path.join(os.path.dirname(__file__), 'baselines', 'ts_reporter')
    baseline_file = os.path.join(baseline_dir, f'{test_file}.json')

    # Check if we should generate baseline
    if os.environ.get("SONIC_MGMT_GENERATE_BASELINE") == "1":
        # Ensure baseline directory exists
        os.makedirs(baseline_dir, exist_ok=True)

        # Write sorted data as new baseline
        with open(baseline_file, 'w') as f:
            json.dump(sorted_actual, f, indent=2, sort_keys=True)

        print(f"Generated TS reporter baseline file: {baseline_file}")
        return

    # Load expected data from JSON baseline for validation
    with open(baseline_file, 'r') as f:
        expected_data = json.load(f)

    # Deep comparison
    assert sorted_actual == expected_data, \
        f"TS reporter output does not match baseline for {test_file}"
