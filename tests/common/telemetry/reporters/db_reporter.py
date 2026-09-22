"""
Database (DB) Reporter for historical analysis and trend tracking.

This reporter writes metrics to local files that can be uploaded to
OLTP databases for historical analysis, reporting, and trend tracking.
"""

import datetime
import json
import logging
import os
from typing import Optional, List
from ..base import Reporter, HistogramRecordData
from ..constants import REPORTER_TYPE_DB


class DBReporter(Reporter):
    """
    Database reporter for historical analysis.

    Writes metrics to local JSON files that can be processed and uploaded
    to databases for long-term storage, trend analysis, and reporting.
    """

    def __init__(self, output_dir: Optional[str] = None, request=None, tbinfo=None):
        """
        Initialize DB reporter with file output configuration.

        Args:
            output_dir: Directory for output files (default: current directory)
            request: pytest request object for test context
            tbinfo: testbed info fixture data
        """
        super().__init__(REPORTER_TYPE_DB, request, tbinfo)
        self.output_dir = output_dir or os.getcwd()

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

        logging.info(f"DBReporter initialized: output_dir={self.output_dir}")

    def _report(self, timestamp: float):
        """
        Write all collected metrics to local files.

        Args:
            timestamp: Timestamp for this reporting batch
        """
        logging.info(f"DBReporter: Writing {len(self.recorded_metrics)} metric records to file")

        # Generate filename based on test file path
        filename = self._generate_filename()
        filepath = os.path.join(self.output_dir, filename)

        # Convert timestamp to datetime for ISO format
        timestamp_dt = datetime.datetime.fromtimestamp(timestamp / 1e9)  # timestamp is in nanoseconds

        # Prepare data structure
        report_data = {
            "metadata": {
                "reporter_type": self.reporter_type,
                "timestamp": timestamp_dt.isoformat(),
                "test_context": self.test_context,
                "record_count": len(self.recorded_metrics)
            },
            "records": []
        }

        # Convert records to JSON-serializable format
        for record in self.recorded_metrics:
            # Handle HistogramRecordData serialization
            if isinstance(record.data, HistogramRecordData):
                data_value = record.data.to_dict()
                # Add bucket boundaries for histogram data
                if hasattr(record.metric, 'buckets'):
                    data_value["buckets"] = record.metric.buckets
            else:
                data_value = record.data

            record_dict = {
                "metric_name": record.metric.name,
                "metric_type": record.metric.metric_type,
                "description": record.metric.description,
                "unit": record.metric.unit,
                "labels": record.labels,
                "data": data_value,
                "timestamp": timestamp,
                "timestamp_iso": timestamp_dt.isoformat()
            }
            report_data["records"].append(record_dict)

        # Write to file
        try:
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2, sort_keys=True)

            logging.info(f"DBReporter: Successfully wrote {len(self.recorded_metrics)} "
                         f"metric records to {filepath}")

        except Exception as e:
            logging.error(f"DBReporter: Failed to write metric records to {filepath}: {e}")
            raise

    def _generate_filename(self) -> str:
        """
        Generate filename based on test file path.

        Returns:
            Filename in format: <test_file_path_without_extension>.metrics.json,
            e.g. "/dns/static_dns/test_static_dns.metrics.json"
        """
        # Get test file path from test context
        test_file = self.test_context.get('test.file', 'unknown')

        # Remove extension if present (.py)
        if test_file.endswith('.py'):
            test_file = test_file[:-3]

        return f"{test_file}.metrics.json"

    def get_output_files(self) -> List[str]:
        """
        Get list of output files created by this reporter.

        Returns:
            List of output file paths
        """
        files = []
        for filename in os.listdir(self.output_dir):
            if filename.endswith('.metrics.json'):
                files.append(os.path.join(self.output_dir, filename))
        return sorted(files)

    def clear_output_files(self):
        """
        Remove all output files created by this reporter.

        Use with caution - this permanently deletes telemetry data files.
        """
        files = self.get_output_files()
        for filepath in files:
            try:
                os.remove(filepath)
                logging.info(f"DBReporter: Removed output file {filepath}")
            except Exception as e:
                logging.warning(f"DBReporter: Failed to remove {filepath}: {e}")
