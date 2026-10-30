# Copyright (c) 2025 Clounix (Shanghai) Technology Limited.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
#    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
#    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
#    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
#    See the Apache Version 2.0 License for specific language governing
#    permissions and limitations under the License.


"""
SAI Test Result Collection Module

Provides vendor-agnostic structured result output for SAI tests.
Generates JSON result files that can be parsed by Jenkins or other CI systems.

Components:
    - SpecRegistry: Loads spec definitions (unit/result_type/direction) from
      spec_registry.json; provides authoritative unit and comparison direction
    - Measurement: Lightweight data carrier used by record_spec()
    - TestResultCollector: Collects test results and writes JSON output

Usage:
    Integrated into SaiHelperBase (sai_base_test.py). Test classes use:
        self.record_spec(spec_name, operation, value, details={})
        self.mark_test_fail(error_message)
"""

import json
import os
import time
from datetime import datetime, timezone


class Measurement:
    """Lightweight data carrier for one v2 spec result."""

    def __init__(self, spec_name, operation, value, details=None,
                 threshold=None):
        self.spec_name = spec_name
        self.operation = operation
        self.value = value
        self.details = details if details is not None else {}
        self.threshold = threshold


class SpecRegistry:
    """Load spec definitions from spec_registry.json.

    Provides authoritative unit / result_type / direction for each spec_name,
    so callers never hand-write units (avoids mismatches like 'ECMP groups/s').

    is_known() backs the hard check in record_spec: an unregistered spec name
    aborts the test instead of vanishing from the report.
    """

    DEFAULT_UNIT = "unknown"
    DEFAULT_RESULT_TYPE = "performance"
    DEFAULT_DIRECTION = "higher_better"

    def __init__(self, registry_file_path=None):
        self.specs = {}
        self.file_path = registry_file_path
        if registry_file_path is None:
            # Default to spec_registry.json next to this module
            registry_file_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "spec_registry.json")
            self.file_path = registry_file_path
        self._load(registry_file_path)

    def _load(self, file_path):
        if not file_path or not os.path.exists(file_path):
            print(f"[SpecRegistry] Warning: registry file not found: "
                  f"{file_path}")
            return
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except (ValueError, OSError) as e:
            print(f"[SpecRegistry] Warning: failed to parse {file_path}: {e}")
            return

        for key, value in data.items():
            # Skip comment / non-dict entries
            if key.startswith('_') or not isinstance(value, dict):
                continue
            self.specs[key] = value

        print(f"[SpecRegistry] Loaded {len(self.specs)} specs from {file_path}")

    def is_known(self, spec_name):
        return spec_name in self.specs

    def get_unit(self, spec_name):
        spec = self.specs.get(spec_name)
        if spec is None:
            print(f"[SpecRegistry] Warning: unknown spec_name '{spec_name}', "
                  f"using unit='{self.DEFAULT_UNIT}'")
            return self.DEFAULT_UNIT
        return spec.get('unit', self.DEFAULT_UNIT)

    def get_result_type(self, spec_name):
        spec = self.specs.get(spec_name, {})
        return spec.get('result_type', self.DEFAULT_RESULT_TYPE)

    def get_direction(self, spec_name):
        spec = self.specs.get(spec_name, {})
        return spec.get('direction', self.DEFAULT_DIRECTION)


class TestResultCollector:
    """Collect SAI test results and output structured JSON.

    Each test class instance creates one collector. The collector gathers
    individual spec results during test execution and writes a single
    JSON file on finalization.

    Output path: {output_dir}/{test_module}_{test_class}.json
    """

    def __init__(self, test_class_name, test_module_name,
                 output_dir="/tmp/sai_test_results"):
        """Initialize the result collector.

        Args:
            test_class_name: Name of the test class (e.g., 'L3IPv4SingleHopScaleMask16Test')
            test_module_name: Module name (e.g., 'ext_sai_l3_route_scale_test')
            output_dir: Directory to write result JSON files
        """
        self.test_class = test_class_name
        self.test_module = test_module_name
        self.start_time = None
        self.end_time = None
        self.overall_result = "PASS"
        self.error_message = None
        self.spec_results = []
        self.attr_rows = []
        self.metadata = {}
        self.output_dir = output_dir

    def set_metadata(self, platform=None, chip=None, sai_version=None,
                     port_count=None, **kwargs):
        """Set test environment metadata.

        Args:
            platform: Platform name (e.g., 'broadcom', 'ctc')
            chip: Chip name (e.g., 'th3', 'tsingma')
            sai_version: SAI API version string
            port_count: Number of active ports
            **kwargs: Additional metadata key-value pairs
        """
        if platform is not None:
            self.metadata['platform'] = platform
        if chip is not None:
            self.metadata['chip'] = chip
        if sai_version is not None:
            self.metadata['sai_version'] = sai_version
        if port_count is not None:
            self.metadata['port_count'] = port_count
        self.metadata.update(kwargs)

    def add_spec_result(self, spec_name, operation, value, threshold=None,
                        details=None):
        """Record one measurement fact in the v2 result schema.

        Static unit, result type and comparison direction belong to
        spec_registry.json. Per-case JSON contains only the value observed in
        this run and optional metric-specific details.
        """
        entry = {
            "spec_name": spec_name,
            "operation": operation,
            "value": value,
            "threshold": threshold,
            "details": details if details is not None else {},
        }
        self.spec_results.append(entry)

    def mark_fail(self, error_message):
        """Mark the overall test as failed and record the error.

        Args:
            error_message: Description of the failure
        """
        self.overall_result = "FAIL"
        if self.error_message:
            self.error_message += f"\n{error_message}"
        else:
            self.error_message = str(error_message)

    def record_attr_row(self, row):
        """Sink for sai_capture: which attr/op/value this case touched.

        Association only -- the verdict comes from the case outcome, so no
        judgement is applied or stored here.
        """
        self.attr_rows.append(row)

    def _distinct_attr_records(self):
        """Drop repeats: a case may touch one attr many times across its stages,
        and the report-side join only needs the distinct set."""
        seen, uniq = set(), []
        for r in self.attr_rows:
            key = (r.get('attr'), r.get('op'), r.get('value'))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(r)
        return uniq

    def to_dict(self):
        """Convert the collected results to a dictionary."""
        duration = None
        if self.start_time and self.end_time:
            duration = round(self.end_time - self.start_time, 3)

        result = {
            "test_class": self.test_class,
            "test_module": self.test_module,
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": duration,
            "overall_result": self.overall_result,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "spec_results": self.spec_results,
            "attr_records": self._distinct_attr_records(),
        }

        return result

    def write_json(self):
        """Write the result JSON file to the output directory.

        File name: {test_module}_{test_class}.json
        """
        os.makedirs(self.output_dir, exist_ok=True)

        file_name = f"{self.test_module}_{self.test_class}.json"
        file_path = os.path.join(self.output_dir, file_name)

        result_data = self.to_dict()

        with open(file_path, 'w') as f:
            json.dump(result_data, f, indent=4, ensure_ascii=False)

        print(f"\n[RESULT] Test result written to: {file_path}")
        print(f"[RESULT] Overall: {self.overall_result} | "
              f"Specs recorded: {len(self.spec_results)}")

        return file_path
