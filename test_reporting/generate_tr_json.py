"""
generate_tr_json.py

This script generates a synthetic test result JSON file (`tr.json`) in a format
compatible with the Pytest JUnit-style output. It is typically used in CI pipelines
to report test step failures (e.g., locking failures, deployment issues) where the
failure occurs outside of the normal test execution flow.

The generated `tr.json` includes metadata, summary, and test case fields, and can
be uploaded to the Kusto database for visibility and tracking.

Usage:
    python generate_tr_json.py --output tr.json --test-name <name> --result <result> \
        [--error-msg <msg>] [--error-type <type>] [--testbed <name>]
"""

import json
import argparse
import uuid
from datetime import datetime, timezone


def generate_tr_json(
    test_name: str,
    result: str,
    error_msg: str,
    error_type: str,
    testbed: str = "unknown",
    report_id: str = None
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    report_id = report_id or str(uuid.uuid4())

    test_case = {
        "Feature": "upgrade_path",
        "TestCase": test_name,
        "classname": "upgrade_path",
        "file": "synthetic",
        "name": test_name,
        "line": 0,
        "ModulePath": "upgrade_path",
        "FilePath": "synthetic",
        "time": 1.0,
        "StartLine": 0,
        "Runtime": 1.0,
        "result": result,
        "ReportId": report_id,
        "error": result == "error",
        "summary": error_msg,
        "StartTime": now,
        "EndTime": now,
        "CustomMsg": {
            "upgrade_path_result": {
                "error_type": error_type
            }
        },
        "start": now,
        "end": now,
        "properties": [
            {"name": "start", "value": now},
            {"name": "end", "value": now},
            {"name": "CustomMsg", "value": {
                "upgrade_path_result": {
                    "error_type": error_type
                }
            }}
        ]
    }

    return {
        "created": now,
        "start_time": now,
        "duration": 1.0,
        "report": {
            "tests": 1,
            "errors": 1 if result == "error" else 0,
            "failures": 1 if result == "failure" else 0,
            "skipped": 1 if result == "skipped" else 0
        },
        "test_cases": {
            "upgrade_path": [test_case]
        },
        "test_metadata": {
            "testbed": testbed,
            "platform": "synthetic_platform",
            "hwsku": "synthetic_hwsku",
            "os_version": "synthetic_os_version",
            "asic": "synthetic_asic",
            "topology": "synthetic_topology",
            "host": "synthetic_host",
            "timestamp": now
        },
        "test_summary": {
            "tests": 1,
            "passed": 1 if result == "passed" else 0,
            "failures": 1 if result == "failure" else 0,
            "errors": 1 if result == "error" else 0,
            "skipped": 1 if result == "skipped" else 0,
            "time": 1.0
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic tr.json for test failure.")
    parser.add_argument("--output", required=True, help="Path to output tr.json")
    parser.add_argument("--test-name", required=True, help="Full test name e.g. upgrade_path::lock_testbed")
    parser.add_argument("--result", choices=["passed", "failure", "error", "skipped"], required=True)
    parser.add_argument("--error-msg", required=True, help="Custom error message for summary")
    parser.add_argument("--error-type", required=True, help="Type of error e.g. LOCK_TESTBED")
    parser.add_argument("--testbed", default="unknown", help="Testbed name")

    args = parser.parse_args()
    result = generate_tr_json(
        test_name=args.test_name,
        result=args.result,
        error_msg=args.error_msg,
        error_type=args.error_type,
        testbed=args.testbed
    )

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Generated {args.output}")


if __name__ == "__main__":
    main()
