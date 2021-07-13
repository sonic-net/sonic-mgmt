import os
import sys
import json


class TestResultJSONValidationError(Exception):
    """Expected errors that are trhown while validating the contents of the Test Result JSON file."""


def validate_json_file(path):
    if not os.path.exists(path):
        print(f"{path} not found")
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"{path} is not a JSON file")
        sys.exit(1)

    try:
        with open(path) as f:
            test_result_json = json.load(f)
    except Exception as e:
        raise TestResultJSONValidationError(f"Could not load JSON file {path}: {e}") from e

    return test_result_json
