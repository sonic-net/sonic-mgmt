# Unit Tests for `tests/common/snappi_tests/`

This directory contains unit tests for modules under
`tests/common/snappi_tests/`.

## Running Unit Tests

### Run all unit tests in this directory
```bash
# From repository root
python3 -m pytest --noconftest tests/common/unit_tests/snappi_tests/ -v
```

### Run a specific test file
```bash
python3 -m pytest --noconftest \
  tests/common/unit_tests/snappi_tests/unit_test_common_helpers.py -v
```

### Run a specific test case
```bash
python3 -m pytest --noconftest \
  tests/common/unit_tests/snappi_tests/unit_test_common_helpers.py::test_get_queue_scheduler_weight_dict \
  -v
```

## Why `--noconftest`

`tests/conftest.py` pulls in integration-test dependencies (for example,
`paramiko`) that are not needed for these isolated unit tests. Using
`--noconftest` keeps the run lightweight and avoids unrelated import
failures.

The target module `tests/common/snappi_tests/common_helpers.py` itself
imports heavy dependencies (`tests.conftest`, `ipaddr`, mellanox helpers,
etc.) at import time. To stay dependency-free, the unit tests load only the
function under test by parsing the source with `ast` and `exec`-ing the
single function definition in an isolated namespace. No real DUT, Ansible
inventory, or Snappi environment is required.

If your environment has the full sonic-mgmt test dependencies installed and
you intentionally want global fixtures, you can remove `--noconftest`.

## Requirements

- Python 3
- `pytest`
- `unittest.mock` (built into Python standard library)
