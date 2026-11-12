# Unit Tests for `tests/snappi_tests/pfc/`

This directory contains unit tests for modules under
`tests/snappi_tests/pfc/`.

## Running Unit Tests

### Run all unit tests in this directory
```bash
# From repository root
python3 -m pytest --noconftest tests/snappi_tests/unit_tests/pfc/ -v
```

### Run a specific test file
```bash
python3 -m pytest --noconftest \
  tests/snappi_tests/unit_tests/pfc/unit_test_m2o_fluctuating_lossless_helper.py -v
```

### Run a specific test case
```bash
python3 -m pytest --noconftest \
  "tests/snappi_tests/unit_tests/pfc/unit_test_m2o_fluctuating_lossless_helper.py::test_expected_bg_loss_matches_analytical_dwrr_split[mixed_weights_15_14-0-11.2676]" \
  -v
```

## What `unit_test_m2o_fluctuating_lossless_helper.py` covers

The test reproduces the IxNetwork Flow Statistics observed on
SN4700 / 7260CX3 for the `m2o_fluctuating_lossless` scenario and validates
that `get_expected_bg_loss_percent` returns a value matching the analytical
DWRR split.

Fixed scenario inputs:

| Parameter                 | Value           |
| ------------------------- | --------------- |
| `test_prio_list`          | `[3, 4]`        |
| `test_flow_rate_percent`  | `[20, 10]`      |
| `bg_prio_list`            | `[0, 1, 2, 5]`  |
| `bg_flow_rate_percent`    | `[20, 20, 20, 20]` |

Parametrized DWRR weight profiles (vary only the scheduler weights):

| Case                  | Q0/Q1/Q2/Q5/Q6 | Q3/Q4 | Expected per-BG loss |
| --------------------- | -------------- | ----- | -------------------- |
| `mixed_weights_15_14` | 14             | 15    | ~11.27% (IxNetwork measured 11.259%) |
| `uniform_weights_15`  | 15             | 15    | 10.0% (fair share)   |

Tolerance: `abs=0.01`.

## Why `--noconftest`

`tests/conftest.py` pulls in integration-test dependencies (for example,
`paramiko`) that are not needed for these isolated unit tests. Using
`--noconftest` keeps the run lightweight and avoids unrelated import
failures.

The target module
`tests/snappi_tests/pfc/files/m2o_fluctuating_lossless_helper.py` itself
imports heavy sonic-mgmt deps (`tests.conftest`, mellanox helpers, etc.)
at import time. To stay dependency-free, the test parses the source with
`ast`, picks just the top-level `get_expected_bg_loss_percent` definition
(its `_prio_to_queue` / `_compute_dwrr_allocation` / `_add_demand` helpers
are nested inside it and come along for free) and `exec`s it into a fresh
namespace. Two names are then injected into that namespace so the function
can run standalone:

- `get_queue_scheduler_weight_dict` — replaced with a `MagicMock` returning
  a canned per-queue weight dict, so no DUT / Ansible inventory / Snappi
  environment is required.
- `pytest_assert` — replaced with a tiny stub (`assert condition, message`)
  so the helper's input-validation asserts work without importing
  `tests.common.helpers.assertions`.

If your environment has the full sonic-mgmt test dependencies installed and
you intentionally want global fixtures, you can drop `--noconftest`.

## Requirements

- Python 3
- `pytest`
- `unittest.mock` (built into the Python standard library)
