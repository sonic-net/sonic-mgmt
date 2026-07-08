# Unit Tests for ECN WRED counter parsing

This directory contains unit tests for the ECN/WRED counter parsing
helpers in `tests/common/snappi_tests/common_helpers.py`.

## Running Unit Tests

### Run all unit tests in this directory
```bash
# From repository root
python3 -m pytest --noconftest tests/snappi_tests/unit_tests/ecn/ -v
```

### Run a specific test file
```bash
python3 -m pytest --noconftest \
  tests/snappi_tests/unit_tests/ecn/unit_test_ecn_wred_counter_parsing.py -v
```

### Run a specific test case
```bash
python3 -m pytest --noconftest \
  "tests/snappi_tests/unit_tests/ecn/unit_test_ecn_wred_counter_parsing.py::test_parse_int_counter[N/A-0]" \
  -v
```

## What `unit_test_ecn_wred_counter_parsing.py` covers

The tests validate parsing of `show queue wredcounters --json` output used by
`get_ecn_wred_counters()`:

| Helper | What is tested |
| ------ | -------------- |
| `_parse_int_counter` | `N/A`, empty strings, comma-separated values |
| `_txq_from_priority` | Numeric priority to `UC<n>` / `VOQ<n>`, explicit labels |
| `_parse_wred_counters_json` | Metadata skip (`time`, `cached_time`), key rename, `N/A` |
| `_filter_wred_counters_by_priority` | No filter, match, and missing TxQ |

Sample JSON under test:

| Port | Queues | Notes |
| ---- | ------ | ----- |
| `Ethernet0` | `UC3`, `UC4` | `N/A` drop counters, comma-separated ECN values |
| `Ethernet8` | `VOQ3` | VOQ chassis label, `cached_time` metadata only |

## Why `--noconftest`

`tests/conftest.py` pulls in integration-test dependencies (for example,
`paramiko`) that are not needed for these isolated unit tests. Using
`--noconftest` keeps the run lightweight and avoids unrelated import
failures.

The target module `tests/common/snappi_tests/common_helpers.py` itself
imports heavy sonic-mgmt deps at import time. To stay dependency-free, the
test parses the source with `ast`, extracts only the top-level parsing
helpers, and `exec`s them into a fresh namespace:

- `_parse_int_counter`
- `_txq_from_priority`
- `_normalize_wred_counter_entry`
- `_parse_wred_counters_json`
- `_filter_wred_counters_by_priority`

No DUT, Ansible inventory, or Snappi environment is required.

If your environment has the full sonic-mgmt test dependencies installed and
you intentionally want global fixtures, you can drop `--noconftest`.

## Requirements

- Python 3
- `pytest`
