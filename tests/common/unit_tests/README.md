# Unit Tests for tests/common/unit_tests

This directory contains unit tests for modules under `tests/common`.

## Running Unit Tests

### Run all unit tests in this directory
```bash
# From repository root
python3 -m pytest --noconftest tests/common/unit_tests/ -v
```

### Run a specific test file
```bash
python3 -m pytest --noconftest tests/common/unit_tests/fixtures/unit_test_conn_graph_facts.py -v
```

### Run a specific test case
```bash
python3 -m pytest --noconftest \
  tests/common/unit_tests/fixtures/unit_test_conn_graph_facts.py::test_get_graph_facts_matches_graph_group_for_trim_and_non_trim_inventory \
  -v
```

## Why `--noconftest`

`tests/conftest.py` pulls in integration-test dependencies (for example, `paramiko`) that are not needed for these isolated unit tests. Using `--noconftest` keeps the run lightweight and avoids unrelated import failures.

If your environment has the full sonic-mgmt test dependencies installed and you intentionally want global fixtures, you can remove `--noconftest`.

### DHCP relay cleanup regression

`unit_test_dhcp_relay_cleanup.py` exercises both DHCP relay cleanup blocks with
independent selected/standby relay modes, single/dual-ToR topologies, and config,
readiness, and socket failures. It extracts the cleanup code via `ast` to avoid
testbed dependencies; physical packet forwarding still requires a dual-ToR run.

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/unit_test_dhcp_relay_cleanup.py -v
```

The `--confcutdir` option also prevents collection of parent package setup that
imports Linux-only testbed utilities.

## Requirements

- Python 3
- `pytest`
- `unittest.mock` (built into Python standard library)
