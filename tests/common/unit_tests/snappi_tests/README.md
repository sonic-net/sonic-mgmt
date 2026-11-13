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

For final MACsec statistics readiness checks:
```bash
python3 -m pytest --noconftest \
  tests/common/unit_tests/snappi_tests/unit_test_traffic_generation.py -v
```

These checks cover delayed TX/RX updates, missing flows, traffic-engine completion,
counter stability, and explicit timeout diagnostics. Genuine positive packet
loss is returned unchanged for the existing test-specific assertions.
Registered MACsec flows are explicitly stopped before final-counter polling;
regressions also verify this ordering when counters time out or shutdown fails.
On a final-counter timeout, raw Flow Statistics, Traffic Item Statistics, and
Port Statistics snapshots are logged for comparison without changing the
reported counts. Missing diagnostic views do not mask the original failure.

The deferred-first-read MACsec experiment avoids Flow Statistics reads while
registered flows run, unless pause-time snapshots are explicitly required.
It waits for the IxNetwork traffic engine to finish before reading counters.
The in-flight return value is `None` for this path; final loss assertions and
counter consistency checks remain unchanged. A hardware run showed consistent
TX/RX counters after deferral, but retained nonzero Quick Flow Group rates.
Final readiness therefore requires the engine to be `stopped` or
`stoppedWaitingForStats` and valid counters stable across two consecutive
snapshots; nonzero rate cells are logged as a warning rather than treated as
ongoing traffic. Running engines, invalid or changing counters, missing flows,
and RX greater than TX still fail. Hardware validation of this readiness
correction is pending.

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
