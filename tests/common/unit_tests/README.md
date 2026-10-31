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

## PTF daily TACACS provisioning regression

`helpers/unit_test_ptf_tacacs_provisioning.py` loads the topology task YAML and
evaluates its conditions for Docker networking enabled, disabled, and unset.
It covers both `add-topo` and `renumber-topo`, preserves the PTF-only scope and
MAC-change guard, and checks delegation to the PTF management address.
These isolated checks require `PyYAML` and `Jinja2`; they do not start a daemon
or replace a live testbed run.

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/helpers/unit_test_ptf_tacacs_provisioning.py -q
```

## Host-failure lifecycle regressions

Run the classifier unit tests and the real pytest lifecycle regressions together:

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/helpers/unit_test_host_failure_utils.py \
  tests/common/unit_tests/helpers/unit_test_host_failure_lifecycle.py -q
```

`--confcutdir` also excludes parent package setup, so these tests do not load
`tests/common/__init__.py` or require a SONiC container. The lifecycle tests extract
the production hooks from `tests/conftest.py` and run them in isolated pytest
subprocesses with real function/module/session fixtures. They cover teardown-first
unreachability, later cleanup failures, exit code 15, complete final `CustomMsg`
and captured cleanup logs, and preservation of normal test execution. Exception
coverage includes `pytest.fail`, `pytest.skip`, mixed exception groups, and
unchanged propagation of `SystemExit`, `KeyboardInterrupt`, and `pytest.exit`.
Mixed-group coverage also checks independent same-scope finalizers and errors
raised before the group, so completing ancestor scopes alone is not sufficient.

## ICMP Responder

Run the responder regressions from the repository root in a sonic-mgmt container:

```bash
python3 -m pytest --noconftest tests/common/unit_tests/fixtures/unit_test_icmp_responder.py -v
```

These tests require Scapy and libpcap, available in the SONiC test containers.
Run in an isolated container network namespace with `NET_RAW` to exercise the
kernel BPF filters and asynchronous responder over loopback. Those cases skip
without raw-socket permission. Runtime tests cover both address families,
payload/checksum integrity, destination-MAC override, and JSON FIFO pause/recovery.

The responder retains its existing IPv4 source filter. IPv6 is opt-in through
repeatable `--src_ipv6 ADDRESS` arguments, accepting only echo requests from those
sources with ICMPv6 directly following the IPv6 header, as emitted by linkmgrd.
Both PTF responder fixtures derive these sources from DUT Loopback2 configuration
when a mux port selects `soc_ipv6` (active-active) or `server_ipv6` (active-standby)
because the corresponding IPv4 field is absent. Dual-stack ports keep IPv4
preference. IPv6-selected ports without an IPv6 Loopback2 fail fixture setup.
