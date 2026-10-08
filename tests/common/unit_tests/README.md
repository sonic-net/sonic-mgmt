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

## Multi-password SSH rotation

`connections/unit_test_multi_passwd_ssh.py` also requires Ansible. It loads the
real connection plugin and covers command execution, SFTP, SCP and piped transfers
without connecting to a DUT.

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/connections/unit_test_multi_passwd_ssh.py -q
```

The plugin rotates through distinct supplied endpoint/password pairs, beginning
with the last successful pair for that connection. Each operation stops on
success or before repeating its starting pair. Changed candidates reset the
cursor; reapplying identical candidates preserves it. Connection/authentication exceptions, including censored
`no_log` failures, permit rotation; remote command exit statuses do not.
Password settings are restored after each operation, and endpoint settings are
restored if every candidate fails. Existing Ansible same-endpoint reconnect
retries remain independent of this one-cycle bound.

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
