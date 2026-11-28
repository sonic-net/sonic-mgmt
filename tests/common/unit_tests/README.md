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

## BMC cooling-aware startup regression

`unit_test_bmcctld_startup.py` executes the startup assertions and power-loss test
method via AST without importing Linux/testbed dependencies. It covers both
air-cooled startup paths, liquid-cooled boot-relative delay thresholds, missing
or malformed evidence, reboot/health failures, platform API JSON boolean type checking,
and PDU outlet restoration after individual controller exceptions.
It also exercises BMC-only cold reboot with an explicit nonzero delay, verifies
positive delay-bypass and host-isolation evidence, and checks configuration
restoration on success and failures. Failed or malformed delay snapshots must
abort before configuration changes, cleanup, or reboot.
For `test_bmcctld_power_on_delay`, a PDU remains preferred. Without a controller,
SKUs in `PSU_SYSTEM_POWER_CYCLE_HWSKUS` can use the shared `power_cycle_via_psu()`
workaround. `check_power_cycle_via_psu()` validates the allowlist and
platform API without cycling the devices, before changing the delay. Unlisted
SKUs without a PDU skip. Both paths retain power-loss reboot causes, changed boot
IDs for both devices, marker-bounded startup logs, boot-relative liquid-cooling
delay, configuration persistence/restoration, and host health checks. Both paths
wait for BMC readiness before restoring configuration, including after a failed cycle.
The regressions cover fallback routing and failures without touching hardware.
Physical startup behavior requires a BMC chassis with a wired PDU or a verified
full-system PSU-cycle implementation on an allowlisted SKU.

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/unit_test_bmcctld_startup.py -q
```

## BMC critical-process recovery regression

`unit_test_critical_process_bmc_recovery.py` exercises the shared `power_cycle_via_psu()` helper
and process-monitoring fixture without Linux or testbed dependencies. On
`bmc-dual-mgmt`, a PDU takes precedence. Without a PDU, the system power-cycle
workaround applies only to exact `hwsku` entries in
`tests/common/platform/bmc_utils.py::PSU_SYSTEM_POWER_CYCLE_HWSKUS`, currently
`['Arista-7060XE7-64PRS']`. Add future supported SKUs to that shared list; both
fixture routing and helper validation use it. Admission resolves one recovery
route before destructive work; configured PDU lookup failures do not select a
fallback. Recovery requires a callable
`SWITCH-HOST.do_system_power_cycle()`, checked before the destructive database
test. Unlisted SKUs and missing SKU metadata retain ordinary software reboot
recovery without probing the platform API. No unified chassis API or new platform
package is required.

The chassis operation must power-cycle both the BMC and switch host. Recovery
requires changed boot IDs from both devices, not just reachable SSH. The unit
tests cover capability checks, pre-test rejection, restart evidence, disconnects,
PDU routing, exact SKU allowlisting and future list additions, the frozen recovery
route, and preserved direct OS/VS recovery and post-reboot health gates. They do
not establish hardware power-cycle support; that requires vendor implementation
and a physical testbed. The log-format override avoids integration-only log
metadata when running the direct-reboot regressions without conftest.

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/unit_test_critical_process_bmc_recovery.py \
  tests/common/unit_tests/unit_test_critical_process_direct_reboot.py \
  -o log_format='%(levelname)s:%(message)s' -q
```

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

## gNMI AAA TLS reuse

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/fixtures/unit_test_gnmi_aaa.py -q
```

These offline regressions extract production helpers to avoid testbed imports.
They independently model raw Redis hashes and cfggen-decoded role lists, including
empty fields and NULL sentinels. They exercise exact metadata restoration,
setup/body/cleanup failures, configuration-leak detection, strict certificate
cleanup, fresh public RPC channels, and real pytest fixture
ordering with mocked devices. They do not establish device authorization,
audit/rate-limit behavior, or a hardware performance improvement.
