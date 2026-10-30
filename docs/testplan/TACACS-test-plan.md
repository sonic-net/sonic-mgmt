# TACACS+ AAA Test Plan

## Table of Contents
- [TACACS+ AAA Test Plan](#tacacs-aaa-test-plan)
  - [Table of Contents](#table-of-contents)
  - [1 Overview](#1-overview)
  - [2 Scope](#2-scope)
  - [3 Test Setup](#3-test-setup)
    - [3.1 Test Environment](#31-test-environment)
    - [3.2 TACACS+ Server Configuration](#32-tacacs-server-configuration)
  - [4 Test Cases](#4-test-cases)
    - [4.1 Preflight / Setup Validation](#41-preflight--setup-validation)
    - [4.2 Authentication Tests](#42-authentication-tests)
    - [4.3 Authorization and AAA Configuration Tests](#43-authorization-and-aaa-configuration-tests)
    - [4.4 Accounting Tests](#44-accounting-tests)
  - [5 Implementation Details](#5-implementation-details)
    - [5.1 Test Framework](#51-test-framework)
    - [5.2 Key Fixtures and Helpers](#52-key-fixtures-and-helpers)
    - [5.3 Test Configuration](#53-test-configuration)
  - [6 Expected Results](#6-expected-results)

## 1 Overview

This document describes the test plan for new TACACS+ test files added under `tests/tacacs/` alongside the existing community TACACS+ suite. The new files extend the existing coverage with scenarios that are not exercised by the current `test_accounting.py`, `test_authorization.py`, `test_ro_disk.py`, `test_ro_user.py`, `test_rw_user.py`, or `test_jit_user.py` modules.

Files added by this plan:

- `tests/tacacs/test_aaa_preflight.py` — environment readiness checks that gate the rest of the suite.
- `tests/tacacs/test_aaa_authentication.py` — TACACS+ authentication scenarios (failover, timeout, source IP, concurrent sessions, etc.).
- `tests/tacacs/test_aaa_accounting.py` — event-level accounting coverage (login events, command execution, wildcard encoding, dual TACACS+local accounting). Complements the existing `tests/tacacs/test_accounting.py` which focuses on server-availability scenarios.
- `tests/tacacs/test_aaa_config.py` — end-to-end AAA-config tests covering SSH authentication, local fallback, and role-based command access.
- `tests/tacacs/test_aaa.py` — aggregator entry point that re-exports tests from the four modules above for single-run execution.

## 2 Scope

This plan covers TACACS+ behavior on SONiC. The 26 test cases collectively validate:

- TACACS+ service / daemon health on both DUT and PTF.
- DUT-side AAA mode configuration (authentication / authorization / accounting).
- TACACS+ authentication flows including failover, timeout, source IP, and concurrent RO/RW sessions.
- TACACS+ accounting events at the protocol level (login events, command execution, wildcard encoding) and accounting hand-off between TACACS+ and local sinks.
- Role-based authorization for RO and RW TACACS+ users.
- Defensive behavior (wrong passkey, server timeout, disable-TACACS revert, config persistence across reload).

Out of scope for this plan:

- TACACS+ server-availability scenarios already covered by community `test_accounting.py` (`test_accounting_tacacs_only`, `*_all_tacacs_server_down`, `*_some_tacacs_server_down`, `test_accounting_local_only`, `test_accounting_tacacs_and_local`).
- TACACS+ authorization scenarios already covered by community `test_authorization.py`.
- Per-user filesystem behavior already covered by `test_ro_disk.py`, `test_ro_user.py`, `test_rw_user.py`.

## 3 Test Setup

### 3.1 Test Environment

The test environment consists of:

- SONiC Device Under Test (DUT).
- PTF (Packet Test Framework) host running a `tac_plus` TACACS+ server.
- Test credentials defined by the standard `tacacs_creds` fixture (`tests/common/fixtures/tacacs.py`).
- Management-network reachability between the DUT and the PTF-hosted TACACS+ server.

Topology marker:

```python
pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs'),
]
```

### 3.2 TACACS+ Server Configuration

The TACACS+ server (`tac_plus`) on PTF is configured with:

- Authentication on TCP/49.
- Shared secret matching the value in `tacacs_creds`.
- User database with the standard `tacacs_rw_user` and `tacacs_ro_user` accounts plus their group memberships.
- Per-command accounting enabled.

Configuration template used: `tests/tacacs/tac_plus.conf.j2` (existing community asset).

## 4 Test Cases

### 4.1 Preflight / Setup Validation

File: `tests/tacacs/test_aaa_preflight.py`

Eight readiness checks that run before any functional test. Failure here indicates a misconfigured testbed, not a SONiC bug.

**Test Case H01: SONiC services running (`test_h01_sonic_services_running`)**
- Verify DUT critical services (SwSS, syncd, bgp, lldp, etc.) are fully started.
- Fail-fast if the DUT is not in a healthy baseline before TACACS+ tests run.

**Test Case H02: TACACS+ server reachable (`test_h02_tacacs_server_reachable`)**
- Verify TCP/49 reachability from DUT to the PTF-hosted TACACS+ server.
- Fail-fast if the DUT cannot reach the server (rules out routing/firewall issues before functional tests).

**Test Case H03: TACACS+ config on DUT (`test_h03_tacacs_config_on_dut`)**
- Verify `config tacacs` returns at least one configured server.
- Verify the configured server matches the PTF TACACS+ instance.

**Test Case H04: AAA authentication mode (`test_h04_aaa_authentication_mode`)**
- Verify `show aaa` reports the configured authentication mode (`tacacs+`, `local`, or `tacacs+ local`).
- Confirm the configured mode matches what the test fixtures expect.

**Test Case H05: AAA authorization mode (`test_h05_aaa_authorization_mode`)**
- Verify `show aaa` reports the configured authorization mode.

**Test Case H06: AAA accounting mode (`test_h06_aaa_accounting_mode`)**
- Verify `show aaa` reports the configured accounting mode.

**Test Case H07: TACACS+ daemon running on PTF (`test_h07_tacacs_daemon_running_on_ptf`)**
- Verify the `tac_plus` process is alive on the PTF host.
- Verify the daemon is listening on TCP/49.

**Test Case H08: End-to-end smoke login (`test_h08_end_to_end_smoke_login`)**
- Authenticate the RW TACACS+ user via SSH to the DUT.
- Run a trivial command and assert it succeeds.
- Confirms the full authentication path works end-to-end before the rest of the suite runs.

### 4.2 Authentication Tests

File: `tests/tacacs/test_aaa_authentication.py`

Nine TACACS+ authentication scenarios not exercised by the existing community suite.

**Test Case A1: Failover primary down, secondary takes over (`test_failover_primary_down_secondary_takes_over`)**
- Configure two TACACS+ servers; mark the first as unreachable.
- Attempt SSH login with TACACS+ credentials.
- Verify authentication succeeds via the secondary server.

**Test Case A2: Wrong passkey rejected (`test_wrong_passkey_rejected`)**
- Configure the DUT with an incorrect TACACS+ shared secret.
- Attempt SSH login.
- Verify authentication is rejected and the failure is logged.

**Test Case A3: Server timeout no hang (`test_server_timeout_no_hang`)**
- Block traffic to the TACACS+ server (or stop the server).
- Attempt SSH login.
- Verify the DUT-side authentication does not hang past the configured timeout and returns a failure within bounded time.

**Test Case A4: JIT user created on login (`test_jit_user_created_on_login`)**
- Authenticate a TACACS+ user who does not exist locally on the DUT.
- Verify SONiC just-in-time creates the local Linux user and group.
- Verify the local entry is consistent with the TACACS+ user role.

**Test Case A5: Disable TACACS+ reverts to local (`test_disable_tacacs_reverts_to_local`)**
- Configure local fallback alongside TACACS+.
- Disable TACACS+ on the DUT via `config aaa authentication`.
- Verify subsequent logins are authenticated locally.

**Test Case A6: TACACS+ config persists after reload (`test_tacacs_config_persists_after_reload`)**
- Configure TACACS+ via CLI.
- `config save` and `config reload -y -f`.
- Verify TACACS+ config is restored after reload and authentication still works.

**Test Case A7: TACACS+ source IP (`test_tacacs_source_ip`)**
- Configure a specific source-interface for TACACS+ traffic.
- Authenticate and capture TACACS+ traffic on PTF.
- Verify outbound TACACS+ packets use the configured source IP.

**Test Case A8: Concurrent RO/RW sessions (`test_concurrent_ro_rw_sessions`)**
- Open simultaneous SSH sessions as the RO and RW TACACS+ users.
- Run commands in both sessions in parallel.
- Verify each session retains its own authorization scope and there is no cross-contamination.

**Test Case A9: Local user blocked under tacacs-only (`test_local_user_blocked_tacacs_only`)**
- Configure `aaa authentication tacacs+` (no local fallback).
- Attempt SSH login with a local-only account.
- Verify the login is rejected.

### 4.3 Authorization and AAA Configuration Tests

File: `tests/tacacs/test_aaa_config.py`

Five tests covering end-to-end SSH authentication and role-based command access.

**Test Case C1: Valid SSH authentication (`test_valid_ssh_authentication`)**
- Authenticate the RW TACACS+ user via SSH.
- Verify the session is established and a basic command runs successfully.

**Test Case C2: Invalid credentials rejected (`test_invalid_credentials_rejected`)**
- Attempt SSH login with a known-bad password.
- Verify authentication is rejected and no session is opened.

**Test Case C3: Local fallback when server unreachable (`test_local_fallback_when_server_unreachable`)**
- Configure `aaa authentication tacacs+ local`.
- Stop the TACACS+ server on PTF.
- Authenticate as a local-only user.
- Verify the local credential succeeds (fallback chain works).

**Test Case C4: RO user blocked from write commands (`test_ro_user_blocked_from_write_commands`)**
- Authenticate as the RO TACACS+ user.
- Attempt a privileged write command (e.g. `sudo config interface shutdown`).
- Verify the command is denied.

**Test Case C5: RW user read/write commands (`test_rw_user_read_write_commands`)**
- Authenticate as the RW TACACS+ user.
- Run a representative read command and a representative write command.
- Verify both succeed.

### 4.4 Accounting Tests

File: `tests/tacacs/test_aaa_accounting.py`

Four event-level accounting scenarios that complement the existing `tests/tacacs/test_accounting.py` (which focuses on server-availability scenarios).

**Test Case ACT1: Accounting records login events (`test_accounting_records_login_events`)**
- Open and close an SSH session as the RW TACACS+ user.
- Verify the TACACS+ server's accounting log (`/var/log/tac_plus.acct`) records both the start and stop records for the session.

**Test Case ACT2: Accounting records command execution (`test_accounting_records_command_execution`)**
- As the RW TACACS+ user, execute a representative command (e.g. `grep`).
- Verify the per-command accounting record reaches the TACACS+ server log.

**Test Case ACT3: Wildcard encoding sent to server (`test_wildcard_encoding_sent_to_server`)**
- Execute a command containing shell wildcards (e.g. `ls /tmp/*`).
- Verify the wildcard is sent to the TACACS+ server intact in the accounting record (not pre-expanded).

**Test Case ACT4: Dual accounting TACACS+ and local (`test_dual_accounting_tacacs_and_local`)**
- Configure `aaa accounting tacacs+ local`.
- Execute a command as the RW TACACS+ user.
- Verify the same command appears in **both** the TACACS+ server log and the DUT-local syslog (`audisp-tacplus`).

## 5 Implementation Details

### 5.1 Test Framework

- Python pytest.
- All test files reuse the standard sonic-mgmt fixture and helper layout — no new conftest changes are introduced.
- Module-level markers: `pytest.mark.disable_loganalyzer`, `pytest.mark.topology('any', 't1-multi-asic')`, `pytest.mark.device_type('vs')`.

### 5.2 Key Fixtures and Helpers

| Provider | Fixture / helper |
|---|---|
| `tests/common/fixtures/tacacs.py` | `tacacs_creds` |
| `tests/common/helpers/tacacs/tacacs_helper.py` | `check_tacacs`, `tacacs_v6_context`, `ssh_remote_run`, `ssh_remote_run_retry`, `start_tacacs_server`, `stop_tacacs_server`, `remove_all_tacacs_server`, `per_command_accounting_skip_versions`, `per_command_authorization_skip_versions` |
| `tests/tacacs/conftest.py` | `tacacs_creds`, `check_tacacs_v6`, `skip_in_container_test` (reused from existing community suite) |
| `tests/common/utilities` | `wait_until`, `paramiko_ssh`, `check_output`, `skip_release` |

### 5.3 Test Configuration

- TACACS+ server template: `tests/tacacs/tac_plus.conf.j2` (existing community asset).
- TACACS+ credentials and per-test parameters loaded via the standard `tacacs_creds` fixture.
- No new YAML, no new Jinja2 templates.

## 6 Expected Results

All 26 test cases should:

- Complete successfully without errors on a healthy single-DUT t1-multi-asic / t0 testbed with a PTF-hosted `tac_plus` server.
- Restore the DUT to its pre-test AAA configuration on teardown.
- Emit clear error messages, relevant DUT and PTF logs, and TACACS+ server-side accounting context for failures.

Test failures should provide:

- The exact CLI command and DUT response.
- Relevant snippets from `/var/log/syslog` (DUT side) and `/var/log/tac_plus.acct` (server side).
- Configured AAA modes and the TACACS+ server list at the moment of failure.
