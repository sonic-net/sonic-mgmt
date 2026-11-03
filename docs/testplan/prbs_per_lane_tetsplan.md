# Test Plan- PRBS per Lane Testing

## Table of Content

- [Revision](#revision)
- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
    - [Design](#design)
- [Tests](#tests)

## Revision

| Rev  |   Date   |    Author     |       Change Description                  |
| :--: | :------: | :-----------: | ------------------------------------------|
| 0.1  | 18/03/26 | Madhukiran AS | Initial version                           |
| 0.2  | 25/05/26 | Madhukiran AS | Updated to reflect implemented test cases: added end-to-end flow tests (Flow 1-5), L1/SerDes sign-off tests (pattern mismatch, force-disable on admin-down / speed-change, warm/fast-boot persistence), and full-box stress test. |
| 0.3  | 2/06/26 | Madhukiran AS | updated test names                      |
## Overview

This document describes the test plan for PRBS (Pseudo‑Random Bit Sequence) interface functionality in SONiC. The PRBS feature provides CLI support to enable, disable, monitor, and clear PRBS tests on network interfaces, with configuration and runtime state reflected in SONiC databases. The goal of this test plan is to validate correct PRBS CLI behavior, database interactions, end-to-end RX lock with a connected fanout peer, SerDes/L1 sign-off behavior, and full-box stress, as implemented in sonic-swss and the SAI.More details on PRBS design can be found  in below HLD link https://github.com/pavannaregundi/SONiC/blob/f703bfca0c25a14bfbec800e53fce9c8c636c5f9/doc/prbs/PRBS_Per_Lane_HLD.md


### Scope

This test plan covers:
- Enabling and disabling PRBS on interfaces (rx / tx / both modes)
- Validation of PRBS configuration parameters and polynomial handling
- PRBS status display for all interfaces, per interface, and in JSON form
- Clearing PRBS test results (all interfaces and per-interface)
- End-to-end PRBS flows over a real DUT↔fanout link, parametrized over every common (speed × pattern) the link advertises (Flow 1–5)
- Auto-negotiated end-to-end PRBS (Flow 5; DAC only per IEEE 802.3)
- Full-box stress: PRBS31 on every admin-up DUT port (DUT=rx, fanout=tx) simultaneously
- L1 / SerDes sign-off behaviour: polynomial correctness via pattern mismatch, force-disable on admin-down, force-disable on speed change, warm/fast-boot persistence per HLD

This test plan does not cover:
- Electrical / eye-diagram analysis on the SerDes (use lab instruments)
- Dataplane traffic testing (PRBS is L1; ports are in TESTING state)


---


### Testbed
Most CLI / DB tests need only a single SONiC DUT (no fanout required).
End-to-end flow tests (Flow 1–5), the L1 sign-off tests, and the full-box stress test additionally require at least one SONiC-capable fanout peer cabled to the DUT (DAC, AEC, or optical). The full-box test requires **every admin-up DUT Ethernet port** to be paired with a SONiC fanout peer.


### Design
The PRBS per-lane diagnostics feature integrates into the existing SONiC architecture without requiring fundamental architectural changes. The feature utilizes the standard SONiC database infrastructure and orchestration framework.

<img width="1217" height="1022" alt="image" src="https://github.com/user-attachments/assets/10d0a35e-51e7-477c-b6e9-d2b09b50e84d" />




### Environment Validation

Before starting tests, verify the following system conditions:

1. **System Health Check**
   - All critical services are running (xcvrd, pmon, swss, syncd)
   - No existing system errors in logs

2. **Transceiver Baseline Verification**
   - All expected transceivers are present and detected
   - All links are in operational state
   - No existing I2C communication errors
   - LLDP neighbors are discovered (if LLDP is enabled)

3. **Configuration Validation**
   - `system.json` configuration file is properly formatted and accessible
   - All required attributes are defined for the transceivers under test
   - Platform-specific settings are correctly configured

## Test Cases

### A. CLI / DB happy-path and negative tests (single DUT, no fanout required)

Pinned to a DAC port via the `dac_link` / `test_port` fixtures — CLI plumbing
doesn't exercise the SerDes, so running once per media is pure overhead.

| ID | pytest test function | Description | Expected result |
|----|----------------------|-------------|-----------------|
| 1  | `test_cli_prbs_enable_rx` | Enable PRBS in `rx` mode on a valid Ethernet port. | STATE_DB `PORT_PRBS_TEST.mode == 'rx'`; oper_status transitions to TESTING. |
| 2  | `test_cli_prbs_enable_tx` | Enable PRBS in `tx` mode. | STATE_DB `PORT_PRBS_TEST.mode == 'tx'`; oper_status transitions to TESTING. |
| 3  | `test_cli_prbs_enable_both` | Enable PRBS in `both` mode. | STATE_DB `PORT_PRBS_TEST.mode == 'both'`; oper_status transitions to TESTING. |
| 4  | `test_cli_prbs_disable` | Disable PRBS on a port that has PRBS active. | Session cleanly stopped; STATE_DB `PORT_PRBS_TEST.status == 'stopped'`; oper_status returns to `up`. |
| 5  | `test_show_prbs_status_all` | Run `show interfaces prbs status` (box-level). | One row per port that has PRBS state; Status / RX Status columns populated. |
| 6  | `test_show_prbs_status_per_interface` | Run `show interfaces prbs status -i <port>`. | Per-lane table rendered for the port. |
| 7  | `test_show_prbs_status_json` | Run `show interfaces prbs status --json`. | Valid JSON with the documented fields. |
| 8  | `test_clear_prbs_results_all` | `sonic-clear prbs results` with no flag. | All `PORT_PRBS_RESULTS*` / `PORT_PRBS_LANE_RESULT*` keys deleted from STATE_DB. |
| 9  | `test_clear_prbs_results_per_interface` | `sonic-clear prbs results -i <port>`. | Only that port's STATE_DB result keys deleted. |
| 10 | `test_prbs_enable_invalid_pattern` | Attempt enable with a bogus pattern. | CLI rejects with non-zero rc; nothing leaks into STATE_DB. |
| 11 | `test_prbs_enable_admin_down` | Attempt enable on an admin-down port. | CLI rejects with non-zero rc. |
| 12 | `test_prbs_enable_non_ethernet` | Attempt enable on a non-Ethernet object (e.g. `Loopback0`). | CLI rejects (PRBS valid only on Ethernet ports). |
| 13 | `test_prbs_disable_when_not_enabled` | Disable on a port that has no PRBS active. | Command succeeds gracefully (idempotent disable). |
| 14 | `test_prbs_reenable_after_disable` | Enable → disable → enable on the same port. | Final STATE_DB reflects the latest enable. |
| 15 | `test_prbs_re_enable_without_disable` | Enable twice in a row without disabling. | Second enable is rejected (CLI guards against double-enable) OR cleanly replaces, per platform CLI behavior. |

### B. End-to-end PRBS flows over a real DUT↔fanout link

Each `(media, speed)` combo is filtered through `SPEEDS_BY_MEDIA` (DAC/optical
get the full speed superset; AEC restricted to `200G/400G/800G` because AEC
modules are only specified for ≥200G lane rates). Each flow runs once per
`(media, speed, pattern)` the link advertises. PRBS is disabled cleanly on
both sides BEFORE results are read, so STATE_DB is stable when sampled.

| ID | pytest test function | Description | Expected result |
|----|----------------------|-------------|-----------------|
| 16 | `test_prbs_flow_dut_rx_fanout_tx` | Flow 1 — DUT in `rx`, fanout in `tx`. | DUT-side rx_status ∈ {LOCKED, LOCK_WITH_ERRORS}; every lane locked; `err_count` not saturated; oper_status returns to `up` after disable. |
| 17 | `test_prbs_flow_dut_tx_fanout_rx` | Flow 2 — DUT in `tx`, fanout in `rx`. | Same checks on the fanout side. |
| 18 | `test_prbs_flow_both_disable_dut_first` | BOTH-mode on both ends; **DUT disabled FIRST** (peer fanout TX still alive when DUT captures snapshot). | DUT-side rx_status / lane lock / err_count clean; both ends recover to `up`. |
| 19 | `test_prbs_flow_both_disable_fanout_first` | BOTH-mode on both ends; **fanout disabled FIRST**. | Fanout-side rx_status / lane lock / err_count clean; both ends recover to `up`. |
| 20 | `test_prbs_flow_autoneg` | DAC-only. Enable autoneg on both ends, wait for link up, then run PRBS at the negotiated speed for every common pattern. | Autoneg negotiates the same speed on both ends; PRBS locks at the negotiated speed for every pattern; link recovers to `up`. |

### C. Full-box stress

| ID | pytest test function | Description | Expected result |
|----|----------------------|-------------|-----------------|
| 21 | `test_prbs_fullbox_DUT` | Enable PRBS in `both` mode simultaneously on every admin-up DUT port and on every paired SONiC fanout peer (also `both`). After a fixed soak, disable on every port (DUT first, then fanout) and read one box-level `show interfaces prbs status`. Parametrized over every supported pattern. | Every fanout-paired DUT port shows RX Status ∈ {LOCKED, LOCK_WITH_ERRORS}; every port returns to oper_status `up` within `PRBS_FULLBOX_LINK_RECOVERY_TIME`; STATE_DB `PORT_PRBS_TEST.status == 'stopped'` on every port; no stale state. |

### D. L1 / SerDes sign-off

| ID | pytest test function | Description | Expected result |
|----|----------------------|-------------|-----------------|
| 22 | `test_prbs_pattern_mismatch_does_not_lock` | DAC-only. DUT TXes one pattern (e.g. PRBS31), fanout RXes a DIFFERENT pattern (e.g. PRBS9). | Fanout RX MUST NOT report lock — validates polynomial implementation correctness in the SerDes / SAI. |
| 23 | `test_prbs_with_warmboot` | DAC-only. Enable PRBS, trigger `warm-reboot`. Per HLD ("PRBS is compatible with warm boot; no special pre-warmboot steps required"). | Active PRBS session metadata persists after the box comes back; `PORT_PRBS_TEST` reflects the pre-reboot session. |

### Immediate Cleanup

1. **State Restoration**: Verify all transceivers are restored to their original operational state
2. **Link Status**: Verify all transceivers are in operational state with links up
4. **System Health**: Check system logs for any unexpected errors or warnings introduced during testing
5. **Service Status**: Verify all services and daemons are running normally
6. **Database Consistency**: Verify state databases contain expected transceiver information and are consistent

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case
2. **Performance Metrics**: Document settle times, iteration counts, and any performance deviations
3. **Error Analysis**: Compile any errors or warnings encountered during testing with recommended remediation
4. **System State**: Document final system state and any persistent configuration changes.



