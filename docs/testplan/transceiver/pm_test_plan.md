# Performance Monitoring (PM) Test Plan For Transceivers

## Overview

The Performance Monitoring (PM) Test Plan for transceivers outlines a comprehensive testing strategy for the Performance Monitoring functionality of CMIS / C-CMIS based transceiver modules. PM exposes statistical (minimum, maximum, and average) samples of basic optical and signal-integrity observables collected by the module over a Performance Monitoring Interval, published by `xcvrd` into the `TRANSCEIVER_PM` table in STATE_DB and surfaced through the `show interfaces transceiver pm` CLI.

This document covers the objectives, scope, attributes, test cases, and validation procedures required to validate PM data integrity, the host-controlled PM interval (freeze / unfreeze) behavior described by CMIS Page 2Fh, PM polling-period configuration, and the coherent (C-CMIS, Page 35h) and grey (CMIS VDM) metric sets.

**References:**

- [OIF-CMIS-05.2](https://www.oiforum.com/wp-content/uploads/OIF-CMIS-05.2.pdf) — Common Management Interface Specification (Page 2Fh VDM Advertisement and Dynamic Controls, Section 8.19; VDM Observable Types, Table 8-153)
- [OIF-C-CMIS-01.4](https://www.oiforum.com/wp-content/uploads/OIF-C-CMIS-01.4.pdf) — Coherent CMIS (Page 35h Media Lane Link Performance Monitoring, Table 15)

## Scope

The scope of this test plan includes the following:

- Validation of PM data availability, freshness, and field completeness in the `TRANSCEIVER_PM` table and via `show interfaces transceiver pm`
- Validation of the statistical relationship (`min <= avg <= max`) and operational-range bounds for every reported PM metric
- Validation of the coherent C-CMIS Page 35h media-lane metric set for ZR / coherent optics (CD, DGD, SOPMD, PDL, OSNR, eSNR, CFO, EVM, SOPROC, Tx/Rx power, Pre-FEC BER, FERC)
- Validation of the grey-optic CMIS VDM statistic metric set (Pre-FEC BER and FERC min/avg/max)
- Validation of the host-controlled PM interval via the freeze / unfreeze (Page 2Fh) control flow, including `tVDMF` timing and statistics-register behavior
- Validation of PM polling-period configuration and PM recovery across link-state-change events
- Error handling for PM operations on non-PM-capable transceivers and on ports without transceivers

## Optics Scope

PM is a CMIS / C-CMIS capability. The test cases in this plan apply only to transceivers that advertise PM support (`pm_supported` = true). Within the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope) optics set, this plan distinguishes two sub-classes:

- **Coherent (ZR / C-CMIS) optics** (`zr_optics` = true): report the full Page 35h media-lane metric set.
- **Grey (CMIS VDM) optics** (`zr_optics` = false): report the VDM statistic observables — primarily Pre-FEC BER and FERC (min/avg/max).

Non-CMIS transceivers (SFF-8636 / SFF-8436 / SFF-8472) and CMIS modules without PM support do not have a `pm.json` entry and are skipped.

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology).

## Pre-requisites

Before executing the PM tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-prerequisites-and-configuration-files) must be met
- `pm.json` is properly formatted and accessible; required attributes are defined for the transceivers under test (see [Attributes](#attributes) for the shard layout)
- The transceivers under test are linked up and carrying a healthy signal, so that PM observables reflect a real operating point (verified once at session start via the inherited `links_verified` gate)

System health (running daemons, fresh logs) and transceiver baseline (presence, gold firmware, link-up) are covered by the parent's [Common Session-Level Prerequisites](test_plan.md#common-session-level-prerequisites) and [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks); see the prerequisite matrix for which gates PM consumes.

## Attributes

A `pm.json` file is used to define the attributes for the PM tests for the various types of transceivers the system supports. The category is sharded across all five shard scopes (category, platform, HWSKU, vendor, per-PN) under `attributes/pm/`; see [File Organization](test_plan.md#file-organization) for the shard contract and [Loader Validation](test_plan.md#loader-validation) for how it is enforced.

**Note on Operational Ranges:** PM metrics are statistics of basic observables collected over a PM interval. Each configured `<metric>_operational_range` represents the realistic operational window expected during normal, healthy operation in a typical data center environment. These ranges are intentionally tighter than the module's absolute alarm/warning thresholds and help distinguish nominal operation from edge conditions that, while within specification, may indicate fiber degradation, aging components, or suboptimal conditions, enabling early detection before formal alarms trigger.

The following table summarizes the key attributes used in PM testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| pm_supported | boolean | - | O | transceivers | Whether the transceiver supports Performance Monitoring (CMIS VDM statistics or C-CMIS Page 35h). Transceivers without PM should not have this attribute present at all; their absence skips the entire PM category for that port |
| zr_optics | boolean | False | O | transceivers | Whether the transceiver is a coherent (ZR / C-CMIS) optic. When true, the full Page 35h media-lane metric set is expected; when false, only the grey-optic VDM statistic metrics (Pre-FEC BER, FERC) are expected |
| pm_data_max_age_min | integer | 15 | O | platform | Maximum age in minutes for PM data to be considered fresh (`last_update_time` validation in `TRANSCEIVER_PM`) |
| pm_consistency_check_poll_count | integer | 3 | O | transceivers or platform | Number of polling cycles to perform when validating PM data consistency and statistical relationships |
| pm_poll_interval_sec | integer | 60 | O | platform | Default `xcvrd` PM polling/collection interval in seconds, i.e. the cadence at which the module's frozen statistics are read and a new PM interval is started |
| pm_poll_interval_to_test_sec | integer | 60 | O | platform or transceivers | PM polling interval (in seconds) to configure and validate via the polling-period configuration test (default 60 seconds / 1 minute) |
| pm_recovery_margin_sec | integer | 30 | O | platform | Additional grace period in seconds, added on top of the configured polling interval, allowed for PM data to resume updating after a link-state-change event |
| vdm_freeze_unfreeze_timeout_sec | float | 1.0 | O | platform | Maximum time (`tVDMF`) in seconds the module is allowed to take to assert `FreezeDone` after a `FreezeRequest`, or `UnfreezeDone` after a freeze release (Page 2Fh) |
| vdm_supported_groups | integer | - | O | transceivers | Expected number of supported VDM instance groups (1-4) advertised in Page 2Fh byte 128 bits 1-0 (`VDMSupport`). Used to validate VDM page advertisement |
| `<metric>`_operational_range | dict | - | O | transceivers | Realistic operational range for a PM metric, format `{"min": <float>, "max": <float>}`. The `avg`, `min`, and `max` STATE_DB samples for the metric are all validated against this single window. See [PM Metric Catalog](#pm-metric-catalog) for the valid `<metric>` base names and their units |

**Statistical relationship rule:** For every PM metric present in STATE_DB, the test verifies `min <= avg <= max`. Where a `<metric>_operational_range` is configured, the test additionally verifies that all three samples (`<metric>_min`, `<metric>_avg`, `<metric>_max`) fall within `[range.min, range.max]`. Metrics without a configured operational range are still subject to the ordering check and presence check, but not the bounds check.

## PM Metric Catalog

The following table is the authoritative mapping between a `<metric>` attribute base name, the corresponding `TRANSCEIVER_PM` STATE_DB fields (each metric exposes an `_avg`, `_min`, and `_max` field), the CMIS / C-CMIS source register, and the unit. These names match the `TRANSCEIVER_PM` schema published by `xcvrd` (see `get_transceiver_pm` in `sonic-platform-common`).

| Metric base (`<metric>`) | STATE_DB fields | Source (C-CMIS Page 35h / CMIS VDM) | Unit | Applies to |
|--------------------------|-----------------|-------------------------------------|------|-----------|
| `prefec_ber` | `prefec_ber_avg/min/max` | VDM Pre-FEC BER (Media Input) | ratio (0 – 1e-4 nominal) | Grey + ZR |
| `uncorr_frames` | `uncorr_frames_avg/min/max` | VDM FERC (Frame Error Count Ratio) | ratio (`0` nominal) | Grey + ZR |
| `cd` | `cd_avg/min/max` | `rxAvg/Min/MaxCdPm` | ps/nm | ZR |
| `dgd` | `dgd_avg/min/max` | `rxAvg/Min/MaxDgdPm` | ps | ZR |
| `sopmd` | `sopmd_avg/min/max` | `rxAvg/Min/MaxLGSopmdPm` | ps^2 | ZR |
| `pdl` | `pdl_avg/min/max` | `rxAvg/Min/MaxPdlPm` | dB | ZR |
| `osnr` | `osnr_avg/min/max` | `rxAvg/Min/MaxOsnrPm` | dB | ZR |
| `esnr` | `esnr_avg/min/max` | `rxAvg/Min/MaxEsnrPm` | dB | ZR |
| `cfo` | `cfo_avg/min/max` | `rxAvg/Min/MaxCfoPm` | MHz | ZR |
| `evm` | `evm_avg/min/max` | `rxAvg/Min/MaxEvmModemPm` | % | ZR |
| `soproc` | `soproc_avg/min/max` | `rxAvg/Min/MaxSopcrPm` | krad/s | ZR |
| `tx_power` | `tx_power_avg/min/max` | `txAvg/Min/MaxPowerPm` | dBm | ZR |
| `rx_tot_power` | `rx_tot_power_avg/min/max` | `rxAvg/Min/MaxPowerPm` | dBm | ZR |
| `rx_sig_power` | `rx_sig_power_avg/min/max` | `rxAvg/Min/MaxSigPowerPm` | dBm | ZR |

**Notes:**

- For grey optics (`zr_optics` = false), only `prefec_ber` and `uncorr_frames` are expected; the coherent media-lane metrics are not reported and are skipped.
- For coherent optics (`zr_optics` = true), all metrics above are expected.
- The Pre-FEC BER acceptable window for a healthy link is `0` through `1e-4`; the FERC (uncorrected frame ratio) acceptable value for a healthy link is `0`. These bounds are the recommended defaults for `prefec_ber_operational_range` and `uncorr_frames_operational_range` respectively.

## Dynamic Field Mapping Algorithm

The PM test framework uses an attribute-driven approach to dynamically determine which metrics to validate based on the configuration present in `pm.json`, eliminating hardcoded field lists.

### Algorithm Steps

1. **Capability gate**: If `pm_supported` is absent for a port, skip all PM tests for that port.
2. **Metric-set selection**: Determine the expected metric base set from `zr_optics`:
   - `zr_optics` = true → full coherent set from the [PM Metric Catalog](#pm-metric-catalog).
   - `zr_optics` = false → grey set (`prefec_ber`, `uncorr_frames`).
3. **Field expansion**: For each expected metric base `<metric>`, expand to the three STATE_DB fields `<metric>_avg`, `<metric>_min`, `<metric>_max`.
4. **Operational-range discovery**: Scan `pm.json` for attributes ending in `_operational_range`; strip the suffix to obtain the `<metric>` base. A configured range enables the bounds check for that metric's three fields.
5. **Validation**: Validate presence and the `min <= avg <= max` ordering for all expanded fields; apply the operational-range bounds check only to metrics that have a configured range.

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework. This section provides comprehensive examples of all relevant commands.

The primary commands and queries used in these tests are:

```bash
# CLI (relies on redis-db) - dump PM data for a port
show interfaces transceiver pm <port>

# STATE_DB - read a single PM field published by xcvrd
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_PM|<port>" "prefec_ber_avg"

# STATE_DB - read PM data freshness timestamp
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_PM|<port>" "last_update_time"

# Raw EEPROM access to Page 2Fh control/advertisement registers (CMIS)
# VDMSupport advertisement (byte 128)
sudo sfputil read-eeprom -p <port> -n 0x2F -o 128 -s 1
# Freeze/Unfreeze control (byte 144, bit 7 = FreezeRequest)
sudo sfputil read-eeprom  -p <port> -n 0x2F -o 144 -s 1
sudo sfputil write-eeprom -p <port> -n 0x2F -o 144 -d <hex> --verify
# Freeze/Unfreeze status (byte 145, bit 7 = FreezeDone, bit 6 = UnfreezeDone)
sudo sfputil read-eeprom  -p <port> -n 0x2F -o 145 -s 1

# Configure the PM polling interval (seconds) for a port
config interface -n '<namespace>' transceiver pm-poll-interval <port> <seconds>

# Verify configured PM polling interval
sonic-db-cli -n '<namespace>' CONFIG_DB hget "PORT|<port>" "pm_poll_interval"

# Link-state-change events used by the recovery tests
sudo config interface -n '<namespace>' shutdown <port>
sudo config interface -n '<namespace>' startup  <port>
```

> **Note:** The `pm-poll-interval` configuration knob and its `CONFIG_DB` `pm_poll_interval` field model the host-controlled PM collection cadence. If a given image/platform does not expose this knob, the polling-period test case (Advanced TC 1) is skipped gracefully and the dependent recovery checks fall back to the default `pm_poll_interval_sec`.

## Test Cases

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from `port_attributes_dict`) that have `pm_supported` = true, unless specified otherwise.
- ZR-specific metric coverage (coherent media-lane metrics) is exercised only for ports with `zr_optics` = true; grey-optic ports validate only `prefec_ber` and `uncorr_frames`.

### Common Test Setup and Teardown

Inherits the [Common Session-Level Prerequisites](test_plan.md#common-session-level-prerequisites) and [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) from the parent framework (PM consumes the `presence_verified`, `gold_fw_verified`, and `links_verified` gates). PM tests add the following category-specific checks:

#### Session-Level Setup (once per test run)

1. **PM capability**: Confirm at least one port under test has `pm_supported` = true; otherwise skip the entire PM category.
2. **PM polling baseline**: Record the configured `pm_poll_interval` (or the default `pm_poll_interval_sec`) for each port under test so the polling-period tests can restore it during teardown.

#### Per-Test Setup (before each test case)

1. **Interface liveness**: Verify all ports under test are operationally up with no recent link flaps. Checked per test because the Advanced tests are disruptive and may affect link state.
2. **PM data freshness**: Query `TRANSCEIVER_PM` in STATE_DB and verify `last_update_time` is within `pm_data_max_age_min` minutes of current time.

#### Per-Test Teardown (after each test case)

1. **Freeze state restoration**: Ensure the `FreezeRequest` bit (Page 2Fh byte 144 bit 7) is cleared so the module resumes normal statistics reporting (relevant to the freeze/unfreeze tests).
2. **PM data freshness**: Re-verify `last_update_time` in `TRANSCEIVER_PM` is within `pm_data_max_age_min` minutes of current time for all ports under test.

### Basic PM Functionality Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | PM data availability verification | 1. For each port with `pm_supported` = true, access PM data from the `TRANSCEIVER_PM` table in STATE_DB.<br>2. Verify `last_update_time` is within `pm_data_max_age_min` minutes of current time to ensure data freshness.<br>3. Determine the expected metric set using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm) (full coherent set for `zr_optics` = true, grey set otherwise).<br>4. Validate presence of all `<metric>_avg`, `<metric>_min`, `<metric>_max` fields for the expected metric set.<br>5. Skip metrics that do not apply to the port's optic class. | All expected PM fields are present and accessible from STATE_DB without errors. Coherent media-lane metrics are validated only for ZR optics; grey optics validate `prefec_ber` and `uncorr_frames`. Data freshness is confirmed with a recent `last_update_time`. |
| 2 | PM CLI verification | 1. Run `show interfaces transceiver pm <port>` for each PM-capable port.<br>2. Parse the CLI output and confirm every expected metric (min/avg/max columns) for the optic class is populated with a numeric value (no blank/`N/A` for supported metrics).<br>3. Cross-check a sample of CLI values against the corresponding `TRANSCEIVER_PM` STATE_DB fields. | The CLI output is rendered without error and reports populated min/avg/max values for all expected metrics. CLI values are consistent with the STATE_DB `TRANSCEIVER_PM` fields, confirming the CLI correctly reflects redis-db content. |
| 3 | PM value validation (ordering, operational range, and FEC health) | 1. Retrieve PM data from STATE_DB and verify `last_update_time` is within `pm_data_max_age_min` minutes of current time.<br>2. Determine the expected metric set using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm), which selects the correct metric set per optic class: the **coherent (ZR / C-CMIS)** case (`zr_optics` = true) covers the full Page 35h media-lane set (`cd`, `dgd`, `sopmd`, `pdl`, `osnr`, `esnr`, `cfo`, `evm`, `soproc`, `tx_power`, `rx_tot_power`, `rx_sig_power`) plus `prefec_ber` and `uncorr_frames`; the **grey-optic (CMIS VDM)** case (`zr_optics` = false) covers only `prefec_ber` and `uncorr_frames`.<br>3. **Ordering:** for every expected metric, verify `<metric>_min <= <metric>_avg <= <metric>_max`.<br>4. **Operational range:** for each metric with a configured `<metric>_operational_range`, verify `<metric>_min`, `<metric>_avg`, and `<metric>_max` all fall within `[range.min, range.max]`; metrics without a configured range are skipped for this check.<br>5. **FEC health:** verify all `prefec_ber` samples lie within `0` through `1e-4`, and all `uncorr_frames` (FERC) samples are exactly `0` (the ratio is non-negative; any value `> 0` indicates uncorrected frames).<br>6. Aggregate all ordering, range, and FEC violations and report per port and metric at the end. | The correct metric set is validated for each optic class (full coherent set for ZR optics, `prefec_ber`/`uncorr_frames` for grey optics). Every reported PM metric satisfies `min <= avg <= max`. All samples for metrics with a configured operational range fall within that range, Pre-FEC BER is within `[0, 1e-4]`, and FERC is `0`, confirming healthy values during normal operation. Any ordering, range, or FEC violation is logged per port and metric with actual vs. expected values. |
| 4 | PM data consistency verification | 1. Read PM data `pm_consistency_check_poll_count` times, waiting at least one `pm_poll_interval_sec` between reads.<br>2. Confirm `last_update_time` advances across polling cycles.<br>3. Verify each reading independently satisfies the `min <= avg <= max` ordering and (where configured) operational-range bounds.<br>4. Verify metric values vary within physically reasonable limits between intervals (no erratic or impossible jumps). | PM data is refreshed each polling cycle (`last_update_time` advances) and remains internally consistent across `pm_consistency_check_poll_count` cycles. No erratic or impossible value changes are observed, indicating stable PM collection. |

### Advanced PM Testing

> **Note:** Each test case's steps include the TC-specific baselines it needs (configured polling interval, link flap counts, baseline PM snapshot). Failure-path recovery (restoring the polling interval, clearing the freeze bit, restoring shutdown interfaces) is handled by the session-level [Cleanup](#cleanup-and-post-test-verification). Presence/completeness and value validation of the coherent (Page 35h) and grey (CMIS VDM) metric sets are covered by [Basic PM Functionality Tests](#basic-pm-functionality-tests) TC 1 and TC 3; the responsiveness check below (TC 2) applies to all PM-capable optics, observing the metrics expected to react to an optical change for each optic class.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | PM polling-period configuration | 1. Verify the port is operationally up and record the current `pm_poll_interval` so it can be restored.<br>2. Configure the PM polling interval to `pm_poll_interval_to_test_sec` (default 60 seconds / 1 minute): `config interface transceiver pm-poll-interval <port> <pm_poll_interval_to_test_sec>`; verify `CONFIG_DB PORT\|<port> pm_poll_interval` = `<pm_poll_interval_to_test_sec>`.<br>3. Confirm PM data updates at the configured cadence: observe `last_update_time` advancing approximately every `pm_poll_interval_to_test_sec` seconds across at least two cycles.<br>4. Restore the original `pm_poll_interval` and verify CONFIG_DB reflects the restored value. | The PM polling interval is configurable to `pm_poll_interval_to_test_sec` (1 minute by default) and reflected in CONFIG_DB, PM data updates at the configured cadence, and the original interval is restored at the end. |
| 2 | PM metric responsiveness and recovery on link/optical change | 1. For each PM-capable port, determine the expected metric set via the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm) and identify the metrics expected to react to an optical-power change. Record the baseline of those metrics, the current link flap count, and verify freshness.<br>2. Induce a known, recoverable link/optical change: locally toggle the port (`config interface shutdown <port>` then `config interface startup <port>`), or induce a remote-side optical perturbation if the topology allows it.<br>3. Confirm the affected metrics reflected the change during the event.<br>4. After the link returns to oper-up and a wait of `pm_poll_interval_sec` + `pm_recovery_margin_sec`, verify PM collection resumed: `last_update_time` is within `pm_data_max_age_min` of current time and continues to advance, all expected metrics are repopulated and satisfy `min <= avg <= max` and (where configured) operational-range bounds, and the reactive metrics recovered to within their operational ranges.<br>5. Confirm the link flap count increased by exactly the expected amount from the deliberate toggle and is otherwise stable. | The reactive PM metrics track the induced change for the port's optic class (e.g. coherent Rx power/OSNR/eSNR drop and Pre-FEC BER rises; grey Pre-FEC BER rises). After the link is restored, PM collection resumes within `pm_poll_interval_sec` + `pm_recovery_margin_sec` with all metrics repopulated, consistent, and back within their operational ranges, and no unexpected link flaps occur. The test is skipped gracefully when a safe perturbation is not possible. |
| 3 | VDM page advertisement validation (Page 2Fh) (optional) | 1. Read Page 2Fh byte 128 bits 1-0 (`VDMSupport`) via `sfputil read-eeprom -p <port> -n 0x2F -o 128 -s 1`.<br>2. Map the 2-bit code to the number of supported VDM groups (0→1 group, 1→2 groups, 2→3 groups, 3→4 groups).<br>3. If `vdm_supported_groups` is configured, compare the decoded group count against the attribute.<br>4. Read the `FineIntervalLength` (bytes 129-130, U16, units of 0.1 ms) and confirm it is a plausible non-zero value. | The decoded VDM group count matches the configured `vdm_supported_groups` (when present), and `FineIntervalLength` is a plausible non-zero value, confirming the module correctly advertises its VDM capability per Page 2Fh. |
| 4 | Statistics freeze / unfreeze control flow (Page 2Fh) (optional) | 1. Ensure starting from a well-defined point: raise `FreezeRequest` (byte 144 bit 7 = 1) via `sfputil write-eeprom`, then poll byte 145 bit 7 (`FreezeDone`) and confirm it is set within `vdm_freeze_unfreeze_timeout_sec` (`tVDMF`).<br>2. Release the freeze (clear `FreezeRequest`); poll byte 145 bit 6 (`UnfreezeDone`) and confirm it is set within `tVDMF`, indicating the module resumed real-time updates.<br>3. Read a baseline of the statistics reporting registers (a representative metric's min/avg/max from Pages 24h-27h, or via `TRANSCEIVER_PM`), then allow live updates for a short interval.<br>4. Raise `FreezeRequest` again; confirm `FreezeDone` asserts within `tVDMF`.<br>5. While frozen, read the statistics reporting registers twice with a gap and confirm the values are stable (do not change while frozen).<br>6. Release `FreezeRequest`; confirm `UnfreezeDone` asserts within `tVDMF` and the registers begin updating again (a subsequent read differs from the frozen snapshot under live conditions).<br>7. Confirm `FreezeRequest` is left cleared at the end. | The module honors the host-controlled PM interval per Section 8.19.6: `FreezeDone`/`UnfreezeDone` assert within `tVDMF`, statistics reporting registers are stable while frozen and resume updating after unfreeze, and no error/I2C issues occur. A complete freeze→read→unfreeze cycle behaves as specified. |

### Error Handling Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | PM on non-PM-capable transceiver | 1. Identify ports whose transceiver lacks `pm_supported` (CMIS modules without PM, or non-CMIS modules). If none exist, skip.<br>2. Run `show interfaces transceiver pm <port>` for each.<br>3. Verify the command returns an appropriate "not supported"/empty message without crashing or hanging, and no `TRANSCEIVER_PM` entry is populated. | Non-PM-capable ports produce a graceful "not supported" or empty result for `show interfaces transceiver pm` with no crash, hang, or I2C error, and no `TRANSCEIVER_PM` STATE_DB entry. |
| 2 | PM on port without transceiver | 1. Query all physical ports from CONFIG_DB PORT table and subtract ports in `port_attributes_dict` to find empty ports. If none, skip.<br>2. Run `show interfaces transceiver pm <port>` for each empty port.<br>3. Verify each command returns an appropriate error or "not present" message without crashing or hanging, and no core files are generated. | Empty ports yield a graceful error/"not present" message for `show interfaces transceiver pm` with no crash, hang, I2C error, or core file. |

## Cleanup and Post-Test Verification

The following steps are performed once after **all test cases** in this plan have completed. The [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) already cover ongoing health monitoring throughout the run.

### State Restoration

1. **Freeze state**: Confirm the `FreezeRequest` bit (Page 2Fh byte 144 bit 7) is cleared on all ports so modules resume normal real-time statistics reporting. If any port remains frozen (e.g. due to a failure in Advanced TC 4), clear the bit and confirm `UnfreezeDone`.
2. **PM polling interval**: Restore the original `pm_poll_interval` recorded during session setup for any port modified by Advanced TC 1 (`config interface transceiver pm-poll-interval <port> <original>`); verify CONFIG_DB reflects the restored value.
3. **Interface state**: Confirm all ports under test are operationally up. If any port remains shut down (e.g. due to a failure in the polling-period or responsiveness tests), issue `config interface startup <port>`.
4. **Restoration verification**: Verify `last_update_time` in `TRANSCEIVER_PM` is within `pm_data_max_age_min` minutes of current time for all PM-capable ports (confirms PM collection resumed), and LLDP neighbors are discovered (if LLDP is enabled) to confirm end-to-end connectivity.

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case and PM metric.
2. **Metric Analysis**: Document any PM metrics that approached or exceeded their operational-range limits, or showed unusual variation, during the test run.
3. **Range Validation**: Summarize all PM metrics with their actual vs. expected operational ranges and min/avg/max samples.
4. **Freeze/Unfreeze Timing**: If the freeze/unfreeze tests were executed, include the observed `FreezeDone`/`UnfreezeDone` latencies against `tVDMF` (`vdm_freeze_unfreeze_timeout_sec`) for cross-release comparison.
