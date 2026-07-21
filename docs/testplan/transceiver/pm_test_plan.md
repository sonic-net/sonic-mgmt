# Performance Monitoring (PM) Test Plan For Transceivers

## Overview

The Performance Monitoring (PM) Test Plan for transceivers outlines a comprehensive testing strategy for the Performance Monitoring functionality of CMIS / C-CMIS based transceiver modules. PM exposes statistical (minimum, maximum, and average) samples of basic optical and signal-integrity observables collected by the module over a Performance Monitoring Interval, published by `xcvrd` into the `TRANSCEIVER_PM` table in STATE_DB and surfaced through the `show interfaces transceiver pm` CLI.

This document covers the objectives, scope, attributes, test cases, and validation procedures required to validate PM data integrity, PM polling-period configuration, and the coherent (C-CMIS, Page 35h) and grey (CMIS VDM) metric sets.

**References:**

- [OIF-CMIS-05.2](https://www.oiforum.com/wp-content/uploads/OIF-CMIS-05.2.pdf) — Common Management Interface Specification (VDM Observable Types, Table 8-153)
- [OIF-C-CMIS-01.4](https://www.oiforum.com/wp-content/uploads/OIF-C-CMIS-01.4.pdf) — Coherent CMIS (Page 35h Media Lane Link Performance Monitoring, Table 15)

## Scope

The scope of this test plan includes the following:

- Validation of PM data availability, freshness, and field completeness in the `TRANSCEIVER_PM` table and via `show interfaces transceiver pm`
- Validation of the statistical relationship (`min <= avg <= max`) and operational-range bounds for every reported PM metric
- Validation of the coherent C-CMIS Page 35h media-lane metric set for ZR / coherent optics (CD, DGD, SOPMD, PDL, OSNR, eSNR, CFO, EVM, SOPROC, Tx/Rx power, Pre-FEC BER, FERC)
- Validation of the grey-optic CMIS VDM statistic metric set (Pre-FEC BER and FERC min/avg/max)
- Validation of PM polling-period configuration and PM recovery across link-state-change events

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
| pm_poll_interval_sec | integer | 900 | O | platform | Default `xcvrd` PM polling/collection interval in seconds (900 seconds / 15 minutes), i.e. the cadence at which the module's statistics are read and a new PM interval is started |
| pm_poll_interval_to_test_sec | integer | 60 | O | platform or transceivers | PM polling interval (in seconds) to configure and validate via the polling-period configuration test (default 60 seconds / 1 minute) |
| pm_recovery_margin_sec | integer | 30 | O | platform | Additional grace period in seconds, added on top of the configured polling interval, allowed for PM data to resume updating after a link-state-change event |
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

# Configure the PM polling interval (seconds) for a port
config interface -n '<namespace>' transceiver pm-poll-interval <port> <seconds>

# Verify configured PM polling interval
sonic-db-cli -n '<namespace>' CONFIG_DB hget "PORT|<port>" "pm_poll_interval"

# Link-state-change events used by the recovery tests
sudo config interface -n '<namespace>' shutdown <port>
sudo config interface -n '<namespace>' startup  <port>
```

> **Note:** The `pm-poll-interval` configuration knob and its `CONFIG_DB` `pm_poll_interval` field model the host-controlled PM collection cadence. If a given image/platform does not expose this knob, the polling-period test case (TC 4) is skipped gracefully and the dependent recovery checks fall back to the default `pm_poll_interval_sec`.

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

1. **Interface liveness**: Verify all ports under test are operationally up with no recent link flaps. Checked per test because TC 4–5 are disruptive and may affect link state.
2. **PM data freshness**: Query `TRANSCEIVER_PM` in STATE_DB and verify `last_update_time` is within `pm_data_max_age_min` minutes of current time.

#### Per-Test Teardown (after each test case)

1. **PM data freshness**: Re-verify `last_update_time` in `TRANSCEIVER_PM` is within `pm_data_max_age_min` minutes of current time for all ports under test.

### PM Functionality Tests

> **Note:** TC 4–5 extend the basic checks with advanced PM behaviors. Each test case's steps include the TC-specific baselines it needs (configured polling interval, link flap counts, baseline PM snapshot). Failure-path recovery (restoring the polling interval, restoring shutdown interfaces) is handled by the session-level [Cleanup](#cleanup-and-post-test-verification). Presence/completeness and value validation of the coherent (Page 35h) and grey (CMIS VDM) metric sets are covered by TC 1 and TC 3; the responsiveness check (TC 5) applies to all PM-capable optics, observing the metrics expected to react to an optical change for each optic class.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | PM data availability verification | 1. For each port with `pm_supported` = true, access PM data from the `TRANSCEIVER_PM` table in STATE_DB.<br>2. Verify `last_update_time` is within `pm_data_max_age_min` minutes of current time to ensure data freshness.<br>3. Determine the expected metric set using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm) (full coherent set for `zr_optics` = true, grey set otherwise).<br>4. Validate presence of all `<metric>_avg`, `<metric>_min`, `<metric>_max` fields for the expected metric set.<br>5. Skip metrics that do not apply to the port's optic class. | All expected PM fields are present and accessible from STATE_DB without errors. Coherent media-lane metrics are validated only for ZR optics; grey optics validate `prefec_ber` and `uncorr_frames`. Data freshness is confirmed with a recent `last_update_time`. |
| 2 | PM CLI verification | 1. Run `show interfaces transceiver pm <port>` for each PM-capable port.<br>2. Parse the CLI output and confirm every expected metric (min/avg/max columns) for the optic class is populated with a numeric value (no blank/`N/A` for supported metrics).<br>3. Cross-check a sample of CLI values against the corresponding `TRANSCEIVER_PM` STATE_DB fields. | The CLI output is rendered without error and reports populated min/avg/max values for all expected metrics. CLI values are consistent with the STATE_DB `TRANSCEIVER_PM` fields, confirming the CLI correctly reflects redis-db content. |
| 3 | PM value validation and consistency (ordering, range, FEC health, freshness) | 1. Read PM data `pm_consistency_check_poll_count` times, waiting at least one `pm_poll_interval_sec` between reads; confirm `last_update_time` is fresh (within `pm_data_max_age_min`) and advances each cycle.<br>2. Determine the expected metric set via the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm) (full coherent set for `zr_optics` = true; `prefec_ber`/`uncorr_frames` for grey optics).<br>3. For each reading verify ordering `<metric>_min <= <metric>_avg <= <metric>_max`, and where a `<metric>_operational_range` is configured, that all three samples fall within `[range.min, range.max]`.<br>4. Verify FEC health: all `prefec_ber` samples within `[0, 1e-4]` and all `uncorr_frames` (FERC) samples exactly `0`.<br>5. Confirm values vary within physically reasonable limits across cycles (no erratic/impossible jumps); aggregate and report all violations per port and metric. | PM data is fresh and refreshes each cycle. Every metric satisfies `min <= avg <= max`, ranged metrics stay within their operational range, Pre-FEC BER is within `[0, 1e-4]`, and FERC is `0`. Values remain internally consistent across `pm_consistency_check_poll_count` cycles with no erratic changes; any violation is logged per port and metric. |
| 4 | PM polling-period configuration | 1. Verify the port is operationally up and record the current `pm_poll_interval` so it can be restored.<br>2. Configure the PM polling interval to `pm_poll_interval_to_test_sec` (default 60 seconds / 1 minute): `config interface transceiver pm-poll-interval <port> <pm_poll_interval_to_test_sec>`; verify `CONFIG_DB PORT\|<port> pm_poll_interval` = `<pm_poll_interval_to_test_sec>`.<br>3. Confirm PM data updates at the configured cadence: observe `last_update_time` advancing approximately every `pm_poll_interval_to_test_sec` seconds across at least two cycles.<br>4. Restore the original `pm_poll_interval` and verify CONFIG_DB reflects the restored value. | The PM polling interval is configurable to `pm_poll_interval_to_test_sec` (1 minute by default) and reflected in CONFIG_DB, PM data updates at the configured cadence, and the original interval is restored at the end. |
| 5 | PM metric responsiveness and recovery on link/optical change | 1. For each PM-capable port, determine the expected metric set via the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm) and identify the metrics expected to react to an optical-power change. Record the baseline of those metrics, the current link flap count, and verify freshness.<br>2. Induce a known, recoverable link/optical change: locally toggle the port (`config interface shutdown <port>` then `config interface startup <port>`), or induce a remote-side optical perturbation if the topology allows it.<br>3. Confirm the affected metrics reflected the change during the event.<br>4. After the link returns to oper-up and a wait of `pm_poll_interval_sec` + `pm_recovery_margin_sec`, verify PM collection resumed: `last_update_time` is within `pm_data_max_age_min` of current time and continues to advance, all expected metrics are repopulated and satisfy `min <= avg <= max` and (where configured) operational-range bounds, and the reactive metrics recovered to within their operational ranges.<br>5. Confirm the link flap count increased by exactly the expected amount from the deliberate toggle and is otherwise stable. | The reactive PM metrics track the induced change for the port's optic class (e.g. coherent Rx power/OSNR/eSNR drop and Pre-FEC BER rises; grey Pre-FEC BER rises). After the link is restored, PM collection resumes within `pm_poll_interval_sec` + `pm_recovery_margin_sec` with all metrics repopulated, consistent, and back within their operational ranges, and no unexpected link flaps occur. The test is skipped gracefully when a safe perturbation is not possible. |

## Cleanup and Post-Test Verification

The following steps are performed once after **all test cases** in this plan have completed. The [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) already cover ongoing health monitoring throughout the run.

### State Restoration

1. **PM polling interval**: Restore the original `pm_poll_interval` recorded during session setup for any port modified by TC 4 (`config interface transceiver pm-poll-interval <port> <original>`); verify CONFIG_DB reflects the restored value.
2. **Interface state**: Confirm all ports under test are operationally up. If any port remains shut down (e.g. due to a failure in the polling-period or responsiveness tests), issue `config interface startup <port>`.
3. **Restoration verification**: Verify `last_update_time` in `TRANSCEIVER_PM` is within `pm_data_max_age_min` minutes of current time for all PM-capable ports (confirms PM collection resumed), and LLDP neighbors are discovered (if LLDP is enabled) to confirm end-to-end connectivity.

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case and PM metric.
2. **Metric Analysis**: Document any PM metrics that approached or exceeded their operational-range limits, or showed unusual variation, during the test run.
3. **Range Validation**: Summarize all PM metrics with their actual vs. expected operational ranges and min/avg/max samples.
