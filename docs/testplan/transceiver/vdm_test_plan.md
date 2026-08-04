# VDM Test Plan For Transceivers

## Overview

The VDM Test Plan for transceivers outlines a comprehensive testing strategy for the Versatile Diagnostics Monitoring (VDM) functionality within the transceiver module. This document will cover the objectives, scope, test cases, and resources required for effective testing.

## Scope

The scope of this test plan includes the following:

- Validation of VDM data integrity and consistency for transceiver basic VDM content
- Testing of VDM access and performance

## Optics Scope

All the optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

## Pre-requisites

Before executing the VDM tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-prerequisites-and-configuration-files) must be met
- `vdm.json` is defined with all the required attributes applicable to the transceiver (see [Attributes](#attributes) for the shard layout)
- DOM polling is enabled in CONFIG_DB for all relevant ports under test (verified once at session start — see [Common Test Setup and Teardown](#common-test-setup-and-teardown)); there is no separate VDM polling knob — VDM data collection runs inside the same xcvrd polling task as DOM and is gated by the same `dom_polling` control (`config interface transceiver dom <port> enable`/`disable`).

System health (running daemons, fresh logs) and transceiver baseline (presence, link-up) are covered by the parent's [Common Session-Level Prerequisites](test_plan.md#common-session-level-prerequisites) and [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks); see the prerequisite matrix there for which gates VDM consumes.

## Attributes

A `vdm.json` file is used to define the attributes for the VDM tests for the various types of transceivers the system supports. The category is defined at per Part Number level under `attributes/vdm/`; see [File Organization](test_plan.md#file-organization) for the shard contract and [Loader Validation](test_plan.md#loader-validation) for how it is enforced.

**Note on Operational Ranges:** Every VDM attribute is expressed as a realistic operational range, `{"min": <float>, "max": <float>}` — the same model DOM uses.

**Note on unsupported observables:** If a module does not advertise a given VDM observable — or advertises it on only one side (e.g. some modules report `esnr_media_input` but not `esnr_host_input`) — omit the corresponding `_operational_range` attribute for that PN so presence/range checks do not run against a field the module never publishes.

The following table summarizes the attributes common to all CMIS-capable optics (grey and coherent/ZR). This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional. Mandatoriness for a given field on a given part number is the responsibility of whoever authors that `vdm.json` shard — grey and coherent/ZR optics advertise different observable sets, and no field here is universally advertised across all optics tested. If an author declares a field the optic doesn't actually advertise, the corresponding test failing is correct behavior: it surfaces an authoring error, not a false negative.

**Default Value** is `-` for every attribute below: unlike DOM's realistic operational ranges (broadly similar across most transceivers — e.g. temperature, voltage), these VDM values (signal quality, error rates, coherent DSP internals) are inherently part/vendor/reach-specific with no value that applies broadly — each must be authored per part number in `vdm.json`.

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|----------------|-----------|-----------------|-------------|
| laser_temperature_mediaLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational laser temperature range in Celsius, media side, lane LANE_NUM |
| esnr_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational eSNR range in dB, media input, lane LANE_NUM |
| esnr_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational eSNR range in dB, host input, lane LANE_NUM |
| pam4_level_transition_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational PAM4 Level Transition Parameter range in dB, media input, lane LANE_NUM. Not applicable to coherent/ZR optics (line side uses QAM, not PAM4). |
| pam4_level_transition_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational PAM4 Level Transition Parameter range in dB, host input, lane LANE_NUM |
| prefec_ber_curr_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (instantaneous) range, media input, lane LANE_NUM |
| prefec_ber_avg_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (statistic average) range, media input, lane LANE_NUM |
| prefec_ber_min_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (statistic minimum) range, media input, lane LANE_NUM |
| prefec_ber_max_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (statistic maximum) range, media input, lane LANE_NUM |
| prefec_ber_curr_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (instantaneous) range, host input, lane LANE_NUM |
| prefec_ber_avg_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (statistic average) range, host input, lane LANE_NUM |
| prefec_ber_min_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (statistic minimum) range, host input, lane LANE_NUM |
| prefec_ber_max_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational Pre-FEC BER (statistic maximum) range, host input, lane LANE_NUM |
| errored_frames_curr_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (instantaneous) range, media input, lane LANE_NUM |
| errored_frames_avg_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (statistic average) range, media input, lane LANE_NUM |
| errored_frames_min_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (statistic minimum) range, media input, lane LANE_NUM |
| errored_frames_max_media_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (statistic maximum) range, media input, lane LANE_NUM |
| errored_frames_curr_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (instantaneous) range, host input, lane LANE_NUM |
| errored_frames_avg_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (statistic average) range, host input, lane LANE_NUM |
| errored_frames_min_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (statistic minimum) range, host input, lane LANE_NUM |
| errored_frames_max_host_inputLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Realistic operational errored-frames (statistic maximum) range, host input, lane LANE_NUM |
| data_max_age_min | integer | 5 | O | platform | Maximum age (in minutes) of VDM data to be considered fresh; older data fails freshness checks |
| consistency_check_poll_count | integer | 3 | O | transceivers or platform | Number of successive polling cycles used in consistency checks |
| max_update_time_sec | integer | 60 | O | platform | Maximum expected interval (in seconds) between consecutive VDM data updates; also the wait duration between polling cycles in consistency checks |
| recovery_time_sec | integer | No universal default — recommend ≥ 2× `max_update_time_sec` so at least one full polling cycle completes after recovery | O | platform | Time (in seconds) to wait after restoring normal operating conditions before re-validating values |

The following table summarizes Data Path Monitors — additional observables specific to coherent/ZR (DCO) optics; grey optics do not report these, with the exception of `txcurrpower`/`rxtotpower`/`rxsigpower`, which are also available on grey optics (typically also reported via DOM). Unless noted otherwise, these monitors are associated with a data path; the lane identifier indicates the first lane of the relevant data path.

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|----------------|-----------|-----------------|-------------|
| biasxiLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Modulator bias X/I in percentage, lane LANE_NUM (coherent/ZR only) |
| biasxqLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Modulator bias X/Q in percentage, lane LANE_NUM (coherent/ZR only) |
| biasxpLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Modulator bias X_Phase in percentage, lane LANE_NUM (coherent/ZR only) |
| biasyiLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Modulator bias Y/I in percentage, lane LANE_NUM (coherent/ZR only) |
| biasyqLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Modulator bias Y/Q in percentage, lane LANE_NUM (coherent/ZR only) |
| biasypLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Modulator bias Y_Phase in percentage, lane LANE_NUM (coherent/ZR only) |
| cdshortLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Chromatic dispersion, high granularity, short link, in ps/nm, lane LANE_NUM |
| cdlongLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Chromatic dispersion, low granularity, long link, in ps/nm, lane LANE_NUM |
| dgdLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Differential group delay in ps, lane LANE_NUM |
| sopmdLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Second-order polarization mode dispersion in ps^2, lane LANE_NUM |
| soprocLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | State-of-polarization rate of change in krad/s, lane LANE_NUM |
| pdlLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Polarization-dependent loss in dB, lane LANE_NUM |
| osnrLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Optical SNR in dB, lane LANE_NUM |
| esnrLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Combined eSNR in dB, lane LANE_NUM (coherent-specific; distinct from the per-side `esnr_media_input`/`esnr_host_input` in the common table above) |
| cfoLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Carrier frequency offset in MHz, lane LANE_NUM |
| txcurrpowerLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Tx current output power in dBm, lane LANE_NUM. Also available on grey optics (typically also reported via DOM). |
| rxtotpowerLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Rx total power in dBm, lane LANE_NUM. Also available on grey optics (typically also reported via DOM). |
| rxsigpowerLANE_NUM_operational_range | dict `{"min": <float>, "max": <float>}` | - | O | transceivers | Rx signal power in dBm, lane LANE_NUM |

## Example `vdm` Category Shards

The following example demonstrates `_operational_range` attributes for different transceivers across the sharded `vdm` category. Each PN lives in its own file under its vendor directory. Numeric ranges below are illustrative only — as with DOM, derive real values per part number from the module's datasheet or observed steady-state VDM readings.

**`attributes/vdm/transceivers/vendors/FINISAR/part_numbers/FTLX8571D3BCL-10GSFP/vdm.json`:**

```json
{
  "laser_temperature_media1_operational_range": {"min": 20.0, "max": 70.0},
  "prefec_ber_avg_media_input1_operational_range": {"min": 0.0, "max": 1.0e-4}
}
```

## Dynamic Field Mapping Algorithm

The VDM test framework uses an attribute-driven approach to dynamically determine which fields to validate based on the configuration present in `vdm.json`. This eliminates the need for hardcoded field lists and provides flexible, maintainable test execution.

### Algorithm Steps

1. **Attribute Discovery**: Scan `vdm.json` for all attributes ending with `_operational_range`

2. **Base Field Extraction**: Remove the `_operational_range` suffix to get the base field name

3. **Lane Expansion Logic**: Every VDM attribute in this plan is lane- (or data-path-) indexed via the `LANE_NUM` placeholder — unlike DOM, there is no whole-module VDM field. Expand `LANE_NUM` for all available lanes (1 to N) by replacing it with each actual lane number. For Data Path Monitors, "lane" refers to the first lane of the data path.

4. **Special Field Mappings**: Apply any platform-specific field name mappings as needed

5. **Field Validation**: Validate presence and operational-range compliance in `TRANSCEIVER_VDM_REAL_VALUE` for all derived fields

### Example Mappings

| Attribute Name | Base Field | Lane Expansion | Expected STATE_DB Fields |
|----------------|------------|-----------------|--------------------------|
| `esnr_media_inputLANE_NUM_operational_range` | `esnr_media_inputLANE_NUM` | Yes | `esnr_media_input1`..`esnr_media_inputN` |
| `prefec_ber_avg_media_inputLANE_NUM_operational_range` | `prefec_ber_avg_media_inputLANE_NUM` | Yes | `prefec_ber_avg_media_input1`..`prefec_ber_avg_media_inputN` |
| `errored_frames_curr_host_inputLANE_NUM_operational_range` | `errored_frames_curr_host_inputLANE_NUM` | Yes | `errored_frames_curr_host_input1`..`errored_frames_curr_host_inputN` |
| `osnrLANE_NUM_operational_range` | `osnrLANE_NUM` | Yes | `osnr1`..`osnrN` |

During threshold validation, one must verify that the number of active media lanes/datapaths
and only validate against those, as in SONiC not applicable/supported lanes are
nonetheless populated with sentinel values which may flag a failure incorrectly.

## Threshold Validation

xcvrd publishes vendor-configured alarm/warning thresholds — for any field with a configured `_operational_range` attribute (per the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) — into four STATE_DB tables, one per severity level:

`TRANSCEIVER_VDM_LALARM_THRESHOLD`, `TRANSCEIVER_VDM_LWARN_THRESHOLD`, `TRANSCEIVER_VDM_HWARN_THRESHOLD`, `TRANSCEIVER_VDM_HALARM_THRESHOLD`

For every such field, the correct ordering is `LALARM < LWARN < HWARN < HALARM`. Any test case below that reads, records a baseline from, or verifies thresholds does so against this table set and this invariant, and references this section rather than restating it.

## Flag Validation

xcvrd publishes a high/low alarm/warning flag for any field with a configured `_operational_range` attribute (per the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) into four STATE_DB tables, one per severity level:

`TRANSCEIVER_VDM_LALARM_FLAG`, `TRANSCEIVER_VDM_LWARN_FLAG`, `TRANSCEIVER_VDM_HWARN_FLAG`, `TRANSCEIVER_VDM_HALARM_FLAG`

Each flag table has three corresponding metadata tables — `*_FLAG_CHANGE_COUNT`, `*_FLAG_SET_TIME`, `*_FLAG_CLEAR_TIME` (e.g. `TRANSCEIVER_VDM_LALARM_FLAG_CHANGE_COUNT`) — tracking how many times the flag has changed state, when it was last set, and when it was last cleared.

Flags are **clear-on-read (COR)**: after a read, the table re-reflects the current live state on the next poll rather than latching the read-away value.

**Flag-metadata tables reset on `xcvrd` restart / reboot / module re-seat.** The `*_FLAG_CHANGE_COUNT`, `*_FLAG_SET_TIME`, and `*_FLAG_CLEAR_TIME` tables are deleted by `xcvrd` on stop and recreated from the *current* flag status on restart (counts reset to `0`, times to `never`) — likewise across cold/warm reboot and transceiver removal/insertion. A verifier must not assert these metadata values persist across such an event; asserting persistence would be a guaranteed false failure.

Any test case below that reads, records a baseline from, or verifies flags does so against this table set and these semantics, and references this section rather than restating it.

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework. This section provides comprehensive examples of all relevant commands

## Test Cases


- All the tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

### Common Test Setup and Teardown

Inherits the [Common Session-Level Prerequisites](test_plan.md#common-session-level-prerequisites) and [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) from the parent framework. VDM tests add the following category-specific checks:

#### Session-Level Setup (once per test run)

1. **DOM/VDM polling state**: Confirm DOM polling is enabled for all ports under test.

#### Per-Test Setup (before each test case)

1. **Interface liveness**: Verify all ports under test are operationally up with no recent link flaps. Checked per test because Advanced tests are disruptive and may affect link state.
2. **Data freshness**: Query `TRANSCEIVER_VDM_REAL_VALUE` in STATE_DB and verify `last_update_time` is within `data_max_age_min` minutes of current time.

#### Per-Test Teardown (after each test case)

1. **Data freshness**: Re-verify `last_update_time` in `TRANSCEIVER_VDM_REAL_VALUE` is within `data_max_age_min` minutes of current time for all ports under test.

### Basic VDM Functionality Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | VDM data availability verification | 1. Access VDM data from `TRANSCEIVER_VDM_REAL_VALUE` table in STATE_DB for each port.<br>2. Verify `last_update_time` is within `data_max_age_min` minutes of current time to ensure data freshness.<br>3. Dynamically determine expected VDM fields based on attributes present in `vdm.json` using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>4. Validate presence of all dynamically determined expected fields in STATE_DB.<br>5. Skip validation for fields whose corresponding attributes are absent from `vdm.json`. | All VDM fields corresponding to configured attributes are present and accessible from STATE_DB. VDM data is successfully retrieved without errors for all attribute-driven fields. Lane-specific fields are automatically expanded for all available lanes (1 to N) based on the `LANE_NUM` placeholder. Field expectations are dynamically derived using the mapping algorithm. Data freshness is confirmed with recent `last_update_time` timestamp. |
| 2 | VDM sensor operational range validation | 1. Retrieve VDM data from STATE_DB.<br>2. Verify `last_update_time` is within `data_max_age_min` minutes of current time to ensure data freshness.<br>3. For each attribute ending with `_operational_range` present in `vdm.json`, validate the corresponding field(s) in STATE_DB using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>4. Check that sensor values fall within the configured operational range (`min <= live <= max`).<br>5. Fail the test case if any values fall outside their respective operational ranges.<br>6. Log detailed information about any out-of-range values including actual vs expected ranges.<br>7. Only validate fields derived from attributes present in `vdm.json`. | All VDM sensor values fall within their respective operational ranges during normal operation (only for parameters with configured operational range attributes). Test case fails if any values fall outside their configured operational ranges. Data freshness is confirmed before validation. Lane-specific validation is automatically performed for all available lanes using the `LANE_NUM` placeholder expansion. Detailed logging is provided for any out-of-range conditions. |
| 3 | VDM alarm/warning threshold hierarchy validation | 1. Retrieve threshold data per [Threshold Validation](#threshold-validation).<br>2. Dynamically determine expected threshold fields based on attributes ending with `_operational_range` present in `vdm.json` using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>3. For each determined field, verify the hierarchy from [Threshold Validation](#threshold-validation).<br>4. Only validate fields derived from attributes present in `vdm.json`. | All four threshold tables are present in STATE_DB for the configured fields and follow the hierarchy in [Threshold Validation](#threshold-validation). Threshold data integrity is maintained in STATE_DB. Threshold validation is dynamically determined from the attribute table. |
| 4 | VDM data consistency verification | 1. Read VDM data `consistency_check_poll_count` times with `max_update_time_sec` intervals between readings.<br>2. Verify data consistency between readings.<br>3. Check that `last_update_time` field is being updated correctly with each polling cycle.<br>4. Validate that VDM readings show expected behavior (e.g., eSNR/Pre-FEC BER variations within reasonable limits). | VDM data shows consistent and reasonable variations between polling intervals over `consistency_check_poll_count` polling cycles. The `last_update_time` field is properly updated with each polling cycle. No erratic or impossible sensor value changes are observed during the monitoring period. Variation patterns indicate stable VDM monitoring system operation. |
| 5 | VDM statistic freeze/unfreeze coherence (capability-gated) | 1. For each port, check whether its `vdm.json` entry has any `_min`/`_max`/`_avg`-suffixed `_operational_range` attribute configured, and whether the port is in LPMODE. This is a config-driven proxy for xcvrd's real `is_vdm_statistic_supported()` gate (an internal platform-API capability call not directly exposed to sonic-mgmt tests). If either condition means the port has no statistic observables to validate, call `pytest.skip(...)` for that port with an explicit reason (e.g., "no min/max/avg attributes configured in vdm.json" or "port in LPMODE") so the skip is reported per-port rather than silently omitted, making any systematic coverage gap (e.g., all grey-optics ports skipped) visible in the test report.<br>2. Disable DOM polling for the port (`config interface transceiver dom <port> disable`). Since VDM has no independent polling knob (see [Pre-requisites](#pre-requisites)), this also halts xcvrd's own VDM freeze/unfreeze cycle for the port, so the test can drive freeze/unfreeze directly via the platform API without racing the daemon. Wait one DOM poll interval plus ~1 second for quiescence.<br>3. Invoke the platform API to freeze VDM statistics (`freeze_vdm_stats`); verify the freeze-done indication (`VDM_FREEZE_DONE`) asserts within its timing budget (~10 ms, up to 1 s).<br>4. While frozen, read the configured `_min`/`_max`/`_avg` fields (per the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) twice with a short interval between reads; verify all values are unchanged (latched) across both reads. Where a field's `_min`, `_avg`, and `_max` variants are all configured, also verify `min <= avg <= max` coherence. Note: the corresponding `_curr` (instantaneous) fields are basic, not statistic, observables — they are not frozen and continue updating normally during this window.<br>5. Invoke the platform API to unfreeze VDM statistics (`unfreeze_vdm_stats`); verify the unfreeze-done indication (`VDM_UNFREEZE_DONE`) asserts within its timing budget.<br>6. Wait at least one `max_update_time_sec` interval, then re-read the configured `_min`/`_max`/`_avg` values and verify they have resumed updating.<br>7. **Teardown (failure-path safe — runs even if a prior step failed):** unconditionally attempt unfreeze first (in case a step failed mid-frozen), then re-enable DOM polling (`config interface transceiver dom <port> enable`), and verify `TRANSCEIVER_VDM_REAL_VALUE` updates resume (`last_update_time` refreshes within `data_max_age_min`). | Freeze completes within its timing budget and latches all configured `_min`/`_max`/`_avg` values — no changes are observed across repeated reads while frozen, and min/avg/max coherence holds where all three are configured; `_curr` fields continue updating unaffected. Unfreeze completes within its timing budget and statistic values resume updating afterward. DOM/VDM polling is fully restored in teardown regardless of test outcome, with STATE_DB updates confirmed to resume. Ports whose `vdm.json` entry has no min/max/avg attributes configured, or that are in LPMODE, are skipped with an explicit per-port reason reported in the test results. (A raw-register freeze-handshake test against a mocked EEPROM belongs in the platform-daemons unit tests, not here — this test stays at the platform-API/STATE_DB level.) |

### Advanced VDM Testing

> **Note:** Each test case's steps include the TC-specific baselines it needs (e.g., threshold values, flag metadata). Failure-path recovery (restoring shutdown interfaces, re-enabling DOM polling, reverting environmental stress) is handled by the session-level [Cleanup](#cleanup-and-post-test-verification).

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | VDM data persistence during interface state changes | 1. Record baseline VDM data from `TRANSCEIVER_VDM_REAL_VALUE` table in STATE_DB including all sensor values and `last_update_time`.<br>2. Record baseline link flap count for the port.<br>3. Execute interface shutdown: `config interface shutdown <port>`.<br>4. Wait for interface to reach down state (verify with `show interfaces status`).<br>5. Read VDM data from `TRANSCEIVER_VDM_REAL_VALUE` table while interface is down.<br>6. Verify `last_update_time` continues to be updated during shutdown state.<br>7. Validate that VDM sensor values remain accessible and within expected ranges during shutdown.<br>8. Execute interface startup: `config interface startup <port>`.<br>9. Wait for interface to reach up state and link to establish (verify with `show interfaces status`).<br>10. Read VDM data from `TRANSCEIVER_VDM_REAL_VALUE` table after interface comes up.<br>11. Perform consistency check by reading VDM data `consistency_check_poll_count` times with `max_update_time_sec` intervals.<br>12. Validate all dynamically determined VDM fields (per [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) are present and updated.<br>13. Verify sensor values return to operational ranges after link establishment.<br>14. Compare final link flap count to baseline to confirm exactly 2 flaps occurred (1 down, 1 up). | VDM monitoring continues during interface shutdown with data updates and accessibility maintained. VDM data remains consistent and fresh throughout the shutdown period without data corruption. Interface state transitions do not disrupt VDM data collection or cause service crashes. After interface startup, all sensor values stabilize within operational ranges. Link flap count increases by exactly 2 confirming controlled interface state changes. Critical processes (`xcvrd`, `pmon`, `syncd`) remain stable throughout with no crashes or restarts. |
| 2 | VDM threshold violation detection and recovery | 1. Read baseline VDM data and verify all sensor values are within their configured operational ranges.<br>2. Record baseline threshold values per [Threshold Validation](#threshold-validation).<br>3. Gradually stress the optical path to approach warning thresholds (e.g., insert attenuation to reduce received optical power, or use a thermal chamber to shift module temperature) — this degrades link-quality metrics like Pre-FEC BER/eSNR in a physically realistic way, unlike traffic-load changes which do not affect optical impairments.<br>4. Monitor VDM sensor values at `max_update_time_sec` intervals using `TRANSCEIVER_VDM_REAL_VALUE` table.<br>5. Verify that sensor values approaching or exceeding thresholds are accurately reported and `last_update_time` is continuously updated.<br>6. Check system logs for threshold violation warnings.<br>7. Restore normal operating conditions.<br>8. Wait for `recovery_time_sec` to allow sensors to stabilize.<br>9. Verify all VDM sensor values return within their configured operational ranges.<br>10. Perform consistency check by reading VDM data `consistency_check_poll_count` times.<br>11. Verify interface remained operationally up throughout and link flap count is unchanged.<br>12. Confirm no critical process crashes occurred during the stress and recovery period. | VDM monitoring accurately detects and reports sensor values approaching or exceeding thresholds with continuous data freshness. System logs capture threshold violations with clear warning messages. VDM data updates remain consistent during environmental stress with no polling interruptions or data corruption. After restoration of normal conditions, all sensor values return within thresholds within `recovery_time_sec`. Interface stability is maintained throughout with no link flaps. Critical processes (`xcvrd`, `pmon`, `syncd`, `swss`) remain stable with no crashes during stress and recovery. |
| 3 | VDM flag lifecycle validation (assertion, clearing, and flag metadata) | 1. Determine the fields for which the port has a configured `_operational_range` attribute (per the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) — any such field may have module-reported flags. If none are configured for the port, call `pytest.skip(...)` with an explicit reason so the gap is visible in the test report rather than silently omitted.<br>2. Record baseline flag state and flag metadata per [Flag Validation](#flag-validation) for the ports under test.<br>3. Execute interface shutdown: `config interface shutdown <port>`. Pre-FEC BER/errored-frames degrade sharply on link-down, which is expected to assert the corresponding warn/alarm flag(s) without needing environmental stress.<br>4. After the flag asserts, verify from STATE_DB: the corresponding flag is set; flag change count increments vs baseline; last set time is updated to reflect the shutdown event; last clear time remains unchanged from baseline.<br>5. Execute interface startup: `config interface startup <port>` and wait for link recovery.<br>6. After recovery, verify: the flag clears; flag change count increments again; last clear time is updated to reflect the recovery event.<br>7. (Optional) Confirm the COR semantics from [Flag Validation](#flag-validation): after reading a flag, verify the flag table re-reflects the current live state on the next poll.<br>8. **Teardown (failure-path safe — runs even if a prior step failed):** ensure the port is returned to `startup`, and verify VDM flags and flag metadata are back to a steady, non-alarming state. | The corresponding flag (per [Flag Validation](#flag-validation)) asserts on link-down with change count incremented and last set time updated, while last clear time stays unchanged from baseline. On recovery, the flag clears with change count incremented again and last clear time updated. Flag behavior is COR-consistent across polls. The port is confirmed `startup` and its VDM flags/metadata are back to steady state after the test, including on failure. Ports with no `_operational_range` attributes configured are skipped with an explicit reason reported in the test results. This test is complementary to (and non-overlapping with) [Basic TC5](#basic-vdm-functionality-tests): TC5 validates snapshot coherence (freeze/unfreeze); this validates threshold-crossing lifecycle. |

### Scenario Coverage Test Cases

These validate that VDM data recovers correctly across disruptive operations, following the shared
[Scenario Coverage Test-Case Template](scenario_test_template.md). The reusable verifier
`verify_vdm_recovered(duthost, ports=None, baseline=None)` — for every port under test — confirms VDM
data is present in `TRANSCEIVER_VDM_REAL_VALUE`, that `last_update_time` is fresh (within
`data_max_age_min`), that every attribute configured with an `_operational_range` in `vdm.json` falls
within range (per the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)), and that
thresholds are present and correctly ordered (per [Threshold Validation](#threshold-validation)). The VDM plan does not currently define any
`_deviation_range`-style attributes, so `capture_vdm_baseline(duthost)`/`baseline` exist for contract
parity with DOM/EEPROM but are not yet used for a relative check here — a future `_deviation_range`
addition to `vdm.json` would extend `verify_vdm_recovered` to consume it, matching DOM.

VDM is **link-dependent for recovery purposes** (values are expected to return to their configured
ranges once the link is back up), so each recovery scenario runs the
[Standard Port Recovery and Verification Procedure](system_test_plan.md#standard-port-recovery-and-verification-procedure)
before verifying. Shut/no-shut is already covered by
[Advanced TC 1 (VDM data persistence during interface state changes)](#advanced-vdm-testing). Settle
timers reuse the System plan's `*_settle_sec` attributes.

> **Flag metadata resets across these scenarios** (see [Flag Validation](#flag-validation)). Therefore
> `verify_vdm_recovered` intentionally does **not** assert flag-metadata values persist across a
> scenario (S1–S3); asserting persistence would be a guaranteed false failure. Their increment/set/clear
> lifecycle is instead exercised by [Advanced TC 3](#advanced-vdm-testing) (shutdown/startup), where no
> such table reset occurs.

**Applicability:**

Shut/no-shut is already covered by Advanced TC 1 (see above), not by S1 below. All of the following
disruptive operations are covered by S1, substituting the matching helper/settle-timer pair for the
scenario under test:
- Cold/Warm/Fast Reboot (`perform_cold_reboot`/`perform_warm_reboot`/`perform_fast_reboot`; gate on `warm_reboot_supported`/`fast_reboot_supported`)
- Config reload (`perform_config_reload`)
- Docker/Daemon restart (`perform_daemon_restart(duthost, <daemon>)`, iterating xcvrd/pmon/swss/syncd)
- sfputil reset (`perform_sfputil_reset(duthost, <port>, recover_with_port_toggle=True)` — default wraps shutdown → reset → startup, since a bare reset can leave the port oper-down on some modules)
- LPM toggle (`perform_lpm_toggle(duthost, <port>, low_power=True)` — no shut; **the request latches**, so this scenario needs the mandatory teardown in step 5 below, unlike the others)

| TC No. | Test | Steps | Expected Results |
|--------|------|-------|------------------|
| S1 | VDM recovery after a disruptive operation | 1. **Pre-check**: capture the baseline via `capture_vdm_baseline(duthost)` with all ports up, then confirm a clean state with `verify_vdm_recovered(duthost)`.<br>2. **Operate**: invoke the helper matching the scenario under test (see Applicability above) — not a reboot for config reload/daemon restart/LPM toggle, so treat `perform_<op>` as the general shape rather than assuming a reboot.<br>3. **Recover**: for reboot/config-reload/daemon-restart, poll (via `wait_until`) up to the matching `*_settle_sec` for the DUT/daemon to return, then run the [Standard Port Recovery and Verification Procedure](system_test_plan.md#standard-port-recovery-and-verification-procedure) (VDM needs the link up). LPM toggle does not reboot the DUT — instead poll until the next periodic DOM/VDM poll reflects the state change, then recover via `perform_lpm_toggle(duthost, <port>, low_power=False)` and run the Standard Port Recovery and Verification Procedure.<br>4. **Verify**: `verify_vdm_recovered(duthost, baseline=baseline)` — VDM data present and fresh, all configured fields within their operational range, and thresholds restored per [Threshold Validation](#threshold-validation). Aggregate failures and report at the end.<br>5. **Mandatory teardown (LPM toggle only)**: ensure `perform_lpm_toggle(duthost, <port>, low_power=False)` runs even if a prior step failed — the low-power request latches and would otherwise leave the port oper-down for all later tests. | VDM data is re-published and fresh after recovery, all configured attributes are within their operational range, and thresholds are present and correctly ordered per [Threshold Validation](#threshold-validation). For LPM toggle, the port is confirmed back at full power even on failure. |

## Cleanup and Post-Test Verification

The following steps are performed once after **all test cases** in this plan have completed. The [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) already cover ongoing health monitoring throughout the run.

### State Restoration

1. **Interface state**: Confirm all ports under test are operationally up. If any port remains in a shutdown state (e.g., due to test failure in Advanced TC 1 or Advanced TC 3), issue `config interface startup <port>`.
2. **DOM/VDM polling**: Confirm DOM polling is re-enabled for all ports (there is no separate VDM polling knob — see [Pre-requisites](#pre-requisites)). If any port has DOM polling disabled (e.g., due to test failure in Basic TC 5), issue `config interface transceiver dom <port> enable`.
3. **Environmental conditions**: Confirm any environmental stress applied during testing (e.g., Advanced TC 2) has been reverted to normal operating conditions.
4. **Restoration verification**: Verify `last_update_time` in `TRANSCEIVER_VDM_REAL_VALUE` is within `data_max_age_min` minutes of current time for all ports (confirms polling resumed), and LLDP neighbors are discovered (if LLDP is enabled) to confirm end-to-end connectivity.

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each VDM parameter
2. **Analysis**: Document any reported values that approached range limits
3. **Performance Metrics**: Report VDM access times and any performance variations observed
4. **Range Validation**: Summary of all VDM parameters with their actual vs. expected ranges
