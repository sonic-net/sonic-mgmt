# Signal Integrity Test Plan

## Overview

The Signal Integrity Test Plan defines the strategy for validating the signal integrity (SI) of optical links using transceivers onboarded to SONiC. It covers extended-duration soak testing for long-term link stability, optical margin characterization (receiver sensitivity and crosstalk), SI fault injection at CMIS test points (TP0–TP5), and ZR coherent-optics validation (neighboring-channel isolation and OSNR tolerance).

## Scope

The scope of this test plan includes the following:

- Extended-duration link stability soak testing
- Optical margin characterization under degraded signal conditions (receiver sensitivity, crosstalk)
- Signal integrity fault injection across CMIS test points (TP0–TP5)
- ZR coherent-optics validation (neighboring-channel disturbance, single-channel and WDM OSNR tolerance)
- Post-FEC error rate monitoring and traffic integrity checks

## Optics Scope

This plan covers all optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope).

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

> **Note:** Some of the test cases require specialized test setup, including Viavi instruments, VOAs, and optical power splitters.

## Pre-requisites

Before executing the signal integrity tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-prerequisites-and-configuration-files) must be met

### Environment Validation

Before starting tests, verify the following system conditions:

1. **System Health Check**
   - All critical services are running (xcvrd, pmon, swss, syncd) for at least 5 minutes
   - No existing system errors in logs

2. **Transceiver Baseline Verification**
   - All expected transceivers are present and detected
   - All links are in operational state with no pre-existing link flaps
   - No existing I2C communication errors
   - LLDP neighbors are discovered (if LLDP is enabled)
   - Post-FEC error counters are at zero (or baselined)

3. **Configuration Validation**
   - `signal_integrity.json` configuration file is properly formatted and accessible
   - All required attributes are defined for the transceivers under test
   - Platform-specific SI settings are correctly configured

## Attributes

A `signal_integrity.json` file defines the attributes for signal integrity tests across the transceiver types the system supports.

The table below is the authoritative reference for all signal integrity test attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| tp0_tp1_fault_injection_method | string | - | O | transceivers or platform | Method to induce TP0-TP1 (host-side) signal integrity faults. Vendor-dependent (e.g., SI setting change). |
| tp4_tp5_fault_injection_method | string | - | O | transceivers or platform | Method to induce TP4-TP5 (media-side) signal integrity faults. Vendor-agnostic (e.g., SI setting change in TP4). |
| rx_power_reduction_method | string | - | O | transceivers or platform | Method to reduce RX optical power for receiver sensitivity testing (e.g., variable optical attenuator). |
| crosstalk_injection_method | string | - | O | transceivers or platform | Method to inject crosstalk (e.g., coupling aggressor TX to an existing link). |
| post_fec_error_threshold | integer | 0 | O | transceivers | Maximum allowable post-FEC error increment during tests. 0 means zero-error requirement. |
| link_flap_tolerance | integer | 0 | O | transceivers | Maximum allowable link flap count during tests. 0 means no flaps allowed. |
| traffic_validation_enabled | boolean | False | O | platform | Whether to validate transmitted byte/packet counts match received counts. |
| zr_optics | boolean | False | O | transceivers or platform | Whether the transceiver/platform supports ZR coherent-optics testing and the required line-system testbed. Used to gate ZR-specific test cases. |
| si_fault_stress_iterations | integer | 4 | O | transceivers | Number of iterations for SI fault injection tests. |
| soak_duration_hr | integer | 24 | O | transceivers or platform | Duration in hours for soak test. |

## CLI Commands Reference

For the detailed CLI commands used in the test cases below, refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework, which provides comprehensive examples of all relevant commands.

Key commands specific to this test plan:

```bash
# Post-FEC error counters
show interfaces counters errors

# Link flap count and last_up_time
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "flap_count"
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "last_up_time"

# DOM sensor monitoring (RX/TX power)
sonic-db-cli -n '<namespace>' STATE_DB hgetall 'TRANSCEIVER_DOM_SENSOR|<port>'

# VDM real-time values (if supported)
sonic-db-cli -n '<namespace>' STATE_DB hgetall 'TRANSCEIVER_VDM_REAL_VALUE|<port>'
```

## Test Cases

**Test Execution Prerequisites:**

The following tests from the Transceiver Onboarding Test Infrastructure and Framework will be run prior to executing the signal integrity tests:

- Transceiver presence check
- Ensure active firmware is gold firmware (for non-DAC CMIS transceivers)
- Link up verification
- LLDP verification (if enabled)

> **Note:** Each prerequisite check is itself a test case. If a prerequisite test case fails, the dependent signal integrity test case will also be declared as failed.

**Assumptions for the Below Tests:**

- All tests below are executed for every transceiver connected to the DUT (the port list is derived from `port_attributes_dict`) unless specified otherwise.
- Post-FEC error counters and link flap counts are baselined at the start of each test case.

### Skip / Execution Gates for Optional Tests

The following optional tests are executed only when the required capability is present. If the relevant attribute is not configured, is empty, or evaluates to false/`-`, the test should be marked as skipped rather than failed:

- Receiver Sensitivity Test: skip if `rx_power_reduction_method` is empty or `-`.
- Crosstalk Penalty Test: skip if `crosstalk_injection_method` is empty or `-`.
- TP0 FIR Change Test (host-side): skip if `tp0_tp1_fault_injection_method` is empty or `-`.
- TP4 FIR Change Test (media-side): skip if `tp4_tp5_fault_injection_method` is empty or `-`.
- ZR Coherent Optics Test Cases: skip if `zr_optics` is empty/False or the required coherent line-system setup is unavailable.

### Link Stability and Optical Margin Test Cases

These tests validate long-term link stability and characterize link margin under degraded optical conditions (reduced receive power and crosstalk).

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Link soak test | 1. Verify all links are operationally up.<br>2. Record baseline: link status, post-FEC error counters, link flap counts, and traffic counters (if `traffic_validation_enabled`) for all ports.<br>3. Monitor continuously for `soak_duration_hr` hours (default 24 hrs):<br>   a. Periodically check link status (no link flaps).<br>   b. Periodically record post-FEC error counters.<br>   c. Periodically record DOM sensor values (TX/RX power).<br>   d. If `traffic_validation_enabled`, verify transmitted byte/packet counts match received counts.<br>4. After the soak duration completes, verify the final state:<br>   a. All links remain operationally up.<br>   b. Post-FEC error increment = 0 (or within `post_fec_error_threshold`).<br>   c. Link flap count unchanged (or within `link_flap_tolerance`).<br>   d. Traffic counters: transmitted = received (if enabled). | 1. Link flap count increment = 0 (or within `link_flap_tolerance`).<br>2. Post-FEC error increment for any link = 0 (or within `post_fec_error_threshold`).<br>3. Transmitted byte/packet count = received byte/packet count (if traffic validation enabled).<br>4. All DOM values remain within operational ranges throughout the test. |
| 2 | Receiver Sensitivity Test | 1. Skip test if `rx_power_reduction_method` is empty or `-`.<br>2. Testbed: use a uni-directional optical path (DR8 one optic pair — 8 links, or 2xLR4-6 two optic pairs — 4 links).<br>3. Record baseline: link status, post-FEC error counters, and RX power levels for all lanes.<br>4. Reduce RX optical power using `rx_power_reduction_method` (e.g., variable optical attenuator).<br>5. Monitor and record:<br>   a. Link status per lane<br>   b. Post-FEC error counter increments<br>   c. RX power levels from DOM<br>   d. RX LOS/LOL alarm flags<br>   e. VDM values (if supported)<br>6. Optionally introduce reflection between the TX and RX paths.<br>7. Restore original optical power levels.<br>8. Verify the link recovers and all counters stabilize. | RX power reduction triggers the appropriate alarm thresholds. Link behavior at the margin boundary is characterized, and the link recovers after optical power is restored. |
| 3 | Crosstalk Penalty Test | 1. Skip test if `crosstalk_injection_method` is empty or `-`.<br>2. Testbed: use a uni-directional optical path (DR8 one optic pair — 8 links, or 2xLR4-6 two optic pairs — 4 links).<br>3. Record baseline: link status, post-FEC error counters, and DOM values for all lanes.<br>4. Couple an aggressor TX to an existing link using `crosstalk_injection_method`.<br>5. Monitor and record:<br>   a. Link status per lane<br>   b. Post-FEC error counter increments<br>   c. Crosstalk penalty impact on RX signal quality<br>   d. DOM alarm/warning flags<br>   e. VDM values (if supported)<br>6. Remove the crosstalk source.<br>7. Verify the link recovers and all counters stabilize. | The crosstalk penalty impact on link quality is characterized, the appropriate alarm thresholds are triggered, and the link recovers after the crosstalk source is removed. |

### Host and Media SI Fault Injection Test Cases

These tests validate link behavior when signal integrity is deliberately degraded through SI/FIR setting changes at the host-side (TP0–TP1) and media-side (TP4–TP5) interfaces. They require collaboration with the switch and optics vendors to define appropriate fault injection methods.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | TP0 FIR Change Test (host-side) | 1. Skip test if `tp0_tp1_fault_injection_method` is empty or `-`.<br>2. Record baseline: link status, post-FEC error counters, and DOM values for all ports under test.<br>3. Apply host-side SI fault injection using `tp0_tp1_fault_injection_method` (e.g., SI setting change at TP0).<br>4. Monitor link behavior for `si_fault_stress_iterations` iterations.<br>5. For each iteration, record:<br>   a. Link status (up/down)<br>   b. Post-FEC error counter increments<br>   c. DOM alarm/warning flags (TX LOS, TX LOL, RX LOS, RX LOL)<br>   d. VDM values (if supported)<br>6. Restore original SI settings.<br>7. Verify the link recovers and all counters stabilize. | TP0–TP1 alarm behavior is validated. Link behavior under SI degradation is characterized, alarm flags are raised when SI thresholds are crossed, and the link recovers after fault removal. |
| 2 | TP4 FIR Change Test (media-side) | 1. Skip test if `tp4_tp5_fault_injection_method` is empty or `-`.<br>2. Record baseline: link status, post-FEC error counters, and DOM values for all ports under test.<br>3. Apply media-side SI fault injection using `tp4_tp5_fault_injection_method` (e.g., SI setting change at TP4).<br>4. Monitor link behavior for `si_fault_stress_iterations` iterations.<br>5. For each iteration, record:<br>   a. Link status (up/down)<br>   b. Post-FEC error counter increments<br>   c. DOM alarm/warning flags (TX power, TX bias, RX power on the remote side)<br>   d. VDM values (if supported)<br>6. Restore original SI settings.<br>7. Verify the link recovers and all counters stabilize. | TP4–TP5 alarm behavior is validated. Link behavior under media-side SI degradation is characterized, alarm flags are raised when SI thresholds are crossed, and the link recovers after fault removal. |

### ZR Coherent Optics Test Cases

These tests are specific to ZR (coherent) optics. They validate neighboring-channel isolation and receiver OSNR tolerance in single-channel and WDM line-system environments, and require a coherent optical line system with amplifiers, ASE noise loading, VOAs, an OSA, and optical power monitors.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Neighboring Channel Disturbance Test | 1. Skip test if `zr_optics` is empty/False or coherent line-system support is unavailable.<br>2. Turn up all channels and verify all links are healthy.<br>3. For each interface/channel under test:<br>   a. Identify neighboring channels (i-1 and i+1).<br>   b. Record baseline flap counts, BER, and power levels on neighboring channels.<br>   c. Clear FCS error counters on neighboring channels.<br>4. Perform the selected disturbance operation on the target channel: Shut/No-Shut, Reset, Low Power Mode, or Reseat (remove/reinsert optics).<br>5. While the operation is in progress, monitor neighboring channels for link flaps, BER / TX-RX power spikes or degradation, and FCS errors.<br>6. Verify neighboring channels remain stable.<br>7. Repeat for the configured number of iterations.<br>8. Log and aggregate results across all channels. | 1. Zero link flaps on neighboring channels.<br>2. No DOM spikes or degradation on neighboring channels.<br>3. Zero FCS errors on neighboring channels.<br>4. Pass criteria met for all tested interfaces. |
| 2 | OSNR Single Channel Test | 1. Skip test if `zr_optics` is empty/False or coherent line-system support is unavailable.<br>2. Verify the link is healthy at high OSNR (no ASE noise).<br>3. Collect baseline measurements: TX power, RX power, BER.<br>4. Calibrate ASE power and use VOA2/OPM to keep RX power constant.<br>5. Sweep VOA1 attenuation to vary OSNR:<br>   a. Inject ASE noise.<br>   b. Measure OSNR using the OSA.<br>   c. Record pre-FEC BER and FCS errors.<br>   d. Check alarms/warnings.<br>6. Return to high OSNR (remove ASE noise) and verify recovery.<br>7. Save results to a `.npz` file.<br>8. Repeat for short-, center-, and long-wavelength channels in the C-band. | 1. OSNR tolerance meets 400ZR spec (≥ 26 dB for BER < 1.25e-2).<br>2. BER vs OSNR follows the expected waterfall curve.<br>3. Link recovers when ASE is removed.<br>4. No false alarms at high OSNR.<br>5. Interop variance < 1 dB between interop combinations.<br>_Outputs:_ `SC_OSA.png`, `SC_OSNR.png`, `ber_vs_osnr.npz`, and an OSNR log file per TX/RX vendor combination. |
| 3 | OSNR WDM Test | 1. Skip test if `zr_optics` is empty/False or coherent line-system support is unavailable.<br>2. Turn up all four channels and verify links are healthy.<br>3. Collect baseline measurements for all channels: TX power, RX power, BER.<br>4. Run amplifier auto-gain equalization when transitioning from single-channel to multi-channel operation.<br>5. Calibrate ASE power and hold RX power constant using VOA2/OPM.<br>6. Sweep VOA1 attenuation to vary OSNR:<br>   a. Inject ASE noise.<br>   b. Use the On/Off method: turn OFF target channel (e.g., channel 2), turn ON balancing channel (e.g., channel 4), measure noise floor.<br>   c. Measure OSNR using the OSA.<br>   d. Record pre-FEC BER and FCS errors for all channels.<br>   e. Record adjacent-channel interference/crosstalk metrics.<br>   f. Check alarms/warnings.<br>7. Return to high OSNR and verify all channels recover.<br>8. Save results to `.npz`.<br>9. Repeat for short-, center-, and long-wavelength regions in the C-band. | 1. OSNR tolerance meets 400ZR spec (≥ 26 dB for BER < 1.25e-2).<br>2. BER vs OSNR follows the expected waterfall curve.<br>3. Adjacent-channel impact shows minimal degradation vs. the single-channel test.<br>4. All channels recover when ASE is removed.<br>5. Interop variance < 1 dB between interop combinations.<br>6. Meets OIF 400ZR ROSNR specification.<br>_Outputs:_ `WDM_OSA.png`, `WDM_OSNR.png`, `combined_OSNR.png`, `ber_vs_osnr.npz`, individual signal/noise OSA traces, and an OSNR log file. |

## Cleanup and Post-Test Verification

After test completion:

### Immediate Cleanup

1. **SI Settings Restoration**: Verify all signal integrity settings are restored to their original operational values
2. **Link Status**: Verify all transceivers are in operational state with links up
3. **System Health**: Check system logs for any unexpected errors or warnings introduced during testing
4. **Service Status**: Verify all critical services (xcvrd, pmon, swss, syncd) are running normally

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case
2. **Error Analysis**: Document any post-FEC errors, link flaps, or alarm events observed during testing with timestamps and correlation to test conditions
3. **DOM Trending**: Provide DOM sensor trending data (temperature, TX/RX power) captured during soak tests for baseline comparison
4. **Margin and OSNR Results**: Document RX sensitivity and crosstalk margin measurements, and ZR OSNR tolerance results (BER vs. OSNR) per port/lane and vendor combination
