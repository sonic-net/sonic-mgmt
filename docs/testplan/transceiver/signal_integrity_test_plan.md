# Signal Integrity Test Plan

## Overview

The Signal Integrity Test Plan outlines a comprehensive strategy to validate the signal integrity (SI) of optical links using transceivers onboarded to SONiC. This document covers extended-duration soak testing to validate long-term signal quality and link stability, fault injection at various CMIS test points (TP0–TP5) to stress the link margins, and SI optimization validation to ensure BER targets are met across all ports.

## Scope

The scope of this test plan includes the following:

- Extended-duration link stability soak testing
- Signal integrity fault injection across CMIS test points (TP0–TP5)
- Validation of link behavior under degraded signal conditions (receiver sensitivity, crosstalk)
- SI optimization and scripting validation for host-side (TP0→TP1) and media-side (TP4→TP5) with BER targets
- Post-FEC error rate monitoring and traffic integrity checks

## Optics Scope

All the optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope)

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
   - `link.json` configuration file is properly formatted and accessible
   - All required attributes are defined for the transceivers under test
   - Platform-specific SI settings are correctly configured

## Attributes

A `link.json` file is used to define the attributes for the signal integrity tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in signal integrity testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

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
| si_fault_stress_iterations | integer | 4 | O | transceivers | Number of iterations for SI fault injection tests. |
| soak_duration_hr | integer | 24 | O | transceivers or platform | Duration in hours for soak test. |
| tp0_ber_target | float | 1e-10 | M | transceivers | Target BER at TP1 for host-side SI optimization (TC 8-1). |
| tp4_ber_target | float | 1e-8 | M | transceivers | Target BER at TP5 for media-side SI optimization (TC 8-2). |

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework. This section provides comprehensive examples of all relevant commands.

Key commands specific to this test plan:

```bash
# Post-FEC error counters
show interfaces counters errors

# Link flap count and last_up_time
show interfaces status

# DOM sensor monitoring (RX/TX power)
sonic-db-cli -n '' STATE_DB hgetall 'TRANSCEIVER_DOM_SENSOR|<port>'

# VDM real-time values (if supported)
sonic-db-cli -n '' STATE_DB hgetall 'TRANSCEIVER_VDM_REAL_VALUE|<port>'
```

## Test Cases

**Test Execution Prerequisites:**

The following tests from the [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-cases-interim) will be run prior to executing the signal integrity tests:

- Transceiver presence check
- Ensure active firmware is gold firmware (for non-DAC CMIS transceivers)
- Link up verification
- LLDP verification (if enabled)

> **Note:** Each prerequisite check is itself a test case. If a prerequisite test case fails, the dependent signal integrity test case will also be declared as failed.

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.
- Post-FEC error counters and link flap counts are baselined at the start of each test case.

### Link Soak Test Cases

These tests validate long-term link stability over an extended duration.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Link soak test | 1. Verify all links are operationally up.<br>2. Record baseline: link status, post-FEC error counters, link flap counts, and traffic counters (if `traffic_validation_enabled`) for all ports.<br>3. Start continuous monitoring for `soak_duration_hr` hours (default 24 hrs):<br>   a. Periodically check link status (no link flaps).<br>   b. Periodically record post-FEC error counters.<br>   c. Periodically record DOM sensor values (TX/RX power).<br>   d. If `traffic_validation_enabled`, verify transmitted byte/packet counts match received counts.<br>4. After soak duration completes, verify final state:<br>   a. All links remain operationally up.<br>   b. Post-FEC error increment = 0 (or within `post_fec_error_threshold`).<br>   c. Link flap count unchanged (or within `link_flap_tolerance`).<br>   d. Traffic counters: transmitted = received (if enabled). | 1. No link flaps during the entire soak duration.<br>2. Post-FEC error increment for any link = 0.<br>3. Transmitted byte/packet = received byte/packet count (if traffic validation enabled).<br>4. All DOM values remain within operational ranges throughout the test. |

### Signal Integrity - Fault Injection Test Cases

These tests validate link behavior when signal integrity is deliberately degraded at specific CMIS test points. They require collaboration with switch and optics vendors to define appropriate fault injection methods.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | TP0-TP1 (host-side) signal integrity fault injection | 1. Record baseline: link status, post-FEC error counters, and DOM values for all ports under test.<br>2. Apply host-side SI fault injection using `tp0_tp1_fault_injection_method` (e.g., SI setting change in TP0).<br>3. Monitor link behavior for `si_fault_stress_iterations` iterations.<br>4. For each iteration, record:<br>   a. Link status (up/down)<br>   b. Post-FEC error counter increments<br>   c. DOM alarm/warning flags (TX LOS, TX LOL, RX LOS, RX LOL)<br>   d. VDM values (if supported)<br>5. Restore original SI settings.<br>6. Verify link recovers and all counters stabilize. | Extended testing validates TP0-TP1 alarm behavior. Link behavior under SI degradation is characterized and documented. Alarm flags are properly raised when signal integrity thresholds are crossed. Link recovers after fault removal. |
| 2 | TP2-TP3 (media-side RX) receiver sensitivity test | 1. Testbed: Use uni-directional optical path (DR8 one optic pair — 8 links, or 2xLR4-6 two optic pairs — 4 links).<br>2. Record baseline: link status, post-FEC error counters, RX power levels for all lanes.<br>3. Reduce RX optical power using `rx_power_reduction_method` (e.g., variable optical attenuator).<br>4. Monitor and record:<br>   a. Link status per lane<br>   b. Post-FEC error counter increments<br>   c. RX power levels from DOM<br>   d. RX LOS/LOL alarm flags<br>   e. VDM values (if supported)<br>5. Optionally introduce reflection between TX and RX paths.<br>6. Restore original optical power levels.<br>7. Verify link recovers and all counters stabilize. | Extended testing validates TP2-TP3 alarm behavior under receiver sensitivity degradation. RX power reduction triggers appropriate alarm thresholds. Link behavior at margin boundaries is characterized. Link recovers after optical power is restored. |
| 3 | TP2-TP3 (media-side RX) crosstalk penalty test | 1. Testbed: Use uni-directional optical path (DR8 one optic pair — 8 links, or 2xLR4-6 two optic pairs — 4 links).<br>2. Record baseline: link status, post-FEC error counters, DOM values for all lanes.<br>3. Couple aggressor TX to an existing link using `crosstalk_injection_method`.<br>4. Monitor and record:<br>   a. Link status per lane<br>   b. Post-FEC error counter increments<br>   c. Crosstalk penalty impact on RX signal quality<br>   d. DOM alarm/warning flags<br>   e. VDM values (if supported)<br>5. Remove crosstalk source.<br>6. Verify link recovers and all counters stabilize. | Extended testing validates TP2-TP3 alarm behavior under crosstalk conditions. Crosstalk penalty impact on link quality is characterized and documented. Appropriate alarm thresholds are triggered. Link recovers after crosstalk removal. |
| 4 | TP4-TP5 (media-side TX) signal integrity fault injection | 1. Record baseline: link status, post-FEC error counters, and DOM values for all ports under test.<br>2. Apply media-side SI fault injection using `tp4_tp5_fault_injection_method` (e.g., SI setting change in TP4).<br>3. Monitor link behavior for `si_fault_stress_iterations` iterations.<br>4. For each iteration, record:<br>   a. Link status (up/down)<br>   b. Post-FEC error counter increments<br>   c. DOM alarm/warning flags (TX power, TX bias, RX power on remote side)<br>   d. VDM values (if supported)<br>5. Restore original SI settings.<br>6. Verify link recovers and all counters stabilize. | Extended testing validates TP4-TP5 alarm behavior. Link behavior under media-side SI degradation is characterized and documented. Alarm flags are properly raised when signal integrity thresholds are crossed. Link recovers after fault removal. |

### Signal Integrity - Optimization Test Cases

These tests validate that the signal integrity optimization on host-side (TP0→TP1) and media-side (TP4→TP5) achieves the required BER targets across all ports on a fully loaded switch.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | TP0 SI optimization and scripting (host-side) | 1. Ensure the switch is fully populated with transceivers and all links are operationally up.<br>2. Record baseline: link status, post-FEC error counters for all ports.<br>3. Execute TP0 (host-side TX) SI optimization procedure for all ports under test.<br>4. Monitor TP1 (host-side RX) BER for each port/lane after optimization.<br>5. Verify BER at TP1 meets `tp0_ber_target` (default < 1e-10) for all ports.<br>6. Record final SI settings applied per port. | 1. TP1 BER < `tp0_ber_target` (1e-10) for all ports.<br>2. All links remain operationally up after SI optimization.<br>3. SI optimization completes successfully for all ports on the fully loaded switch. |
| 2 | TP4 SI optimization and scripting (media-side) | 1. Ensure the switch is fully populated with transceivers and all links are operationally up.<br>2. Record baseline: link status, post-FEC error counters for all ports.<br>3. Execute TP4 (media-side TX) SI optimization procedure for all ports under test.<br>4. Monitor TP5 (media-side RX) BER for each port/lane after optimization.<br>5. Verify BER at TP5 meets `tp4_ber_target` (default < 1e-8) for all ports.<br>6. Record final SI settings applied per port. | 1. TP5 BER < `tp4_ber_target` (1e-8) for all ports.<br>2. All links remain operationally up after SI optimization.<br>3. SI optimization completes successfully for all ports on the fully loaded switch. |

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
4. **SI Optimization Results**: Document BER measurements per port/lane and final SI settings applied during optimization tests
