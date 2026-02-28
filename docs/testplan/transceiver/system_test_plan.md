# System Test Plan For Transceivers

## Overview

The System Test Plan for transceivers outlines a comprehensive testing strategy for overall system functionality, including link behavior in various scenarios such as process and docker restarts, and advanced transceiver features. This document employs an attribute-driven approach to provide flexible, platform-specific testing that covers traditional transceiver operations as well as modern C-CMIS capabilities.

## Scope

The scope of this test plan includes the following:

- Verification of transceiver system-level functionality and performance across various transceiver types
- Validation of link behavior during system disruptions (process restarts, docker restarts, reboots)
- Testing of transceiver subsystem resilience and recovery mechanisms
- Validation of data consistency across transceiver-related components
- Advanced C-CMIS transceiver testing including frequency and tx power adjustment
- SI (Signal Integrity) settings validation for both optics and media configurations
- Stress testing and load validation under various system conditions
- Platform-specific behavior validation and attribute-driven test configuration

## Optics Scope

All the optics covered in the parent [transceiver onboarding test plan](test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

## Pre-requisites

Before executing the system tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](test_plan.md#test-prerequisites-and-configuration-files) must be met

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

## Attributes

A `system.json` file is used to define the attributes for the system tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in system testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| verify_lldp_on_link_up | boolean | True | O | dut | Whether to verify LLDP functionality when link comes up |
| port_shutdown_wait_sec | integer | 5 | O | transceivers or platform_hwsku_overrides | Wait time after port shutdown before verification |
| port_startup_wait_sec | integer | 60 | O | transceivers or platform_hwsku_overrides | Wait time after port startup before link verification |
| port_toggle_iterations | integer | 100 | O | transceivers or platform_hwsku_overrides | Number of iterations for port toggle stress test |
| port_toggle_delay_sec | integer | 2 | O | transceivers or platform_hwsku_overrides | Delay between port toggle cycles |
| port_range_toggle_iterations | integer | 50 | O | transceivers or platform_hwsku_overrides | Number of iterations for port range toggle stress test |
| port_range_test_ports | list | [] | O | dut | List of specific port names (e.g., 'Ethernet0', 'Ethernet4') to include in port range stress test. Empty list means use all available ports. |
| port_range_startup_wait_sec | integer | 60 | O | transceivers or platform_hwsku_overrides | Wait time after port range startup |
| xcvrd_restart_settle_sec | integer | 120 | O | hwsku | Time to wait after xcvrd restart before checking link status |
| pmon_restart_settle_sec | integer | 120 | O | hwsku | Time to wait after pmon restart before verification |
| swss_restart_settle_sec | integer | 180 | O | hwsku | Time to wait after swss restart before verification |
| syncd_restart_settle_sec | integer | 240 | O | hwsku | Time to wait after syncd restart before verification |
| expect_pmon_restart_with_swss_or_syncd | boolean | False | O | platform | Whether pmon restart is expected during swss/syncd restart |
| config_reload_settle_sec | integer | 300 | O | hwsku | Time to wait after config reload before link status check |
| cold_reboot_settle_sec | integer | 400 | O | hwsku | Time to wait after cold reboot before link status check |
| cold_reboot_iterations | integer | 5 | O | hwsku | Number of iterations for cold reboot stress test |
| warm_reboot_supported | boolean | False | O | platform or hwsku | Whether platform supports warm reboot functionality |
| warm_reboot_settle_sec | integer | 300 | O | hwsku | Time to wait after warm reboot before verification |
| warm_reboot_iterations | integer | 5 | O | hwsku | Number of iterations for warm reboot stress test |
| fast_reboot_supported | boolean | False | O | platform or hwsku | Whether platform supports fast reboot functionality |
| fast_reboot_settle_sec | integer | 300 | O | hwsku | Time to wait after fast reboot before verification |
| fast_reboot_iterations | integer | 5 | O | hwsku | Number of iterations for fast reboot stress test |
| power_cycle_supported | boolean | False | O | platform or hwsku | Whether automated power cycle testing is supported (requires controllable PDU) |
| power_cycle_settle_sec | integer | 600 | O | hwsku | Time to wait after full power restoration before starting verification (allows hardware, optics, and services to fully initialize) |
| power_cycle_iterations | integer | 3 | O | hwsku | Number of power cycle iterations for recovery/stress validation |
| transceiver_reset_supported | boolean | True | O | transceivers | Whether transceiver supports reset functionality |
| transceiver_reset_i2c_recover_sec | integer | 5 | O | transceivers | Time to wait for I2C recovery after transceiver state changes (reset, low power mode) before verification |
| low_power_mode_supported | boolean | False | O | transceivers | Whether transceiver supports low power mode |
| loopback_supported | boolean | False | O | transceivers | Whether transceiver supports loopback functionality |
| supported_loopback_modes | list | [] | O | transceivers | List of supported loopback modes. Possible values include, but are not limited to: ["host-side-input", "media-side-input", "host-side-output", "media-side-output"]. |
| loopback_settle_sec | integer | 15 | O | transceivers | Time to wait after loopback mode changes |
| low_pwr_request_hw_asserted | boolean | True | O | platform | Whether to check DataPath state and LowPwrRequestHW signal. When True, expects LowPwrRequestHW signal to be asserted (1); when False, skips these checks |
| cmis_bootup_low_power_test_supported | boolean | False | O | platform | Whether to test that CMIS transceivers boot up in low power mode when xcvrd is disabled during startup |
| tx_disable_test_supported | boolean | False | O | transceivers | Whether transceiver supports Tx disable testing and DataPath state verification |
| optics_si_settings | dict | {} | O | transceivers | Dictionary containing optics SI settings with nested structure for parameters like OutputAmplitudeTargetRx, OutputEqPreCursorTargetRx, OutputEqPostCursorTargetRx, etc. Each parameter contains per-lane values (e.g., OutputAmplitudeTargetRx1-8). Test runs if dictionary is non-empty. |
| media_si_settings | dict | {} | O | platform_hwsku_overrides | Dictionary containing media SI settings following media_settings.json structure for comparison with APPL_DB values. Test runs if dictionary is non-empty. |
| frequency_values | list | [] | O | transceivers | List of frequency values for C-CMIS transceivers. First value is the default frequency, followed by test frequencies (min/max supported). Test runs if list is non-empty. |
| tx_power_values | list | [] | O | transceivers | List of tx power values in dBm for C-CMIS transceivers. First value is the default tx power, followed by test power levels (min/max supported). Test runs if list is non-empty. |
| expected_application_code | integer | - | O | platform_hwsku_overrides | Expected application code value for the specific transceiver type, platform, and hwsku combination. When defined, the test will verify that the actual application code read from the transceiver matches this expected value. |
| link_stability_monitor_sec | integer | 300 | O | transceivers or platform_hwsku_overrides | Duration in seconds to monitor link stability without link flaps during steady state monitoring test |

For information about attribute override hierarchy and precedence, please refer to the [Priority-Based Attribute Resolution](test_plan.md#priority-based-attribute-resolution) documentation.

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the transceiver onboarding test plan. This section provides comprehensive examples of all relevant commands

## Test Cases

**Test Execution Prerequisites:**

The following tests from the [Transceiver Onboarding Test Plan](test_plan.md#test-cases) will be run prior to executing the system tests:

- Transceiver presence check
- Ensure active firmware is gold firmware (for non-DAC CMIS transceivers)
- Link up verification
- LLDP verification (if enabled)

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

## Test Execution Flow

### Recommended Test Order

The following execution order is recommended to minimize system disruption and ensure reliable test results:

1. **Link Behavior Test Cases** - Basic port operations that establish baseline functionality
2. **Diagnostic Test Cases** - Non-disruptive validation of transceiver capabilities and SI settings
3. **Configuration Validation Test Cases** - C-CMIS tuning and configuration parameter verification
4. **Transceiver Event Handling Test Cases** - Physical state change validation (requires careful state management)
5. **Process and Service Restart Test Cases** - Medium system disruption tests
6. **System Recovery Test Cases** - High system disruption tests (reboots)
7. **Stress and Load Test Cases** - Extended duration tests (run last to avoid impact on other tests)

## Test Execution Guidelines

### Attribute Usage in Tests

- **Settle Time Attributes**: Used as maximum wait times before declaring test failure
- **Iteration Attributes**: Define the number of test cycles for stress testing
- **Boolean Attributes**: Control conditional test behavior and expectations

### Test State Management

- **State Preservation**: Before each test that modifies transceiver settings (e.g., loopback modes, low power mode, Tx disable), the original state should be captured
- **State Reversion**: After each test completion (pass or fail), the transceiver should be reverted to its original operational state
- **Cleanup on Failure**: If a test fails during execution, cleanup procedures should still attempt to restore the original state to prevent impact on subsequent tests
- **Link Recovery**: After state reversion, tests should verify that links return to their expected operational state before proceeding to the next test

## Common Verification Procedures

The following procedures are referenced throughout the test cases to ensure consistent validation:

### Standard Port Recovery and Verification Procedure

This procedure is used after any test that modifies transceiver state or after system disruptions:

1. **Link Status Verification**
   - Verify port is operationally up
   - Wait for configured timeout period before declaring failure

2. **LLDP Verification** (if `verify_lldp_on_link_up` is True)
   - Verify port appears in LLDP neighbor table
   - Confirm LLDP neighbor information is correctly populated (remote device ID, port ID, etc. if applicable)

3. **CMIS State Verification** (for non-DAC CMIS transceivers (can be checked via `is_non_dac_and_cmis` attribute))
   - Verify DataPathState is `DPActivated` for operational ports
   - Verify ConfigState is `ConfigSuccess`

4. **SI Settings Verification** (if applicable)
   - **Optics SI Settings**: If `optics_si_settings` is defined, verify current EEPROM values match configured attributes
   - **Media SI Settings**: If `media_si_settings` is defined, verify PORT_TABLE APPL_DB values match configured attributes. Also, ensure `NPU_SI_SETTINGS_SYNC_STATUS_KEY` is set to `NPU_SI_SETTINGS_DONE` in `PORT_TABLE` of `APPL_DB`
   - Log any discrepancies for analysis

5. **Application Code Verification** (if `expected_application_code` is defined and not null)
   - Read current application code from transceiver EEPROM
   - Verify the actual application code matches the `expected_application_code` value
   - Log any discrepancies for analysis

6. **Docker and Process Health Check**
   - Verify all critical services (`xcvrd, pmon, swss, syncd`) are running for at least 3 minutes
   - Ensure no core files are present in `/var/core`
   - Log any service failures for analysis

### State Preservation and Restoration

This procedure ensures tests don't interfere with each other:

1. **State Capture** (before test execution)
   - Record current port operational states

2. **State Restoration** (after test completion, regardless of pass/fail)
   - Restore all modified transceiver settings to original values
   - Verify all ports return to their original operational states
   - Execute **Standard Port Recovery and Verification Procedure** for affected ports

### Link Behavior Test Cases

The following tests aim to validate the link status and stability of transceivers under various conditions.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Port shutdown validation | 1. For each transceiver port individually:<br>   a. Issue `config interface shutdown <port>`.<br>   b. Wait for `port_shutdown_wait_sec`.<br>   c. Verify port is operationally down.<br>2. Validate link status using CLI configuration. | Ensure that the link goes down within the configured timeout period for each port. |
| 2 | Port startup validation | 1. For each transceiver port individually:<br>   a. Issue `config interface startup <port>`.<br>   b. Wait for `port_startup_wait_sec`.<br>2. Execute **Standard Port Recovery and Verification Procedure**. | Ensure that the port passes all verification checks including link status, LLDP, CMIS states, SI settings, and application code validation. |

### Process and Service Restart Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | xcvrd daemon restart impact | 1. Verify current link states to be up for all transceivers and record the link up time.<br>2. Restart xcvrd daemon.<br>3. Wait for `xcvrd_restart_settle_sec` before verification.<br>4. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and all verification checks pass. Also ensure that xcvrd is up for at least `xcvrd_restart_settle_sec` seconds. |
| 2 | xcvrd restart with I2C errors | 1. Verify current link states to be up for all transceivers and record the link up time.<br>2. Induce I2C errors in the system.<br>3. Restart xcvrd daemon.<br>4. Monitor link behavior and system stability.<br>5. Wait for `xcvrd_restart_settle_sec` before verification.<br>6. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and all verification checks pass even with I2C errors present. |
| 3 | xcvrd crash recovery test | 1. Verify current link states to be up for all transceivers and record the link up time.<br>2. Modify xcvrd.py to raise an Exception and induce a crash.<br>3. Monitor automatic restart behavior.<br>4. Wait for `xcvrd_restart_settle_sec` before verification.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and all verification checks pass. Also ensure that xcvrd is up for at least `xcvrd_restart_settle_sec` seconds. |
| 4 | pmon docker restart impact | 1. Verify current link states to be up for all transceivers and record the link up time.<br>2. Restart pmon container.<br>3. Monitor transceiver monitoring and link behavior.<br>4. Wait for `pmon_restart_settle_sec` before verification.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and all verification checks pass. |
| 5 | swss docker restart impact | 1. Verify current link states to be up for all transceivers.<br>2. Restart swss container.<br>3. Monitor link state transitions and recovery.<br>4. Wait for `swss_restart_settle_sec` before verification.<br>5. Check if `expect_pmon_restart_with_swss_or_syncd` is True and verify pmon restart accordingly.<br>6. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Ensure `xcvrd` restarts (based on `expect_pmon_restart_with_swss_or_syncd`) and all ports pass verification checks. |
| 6 | syncd process restart impact | 1. Verify current link states to be up for all transceivers.<br>2. Restart syncd.<br>3. Monitor system recovery and link restoration.<br>4. Wait for `syncd_restart_settle_sec` before verification.<br>5. Check if `expect_pmon_restart_with_swss_or_syncd` is True and verify pmon restart accordingly.<br>6. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Ensure `xcvrd` restarts (based on `expect_pmon_restart_with_swss_or_syncd`) and all ports pass verification checks. |

### System Recovery Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Config reload impact | 1. Verify current link states to be up for all transceivers.<br>2. Execute `sudo config reload -y`.<br>3. Wait for `config_reload_settle_sec` and verify transceiver link restoration.<br>4. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Ensure `xcvrd` restarts and all ports pass comprehensive verification checks. |
| 2 | Cold reboot link recovery | 1. Verify current link states to be up for all transceivers.<br>2. Execute a cold reboot.<br>3. Wait for `cold_reboot_settle_sec` and monitor link recovery after reboot.<br>4. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm all ports link up again post-reboot and pass comprehensive verification checks. |
| 3 | Warm reboot link recovery | 1. Skip test if `warm_reboot_supported` is False.<br>2. Verify current link states to be up for all transceivers.<br>3. Perform warm reboot.<br>4. Wait for `warm_reboot_settle_sec` and monitor link recovery after reboot.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Ensure `xcvrd` restarts and maintains link stability for all ports, with comprehensive verification checks passing. |
| 4 | Fast reboot link recovery | 1. Skip test if `fast_reboot_supported` is False.<br>2. Verify current link states to be up for all transceivers.<br>3. Perform fast reboot.<br>4. Wait for `fast_reboot_settle_sec` and monitor link establishment timing.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm all ports link up again post-reboot and pass comprehensive verification checks. |
| 5 | Power cycle link recovery | 1. Skip test if `power_cycle_supported` is False.<br>2. Verify current link states are up for all transceivers.<br>3. Perform a controlled chassis power cycle.<br>4. Wait for `power_cycle_settle_sec` and monitor link recovery after full boot.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Confirm all ports link up again post-power cycle and pass comprehensive verification checks (link status, LLDP, CMIS states, SI settings, application code if defined, docker and process stability). |

### Transceiver Event Handling Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver reset validation | 1. Skip test if `transceiver_reset_supported` is False.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. Reset the transceiver using appropriate CLI command.<br>4. Wait for `transceiver_reset_i2c_recover_sec` to allow I2C recovery.<br>5. Verify port is linked down after reset and transceiver is in low power mode (if `low_power_mode_supported` is True).<br>6. If `low_pwr_request_hw_asserted` is True:<br>   a. Check DataPath is in DPDeactivated state.<br>   b. Verify LowPwrAllowRequestHW (page 0h, byte 26.6) is set to 1.<br>7. Issue `config interface shutdown <port>` and wait for `port_shutdown_wait_sec`.<br>8. Issue `config interface startup <port>` and wait for `port_startup_wait_sec`.<br>9. Execute **Standard Port Recovery and Verification Procedure**.<br>10. Execute **State Preservation and Restoration** (restoration phase). | Ensure that the port is linked down after reset and is in low power mode (if transceiver supports it). If `low_pwr_request_hw_asserted` is True, verify DataPath is in DPDeactivated state and LowPwrAllowRequestHW signal is asserted (set to 1). The shutdown and startup commands should re-initialize the port and bring the link up with all verification checks passing. |
| 2 | Transceiver low power mode validation | 1. Skip test if `low_power_mode_supported` is False.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. Ensure transceiver is in high power mode initially.<br>4. Put the transceiver in low power mode using CLI command.<br>5. Wait for `transceiver_reset_i2c_recover_sec`.<br>6. Verify port is linked down and DataPath is in DPDeactivated state.<br>7. Verify transceiver is in low power mode through CLI.<br>8. Disable low power mode (restore to high power mode).<br>9. Wait for `transceiver_reset_i2c_recover_sec`.<br>10. Execute **Standard Port Recovery and Verification Procedure**.<br>11. Execute **State Preservation and Restoration** (restoration phase). | Ensure transceiver transitions correctly between high and low power modes. Port should be down in low power mode and up in high power mode with all verification checks passing. |
| 3 | CMIS transceiver boot-up low power mode test | 1. Skip test if `cmis_bootup_low_power_test_supported` is False.<br>2. Add `"skip_xcvrd": true,` to the `pmon_daemon_control.json` file.<br>3. Reboot the device using cold reboot.<br>4. Wait for `cold_reboot_settle_sec` and verify system is operational.<br>5. Verify CMIS transceiver is in low power mode after boot-up.<br>6. Revert the `pmon_daemon_control.json` file to original state.<br>7. Restart pmon service: `sudo systemctl restart pmon`.<br>8. Wait for `pmon_restart_settle_sec` and verify normal operation restored.<br>9. Execute **Standard Port Recovery and Verification Procedure** for all ports. | Ensure CMIS transceiver boots up in low power mode when xcvrd is disabled. System should restore normal operation after reverting configuration and restarting pmon with all verification checks passing. |
| 4 | Transceiver Tx disable DataPath validation | 1. Skip test if `tx_disable_test_supported` is False.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. Verify transceiver is in operational state with DataPath in DPActivated state.<br>4. Read MaxDurationDPTxTurnOff value from EEPROM (page 1h, byte 168.7:4) using appropriate API.<br>5. Disable Tx by writing to EEPROM or calling `tx_disable` API.<br>6. Monitor DataPath state transition from DPActivated within the MaxDurationDPTxTurnOff time read from EEPROM.<br>7. Verify DataPath state changes from DPActivated to a different state within the specified time.<br>8. Issue `config interface shutdown <port>` and wait for `port_shutdown_wait_sec`.<br>9. Issue `config interface startup <port>` and wait for `port_startup_wait_sec`.<br>10. Execute **Standard Port Recovery and Verification Procedure**.<br>11. Execute **State Preservation and Restoration** (restoration phase). | Ensure DataPath state transitions correctly within MaxDurationDPTxTurnOff time (read from EEPROM) when Tx is disabled. Port should recover after shutdown/startup cycle with all verification checks passing. This test can be run as a stress test with multiple iterations. |

### Diagnostic Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver loopback validation | 1. Skip test if `loopback_supported` is False or `supported_loopback_modes` is empty.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. For each loopback mode in `supported_loopback_modes`:<br>   a. Enable the loopback mode using CLI command.<br>   b. Wait for `loopback_settle_sec`.<br>   c. Verify loopback is active through CLI.<br>   d. Test data path functionality (use LLDP neighbor verification for host-side input loopback if applicable).<br>   e. Disable loopback mode.<br>   f. Wait for `loopback_settle_sec`.<br>   g. Verify normal operation is restored.<br>4. Execute **Standard Port Recovery and Verification Procedure**.<br>5. Execute **State Preservation and Restoration** (restoration phase). | Ensure that the various supported types of loopback work on the transceiver. The LLDP neighbor can also be used to verify the data path after enabling loopback (such as host-side input loopback). All comprehensive verification checks should pass. |
| 2 | CMIS optics SI settings validation | 1. Skip test if `optics_si_settings` is empty or not defined.<br>2. Ensure the port is linked up.<br>3. Read optics SI settings from transceiver-level attribute `optics_si_settings` (following optics_si_settings.json structure).<br>4. Read corresponding SI settings from EEPROM using appropriate API calls.<br>5. Compare each SI setting parameter between attribute and EEPROM values.<br>6. Verify all optics SI settings match<br>7. Log any discrepancies found between attribute and EEPROM values.<br>8. Execute **Standard Port Recovery and Verification Procedure** (SI settings verification will be included). | Ensure optics SI settings defined in transceiver attributes match the corresponding values read from EEPROM and all comprehensive verification checks pass. |
| 3 | Media SI settings validation | 1. Skip test if `media_si_settings` is empty or not defined.<br>2. Ensure the port is linked up and `NPU_SI_SETTINGS_SYNC_STATUS_KEY` is set to `NPU_SI_SETTINGS_DONE` in `PORT_TABLE` of `APPL_DB`.<br>3. Read media SI settings from `media_si_settings` attribute (following media_settings.json structure).<br>4. Query PORT_TABLE in APPL_DB to retrieve corresponding media SI setting values for the port.<br>5. Compare each media SI setting parameter between attribute and APPL_DB values.<br>6. Verify all media SI settings match.<br>7. Log any discrepancies found between attribute and APPL_DB values.<br>8. Execute **Standard Port Recovery and Verification Procedure** (media SI settings verification will be included). | Ensure media SI settings defined in platform/hwsku attributes match the corresponding values in PORT_TABLE of APPL_DB and all comprehensive verification checks pass. This validates media configuration consistency for all optics with media SI settings. |

### Configuration Validation Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | C-CMIS frequency adjustment validation | 1. Skip test if `frequency_values` is empty or not defined.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. Capture current frequency configuration from CONFIG_DB and STATE_DB.<br>4. For each frequency value in `frequency_values` (starting from index 1, skipping default):<br>   a. Apply frequency using `config interface transceiver frequency <port> <frequency>`.<br>   b. Wait for `port_startup_wait_sec`.<br>   c. Verify frequency is set correctly in CONFIG_DB and STATE_DB.<br>   d. Execute **Standard Port Recovery and Verification Procedure**.<br>5. Restore original frequency (first value in `frequency_values`).<br>6. Wait for `port_startup_wait_sec` and verify restoration.<br>7. Execute **Standard Port Recovery and Verification Procedure**.<br>8. Execute **State Preservation and Restoration** (restoration phase). | Ensure C-CMIS transceiver frequency can be adjusted to supported values and restored to original frequency. Port should remain stable throughout frequency changes with all verification checks passing. |
| 2 | C-CMIS tx power adjustment validation | 1. Skip test if `tx_power_values` is empty or not defined.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. Capture current tx power configuration from CONFIG_DB and STATE_DB.<br>4. For each tx power value in `tx_power_values` (starting from index 1, skipping default):<br>   a. Apply tx power using `config interface transceiver tx-power <port> <tx_power>`.<br>   b. Wait for `port_startup_wait_sec`.<br>   c. Verify tx power is set correctly in CONFIG_DB and STATE_DB.<br>   d. Execute **Standard Port Recovery and Verification Procedure**.<br>5. Restore original tx power (first value in `tx_power_values`).<br>6. Wait for `port_startup_wait_sec` and verify restoration.<br>7. Execute **Standard Port Recovery and Verification Procedure**.<br>8. Execute **State Preservation and Restoration** (restoration phase). | Ensure C-CMIS transceiver tx power can be adjusted to supported values and restored to original tx power. Port should remain stable throughout power changes with all verification checks passing. |

### Stress and Load Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Port startup/shutdown stress test | 1. Execute **State Preservation and Restoration** (capture phase).<br>2. In a loop, for `port_toggle_iterations` iterations (default 100 times) for 1 random port:<br>   a. Issue `config interface shutdown <port>` and wait for `port_shutdown_wait_sec`.<br>   b. Issue `config interface startup <port>` and wait for `port_startup_wait_sec`.<br>   c. Use `port_toggle_delay_sec` delay between cycles.<br>   d. Monitor system stability and link status validation.<br>3. Execute **Standard Port Recovery and Verification Procedure**.<br>4. Execute **State Preservation and Restoration** (restoration phase). | Ensure link status toggles to up/down appropriately with each startup/shutdown command. System should remain stable throughout stress testing and all comprehensive verification checks should pass. |
| 2 | Port range stress test | 1. Use ports from `port_range_test_ports` if specified, otherwise use all available transceiver ports.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. Perform range shut and no-shut operations on the selected ports for `port_range_toggle_iterations` iterations.<br>4. Wait `port_range_startup_wait_sec` after each startup cycle.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all tested ports.<br>6. Execute **State Preservation and Restoration** (restoration phase). | System should handle concurrent port operations without instability and all comprehensive verification checks should pass for all tested ports. |
| 3 | Cold reboot stress test | 1. Execute **State Preservation and Restoration** (capture phase).<br>2. In a loop, execute cold reboot for `cold_reboot_iterations` consecutive times (default 5, can be configured to 100).<br>3. Wait `cold_reboot_settle_sec` after each reboot.<br>4. After each reboot iteration, execute **Standard Port Recovery and Verification Procedure**.<br>5. Execute **State Preservation and Restoration** (restoration phase). | Confirm the expected ports link up again post-reboot, with all comprehensive verification checks passing for all iterations. System should remain stable throughout multiple reboots. |
| 4 | Warm reboot stress test | 1. Skip test if `warm_reboot_supported` is False.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. In a loop, execute warm reboot for `warm_reboot_iterations` iterations.<br>4. Wait `warm_reboot_settle_sec` after each reboot.<br>5. After each reboot iteration, execute **Standard Port Recovery and Verification Procedure**.<br>6. Execute **State Preservation and Restoration** (restoration phase). | Ensure all ports link up again post-reboot with all comprehensive verification checks passing for all iterations. System should remain stable throughout multiple reboots. |
| 5 | Fast reboot stress test | 1. Skip test if `fast_reboot_supported` is False.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. In a loop, execute fast reboot for `fast_reboot_iterations` iterations.<br>4. Wait `fast_reboot_settle_sec` after each reboot.<br>5. After each reboot iteration, execute **Standard Port Recovery and Verification Procedure**.<br>6. Execute **State Preservation and Restoration** (restoration phase). | Ensure all ports link up again post-reboot with all comprehensive verification checks passing for all iterations. System should remain stable throughout multiple reboots. |
| 6 | Link stability monitoring test | 1. Verify all transceivers are in operational state with links up.<br>2. Record initial `last_up_time` and `flap_count` for each port from interface status.<br>3. Start monitoring for `link_stability_monitor_sec` duration:<br>   a. Continuously check link status every 10 seconds.<br>   b. Log any link state changes (up to down or down to up).<br>4. After monitoring period completion, verify that `last_up_time` and `flap_count` remain unchanged for all ports.<br>5. Execute **Standard Port Recovery and Verification Procedure** for all ports. | All transceivers maintain stable link status throughout the entire monitoring period with no unexpected link flaps. The `last_up_time` and `flap_count` values must remain unchanged, confirming no link instability occurred. This test validates long-term stability under steady-state conditions. |
| 7 | Power cycle stress test | 1. Skip test if `power_cycle_supported` is False.<br>2. Execute **State Preservation and Restoration** (capture phase).<br>3. For each iteration (1..`power_cycle_iterations`):<br>   a. Perform controlled power cycle of DUT.<br>   b. Wait for `power_cycle_settle_sec`.<br>   c. Execute **Standard Port Recovery and Verification Procedure** for all ports.<br>4. Execute **State Preservation and Restoration** (restoration phase). | Confirm the expected ports link up again post-reboot, with all comprehensive verification checks passing for all iterations. System should remain stable throughout multiple reboots. |

## Cleanup and Post-Test Verification

After test completion:

### Immediate Cleanup

1. **State Restoration**: Verify all transceivers are restored to their original operational state
2. **Link Status**: Verify all transceivers are in operational state with links up
3. **Configuration Reset**: Ensure any temporary configuration changes (e.g., pmon_daemon_control.json modifications) are reverted
4. **System Health**: Check system logs for any unexpected errors or warnings introduced during testing
5. **Service Status**: Verify all services and daemons are running normally
6. **Database Consistency**: Verify state databases contain expected transceiver information and are consistent

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case
2. **Performance Metrics**: Document settle times, iteration counts, and any performance deviations
3. **Error Analysis**: Compile any errors or warnings encountered during testing with recommended remediation
4. **System State**: Document final system state and any persistent configuration changes
