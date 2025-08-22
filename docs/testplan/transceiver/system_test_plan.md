# System Test Plan For Transceivers

## Overview

The System Test Plan for transceivers outlines the testing strategy for overall system functionality, including link behavior in various scenarios such as process and docker restarts, and debug tools for troubleshooting unexpected link down issues. This document covers the objectives, scope, test cases, and resources required for effective system-level testing.

## Scope

The scope of this test plan includes the following:

- Verification of transceiver system-level functionality and performance
- Validation of link behavior during system disruptions (process restarts, docker restarts, reboots)
- Testing of transceiver subsystem resilience and recovery mechanisms
- Verification of debug tools and diagnostic capabilities
- Validation of data consistency across transceiver-related components
- Testing of system response to transceiver insertion/removal events

## Optics Scope

All the optics covered in the parent [transceiver onboarding test plan](../transceiver_onboarding_test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](../transceiver_onboarding_test_plan.md#testbed-topology)

## Pre-requisites

Before executing the system tests, ensure the following pre-requisites are met:

- The testbed is set up according to the [Testbed Topology](../transceiver_onboarding_test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](../transceiver_onboarding_test_plan.md#test-cases) must be met
- Following tests will be run prior to system tests:
  - Transceiver presence check
  - Ensure active firmware is gold firmware (for non-DAC CMIS transceivers)
  - Link up verification
  - LLDP verification (if enabled)

## Attributes

A `system.json` file is used to define the attributes for the system tests for the various types of transceivers the system supports.  
Following table summarizes the key attributes:

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| verify_lldp_on_link_up | boolean | True | ✗ | dut | Whether to verify LLDP functionality when link comes up |
| port_shutdown_wait_sec | integer | 5 | ✗ | transceivers or platform_hwsku_overrides | Wait time after port shutdown before verification |
| port_startup_wait_sec | integer | 60 | ✗ | transceivers or platform_hwsku_overrides  | Wait time after port startup before link verification |
| port_toggle_iterations | integer | 100 | ✗ | transceivers or platform_hwsku_overrides | Number of iterations for port toggle stress test |
| port_toggle_delay_sec | integer | 2 | ✗ | transceivers or platform_hwsku_overrides | Delay between port toggle cycles |
| port_range_toggle_iterations | integer | 50 | ✗ | transceivers or platform_hwsku_overrides | Number of iterations for port range toggle stress test |
| port_range_test_ports | list | [] | ✗ | dut | List of specific ports to include in port range stress test. Empty list means use all available ports |
| port_range_startup_wait_sec | integer | 60 | ✗ | transceivers or platform_hwsku_overrides | Wait time after port range startup (may scale with transceiver count) |
| xcvrd_restart_settle_sec | integer | 120 | ✗ | HWSKU | Time to wait after xcvrd restart before checking link status |
| pmon_restart_settle_sec | integer | 120 | ✗ | HWSKU | Time to wait after pmon restart before verification |
| swss_restart_settle_sec | integer | 180 | ✗ | transceivers | Time to wait after swss restart before verification |
| syncd_restart_settle_sec | integer | 240 | ✗ | transceivers | Time to wait after syncd restart before verification |
| expect_pmon_restart_with_swss_or_syncd | boolean | False | ✗ | platform | Whether pmon restart is expected during swss/syncd restart |
| config_reload_settle_sec | integer | 300 | ✗ | transceivers | Time to wait after config reload before link status check |
| cold_reboot_settle_sec | integer | 400 | ✗ | transceivers | Time to wait after cold reboot before link status check |
| cold_reboot_iterations | integer | 5 | ✗ | transceivers | Number of iterations for cold reboot stress test |
| warm_reboot_supported | boolean | False | ✗ | platform or hwsku | Whether platform supports warm reboot functionality |
| warm_reboot_settle_sec | integer | 300 | ✗ | transceivers | Time to wait after warm reboot before verification |
| fast_reboot_supported | boolean | False | ✗ | platform or hwsku | Whether platform supports fast reboot functionality |
| fast_reboot_settle_sec | integer | 300 | ✗ | transceivers | Time to wait after fast reboot before verification |
| transceiver_reset_supported | boolean | True | ✗ | transceivers | Whether transceiver supports reset functionality |
| transceiver_reset_i2c_recover_sec | integer | 5 | ✗ | transceivers | Time to wait for I2C recovery after transceiver state changes (reset, low power mode) before verification |
| low_power_mode_supported | boolean | False | ✗ | transceivers | Whether transceiver supports low power mode |
| loopback_supported | boolean | False | ✗ | transceivers | Whether transceiver supports loopback functionality |
| supported_loopback_modes | list | [] | ✗ | transceivers | List of supported loopback modes (e.g., ["host-side-input", "media-side-input", "host-side-output", "media-side-output"]) |
| loopback_settle_sec | integer | 15 | ✗ | transceivers | Time to wait after loopback mode changes |
| low_pwr_request_hw_asserted | boolean | False | ✗ | platform | Whether to check DataPath state and LowPwrRequestHW signal. When True, expects LowPwrRequestHW signal to be asserted (1); when False, skips these checks |

## Test Cases

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

## Test Execution Guidelines

### Attribute Usage in Tests

- **Settle Time Attributes**: Used as maximum wait times before declaring test failure
- **Iteration Attributes**: Define the number of test cycles for stress testing
- **Boolean Attributes**: Control conditional test behavior and expectations
- **Scaling Attributes**: Adjust timeouts based on system characteristics (number of transceivers, platform type)

### Link Behavior Test Cases

The following tests aim to validate the link status and stability of transceivers under various conditions.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Port shutdown validation | 1. For each transceiver port individually, issue CLI command `config interface shutdown <port>`.<br>2. Wait for `port_shutdown_wait_sec` before confirming link down.<br>3. Validate link status using CLI configuration. | Ensure that the link goes down within the configured timeout period for each port. |
| 2 | Port startup validation | 1. For each transceiver port individually, issue CLI command `config interface startup <port>`.<br>2. Wait for `port_startup_wait_sec` and monitor link recovery.<br>3. Validate link status using CLI configuration.<br>4. If `verify_lldp_on_link_up` is True, verify port appears in LLDP table. | Ensure that the link is up within configured timeout and the port appears in the LLDP table when enabled for each port. |

### Process and Service Restart Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | xcvrd daemon restart impact | 1. Verify current link states to be up for all transceivers.<br>2. Restart xcvrd daemon: `sudo systemctl restart xcvrd`.<br>3. Wait for `xcvrd_restart_settle_sec` before verification.<br>4. Verify ports appear in LLDP table if `verify_lldp_on_link_up` is True. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table. Also ensure that xcvrd is up for at least `xcvrd_restart_settle_sec` seconds. |
| 2 | xcvrd restart with I2C errors | 1. Induce I2C errors in the system.<br>2. Restart xcvrd daemon: `sudo systemctl restart xcvrd`.<br>3. Monitor link behavior and system stability.<br>4. Wait for `xcvrd_restart_settle_sec` before verification.<br>5. Verify ports appear in LLDP table if enabled. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table even with I2C errors present. |
| 3 | xcvrd crash recovery test | 1. Modify xcvrd.py to raise an Exception and induce a crash.<br>2. Monitor automatic restart behavior.<br>3. Wait for `xcvrd_restart_settle_sec` before verification.<br>4. Verify ports appear in LLDP table if enabled. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table. Also ensure that xcvrd is up for at least 2 minutes. |
| 4 | pmon docker restart impact | 1. Verify current link states to be up for all transceivers.<br>2. Restart pmon container: `sudo systemctl restart pmon`.<br>3. Monitor transceiver monitoring and link behavior.<br>4. Wait for `pmon_restart_settle_sec` before verification.<br>5. Verify ports appear in LLDP table if enabled. | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table. |
| 5 | swss docker restart impact | 1. Verify current link states to be up for all transceivers.<br>2. Restart swss container: `sudo systemctl restart swss`.<br>3. Monitor link state transitions and recovery.<br>4. Wait for `swss_restart_settle_sec` before verification.<br>5. Check if `expect_pmon_restart_with_swss_or_syncd` is True and verify pmon restart accordingly.<br>6. Verify ports appear in LLDP table if enabled. | Ensure `xcvrd` restarts (based on `expect_pmon_restart_with_swss_or_syncd`) and the expected ports link up again, with port details visible in the LLDP table. |
| 6 | syncd process restart impact | 1. Verify current link states to be up for all transceivers.<br>2. Restart syncd: `sudo systemctl restart syncd`.<br>3. Monitor system recovery and link restoration.<br>4. Wait for `syncd_restart_settle_sec` before verification.<br>5. Check if `expect_pmon_restart_with_swss_or_syncd` is True and verify pmon restart accordingly.<br>6. Verify ports appear in LLDP table if enabled. | Ensure `xcvrd` restarts (based on `expect_pmon_restart_with_swss_or_syncd`) and the expected ports link up again, with port details visible in the LLDP table. |

### System Recovery Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Config reload impact | 1. Verify current link states to be up for all transceivers.<br>2. Execute `sudo config reload -y`.<br>3. Wait for `config_reload_settle_sec` and verify transceiver link restoration.<br>4. Verify ports appear in LLDP table if `verify_lldp_on_link_up` is True. | Ensure `xcvrd` restarts and the expected ports link up again, with port details visible in the LLDP table. |
| 2 | Cold reboot link recovery | 1. Verify current link states to be up for all transceivers.<br>2. Execute a cold reboot.<br>3. Wait for `cold_reboot_settle_sec` and monitor link recovery after reboot.<br>4. Verify ports appear in LLDP table if enabled. | Confirm the expected ports link up again post-reboot, with port details visible in the LLDP table. |
| 3 | Warm reboot link recovery | 1. Skip test if `warm_reboot_supported` is False.<br>2. Verify current link states to be up for all transceivers.<br>3. Perform warm reboot: `sudo reboot`.<br>4. Wait for `warm_reboot_settle_sec` and monitor link recovery after reboot.<br>5. Verify ports appear in LLDP table if enabled. | Ensure `xcvrd` restarts and maintains link stability for the interested ports, with their presence confirmed in the LLDP table. |
| 4 | Fast reboot link recovery | 1. Skip test if `fast_reboot_supported` is False.<br>2. Verify current link states to be up for all transceivers.<br>3. Perform fast reboot: `sudo fast-reboot`.<br>4. Wait for `fast_reboot_settle_sec` and monitor link establishment timing.<br>5. Verify ports appear in LLDP table if enabled. | Confirm the expected ports link up again post-reboot, with port details visible in the LLDP table. |

### Transceiver Event Handling Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver reset validation | 1. Skip test if `transceiver_reset_supported` is False.<br>2. Reset the transceiver using appropriate CLI command.<br>3. Wait for `transceiver_reset_i2c_recover_sec` to allow I2C recovery.<br>4. Verify port is linked down after reset and transceiver is in low power mode (if `low_power_mode_supported` is True).<br>5. If `low_pwr_request_hw_asserted` is True:<br>   a. Check DataPath is in DPDeactivated state.<br>   b. Verify LowPwrAllowRequestHW (page 0h, byte 26.6) is set to 1.<br>6. Issue shutdown command: `config interface shutdown <port>`.<br>7. Wait for `port_shutdown_wait_sec`.<br>8. Issue startup command: `config interface startup <port>`.<br>9. Wait for `port_startup_wait_sec` and verify link recovery.<br>10. Verify ports appear in LLDP table if `verify_lldp_on_link_up` is True. | Ensure that the port is linked down after reset and is in low power mode (if transceiver supports it). If `low_pwr_request_hw_asserted` is True, verify DataPath is in DPDeactivated state and LowPwrAllowRequestHW signal is asserted (set to 1). The shutdown and startup commands should re-initialize the port and bring the link up. |
| 2 | Transceiver low power mode validation | 1. Skip test if `low_power_mode_supported` is False.<br>2. Ensure transceiver is in high power mode initially.<br>3. Put the transceiver in low power mode using CLI command.<br>4. Wait for `transceiver_reset_i2c_recover_sec`.<br>5. Verify port is linked down and DataPath is in DPDeactivated state.<br>6. Verify transceiver is in low power mode through CLI.<br>7. Disable low power mode (restore to high power mode).<br>8. Wait for `transceiver_reset_i2c_recover_sec`.<br>9. Verify link is up and transceiver is in high power mode.<br>10. Verify ports appear in LLDP table if `verify_lldp_on_link_up` is True. | Ensure transceiver transitions correctly between high and low power modes. Port should be down in low power mode and up in high power mode. |

### Diagnostic Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver loopback validation | 1. Skip test if `loopback_supported` is False or `supported_loopback_modes` is empty.<br>2. For each loopback mode in `supported_loopback_modes`:<br>   a. Enable the loopback mode using CLI command.<br>   b. Wait for `loopback_settle_sec`.<br>   c. Verify loopback is active through CLI.<br>   d. Test data path functionality (use LLDP neighbor verification for host-side input loopback if applicable).<br>   e. Disable loopback mode.<br>   f. Wait for `loopback_settle_sec`.<br>   g. Verify normal operation is restored.<br>3. Verify ports appear in LLDP table if `verify_lldp_on_link_up` is True after all loopback tests. | Ensure that the various supported types of loopback work on the transceiver. The LLDP neighbor can also be used to verify the data path after enabling loopback (such as host-side input loopback). |

### Stress and Load Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Port startup/shutdown stress test | 1. In a loop, issue startup/shutdown command for `port_toggle_iterations` iterations (default 100 times) for 1 random port.<br>2. Use `port_toggle_delay_sec` delay between cycles.<br>3. Monitor system stability and link status validation.<br>4. Verify ports appear in LLDP table when links are up (if `verify_lldp_on_link_up` is True). | Ensure link status toggles to up/down appropriately with each startup/shutdown command. Verify ports appear in the LLDP table when the link is up. |
| 2 | Port range stress test | 1. Use ports from `port_range_test_ports` if specified, otherwise use all available transceiver ports.<br>2. Perform range shut and no-shut operations on the selected ports for `port_range_toggle_iterations` iterations.<br>3. Wait `port_range_startup_wait_sec` after each startup cycle. | System should handle concurrent port operations without instability. |
| 3 | Cold reboot stress test | 1. In a loop, execute cold reboot for `cold_reboot_iterations` consecutive times (default 5, can be configured to 100).<br>2. Wait `cold_reboot_settle_sec` after each reboot.<br>3. Verify link recovery and system stability after each iteration.<br>4. Verify ports appear in LLDP table if enabled. | Confirm the expected ports link up again post-reboot, with port details visible in the LLDP table for all iterations. |

## Pass/Fail Criteria

### Pass Criteria

- All links recover within their respective configured settle times (e.g., `xcvrd_restart_settle_sec`, `warm_reboot_settle_sec`)
- No system crashes or hangs during any test scenario
- Debug tools provide actionable information for troubleshooting
- State databases remain consistent throughout all operations
- All stress test iterations complete successfully within configured parameters
- LLDP functionality works correctly when `verify_lldp_on_link_up` is enabled
- Platform-specific behavior matches expectations (e.g., `expect_pmon_restart_with_swss_or_syncd`)
- Transceiver reset functionality works correctly when `transceiver_reset_supported` is enabled
- Low power mode transitions work correctly when `low_power_mode_supported` is enabled
- Loopback modes function correctly when `loopback_supported` is enabled and modes are specified

### Fail Criteria

- Link recovery takes longer than configured settle times for any test
- System crashes, hangs, or becomes unresponsive during any operation
- Data inconsistency between system components or state databases
- Debug tools fail to provide useful diagnostic information
- Memory leaks or significant performance degradation under stress testing
- Any stress test iteration fails to complete within expected parameters
- Unexpected process restarts when `expect_pmon_restart_with_swss_or_syncd` is False
- Transceiver reset does not properly transition to expected states
- Low power mode transitions fail or do not achieve expected power states
- Loopback modes fail to activate or do not properly restore normal operation

## Cleanup and Post-Test Verification

After test completion:

1. Verify all transceivers are in operational state
2. Check system logs for any unexpected errors or warnings
3. Verify all services and daemons are running normally
