# Optics Insertion and Removal Test Plan

## Scope

This test plan outlines a comprehensive framework for testing the online insertion and removal (OIR) of CMIS compliant transceivers being onboarded to SONiC. It includes both physical OIR (where transceivers are physically inserted and removed) and remote reseat (where OIR is simulated using on-device command or script). The goal is to automate all tests listed in this document.

**Optics Scope**:
The test plan includes various optics types, such as:

- Active Optical Cables (AOC)
- Active Electrical Cables (AEC)
- DR8 optics
- Direct Attach Cables (DAC)
- Short Range/Long Range (SR/LR) optics
- Far Range (FR) optics
- ZR optics
- SONiC-supported breakout cables

**Optics Specifications**:
Tests will cover optics compliant with:

- CMIS
- C-CMIS
- SFF-8636
- SFF-8436
- SFF-8472

## Testbed Topology

Please refer to the [Testbed Topology](./transceiver_onboarding_test_plan.md#testbed-topology) section.

## Test Cases

**Pre-requisites for the Below Tests:**

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases) must be met.

2. `physical_oir_attributes.json` located in `ansible/files/transceiver/inventory` directory should be present to define the attributes for the physical OIR tests. The schema is defined in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases). Following attributes are applicable here:

| Attribute | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| port_under_test | List | All | No | None|  A list under `dut.dut_name` containing the ports to be tested for physical OIR test.<br>This attribute must exist only under `dut` field. |
| oir_method | String | manual | No | dut | The method used for OIR ("manual" or "automated"). |
| physical_oir_timeout | Int | 30 | No | dut |  The timeout value in minutes to wait for the optics to be inserted/removed. |
| simultaneous_oir | Bool | False | No | dut |  A flag indicating whether to allow simultaneous OIR operations on multiple ports. |
| physical_oir_stress_iteration | Int | 5 | No | dut |  The number of iterations to stress test the physical OIR process. |
| monitor_kernel_errors | Bool | False | No | transceivers |  A flag indicating whether to monitor kernel errors during the test. |
| link_flap_monitor_timeout | Int | 10 | No | transceivers | The duration in seconds to monitor for link flaps after OIR operations. |


3. `remote_reseat_attributes.json` located in `ansible/files/transceiver/inventory` directory should be present to define the attributes for the remote reseat tests. The schema is defined in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases).

| Attribute | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| port_under_test | List | All | No | None | A list under `dut.dut_name` containing the ports to be tested for remote reseat test.<br>This attribute must exist only under `dut` field. | 
| remote_reseat_timeout | Int | 10 | No | transceivers | The timeout value in seconds to wait for the remote reseat process to complete. |
| remote_reseat_stress_iteration | Int | 5 | No | dut | The number of iterations to stress test the remote reseat process. |
| monitor_kernel_errors | Bool | False | No | transceivers | A flag indicating whether to monitor kernel errors during the test. |
| link_flap_monitor_timeout | Int | 10 | No | transceivers | The duration in seconds to monitor for link flaps after remote reseat. |

#### 1.1 Optics Insertion and Removal Testing

This section outlines the test cases for validating the insertion and removal of optics in SONiC. The state transitions and services' health are to be tested as a result of optics insertion and removal. The tests cover both physical OIR and remote reseat scenarios, ensuring that the system behaves correctly when optics are inserted or removed.

##### 1.1.1 Physical OIR Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Optics removal validation| 1. Physically remove the optical module under test.| 1. Transceiver eeprom command should return "SFP EEPROM not detected" with exit code 0.<br>2. DOM, VDM and PM (if applicable) values are returned as empty from the CLI.<br>3. Transceiver related db tables are not deleted.<br>4. Interface should go oper down.<br>5.Other interfaces on the device should stay up.<br>6. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>7. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Optics insertion validation| 1. Insert the optical module under test.| 1. Transceiver eeprom show command should the values as per the configuration file with the exit code as 0.<br>2. Expected DOM, VDM and PM (if applicable) values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen for `link_flap_monitor_timeout` seconds.<br>5. Check that optics SI settings and media settings are as expected.<br>6. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>7. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 3 | Simultaneous Physical OIR | 1. Physically remove all optical modules under test simultaneously.<br>2. Physically insert all optical modules under test simultaneously.| 1. All the expected results from TC#1 for all ports under test.<br>2. All the expected results from TC#2 for all ports under test.|
| 4 | Physical OIR stress test| 1. Perform the physical OIR process `physical_oir_stress_iteration` times in quick succession.| 1. All the expected results from TC#2 after last insertion.|

> Note: List of transceiver related DB tables can be found at [transceiver related DB tables](https://github.com/sonic-net/sonic-platform-daemons/blob/master/sonic-xcvrd/xcvrd/xcvrd_utilities/xcvr_table_helper.py#L11C1-L46C40).

##### 1.1.2 Remote reseat Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Remote reseat test| 1. Perform the remote reseat on the module under test.|  1. Transceiver eeprom show command should the values as per the configuration file with the exit code as 0.<br>2. Expected DOM, VDM and PM (if applicable) values should be present for the interface.<br>3. Interface should go oper up.<br>4.No link flaps are seen for `link_flap_monitor_timeout` seconds<br>5. Check that optics SI settings and media settings are as expected.<br>6. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>7. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Remote reseat stress test| 1. Perform the remote reseat process `remote_reseat_stress_iteration` times.| 1. All the expected results from TC#4 after the last remote reseat.|

## Physical OIR API

The Physical OIR API provides a set of functions for performing physical optical insertion and removal tests on the device under test (DUT). This API allows users to initiate optics insertion/removal operations, monitor their progress, and retrieve results.

A class named `PhysicalOIR` is defined under `tests.platform_tests.transceiver.utils.physical_oir` module. If the class can not be imported, the physical OIR tests are skipped. The class has following methods:

1. **Constructor Method**
   - Description: Initializes the PhysicalOIR class.
   - Parameters:
     - `duthost` : AnsibleHost object of the dut.
     - `ports`: List of ports to be tested.
     - `timeout`: Timeout value in minutes for the OIR process.
     - `oir_method`: The method used for OIR ("manual" or "automated").

2. **initiate_insertion**
   - Description: Initiates the insertion process for the specified ports.
   - Parameters: None
   - Returns: None

3. **wait_for_insertion_complete**
    - Description: Waits for the insertion process to complete for the specified ports.
    - Parameters: None
    - Returns: True if the insertion process is complete, False otherwise.

4. **initiate_removal**
    - Description: Initiates the removal process for the specified ports.
    - Parameters: None
    - Returns: None

5. **wait_for_removal_complete**
    - Description: Waits for the removal process to complete for the specified ports.
    - Parameters: None
    - Returns: True if the removal process is complete, False otherwise.


#### CLI commands

Refer to [CLI commands](./transceiver_onboarding_test_plan.md#cli-commands) section for the CLI commands used in the above test cases.