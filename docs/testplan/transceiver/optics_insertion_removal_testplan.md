# Optics Insertion and Removal Test Plan

## Scope

This test plan outlines a comprehensive framework for testing the online insertion and removal (OIR) of CMIS compliant transceivers being onboarded to SONiC. It includes both physical OIR (where transceivers are physically inserted and removed) and remote reseat (where OIR is simulated using on-device command or script). The goal is to automate all tests listed in this document.

**Optics Scope**:
All the optics types mentioned in the [Transceiver Onboarding Test Plan](./test_plan.md#scope) are in scope for this test plan.

## Testbed Topology

Please refer to the [Testbed Topology](./test_plan.md#testbed-topology) section.

## Test Cases

**Pre-requisites for the Below Tests:**

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](./test_plan.md#test-cases) must be met.

2. `physical_oir.json` located in `ansible/files/transceiver/inventory` directory should be present to define the attributes for the physical OIR tests. The schema is defined in [Transceiver Onboarding Test Plan](./test_plan.md#test-cases). Following attributes are applicable here:

| Attribute | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| port_under_test | List | All | No | None|  A list under `dut.dut_name` containing the ports to be tested for physical OIR test.<br>This attribute must exist only under `dut` field. |
| oir_method | String | manual | No | dut | The method used for OIR ("manual" or "automated"). |
| physical_oir_timeout_min | Int | 30 | No | dut |  The timeout value in minutes to wait for the optics to be inserted/removed. |
| simultaneous_oir | Bool | False | No | dut |  A flag indicating whether to allow simultaneous OIR operations on multiple ports. |
| physical_oir_stress_iteration | Int | 5 | No | dut |  The number of iterations to stress test the physical OIR process. |
| monitor_kernel_errors | Bool | False | No | transceivers |  A flag indicating whether to monitor kernel errors during the test. |
| link_flap_monitor_timeout_sec | Int | 10 | No | transceivers | The duration in seconds to monitor for link flaps after OIR operations. |


3. `remote_reseat.json` located in `ansible/files/transceiver/inventory` directory should be present to define the attributes for the remote reseat tests. The schema is defined in [Transceiver Onboarding Test Plan](./test_plan.md#test-cases).

| Attribute | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| port_under_test | List | All | No | None | A list under `dut.dut_name` containing the ports to be tested for remote reseat test.<br>This attribute must exist only under `dut` field. | 
| remote_reseat_timeout_min | Int | 10 | No | transceivers | The timeout value in seconds to wait for the remote reseat process to complete. |
| remote_reseat_stress_iteration | Int | 5 | No | dut | The number of iterations to stress test the remote reseat process. |
| monitor_kernel_errors | Bool | False | No | transceivers | A flag indicating whether to monitor kernel errors during the test. |
| link_flap_monitor_timeout_sec | Int | 10 | No | transceivers | The duration in seconds to monitor for link flaps after remote reseat. |

4. `port_startup_wait_sec` attribute of the [transceiver system testplan](./system_test_plan.md#attributes) is to be used to get the wait time before checking the interface operational status after the optics insertion or remote reseat.

#### 1.1 Optics Insertion and Removal Testing

This section outlines the test cases for validating the insertion and removal of optics in SONiC. The state transitions and services' health are to be tested as a result of optics insertion and removal. The tests cover both physical OIR and remote reseat scenarios, ensuring that the system behaves correctly when optics are inserted or removed.

##### 1.1.1 Physical OIR Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Optics removal validation| 1. Physically remove the optical module under test.|1. Transceiver presence command should return "Not present" with exit code 0.<br>2. Transceiver eeprom command should return "SFP EEPROM not detected" with exit code 0.<br>3. DOM, VDM and PM (if applicable) values are returned as empty from the CLI.<br>4. Transceiver related db tables are not deleted.<br>5. Interface should go oper down.<br>6. Other interfaces on the device should stay up.<br>7. Peer port should go oper down.<br>8. Link flap count of the peer port should increase by 1.<br>9. Ensure that [transceiver info tables](#transceiver-info-tables) and [transceiver flag change tables](#transceiver-flag-change-tables) are updated correctly for the peer  port.<br>10. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>11. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Optics insertion validation| 1. Insert the optical module under test.|1. Transceiver presence command should return "Present" with exit code 0.<br>2. Transceiver eeprom show command should show the values as per the configuration file and with the exit code as 0.<br>3. Expected DOM, VDM and PM (if applicable) values should be present for the interface.<br>4. Interface should go oper up after `port_startup_wait_sec` seconds.<br>5. No link flaps are seen for `link_flap_monitor_timeout_sec` seconds.<br>6. Check that optics SI settings and media settings are as expected.<br>7. Verify that port appears in LLDP neighbor table and the LLDP neighbor information is correctly populated.<br>8. Ensure that [transceiver info tables](#transceiver-info-tables) and [transceiver flag change tables](#transceiver-flag-change-tables) are updated correctly for the local and the peer port.<br>9. Peer port should become oper up.<br>10. Link flap count of the peer port should increase by 1.<br>11. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>12. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 3 | Simultaneous Physical OIR | 1. Physically remove all optical modules under test simultaneously.<br>2. Physically insert all optical modules under test simultaneously.| 1. All the expected results from TC#1 for all ports under test.<br>2. All the expected results from TC#2 for all ports under test.|
| 4 | Physical OIR stress test| 1. Perform the physical OIR process `physical_oir_stress_iteration` times in quick succession.| 1. All the expected results from TC#2 after last insertion.|

> Note: List of transceiver related DB tables can be found at [transceiver related DB tables](https://github.com/sonic-net/sonic-platform-daemons/blob/master/sonic-xcvrd/xcvrd/xcvrd_utilities/xcvr_table_helper.py#L11C1-L46C40).

##### 1.1.2 Remote reseat Tests
Remote reseat involves simulating the insertion and removal of optical modules by resetting the optics and restarting the interface. This method is useful for testing the system's response to optics insertion and removal without physically handling the hardware.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Remote reseat test| 1. Perform the remote reseat on the module under test.|  1. Transceiver eeprom show command should show the values as per the configuration file with the exit code as 0.<br>2. Expected DOM, VDM and PM (if applicable) values should be present for the interface.<br>3. Interface should go oper up after `port_startup_wait_sec` seconds.<br>4. No link flaps are seen for `link_flap_monitor_timeout_sec` seconds<br>5. Check that optics SI settings and media settings are as expected.<br>6. Verify that port appears in LLDP neighbor table and the LLDP neighbor information is correctly populated.<br>7. Ensure that [transceiver info tables](#transceiver-info-tables) and [transceiver flag change tables](#transceiver-flag-change-tables) are updated correctly for the local and the peer port.<br>8. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>9. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Remote reseat stress test| 1. Perform the remote reseat process `remote_reseat_stress_iteration` times.| 1. All the expected results from TC#1 after the last remote reseat.|

##### Transceiver info tables
This table lists the transceiver related DB tables with the attributes that should be monitored during the physical OIR and remote reseat tests to ensure they are not deleted or corrupted.

| Table name | Attributes to Monitor |
|------------|----------------------|
| TRANSCEIVER INFO TABLE | cmis_rev, model, type, connector, manufacturer |
| TRANSCEIVER FIRMWARE INFO TABLE | active firmware |
| TRANSCEIVER DOM SENSOR TABLE | everything |
| TRANSCEIVER DOM FLAG TABLE | everything |
| TRANSCEIVER VDM REAL VALUE table | everything |
| TRANSCEIVER STATUS TABLE | everything |
| TRANSCEIVER STATUS FLAG TABLE | everything |
| APPL_DB | link related info, admin status, oper status, fec should be rs. |


##### Transceiver flag change tables
This table lists the transceiver flag change count DB tables that should be monitored during the physical OIR and remote reseat tests to ensure they are updated correctly.

| Table name |
|------------|
| TRANSCEIVER STATUS FLAG CHANGE COUNT |
| TRANSCEIVER DOM FLAG CHANGE COUNT |
| TRANSCEIVER VDM HALARM FLAG CHANGE COUNT |
| TRANSCEIVER VDM LALARM FLAG CHANGE COUNT |
| TRANSCEIVER VDM HWARN FLAG CHANGE COUNT |
| TRANSCEIVER VDM LWARN FLAG CHANGE COUNT |


## Physical OIR API

The Physical OIR API provides a set of functions for performing physical optical insertion and removal tests on the device under test (DUT). This API allows users to check OIR support status, perform optics insertion/removal operations, and clean up OIR resources.

A class named `PhysicalOIR` is defined under `tests.common.physical_oir` module. If the class can not be imported, the physical OIR tests are skipped. The class has following methods:

1. **Constructor Method**
   - Description: Initializes the PhysicalOIR class.
   - Parameters:
        - `duthost` : AnsibleHost object of the dut. Following attributes are fetched from the `duthost` object for further processing:
            - `port_under_test`: List of ports to be tested.
            - `tbinfo`: Testbed information
            - `physical_oir_timeout_min`: Timeout value in minutes for the OIR process.
            - `oir_method`: The method used for OIR ("manual" or "automated").
            - `simultaneous_oir`: A flag indicating whether to allow simultaneous OIR operations on multiple ports.

        - `ansible-adhoc` : Ansible adhoc fixture to send commands to perform OIR operations.
2. **is_available**
    - Description: Checks if the testbed supports physical OIR.
    - Parameters: None
    - Returns: Boolean indicating availability.

3. **insert_sfps**
    - Description: Inserts SFPs on the ports specified by the port_under_test attribute.
    - Parameters: None
    - Returns: True if insertion is successful, False otherwise.

4. **remove_sfps**
    - Description: Removes SFPs from the ports specified by the port_under_test attribute.
    - Parameters: None
    - Returns: True if removal is successful, False otherwise.

5. **cleanup**
    - Description: Cleans up resources used by the PhysicalOIR class.
    - Parameters: None
    - Returns: None

The `PhysicalOIR` class should look like below:

```python
# File tests/common/physical_oir.py
class PhysicalOir:
    def __init__(self, duthost, ansible_adhoc):
        # Initiate the class with required attributes
        pass

    def is_available(self) -> bool:
        # Check if physical OIR is supported in the testbed
        pass

    def insert_sfps(self) -> bool:
        # Insert SFPs on the ports specified by port_under_test attribute
        pass

    def remove_sfps(self) -> bool:
        # Remove SFPs from the ports specified by port_under_test attribute
        pass

    def cleanup(self):
        # Cleanup resources used by the PhysicalOIR class
        pass  
```

#### CLI commands

Refer to [CLI commands](./test_plan.md#cli-commands) section for the CLI commands used in the above test cases.