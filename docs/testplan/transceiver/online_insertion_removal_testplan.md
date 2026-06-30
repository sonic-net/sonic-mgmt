# Online Insertion and Removal Test Plan

## Scope

This test plan outlines a comprehensive framework for testing the online insertion and removal (OIR) of CMIS compliant transceivers being onboarded to SONiC. It includes both physical OIR (where transceivers are physically inserted and removed) and remote reseat (where OIR is simulated using on-device command or script). The goal is to automate all tests listed in this document.

**Optics Scope**:
All the optics types mentioned in the [Transceiver Onboarding Test Plan](./test_plan.md#scope) are in scope for this test plan.

## Testbed Topology

Please refer to the [Testbed Topology](./test_plan.md#testbed-topology) section.

## Test Cases

**Pre-requisites for the Below Tests:**

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](./test_plan.md#test-prerequisites-and-configuration-files) must be met.

2. `physical_oir.json` files under `ansible/files/transceiver/inventory/attributes/physical_oir` directory are used to define the attributes for the physical OIR tests. Per-PN body contains transceiver specific defaults, while DUT specific overrides are defined in the category-level shard; see [File Organization](test_plan.md#file-organization) for the shard contract. Following attributes are applicable here:

| Attribute | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| ports_under_test | List | [] | No | dut |  A list under `dut.dut_name` containing the indices of physical ports to be tested for physical OIR test.<br>This attribute must exist only under `dut` field. |
| oir_method | String | manual | No | dut | The method used for OIR ("manual", "pseudo" or "automated"). |
| physical_oir_timeout_min | Int | 30 | No | dut |  The timeout value in minutes to wait for the optics to be inserted/removed. |
| simultaneous_oir | Bool | False | No | dut |  A flag indicating whether to allow simultaneous OIR operations on multiple ports. |
| physical_oir_stress_iteration | Int | 5 | No | dut |  The number of iterations to stress test the physical OIR process. |
| monitor_kernel_errors | Bool | False | No | transceivers |  A flag indicating whether to monitor kernel errors during the test. |
| link_flap_monitor_timeout_sec | Int | 10 | No | transceivers | The duration in seconds to monitor for link flaps after OIR operations. |

>**Note:** In the manual `oir_method`, the user is expected to physically insert or remove the transceivers when prompted by the test script on the terminal. In the pseudo `oir_method`, the test script simulates the insertion and removal of transceivers using platform-specific commands/tools. In the automated `oir_method`, the insertion and removal occur unattended. The test script automatically performs the insertion and removal of transceivers using the appropriate commands, scripts or tools. We plan to implement the code for the manual `oir_method`. 

3. `remote_reseat.json` files under `ansible/files/transceiver/inventory/attributes/remote_reseat` directory are used to define the attributes for the remote reseat tests. Per-PN body contains transceiver specific defaults, while DUT specific overrides are defined in the category-level shard; see [File Organization](test_plan.md#file-organization) for the shard contract. Following attributes are applicable here:

| Attribute | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| ports_under_test | List | [] | No | dut | A list under `dut.dut_name` containing the indices of physical ports to be tested for remote reseat test.<br>This attribute must exist only under `dut` field. | 
| remote_reseat_timeout_min | Int | 10 | No | transceivers | The timeout value in minutes to wait for the remote reseat process to complete. |
| remote_reseat_stress_iteration | Int | 5 | No | dut | The number of iterations to stress test the remote reseat process. |
| monitor_kernel_errors | Bool | False | No | transceivers | A flag indicating whether to monitor kernel errors during the test. |
| link_flap_monitor_timeout_sec | Int | 10 | No | transceivers | The duration in seconds to monitor for link flaps after remote reseat. |

4. `port_startup_wait_sec` attribute of the [transceiver system testplan](./system_test_plan.md#attributes) is to be used to get the wait time before checking the interface operational status after the optics insertion or remote reseat.

#### 1.1 Online Insertion and Removal Testing

This section outlines the test cases for validating the insertion and removal of optics in SONiC. The state transitions and services' health are to be tested as a result of optics insertion and removal. The tests cover both physical OIR and remote reseat scenarios, ensuring that the system behaves correctly when optics are inserted or removed.

##### 1.1.1 Physical OIR Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Optics removal validation| 1. Physically remove the optical module under test.|1. Show transceiver presence and sfputil presence commands should return "Not present" with exit code 0.<br>2. Show transceiver eeprom, show transceiver info and sfputil eeprom commands should return "SFP EEPROM not detected" with exit code 0.<br>3. DOM, VDM and PM (if applicable) values are returned as empty from the CLI.<br>4. Interface should go oper down.<br>5. Other interfaces on the device should stay up.<br>6. Peer port should go oper down.<br>7. Link flap count of the local port and the peer ports should increase by 1.<br>8. Ensure that [transceiver state tables](#transceiver-state-tables) and [transceiver flag change tables](#transceiver-flag-tables) are updated correctly for the local and the peer ports.<br>9. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>10. Critical process such as `xcvrd`, `syncd`, `orchagent` does not crash/restart. |
| 2 | Optics insertion validation| 1. Insert the optical module under test.|1. Show transceiver presence and sfputil presence commands should return "Present" with exit code 0.<br>2. Show transceiver eeprom, show transceiver info and sfputil eeprom commands should show the values as per the configuration file and with the exit code as 0.<br>3. No link flaps are seen for `link_flap_monitor_timeout_sec` seconds.<br>4. Check if the port has recovered as per [system test plan](./system_test_plan.md#standard-port-recovery-and-verification-procedure).<br>5. Ensure that [transceiver state tables](#transceiver-state-tables) and [transceiver flag change tables](#transceiver-flag-tables) are updated correctly for the local and the peer ports.<br>6. Peer port should become oper up.<br>7. Link flap count of the peer port should increase by 1.<br>8. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set. |
| 3 | Simultaneous Physical OIR | Perform the following steps if `simultaneous_oir` attribute is `True`. Skip the test otherwise.<br>1. Physically remove all optical modules under test simultaneously.<br>2. Physically insert all optical modules under test simultaneously.| 1. All the expected results from TC#1 for all ports under test.<br>2. All the expected results from TC#2 for all ports under test.|
| 4 | Physical OIR stress test| 1. Perform the physical OIR process `physical_oir_stress_iteration` times in quick succession.| 1. All the expected results from TC#2 after last insertion.|

> Note: List of transceiver related DB tables can be found at [transceiver related DB tables](https://github.com/sonic-net/sonic-platform-daemons/blob/33c0d5e8236d99f870136731a2c3914888207749/sonic-xcvrd/xcvrd/xcvrd_utilities/xcvr_table_helper.py#L11-L47).

##### 1.1.2 Remote reseat Tests
Remote reseat involves simulating the insertion and removal of optical modules by resetting the optics and restarting the interface. This method is useful for testing the system's response to optics insertion and removal without physically handling the hardware.

To perform remote reseat on a module, following steps are taken in a sequential order:
| Step No. | Step | Expected Result |
|------|------|------------------|
|1 | Issue CLI command to disable DOM monitoring | Ensure that the DOM monitoring is disabled for the port |
|2 | Issue CLI command to shutdown the port | Ensure that the port is linked down |
|3 | Reset the transceiver followed by a sleep for 5s | Ensure reset command executes successfully |
|4 | Put transceiver in low power mode (if LPM supported) | Ensure that the port is in low power mode |
|5 | Put transceiver in high power mode (if LPM supported) | Ensure that the port is in high power mode |
|6 | Issue CLI command to startup the port | Ensure that the port is linked up and is seen in the LLDP table |
|7 | Issue CLI command to enable DOM monitoring for the port | Ensure that the DOM monitoring is enabled for the port |

The following table lists the test cases for validating the remote reseat of optics in SONiC.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Remote reseat test| 1. Perform the remote reseat on the module under test.|  1. Show transceiver eeprom and sfputil eeprom commands should show the values as per the configuration file with the exit code as 0.<br>2. Expected DOM, VDM and PM (if applicable) values should be present for the interface.<br>3. Interface should go oper up after `port_startup_wait_sec` seconds.<br>4. No link flaps are seen for `link_flap_monitor_timeout_sec` seconds<br>5. Check that optics SI settings and media settings are as expected.<br>6. Verify that port appears in LLDP neighbor table and the LLDP neighbor information is correctly populated.<br>7. Ensure that [transceiver state tables](#transceiver-state-tables) and [transceiver flag change tables](#transceiver-flag-tables) are updated correctly for the local and the peer ports.<br>8. Check that kernel has no error messages in syslog if `monitor_kernel_errors` flag is set.<br>9. Critical process such as `xcvrd`, `syncd`, `orchagent` does not crash/restart. |
| 2 | Remote reseat stress test| 1. Perform the remote reseat process `remote_reseat_stress_iteration` times.| 1. All the expected results from TC#1 after the last remote reseat.|



##### Transceiver state tables
This table lists the transceiver related DB tables with the attributes that should be monitored during the physical OIR and remote reseat tests to ensure they are updated correctly.

###### Local port tables to monitor after insertion
| DB Name | Table Name(s) | Attributes to Monitor |
|---------|---------------|-----------------------|
| APPL_DB | PORT_TABLE | link related info, admin status, oper status, fec. |
| STATE_DB | TRANSCEIVER_DOM_* | everything |
| STATE_DB | TRANSCEIVER_FIRMWARE_INFO | active firmware |
| STATE_DB | TRANSCEIVER_INFO | cmis_rev, model, type, connector, manufacturer |
| STATE_DB | TRANSCEIVER_PM | everything if applicable |
| STATE_DB | TRANSCEIVER_STATUS | everything |
| STATE_DB | TRANSCEIVER_STATUS_FLAG* | everything |
| STATE_DB | TRANSCEIVER_STATUS_SW | Should be updated with `{'cmis_state': 'READY', 'status': '1', 'error': 'N/A'}`|
| STATE_DB | TRANSCEIVER_VDM_* | everything |


##### Local port tables to monitor after removal
| DB Name | Table Name(s) | Table Status |
|---------|---------------|--------------|
| APPL_DB | PORT_TABLE | link related info, admin status, oper status should be updated. |
| STATE_DB | TRANSCEIVER_DOM_* | Deleted |
| STATE_DB | TRANSCEIVER_FIRMWARE_INFO | Deleted |
| STATE_DB | TRANSCEIVER_INFO | Deleted |
| STATE_DB | TRANSCEIVER_PM | Deleted |
| STATE_DB | TRANSCEIVER_STATUS | Deleted |
| STATE_DB | TRANSCEIVER_STATUS_FLAG* | Deleted |
| STATE_DB | TRANSCEIVER_STATUS_SW | Should be updated with `{'cmis_state': 'REMOVED', 'status': '0', 'error': 'N/A'}`|
| STATE_DB | TRANSCEIVER_VDM_* | Deleted |


##### Peer port tables to monitor after insertion or removal
| DB Name | Table Name(s) | Attributes to Monitor |
|---------|---------------|-----------------------|
| APPL_DB | PORT_TABLE | link related info, oper status, flap count |
| STATE_DB | TRANSCEIVER_DOM_SENSOR | Rx power |
| STATE_DB | TRANSCEIVER_PM | Rx related metrics if applicable |
| STATE_DB | TRANSCEIVER_STATUS_FLAG_* | Rx related fields |
| STATE_DB | TRANSCEIVER_VDM_* | Rx related metrics if applicable |
 

##### Transceiver flag tables
This table lists the transceiver flag tables in STATE_DB. All the relevant fields of these tables for the local and the peer ports should be monitored during the physical OIR and remote reseat tests to ensure they are updated correctly.

| Table name |
|------------|
| TRANSCEIVER_STATUS_FLAG* |
| TRANSCEIVER_DOM_FLAG* |
| TRANSCEIVER_VDM_HALARM_FLAG* |
| TRANSCEIVER_VDM_LALARM_FLAG* |
| TRANSCEIVER_VDM_HWARN_FLAG* |
| TRANSCEIVER_VDM_LWARN_FLAG* |


## Physical OIR API

The Physical OIR API provides a set of functions for performing physical optical insertion and removal tests on the device under test (DUT). This API allows users to check OIR support status, perform optics insertion/removal operations, and clean up OIR resources. This API is needed to abstract the physical OIR operations for all OIR methods (manual, pseudo and automated) and provide a consistent interface for the test cases to interact with the underlying OIR mechanisms, regardless of the specific hardware or platform being tested.

A class named `PhysicalOir` is defined under `tests.common.physical_oir` module. If the class cannot be imported, the physical OIR tests are skipped. The class has following methods:

1. **Constructor Method**
   - Description: Initializes the PhysicalOir class.
   - Parameters:
        - `duthost` : AnsibleHost object of the dut.
        - `ansible-adhoc` : Ansible adhoc fixture to send commands to perform OIR operations.
        - `port_attributes_dict`: A dictionary containing the port test attributes defined in `physical_oir.json` file.  Following attributes are fetched from the `port_attributes_dict` object for further processing:
            - `ports_under_test`: List of ports to be tested.
            - `physical_oir_timeout_min`: Timeout value in minutes for the OIR process.
            - `oir_method`: The method used for OIR ("manual", "pseudo" or "automated").
            - `simultaneous_oir`: A flag indicating whether to allow simultaneous OIR operations on multiple ports.

2. **is_available**
    - Description: Checks if the testbed supports physical OIR.
    - Parameters: None
    - Returns: Boolean indicating availability.

3. **insert_sfps**
    - Description: Inserts SFPs on the ports specified by the ports_under_test attribute.
    - Parameters: None
    - Returns: None when the operation is complete.

4. **remove_sfps**
    - Description: Removes SFPs from the ports specified by the ports_under_test attribute.
    - Parameters: None
    - Returns: None when the operation is complete.

5. **cleanup**
    - Description: Cleans up resources used by the PhysicalOir class.
    - Parameters: None
    - Returns: None

The `PhysicalOir` class should look like below:

```python
# File tests/common/physical_oir.py
class PhysicalOir:
    def __init__(self, duthost, ansible_adhoc, port_attributes_dict):
        # Initiate the class with required attributes

    def is_available(self) -> bool:
        # Check if physical OIR is supported in the testbed

    def insert_sfps(self) -> None:
        # Insert SFPs on the ports specified by the ports_under_test attribute

    def remove_sfps(self) -> None:
        # Remove SFPs from the ports specified by the ports_under_test attribute

    def cleanup(self) -> None:
        # Cleanup resources used by the PhysicalOir class
```

#### CLI commands

Refer to [CLI commands](./test_plan.md#cli-commands) section for the CLI commands used in the above test cases.
