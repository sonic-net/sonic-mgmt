# SmartSwitch PMON Test Plan

- [Introduction](#introduction)
- [Scope](#scope)C
- [Definitions and Abbreviations](#definitions-and-abbreviations)
- [Test Cases](#test-cases)
    - [1.1 Check SmartSwitch specific ChassisClass APIs](#11-check-smartswitch-chassis-apis)
    - [1.2 Check modified ChassisClass APIs](#12-check-modified-chassis-apis)
    - [1.3 Check DpuModule APIs for SmartSwitch](#13-check-dpu-module-apis)
    - [1.4 Check modified ModuleClass APIs](#14-check-modified-module-apis)
    - [1.5 Check SwitchModule APIs for SmartSwitch](#15-check-switch-module-apis)
    - [1.6 Check the show reboot-cause CLI on the DPU](#16-check-dpu-reboot-cause-cli)
    - [1.7 Check the show reboot-cause history CLI on the DPU](#17-check-dpu-reboot-cause-history-cli)
    - [1.8 Check the show reboot-cause CLI on the SWITCH](#18-check-switch-reboot-cause-cli)
    - [1.9 Check the show reboot-cause history CLI on the SWITCH](#19-check-switch-reboot-cause-history-cli)
    - [1.10 Check the show system-health summary CLI on the SWITCH](#110-check-switch-system-health-summary-cli)
    - [1.11 Check the show system-health monitor-list CLI on the SWITCH](#111-check-switch-system-health-monitorlist-cli)
    - [1.12 Check the show system-health detail CLI on the SWITCH](#112-check-switch-system-health-detail-cli)
    - [1.13 Check the show system-health dpu DPUx CLI on the SWITCH](#113-check-dpu-state-cli)
    - [1.14 Check the cold startup of the DPUs and SWITCH](#114-check-startup-config)
    - [1.15 Check the startup config CLI](#115-check-startup-config-cli)
    - [1.16 Check the shutdown config CLI](#116-check-shutdown-config-cli)
    - [1.17 Check the reboot config CLI](#117-check-reboot-config-cli)

## Introduction

The purpose is to test the SONiC PMON functionality of SmartSwitch platform.

## Scope

The primary goal is to cover SmartSwitch specific PMON APIs. The corresponding CLIs and remaining SmartSwitch life cycle management related functions are covered in the "DPU-test-plan.md"

## Definitions and Abbreviations

| **Term**   | **Meaning**                              |
| ---------- | ---------------------------------------- |
| DPU       | Data Processing Unit       |
| NPU       | Network Processing Unit       |
| SWITCH    | Refers to NPU and the anything other than DPUs    |
| SS        | SmartSwitch       |


## Objectives of Test Cases

|    | **Test Case**   | **Intention**                              |
| ---------- | ---------- | ---------------------------------------- |
| 1.1 | Check SmartSwitch specific ChassisClass APIs      | To verify the newly implemented SmartSwitch specific ChassisClass APIs |
| 1.2 | Check modified ChassisClass APIs for SmartSwitch       |  To verify the existing ChassisClass APIs that undergo minor changes with the addition of SmartSwitch|
| 1.3 | Check DpuModule APIs for SmartSwitch       |  To verify the newly implemented  DpuModule APIs for SmartSwitch|
| 1.4 | Check modified ModuleClass APIs for SmartSwitch       |  To verify the existing ModuleClass APIs that undergo minor changes with the addition of SmartSwitch|
| 1.5 | Check SwitchModule APIs for SmartSwitch       |  To verify the newly implemented  SwitchModule APIs for SmartSwitch|
| 1.6 | Check the show reboot-cause CLI on the DPU       |  To verify the reboot-cause CLI on the DPU is unaffected |
| 1.7 | Check the show reboot-cause history CLI on the DPU       |  To verify the reboot-cause history CLI on the DPU is unaffected|
| 1.8 | Check the show reboot-cause CLI on the SWITCH       |  To verify the reboot-cause CLI on the SWITCH is unaffected and the new extensions of the CLI work as intended|
| 1.9 | Check the show reboot-cause history CLI on the SWITCH       |  To verify the reboot-cause history CLI on the SWITCH is unaffected and the new extensions of the CLI work as intended|
| 1.10 | Check the show system-health summary CLI on the SWITCH       |  To verify the new extensions such as "all, SWITCH, DPUx" of the show system-health summary" CLI work as expected |
| 1.11 | Check the show system-health monitor-list CLI on the SWITCH        |  To verify the new extensions such as "all, SWITCH, DPUx" of the show system-health monitor-list" CLI work as expected|
| 1.12 | Check the show system-health detail CLI on the SWITCH       |  To verify the new extensions such as "all, SWITCH, DPUx" of the show system-health detail" CLI work as expected|
| 1.13 | Check the show system-health dpu DPUx CLI on the SWITCH       |  To verify the newly implemented  show system-health dpu DPUx CLI for SmartSwitch reflects the midplane, control-plane, data-plane states of the DPU|
| 1.14 | Check the cold startup of the DPUs and SWITCH       |  To verify the "chassisd", "chassis instance o database" are created and the admin state of the DPUs as defined in the config_db.json are applied properly |
| 1.15 |  Check the startup config CLI       |  To verify the "config chassis modules startup DPUx" CLI does startup the DPU|
| 1.16 | Check the shutdown config CLI        |   To verify the "config chassis modules shutdown DPUx" CLI does shutdown the DPU|
| 1.17 | Check the reboot config CLI       |  To verify the "config chassis modules reboot SWITCH " CLI does reboot the SWITCH|

## Test Cases


### 1.1 Check SmartSwitch specific ChassisClass APIs

#### Steps
 * Execute the following CLIs on SmartSwitch
 * get_dpu_id(self, name):
    * Provide DPU0-DPU7
    * This API should return 1-8 for DPU0-DPU7
 * is_smartswitch(self):
    * This API should return True
 * get_module_dpu_data_port(self, index):
    * For index: 1 will return the dup0 port association which is "Ethernet224: Ethernet0" where the string left of ":" (Ethernet224) is the NPU port and the string right of ":" (Ethernet0) is the DPU port.
 

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:
    get_dpu_id(self, DPU3)
    Output: 4

    is_smartswitch(self):
    Output: True

    get_module_dpu_data_port(self, DPU0):
    Output: "Ethernet224: Ethernet0"

```
#### Pass/Fail Criteria
 *  The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output".


### 1.2 Check modified ChassisClass APIs for SmartSwitch

#### Steps
 * is_modular_chassis(self):
    * Should return False
 * get_num_modules(self):
    * Should return number of DPUs + 1 switch
 * get_module(self, index):
    * Make sure for each index this API returns an object and has some content and not None
 * get_all_modules(self):
    * This should return a list of items
 * get_module_index(self, module_name):
    * Given the module name say “DPU0” should return the index of it “1”
 

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:
    is_modular_chassis(self):
    Output: False

    get_num_modules(self):
    Output: number of DPUs + 1

    get_module(self, DPU0):
    Output: DPU0 object

    get_all_modules(self):
    Output: list of objects (one per DPU + 1 switch object)

    get_module_index(self, DPU0):
    Output: could be any value from 0 to modules count -1
```
#### Pass/Fail Criteria
 * The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output"

### 1.3 Check DpuModule APIs for SmartSwitch

#### Steps
 * get_dpu_id(self):
    * Should return ID of the DpuModule Ex: 1 on DPU0
 * get_reboot_cause(self):
    * Reboot the module and then execute the "show reboot-cause ..." CLIs
    * Verify the output string shows the correct Time and Cause
    * Limit the testing to software reboot
 * get_state_info(self):
    * This should return an object
    * Stop one of the DPU containers on this DPU
    * Execute the CLI and check the dpu-controlplane value should be down
 * get_health_info(self):
    * This should return an object
    * Stop one of the DPU containers on this DPU
    * Execute the CLI and check if the health shows the stopped container
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:
    get_dpu_id(self):
    Output: When on module DPUx should return x+1

    get_reboot_cause(self):
    Output: {"Device": "DPU0", "Name": 2024_05_31_00_33_30, "Cause":  "reboot", "Time": "Fri 31 May 2024 12:29:34 AM UTC", "User": "NA", "Comment": "NA"}

    get_state_info(self):
    Output: dpu state info object

    get_health_info(self):
    Output: dpu health info object

```
#### Pass/Fail Criteria
 * Verify that all the APIs mentioned return the expected output

### 1.4 Check modified ModuleClass APIs

#### Steps
 * get_base_mac(self):
    * Should return the base mac address of this DPU
    * Read all DPUs mac and verify if they are unique and not None
 * get_system_eeprom_info(self):
    * Verify the returned dictionary key:value
 * get_name(self):
    * Verify if this API returns “DPU0” to “DPU7” on each of them
 * get_description(self):
    * Should return a string
 * get_type(self):
    * Should return “DPU” which is “MODULE_TYPE_DPU”
 * get_oper_status(self):
    * Should return the operational status of the DPU
    * Stop one ore more containers
    * Execute the CLI and see if it is down
 * reboot(self, reboot_type):
    * Issue this CLI with input “MODULE_REBOOT_DEFAULT”
    * verify if the module reboots
 * get_midplane_ip(self):
    * should return the midplane IP

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:
    get_base_mac(self):
    Output: BA:CE:AD:D0:D0:01

    get_system_eeprom_info(self):
    Output: eeprom info object

    get_name(self):
    Output: DPU2

    get_description(self):
    Output "Pensando DSC"

    get_type(self):
    Output: DPU

    get_oper_status(self):
    Output: Online

    reboot(self, reboot_type):
    Result: the DPU should reboot

    get_midplane_ip(self):
    Output: 169.254.200.1

```
#### Pass/Fail Criteria
 *  The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output".

### 1.5 Check SwitchModule APIs for SmartSwitch
* This includes the appropriate new and modified ChassisClass and ModuleClass APIs 

#### Steps
 * get_dpu_id(self, name):
    * Provide “SWITCH”
    * Should return 0
 * is_smartswitch(self):
    * This API should return True
 * get_module_dpu_port(self, index):
    * For index 0 should return None
 * get_base_mac(self):
    * Should return the base mac address of the switch
 * get_system_eeprom_info(self):
    * Verify the returned dictionary key:value
 * get_name(self):
    * Verify if this API returns “SWITCH”
 * get_description(self):
    * Should return a string
 * get_type(self):
    * Should return “SWITCH” which is “MODULE_TYPE_SWITCH”
 * get_oper_status(self):
    * Should return the operational status of the DPU
    * Stop one ore more containers
    * Execute the CLI and see if it is down
 * reboot(self, reboot_type):
    * Issue this CLI with input “MODULE_REBOOT_DEFAULT”
    * verify if the chassis is rebooted
 * get_midplane_ip(self):
    * should return the midplane IP of the switch

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:
    get_dpu_id(self, SWITCH)
    Output: 0

    is_smartswitch(self):
    Output: True

    get_module_dpu_data_port(self, DPU0):
    Output: None

    get_base_mac(self):
    Output: AA:CE:DD:D0:D0:78

    get_system_eeprom_info(self):
    Output: eeprom info object

    get_name(self):
    Output: SWITCH

    get_description(self):
    Output "Cisco 28x400G QSFPDD DPU-Enabled 2RU Smart Switch,Open SW"

    get_type(self):
    Output: SWITCH

    get_oper_status(self):
    Output: Online

    reboot(self, reboot_type):
    Result: the Chassis should reboot

    get_midplane_ip(self):
    Output: 169.254.200.254

```
#### Pass/Fail Criteria
 *  The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output".
 
 
### 1.6 Check the show reboot-cause CLI on the DPU

#### Steps
 * reboot the DPU
 * issue the CLI “show reboot-cause” on the DPU
 * verify the returned content’s time and cause
 
#### Verify in
 * DPU
   
#### Sample Output
```
On DPU: “show reboot-cause”
Unknown
```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error

### 1.7 Check the show reboot-cause history CLI on the DPU

#### Steps
 * reboot the DPU a few times
 * issue the CLI “show reboot-cause history” on the DPU
 * verify the returned contents show all the reboot events time and cause
 
#### Verify in
 * DPU
   
#### Sample Output
```
On DPU: “show reboot-cause history”
TBD: show the DPU output
```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error as shown
 
### 1.8 Check the show reboot-cause CLI on the SWITCH

#### Steps
 * reboot the SWITCH
 * issue the CLI “show reboot-cause” on the SWITCH
 * verify the returned content’s time and cause
 * issue the cli extension for smartswitch which is “show reboot-cause all”
 * verify the returned output has the DPU modules's reboot-cause as well
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show reboot-cause”
Output: User issued 'reboot' command [User: cisco, Time: Fri 31 May 2024 12:29:34 AM UTC]

On Switch: “show reboot-cause all”

Device    Name                 Cause    Time                             User
--------  -------------------  -------  -------------------------------  ------
SWITCH    2024_05_31_00_33_30  reboot   Fri 31 May 2024 12:29:34 AM UTC  cisco

```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error

### 1.7 Check the show reboot-cause history CLI on the SWITCH

#### Steps
 * reboot the SWITCH a few times
 * issue the CLI “show reboot-cause history” on the SWITCH
 * verify the returned contents show all the reboot events time and cause
 * issue the cli extension for smartswitch which is “show reboot-cause history all”
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show reboot-cause history”

Name                 Cause       Time                             User    Comment
-------------------  ----------  -------------------------------  ------  ---------
2024_05_31_00_33_30  reboot      Fri 31 May 2024 12:29:34 AM UTC  cisco   N/A
2024_05_30_05_09_36  reboot      Thu May 30 05:04:00 UTC 2024     cisco   N/A
2024_05_24_19_50_39  reboot      Fri 24 May 2024 07:45:40 PM UTC  cisco   N/A
2024_05_24_04_13_41  Power Loss  N/A                              N/A     Unknown
2024_05_22_21_51_18  Power Loss  N/A                              N/A     Unknown
2024_05_22_19_08_52  reboot      Wed 22 May 2024 07:03:16 PM UTC  cisco   N/A

On Switch: “show reboot-cause history SWITCH”

Device    Name                 Cause       Time                             User    Comment
--------  -------------------  ----------  -------------------------------  ------  ---------
SWITCH    2024_05_31_00_33_30  reboot      Fri 31 May 2024 12:29:34 AM UTC  cisco   N/A
SWITCH    2024_05_30_05_09_36  reboot      Thu May 30 05:04:00 UTC 2024     cisco   N/A
SWITCH    2024_05_24_21_13_52  reboot      Fri 24 May 2024 09:08:56 PM UTC  cisco   N/A
SWITCH    2024_05_24_20_59_48  reboot      Fri 24 May 2024 08:54:50 PM UTC  cisco   N/A
SWITCH    2024_05_24_19_50_39  reboot      Fri 24 May 2024 07:45:40 PM UTC  cisco   N/A
SWITCH    2024_05_24_04_13_41  Power Loss  N/A                              N/A     Unknown

On Switch: “show reboot-cause history all"
Device    Name                 Cause       Time                             User    Comment
--------  -------------------  ----------  -------------------------------  ------  ---------
SWITCH    2024_05_31_00_33_30  reboot      Fri 31 May 2024 12:29:34 AM UTC  cisco   N/A
SWITCH    2024_05_30_05_09_36  reboot      Thu May 30 05:04:00 UTC 2024     cisco   N/A
SWITCH    2024_05_24_19_50_39  reboot      Fri 24 May 2024 07:45:40 PM UTC  cisco   N/A
SWITCH    2024_05_24_04_13_41  Power Loss  N/A                              N/A     Unknown

```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error as shown

### 1.10 Check the show system-health summary CLI on the SWITCH

#### Steps
 * Issue this CLI “show system-health summary" on the switch
 * Verify the health is reflected properly
 * Test all, switch, DPU0 options by issuing “show system-health summary \<options\>”
 * Verify the health is reflected properly for the given module
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show system-health summary"
Output: TBD

On Switch: “show system-health summary DPU0"

On Switch: “show system-health summary SWITCH"

On Switch: “show system-health summary all"
```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error

### 1.11 Check the show system-health monitor-list CLI on the SWITCH

#### Steps
 * Issue this CLI “show system-health monitor-list" on the switch
 * Verify the health is reflected properly
 * Test all, switch, DPU0 options by issuing “show system-health monitor-list \<options\>”
 * Verify the health is reflected properly for the given module
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show system-health monitor-list"
Output: TBD

On Switch: “show system-health monitor-list DPU0"

On Switch: “show system-health monitor-list SWITCH"

On Switch: “show system-health monitor-list all"
```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error

### 1.12 Check the show system-health detail CLI on the SWITCH

#### Steps
 * Issue this CLI “show system-health detail" on the switch
 * Verify the health is reflected properly
 * Test all, switch, DPU0 options by issuing “show system-health detail \<options\>”
 * Verify the health is reflected properly for the given module
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show system-health detail"
Output: TBD

On Switch: “show system-health detail DPU0"

On Switch: “show system-health detail SWITCH"

On Switch: “show system-health detail all"
```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error

### 1.13 Check the show system-health dpu DPUx CLI on the SWITCH

#### Steps
 * Issue this CLI “show system-health dpu DPU0" on the switch
 * Verify the DPU0 state information
 * Check the midplane state, control-plane state, data-plane state
 * Alter the control-plane state, data-plane of the DPU by causing a container failure and pipeline failure respectively
 * Verify the state changes get reflected
 * TBD: midplane state
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show system-health dpu DPU0"
Output: TBD

```
#### Pass/Fail Criteria
 *  A proper output should be delayed without any error

### 1.14 Check the cold startup of the DPUs and SWITCH

#### Steps
 * Set the config_db.json such that some DPUs are powered down
 * Cold start the system with the config
 * Verify if the expected DPUs  are ON and the remaining are OFF and the  admin_status is set properly
 
#### Verify in
 * Switch
   
#### Sample Output
```
Once the all the containers are up, (give enough time for the DPUs to boot up as well) and the system is stable
On Switch: “show platform inventory"
Output: TBD

On Switch: "show chassis modules status"
Output: TBD

```
#### Pass/Fail Criteria
 * Verify if the expected DPUs are ON and the remaining are OFF and the  admin_status is set properly

### 1.15 Check the startup config CLI

#### Steps
 * Boot the system
 * Change config such that DPU3 which is OFF will be shutdown with the CLI “config chassis modules startup DPU3”
 * Wait for the DPU to boot fully and the midplane IP is established
 * Verify if the expected DPU "DPU3"  is ON and the  admin_status is set properly
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show platform inventory"
Output: TBD

On Switch: "show chassis modules status"
Output: TBD

```
#### Pass/Fail Criteria
 * Verify if the expected DPU "DPU3"  is ON and the  admin_status is set properly

### 1.16 Check the shutdown config CLI

#### Steps
 * Boot the system
 * Change config such that DPU1 which is ON will be shutdown with the CLI “config chassis modules shutdown DPU1”
 * Wait for the DPU to shutdown fully and the midplane IP is detached
 * Verify if the expected DPU "DPU1"  is OFF and the  admin_status is set properly
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: “show platform inventory"
Output: TBD

On Switch: "show chassis modules status"
Output: TBD

```
#### Pass/Fail Criteria
 * Verify if the expected DPU "DPU1" is OFF and the  admin_status is set properly

### 1.17 Check the reboot config CLI
* TBD

#### Steps
 * Boot the system
 * TBD: Change config such that "SWITCH" module is rebooted with the CLI “config chassis modules reboot SWITCH”
 * Wait for the system to reboot fully
 * Verify if the SWITCH and the DPUs that were ON rebooted properly
 
#### Verify in
 * Switch
   
#### Sample Output
```
Once the all the containers are up, (give enough time for the DPUs to boot up as well) and the system is stable
On Switch: “show platform inventory"
Output: TBD

On Switch: "show chassis modules status"
Output: TBD

```
#### Pass/Fail Criteria
 * Verify if the expected DPUs are ON and the remaining are OFF and the admin_status is set properly