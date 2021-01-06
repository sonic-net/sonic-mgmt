# CRM test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
   * [Pytest scripts to setup and run test](#Ansible%20scripts%20to%20setup%20and%20run%20test)
     * [pmon.yml](#pmon.yml)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
The purpose is to test stablity and functionality of PMON on the SONIC switch DUT, closely resembling production environment.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of PMON on SONIC system.
1. check if pmon docker is running
2. check if all daemon/critical process is running for the platform - /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 and /usr/share/sonic/platform/pmon_daemon_control.json
3. check the uptime and/or the expected data status of each daemon/process if it can be checked

### Testbed
The test will run on the all testbeds.

## Setup configuration
No setup pre-configuration is required, test will configure and clean-up all the configuration.
### Pytest scripts to setup and run test
#### pmon.json
pmon.json which hold the data structure he following for each daemon in the PMON docker:

## Test

## Test cases

### Test case # 1 – PMON running on the DUT
#### Test objective
Verify PMON docker status
#### Test steps
* Verify the uptime to see if all dockers are running
* Perform the following steps
	* Verify the PMON running status and uptime
	* Restart the PMON
	* Verify the PMON running status and uptime

### Test case # 2 – All daemons are running
#### Test objective
Verify each daemon status in PMON docker
#### Test steps
* Parse /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 and /usr/share/sonic/platform/pmon_daemon_control.json
* Find the list of daemons running in PMON docker for the specific platform of DUT
* Perform the following steps for the list of the expected daemon
	* Verify the daemon is running
	* Restart the daemon
	* Verify the daemon is running again

### Test case # 3 – Data for chassisd daemon
#### Test objective
Verify the expected data for chassisd daemon (if not skip_chassisd)
#### Test steps
* Verify the chassisd running status based on the platform type (if IS_MODULAR_CHASSIS == 1 : "/usr/share/sonic/platform/chassisdb.conf" )
	* Verify that chassisd is not running for the fixed platform otherwise go next
	* Verify that module db data setting
```
CHASSIS_INFO_TABLE = 'CHASSIS_TABLE'
CHASSIS_INFO_KEY_TEMPLATE = 'CHASSIS {}'
CHASSIS_INFO_CARD_NUM_FIELD = 'module_num'

CHASSIS_MODULE_INFO_TABLE = 'CHASSIS_MODULE_TABLE'
CHASSIS_MODULE_INFO_KEY_TEMPLATE = 'CHASSIS_MODULE {}'
CHASSIS_MODULE_INFO_NAME_FIELD = 'name'
CHASSIS_MODULE_INFO_DESC_FIELD = 'desc'
CHASSIS_MODULE_INFO_SLOT_FIELD = 'slot'
CHASSIS_MODULE_INFO_OPERSTATUS_FIELD = 'oper_status'
```

### Test case # 4 – Data for ledd daemon
#### Test objective
Verify the expected data for ledd daemon (if not skip_ledd)
#### Test steps
* Verify the ledd running status

### Test case # 5 – Data for pcied daemon
#### Test objective
Verify the expected data for pcied daemon (if not skip_pcied)
#### Test steps
* Verify the pcie config file "/usr/share/sonic/platform/pcie.yaml" exists
* Verify the "PCIE_DEVICES" has "status" field set to "SUCCESS" 

### Test case # 6 – Data for psud daemon
#### Test objective
Verify the expected data for psud daemon (if not skip_psud)
#### Test steps
* Verify the 'PSU_INFO|PSU {}' is/are available
* Verify the information data for each 'PSU {}' is expected to compare "/usr/share/sonic/platform/platform.json"

### Test case # 7 – Data for syseepromd daemon
#### Test objective
Verify the expected data for syseepromd daemon (if not skip_syseepromd)
#### Test steps
* Verify the 'EEPROM_INFO|State' in state_db has the 'Initialized' field set to '1'
* Verify the 'EEPROM_INFO|*' has valid pairs of key and value
   * Q) how to verify the data is valid value or if we can skip the check for the value?

### Test case # 8 – Data for thermalctld daemon
#### Test objective
Verify the expected data for thermalctld daemon (if not skip_thermalctld)
#### Test steps
* Verify the policy file "/usr/share/sonic/platform/thermal_policy.json" exists
* Verify the 'FAN_INFO|{}' and 'TEMPERATURE_INFO|{}' available
   * Q) how to verify the data is valid value ? log check?

### Test case # 9 – Data for xcvrd daemon
#### Test objective
Verify the expected data for xcvrd daemon (if not skip_xcvrd)
#### Test steps
* Verify the 'TRANSCEIVER_INFO', 'TRANSCEIVER_DOM_SENSOR' and 'TRANSCEIVER_STATUS' state_db table has data
* Verify the information data for each 'TRANSCEIVER_INFO' is expected to compare "/usr/share/sonic/platform/platform.json"
   * Q) how to verify the data is valid value? log check?

## TODO

## Open questions
