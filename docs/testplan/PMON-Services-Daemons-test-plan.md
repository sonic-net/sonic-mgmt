- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Test setup](#test-setup)
- [Test cases](#test-cases)
  - [Test case # 1 Verify all expected daemons are running](#test-case-#-1-verify-all-expected-daemons-are-running)
  - [Test case # 2 Verify each daemon status if all expected DB data is populated](#test-case-#-2-verify-each-daemon-status-if-all-expected-db-data-is-populated)
- [Daemon-specific apis and database data verification procedures](#daemon-specific-apis-and-database-data-verification-procedures)
  - [chassisd daemon](#chassisd-daemon)
  - [lm-sensors service](#lm-sensors-service)
  - [fancontrol daemon](#fancontrol-daemon)
  - [ledd daemon](#ledd-daemon)
  - [pcied daemon](#pcied-daemon)
  - [psud daemon](#psud-daemon)
  - [syseepromd daemon](#syseepromd-daemon)
  - [thermalctld daemon](#thermalctld-daemon)
  - [xcvrd daemon](#xcvrd-daemon)
- [Platform daemon test report](#platform-daemon-test-report)
  - [Platform daemon test result table](#platform-daemon-test-result-table)

# Overview
The purpose is to test the status of daemons in PMON docker on the SONIC switch DUT.

## Scope
The test is targeting all expected daemons running inside SONIC PMON docker with fully functioning configuration.  
The purpose of the test is not to test specific api but to verify the platform daemon status and functionality on each platform.
1. check if pmon docker is running: this can be covered by the critical process check in sanity_check plugin
2. check if all expected daemons are running on the DUT based on the SONiC pmon docker configuration file and platform specific configuration files:  
   - /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2
   - /usr/share/sonic/platform/pmon_daemon_control.json
   - /etc/supervisor/conf.d/supervisord.conf
3. check the expected data status for the daemon if it's running as expected
4. check any db data gets cleared and the daemon stops when any exit signal is received

## Testbed
The test will run on the all testbeds.

# Test setup
No setup pre-configuration is required, test will configure and clean-up all the configuration.
The sanity-check plugin needs to be run before running this test, which will cover the verification of pmon docker running on SONiC system.

# Test cases
## Test case # 1  Verify all expected daemon are running
### Test objective
Verify all daemon staus in PMON container using "check_pmon_daemon_status()" in "tests/common/platform/daemon_utils.py"
Extend "check_pmon_daemon_status()" to cover all steps below.
### Test steps
1. Parse /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2,
   /usr/share/sonic/platform/pmon_daemon_control.json, and /etc/supervisor/conf.d/supervisord.conf
2. Find the list of daemons running in PMON docker for the specific platform of DUT 
   a. Check all available daemons in SONiC image
      - Check the output of `sudo docker exec pmon bash -c '[ -f /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 ] \
      && cat /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 | grep program'`
      - Add the daemons from the output as "all_daemons" list
      ```
   admin@sonic:~$ sudo docker exec pmon bash -c '[ -f /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 ]  && cat /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 | grep program'
   [program:rsyslogd]
   [program:chassisd]
   [program:lm-sensors]
   [program:fancontrol]
   [program:ledd]
   [program:pcied]
   [program:psud]
   [program:syseepromd]
   [program:thermalctld]
   [program:xcvrd]
      ```
   b. Find any daemon that isn't supported by the platform 
      - Check the output of `sudo docker exec pmon bash -c '[ -f /usr/share/sonic/platform/pmon_daemon_control.json ] \
      && cat /usr/share/sonic/platform/pmon_daemon_control.json'`
      - Add each skip_<daemon_name> entry to a "skipped_daemons" list
      ```
   admin@sonic:~$ sudo docker exec pmon bash -c '[ -f /usr/share/sonic/platform/pmon_daemon_control.json ] \
   && cat /usr/share/sonic/platform/pmon_daemon_control.json '
   {
       "skip_ledd": true,
       "skip_thermalctld": true
   }
      ```
   c. Check whether the DUT (platform) has configuration files which the specific daemon can start with.
      - Check if the platform configuration files exists
         <202012 master has three configuration files available to start the daemons as below.>
         * chassisd : "/usr/share/sonic/platform/chassisdb.conf"
         * lm-sensors : "/usr/share/sonic/platform/sensors.conf"
         * fancontrol : "/usr/share/sonic/platform/fancontrol"
      - Add the daemon to "skipped_daemons" list if the platform configuration file doesn't exist for a daemon to start.

   d. Verify the expected daemon list from the output of a, b, and c with "/etc/supervisor/conf.d/supervisord.conf"
      - Check the output of `sudo docker exec pmon bash -c '[ -f /etc/supervisor/conf.d/supervisord.conf ] \
      && cat /etc/supervisor/conf.d/supervisord.conf | grep program'`
      - Compare the output with the results from the above steps, which is {"all_daemons" - "skipped_daemons"}
      - Report an error if they don't match
      - Save the {"all_daemons" - "skipped_daemons"} to "expected_daemons"
      ```
   admin@sonic:~$ sudo docker exec pmon bash -c '[ -f /etc/supervisor/conf.d/supervisord.conf ]  && cat /etc/supervisor/conf.d/supervisord.conf | grep program'
   [program:rsyslogd]
   [program:lm-sensors]
   [program:pcied]
   [program:psud]
   [program:syseepromd]
   [program:xcvrd]
      ```
   
   e. Verify each daemon status using `sudo docker exec pmon supervisorctl status`
      - compare the output with 
      - Example) "skip_ledd"==true && "skip_thermalctld"==true && none of three config files in c. available
      ```
   admin@sonic:~$ sudo docker exec pmon supervisorctl status
   supervisor-proc-exit-listener    RUNNING   pid 24, uptime 1:30:24
   dependent-startup                EXITED    Jan 25 08:23 AM
   rsyslogd                         RUNNING   pid 27, uptime 1:30:22
   pcied                            RUNNING   pid 36, uptime 1:30:20
   psud                             RUNNING   pid 34, uptime 1:30:20
   syseepromd                       RUNNING   pid 35, uptime 1:30:20
   xcvrd                            RUNNING   pid 32, uptime 1:30:20
      ```

## Test case # 2 Verify each daemon status if all expected DB data is populated
### Test objective
Verify each daemon staus in PMON container using "check_pmon_daemon_status()" in "tests/common/platform/daemon_utils.py"
Extend "check_pmon_daemon_status()" if there is any gap to follow the steps below.
Refer to daemon-specific dpis and atabase data verification procedure below.
### Test steps
Perform the following steps for the list of the expected daemon
  - This flow will be able to be used for each daemon test (Test case #3 ~ #11) if it's applicable
1. Verify the daemon is running and check if all expected DB data is populated
2. Disable the critical process autorestart if it's enabled using [disable_and_enable_autorestart](https://github.com/Azure/sonic-mgmt/blob/73830827460750d88ba0a5de71bb5c79ad33c46e/tests/process_monitoring/test_critical_process_monitoring.py#L37)
3. Stop the daemon using `sudo docker exec pmon supervisorctl stop {daemon}`
4. Verify the daemon is not running using `sudo docker exec pmon supervisorctl status {daemon}` 
5. Verify all DB data is cleared if any DB data has been populated while daemon was running 
6. Restart the daemon using `sudo docker exec pmon supervisorctl start {daemon}`
7. Verify the daemon is running using `sudo docker exec pmon supervisorctl status {daemon}`
8. Verify all expected DB data is populated same as step 1.
9. Repeat from step 3 to step 8 with sending the signal to kill the daemon for each exit signal being handled by the daemon
10. Enable the critical process autorestart

# Daemon-specific apis and database data verification procedures
## chassisd daemon
### Test objective
Verify the expected data for chassisd daemon
   - This test is covered by [PMON-Chassis-Enhancements-test-plan](https://github.com/Azure/sonic-mgmt/blob/master/docs/testplan/PMON-Chassis-Enhancements-test-plan.md)
   - condition to start : "skip_chassisd" != true and [ -e "/usr/share/sonic/platform/chassisdb.conf" ]
### Test steps
1. Verify the chassisd running status
   - If it's not running, report the error status
2. Verify that module db data setting
   ```py
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
3. Repeat the steps from step #2 to step 10 in Test case #2

## lm-sensors service
### Test objective
Verify the expected data for lm-sensors daemon
   - condition to start : "skip_sensors" != true and [ -e "/usr/share/sonic/platform/sensors.conf" ]
### Test steps
1. Verify the lm-sensors running status using "check_sensord_status()" in "tests/platform_tests/test_platform_info.py"
   - If it's not running, report the error status and go to the next daemon test
2. Repeat the steps from step #2 to step 10 in Test case #2

## fancontrol daemon
### Test objective
Verify the expected data for fancontrol daemon
   - condition to start : "skip_fancontrol" != true and [ -e "/usr/share/sonic/platform/fancontrol" ]
### Test steps
1. Verify the fancontrol running status
   - If it's not running, report the error status and go to the next daemon test
2. Repeat the steps from step #2 to step 10 in Test case #2

## ledd daemon
### Test objective
Verify the expected data for ledd daemon
   - condition to start : "skip_ledd" != true
### Test steps
1. Verify the ledd running status
   - If it's not running, report the error status and go to the next daemon test
2. Repeat the steps from step #2 to step 10 in Test case #2

## pcied daemon
### Test objective
Verify the expected data for pcied daemon
   - condition to start : "skip_pcied" != true
### Test steps
1. Verify the pcied running status
   - If it's not running, report the error status and go to the next daemon test
2. Verify the pcie config file "/usr/share/sonic/platform/pcie.yaml" exists
3. Verify the "PCIE_DEVICES" has "status" field set to "PASSED" in state DB
   - If the "status" is not "PASSED", report the error status and go to the next daemon test
   - Otherwise, report the passed status
4. Repeat the steps from step #2 to step 10 in Test case #2

## psud daemon
### Test objective
Verify the expected data for psud daemon
   - condition to start : "skip_psud" != true
### Test steps
1. Verify the psud running status
   - If it's not running, report the error status and go to the next daemon test
2. Verify the 'PSU_INFO|PSU {}' is/are available in State DB
3. Verify if the data for each 'PSU {}' is expected to compare "/usr/share/sonic/platform/platform.json"
4. Verify if the status of each PSU is "OK"
   - If any PSU status is not "OK", report the error status and go to the next daemon test
   - Otherwise, report the success status
5. Repeat the steps from step #2 to step 10 in Test case #2

## syseepromd daemon
### Test objective
Verify the expected data for syseepromd daemon
   - condition to start : "skip_syseepromd" != true
### Test steps
1. Verify the syseepromd running status
   - If it's not running, report the error status and go to the next daemon test
2. Verify the 'EEPROM_INFO|State' in State DB has the 'Initialized' field set to '1'
3. Verify the 'EEPROM_INFO|*' has valid pairs of key and value in State DB
   - Verify the data to check with the output of the platform api or cli command
   - If any data is not valid or matched, report the error status and go to the next daemon test
4. Repeat the steps from step #2 to step 10 in Test case #2

## thermalctld daemon
### Test objective
Verify the expected data for thermalctld daemon
   - condition to start : "skip_thermalctld" != true
### Test steps
1. Verify the thermalctld running status
   - If it's not running, report the error status and go to the next daemon test
2. Verify the policy file "/usr/share/sonic/platform/thermal_policy.json" exists
3. Verify the "FAN_INFO|{}", "PHYSICAL_ENTITY_INFO|{}" and "TEMPERATURE_INFO|{}" available in State DB
   - Verify the data to check with the output of the platform api or cli command
   - If any data is not valid or matched, report the error status and go to the next daemon test
4. Repeat the steps from step #2 to step 10 in Test case #2

## xcvrd daemon
### Test objective
Verify the expected data for xcvrd daemon : This test can be covered by "test_xcvr_info_in_db()" in "tests/platform_tests/test_xcvr_info_in_db.py"
   - condition to start : "skip_xcvrd" != true
### Test steps
1. Verify the xcvrd running status
   - If it's not running, report the error status and go to the next daemon test
2. Verify the 'TRANSCEIVER_INFO', 'TRANSCEIVER_DOM_SENSOR' and 'TRANSCEIVER_STATUS' in State DB
3. Verify the information data for each 'TRANSCEIVER_INFO' is expected to compare "/usr/share/sonic/platform/platform.json"
   - Verify the data to check with the output of the platform api or cli command
   - If any data is not valid or matched, report the error status and go to the next daemon test
4. Repeat the steps from step #2 to step 10 in Test case #2

# Platform daemon test report
## Platform daemon test result table
### Contents of test result table
1. All available platform daemon list
   - List all available platform daemon list of the SONiC image in the test
2. Skipped daemon list
   - Mark as "skipped" for all skipped platform daemon list of the DUT platform in the test
3. Daemon running status
   - Indicate the status of daemon when the test starts
4. Data for daemon
   - Display any data available for daemon
5. Data validation status
   - Indicate the data validation status if available
