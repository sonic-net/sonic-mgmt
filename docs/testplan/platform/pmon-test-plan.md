- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Test setup](#test-setup)
- [Test cases](#test-cases)
  - [Test case # 1 All expected daemons are running](#test-case-#-1-all-expected-daemons-are-running)
  - [Test case # 2 Data for chassisd daemon](#test-case-#-2-data-for-chassisd-daemon)
  - [Test case # 3 Data for lm-sensors daemon](#test-case-#-3-data-for-lm-sensors-daemon)
  - [Test case # 4 Data for fancontrol daemon](#test-case-#-4-data-for-fancontrol-daemon)
  - [Test case # 5 Data for ledd daemon](#test-case-#-5-data-for-ledd-daemon)
  - [Test case # 6 Data for pcied daemon](#test-case-#-6-data-for-pcied-daemon)
  - [Test case # 7 Data for psud daemon](#test-case-#-7-data-for-psud-daemon)
  - [Test case # 8 Data for syseepromd daemon](#test-case-#-8-data-for-syseepromd-daemon)
  - [Test case # 9 Data for thermalctld daemon](#test-case-#-9-data-for-thermalctld-daemon)
  - [Test case # 10 Data for xcvrd daemon](#test-case-#-10-data-for-xcvrd-daemon)
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

## Testbed
The test will run on the all testbeds.

# Test setup
No setup pre-configuration is required, test will configure and clean-up all the configuration.
The sanity-check plugin needs to be run before running this test, which will cover the verification of pmon docker running on SONiC system.

# Test cases

## Test case # 1 All expected daemons are running
### Test objective
Verify each daemon status in PMON docker
### Test steps
1. Parse /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2,
   /usr/share/sonic/platform/pmon_daemon_control.json, and /etc/supervisor/conf.d/supervisord.conf
2. Find the list of daemons running in PMON docker for the specific platform of DUT
   a. Check all available daemons in SONiC image
      - Check the output of "sudo docker exec pmon bash -c '[ -f /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 ] \
      && cat /usr/share/sonic/templates/docker-pmon.supervisord.conf.j2 | grep program'"
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
   b. Find any daemon that doesn't support by the platform 
      - Check the output of "sudo docker exec pmon bash -c '[ -f /usr/share/sonic/platform/pmon_daemon_control.json ] \
      && cat /usr/share/sonic/platform/pmon_daemon_control.json'"
      - Add the skip_*** as "skipped_daemons" list
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
      - Add the daemon as "skipped_daemons" list if the platform configuration file doesn't exist for a daemon to start.

   d. Verify the expected daemon list from the output of a, b, and c with "/etc/supervisor/conf.d/supervisord.conf"
      - Check the output of "docker exec pmon bash -c '[ -f /etc/supervisor/conf.d/supervisord.conf ] \
      && cat /etc/supervisor/conf.d/supervisord.conf | grep program'"
      - Compare the output from the above steps which is {"all_daemons" - "skipped_daemons"}
      ```
   admin@sonic:~$ sudo docker exec pmon bash -c '[ -f /etc/supervisor/conf.d/supervisord.conf ]  && cat /etc/supervisor/conf.d/supervisord.conf | grep program'
   [program:rsyslogd]
   [program:lm-sensors]
   [program:pcied]
   [program:psud]
   [program:syseepromd]
   [program:xcvrd]
      ```
   
   e. Verify each daemon status using "sudo docker exec pmon supervisorctl status"
      - com
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

3. Perform the following steps for the list of the expected daemon
	- Verify the daemon is running and report the daemon running status

## Test case # 2 Data for chassisd daemon
### Test objective
Verify the expected data for chassisd daemon 
   - condition to start : "skip_chassisd" != true and [ -e "/usr/share/sonic/platform/chassisdb.conf" ]
### Test steps
1. Verify the chassisd running status
   - If it's not running, report the error status and go to the next 
2. Verify that module db data setting
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

## Test case # 3 Data for lm-sensors daemon
### Test objective
Verify the expected data for lm-sensors daemon
   - condition to start : "skip_sensors" != true and [ -e "/usr/share/sonic/platform/sensors.conf" ]
### Test steps
1. Verify the lm-sensors running status
   - If it's not running, report the error status and go to the next 

## Test case # 4 Data for fancontrol daemon
### Test objective
Verify the expected data for fancontrol daemon
   - condition to start : "skip_fancontrol" != true and [ -e "/usr/share/sonic/platform/fancontrol" ]
### Test steps
1. Verify the fancontrol running status
   - If it's not running, report the error status and go to the next 

## Test case # 5 Data for ledd daemon
### Test objective
Verify the expected data for ledd daemon
   - condition to start : "skip_ledd" != true
### Test steps
1. Verify the ledd running status
   - If it's not running, report the error status and go to the next 

## Test case # 6 Data for pcied daemon
### Test objective
Verify the expected data for pcied daemon
   - condition to start : "skip_pcied" != true
### Test steps
1. Verify the pcied running status
   - If it's not running, report the error status and go to the next 
2. Verify the pcie config file "/usr/share/sonic/platform/pcie.yaml" exists
3. Verify the "PCIE_DEVICES" has "status" field set to "SUCCESS" in state DB

## Test case # 7 Data for psud daemon
### Test objective
Verify the expected data for psud daemon
   - condition to start : "skip_psud" != true
### Test steps
1. Verify the pcied running status
   - If it's not running, report the error status and go to the next 
2. Verify the 'PSU_INFO|PSU {}' is/are available in state DB
3. Verify if the data for each 'PSU {}' is expected to compare "/usr/share/sonic/platform/platform.json"
4. Verify if the status of each PSU is "OK"

## Test case # 8 Data for syseepromd daemon
### Test objective
Verify the expected data for syseepromd daemon
   - condition to start : "skip_syseepromd" != true
### Test steps
1. Verify the pcied running status
   - If it's not running, report the error status and go to the next 
2. Verify the 'EEPROM_INFO|State' in state DB has the 'Initialized' field set to '1'
3. Verify the 'EEPROM_INFO|*' has valid pairs of key and value in state DB
   - Verify the data to check with the output of the platform api or cli command

## Test case # 9 Data for thermalctld daemon
### Test objective
Verify the expected data for thermalctld daemon
   - condition to start : "skip_thermalctld" != true
### Test steps
1. Verify the pcied running status
   - If it's not running, report the error status and go to the next 
2. Verify the policy file "/usr/share/sonic/platform/thermal_policy.json" exists
3. Verify the 'FAN_INFO|{}' and 'TEMPERATURE_INFO|{}' available in state DB
   - Verify the data to check with the output of the platform api or cli command

## Test case # 10 Data for xcvrd daemon
### Test objective
Verify the expected data for xcvrd daemon
   - condition to start : "skip_xcvrd" != true
### Test steps
1. Verify the pcied running status
   - If it's not running, report the error status and go to the next 
2. Verify the 'TRANSCEIVER_INFO', 'TRANSCEIVER_DOM_SENSOR' and 'TRANSCEIVER_STATUS' state_db table has data
3. Verify the information data for each 'TRANSCEIVER_INFO' is expected to compare "/usr/share/sonic/platform/platform.json"
   - Verify the data to check with the output of the platform api or cli command

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