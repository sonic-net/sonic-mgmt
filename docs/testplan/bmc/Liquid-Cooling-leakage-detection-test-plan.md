# Liquid cooling leakage detection test plan

* [Overview](#Overview)
   * [HLD](#HLD)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
Liquid cooling technology has become essential for efficiently cooling equipment and ensuring its proper operation. To address the potential dangers associated with liquid cooling leakage, it is crucial to implement a monitoring mechanism that can instantly alert the system when such an event occurs.The purpose of this test is to verify the functionality of leakage detection.

### HLD
- Feature HLD: https://github.com/sonic-net/SONiC/pull/2032/

### Scope
The test is targeting on the verification of the functionality of leakage detection on device has liquid cooling system.

### Testbed
Any

### Setup configuration
Common tests configuration:
- Check whether the device has liquid cooling system. If yes, do the following tests, else skip them.
  - When device has liquid cooling system: The key of enable_liquid_cooling exsits in pmon_daemon_control.json and the value is true

Common tests cleanup:
- No.


## Test
###  Test case #1 test_verify_liquid_senors_number_and_status
#### Test objective
Verify the number of the liquid sensors equals the configured number and the corresponding status is ok
#### Test steps
* Verify the number of the liquid sensors equals the configured number
* Verify there are no leaks
  * Check that the status of all leak sensors is 'NO' in the output of the 'show platform leakage status' command
  * Check that the status of all leak sensors is 'OK' in the output of the 'show system-health detail' command

###  Test case #2 test_mock_liquid_leak_event
#### Test objective
1. Mock liquid leak event and verify the dut has the correct response
2. Mock liquid leak event is fixed and verify the dut has the correct response
#### Test steps
* Randomly select one or serveral sensors to mock leak event. Take leakage1 as example:
  * Save the value of /var/run/hw-management/system/leakage1 and unlink it
  * Create a file /var/run/hw-management/system/leakage1
  * Echo 0 to /var/run/hw-management/system/leakage1 to mock leak event
* sleep liguid_cooling_update_interval (The default value is 0.5s)
* Verify state db has been updated to 'YES' for the mocked sensors
* Verify syslog has the corresponding GNMI event log indicating the liquid leakage event occurs, and msg has been sent out
* Verify there are leaks for the mocked sensors
  * Check that the status of the mocked sensors is 'Yes' in the output of the 'show platform leakage status' command
  * Check that the status of the mocked sensors is 'Not OK' in the output of the 'show system-health detail' command
* Restore the liquid sensor
* sleep liguid_cooling_update_interval
* Verify state db has been updated to 'No' for the mocked sensors
* Verify syslog has the corresponding GNMI event log indicating liquid leakgae event has been fixed
* Verify the leaks for the mocked sensors has been fixed
  * Check that the status of the mocked sensors is 'NO' in the output of the 'show platform leakage status' command
  * Check that the status of the mocked sensors is 'OK' in the output of the 'show system-health detail' command

###  Test case #3 Extend check_sysfs
#### Test objective
 Extend check_sysfs so that when dut do reboot and config reload, the liquid cooling leakage sysfs can be verified
#### Test steps
* Extend the function of check_sysfs to check the sysfs related to liquid cooling leakage

###  Test case #4 Platfform API get_name
#### Test objective
 Verify get_name gets the correct value
#### Test steps
* Call get_name, and verify it returns the correct value like leakage1,leakage2...

###  Test case #5 Platfform API is_leak
#### Test objective
 Verify is_leak gets the correct value
#### Test steps
* Call is_leak, and verify it returns Flase

###  Test case #6 Platfform API get_leak_sensor_status
#### Test objective
 Verify get_leak_sensor_status gets the correct value
#### Test steps
* Call get_leak_sensor_status, and verify it return the emtpy list

###  Test case #7 Platfform API get_num_leak_sensors
#### Test objective
 Verify get_num_leak_sensors gets the correct value
#### Test steps
* Call get_num_leak_sensors, and verify the return vlaue equals to the leak sensros number defined in pltform.json

###  Test case #8 Platfform API get_all_leak_sensors
#### Test objective
 Verify get_all_leak_sensors gets the correct value
#### Test steps
* Call get_all_leak_sensors, and verify the return vlaue equals to the leak sensros number defined in pltform.json


## TODO


## Open questions
