- [Introduction](#introduction)
- [Platform API Test Cases](#platform-api-test-cases)
  - [1.1 Check platform API implementation](#11-check-platform-api-implementation) 
- [Platform CLI Test Cases](#platform-cli-test-cases)
  - [1.2 Check Platform-Related CLI](#12-check-platform-related-cli)
  - [1.3 Check SFP status and configure SFP](#13-check-sfp-status-and-configure-sfp)
  - [1.4 Check xcvrd information in DB](#14-check-xcvrd-information-in-db)
  - [1.5 Sequential syncd/swss restart](#15-sequential-syncdswss-restart)
  - [1.6 Reload configuration](#16-reload-configuration)
  - [1.7 COLD/WARM/FAST/POWER OFF/WATCHDOG reboot](#17-coldwarmfastpower-offwatchdog-reboot)
  - [1.8 Check thermal sensors output using new OPTIC cables](#18-check-thermal-sensors-output-using-new-optic-cables)
  - [1.9 Manually plug in and pull out PSU modules](#19-manually-plug-in-and-pull-out-psu-modules)
  - [1.10 Manually plug in and pull out PSU power cord](#110-manually-plug-in-and-pull-out-psu-power-cord)
  - [1.11 Manually plug in and pull out FAN modules](#111-manually-plug-in-and-pull-out-fan-modules)
  - [1.12 Manually plug in and pull out optical cables](#112-manually-plug-in-and-pull-out-optical-cables)
  - [1.13 Check platform daemon status](#113-check-platform-daemon-status)
- [LED Test Cases](#led-test-cases)
  - [2.1 Check system LED](#21-check-system-led)
  - [2.2 Check fan LED](#22-check-fan-led)
  - [2.3 Check psu LED](#23-check-psu-led)
  - [2.4 Check activity LED's for ports](#24-check-activity-for-ports)
  - [2.5 Check ssdhealth](#25-check-ssdhealth)
- [Thermal policy json tests](thermal-policy-json-tests)
  - [3.1 Show FAN Status Test](#31-show-fan-status-test)
  - [3.2 Show Thermal Status Test](#32-show-thermal-status-test)
  - [3.3 Fan Test](#33-fan-test)
  - ~~[3.4 PSU Absence Test]~~
  - [3.5 Invalid Policy Format Load Test](#35-invalid-policy-format-load-test))
  - [3.6 Invalid Policy Value Load Test](#36-invalid-policy-value-load-test)
# Introduction

This test plan meets following deliverables:
 - Physical delivery of IXS7215 Hardware box to Microsoft with Software based on 202006 SONiC 
 - Electronic delivery of IXS7215 platform software to open source via PR based on master SONiC 

This test plan is to check the functionalities of platform related software components. These software components are for managing platform hardware, including FANs, SFP, transceivers, pmon, etc.

The software components for managing platform hardware on NOKIA platform is the [hw-management package](https://github.com/Mellanox/hw-mgmt).

To verify that the hw-management package works as expected, the test cases need to be executed on the following NOKIA platforms:

NOKIA IXS 7215

The test cases are grouped in two categories:
* Platform test cases for all vendors from [https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md].
* Thermal policy test cases from [https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_thermal_control_test_plan.md]

In Platform test cases, some steps are platform dependent. Detailed information will be given in the test cases.

# Platform API Test Cases

These tests are not run for delivery of IXS7215 Hardware box to Microsoft with Software based on 202006 SONiC.

## 1.1 Check platform API implementation
   
All platform API methods will be exercised, and ensuring that:

* The vendor has implmented the method for the particular platform
* The API call returned 'sane' data (type is correct, etc.)
* Where applicable, the data returned is appropriate for the platform being tested (number of fans, number of transceivers, etc.)
* Where applicable, the data returned is appropriate for the specific DuT (serial number, system EERPOM data, etc.)

### Steps
run Automated test suites under /data/tests/platform_tests/api/ :
```
1. test_chassis.py
2. test_component.py
3. test_fan.py
4. test_fan_drawer.py
5. test_module.py
6. test_psu.py
7. test_sfp.py
8. test_thermal.py
9. test_watchdog.py
```

# Platform Cli Test Cases

## 1.2 Check Platform-Related CLI

### Steps

Test all subcommands of show platform

* Run `show platform summary`
* Turn off/on PSU from PDU (Power Distribution Unit), run `show platform psustatus` respectively. In automation, PDU with programmable interface is required for turning off/on PSU. Without PDU, manual intervention required for this step.
* Run `show platform syseeprom`
* Use the platform specific eeprom.py utility to directly decode eeprom information from hardware, compare the result with output of cmd `show platform syseeprom`. **This step is platform dependent.** Different eeprom.py utility should be used on different platforms. The below example is taken from Mellanox platform.
```
SAMPLE OUTPUT:
root@mtbc-sonic-03-2700:~# python
Python 2.7.13 (default, Sep 26 2018, 18:42:22)
[GCC 6.3.0 20170516] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import imp
>>> m = imp.load_source('eeprom', '/usr/share/sonic/device/armhf-nokia_ixs7215_52x-r0/plugins/eeprom.py')
>>> t = m.board('board', '', '', '')
>>> e = t.read_eeprom()
>>> t.decode_eeprom(e)
TlvInfo Header:
   Id String:    TlvInfo
   Version:      1
   Total Length: 139
TLV Name             Code Len Value
-------------------- ---- --- -----
Part Number          0x22  14 3HE16794AARA01
Serial Number        0x23  11 NK203110018
Base MAC Address     0x24   6 50:E0:EF:51:27:11
Manufacture Date     0x25  19 08/24/2020 16:01:21
ONIE Version         0x29   7 2020.31
MAC Addresses        0x2A   2 64
Service Tag          0x2F  10 0000000000
Vendor Extension     0xFD   7 
Product Name         0x21  11 7215 IXS-T1
Platform Name        0x28  26 armhf-nokia_ixs7215_52x-r0
CRC-32               0xFE   4 0x853ECAA6
>>>

```

### Pass/Fail Criteria

* `show platform summary` should output these fields: Platform, HwSKU, ASIC, for example:
```
SAMPLE OUTPUT:
admin@sonic:~$ show platform summary
Platform: armhf-nokia_ixs7215_52x-r0
HwSKU: Nokia-7215
ASIC: marvell
```
* PSU status should be `OK` when it is on, `NOT OK` when it is off. Use PDU to turn off/on PSU to verify that correct PSU status can be displayed.
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ show platform psustatus
PSU    Status
-----  --------
PSU 1  NOT OK
PSU 2  OK
```
* The syseeprom information should have format as the example:
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ show platform syseeprom
show platform syseeprom
TlvInfo Header:
   Id String:    TlvInfo
   Version:      1
   Total Length: 139
TLV Name             Code Len Value
-------------------- ---- --- -----
Product Name         0x21  11 7215 IXS-T1
Part Number          0x22  14 3HE16794AARA01
Serial Number        0x23  11 NK203110018
Base MAC Address     0x24   6 50:E0:EF:51:27:11
Manufacture Date     0x25  19 08/24/2020 16:01:21
Platform Name        0x28  26 armhf-nokia_ixs7215_52x-r0
ONIE Version         0x29   7 2020.31
MAC Addresses        0x2A   2 64
Service Tag          0x2F  10 0000000000
Vendor Extension     0xFD   7 
CRC-32               0xFE   4 0x853ECAA6

(checksum valid)

```
* The syseeprom info output from cmd `show platform syseeprom` should comply with the info decoded using platform specific eeprom.py utility.

### Automation
Covered in existing Automated.
The step for turning on/off PSU needs programmable PDU. Need to implement a fixture for turning on/off PSU. When programmable PDU is not available in testbed, this step can only be tested manually. The fixture should be able to return information about whether this capability is supported. If not supported, skip this step in automatin.

## 1.3 Check SFP status and configure SFP

This case is to use the sfputil tool and show command to check SFP status and configure SFP. Currently the the only configuration is to reset SFP.
  * `sfputil show presence`
  * `show interface transceiver presence`
  * `sfputil show eeprom`
  * `show interface transceiver eeprom`
  * `sfputil reset <interface name>`

### Steps
* Get the list of connected ports from `ansible/files/lab_connection_graph.xml`, all connected ports need to be checked.
* Use the `sfputil show presence` and `show interface transceiver presence` commands to check presence of ports.
* Use the `sfputil show eeprom` and `show interface transceiver eeprom` commands to check eeprom information of ports.
* Use the `sfputil reset <interface name>` command to reset each port.
* Use the `show interface status` and `show interface portchannel` commands to check interface and port channel status against current topology.

### Pass/Fail Criteria

* Both `sfputil show presence` and `show interface transceiver presence` should list presence of all connected ports, for example:
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ sudo sfputil show presence
Port         Presence
-----------  ----------
Ethernet0    Present
Ethernet4    Present
Ethernet8    Present
Ethernet12   Present
...
```
* Both `sfputil show eeprom` and `show interface transceiver eeprom` should output eeprom information of all connected ports. For each port, eeprom information should have format as the example:
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ sudo sfputil show eeprom
Ethernet0: SFP EEPROM detected
    Connector: No separable connector
    Encoding: Unspecified
    Extended Identifier: Power Class 1(1.5W max)
    Extended RateSelect Compliance: QSFP+ Rate Select Version 1
    Identifier: QSFP+
    Length Cable Assembly(m): 1
    Nominal Bit Rate(100Mbs): 255
    Specification compliance:
        10/40G Ethernet Compliance Code: 40GBASE-CR4
    Vendor Date Code(YYYY-MM-DD Lot): 2018-08-24
    Vendor Name: Mellanox
    Vendor OUI: 00-02-c9
    Vendor PN: MCP1600-E001
    Vendor Rev: A3
    Vendor SN: MT1834VS04288

...
```
* The `sfputil reset <interface name>` command should be successful without error.
```
admin@mtbc-sonic-03-2700:~$ sudo sfputil reset Ethernet0
Resetting port Ethernet0...  OK
```
* Verify that interface status is not affected after reading of EEPROM. Up and down status of interfaces and port channels should comply with current topology.

### Automation
Covered in exisiting automation

## 1.4 Check xcvrd information in DB
This test case is to verify that xcvrd works as expected by checking transcever information in DB.

### Steps
* Get the list of connected ports from `ansible/files/lab_connection_graph.xml`, all connected ports need to be checked.
* Check whether transceiver information of all ports are in redis: `redis-cli -n 6 keys TRANSCEIVER_INFO*`
* Check detailed transceiver information of each connected port, for example: `redis-cli -n 6 hgetall "TRANSCEIVER_INFO|Ethernet0"`
* Check whether TRANSCEIVER_DOM_SENSOR of all ports in redis: `redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*`
* Check detailed TRANSCEIVER_DOM_SENSOR information of each connected ports for example: `redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|Ethernet0"`

### Pass/Fail Criteria
* Ensure that transceiver information of all ports are in redis
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ redis-cli -n 6 keys TRANSCEIVER_INFO*
 1) "TRANSCEIVER_INFO|Ethernet16"
 2) "TRANSCEIVER_INFO|Ethernet84"
 3) "TRANSCEIVER_INFO|Ethernet40"
 4) "TRANSCEIVER_INFO|Ethernet44"
...
```
* Ensure that detailed transceiver information of a port should be like this example:
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ redis-cli -n 6 hgetall "TRANSCEIVER_INFO|Ethernet0"
 1) "type"
 2) "QSFP+"
 3) "hardwarerev"
 4) "A3"
 5) "serialnum"
 6) "MT1834VS04288"
 7) "manufacturename"
 8) "Mellanox"
 9) "modelname"
10) "MCP1600-E001"
```
* Ensure that TRANSCEIVER_DOM_SENSOR of all ports are in redis:
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*
 1) "TRANSCEIVER_DOM_SENSOR|Ethernet104"
 2) "TRANSCEIVER_DOM_SENSOR|Ethernet88"
 3) "TRANSCEIVER_DOM_SENSOR|Ethernet80"
 4) "TRANSCEIVER_DOM_SENSOR|Ethernet120"
...
```
* Ensure that detailed TRANSCEIVER_DOM_SENSOR information of a port should be like this example:
```
SAMPLE OUTPUT:
admin@mtbc-sonic-03-2700:~$ redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|Ethernet0"
 1) "temperature"
 2) "0.0000"
 3) "voltage"
 4) "0.0000"
 5) "rx1power"
 6) "-inf"
 7) "rx2power"
 8) "-inf"
 9) "rx3power"
10) "-inf"
11) "rx4power"
12) "-inf"
13) "tx1bias"
14) "0.0000"
15) "tx2bias"
16) "0.0000"
17) "tx3bias"
18) "0.0000"
19) "tx4bias"
20) "0.0000"
21) "tx1power"
22) "N/A"
23) "tx2power"
24) "N/A"
25) "tx3power"
26) "N/A"
27) "tx4power"
28) "N/A"
```

### Automation
Partly covered in existing automation

## 1.5 Sequential syncd/swss restart

### Steps
* Restart the syncd and swss service:
  * `sudo service syncd restart`
  * `sudo service swss restart`
* After restart, check:
  * status of services: syncd, swss
    * `sudo systemctl status syncd`
    * `sudo systemctl status swss`
  * ~~status of hw-management - **Mellanox specific**~~
    * ~~`sudo systemctl status hw-management`~~
  * status of interfaces and port channels
    * `show interface status`
    * `show interface portchannel`
  * status of transceivers
    * `show interface transcever presence`
    * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Pass/Fail Criteria
* After restart, status of services, interfaces and transceivers should be normal:
  * Services syncd and swss should be active(running)
  * All interface and port-channel status should comply with current topology.
  * All ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.

### Automation
Partly covered in existing automation

## 1.6 Reload configuration

### Steps
* Reload configuration using: `config load_minigraph -y` and `config reload -y`
* After reload, check:
  * status of services: syncd, swss
    * `sudo systemctl status syncd`
    * `sudo systemctl status swss`
  * status of interfaces and port channels
    * `show interface status`
    * `show interface portchannel`
  * status of transceivers
    * `show interface transcever presence`
    * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Pass/Fail Criteria
* After reload, status of services, interfaces and transceivers should be normal:
  * Services syncd and swss should be active(running)
  * All interface and port-channel status should comply with current topology.
  * All ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.

### Automation
Partly covered by existing automation. New automation required.

## 1.7 COLD/WARM/FAST/POWER OFF/WATCHDOG reboot

### Steps
* Perform cold/warm/fast/power off/watchdog reboot
  * cold/warm/fast reboot
    * Make use of commands to reboot the switch
  * watchdog reboot
    * Make use of new platform api to reboot the switch
  * power off reboot
    * Make use of PDUs to power on/off DUT.
    * Power on/off the DUT for (number of PSUs + 1) * 2 times
      * Power on each PSU solely
      * Power on all the PSUs simultaneously
      * Delay 5 and 15 seconds between powering off and on in each test
* After reboot, check:
  * status of services: syncd, swss
    * `sudo systemctl status syncd`
    * `sudo systemctl status swss`
  * reboot cause:
    * `show reboot-cause`
  * status of interfaces and port channels
    * `show interface status`
    * `show interface portchannel`
  * status of transceivers
    * `show interface transcever presence`
    * `redis-cli -n 6 keys TRANSCEIVER_INFO*`
* Check dmesg

### Pass/Fail Criteria
* After reboot, status of services, interfaces and transceivers should be normal:
  *  Services syncd and swss should be active(running)
  *  Reboot cause should be correct
  *  All transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.
* Verify that there is no error in dmesg

### Automation
Partly covered by existing automation:
* ansible/roles/test/tasks/reboot.yml
* ansible/roles/test/tasks/warm-reboot.yml
* ansible/roles/test/tasks/fast-reboot.yml

Need to port these scripts to pytest and cover the testing in this test case.

## 1.8 Check thermal sensors output using new OPTIC cables

### Steps
* Plug in new OPTIC cables
* Check the thermal sensors output using command `redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|Ethernet0"`. Replace 'Ethernet0' in the example with actual interface name.

### Pass/Fail Criteria
* Verify that the thermal sensors could properly detect temperature.

### Automation
Manual intervention required, not automatable

## 1.9 Manually plug in and pull out PSU modules

This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of services: syncd, swss:
  * `systemctl status syncd`
  * `systemctl status swss`
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`
* CPU and memory usage: `top`

Expected results of checking varous status:
* Services syncd and swss should be active(running)
* All interface and port-channel status should comply with current topology.
* All transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check PSU status using command `show platform psustatus`
* Check various status.
* Pull out one of the PSU if there are multiple PSU modules available.
* Check PSU status using command `show platform psustatus`
* Check various status.
* Plug in the PSU module again
* Check PSU status using command `show platform psustatus`
* Check various status.
* Repeat the test on the other PSU module.

### Pass/Fail Criteria
* Verify that command `show platform psustatus` can correctly indicate the current PSU status.
* Verify that various status are expected after manual intervention. Please refer to the test case description for detailed command for checking status and expected results.

### Automation
Manual intervention required, not automatable

## 1.10 Manually plug in and pull out PSU power cord

This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of services: syncd, swss:
  * `systemctl status syncd`
  * `systemctl status swss`
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`
* CPU and memory usage: `top`

Expected results of checking varous status:
* Services syncd and swss should be active(running)
* All interface and port-channel status should comply with current topology.
* All transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check PSU status using command `show platform psustatus`
* Check various status.
* Pull out power cord from one of the PSU if there are multiple PSU modules available.
* Check PSU status using command `show platform psustatus`
* Check various status.
* Plug in the power cord.
* Check PSU status using command `show platform psustatus`
* Check various status.
* Repeat the test on the other PSU module

### Pass/Fail Criteria
* Verify that command `show platform psustatus` can correctly indicate the current PSU status.
* Verify that various status are expected after manual intervention. Please refer to the test case description for detailed command for checking status and expected results.

### Automation
Manual intervention required, not automatable

## 1.11 Manually plug in and pull out FAN modules

This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of services: syncd, swss:
  * `systemctl status syncd`
  * `systemctl status swss`
* status of service: hw-management - **Mellanox specific**
  * `systemctl status hw-management`
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`
* CPU and memory usage: `top`

Expected results of checking varous status:
* Services syncd and swss should be active(running)
* Service hw-management should be active(exited) - **Mellanox specific**
* All interface and port-channel status should comply with current topology.
* All transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check FAN status using command `show environment` or `sensors`
* Check various status.
* Pull out a FAN module if there are multiple FAN modules available.
* Check FAN status using command `show environment` or `sensors`
* Check various status.
* Plug in the FAN module back.
* Check FAN status using command `show environment` or `sensors`
* Check various status.
* Repeat the test on another FAN module

### Pass/Fail Criteria
* Verify that command `show environment` or `sensors` can get correct FAN status and FAN speed
* Verify that various status are expected after manual intervention. Please refer to the test case description for detailed command for checking status and expected results.

### Automation
Manual intervention required, not automatable

## 1.12 Manually plug in and pull out optical cables

This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of services: syncd, swss:
  * `systemctl status syncd`
  * `systemctl status swss`
* status of service: hw-management - **Mellanox specific**
  * `systemctl status hw-management`
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`
* CPU and memory usage: `top`

Expected results of checking varous status:
* Services syncd and swss should be active(running)
* Service hw-management should be active(exited) - **Mellanox specific**
* All interface and port-channel status should comply with current topology and hardware availability:
  * When cable is unplugged, interface should be down. If the interface was the last one in port channel, the port channel should be down as well.
  * After cable is plugged in, interface should be up. If the interface was in port channel, the port channel should be up as well.
* Transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) and unplugged should present. Transcever of cable unplugged port should be not present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check various status.
* Pull out an optical cable.
* Check various status.
* Plug in the optical cable back.
* Check various status.

### Pass/Fail Criteria
* Verify that after an interface is pulled out, the corresponding interface is down.
* Verify that after the interface is plugged back, the corresponding interface should recover automatically.
* Verify that syncd, swss and hw-management services are not affected.
* Verify that CPU and memory usage are at the same level before and after the manual intervention.

### Automation
Manual intervention required, not automatable

## 1.13 Check platform daemon status

This test case will check the all daemon running status inside pmon(led not included) if they are supposed to to be running on this platform.
* Using command `docker exec pmon supervisorctl status | grep {daemon}` to get the status of the daemon

Expected results of checking daemon status:
* the status of the daemon should be `RUNNING`

### Steps
* Get the running daemon list from the configuration file `/usr/share/sonic/device/{platform}/{hwsku}/pmon_daemon_control.json`
* Check all the daemons running status in the daemon list

### Pass/Fail Criteria
* All the daemon status in the list shall be `RUNNING`

# LED Test Cases

## 2.1 Check system LED

This test case will check system led 

### Steps
* Turn the box up and check for the system LED and verify its blinking green when its booting up and then solid green when its completely booted  
* Reboot the box multiple times and verify the LED works as expected
* Check the LED color changes if a docker restarts 
* Verify with a bad build which doesn't bring all the process up to make sure LED doesn't turn solid green 

### Pass/Fail Criteria
* Led for the system should be  `SOLID GREEN`

## 2.2 Check  fan LED

This test case will check fan led

### Steps
* With 2 fans in and running, LED should be green
* Reboot the box multiple times and verify the LED works as expected
* Verify the LED by taking a fan out and verify the LED turns orange 
* When the fan is put back verify LED turns Solid Green

### Pass/Fail Criteria
* Led for the fan should be  `SOLID GREEN`

## 2.3 Check psu LED

This test case will check psu led

### Steps
* With 2 PSU's in and running, LED should be green
* Reboot the box multiple times and verify the LED works as expected
* Verify the LED by taking one PSU out and verify the LED turns orange 
* When the PSU is put back verify LED turns Solid Green
* Verify when both PSU are in but only one is powered on.

### Pass/Fail Criteria
* PSU for the fan should be `SOLID GREEN`

## 2.4 Check activity LED's for ports

This test case will check activity led for each port

### Steps
* Verify the LED if the link is up 
* Pass traffic and verify blinking green 
* Check this on all ports  
* Reboot the box and verify

## 2.5 Check ssdhealth  

This test case will check ssd health

### Steps
* Check SSD health with `sudo show platform ssdhealth`
* Verify it doesnt crash   
* Reboot the box and verify

### Pass/Fail Criteria
*  `sudo show platform ssdhealth` doesn't crash and shows correct output

# Thermal policy json Test Cases

## 3.1 Show FAN Status Test

Show FAN status test verifies that all FAN related information can be shown correctly via `show platform fanstatus`.

### Procedure

1. Testbed setup.
2. Mock random data for "presence", "speed", "status", "target_speed", "led status".
3. Issue command `show platform fanstatus`.
4. Record the command output.
5. Verify that command output matches the mock data.
6. Restore mock data.

## 3.2 Show Thermal Status Test

Show thermal status test verifies that all thermal related information can be shown correctly via `show platform temperature`.

### Procedure

1. Testbed setup.
2. Fill mock data for "temperature", "high_threshold", "high_critical_threshold".
3. Issue command `show platform temperature`.
4. Record the command output.
5. Verify that command output matches the mock data.
6. Restore mock data.

## 3.3 FAN Test

FAN test verifies that proper action should be taken for conditions including: FAN absence, FAN over speed, FAN under speed.

### Procedure

1. Testbed setup.
2. Copy valid_policy.json to pmon docker and backup the original one.
3. Restart thermal control daemon to reload policy configuration file. Verify thermal algorithm is disabled and FAN speed is set to 60% according to configuration file.
4. Make mock data: first FAN absence.
5. Wait for at least 65 seconds. Verify target speed of all FANs are set to 100% according to valid_policy.json. Verify there is a warning log for FAN absence.
6. Make mock data: first FAN presence.
7. Wait for at least 65 seconds. Verify target speed of all FANs are set to 65% according to valid_policy.json. Verify there is a notice log for FAN presence.
8. Make mock data: first FAN speed exceed threshold(speed < target speed), second FAN speed exceed threshold(speed > target speed).
9. Wait for at least 65 seconds. Verify led turns to red for first and second FAN. Verify there is a warning log for over speed and a warning log for under speed.
10. Make mock data: first and second FAN speed recover to normal.
11. Wait for at least 65 seconds. Verify led turns to green for first and second FAN. Verify there are two notice logs for speed recovery.
12. Restore the original policy file. Restore mock data.

> Note: The reason that we wait at least 65 seconds is that thermal policy run every 60 seconds according to design.

~~## 3.4 PSU Absence Test~~

PSU absence test verifies that once any PSU absence, all FAN speed will be set to proper value according to policy file.

### Procedure

1. Testbed setup.
2. Copy valid_policy.json to pmon docker and backup the original one.
3. Restart thermal control daemon to reload policy configuration file.
4. Turn off one PSUs.
5. Wait for at least 65 seconds. Verify target speed of all FANs are set to 100% according to valid_policy.json.
6. Turn on one PSU and turn off the other PSU.
7. Wait for at least 65 seconds. Verify target speed of all FANs are still 100% according to valid_policy.json.
8. Turn on all PSUs.
9. Wait for at least 65 seconds. Verify target speed of all Fans are set to 65% according to valid_policy.json.
10. Restore the original policy file.

> Note: The reason that we wait at least 65 seconds is that thermal policy run every 60 seconds according to design.
> For switch who has only one PSU, step 6 and step 7 will be ignored.

## 3.5 Invalid Policy Format Load Test

Invalid policy format test verifies that thermal control daemon does not exit when loading a invalid_format_policy.json file. The thermal control daemon cannot perform any thermal policy in this case, but FAN monitor and thermal monitor should still work.

### Procedure

1. Testbed setup.
2. Copy invalid_format_policy.json to pmon docker and backup the original one.
3. Restart thermal control daemon to reload policy configuration file.
4. Verify thermal control daemon can be started up. Verify error log about loading invalid policy file is output.
5. Restore the original policy file.

## 3.6 Invalid Policy Value Load Test

Invalid policy value test verifies that thermal control daemon does not exit when loading a invalid_value_policy.json file. The thermal control daemon cannot perform any thermal policy in this case, but FAN monitor and thermal monitor should still work.

### Procedure

1. Testbed setup.
2. Copy invalid_value_policy.json to pmon docker and backup the original one.
3. Restart thermal control daemon to reload policy configuration file.
4. Verify thermal control daemon can be started up. Verify error log about loading invalid policy file is output.
5. Restore the original policy file.
## 2.1 Thermal policy json tests 

 

### Pass/Fail Criteria
*  Execute the above test cases

# Mellanox Specific Test Cases

## 3.1 ~~Ensure that the hw-management service is running properly~~



## 3.2 ~~Check SFP using ethtool~~


## 3.3 ~~Check SYSFS~~


## 3.4 ~~Verify that `/var/run/hw-management` is mapped to docker pmon~~

