- [Introduction](#introduction)
- [Platform Test Cases](#platform-test-cases)
  - [1.1 Check platform information](#11-check-platform-information)
  - [1.2 Check SFP status and configure SFP](#13-check-sfp-status-and-configure-sfp)
  - [1.3 Check xcvrd information in DB](#14-check-xcvrd-information-in-db)
  - [1.4 Sequential syncd/swss restart](#15-sequential-syncdswss-restart)
  - [1.5 Reload configuration](#16-reload-configuration)
  - [1.6 COLD/POWER OFF reboot of the chassis](#17-coldpower-offwatchdog-reboot-of-the-chassis)
  - [1.7 COLD/POWER OFF reboot of the line card](#17-coldpower-offwatchdog-reboot-of-the-line-card)
  - [1.8 Check thermal sensors output using new OPTIC cables](#18-check-thermal-sensors-output-using-new-optic-cables)
  - [1.9 Manually plug in and pull out PSU modules](#19-manually-plug-in-and-pull-out-psu-modules)
  - [1.10 Manually plug in and pull out PSU power cord](#110-manually-plug-in-and-pull-out-psu-power-cord)
  - [1.11 Manually plug in and pull out FAN modules](#111-manually-plug-in-and-pull-out-fan-modules)
  - [1.12 Manually plug in and pull out SFPs](#112-manually-plug-in-and-pull-out-sfps)
  - [1.13 Check platform daemon status](#113-check-platform-daemon-status)
  - [1.14 Verify 100G Optics detection with various lengths (nokia_new)](#114-verify-100g-optics-detection-with-various-lengths-nokia_new)
  - [1.15 Verify 400G Optics detection (nokia_new)](#115-verify-400g-optics-detection-nokia_new)
  - [1.16 Perform fresh boot on line card with USB dongle (nokia_new)](#116-perform-fresh-boot-on-line-card-with-usb-dongle-nokia_new)
  - [1.17 Perform fresh boot on line card from a http server (nokia_new)](#117-perform-fresh-boot-on-line-card-from-a-http-server-nokia_new)
  - [1.18 Verify whether system reboots golden image if upgrade of primary image fails for chassis  (nokia_new)](#118-verify-whether-system-reboots-golden-image-if-upgrade-of-primary-image-fails-for-chassis-nokia_new)
  - [1.19 Verify whether system reboots golden image if upgrade of primary image fails per line card (nokia_new)](#119-verify-whether-system-reboots-golden-image-if-upgrade-of-primary-image-fails-per-line-card-nokia_new)
  - [1.20 Verify boot diagnostics can be performed (nokia_new)](#120-verify-boot-diagnostics-can-be-performed-nokia_new)
  - [1.21 Verify all Fabric links are coming up in IMM (nokia_new)](#121-verify-all-fabric-links-are-coming-up-in-imm-nokia_new)
  - [1.22 Verify speed of each ramon link is 53.1G (nokia_new)](#122-verify-speed-of-each-ramon-link-is-53.1g-nokia_new)
  - [1.23 Verify all links comes up after adding/removing IMM (nokia_new)](#123-verify-all-links-comes-up-after-adding-removing-imm-nokia_new)
  - [1.24 Reboot IMM from cli and verify all ports (nokia_new)](#124-reboot-imm-from-cli-and-verify-all-ports-nokia_new)
  - [1.25 Check platform chassis information (new_pr)](#125-check-platform-chassis-information-new_pr)
  - [1.26 Configure platform chassis modules (new_pr)](#126-configure-platform-chassis-modules-new_pr)
  - [1.27 Verify config db redis dump output (new_pr)](#127-verify-config-db-redis-dump-output-new_pr)
  - [1.28 Verify state db redis dump output (new_pr)](#128-verify-state-db-redis-dump-output-new_pr)
  - [1.29 Check thermal sensor output in chassis state db (new_pr)](#129-check-thermal-sensor-output-in-chassis-state-db-new_pr)
  - [1.30 Check power budget output in chassis state db (new_pr)](#130-check-power-budget-output-in-chassis-state-db-new_pr)
  - [1.31 Check chassisd process automatic restart](#131-check-chassisd-process-automatic-restart)

- [LED Test Cases](#led-test-cases)
  - [2.1 Check system LED](#21-check-system-led)
  - [2.2 Check fan LED](#22-check-fan-led)
  - [2.3 Check psu LED](#23-check-psu-led)
  - [2.4 Check activity LEDs for ports](#24-check-activity-for-ports)
  - [2.5 Check ssdhealth](#25-check-ssdhealth)
  
- [Thermal policy json tests](#thermal-policy-json-tests)
  - [3.1 Show FAN Status Test](#31-show-fan-status-test)
  - [3.2 Show Thermal Status Test](#32-show-thermal-status-test)
  - [3.3 Fan Test](#33-fan-test)
  - [3.4 PSU Absence Test](#34-psu-absence-test)
  - [3.5 Invalid Policy Format Load Test](#35-invalid-policy-format-load-test)
  - [3.6 Invalid Policy Value Load Test](#36-invalid-policy-value-load-test)
  
- [Platform API Test Cases](#platform-api-test-cases)
  - [4.1 Check platform API implementation](#41-check-platform-api-implementation)
  - [4.2 APIs for modular chassis support (new_pr)](#42-apis-for-modular-chassis-support-new_pr)
  - [4.3 APIs for power consumption and supply for modular chassis (new_pr)](#43-apis-for-power-consumption-and-supply-for-modular-chassis-new_pr)
  - [4.4 APIs for thermalctld for recording min and max temperature (new_pr)](#44-apis-for-thermalctld-for-recording-min-and-max-temperature-new_pr)
  
- [Descoped for Beta](#descoped-for-beta)
  * 5.1 Add/remove multiple SFM/IMM and verify the power consumption
  * 5.2 Continously reload all IMMs at the same time and verify whether IMM img gets downloaded to IMM from CPM successfully
  * 5.3 Remove IMM during BDB download and verify whether B2B download restarts when IMM comes back UP
  * 5.4 Connect all SFMs and verify whether it is powered up and remove/add physically - Tests the i2c bus between CPU Ctrl FPGA & SFMs
  * 5.5 IMM should not crash when rebooting with all storage devices such as SSD and SD cards disk space are used up
  * 5.6 Various tests related to alarm thresholds for temperature, input power and laser bias

- [Descoped for GA](#descoped-for-GA)
  * 6.1 Verify 100G optics in 400G ports
  * 6.2 Tests related to the speed of fabric links
  * 6.3 Tests related to the FPGA
  * 6.4 Tests related to CPM Slot-B
  * 6.5 Tests related to PHY congestion
  * 6.6 Tests related to the file system
  * 6.7 RFC 2544 and end-to-end datapath performance
  * 6.8 SRL Tests related to IDB not applicable for disaggregated chassis
  * 6.9 Upgrade/downgrade BIOS in CPM and IMM and verify the sytem state
  * 7.0 Verify the boot order sequence if one of the component fails like USB or HDD
  * 7.1 Load the image with USB (with various capacity) and check whether system boots up without any issues
  * 7.2 Running different images on different LCs
  * 7.3 Perform on-demand diagnostics for every possible components and verify it is successful

# Introduction

This test plan is to check the functionalities of platform related components. These software components are for managing platform hardware, including FANs, thermal sensors, SFP, transceivers, pmon, etc.

## Important items of note
* Line cards will be tested in slots that would be staged for the customer for Beta and will be tested in all the slots for GA
* For Beta, it is assumed that the CPM will always be inserted into slot A

## Reference
The test cases are grouped in multiple categories of which the below are the open source test plan links:
* Platform test cases for all vendors from [https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md].
* Thermal policy test cases from [https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_thermal_control_test_plan.md]

In Platform test cases, some steps are platform dependent. Detailed information will be given in the test cases.

# Platform Test Cases

## 1.1 Check platform information

### Steps

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
>>> m = imp.load_source('eeprom', '/usr/share/sonic/device/x86_64-mlnx_msn2740-r0/plugins/eeprom.py')
>>> t = m.board('board', '', '', '')
>>> e = t.read_eeprom()
>>> t.decode_eeprom(e)
TlvInfo Header:
   Id String:    TlvInfo
   Version:      1
   Total Length: 507
TLV Name             Code Len Value
-------------------- ---- --- -----
Product Name         0x21  64 Panther Eth 100
Part Number          0x22  20 MSN2700-CS2F
Serial Number        0x23  24 MT1533X04568
Base MAC Address     0x24   6 E4:1D:2D:F7:D5:5A
Manufacture Date     0x25  19 08/16/2015 22:28:24
Device Version       0x26   1 0
MAC Addresses        0x2A   2 2
Manufacturer         0x2B   8 Mellanox
Vendor Extension     0xFD  36
Vendor Extension     0xFD 164
Vendor Extension     0xFD  36
Vendor Extension     0xFD  36
Vendor Extension     0xFD  36
ONIE Version         0x29  21 2018.05-5.2.0004-9600
CRC-32               0xFE   4 0x371DD10F

>>>
```
### Verify in
* CPM 
* Line cards

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
TlvInfo Header:
   Id String:    TlvInfo
   Version:      1
   Total Length: 507
TLV Name             Code Len Value
-------------------- ---- --- -----
Product Name         0x21  64 Panther Eth 100
Part Number          0x22  20 MSN2700-CS2F
Serial Number        0x23  24 MT1533X04568
Base MAC Address     0x24   6 E4:1D:2D:F7:D5:5A
Manufacture Date     0x25  19 08/16/2015 22:28:24
Device Version       0x26   1 0
MAC Addresses        0x2A   2 2
Manufacturer         0x2B   8 Mellanox
Vendor Extension     0xFD  36
Vendor Extension     0xFD 164
Vendor Extension     0xFD  36
Vendor Extension     0xFD  36
Vendor Extension     0xFD  36
ONIE Version         0x29  21 2018.05-5.2.0004-9600
CRC-32               0xFE   4 0x371DD10F

(checksum valid)
```
* The syseeprom info output from cmd `show platform syseeprom` should comply with the info decoded using platform specific eeprom.py utility.

### Automation
Covered in existing Automated.
The step for turning on/off PSU needs programmable PDU. Need to implement a fixture for turning on/off PSU. When programmable PDU is not available in testbed, this step can only be tested manually. The fixture should be able to return information about whether this capability is supported. If not supported, skip this step in automatin.

## 1.2 Check SFP status and configure SFP

This case is to use the sfputil tool(need to verify if this needs to be supported) and show command to check SFP status and configure SFP. Currently the the only configuration is to reset SFP.
  * ~~`sfputil show presence`~~
  * `show interface transceiver presence`
  * ~~`sfputil show eeprom`~~
  * `show interface transceiver eeprom`
  * ~~`sfputil reset <interface name>`~~

### Steps
* Get the list of connected ports from `ansible/files/lab_connection_graph.xml`, all connected ports need to be checked.
* Use the ~~`sfputil show presence`~~ and `show interface transceiver presence` commands to check presence of ports.
* Use the ~~`sfputil show eeprom`~~ and `show interface transceiver eeprom` commands to check eeprom information of ports.
* ~~Use the `sfputil reset <interface name>` command to reset each port.~~
* Use the `show interface status` and `show interface portchannel` commands to check interface and port channel status against current topology.
### Verify in 
* line cards

### Pass/Fail Criteria

* Both ~~`sfputil show presence`~~ and `show interface transceiver presence` should list presence of all connected ports, for example:
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
~~* The `sfputil reset <interface name>` command should be successful without error.~~
```
admin@mtbc-sonic-03-2700:~$ sudo sfputil reset Ethernet0
Resetting port Ethernet0...  OK
```
* Verify that interface status is not affected after reading of EEPROM. Up and down status of interfaces and port channels should comply with current topology.

### Automation
Covered in exisiting automation

## 1.3 Check xcvrd information in DB
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
### Verify in
* Line cards

### Automation
Partly covered in existing automation

## 1.4 Sequential syncd/swss restart

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
### Verify in 
* Line cards

### Pass/Fail Criteria
* After restart, status of services, interfaces and transceivers should be normal:
  * Services syncd and swss should be active(running)
  * All interface and port-channel status should comply with current topology.
  * All ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.

### Automation
Partly covered in existing automation

## 1.5 Reload configuration

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
### Verify in
* Line cards

### Automation
Partly covered by existing automation. New automation required.

## 1.6 COLD/POWER OFF reboot of the chassis

### Steps
* Perform cold/power off reboot of the chassis
  * cold
    * Make use of commands to reboot the switch
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
### Verify in:
* Chassis

### Pass/Fail Criteria
* After reboot, status of services, interfaces and transceivers should be normal:
  *  Services syncd and swss should be active(running)
  *  Reboot cause should be correct
  *  All transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.
* Verify that there is no error in dmesg

### Automation
Partly covered by existing automation:
* ansible/roles/test/tasks/reboot.yml

## 1.7 COLD/POWER OFF reboot of the Line cards

### Steps
* Perform cold/power off reboot of the line cards
  * cold
    * Make use of commands to reboot the switch
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
### Verify in:
* Line cards

### Pass/Fail Criteria
* After reboot, status of services, interfaces and transceivers should be normal:
  *  Services syncd and swss should be active(running)
  *  Reboot cause should be correct
  *  All transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) should present.
* Verify that there is no error in dmesg

### Automation
Partly covered by existing automation:
* ansible/roles/test/tasks/reboot.yml

Need to port these scripts to pytest and cover the testing in this test case.

## 1.8 Check thermal sensors output using new OPTIC cables

### Steps
* Plug in new OPTIC cables
* Check the thermal sensors output using command `redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|Ethernet0"`. Replace 'Ethernet0' in the example with actual interface name.
### Verify in 
* Line cards

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
### Verify in
* Chassis

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
### Verify in
* Chassis 


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
### Verify in
* Chassis


### Pass/Fail Criteria
* Verify that command `show environment` or `sensors` can get correct FAN status and FAN speed
* Verify that various status are expected after manual intervention. Please refer to the test case description for detailed command for checking status and expected results.

### Automation
Manual intervention required, not automatable

## 1.12 Manually plug in and pull out SFPs

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

Expected results of checking various status:
* Services syncd and swss should be active(running)
* All interface and port-channel status should comply with current topology and hardware availability:
  * When cable is unplugged, interface should be down. If the interface was the last one in port channel, the port channel should be down as well.
  * After cable is plugged in, interface should be up. If the interface was in port channel, the port channel should be up as well.
* Transcevers of ports specified in lab connection graph (`ansible/files/lab_connection_graph.xml`) and unplugged should present. Transcever of cable unplugged port should be not present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check various status.
* Pull out an SFPs.
* Check various status.
* Plug in the SFPs back.
* Check various status.
### Verify in 
* Line cards

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
### Verify in
* CPM 
* Line cards

### Pass/Fail Criteria
* All the daemon status in the list shall be `RUNNING`

## 1.14 Verify 100G Optics detection with various lengths (nokia_new) 
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

Expected results of checking various status:
* Services syncd and swss should be active(running)
* All interface and port-channel status should comply with current topology and hardware availability:
  * When cable is unplugged, interface should be down. If the interface was the last one in port channel, the port channel should be down as well.
  * After cable is plugged in, interface should be up. If the interface was in port channel, the port channel should be up as well.
* Transcevers of ports specified in lab connection graph  and unplugged should present. Transcever of cable unplugged port should be not present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check various status after plugging in 100G cables.
* Pull out an optical cable.
* Check various status.
* Plug in the optical cable back.
* Check various status.

## 1.15 Verify 400G Optics detection with various lengths (nokia_new)  
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

Expected results of checking various status:
* Services syncd and swss should be active(running)
* All interface and port-channel status should comply with current topology and hardware availability:
  * When cable is unplugged, interface should be down. If the interface was the last one in port channel, the port channel should be down as well.
  * After cable is plugged in, interface should be up. If the interface was in port channel, the port channel should be up as well.
* Transcevers of ports specified in lab connection graph  and unplugged should present. Transcever of cable unplugged port should be not present.
* Average CPU and memory usage should be at the same level before and after the manual intervention.

### Steps
* Check various status after plugging in 400G cables.
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

## 1.16 Perform fresh boot on line card with USB dongle (nokia_new)
### Steps
 * Load a new image on the USB dongle 
 * Attach the dongle to a line card and do a fresh boot 
 * Verify everything came up good as expected 
 * Repeat this test on all the linecards in the chassis 

### Pass/Fail Criteria 
 *  Verify that the USB dongle is read correctly 
 *  Verify that the line card is upgraded 
 *  Verify that the line card came up correctly after the fresh boot
 *  Verify that the process worked on all the line cards in the chassis 
 

## 1.17 Perform fresh boot on line card from a http server (nokia_new)

### Steps
 * Load a new image on a http server 
 * Start the upgrade of the line card from the http server 
 * Verify everything came up good as expected 
 * Repeat this test on all the linecards in the chassis 

### Pass/Fail Criteria 
 *  Verify that the line card is upgraded 
 *  Verify that the line card came up correctly after the fresh boot
 *  Verify that the process worked on all the line cards in the chassis 

## 1.18 Verify whether system reboots golden image if upgrade of primary image fails on chassis (nokia_new)
### Steps
 * Start the upgrade with sonic installed with bogus image 
 * Verify the upgrade fails with primary image and check golden image loads
 * Verify everything came up good as expected 

### Pass/Fail Criteria 
 *  Verify each line card is upgraded 
 *  Verify that the line card came up correctly after the fresh boot


## 1.19 Verify whether system reboots golden image if upgrade of primary image fails per line card (nokia_new)
### Steps
 * Start the upgrade with sonic installed with bogus image 
 * Verify the upgrade fails with primary image and check golden image loads
 * Verify everything came up good as expected 
 * Repeat this test on all the linecards in the chassis 

### Pass/Fail Criteria 
 *  Verify that the line card is upgraded 
 *  Verify that the line card came up correctly after the fresh boot
 *  Verify that the process worked on all the line cards in the chassis 


## 1.20 Verify boot diagnostics can be performed (nokia_new)
### Steps
 * Manju to provide nokia_cmd to perform boot diags 
 * Will add more steps when i know more details 

### Pass/Fail Criteria 
 * Run the diags on a faulty card and make sure it fails 
 * Verify the output is logged and isnt too big of a file 

## 1.21 Verify all Fabric links are coming up in Line card (nokia_new)
### Steps 
 * Verify all the line cards and CPM are in the Line card
 * Verify all the fabric links are seen in the Line card
 * Remove a line card and verify the same reflects in the fabric links 
 * For Beta manju will provide nokia_cmd and for GA SFM_SAI should be used 

### Pass/Fail Criteria 
 * Verify all the fabric links are seen in Line card
 * Verify nokia_cmd has the required output 

## 1.22 Verify speed of each Ramon link is 53.1G (nokia_new)
### Steps  
 * For Beta manju will provide nokia_cmd and for GA SFM_SAI should be used 
 * Will add more steps later 

### Pass/Fail Criteria 
 * Verify nokia_cmd has the required output 

## 1.23 Verify all links comes up after adding/removing IMM (nokia_new)
### Steps  
 * Remove an IMM from the chassis
 * Verify all the links are shown as expected in the chassis 
 * Add the IMM back and verify the links again 

### Pass/Fail Criteria 
 * Verify nokia_cmd has the required output 
 * Verify if all the links are shown as expected

## 1.24 Reboot Line card from cli and verify all ports (nokia_new)
### Steps  
 * Reload line card from cli.
 * Check ports on the linecards in the chassis 
 * Repeat for all IMM's in the chassis 

### Pass/Fail Criteria 
 * Will add command here 
 * Verify redis-db has the output as well

## 1.25 Check platform chassis information (new_pr)
### PR - [Configure and show for platform chassis_modules #1145](https://github.com/Azure/sonic-utilities/pull/1145)
### Automation - Automatable
### Steps
 * Run command “show chassis-modules status”
 * Run command "show chassis-modules status LINE-CARD1"
 
### Verify in
 * cpm
 * imm

### Sample Output
 ```
 admin@sonic:~$ show chassis-modules status
 Name                      Description    Slot    Oper-Status    Admin-Status
-------------  -------------------------------  ------  -------------  --------------
CONTROL-CARD1                         cpm2-ixr      16         Online              up
 FABRIC-CARD1                             SFM1      17          Empty              up
 FABRIC-CARD2                             SFM2      18          Empty              up
 FABRIC-CARD3                             SFM3      19         Online              up
 FABRIC-CARD4                             SFM4      20          Empty              up
 FABRIC-CARD5                             SFM5      21         Online              up
 FABRIC-CARD6                             SFM6      22          Empty              up
   LINE-CARD1                        line-card       1          Empty              up
   LINE-CARD2                        line-card       2          Empty              up
   LINE-CARD3                        line-card       3          Empty              up
   LINE-CARD4                        line-card       4          Empty              up
   LINE-CARD5                        line-card       5          Empty              up
   LINE-CARD6                        line-card       6          Empty              up
   LINE-CARD7  		    	 line card       7         Online              up
   LINE-CARD8  		        line-card       8         Online              up
```
```
 admin@sonic:~$ show chassis-modules status LINE-CARD1 
         Name        Description    Slot    Oper-Status    Admin-Status
-------------  -----------------  ------  -------------  --------------
  LINE-CARD1  imm36-400g-qsfpdd       1         Online            down
```

### Pass/Fail Criteria
 * Verify all line cards detected in chassis show operational state is Online and admin state is up.
 * Verify the all fabric cards show up in the chassis output.
 * Verify all fabric cards operational state and admin state is correct.
 * Verify the control card operational state and admin state is correct.
 * Verify line card information on imm.

## 1.26 Configure platform chassis modules (new_pr)
### PR - [Configure and show for platform chassis_modules #1145]([https://github.com/Azure/sonic-utilities/pull/1145])
### Automation - Automatable
### Steps
 * Run command “sudo config chassis-modules shutdown <card>”
 * Run command "sudo config chassis-modules startup <card>"

### Verify in
 * cpm
 * imm

### Sample Output
```
 sudo config chassis-modules shutdown LINE-CARD1
 admin@sonic:~$ show chassis-modules status LINE-CARD1 
           Name        Description     	Slot    Oper-Status    Admin-Status
		-------------  -----------------  ------  -------------  --------------
  		LINE-CARD1  imm36-400g-qsfpdd       1       down            down
```
```
 sudo config chassis-modules startup LINE-CARD1
 admin@sonic:~$ show chassis-modules status LINE-CARD1 
           Name        Description     	Slot    Oper-Status    Admin-Status
		-------------  -----------------  ------  -------------  --------------
  		LINE-CARD1  imm36-400g-qsfpdd       1       Online           up
```

### Pass/Fail Criteria
 * Verify that show chassis command shows that the LINE-CARD1 is down after config shutdown using command “show chassis-modules status LINE-CARD1” on cpm.
 * Verify the config chassis-modules shutdown cannot be done from line card for cpm or another imm.
 * Verify that show chassis command shows that the LINE-CARD1 is Online after config startup using command “show chassis-modules status LINE-CARD1” on cpm.
 * Verify the config chassis-modules startup cannot be done from line card for cpm or another imm.

## 1.27 Verify config db redis dump output (new_pr)
### PR - [Configure and show for platform chassis_modules #1145](https://github.com/Azure/sonic-utilities/pull/1145)
### Automation - Automatable
### Steps
 * Shutdown one of the line card by using “sudo config chassis-modules startup LINE-CARD1”
 * Run command “redis-dump -d 4 -y -k "*CHASSI*”

### Verify in
 * cpm

### Sample Output
```
 admin@sonic:~$ redis-dump -d 4 -y -k "*CHASSI*"
		{
  		"CHASSIS_MODULE|LINE-CARD1": {
   		 "expireat": 1602657677.581144,
   		 "ttl": -0.001,
    		 "type": "hash",
    		 "value": {
     		 "admin_status": "down"
   			 }
  		      }
		}
```
### Pass/Fail Criteria
 * verify the line card that is Down is show in the redis output.

## 1.28 Verify state db redis dump output (new_pr)
### PR - [Configure and show for platform chassis_modules #1145](https://github.com/Azure/sonic-utilities/pull/1145)
### Automation - Automatable
### Steps
 * Run command “redis-dump -d 6 -y -k "*CHASSI*”

### Verify in
 * cpm
 * imm

### Sample Output
```
 admin@dut1-imm1:~$ redis-dump -d 6 -y -k "*CHASSI*"
{
  "CHASSIS_TABLE|CHASSIS 1": {
    "expireat": 1550415348.3291152, 
    "ttl": -0.001, 
    "type": "hash", 
    "value": {
      "module_num": "0"
    }
  }
```
### Pass/Fail Criteria
 * Verify that all modules show up in output.

## 1.29 Check thermal sensor output in chassis state db (new_pr)
### PR - [CHASSIS_STATE_DB on control-card for chassis state #395](https://github.com/Azure/sonic-swss-common/pull/395)
### Automation - Automatable
### Steps
 * Run command “redis-dump -p 6380 -d 13 -y -k "*TEMP*" "on cpm
 * Run command “redis-dump -d 6 -y -k "*TEMP*" on imm

### Verify in
 * cpm
 * imm
 
### Sample Output
```
 "TEMPERATURE_INFO_8|Thermal 7": {
    "expireat": 1605120521.5682561, 
    "ttl": -0.001, 
    "type": "hash", 
    "value": {
      "critical_high_threshold": "N/A", 
      "critical_low_threshold": "N/A", 
      "high_threshold": "105.0", 
      "low_threshold": "0.0", 
      "maximum_temperature": "127.0", 
      "minimum_temperature": "-2.0", 
      "temperature": "47.0", 
      "timestamp": "20190217 16:03:13", 
      "warning_status": "False"
    }

```
### Pass/Fail Criteria
 * High threshold is greater than maximum_temperature.
 * Low threshold is lesser than the minimum_temperature.
 * Warning status should be true if above requirement is not met otherwise False.
 
#### Todo
 * Manju to find out if there is a way to set the warning status
 * Manju to find out if there is way to change threshold during runtime.

## 1.30 Check power budget output in chassis state db (new_pr)
### PR - [PSUd changes to compute power-budget for Modular chassis #104](https://github.com/Azure/sonic-platform-daemons/pull/104)
### Automation - Semi-automatable , requires manual intervention to remove/plug in psu
### Steps
 * Run command “redis-dump -d 6 -y -k "*power*"”

### Verify in
 * cpm

### Sample Output
```
redis-dump -d 6 -y -k "*power*"
{
  "CHASSIS_INFO|chassis_power_budget 1": {
    "expireat": 1605209491.4552531, 
    "ttl": -0.001, 
    "type": "hash", 
    "value": {
      "": "", 
      "Consumed Power FABRIC-CARD0": "370", 
      "Consumed Power FABRIC-CARD1": "370", 
      "Consumed Power FABRIC-CARD2": "370", 
      "Consumed Power FABRIC-CARD3": "370", 
      "Consumed Power FABRIC-CARD4": "370", 
      "Consumed Power FABRIC-CARD5": "370", 
      "Consumed Power FanTray0": "500", 
      "Consumed Power FanTray1": "500", 
      "Consumed Power FanTray2": "500", 
      "Consumed Power LINE-CARD1": "1000", 
      "Consumed Power LINE-CARD7": "1000", 
      "Consumed Power SUPERVISOR0": "80", 
      "Supplied Power PSU7": "3000.0", 
      "Supplied Power PSU8": "3000.0", 
      "Supplied Power PSU9": "3000.0", 
      "Total Consumed Power": "5800.0", 
      "Total Supplied Power": "3000.0"
    }
```
### Pass/Fail Criteria
 * Verify the supplied power is > 0 using the above command e.g.: "Supplied Power PSU7": "3000.0"
 * Unplug one of the psu
 * Verify the supplied power is = 0.0 using the above command e.g.: “Supplied Power PSU7": "0.0"
 * Plug in the psu back.
 * Verify the supplied power is > 0 using the above command e.g.: "Supplied Power PSU7": "3000.0"
 * Verify the total consumed power should be equal to the total power consumed by line card, fabric card and control card.
 * Verify the total supplied power is equal to the total power supplied by line card, fabric card and control card.
 * Verify the consumed power should not be greater than the supplied power.
 * Verify when LINE CARD1 is shutdown by using config command, the consumed power is 0 for LINE_CARD1 and when it is started the consumed power is not 0
 * Verify when FABRIC CARD1 is shut down, the consumed power is 0 for FABRIC_CARD1 and when it is started the consumed power is not 0
 * Verify that when fan tray is removed the consumed power is 0 and when fan tray is re-inserted it is not 0.

#### Todo:
 * Manju : to find a way to power off fabric card and fan tray

## 1.31 Check chassisd process automatic restart 
### Automation - semi-Automatable, cannot automate chassisd process crash on cpm, will require reboot.
### Steps
 * Docker exec -it pmon bash
 * Ps -ef 
 * Kill -9 <chassisd process id>

### Verify in
 * cpm
 * imm

### Pass/Fail Criteria
 * Verify the chassisd process is automatically restarted on imm.
 * Verify the chassisd process is not recovered on cpm and will require reboot.

# LED Test Cases

## 2.1 Check system LED 

This test case will check system led 

### Steps
* Turn the box up and check for the system LED and verify its blinking green when its booting up and then solid green when its completely booted  
* Reboot the box multiple times and verify the LED works as expected
* Check the LED color changes if a docker restarts 
* Verify with a bad build which doesn't bring all the process up to make sure LED doesn't turn solid green 

### Verify in
* Chassis 

### Pass/Fail Criteria
* Led for the system should be  `SOLID GREEN`

## 2.2 Check  fan LED

This test case will check fan led

### Steps
* With 2 fans in and running, LED should be green
* Reboot the box multiple times and verify the LED works as expected
* Verify the LED by taking a fan out and verify the LED turns orange 
* When the fan is put back verify LED turns Solid Green
### Verify in
* Chassis 

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
### Verify in
* Chassis 

### Pass/Fail Criteria
* PSU for the fan should be `SOLID GREEN`

## 2.4 Check activity LEDs for ports

This test case will check activity led for each port

### Steps
* Verify the LED if the link is up 
* Pass traffic and verify blinking green 
* Check this on all ports  
* Reboot the box and verify
### Verify in
* Chassis 

## 2.5 Check ssdhealth  

This test case will check ssd health

### Steps
* Check SSD health with `sudo show platform ssdhealth`
* Verify it doesnt crash   
* Reboot the box and verify
### Verify in
* IMM cards 

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
### Verify in
* CPM 

## 3.2 Show Thermal Status Test

Show thermal status test verifies that all thermal related information can be shown correctly via `show platform temperature`.

### Procedure

1. Testbed setup.
2. Fill mock data for "temperature", "high_threshold", "high_critical_threshold".
3. Issue command `show platform temperature`.
4. Record the command output.
5. Verify that command output matches the mock data.
6. Restore mock data.
### Verify in
* CPM 


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
### Verify in
* CPM 

## 3.4 PSU Absence Test

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
### Verify in
* CPM 

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

# Platform API Test Cases

## 4.1 Check platform API implementation

All platform API methods will be exercised, and ensuring that:

* The vendor has implmented the method for the particular platform
* The API call returned 'sane' data (type is correct, etc.)
* Where applicable, the data returned is appropriate for the platform being tested (number of fans, number of transceivers, etc.)
* Where applicable, the data returned is appropriate for the specific DuT (serial number, system EERPOM data, etc.)

## Steps
run Automated test suites under /data/tests/platform_tests/api/ 
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
## 4.2 APIs for modular chassis support (new_pr)
### PR - [Introduce APIs for modular chassis support #124](https://github.com/Azure/sonic-platform-common/pull/124)
### Automation - Automatable
### Steps
 * verify following apis
```
module_base :
1. get_name() - Retrieves the name of the module prefixed by SUPERVISOR, LINE-CARD,FABRIC-CARD
2. get_description() - A string, providing the vendor's product description of the module.
3. get_slot() - An integer, indicating the slot number in the chassis
4. get_type() - A string, the module-type from one of the predefined types MODULE_TYPE_SUPERVISOR, MODULE_TYPE_LINE or MODULE_TYPE_FABRIC
5. get_oper_status()- A string, the operational status of the module from one of the predefined status values: MODULE_STATUS_EMPTY,  MODULE_STATUS_OFFLINE,MODULE_STATUS_FAULT, MODULE_STATUS_PRESENT or MODULE_STATUS_ONLINE
6. reboot() - bool: True if the request has been issued successfully, False if not
7. set_admin_state() - bool: True if the request has been issued successfully, False if not.

Chassis_base:
1. get_module_index() - A string, prefixed by SUPERVISOR, LINE-CARD or FABRIC-CARD Ex. SUPERVISOR0, LINE-CARD1, FABRIC-CARD5
2. get_supervisor_slot() - Returns an integer and vendor specific slot identifier
3. get_my_slot() - Returns an integer and vendor specific slot identifier

```
### Verify in
 * cpm
 * imm

### Pass/Fail Criteria
 * The vendor has implmented the method for the particular platform.
 * The API call returned 'sane' data (type is correct, etc.).
 * Where applicable, the data returned is appropriate for the specific DuT (slot number , supervisor slot, etc.).

## 4.3 APIs for power consumption and supply for modular chassis (new_pr)
### PR - [Common power consumption and supply APIs for modular chassis #136](https://github.com/Azure/sonic-platform-common/pull/136/files)
### Automation - Automatable
### Steps
 * Verify following Apis
```
Fan drawer base:
1. get_maximum_consumed_power() - A float, with value of the maximum consumable power of the component.

Modular base:
1. get_maximum_consumed_power() - A float, with value of the maximum consumable power of the component.

psu_base:
1. get_maximum_supplied_power() -A float number, the maximum power output in Watts, e.g. 1200.1 
2. get_status_master_led() - A string, one of the predefined STATUS_LED_COLOR_* strings.
3. set_status_master_led() - bool: True if status LED state is set successfully, False if not

chassis_base:
1. is_modular_chassis() - A bool value, should return False by default or for fixed-platforms. Should return True for supervisor-cards, line-cards etc running as part of modular-chassis.
```
### Verify in
 * cpm
 * imm

### Pass/Fail Criteria
 * The vendor has implmented the method for the particular platform.
 * The API call returned 'sane' data (type is correct, etc.).
 * Where applicable, the data returned is appropriate for the specific DuT.

## 4.4 APIs for thermalctld for recording min and max temperature (new_pr)
### PR - [Thermalctld APIs for recording min and max temp #131](https://github.com/Azure/sonic-platform-common/pull/131)
### Automation - Automatable
### Steps
 * Verify following APIs
 ```
 thermal_base:
 1. get_minimum_recorded()-A float number, the minimum recorded temperature of thermal in Celsius up to nearest thousandth of one degree Celsius, e.g. 30.125
 2. get_maximum_recorded() - A float number, the maximum recorded temperature of thermal in Celsius up to nearest thousandth of one degree Celsius, e.g. 30.125
 ```
### Verify in
 * cpm
 * imm

### Pass/Fail Criteria
 * The vendor has implmented the method for the particular platform.
 * The API call returned 'sane' data (type is correct, etc.).
 * Where applicable, the data returned is appropriate for the specific DuT.

# Descoped for Beta 

### 5.1 Add/remove multiple SFM/IMM and verify the power consumption is changed accordingly
### 5.2 Continously reload all IMMs at the same time and verify whether IMM img gets downloaded to IMM from CPM successfully
### 5.3 Remove IMM during BDB download and verify whether B2B download restarts when IMM comes back UP
### 5.4 Connect all SFMs and verify whether it is powered up and remove/add physically - Tests the i2c bus between CPU Ctrl FPGA & SFMs
### 5.5 IMM should not crash when rebooting with all storage devices such as SSD and SD cards disk space are used up
### 5.6 Bring Temp below low level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.7 Bring Temp above high level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.8 Bring Temp below low level warning threshold. Verify syslog threshold is generated [verify from info state ethernet <> too]
### 5.9 Bring Temp above high level alarm threshold. Verify syslog is generated [verify from info state ethernet <> too]
### 5.10 Bring Voltage below low level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.11 Bring Voltage above high level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.12 Bring Voltage below low level warning threshold. Verify syslog threshold is generated [verify from info state ethernet <> too]
### 5.13 Bring Volatage above high level alarm threshold. Verify syslog is generated [verify from info state ethernet <> too]
### 5.10 Bring Input power on channel 1 below low level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.11 Bring Input power  on channel 1 above high level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.12 Bring input power  on channel 1 below low level warning threshold. Verify syslog threshold is generated [verify from info state ethernet <> too]
### 5.13 Bring input power  on channel 1 above high level alarm threshold. Verify syslog is generated [verify from info state ethernet <> too]
### 5.14 Bring Output power on channel 1 below low level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.15 Bring Output power  on channel 1 above high level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.16 Bring Output power  on channel 1 below low level warning threshold. Verify syslog threshold is generated [verify from info state ethernet <> too]
### 5.17 Bring Output power  on channel 1 above high level alarm threshold. Verify syslog is generated [verify from info state ethernet <> too]
### 5.18 Bring laser bias current on channel 1 below low level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.19 Bring laser bias current  on channel 1 above high level alarm threshold. Verify alarm is generated [verify from info state ethernet <> too]
### 5.20 Bring laser bias current  on channel 1 below low level warning threshold. Verify syslog threshold is generated [verify from info state ethernet <> too]
### 5.21 Bring laser bias current on channel 1 above high level alarm threshold. Verify syslog is generated [verify from info state ethernet <> too]

# Descoped for GA
### 6.1 Verify 100G optics in 400G ports
### 6.2 Verify whether the speed of fabric link in IMM is 53.1G
### 6.3 Send line rate traffic on the ports which are connected to same PHY and verify whether there is no congestion in the PHY level (Covered in RFC2544)
### 6.4 Send line rate traffic on the ports across PHY and verify there is no congestion (Covered in RFC2544)
### 6.5 Send line rate traffic on the ports across different CPU CORE and verify the behavior(Covered in RFC2544)
### 6.6 Congest the IDB vlan traffic and verify control plane protocol traffic is not affected - This is to stress the link between LC CPU-->IOCTL FPGA-->ELK-->CPU CTL FPGA path(not applicable)
### 6.7 Congest the Control plane traffic and verify whether IDB traffic is not affected and config gets pushed successfully - This is to stress the link between LC CPU-->IOCTL FPGA-->ELK-->CPU CTL FPGA path(not applicable)
### 6.8 Send continous ping from IOCTL FPGA to CPU CTrl FPGA and test the link b/w
### 6.9 Check whether ARP tables are populated properly in IMM and CPM to talk via Elkhound
### 6.10 Add/remove IMM and verify IMM can reach the CPM via elkhound
### 6.11 Check whether multiple vlans are configured in IMM between LC CPU & FPGA for control & idb traffic
### 6.12 Check whether idb & control traffic are prioritized/classified with different dot1p values, sent to Elkhound and reaches CPM
### 6.13 Perform shut/noshut of the FPGA links in IMM and verify communication between IMM and CPM is recovered
### 6.14 Verify Elkhound , B2B and I2C bus testcases by moving the CPM to slot-B
### 6.15 Send traffic from J2 to LC CPU via the PCIe link - mostly need to use some internal dev apps to generate huge traffic
### 6.16 Upgrade/downgrade BIOS in CPM and IMM and verify the sytem state
### 6.17 Upgrade/downgrade the QFPGA and verify the system state
### 6.18 Verify the boot order sequence if one of the component fails like USB or HDD
### 6.19 Load the image with USB(with various capacity) and check whether system boots up without any issues
### 6.20 Running different images on different LCs
### 6.21 Perform on-demand diagnostics for every possible components and verify it is successful
### 6.22 Send full line rate on 12 100G ports with only 1 SFM which create back pressure in SFM and verify the behavior
### 6.23 Shut all fabric links except 1 in IMM and send line rate traffic in 1 100G port which increases the buffer . Now slowly bringup the fabric links and verify the behavior. During these tests, monitor the temperature of each component
### 6.24 Perform active CPM admin reload and verify whether elkhound and ramon asics are coming up after reload(covered in reload test)
### 6.25 Pull active CPM reload verify whether elkhound and ramon asics are coming up after reload(covered in reload test)
### 6.26 Reload one SFM and measure traffic loss. Repeat the same for multiple SFM reloads at same time
### 6.27 Check whether all files are present in the respective location as per the PRD for eg: check for app binaries, shared lib, system config json, license, self-signed certs & , env, tls certs, yml config, yang model, app pid, tmpfs logging, persistent logging
### 6.28 Insert both CPM A & CPMB and bring up the Ramon to make sure it comes up.
### 6.29 Check whether link between CPMA & CPMB is coming up and send traffic in line rate
