# Platform Test plan for Chassis 
- [Introduction](#introduction)
- [Chassis Platform Test Cases](#chassis-platform-test-cases)
  - [1.1 Check platform information after upgrade and reboot](#11-check-platform-information-after-upgrade-and-reboot)
  - [1.2 Check SSD health](#12-check-ssd-health)
  - [1.3 Power cycle chassis](#13-power-cycle-chassis)
  - [1.4 Replace Supervisor Card](#14-replace-supervisor-card)
  - [1.5 Fabric card removal and insertion](#15-fabric-card-removal-and-insertion)
  - [1.6 Multiple Fabric cards removal and insertion](#16-multiple-fabric-cards-removal-and-insertion)
  - [1.7 Console port](#17-console-port)
  - [1.8 USB port](#18-usb-port)

- [LED Test Cases](#led-test-cases)
  - [2.1 Check system LED](#21-check-system-led)
  - [2.2 Check fan Tray LED](#22-check-fan-tray-led)
  - [2.32.3 Check Master Power LED](#23-check-master-power-led)
  - [2.4 Check LEDs for 100G port](#24-check-leds-for-100g-port)
  - [2.5 Check LEDs for 400G port](#25-check-leds-for-400g-port)
  - [2.5 Check activity LED for management port](#25-check-led-for-management-port)
  
- [Optics Test Cases](#optics-test-cases)
  - [3.1 100G optic cable removal insert](#33-100G-optic-cable-removal-insert)
  - [3.2 400G optic cable removal insert](#34-400G-optic-cable-removal-insert)
  - [3.3 100G optic module removal insert](#35-100G-optic-module-removal-insert)
  - [3.4 400G optic module removal insert](#36-400G-optic-module-removal-insert)
  - [3.5 New Link detection after reboot](#37-new-link-detection-after-reboot)

  
- [PSU Test Cases](#psu-test-cases)
  - [4.1 Multiple PSU removal](#42-multiple-psu-removal)
  - [4.2 Insert new PSU](#43-psu-addition)
  - [4.3 Power cable remove/insert](#44-psu-cable-removal)

- [FAN Tray Test Cases](#fan-tray-test-cases)
  - [5.1 Remove and Insert back a Fan Tray](#51-remove-insert-fan-tray)
  - [5.2 Multiple Fan Tray removal](#52-multiple-fan-tray-removal)
  - [5.3 Insert Fan Tray](#53-fan-tray-addition)

- [Line Card Test Cases](#line-card-test-cases)
  - [6.1 Remove Insert Line Card](#61-remove-insert-line-card)
  - [6.2 Insert new line Card](#62-insert-new-line-card)
  - [6.3 Replace Line Card](#63-replace-line-card)

  
# Introduction 
This test plan is to check the functionality of manual tests for platform related components for a chassis and **not automatable** tests. 
These software components are for managing platform hardware, including FANs, thermal sensors, SFP, transceivers, pmon, etc.

Assumption: 
* For lab trial the topology we will use will be t2-chassis topology as proposed for OC test cases. 
* For GA we will use fully loaded chassis i.e. all fabric cards, line cards present and atleast one of each hwsku type 
line card with all links connected


# Chassis Platform Test Cases
The test is to check platform related information on chassis after software upgrade and reboot

## 1.1 Check platform information after upgrade and reboot

### Steps

* Run `show platform summary`, `show platform syseeprom`
* Upgrade the chassis
* Run `show platform summary`,`show platform syseeprom`
* reboot multiple times


### Verify in
* CPM 
* Line cards

### Topology
* T2
* Fully Loaded chassis

### Pass/Fail Criteria

* `show platform summary` should output these fields correct. Information unchanged after image upgrade


## 1.2 Check SSD health after upgrade and reboot
The test is to check ssd on chassis after software upgrade and reboot
### Steps

* Run `show platform ssd-health`
* Run `show platform ssd-health --vendor`
* Reboot multiple times
* Insert remove cards multiple times


### Verify in
* CPM 
* Line cards

### Topology
* T2
* Fully Loaded chassis

### Pass/Fail Criteria

* `show platform ssd-health`,`show platform ssd-health --vendor` have correct fields and value, no error on cli command execution

## 1.3 Power cycle Chassis
Test chassis behavior adter power cycle
This test check status of following commands frequently:
  * `show chassis-module status`
  * `show chassis-module midplane-status`

### Topology
* T2
* Fully Loaded chassis

### Steps

* Manually disconnect all power connection
* Wait for 30 seconds and connect all power
* Check all dockers are up, Run `show interface status`, 'show chassis-module status' and `show chassis-module midplane status` after bootup


### Pass/Fail Criteria
* chassis boot up successful, output of cli commands as expected


## 1.4 Replace supervisor Card
Test to check recovery after replacing supervisor card 
This test check status of following commands frequently:
  * `show chassis-module status`
  * `show chassis-module midplane-status`

### Topology
* Fully Loaded chassis
 
### Steps

* Power down Chassis
* Replace supervisor card
* Load correct image on supervisor card and copy config from old card
* Check all dockers are up, Run `show interface status`, 'show chassis-module status' and `show chassis-module midplane status` after bootup

### Pass/Fail Criteria
* verify new card boots up and config as expected

## 1.5 Fabric card removal and insertion
Test to check chassis behavior after Fabric card removed and is re-inserted, implicitly tests bdb
This test check status of following commands frequently:
  * `show chassis-module status`
  * `show chassis-module midplane-status`
  * check internal connectivity and bgp neighborship

### Topology
* T2
* Fully Loaded chassis 

### Steps
* Remove Fabric Card
* Insert back Fabric card and verify links

### Pass/Fail Criteria
* SFM detection and correct status for SFM, mdiplane connectivity with active line cards and supervisor

## 1.6 Multiple Fabric cards removal and insertion
Test to check chassis behavior after Fabric card removed and is re-inserted, implicitly tests bdb
This test check status of following commands frequently:
  * `show chassis-module status`
  * `show chassis-module midplane-status`
  * check internal connectivity and bgp neighborship

### Topology
* Fully Loaded chassis  

### Steps
* Remove two or  Fabric Card
* Insert back removed Fabric cards and verify links

### Pass/Fail Criteria
* SFM detection and correct status for SFM, mdiplane connectivity with active line cards and supervisor

## 1.7 Console port
Test to check cosnole port functionality

### Topology
* T2
* Fully Loaded chassis

### Steps
* Make sure console port cable connected and login via console port
* Change cosnole port baud rate and make sure able to connect with new setting
* Remove cable and re-insert and login
* Repeat cable connect/disconnect 

### Pass/Fail Criteria
* Console connection works and successful login


## 1.8 USB port
Test to check USB port fucntionality

### Topology
* T2
* Fully Loaded chassis

### Steps
* Insert USB drive into usb port and mount usb 
* Transfer files from USB to local drive and from local drive to USB
* Remove and Insert USB multiple times
* Reboot Chassis with USB inserted
* Reboot with USB inserted remove while system boots up

### Pass/Fail Criteria
* USB detected and mounted successfully
* No error in file transfers


# LED Test Cases

## 2.1 Check system LED 

This test case will check system led 

### Topology
* T2
* Fully Loaded chassis

### Steps
* Turn the chassis up and check for the system LED and verify its blinking green when its booting up and then solid green when its completely booted  
* Reboot the Chassis multiple times and verify the LED works as expected
* Check the LED behavior changes to blinking when a critical docker restarts 
* Verify with a bad build which doesn't bring all the process up to make sure LED doesn't turn solid green 

## 2.2 Check fan Tray LED

This test case will check fan led

### Topology
* T2
* Fully Loaded chassis

### Steps
* With 2 fans in and running, LED should be green
* Reboot the box multiple times and verify the LED works as expected
* Verify the LED by taking a fan out and verify the LED turns orange 
* When the fan is put back verify LED turns Solid Green

### Verify in
* Chassis 

### Pass/Fail Criteria
* Led for the fan should be  `SOLID GREEN`

## 2.3 Check Master Power LED

This test case will check psu led

### Topology
* T2
* Fully Loaded chassis

### Steps
* With multiple PSU's in and running, LED should be green when power consumption is below power supplied
* Reboot the Chassis multiple times and verify the LED works as expected
* Verify the LED by taking  PSU out so power consumption is above power supplied and verify the LED turns Red
* When the PSU  are inserted back to power consumption below power supplied verify LED turns Solid Green


### Verify in
* Chassis 

### Pass/Fail Criteria
* LED color as expected in each step

## 2.4 Check LEDs for 100G port

This test case will check led for each port on applicable hwsku

### Topology
* T2
* Fully Loaded chassis

### Steps
* Verify the LED if the link is up 
* Pass traffic and verify blinking green 
* bring down link and check led off
* remove cable and check LED color
* Check this on all 100G ports  
* Reboot the box and verify above steps again

### Verify in
* Line card with 100G ports


## 2.5 Check LEDs for 400G port

This test case will check led for each port on applicable hwsku

### Topology
* T2
* Fully Loaded chassis

### Steps
* Verify the LED if the link is up 
* Pass traffic and verify blinking green 
* bring down link and check led off
* remove cable peer side and check LED color
* Check this on all 400G ports  
* Reboot the box and verify above steps again

### Verify in
* Line card with 400G ports

## 2.5 Check LEDs for management port

This test case will check activity led for management port

### Topology
* T2
* Fully Loaded chassis

### Steps
* Verify the LED if the link is up 
* Pass traffic and verify blinking green 
* LED is off when link is down
* Reboot the box and verify

### Verify in
* supervisor


# Optic Test Cases
Following section focuses on testing transceiver and related component

# 3.1 100G optic cable removal insert
This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Topology
* T2
* Fully Loaded chassis

### Steps
* Disconnect cable on peer for 100G 
* Reconnect cable on peer for 100G
* Repeat cable removal on local interface

### Verify in
* Line cards

### Pass/Fail Criteria
* 100g link status and DOM info updated with removal and insertion

# 3.4 400G optic cable removal insert
This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Topology
* T2
* Fully Loaded chassis

### Steps
* Disconnect cable on peer for 400G 
* Reconnect cable on peer for 400G
* Repeat cable removal on local interface

### Verify in
* Line cards

### Pass/Fail Criteria
* 400g link status and DOM info updated with removal and insertion

# 3.5 100G optic module removal insert
This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Topology
* T2
* Fully Loaded chassis

### Steps
* Remove 100g optic module from line card
* Insert back 100g optic module 

### Verify in
* Line cards

### Pass/Fail Criteria
* 100g optical info updated, syslog has correct logs

# 3.6 400G optic module removal insert
This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Topology
* T2
* Fully Loaded chassis


### Steps
* Remove 400g optic module from line card
* Insert back 100g optic module 

### Verify in
* Line cards

### Pass/Fail Criteria
* 400g optical info updated, syslog has correct logs

# 3.7 New Link detection after reboot
This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Topology
* Fully Loaded chassis

### Steps
* Power down line card
* Insert new optical modules (100G and 400G)
* Power up line card

### Verify in
* Line cards

### Pass/Fail Criteria
* Verify new optical modules detected and information updated
  
# PSU Test Cases
Following section focusing on testing psus in chassis platform

### Pass/Fail Criteria
Removing PSU the information is reflected in show command, After inserting back psu the information is read correctly

## 4.1 Multiple PSU removal

### Topology
* Fully Loaded chassis

### Steps
* Run `show platform psu`
* Remove an active psus and power redis db command, until power supplied < power consummed
* Inser back psus and run power redis db command again

### Pass/Fail Criteria
Removing PSU the information is reflected in show command. Component brought down when power supplied < power consummed.
After inserting back psu the information is read correctly.

## 4.2 Insert new PSU

### Topology
* T2

### Steps
* Insert a PSU in empty psu slot
* Run `show platform psu` and power redis command

### Pass/Fail Criteria
PSU information shown correctly, psu status and power supply have correct information

## 4.3 Power cable remove/insert

### Topology
* T2
* Fully Loaded chassis

### Steps

* remove power cable for an active psu 
* Run `show platform psu status` and power redis command

### Pass/Fail Criteria
Psu status and power supply have correct information updated

# FAN Tray Test Cases 


## 5.1 Multiple Fan Tray removal

### Topology
* Fully Loaded chassis

### Steps
* Run `show platform fan`
* Remove an active fan trays till only one fan left Run `show platform fan` and thermal db command
* Insert back Fan trays
* Run `show platform fan` and thermal db redis command

### Pass/Fail Criteria
* Removing Fan tray the information is reflected in show command, After inserting back fan tray the information is read correctly
* Verify fan speed changes for active fans after one fan tray removed

## 5.2 Insert Fan Tray

### Topology
* T2

###Steps
* Insert a fan tray in empty psu slot
* Run `show platform fan` and thermal db redis command

### Pass/Fail Criteria
FAN Tray detected, status and fan information read correctly

# Line Card Test Cases

## 6.1 Remove Insert Line Card
This test case needs to frequently check various status, the status to be checked and commands for checking them:
  * `show chassis-module status`
  * `show chassis-module midplane-status`
  * `sudo monit status`
  * `docker ps -a`

### Topology
* T2
* Fully Loaded chassis

### Steps
* Remove a Line card from slot
* Insert back line card
* Repeat removal/insertion multiple times

### Pass/Fail Criteria
* Line card boots up correctly, correct information for show commands on supervisor and line cards
* Midplane connectivity between supervisor and line card

## 6.2 Insert a new line Card
This test case needs to frequently check various status, the status to be checked and commands for checking them:
  * `show chassis-module status`
  * `show chassis-module midplane-status`
  * `sudo monit status`
  * `docker ps -a`


### Topology
* T2

### Steps
* Insert a Line card in empty slot
* Install correct image on line card

### Pass/Fail Criteria
* Line card boots up correctly, correct information for show commands on supervisor and line card
Midplane connectivity between supervisor and line card

## 6.3 Replace a Line Card
This test case needs to frequently check various status, the status to be checked and commands for checking them:
  * `show chassis-module status`
  * `show chassis-module midplane-status`
  * `sudo monit status`
  * `docker ps -a`

### Topology
* T2
* Fully Loaded chassis

### Steps
* Removed active Line card 
* Insert a Line card in removed line card slot
* Install correct image on line card and reboot

### Pass/Fail Criteria
* Line card boots up correctly, correct information for show commands on supervisor and line card.
* Midplane connectivity between supervisor and line card

De-scoped:

This test case will verify 100G DAC cables

## 7.1 100G DAC test

This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`


### Steps
* connect 100G DAC cable to port on Line card
* Verify Link up and LED
* Verify transceiver dom info
* Repeat test for different cable lengths

### Verify in
* Line cards

### Pass/Fail Criteria
* 100G DAC cable link successfully comes up and correct info in show command

## 7.2 400G DAC test
This test case needs to frequently check various status, the status to be checked and commands for checking them:
* status of interfaces and port channels
  * `show interface status`
  * `show interface portchannel`
* status of transceivers
  * `show interface transcever presence`
  * `show interface transcever eeprom`
  * `show interface transcever eeprom --dom`
  * `redis-cli -n 6 keys TRANSCEIVER_INFO*`

### Steps
* connect 400G DAC cable to port on Line card
* Verify Link up and LED
* Verify transceiver dom info
* Repeat test for different cable lengths

### Verify in
* Line cards

### Pass/Fail Criteria
* 400G DAC cable link successfully comes up and correct info in show command