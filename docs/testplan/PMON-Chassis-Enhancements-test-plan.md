# Test plan for PMON enhancements for Chassis 

- [Introduction](#introduction)
- [CLI Test Cases](#cli-test-cases)
    - [1.1 Check platform chassis module status ](#11-check-platform-chassis-module-status)
    - [1.2 Configure platform chassis modules](#12-configure-chassis-modules)
    - [1.3 Check platform chassis midplane status ](#13-check-platform-chassis-midplane-status)
    - [1.4 Check thermal sensor output in chassis state db](#14-check-thermal-sensor-output-in-chassis-state-db)
    - [1.5 Check power budget output in chassis state db ](#15-check-power-budget-output-in-chassis-state-db)
- [APIs for module base added for chassis](#apis-for-module-base-added-for-chassis)
    - [2.1 Test api get_name](#210-test-api-is_midplane_reachable)
    - [2.2 Test api get_description](#22-test-api-get_description)
    - [2.3 Test api get_type](#23-test-api-get_type)
    - [2.4 Test api get_slot](#24-test-api-get_slot)
    - [2.5 Test api get_oper_status](#25-test-api-get_oper_status)
    - [2.6 Test api reboot](#26-test-api-reboot)
    - [2.7 Test api get_set_admin_state](#27-test-api-set_admin_state)
    - [2.8 Test api get_maximum_consumed_power](#28-test-api-get_maximum_consumed_power)
    - [2.9 Test api get_midplane_ip](#29-test-api-get_midplane_ip)
    - [2.10 Test api is_midplane_reachable](#210-test-api-is_midplane_reachable)
- [APIs for chassis base added for modular chassis](#apis-for-chassis-base-added-for-chassis)
    - [3.1 Test api get_module_index](#31-test-api-get_module_index)
    - [3.2 Test api get_supervisor_slot](#32-test-api-get_supervisor_slot)
    - [3.3 Test api get_my_slot](#33-test-api-get_my_slot)
    - [3.4 Test api is_modular_chassis](#34-test-api-is_modular_chassis)
- [APIs for power consumption and supply APIs for modular chassis](#apis-for-power-consumption-and-supply-apis-for-chassis)
    - [4.1 Test api get_maximum_supplied_power](#41-test-api-get_maximum_supplied_power)
    - [4.2 Test api get_status_master_led](#42-test-api-get_status_master_led)
    - [4.3 Test api set_status_master_led](#43-test-api-set_status_master_led)
- [APIs for thermal added for modular chassis](#apis-for-thermal-added-for--chassis)
   - [5.1 Test api get_minimum_recorded](#51-test-api-get_minimum_recorded)
   - [5.2 Test api get_maximum_recorded](#52-test-api-get_maximum_recorded)
- [APIs for fan_drawer added for modular chassis](#apis-for-fan_drawer-added-for--chassis)
   - [6.1 Test api get_maximum_consumed_power](#61-test-api-get_maximum_consumed_power)

## Introduction

This test plan ONLY covers the changes associated with PRs below:

1. [Configure and show for platform chassis_modules #1145](https://github.com/Azure/sonic-utilities/pull/1145)
2. [CHASSIS_STATE_DB on control-card for chassis state #395](https://github.com/Azure/sonic-swss-common/pull/395)
3. [PSUd changes to compute power-budget for Modular chassis #104](https://github.com/Azure/sonic-platform-daemons/pull/104)
4. [Introduce APIs for modular chassis support #124](https://github.com/Azure/sonic-platform-common/pull/124)
5. [Common power consumption and supply APIs for modular chassis #136](https://github.com/Azure/sonic-platform-common/pull/136/files)
6. [Thermalctld APIs for recording min and max temp #131](https://github.com/Azure/sonic-platform-common/pull/131)
7. [Modular Chassis - Midplane monitoring APIs #148](https://github.com/Azure/sonic-platform-common/pull/148)
8. [Modular-Chassis: Show midplane status #1267](https://github.com/Azure/sonic-utilities/pull/1267)


### Definitions/Abbrevations
  Term | Description
  -----|-------------
  VOQ  | Virtual Output Queue
  PSU  | Power Suppy Unit
  SFM  | Switch Fabric Card
  
### Test Plan 

#### Debuggability

The following are useful commands for validating the testcases that follow.

1. Use redis cli dump config db using `redis-dump -d 4 -y -k "*CHASSIS*"` after shutdown line card, for example
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
2. Use redis cli to dump state Db `redis-dump -d 6 -y -k "*CHASSIS*"`, for example: 
```
   "CHASSIS_MODULE_TABLE|LINE-CARD1": {
      "expireat": 980474761.732194, 
       "ttl": -0.001, 
       "type": "hash", 
       "value": {
                "desc": "imm36-400g-qsfpdd", 
                "oper_status": "down", 
                "slot": "1"
        }
   }
```
3. Use redis dump `redis-dump  -d 6 -y -k "*MIDPLANE*"` to get database information, for example:
```
   redis-dump  -d 6 -y -k "*MIDPLANE*"
   {
    "CHASSIS_MIDPLANE_TABLE|SUPERVISOR0": {
      "expireat": 1551352416.7598891, 
      "ttl": -0.001, 
      "type": "hash", 
      "value": {
            "access": "True", 
            "ip_address": "10.0.0.16"
            }
       }
    }
```

## CLI Test Cases

### 1.1 Check platform chassis module status 

#### Steps
 * Use command `show chassis-modules status` to get status of modular chassis 
 
 
#### Verify in
 * Supervisor
 * Line card

#### Sample Output
```
    On Supervisor:
    show chassis-module status
           Name                      Description    Physical-Slot    Oper-Status    Admin-Status
     ------------  -------------------------------  ---------------  -------------  --------------
     FABRIC-CARD0                             SFM1               17         Online              up
     FABRIC-CARD1                             SFM2               18         Online              up
     FABRIC-CARD2                             SFM3               19         Online              up
     FABRIC-CARD3                             SFM4               20         Online              up
     FABRIC-CARD4                             SFM5               21         Online              up
     FABRIC-CARD5                             SFM6               22         Online              up
     LINE-CARD0                         line-card                1          Empty              up
     LINE-CARD1                  imm36-400g-qsfpdd               2          Online              up
     LINE-CARD2                         line-card                3          Empty              up
     LINE-CARD3    imm32-100g-qsfp28+4-400g-qsfpdd               4          Online              up
     LINE-CARD4                         line-card                5          Empty              up
     LINE-CARD5    imm32-100g-qsfp28+4-400g-qsfpdd               6          Online              up
     LINE-CARD6                        line-card                 7          Empty              up
     LINE-CARD7                        line-card                 8          Empty              up
     SUPERVISOR0                         cpm2-ixr                16         Online              up


```  
```
    on line card: 
    show chassis-modules status
           Name                      Description    Physical-Slot    Oper-Status    Admin-Status
     -----------  -------------------------------  ---------------  -------------  --------------
     LINE-CARD5  imm32-100g-qsfp28+4-400g-qsfpdd                6         Online              up
     SUPERVISOR0                          cpm-ixr               16        Online              up
```
#### Pass/Fail Criteria
 * Verify output on supervisor shows 'up' for operational and admin state for supervisor, all line cards, all fabric cards for DUT.
 * Verify output of each line card   shows 'up' for operational state admin state for itself and  supervisor for DUT

### 1.2 Configure chassis-modules 

#### Steps

 * Shutdown line card use Run command `sudo config chassis-modules shutdown <card>`
 * Startup line card use Run command `sudo config chassis-modules startup <card>`

#### Repeat steps on
 * Supervisor
 * Line Cards

#### Pass/Fail Criteria
 * Verify `show chassis-modules status` report line-card down after shutdown on supervisor

  ```
     sudo config chassis-modules shutdown LINE-CARD1
     admin@sonic:~$ show chassis-modules status LINE-CARD1 
       Name        Description     	Slot    Oper-Status    Admin-Status
     -------------  -----------------  ------  -------------  --------------
       LINE-CARD1  imm36-400g-qsfpdd       1       down            down
  ```
     

 * Verify  `show chassis-modules status` report line-card up after startup on supervisor
     for example:
    
  ```
    sudo config chassis-modules startup LINE-CARD1
    admin@sonic:~$ show chassis-modules status LINE-CARD1 
      Name        Description     	Slot    Oper-Status    Admin-Status
    -------------  -----------------  ------  -------------  --------------
      LINE-CARD1  imm36-400g-qsfpdd       1       Online           up
  ```
 *  `show chassis-modules status` report card status unchanged after shutdown on line card
 

### 1.3 Check platform chassis midplane status 

#### Steps
 * Use command `show chassis-modules midplane-status` to get status of midplane in modular chassis

#### Verify in
 * Supervisor
 * Line Card

#### Sample Output
```
   on Supervisor:
   show chassis-modules midplane-status
        Name    IP-Address    Reachability
   ----------  ------------  --------------
   LINE-CARD0      10.0.0.1            True
   LINE-CARD1      10.0.0.2           False
   LINE-CARD2      10.0.0.3            True
   LINE-CARD3      10.0.0.4            True
```  
```
   on line card: 
        Name    IP-Address    Reachability
   -----------  ------------  --------------
   SUPERVISOR0     10.0.0.16            True

```
     

#### Pass/Fail Criteria
 * Verify output on supervisor lists all the line cards, midplane ip addresses and reachability status as expected  
 * Verify on each Line Card supervisor reachability is correct and supervisor ip address is correct

### 1.4 Check thermal sensor output in chassis state db 
#### Steps
 * Run command “redis-dump  -p 6380 -d 13 -y -k "*TEMP*" "on Supervisor
 * Run command “redis-dump -d 6 -y -k "*TEMP*" on line card

#### Verify in
 * Supervisor
 * Line Card
 
#### Sample Output
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
#### Pass/Fail Criteria
 * Verify on the supervisor, thermal sensor data for itself and all applicable peripherals. Also verify:
    * High threshold is greater than maximum_temperature.
    * Low threshold is lesser than the minimum_temperature.
    * Warning status is False except check criteria high or low threshold above is false
 * Verify on each line card that all sensor data is correct. Also verify:
    * High threshold is greater than maximum_temperature.
    * Low threshold is lesser than the minimum_temperature.
    * Warning status is False except check criteria high or low threshold above is false
 
 
### 1.5 Check power budget output in chassis state db 

#### Steps
 * Run command `redis-dump -d 6 -y -k "*power*"` 
 * Manually take one of the PSU offline
 * Manually bring back PSU online
 * Manually remove line card
 * Manually insert back line card
 * Manually remove one of the fan tray
 * Manually insert back fan tray

#### Verify in
 * Supervisor

#### Sample Output
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
      }
   }
```
#### Pass/Fail Criteria
 * Verify the supplied power is greater than 0 for each PSU. Verify total consumed power and total supplied power are correct.
 * Verify the supplied power is = 0.0 for offline PSU after step 2
 * Verify the supplied power is > 0 for PSU back online after step 3
 * Verify when LINE CARD1 is shutdown by using config command, the consumed power is 0 for LINE_CARD1 and when it is started the consumed power is not 0
 * Verify that when fan tray is removed, the consumed power is 0 and when fan tray is re-inserted it is not 0.


## API Test Cases 
This set of test cases will verify expected value return API calls using HTTP server in DUT. These tests will use existing API infrastructure existing in platform_tests/api 

## APIs for module base added for chassis

### 2.1 Test api get_name

#### Steps

* call get_name api to retrieve module name
```
  api description :
  get_name - Retrieves the name of the module prefixed by SUPERVISOR, LINE-CARD,FABRIC-CARD
```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Data returned is of correct type and appropriate for the specific platform and verified to fact where applicable (slot number , module type etc., True/False)  
* Verify returned value is correct if called from supervisor should have supervisor in name, if line card should have line card prefix to slot name

### 2.2 Test api get_description

#### Steps
* call get_description api to retrieve module description
```
  api description :
  get_description - A string, providing the vendor's product description of the module.

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate   

### 2.3 Test api get_type

#### Steps
* call get_type api to retrieve module type
```
  api description :
  get_type - A string, the module-type from one of the predefined types MODULE_TYPE_SUPERVISOR, MODULE_TYPE_LINE or MODULE_TYPE_FABRIC

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate
* verify module type is correct if called from supervisor should be type supervisor and line card for line card   


### 2.4 Test api get_slot

#### Steps
* call get_slot api to retrieve module description
```
  api description :
  get_slot - An integer, indicating the slot number in the chassis

```
#### Verify in
 * Supervisor
 * Line Card
 
### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate
* verify slot number , compare with facts

### 2.5 Test api get_oper_status

#### Steps
* call get_oper_status api to retrieve module description
```
  api description :
  get_oper_status- A string, the operational status of the module from one of the predefined status values: MODULE_STATUS_EMPTY,  MODULE_STATUS_OFFLINE,MODULE_STATUS_FAULT, MODULE_STATUS_PRESENT or MODULE_STATUS_ONLINE

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate
* verify status is expected for that module

### 2.6 Test api reboot

#### Steps
* Send reboot api to retrieve module description with correct predefined type MODULE_REBOOT_DEFAULT, MODULE_REBOOT_CPU_COMPLEX, or MODULE_REBOOT_FPGA_COMPLEX
```
  api description :
  reboot - bool: True if the request has been issued successfully, False if not
```

#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate
* verify module is rebooted successfully

### 2.7 Test api set_admin_state
#### Steps
* Set admin state to down set_admin_state
* Set admin state to up set_admin_state
```
  api description :
  set_admin_state - bool: True if the request has been issued successfully, False if not.

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate
* verify set_admin_state down returns true, verify admin status is changed to down for module using get_status
* verify set_admin_state up returns true,verify admin status changed back to up after step 2 using get_status

### 2.8 Test api get_maximum_consumed_power
#### Steps
* call get_maximum_consumed_power api to retrieve module description
```
  api description :
  get_maximum_consumed_power - A float, with value of the maximum consumable power of the component.

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate 

### 2.9 Test api get_midplane_ip
#### Steps
* call get_midplane_ip api to retrieve module description
```
  api description :
  get_midplane_ip: a string, the IP-address of the module reachable over the midplane

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate 
* verify ip is correct based on slot index

### 2.10 Test api is_midplane_reachable
#### Steps
* call is_midplane_reachable api to retrieve module description
```
  api description :
  is_midplane_reachable: A bool value, should return True if module is reachable via midplane

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate 
* Value is true for line card that is up
* Value is false for line card that is not up


## APIs for chassis base added for chassis

### 3.1 Test api get_module_index

#### Steps
* get_module_index api method from chassis_base
```
  api description :
  get_module_index: An integer, the index of the ModuleBase object in the module_list

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate 
* Verify Module index is correct for each module , get modules present from get_all_modules

### 3.2 Test api get_supervisor_slot

#### Steps
* get_supervisor_slot api method from chassis_base
```
  api description :
  get_supervisor_slot: An integer, the vendor specific physical slot identifier of the
                       supervisor module in the modular-chassis

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate 
* Verify slot index return is correct for superovisor card in chassis facts

### 3.3 Test api get_my_slot

#### Steps
* get_my_slot api method from chassis_base
```
  api description :
  get_my_slot - Returns an integer and vendor specific slot identifier
```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate 
* Verify slot index return is correct compare value from chassis facts

### 3.4 Test api is_modular_chassis

#### Steps
* get is_modular_chassis api method from chassis_base
```
  api description :
  is_modular_chassis - A bool value, should return False by default or for fixed-platforms. Should return True for supervisor-cards, line-cards etc running as part of modular-chassis
```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate and true for chassis


## APIs for power consumption and supply APIs for chassis

### 4.1 Test api get_maximum_supplied_power

#### Steps
* get get_maximum_supplied_power api method from psu_base
```
  api description :
  get_maximum_supplied_power -A float number, the maximum power output in Watts, e.g. 1200.1 
```
#### Verify in
 * Supervisor

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate and true for chassis
* Verify for each PSU from chassis facts a valid value is returned


### 4.2 Test api get_status_master_led

#### Steps
* get get_status_master_led api method from psu_base (if supported by platform)

```
  api description :
  get_status_master_led - A string, one of the predefined STATUS_LED_COLOR_* strings.
```
#### Verify in
 * Supervisor

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate and true for chassis
* Verify valid LED color predefined is returned and is as expected

### 4.3 Test api set_status_master_led 

#### Steps
* set set_status_master_led api method from psu_base to red (if supported by platform)
* set set_status_master_led api method from psu_base to green (if supported by platform)

```
  api description :
  set_status_master_led - bool: True if status LED state is set successfully, False if not
```
#### Verify in
 * Supervisor

#### Pass/Fail Criteria
* Verify data returned is of correct type and appropriate and true for chassis
* Verify for master LED color can be set to red using get_status_master_led, Manual step : physical led is changed to red
* Verify for master LED is set to green using get_status_master_led, Manual step : physical led is changed to red

## APIs for thermal added for  chassis

### 5.1 Test api get_minimum_recorded

#### Steps
 * get_minimum_recorded api on each thermal sensor for given device

```
  api description :
  thermal_base:
  get_minimum_recorded- A float number, the minimum recorded temperature of thermal in Celsius up to nearest thousandth of one degree Celsius, e.g. 30.125

```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
 * Values are type float and returns applicable value
 * Verify each sensor returns a valid value for all modules

### 5.2 Test api get_maximum_recorded
#### Steps
 * get_maximum_recorded api on each thermal sensor for given device

```
  api description :
  thermal_base:
  get_maximum_recorded - A float number, the maximum recorded temperature of thermal in Celsius up to nearest thousandth of one degree Celsius, e.g. 30.125
```
#### Verify in
 * Supervisor
 * Line Card

#### Pass/Fail Criteria
 * Values are type float and returns applicable value
 * Verify each sensor returns a valid value

#### AUTOMATION
* Add this new api tests to script tests/api/test_thermal.py 

## APIs for fan_drawer added for  chassis

### 6.1 Test api get_maximum_consumed_power

#### Steps
 * get_maximum_consumed_power for each fan 
```
  api description :
  get_maximum_consumed_power - A float, with value of the maximum consumable power of the component.

```
#### Verify in
 * Supervisor

#### Pass/Fail Criteria
 * Values are type float and returns applicable values
 * verify value returned for each fan is valid


