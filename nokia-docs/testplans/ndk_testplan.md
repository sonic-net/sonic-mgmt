# **NDK Test Plan**

 - [Introduction](#intro)
 - [Scope](#scope)
 - [Test Cases](#test-cases)
     - [FanPlatformNdkService](#fan)
     - [LedPlatformNdkService](#led)
     - [ThermalPlatformNdkService](#th)
     - [PsuPlatformNdkService](#psu)
     - [XcvrPlatformNdkService](#sfp)
     - [EepromPlatformNdkService](#eeprom)
     - [FirmwarePlatformNdkService](#firmware)
     - [UtilPlatformNdkService](#util)
     - [ChassisPlatformNdkService](#chassis)
     
# Introduction <a name="intro"></a>

This is the test plan for NDK services APIs, as described in the [platform_ndk_proto](https://gitlabsr.nuq.ion.nokia.net/sr/srlinux/-/blob/master/protos/platform_ndk/platform_ndk.proto)


# Scope <a name="scope"></a>

The functionalities covered in this test plan are:
All API related to NDK

# Test Cases <a name="test-cases"></a>

## FanPlatformNdkService <a name="fan"></a>

#### Test Case 1. Verify 'GetFanNum' API returns number of fan tray present on chassis 

##### Test Objective
Verify 'GetFanNum' API returns number of fan trays on the supervisor as expected.
 
##### Automation
Done

##### Test Steps
* Send GetFanNum API using grpc protobuf 
* Get fan_nums from the response
* The fan nums should be same as number of fan trays present on the chassis
    
#### Test Case 2. Verify GetFanPresence API 
##### Test Objective
Verify GetFanPresence api returns the correct fan tray presence status

##### Automation
Done

##### Test Steps
* Send GetFanPresence API using GRPC
* Get fan presence from the response 
* The returned value by API should be same as fan presence status on the chassis

#### Test Case 3.  Verify GetFanStatus API 
##### Test Objective
Verify GetFanStatus API returns the correct fan tray status

##### Automation
Done

##### Test Steps
* Send GetFanStatus API using GRPC
* Get fan tray status from the response 
* The returned value should be status of fan tray on chassis

#### Test Case 4. Verify SetFanTargetSpeed/GetFanTragetSpeed API
##### Test Objective
Verify SetFanTargetSpeed/GetFanTargetSpeed API returns the correct fan tray target speed

##### Automation
Done

##### Test Steps
* disable fan algorithm using DisableFanAlgorithm 
* Set fan trays target speed using SetFanTargetSpeed API 
* Get each fan tray target speed using GetFanTragetSpeed
* The returned target speed of each fan tray should be in range +-1 of target speed being set

#### Test Case 5.  Verify GetFanActualSpeed
##### Test Objective
Verify GetFanActualSpeed API returns the correct fan actual speed

##### Automation
Done

##### Test Steps
* Disable fan algorithm using DisableFanAlgorithm
* Set fan trays target speed using SetFanTargetSpeed API  
* get actual speed of each fan tray using GetFanActualSpeed 
* Actual speed of each fan tray should be in the range of fan tray tolerance

#### Test Case 6. Verify GetFanDirection 

##### Test Objective
Verify GetFanDirection API return the correct fan tray direction

##### Automation
Done

##### Test Steps

* Send GetFanDirection API using GRPC
* Get fan tray direction from the response 
* The returned value by API should be same as fan tray direction

#### Test Case 7. Verify GetFanTolerance API

##### Test Objective
Verify GetFanTolerance API return the correct fan tray tolerance value

##### Automation
Done

##### Test Steps

* Send GetFanTolerance API using GRPC
* Get fan speed Tolerance value from the response 
* The returned value by API should be same as fan speed Tolerance 

#### Test Case 8. Verify SetFanLedStatus/GetFanLedStatus API to get fan tray led state 

##### Test Objective

Verify SetFanLedStatus/GetFanLedStatus API can set and get each fan tray led state

##### Automation
Done

##### Test Steps

* Send SetFanLedStatus API to set fantray led state
* Get fantray led state using GetFanLedStatus  
* The returned value by API should be same as fantray led state being set in step1.  
  Supported states:- 
    LED_STATE_INVALID
    LED_STATE_OFF
    LED_STATE_ON
    LED_STATE_BLINK
    LED_STATE_FAST_BLINK

#### Test Case 9. Verify DisableFanAlgorithm API
##### Test Objective

Verify DisableFanAlgorithm API

##### Automation
Done

##### Test Steps

* Set fan algo disable using DisableFanAlgorithm
* Get disable fan algorithm value using grpc 
* the returned value should be same as being set in step 1

#### Test Case 10. Verify SetFanLedStatus/GetFanLedStatus to get led color 
##### Test Objective

Verify fan tay led color can be set/get using SetFanLedStatus/GetFanLedStatus API

##### Automation
Done

##### Test Steps

* Set fan tray led color using SetFanLedStatus
* Get fan led color using GetFanLedStatus
* Verify fan led color is same as being set in step 1

#### Test Case 11. Verify GetFanSerialNo
##### Test Objective
Verify GetFanSerialNo API returns fan serial number
##### Test Steps

* Get fan serial number using GetFanSerialNo
* Verify fan serial number is same as fan serial number on CPM.

##### Automation
Done

#### Test Case 12. Verify GetFanPartNo 
##### Test Objective
Verify GetFanPartNo returns fan part/model number

##### Automation
Done

##### Test Steps
* Get fan part/model number using GetFanPartNo
* Verify fan model number is same as fan model number on CPM.


#### Test Case 13. Verify SetFanTargetSpeed for invaild min/max range
##### Test Objective  
Verify SetFanTargetSpeed should be able to handle invalid min/max value.

##### Automation
Done

##### Test Steps
* Use API to set speed from an invalid range
* The fan target speed should not be set in that invalid range

## LedPlatformNdkService <a name="led"></a>

#### Test Case 1.  Verify SetLed/GetLed  to set/get different component led color and state 

##### Test Objective
Verify SetLed/GetLed can set and get different component(fantray/psu/sfm/port) LED color/state 

##### Automation
Done

##### Test Steps
* Send API to set any component's led color and state
* get led color and state
* the led color/state returned should be same as being set in step1.
* Repeat the step for each component

#### Test Case 2.  Verify SetLed/GetLed can set multiple fantray led color state in one request
##### Test Objective
Verify SetLed/GetLed  can set get state/color of multiple led for a component

##### Automation
Done

##### Test Steps
* Send API to set each any component's led color and state of multiple index
* get led color and state
* the led color/state returned should be same as being set in step1.
* Repeat the step for each component

## ThermalPlatformNdkService <a name="th"></a>

#### Test Case 1.  Verify GetThermalCurrTemp
##### Test Objective
Verify GetThermalCurrTemp returns current temp of each thermal

##### Automation
Done

##### Test Steps
* Send API to get thermal current temp
* Verify the returned value is in the range 

#### Test Case 2.  Verify GetThermalMinTemp 
##### Test Objective
Verify GetThermalMinTemp returns minimum temp of each thermal

##### Automation
Done

##### Test Steps
* Send API to get thermal minimum temp
* Verify the returned value is same as expected

#### Test Case 3.  Verify GetThermalMaxTemp 
##### Test Objective
Verify GetThermalMaxTemp returns maximum temp 
##### Automation
Done

##### Test Steps
* Send API to get thermal maximum temp
* Verify the returned value is same as expected

#### Test Case 4.  Verify GetThermalLowThreshold 
##### Test Objective
Verify GetThermalLowThreshold returns thermal low threshold

##### Automation
Done

##### Test Steps
* Send API to get thermal low threshold
* Verify the returned value is same as expected

#### Test Case 5.  Verify GetThermalHighThreshold  
##### Test Objective
Verify GetThermalHighThreshold returns thermal high threshold

##### Automation
Done

##### Test Steps
* Send API to get thermal high threshold
* Verify the returned value is same as expected

#### Test Case 6.  Verify UpdateThermalHwSlot      
##### Test Objective
Verify UpdateThermalHwSlot can update thermal 

##### Automation
Done

##### Test Steps
* Send API 'UpdateThermalHwSlot' to set thermal min/max temperature
* Get thermal low/hight tempertaure
* verify the value returned in step 2 is same as 1


#### Test Case 7.  Verify GetThermalDevicesInfo      
##### Test Objective
Verify GetThermalDevicesInfo thermal devices info e.g sensor-name, local, remote, device-desc, device-idx
##### Automation
Done

##### Test Steps
* Send API to get thermal devices info 
* verify the values returned are same as expected


#### Test Case 8.  Verify UpdateThermalHwSlot        
##### Test Objective
Verify UpdateThermalHwSlot can update hwslot_temp e.g. current-temp, min-temp, max-temp, margin

##### Automation
Done

##### Test Steps
* Send API to update thermal devices info 
* verify the values returned are same as expected

#### Test Case 9.  Verify SetThermalOffset         
##### Test Objective
Verify SetThermalOffset can set thermal offset 
 
##### Test Steps
* Send API to set thermal offset 
* Get thermal offset 
* verify the values returned are same as expected


#### Test Case 10.  Verify SetThermalAsicInfo         
##### Test Objective
Verify SetThermalAsicInfo can set asic thermal info

##### Automation
Done
 
##### Test Steps
* Send API to set asic thermal info 
* Get thermal info 
* verify the values returned are same as expected

## PsuPlatformNdkService <a name="psu"></a>

#### Test Case 1.  Verify GetPsuNum         
##### Test Objective
Verify GetPsuNum can return number of psu on line card

##### Automation
Done
 
##### Test Steps
* Send API to get number of psu on device
* verify the values returned are same as expected

#### Test Case 2.  Verify GetPsuPresence          
##### Test Objective
Verify GetPsuPresence can return psu presence info
 
##### Automation
Done

##### Test Steps
* Send API to get psu presence info
* verify the values returned are same as expected

#### Test Case 3.  Verify GetPsuStatus          
##### Test Objective
Verify GetPsuStatus can return psu presence info
 
##### Automation
Done

##### Test Steps
* Send API to get psu status
* verify the values returned are same as expected

#### Test Case 4.  Verify GetPsuMaximumPower           
##### Test Objective
Verify GetPsuMaximumPower can return each psu maximum power
 
##### Automation
Done

##### Test Steps
* Send API to get maximum power of each psu
* verify the values returned are same as expected

#### Test Case 5.  Verify GetPsuModel            
##### Test Objective
Verify GetPsuModel can return info of each psu model 
 
##### Automation
Done

##### Test Steps
* Send API to get info of each psu model
* verify the values returned are same as expected

#### Test Case 6.  Verify GetPsuSerial             
##### Test Objective
Verify GetPsuSerial can return info of each psu model 
 
##### Automation
Done

##### Test Steps
* Send API to get info of each psu serial
* verify the values returned are same as expected

#### Test Case 7.  Verify GetPsuOutputCurrent             
##### Test Objective
Verify GetPsuOutputCurrent can return psu output current
 
##### Automation
Done

##### Test Steps
* Send API to get info of each psu output current
* verify the values returned are same as expected

#### Test Case 8.  Verify GetPsuOutputVoltage              
##### Test Objective
Verify GetPsuOutputVoltage can return psu voltage
 
##### Automation
Done

##### Test Steps
* Send API to get info of each psu output voltage
* verify the values returned are same as expected

#### Test Case 9.  Verify GetPsuOutputPower               
##### Test Objective
Verify GetPsuOutputCurrent can return psu output power

##### Automation
Done
 
##### Test Steps
* Send API to get info of each psu output power
* verify the values returned are same as expected

#### Test Case 10.  Verify GetPsuTemperature                
##### Test Objective
Verify GetPsuTemperature  can return psu temp
 
##### Automation
Done

##### Test Steps
* Send API to get info of each psu temp
* verify the values returned are same as expected

#### Test Case 11.  Verify GetPsuMaxOutputVoltage                
##### Test Objective
Verify GetPsuMaxOutputVoltage  can return psu max output voltage
 
##### Automation
Done

##### Test Steps
* Send API to get info of each psu max output voltage
* verify the values returned are same as expected

#### Test Case 12.  Verify GetPsuMinOutputVoltage                 
##### Test Objective
Verify GetPsuMinOutputVoltage can return psu min output voltage
 ##### Automation
Done

##### Test Steps
* Send API to get info of each psu max output voltage
* verify the values returned are same as expected

#### Test Case 13.  Verify GetPsuMaxTemperature                 
##### Test Objective
Verify GetPsuMaxTemperature can return psu max temperature
 ##### Automation
Done

##### Test Steps
* Send API to get info of each psu max output voltage
* verify the values returned are same as expected

## XcvrPlatformNdkService <a name="sfp" ></a>

#### Test Case 1.  Verify GetSfpEepromInfo                  
##### Test Objective
Verify GetSfpEepromInfo can return sfp eeprom info
 

##### Test Steps
* Send API to get info of sfp eeprom info
* verify the values returned are same as expected

 ##### Automation
No plan

#### Test Case 2.  Verify GetSfpPresence                  
##### Test Objective
Verify GetSfpPresence can return sfp presence
 
##### Test Steps
* Send API to get info of sfp presence
* verify the values returned are same as expected

#### Test Case 3.  Verify GetSfpStatus                   
##### Test Objective
Verify GetSfpStatus  can return sfp status
 
##### Test Steps
* Send API to get info of sfp status
* verify the values returned are same as expected

#### Test Case 4.  Verify ReqSfpReset/GetSfpResetStatus                 
##### Test Objective
Verify ReqSfpReset can reset sfp 

 ##### Automation
No Plan

 
##### Test Steps
* Send API to reset sfp
* Get using GetSfpResetStatus sfp status 
* verify the values returned are same as expected

#### Test Case 5.  Verify ReqSfpLPMode/GetSfpLPStatus                    
##### Test Objective
Verify ReqSfpLPMode can reset sfp and GetSfpLPStatus can return
 
 ##### Automation
Done

##### Test Steps
* Send API to reset get sfp lp mode 
* Get lp mode status
* verify the values returned are same as expected

#### Test Case 6.  Verify ReqSfpTxDisable                     
##### Test Objective
Verify ReqSfpTxDisable can request sfp tx disable
 
 ##### Automation
TO BE Done

##### Test Steps
* Send API to request sfp tx disable
* Get sfp tx status
* verify the values returned are same as expected


#### Test Case 7.  Verify GetSfpNumAndType                      
##### Test Objective
Verify GetSfpNumAndType returns sfp num and type
##### Automation
Done

##### Test Steps
* Send API to get GetSfpNumAndType
* verify the values returned are same as expected


#### Test Case 8.  Verify GetSfpInfoJSON                       
##### Test Objective
Verify GetSfpInfoJSON returns sfp info in json

 ##### Automation
To be Done
 
##### Test Steps
* Send API to get GetSfpInfoJSON
* verify the values returned are sfp info in json form

## EepromPlatformNdkService <a name = "eeprom"></a>

#### Test Case 1.  Verify GetCardProductName                     
##### Test Objective
Verify GetCardProductName can return product name
 
 ##### Automation
Done

##### Test Steps
* Send API to get product name
* verify the values returned are same as expected

#### Test Case 2.  Verify GetCardSerialNumber                          
##### Test Objective
Verify GetSerialNumber can return product serial number
 
 ##### Automation
Done

##### Test Steps
* Send API to get product serial number
* verify the values returned are same as expected

#### Test Case 3.  Verify GetCardBaseMac                     
##### Test Objective
Verify GetBaseMac can return product name
 
 ##### Automation
Done

##### Test Steps
* Send API to get product mac address
* verify the values returned are same as expected

#### Test Case 4.  Verify GetCardHwsku                     
##### Test Objective
Verify GetCardHwsku can return card hwsku info

 ##### Automation
Done
 
##### Test Steps
* Send API to get card hwsku
* verify the values returned are same as expected

#### Test Case 4.  Verify GetCardPartNumber                    
##### Test Objective
Verify GetCardHwsku can return card part number

 ##### Automation
Done
 
##### Test Steps
* Send API to get card hwsku
* verify the values returned are same as expected


#### Test Case 5.  Verify GetCardCleiNumber                    
##### Test Objective
Verify GetCardCleiNumber can return clei number
 
 ##### Automation
Done

##### Test Steps
* Send API to get card clei number
* verify the values returned are same as expected

#### Test Case 6.  Verify GetCardMfgDate                    
##### Test Objective
Verify GetCardMfgDate can return mfg date of card
 
 ##### Automation
Done

##### Test Steps
* Send API to get card mfg date
* verify the values returned are same as expected


#### Test Case 7.  Verify GetCardMacCount                    
##### Test Objective
Verify GetCardMacCount can return card mac count
 
 ##### Automation
Done

##### Test Steps
* Send API to get card mac count
* verify the values returned are same as expected


#### Test Case 8.  Verify GetCardEepromAllTlvs                        
##### Test Objective
Verify GetCardEepromAllTlvs can return all tlv
 
 ##### Automation
Done

##### Test Steps
* Send API to get card TLV
* verify the values returned are same as expected


#### Test Case 9.  Verify GetChassisEeprom                        
##### Test Objective
Verify GetChassisEeprom can return chassis eeprom info
 
 ##### Automation
Done

##### Test Steps
* Send API to get chassis eeprom
* verify the values returned are same as expected

## FirmwarePlatformNdkService <a name="firmware"></a>

#### Test Case 1.  Verify ReqHwFirmwareVersion                      
##### Test Objective
Verify ReqHwFirmwareVersion returns firmware version
 
 ##### Automation
Done

##### Test Steps
* Send API to get firmware version
* verify the values returned are same as expected

#### Test Case 2.  Verify HwFirmwareGetComponents                       
##### Test Objective
Verify HwFirmwareGetComponents returns firmware components eg. version, dev_name, dev_type, dev_desc
 
 ##### Automation
Done

##### Test Steps
* Send API to get firmware get components
* verify the values returned are same as expected

## UtilPlatformNdkService <a name="util"></a>

#### Test Case 1.  Verify ReqSfmInfo                        
##### Test Objective
Verify ReqSfmInfo returns number of sfm, hw-slot, admin, initialized, presence, error etc.
 
##### Test Steps
* Send API to get sfm info
* verify the values returned are same as expected

 ##### Automation
Done

#### Test Case 2.  Verify ReqAdminTech                         
##### Test Objective
Verify ReqAdminTech returns admin tech
 
 ##### Automation
Done

##### Test Steps
* Send API to get admin tech
* verify the values returned are same as expected

#### Test Case 3.  Verify ReqLogSetAll                          
##### Test Objective
Verify ReqLogSetAll returns log set all
 
 ##### Automation
To be done

##### Test Steps
* Send API to get log set all
* verify the values returned are same as expected

#### Test Case 4.  Verify ReqLogSetModule                          
##### Test Objective
Verify ReqLogSetModule can set log set all
 
 ##### Automation
To be Done

##### Test Steps
* Send API to set log module
* Get set log module
* verify the values returned are same as expected

#### Test Case 5.  Verify ReqLogResetAll                   
##### Test Objective
Verify ReqLogResetAll can set log reset all
 
 ##### Automation
To be Done

##### Test Steps
* Send API to set log reset all
* Get set log reset all
* verify the values returned are same as expected


## ChassisPlatformNdkService <a name="chassis"></a> 

#### Test Case 1.  Verify GetModuleName                             
##### Test Objective
Verify GetModuleName returns module name
 
 ##### Automation
Done

##### Test Steps
* Send API to get module name
* verify the values returned are same as expected

#### Test Case 2.  Verify GetChassisType                              
##### Test Objective
Verify GetChassisType returns chassis type
 
 ##### Automation
Done

##### Test Steps
* Send API to get chassis type
* verify the values returned are same as expected

#### Test Case 3.  Verify GetChassisStatus                             
##### Test Objective
Verify GetChassisStatus returns chassis status
 
 ##### Automation
Done

##### Test Steps
* Send API to get chassis status
* verify the values returned are same as expected

#### Test Case 4.  Verify GetModuleMaxPower                              
##### Test Objective
Verify GetModuleMaxPower returns module max power
 
 ##### Automation
Done

##### Test Steps
* Send API to get module max power
* verify the values returned are same as expected

#### Test Case 5.  Verify GetMySlot                              
##### Test Objective
Verify GetMySlot  returns my slot value
 
 ##### Automation
Done

##### Test Steps
* Send API to get my slot
* verify the values returned are same as expected


#### Test Case 6.  Verify GetChassisProperties                                
##### Test Objective
Verify GetChassisProperties returns chassis properties
 
 ##### Automation
Done

##### Test Steps
* Send API to get chassis properties
* verify the values returned are same as expected

#### Test Case 7.  Verify GetMidplaneIP                                 
##### Test Objective
Verify GetMidplaneIP returns midplane IP
 
 ##### Automation
Done

##### Test Steps
* Send API to get midplane ip
* verify the values returned are same as expected

#### Test Case 8.  Verify IsMidplaneReachable                                  
##### Test Objective
Verify IsMidplaneReachable returns midplane reachable value
 
 ##### Automation
Done

##### Test Steps
* Send API to get midplane reachable value
* verify the values returned are same as expected

#### Test Case 9.  Verify PingHealthCheck                                    
##### Test Objective
Verify PingMidplaneIP can ping midplane IP.
 
 ##### Automation
Done

##### Test Steps
* Send API to ping midplane IP
* should be able to ping midplane IP.


#### Test Case 10.  Verify GetFabricPcieInfo                                    
##### Test Objective
Verify GetFabricPcieInfo can return pcie info
 
 ##### Automation
To be Done

##### Test Steps
* Send API to get GetFabricPcieInfo 
* verify info is same as expected

#### Test Case 11.  Verify RebootSlot can reboot slot                                    
##### Test Objective
Verify RebootSlot can reboot slot
 
 ##### Automation
To be Done

##### Test Steps
* Send API to reboot slot
* verify slot is rebooted
