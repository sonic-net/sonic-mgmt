#!/usr/bin/env python -tt
##########################################################
#  3132 Fan Speed Testing script
#       Performs fan related tests
#  File:   fan_TEST0004.py
#  Date:   04/27/2015
#  Author: Robin Randall
# Copyright (C) 2015 Cisco Systems, Inc. all rights reserved
###########################################################
# Test TEST0004
#  1. Given we just booted up
#  2. Decrease temp_max to 15 to trigger 4 alarms
#     in /etc/sensors.d/sensors.conf
#     Run "sensors -s"
#     Run "sensors > sensors.data"
#  3. Alarms should show if sensors detect temp >= temp.max
###########################################################
import os, sys, re, time, shutil, pexpect
import BSPfn
global sensor_ID, log_sensor_ID, sens
CSI="\x1B["
RED=CSI+"30;41m"
GREEN=CSI+"30;42m"
END=CSI+"0m"
sensor_ID=""
log_sensor_ID=""
def passit():
    print (GREEN +"PASS"+END)
def failit():
    print (RED +"FAIL"+END)
#########################################################################
def TestAlarms():  #TEST_0004.1
    print ("******************************************")
    print ("*  fan_TEST0004.1     4 ALARMS            ")
    print ("******************************************")
    #Boot up BSP
    BSPfn.backupSensorConf()
    BSPfn.cleanMessageLog()
    print("Set  temp sensor 1 max to 15")
    BSPfn.setTempSensorMax(1, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Set  temp sensor 2 max to 15")
    BSPfn.setTempSensorMax(2, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Set  temp sensor 3 max to 15")
    BSPfn.setTempSensorMax(3, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Set  temp sensor 4 max to 15")
    BSPfn.setTempSensorMax(4, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Check if alarms set")
    (alarms, sensor_ID)=BSPfn.getAlarmOn()
    if alarms  == 4:
       passit()                         #3
    else :
       failit()
       print(RED+"One or more of the ALARMS are missing"+END)

    print "Restore sensors.conf"
    BSPfn.restoreSensorConf()
    BSPfn.setSensor()
    time.sleep(10)
    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR temperature alarm on sensor:", 
                            "XXXX",
                            "XXXX", 
                            "XXXX"])

##########################################################################
def TestAlarm1234():  #TEST_0004.2
    print ("******************************************")
    print ("*  fan_TEST0004.2     4 single ALARMS     ")
    print ("******************************************")
    #Boot up BSP
    BSPfn.backupSensorConf()
    BSPfn.cleanMessageLog()
    print("Set  temp sensor 1 max to 15")
    BSPfn.setTempSensorMax(1, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Check if alarms set")
    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR temperature alarm on sensor:", 
                            "XXXX",
                            "XXXX", 
                            "XXXX"])
    # Does "ALARM" show?
    (alarms, sensor_ID)=BSPfn.getAlarmOn()
    if alarms == 1 :
       passit()                         #1
    else :
       failit()
       print(RED+"Seems to be missing ALARM"+END)
    #Are IDs in sync?
    if sensor_ID == log_sensor_ID :
       passit()
    else :
       failit()
       print(RED+str(sensor_ID)+" NOT = "+str(log_sensor_ID)+END)

    print("Clear Alarm 1")
    BSPfn.restoreSensorConf() #From beginning
    BSPfn.cleanMessageLog()
    BSPfn.setSensor()
    time.sleep(10)
    print("Set  temp sensor 2 max to 15")
    BSPfn.setTempSensorMax(2, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Check if alarm set")
    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR temperature alarm on sensor:", 
                            "XXXX",
                            "XXXX", 
                            "XXXX"])
    # Does "ALARM" show?
    (alarms, sensor_ID)=BSPfn.getAlarmOn()
    if alarms == 1:
       passit()                         #2
    else :
       failit()
       print(RED+"Seems to be missing ALARM"+END)
    #Are IDs in sync?
    if sensor_ID == log_sensor_ID :
       passit()
    else :
       failit()
       print(RED+str(sensor_ID)+" NOT = "+str(log_sensor_ID)+END)

    print("Clear Alarm 2")
    BSPfn.restoreSensorConf() #From beginning
    BSPfn.cleanMessageLog()
    BSPfn.setSensor()
    time.sleep(10)
    print("Set  temp sensor 3 max to 15")
    BSPfn.setTempSensorMax(3, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Check if alarm set")
    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR temperature alarm on sensor:", 
                            "XXXX",
                            "XXXX", 
                            "XXXX"])
    # Does "ALARM" show?
    (alarms, sensor_ID)=BSPfn.getAlarmOn()
    if alarms == 1 :
       passit()                         #3
    else :
       failit()
       print(RED+"Seems to be missing ALARM"+END)
    #Are IDs in sync?
    if sensor_ID == log_sensor_ID :
       passit()
    else :
       failit()
       print(RED+str(sensor_ID)+" NOT = "+str(log_sensor_ID)+END)

    print("Clear Alarm 3")
    BSPfn.restoreSensorConf() #From beginning
    BSPfn.cleanMessageLog()
    BSPfn.setSensor()
    time.sleep(10)
    print("Set  temp sensor 4 max to 15")
    BSPfn.setTempSensorMax(4, 15)
    BSPfn.setSensor()
    time.sleep(10)
    print("Check if alarm set")
    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR temperature alarm on sensor:", 
                            "XXXX",
                            "XXXX", 
                            "XXXX"])
    # Does "ALARM" show?
    (alarms, sensor_ID)=BSPfn.getAlarmOn()
    if alarms == 1 :
       passit()                         #4
    else :
       failit()
       print(RED+"Seems to be missing ALARM"+END)
    #Are IDs in sync?
    if sensor_ID == log_sensor_ID :
       passit()
    else :
       failit()
       print(RED+str(sensor_ID)+" NOT = "+str(log_sensor_ID)+END)

    print ("Clear Alarm 4")
    print ("Restore sensors.conf")
    BSPfn.restoreSensorConf() #From beginning
    #BSPfn.cleanMessageLog()
    BSPfn.setSensor()
    time.sleep(10)
    print ("Check if alarm set")
    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR temperature alarm on sensor:", 
                            "XXXX",
                            "XXXX", 
                            "XXXX"])
#########################################################################
def TestSnap123() :   #TEST_0004.3
    print ("********************************************************")
    print ("*  fan_TEST0004.3     1 ALARMS &  fans & power supplies ")
    print ("********************************************************")
    print ("Get platID")
    id=pexpect.spawn("pfm_util")
    id.expect("PID\s+:\s*(.*?)\r\n.*")
    PID = id.match.groups(1)
    platID=PID[0][5:9]
    print("Select fanFactor")
    if platID  in  ("3132","3172") :
       fanFactor = 1.5
    elif platID in ('3048','3064') :
       fanFactor = 1.2
    else :
       fanFactor = 1.5
    print("Platform ID = "+platID)
    print("Fan Factor = %f" % fanFactor)
    #Boot up BSP
    BSPfn.backupSensorConf()
    BSPfn.cleanMessageLog()
    BSPfn.setSensor()
    (avg1RPM, fans)=BSPfn.createFansSnapshot()# Create Snapshot #1  (Before changes)
    print ("Nbr of fans:"+str(fans))
    print ("Set  temp sensor 1 max to 15")
    BSPfn.setTempSensorMax(1, 15)
    BSPfn.setSensor()
    time.sleep(10)
    (avg2RPM, fans)=BSPfn.createFansSnapshot()# Create Snapshot #2  (After "raising" tempurature)
    print (str(avg2RPM) + " RPM avg. > " + str(avg1RPM)+ " RPM avg.")
    if (avg2RPM >= fanFactor * avg1RPM ) :
       passit()
    else :
       failit()
       print(RED+"Ratio of fan speeds seems off"+END)

    print("Clear Alarm 1")
    print("Get number of power supplies")
    powsups=BSPfn.getPowerSupplies()
    print("Nbr of Power Supplies:"+str(powsups))
    if (powsups > 0 ) :
       passit()
    else :
       failit()
       print(RED+"Seems to be missing a power supply"+END)

    BSPfn.restoreSensorConf() #From beginning
    BSPfn.setSensor()
    time.sleep(10)
    (avg3RPM, fans)=BSPfn.createFansSnapshot()# Create Snapshot #3  (After going back to "normal")
    print (str(avg1RPM) + " RPM avg. about = " + str(avg3RPM)+" RPM avg.")
    if (avg1RPM - 500 <= avg3RPM) and (avg3RPM <= avg1RPM + 500) :
        passit()
    else :
        failit()
        print(RED+"Fans are not returning to normal"+END)

    (result, log_sensor_ID)=BSPfn.verifyMessageLog(["Raise MAJOR", 
                            "System shutdown",
                            "XXXX", 
                            "XXXX"])

#########################################################################
# Main Entrance

TestAlarms()     #TEST_0004.1
TestAlarm1234()  #TEST_0004.2
TestSnap123()    #TEST_0004.3

# End of test/script
###########################################################

