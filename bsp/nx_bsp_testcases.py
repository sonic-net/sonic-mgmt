#!/bin/env python

# ##################################################################
# # bsp Automation Script
###################################################################

import os
import sys
import re
import time
import math
import shutil
import pexpect

#Global Variables
CSI="\x1B["
LOG_MESSAGE_FILE = "/var/log/messages"
pin = "none"
psu = "none"

#Get Platform ID
id=pexpect.spawn("pfm_util")
id.expect("PID\s+:\s*(.*?)\r\n.*")
PID = id.match.groups(1)
platID=PID[0][5:9]


    
#Global Functions
def cleanMessageLog():
    os.system("truncate /var/log/messages --size 0")
    
def verifyMessageLog(pattern):
    f_log = open(LOG_MESSAGE_FILE,"r")
    found = 0
    for line in f_log:
        #print("search pattern: %s in line: %s" % (pattern,line))
        found += line.count(pattern)       
    if found >= 1:
        return True
    else:
        return False
 
#############################################################
# Test softOIR_gpioPsPresence
#  1. Change the active_low status of the power supply module
#       /sys/class/gpio/gpio494# echo 0 > active_low
#  2. Verify the logs
#  3. Change active_low status back to original
#############################################################
      
class softOIR_gpioPsPresence():
    """
    1.  Cause soft OIR for PS
    """

    def softOIR_gpioPsPresence_test(self):   
        print ("*********************************************")
        print ("*     softOIR_gpioPsPresence for %s         *" % psu)
        print ("*********************************************")    
        """test action: Verify the active_low of PS and change it"""
        activeLow_status = os.popen("cat /sys/class/gpio/%s/active_low" % pin).read()
        print ("active_low for %s: %s" % (pin,activeLow_status))
        activeLow_status=activeLow_status.rstrip()
        if activeLow_status in ("1"):
            print ("*****%s Module present*****" % psu)
            print("Clean var/log/messages")
            cleanMessageLog()
            time.sleep(1)
            
            """test action: Change the active_low status"""
            print ("change active_low status to 0")
            activeLow_change = os.system("echo 0 > /sys/class/gpio/%s/active_low" % pin)
            time.sleep(10)
            activeLow_status = os.popen("cat /sys/class/gpio/%s/active_low" % pin).read()
            print ("active_low for %s: %s" % (pin,activeLow_status))
            
            """test action: Verify /var/log/messages"""
            check_result_1 = verifyMessageLog("%s is REMOVED" % psu)
            if (check_result_1 == True):
                print ("%s is removed" % psu)
                print CSI+"30;42m" +"PASS"+CSI+"0m"
            else:
                print ("%s not removed" % psu)
                print CSI+"30;41m" +"FAIL"+CSI+"0m"
                
            print("Clean var/log/messages")
            cleanMessageLog()
            time.sleep(1)
            
            """test action: Change active_low to original"""
            print ("change active_low status to 1")
            activeLow_change = os.system("echo 1 > /sys/class/gpio/%s/active_low" % pin)
            time.sleep(10)
            activeLow_status = os.popen("cat /sys/class/gpio/%s/active_low" % pin).read()
            print ("active_low for %s: %s" % (pin,activeLow_status))   
            
            """test action: Verify /var/log/messages"""
            check_result_1 = verifyMessageLog("%s is OK" % psu)
            if (check_result_1 == True):
                print ("%s is OK" % psu)
                print CSI+"30;42m" +"PASS"+CSI+"0m"
            else:
                print ("%s not OK" % psu)
                print CSI+"30;41m" +"FAIL"+CSI+"0m"
            check_result_2 = verifyMessageLog("PMBus status register not found")
            if (check_result_2 == True):
                print ("PMBus status register not found logged")
                print CSI+"30;41m" +"FAIL"+CSI+"0m"
        else:
            print ("*****%s Module absent*****" % psu)
            print("Clean var/log/messages")
            cleanMessageLog()
            time.sleep(1)
            
            """test action: Change the active_low status"""
            print ("change active_low status to 1")
            activeLow_change = os.system("echo 1 > /sys/class/gpio/%s/active_low" % pin)
            time.sleep(10)
            activeLow_status = os.popen("cat /sys/class/gpio/%s/active_low" % pin).read()
            print ("active_low for %s: %s" % (pin,activeLow_status))
            
            """test action: Verify /var/log/messages"""
            check_result_1 = verifyMessageLog("%s is OK" % psu)
            if (check_result_1 == True):
                print ("%s is ok" % psu)
                print CSI+"30;42m" +"PASS"+CSI+"0m"
            else:
                print ("%s not ok" % psu)
                print CSI+"30;41m" +"FAIL"+CSI+"0m"
                
            print("Clean var/log/messages")
            cleanMessageLog()
            time.sleep(1)
            
            """test action: Change active_low to original"""
            print ("change active_low status to 0")
            activeLow_change = os.system("echo 0 > /sys/class/gpio/%s/active_low" % pin)
            time.sleep(10)
            activeLow_status = os.popen("cat /sys/class/gpio/%s/active_low" % pin).read()
            print ("active_low for %s: %s" % (pin,activeLow_status))   
            
            """test action: Verify /var/log/messages"""
            check_result_1 = verifyMessageLog("%s is REMOVED" % psu)
            if (check_result_1 == True):
                print ("%s is removed" % psu)
                print CSI+"30;42m" +"PASS"+CSI+"0m"
            else:
                print ("%s not removed" % psu)
                print CSI+"30;41m" +"FAIL"+CSI+"0m"    
                
      
###########################################################
# Test softOIR_gpioFanPresence_1 for 3132 and 3172 platforms
#  1. Change the active_low status of the fan module
#       /sys/class/gpio/gpio500# echo 0 > active_low
#  2. Verify the logs
#  3. Change active_low status back to original
###########################################################
      
class softOIR_gpioFanPresence_1():
    """
    1.  Cause soft OIR for fan presence
    """
    
    def softOIR_gpioFanPresence_1_test(self):    
        """test action: Verify the active_low of fan module 1 and change it"""
        activeLow_status = os.popen("cat /sys/class/gpio/gpio500/active_low").read()
        print ("active_low for gpio500: %s" % activeLow_status)
        activeLow_status=activeLow_status.rstrip()
        if activeLow_status in ("1"):
            print ("*****Fan1-1 Module present*****")
            print("Clean var/log/messages")
            cleanMessageLog()
            time.sleep(1)
            
            """test action: Change the active_low status"""
            print ("change active_low status to 0")
            activeLow_change = os.system("echo 0 > /sys/class/gpio/gpio500/active_low")
            time.sleep(5)
            activeLow_status = os.popen("cat /sys/class/gpio/gpio500/active_low").read()
            print ("active_low for gpio500: %s" % activeLow_status)       
            
            """test action: Verify /var/log/messages"""
            check_result_1 = verifyMessageLog("Fan1-1 is REMOVED")
            check_result_2 = verifyMessageLog("Fan1-2 is REMOVED")
            if (check_result_1 == True and check_result_2 == True):
                print ("Fan1 is removed")
                print CSI+"30;42m" +"PASS"+CSI+"0m"
            else:
                print ("Fan1 not removed")
                print CSI+"30;41m" +"FAIL"+CSI+"0m"
                
            print("Clean var/log/messages")
            cleanMessageLog()
            time.sleep(1)
            
            """test action: Change active_low to original"""
            print ("change active_low status to 1")
            activeLow_change = os.system("echo 1 > /sys/class/gpio/gpio500/active_low")
            time.sleep(5)
            activeLow_status = os.popen("cat /sys/class/gpio/gpio500/active_low").read()
            print ("active_low for gpio500: %s" % activeLow_status)   
            
            """test action: Verify /var/log/messages"""
            check_result_1 = verifyMessageLog("Fan1-1 is OK")
            check_result_2 = verifyMessageLog("Fan1-2 is OK")            
            if (check_result_1 == True and check_result_2 == True):
                print ("Fan1 is OK")
                print CSI+"30;42m" +"PASS"+CSI+"0m"
            else:
                print ("Fan1 not OK")
                print CSI+"30;41m" +"FAIL"+CSI+"0m" 
                
    
###########################################################
# Test softOIR_gpioFanPresence_All
#  1. Change the active_low status of all fan module
#  2. Verify the logs
#  3. Change active_low status back to original
###########################################################
      
class softOIR_gpioFanPresence_All():
    """
    1.  Cause soft OIR for all fans
    """
    
    def softOIR_gpioFanPresence_All_test(self):  
        print ("*********************************************")
        print ("*         softOIR_gpioFanPresence_All         *")
        print ("*********************************************")   
        if platID  in  ("3048","3064"):
            print "*****Remove all fans for 30xx platform*****"
            """test action: Verify the active_low of fan modules and change it"""
            activeLow_status = os.popen("cat /sys/class/gpio/gpio509/active_low").read()
            print ("active_low for gpio509: %s" % activeLow_status)
            activeLow_status=activeLow_status.rstrip()
            if activeLow_status in ("1"):
                print ("*****Fan Module present*****")
                print("Clean var/log/messages")
                cleanMessageLog()
                time.sleep(1)
            
                """test action: Change the active_low status"""
                print ("change active_low status to 0")
                activeLow_change = os.system("echo 0 > /sys/class/gpio/gpio509/active_low")
                time.sleep(15)
                activeLow_status = os.popen("cat /sys/class/gpio/gpio509/active_low").read()
                print ("active_low for gpio509: %s" % activeLow_status)       
            
                """test action: Verify /var/log/messages"""
                check_result_1 = verifyMessageLog("Fan1 is REMOVED")
                check_result_2 = verifyMessageLog("Fan2 is REMOVED")
                check_result_3 = verifyMessageLog("Fan3 is REMOVED")
                check_result_4 = verifyMessageLog("Fan4 is REMOVED")
                check_result_5 = verifyMessageLog("System shutdown in 120 seconds due to fan missing or failed")
                if (check_result_1 == True and check_result_2 == True and check_result_3 == True and check_result_4 == True and check_result_5 == True):
                    print ("All fans removed and system shutdown maessage logged")
                    print CSI+"30;42m" +"PASS"+CSI+"0m"
                else:
                    print ("All fans not removed")
                    print CSI+"30;41m" +"FAIL"+CSI+"0m"
                
                print("Clean var/log/messages")
                cleanMessageLog()
                time.sleep(1)
            
                """test action: Change active_low to original"""
                print ("change active_low status to 1")
                activeLow_change = os.system("echo 1 > /sys/class/gpio/gpio509/active_low")
                time.sleep(5)
                activeLow_status = os.popen("cat /sys/class/gpio/gpio509/active_low").read()
                print ("active_low for gpio509: %s" % activeLow_status)   
            
                """test action: Verify /var/log/messages"""
                check_result_1 = verifyMessageLog("Fan1 is OK")
                check_result_2 = verifyMessageLog("Fan2 is OK")
                check_result_3 = verifyMessageLog("Fan3 is OK")
                check_result_4 = verifyMessageLog("Fan4 is OK")          
                if (check_result_1 == True and check_result_2 == True and check_result_3 == True and check_result_4 == True):
                    print ("ALl fans are OK")
                    print CSI+"30;42m" +"PASS"+CSI+"0m"
                else:
                    print ("All fans not OK")
                    print CSI+"30;41m" +"FAIL"+CSI+"0m"
        if platID  in  ("3132","3172"):
            print "*****Remove all fans for 31xx platform*****"
            """test action: Verify the active_low of fan modules and change it"""
            value_1 = (os.popen("cat /sys/class/gpio/gpio500/value").read()).rstrip()
            value_2 = (os.popen("cat /sys/class/gpio/gpio501/value").read()).rstrip()
            value_3 = (os.popen("cat /sys/class/gpio/gpio502/value").read()).rstrip()
            value_4 = (os.popen("cat /sys/class/gpio/gpio503/value").read()).rstrip()
            if value_1 in ("0"):
                print ("Fan module 1 absent")   
            if value_2 in ("0"):
                print ("Fan module 2 absent")
            if value_3 in ("0"):
                print ("Fan module 3 absent")
            if value_4 in ("0"):
                print ("Fan module 4 absent")
            value = value_1+value_2+value_3+value_4
            if value in ("1111"):
                print ("*****Fan Modules present*****")
                print("Clean var/log/messages")
                cleanMessageLog()
                time.sleep(1)
            
                """test action: Change the active_low status"""
                print ("change active_low status to 0")
                os.system("echo 0 > /sys/class/gpio/gpio500/active_low")
                os.system("echo 0 > /sys/class/gpio/gpio501/active_low")
                os.system("echo 0 > /sys/class/gpio/gpio502/active_low")
                os.system("echo 0 > /sys/class/gpio/gpio503/active_low")
                time.sleep(15)     
            
                """test action: Verify /var/log/messages"""
                t_1 = verifyMessageLog("Fan1-1 is REMOVED")
                t_2 = verifyMessageLog("Fan1-2 is REMOVED")
                t_3 = verifyMessageLog("Fan2-1 is REMOVED") 
                t_4 = verifyMessageLog("Fan2-2 is REMOVED")
                t_5 = verifyMessageLog("Fan3-1 is REMOVED")
                t_6 = verifyMessageLog("Fan3-2 is REMOVED")
                t_7 = verifyMessageLog("Fan4-1 is REMOVED")
                t_8 = verifyMessageLog("Fan4-2 is REMOVED")
                t_9 = verifyMessageLog("System shutdown in 120 seconds due to fan missing or failed")
                check_result = t_1 and t_2 and t_3 and t_4 and t_5 and t_6 and t_7 and t_8 and t_9
                if (check_result == True):
                    print ("All fans removed and system shutdown maessage logged")
                    print CSI+"30;42m" +"PASS"+CSI+"0m"
                else:
                    print ("All fans not removed")
                    print CSI+"30;41m" +"FAIL"+CSI+"0m"
                
                print("Clean var/log/messages")
                cleanMessageLog()
                time.sleep(1)
            
                """test action: Change active_low to original"""
                print ("change active_low status to 1")
                os.system("echo 1 > /sys/class/gpio/gpio500/active_low")
                os.system("echo 1 > /sys/class/gpio/gpio501/active_low")
                os.system("echo 1 > /sys/class/gpio/gpio502/active_low")
                os.system("echo 1 > /sys/class/gpio/gpio503/active_low")
                time.sleep(5)
            
                """test action: Verify /var/log/messages"""
                t_1 = verifyMessageLog("Fan1-1 is OK")
                t_2 = verifyMessageLog("Fan1-2 is OK")
                t_3 = verifyMessageLog("Fan2-1 is OK") 
                t_4 = verifyMessageLog("Fan2-2 is OK")
                t_5 = verifyMessageLog("Fan3-1 is OK")
                t_6 = verifyMessageLog("Fan3-2 is OK")
                t_7 = verifyMessageLog("Fan4-1 is OK")
                t_8 = verifyMessageLog("Fan4-2 is OK")   
                check_result = t_1 and t_2 and t_3 and t_4 and t_5 and t_6 and t_7 and t_8  
                if (check_result == True):
                    print ("All fans are OK")
                    print CSI+"30;42m" +"PASS"+CSI+"0m"
                else:
                    print ("All fans not OK")
                    print CSI+"30;41m" +"FAIL"+CSI+"0m" 
            else:
                print "Fan Module missing, please insert all fan modules otherwise system will overheat"            
       
if __name__ == '__main__':

    if platID  in  ("3048","3064"):
        print ("*********************************************")
        print ("*           softOIR_gpioPsPresence          *")
        print ("*********************************************") 
        if ((os.popen("cat /sys/class/gpio/gpio510/value").read()).rstrip('\n')) in ("1"):
            pin = "gpio510"
            psu = "PSU0"
            test1=softOIR_gpioPsPresence()
            test1.softOIR_gpioPsPresence_test()
        else:
            print "PSU0 absent on platform"
        time.sleep(5)
        if ((os.popen("cat /sys/class/gpio/gpio511/value").read()).rstrip('\n')) in ("1"):
            pin = "gpio511"
            psu = "PSU1"
            test1=softOIR_gpioPsPresence()
            test1.softOIR_gpioPsPresence_test()
        else:
            print "PSU1 absent on platform"
                
    if platID  in  ("3132","3172"):
        print ("*********************************************")
        print ("*           softOIR_gpioPsPresence          *")
        print ("*********************************************")  
        if ((os.popen("cat /sys/class/gpio/gpio494/value").read()).rstrip('\n')) in ("1"):
            pin = "gpio494"
            psu = "PSU0"
            test1=softOIR_gpioPsPresence()
            test1.softOIR_gpioPsPresence_test()
        else:
            print "PSU0 absent on platform"     
        time.sleep(5)
        if ((os.popen("cat /sys/class/gpio/gpio495/value").read()).rstrip('\n')) in ("1"):
            pin = "gpio495"
            psu = "PSU1"
            test1=softOIR_gpioPsPresence()
            test1.softOIR_gpioPsPresence_test()
        else:
            print "PSU1 absent on platform"
    if platID  in  ("3132","3172"):
        print ("*********************************************")
        print ("*      softOIR_gpioFanPresence_1 for 31xx   *")
        print ("*********************************************")  
        if ((os.popen("cat /sys/class/gpio/gpio500/value").read()).rstrip('\n')) in ("1"):
            test2=softOIR_gpioFanPresence_1()
            test2.softOIR_gpioFanPresence_1_test()
        else:
            print "Fan module 1 absent on platform"  
     
    test3=softOIR_gpioFanPresence_All()
    test3.softOIR_gpioFanPresence_All_test()

