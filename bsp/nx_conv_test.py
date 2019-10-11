#!/usr/bin/env python
##########################################################
#  3132 Migration Tool Testing script
#       Performs Migration related tests
#  File:   conv_TEST0025.py
#  Date:   05/05/2015
#  Author: Robin Randall
# Copyright (C) 2015 Cisco Systems, Inc. all rights reserved
###########################################################
# Test TEST0025
#  1. Given we just booted up
#  2. Check for the following options 
#  3. Conversion Tool will not continue w/o i, k, & l options
###########################################################
import os, sys, re, math, time, shutil
import pexpect
global show
show=""
def usage() :
    print ("\nnxos-migration-tool Test Case ver. 1.1")
    print ("Copyright (C) 2015 Cisco Systems, Inc. all rights reserved")
    print ("Usage: [python] conv_TEST0025.py (IPV4 | IPV6 | TFTP | LOCAL) [SHOWLOG]")
    print ("Examples:       conv_TEST0025.py IPV6")
    print ("                conv_TEST0025.py TFTP")
    print ("        python  conv_TEST0025.py LOCAL")

if len(sys.argv) < 2 :
   usage()
   exit(0)
elif sys.argv[1].upper() == 'IPV4' :
     print(sys.argv[1])
elif sys.argv[1].upper() == 'IPV6' :
     print(sys.argv[1])
elif sys.argv[1].upper() == 'TFTP' :
     print(sys.argv[1])
elif sys.argv[1].upper() == 'LOCAL' :
     print(sys.argv[1])
elif sys.argv[1].upper() == "SHOWLOG":
     show = "SHOWLOG"
else:
   usage()
   exit(0)
if len(sys.argv) > 2:
   if sys.argv[2].upper() == "SHOWLOG":
      show = "SHOWLOG"
   else :
     usage()
     exit(0)
CSI="\x1B["
LOG_NUM = 0
LOG_MESSAGE_FILE = "/var/log/messages"
SENSORS_CONF_FILE = "/etc/sensors.d/sensors.conf"
SENSORS_CONF_FILE_BAK = "/etc/sensors.d/sensors.conf.bak"
TMP_SENSORS_CONF_FILE = "/tmp/sensors.conf"
TMP_SENSORS_DATA = "/tmp/sensors.data"
TEMP_SENSOR = "temp"
TEMP_SET = "set "
TEMP_MAX = "_max"
def passit():
    print(CSI+"30;42m"+"PASS"+CSI+"0m")
def failit():
    print(CSI+"30;41m"+"FAIL"+CSI+"0m")
def getRPMrange(file) :
   f_data=open(file,'r')
   global minRPM, maxRPM
   minRPM = 0
   maxRPM = 0
   for line in f_data.readlines() :
      m = re.search(r'^Fan\d\-\d:\s+?(\d+?) RPM.*\n$',line)
      if (m):
         print (line)
         if minRPM == 0 :
            minRPM = int(m.group(1))
         minRPM = min(int(m.group(1)),minRPM)
         maxRPM = max(maxRPM, int(m.group(1)))
   return (minRPM, maxRPM)

def getTempSensorStr(sensor_id):
    return TEMP_SENSOR + str(sensor_id)

def getSetTempSensorMaxStr(sensor_id):
    return TEMP_SET + getTempSensorStr(sensor_id) + TEMP_MAX

def setSensor():
    set_sensor_cmd = "sensors -s"
    print os.popen(set_sensor_cmd).read()

def setSensorData():
    set_sensor_cmd = "sensors > /tmp/sensors.data"
    os.popen(set_sensor_cmd).read()

def setTempSensorMax(sensor_id, max_temp):
    shutil.copyfile(SENSORS_CONF_FILE, TMP_SENSORS_CONF_FILE)
    f_conf_tmp = open(TMP_SENSORS_CONF_FILE)
    f_conf = open(SENSORS_CONF_FILE, "rw+")
    set_max_str = getSetTempSensorMaxStr(sensor_id)
    for line in f_conf_tmp:
        if line.find(set_max_str) != -1:
            # replace the max temp in the file
            old_max_temp = line.split()[2]
            new_line = line.replace(old_max_temp, str(max_temp))
            f_conf.write(new_line)
        else:
            f_conf.write(line)
    f_conf.flush()
    f_conf.close()
    f_conf_tmp.close()

def backupSensorConf():
    shutil.copyfile(SENSORS_CONF_FILE, SENSORS_CONF_FILE_BAK)

def restoreSensorConf():
    shutil.copyfile(SENSORS_CONF_FILE_BAK, SENSORS_CONF_FILE)

def cleanMessageLog():
    global LOG_NUM
    LOG_NUM += 1
    new_log_file = LOG_MESSAGE_FILE + "." + str(LOG_NUM)
    shutil.move(LOG_MESSAGE_FILE, new_log_file)
    
def verifyMessageLog(pattern_list, last_exist=1):
    index = 0
    f_log = open(LOG_MESSAGE_FILE)
    for line in f_log:
        if line.find(pattern_list[index]) != -1:
            print "Pattern '%s' found" % pattern_list[index] 
            if index < last_exist :
               index += 1
    #if last_exist:
    #    assert index == len(pattern_list)
    #else:
    #    assert index == (len(pattern_list)-1)

def Test0025(arg):

    print ("*********************************************")
    print ("*         conv_TEST0025.py                    ")
    print ("*********************************************")
    id=pexpect.spawn("telnet 172.27.244.253 6053") 
    logout = file('message.log','w')
    id.logfile = logout
    if show == "SHOWLOG" :
       id.logfile=sys.stdout
    if id == 0:
       print("Connection refused, leaving.")
       id.kill(0)
    else:
       id.expect("Escape character")
       id.sendline("\r")
       try:
          id.expect('root@n3000:~#')
       except:
          print("Unrecognized prompt, leaving.")
          id.kill(1)
          exit()
       id.sendline("uname -a")
       index=id.expect(["standard",pexpect.EOF,pexpect.TIMEOUT])
 
    #Now in BSP box via TELNET ************************************
    print ("Try non-root directory")
    print("*** -h option ****")
    id.sendline("nxos-migration-tool -h")
    index = -1
    index=id.expect(['nxos-migration-tool', '\[ \-k\|\-\-kickstart \<image\-url\>',pexpect.EOF,pexpect.TIMEOUT])  
    if (index>=0) :
       passit()
    else :
       failit()
    print("*** -f option ****")
    id.sendline("nxos-migration-tool -f")
    index = -1
    index=id.expect(['ERROR: License file not provided!!!',pexpect.EOF,pexpect.TIMEOUT])
    if (index>=0) :
       passit()
    else :
       failit()
    print ("Switch to root directory")
    result = os.system("cd /")
    print result
    print ("****** Create license **********")
    result = os.system("rm good.lic")
    s_n = ''
    id.sendline("pfm_util -d")
    id.expect("S/N\s+:\s*(.*?)\r\n.*")
    s_n = id.match.groups(1)
    result=os.system("echo HOSTIDS/N    :  " + s_n[0] + " > good.lic")
    result=os.system("cat good.lic")
    result = os.system("pwd")

    print ("****** no_args ******")
    index = -1
    id.sendline("nxos-migration-tool")
    index=id.expect("ERROR: License file not provided!!!")
    if (index==0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)

    print ("****** -s  -k  -l ******")
    index = -1
    id.sendline("nxos-migration-tool -s -k -l")
    index=id.expect("ERROR: License file not provided!!!")
    if (index==0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)


    print ("****** bad  bad   bad ******")
    id.sendline("nxos-migration-tool -s bad.isan -k bad.kick -l invalid.lic")
    index = -1
    index=id.expect(['Do you want to continue\? \(y/n\) : ',pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.sendline("y")
    index=-1
    index=id.expect("ERROR: Failed to get License!!! Verify License URL") 
    if (index==0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)


    print ("****** bad bad good ***** dup images *")
    id.sendline("nxos-migration-tool -s bad.isan -k bad.kick -l good.lic")
    index = -1
    index=id.expect(['Do you want to continue\? \(y/n\) : ',pexpect.EOF,pexpect.TIMEOUT])
    if (index >= 0) :
       id.sendline("y")
    index = -1
    index=id.expect(['ERROR: Failed to get Image!!! Verify Image URL',pexpect.EOF,pexpect.TIMEOUT])
    if (index>=0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)


    print ("****** bad good good ******")
    id.sendline("nxos-migration-tool -s bad.isan -k http://10.6.54.61//pxe/n3k-ocp2.kick -l good.lic")
    index = -1
    index=id.expect(['Do you want to continue\? \(y/n\) : ',pexpect.EOF,pexpect.TIMEOUT])
    if index >=0 :
       id.sendline("y")
    index = -1
    index=id.expect(['ERROR: Failed',pexpect.EOF,pexpect.TIMEOUT])
    if (index>=0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)


    print ("****** good bad good ******")
    id.sendline("nxos-migration-tool -s http://10.6.54.61//pxe/n3k-ocp2.isan -k http://10.6.54.61//pxe/n3k-ocp2.isan -l good.lic")
    index = -1
    index=id.expect(['Do you want to continue\? \(y/n\) : ',pexpect.EOF,pexpect.TIMEOUT])
    if (index >=0):
       id.sendline("y")
    index = -1
    index=id.expect(['ERROR: Kickstart(.*)\n',pexpect.EOF,pexpect.TIMEOUT])
    if (index>=0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)


    print ("****** good good bad ******")
    id.sendline("nxos-migration-tool -s http://10.6.54.61//pxe/n3k-ocp2.isan -k http://10.6.54.61//pxe/n3k-ocp2.kick -l invalid.lic")
    index = -1
    index=id.expect(['Do you want to continue\? \(y/n\) : ',pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
        id.sendline("y")
    index = -1
    index=id.expect(['ERROR: Failed to get License!!! Verify License URL',pexpect.EOF,pexpect.TIMEOUT])
    if (index>=0) :
       passit()
    else :
       failit()
    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)


    #print ("****** good4 good4 good6 ******")
    #id.sendline("nxos-migration-tool -s http://10.6.54.61//pxe/n3k-ocp2.isan -k http://10.6.54.61//pxe/n3k-ocp2.kick -l http://[2001:192:10:1::85]/pxe/fake.lic")
    #id.expect(r".*\(y\/n\).*")
    #id.sendline("y")
    #id.sendline('\n')
    ## Is it the license file it cannot download or another?
    #index = -1
    #index=id.expect(['ERROR: Failed to download',pexpect.EOF,pexpect.TIMEOUT])
    #if (index>=0) :
    #   passit()
    #else :
    #   failit()
    #index = -1
    #index=id.expect(['Reboot Now',pexpect.EOF,pexpect.TIMEOUT],timeout=1000)
    #if (index>=0) :
    #   passit()
    #else :
    #   failit()
    #print("*********at BSP ready to REBOOT **************")

    #print ("****** good good good ******")
    #id.sendline("nxos-migration-tool -s http://10.6.54.61//pxe/n3k-ocp2.isan -k http://10.6.54.61//pxe/n3k-ocp2.kick -l good.lic")
    #id.expect(r".*\(y\/n\).*")
    #id.sendline("y")
    #id.sendline('\n')
    #index = -1
    #index=id.expect(['Reboot Now',pexpect.EOF,pexpect.TIMEOUT],timeout=1000)
    #if (index>=0) :
    #   passit()
    #else :
    #   failit()
    #print("*********at BSP ready to REBOOT **************")
    id.sendcontrol(']')
    id.sendline('q')
    print("We are done, so kill the Telnet connection.")
    print("Option = "+arg)
    print(CSI+"30;42m"+"###########################################"+CSI+"0m")
    print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
    print(CSI+"30;42m"+"#    N E G A T I V E   T E S T S          #"+CSI+"0m")
    print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
    print(CSI+"30;42m"+"#         C O M P L E T E ! ! !           #"+CSI+"0m")
    print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
    print(CSI+"30;42m"+"###########################################"+CSI+"0m")
    id.kill(0)

#############################################################
# Main Entrance
arg = 'IPV4'
Test0025(arg)     # Setup


# End of test/script
###########################################################
