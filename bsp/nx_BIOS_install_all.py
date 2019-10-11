#!/usr/bin/env python
##########################################################
#  3132 Migration Tool Testing script
#       Performs BIOS upgrade  related tests
#  File:   conv_BIOS.1.py
#  Date:   05/05/2015
#  Author: Robin Randall
###########################################################
# Test conv.BIOS.1
#  1. Given we just booted up
#  2. Check for the following options:  upgrade IPV4
#  3. Conversion Tool will not continue w/o i, k, & l options
###########################################################
import os, sys, re, math, time, shutil
import pexpect,string
###########################################################
def usage() :
    print ("\nnxos-migration-tool BIOS Test Case ver. 1.1")
    print ("Copyright (C) 2015 Cisco Systems, Inc. all rights reserved")
    print ("Usage: [python] conv_BIOS.py [-cur <cur_image> -upg <upg_image>][SHOWLOG]")
    print ("Examples:       conv_BIOS.py  -CUR 170  -UPG 172")
    print ("                conv_BIOS.py SHOWLOG")

n=len(sys.argv)
global show, cur, upg, ip, answer
show="";cur='170';upg='172';ip="IPV4"

if n > 1 and sys.argv[1].upper() == 'SHOWLOG' :
        print sys.argv[1]
        show='SHOWLOG'
        if n > 2 :
           print (sys.argv[2]+" "+sys.argv[3]+" "+sys.argv[4]+" "+sys.argv[5]) 
           cur=str(sys.argv[3])
           upg=str(sys.argv[5])

elif n > 1 and sys.argv[1].upper() =='-CUR' :
        print (sys.argv[1]+" "+sys.argv[2]+" "+sys.argv[3]+" "+sys.argv[4]) 
        cur=str(sys.argv[2])
        upg=str(sys.argv[4])
        if n > 5 and sys.argv[5].upper() == 'SHOWLOG' :
           show='SHOWLOG'
else:
   usage()
   exit(0)

# In case /var/log/messages got deleted, this ensures it is there
# cleanMessageLog   "shutil.move" command can do this.
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

def passit() :
    print CSI+"30;42m" +"PASS"+CSI+"0m"

def failit() :
    print CSI+"30;41m" +"FAIL"+CSI+"0m"

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
    os.system("truncate /var/log/messages --size 0")
    
def verifyMessageLog(pattern):
    global log_sensor_ID, sens
    f_log = open(LOG_MESSAGE_FILE,'r')
    found = 0
    index = 0
    sens = 0
    for line in f_log:
      for index in range(4) :
        if line.find(pattern[index]) >=0 :
           sens = line.find("sensor:")
           if sens >=0 :
             print line[sens+8:]
             end = line[sems+8:].find(')')
             log_sensor_ID = line[sens+8:][:end]
           else:
             print("found pattern: %s in line: %s" % (pattern[index],line))
        found += line.count(pattern[index]) 
    if found >= 1:
        return True
    else:
        return False

def scpCiscoSource(id, command):
      id.sendline("cd /")
      id.sendline(command)
      index=id.expect(["yes/no",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0 :
         id.sendline("yes")
      id.expect(["[pP]assword:",pexpect.EOF,pexpect.TIMEOUT],timeout=100)
      id.sendline("devtest-")
      time.sleep(60)

def copyscpCiscoSource(id, command):
      id.sendline(command)
      index = -1
      index=id.expect(["yes/no",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0:
         id.sendline("yes")
      index = -1
      index=id.expect(["password:",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0:
         id.sendline("devtest-")
      index= -1
      time.sleep(200)

def recoverNexusCommands(id) :
    id.sendline("conf t")
    id.sendline("no boot kick")
    id.sendline("no boot system")
    id.sendline("exit")
    id.sendline("copy run start")

def Test_BIOS(arg):
    print ("*********************************************")
    print ("*         conv_BIOS.py                 ")
    print ("*********************************************")
    print ("*   using  "+arg+" option                   *")
    print ("*********************************************")
    id=pexpect.spawn("telnet 172.19.193.127 6036") 
    logout = file('message.log','w')
    id.logfile = logout
    if show == 'SHOWLOG' :
       id.logfile=sys.stdout
    if id == 0:
       print("Connection refused, leaving.")
       id.kill(0)
    else:
       id.expect("Escape character")
       id.sendline("\r")
       try:
          id.expect('root@n3000:.#')
       except:
          print("Unrecognized prompt, leaving.")
          id.kill(1)
          exit()
       id.sendline("uname -a")
       index=id.expect(["standard",pexpect.EOF,pexpect.TIMEOUT])
 
    #Now in BSP box via TELNET ************************************
    #cleanMessageLog()
    print ("Switch to root directory")
    id.sendline("cd /")
    if arg == "IPV4":
       print ("****** Create license if LOCAL **********")
       id.sendline("rm good.lic")
       s_n = ''
       id.sendline("pfm_util -d")
       id.expect("S/N\s+:\s*(.*?)\r\n.*")
       s_n = id.match.groups(1)
       id.sendline("echo HOSTIDS/N    :  " + s_n[0] + " > good.lic")
       id.sendline("cat good.lic")
       id.sendline("pwd")
    # Configuration variables which can be changed to give different test combinations with different networks
    DHCP_IPV4 = '//10.6.54.61/'
    LOCAL_NET = '172.19.211.47'
    A_PATH    = '/auto/n3keagleinteg/daily_build/eagle_integ/nexus/'
    B_PATH    = '/src/build/images/final/n3000-uk9'
    C_PATH    = 'n3000-uk9'
    ISAN      = '6.0.2.U7.0.'
    KICK      = 'kickstart.6.0.2.U7.0.'
    LICENSE   = 'good.lic'
    TFTP_NET  = '//172.19.211.47//'
    X_PATH    = 'tftpboot/rsangle'
    Y_PATH    = 'n3k-ocp2'
    UPG       = upg
    CUR       = cur

    print ("****** good good good ******")
    if arg == 'IPV4' :
      command = 'scp cisco@'+LOCAL_NET+':/'+A_PATH+cur+B_PATH+'-'+KICK+cur+'.bin .'
      scpCiscoSource(id, command)
      command = 'scp cisco@'+LOCAL_NET+':/'+A_PATH+cur+B_PATH+'.'+ISAN+cur+'.bin .'
      scpCiscoSource(id, command)
      command='nxos-migration-tool -s '+C_PATH+'.'+ISAN+cur+'.bin -k '+C_PATH+'-'+KICK+cur+'.bin -l '+LICENSE
      print(command)
    else :
      usage()
      exit(0)   
    time.sleep(5)
    print ("Send command ...")
    id.sendline(command)
    print ("Monitoring Progress ...")
    try:
       id.expect("Preparing image archive ... OK.")
    except:
       print "Tool not invoked correctly, FAIL"
       failit()
       id.kill(1)
       exit()
    try:
       id.expect("Do you want to continue?")
    except:
       print "Tool did not ask for confirmation, FAIL"
       failit()
       id.kill(1)
       exit()
    id.sendline("y")
    try:
       id.expect(["Reboot Now",pexpect.EOF,pexpect.TIMEOUT],timeout=500)
    except:
       print("Migration tool failed, Test FAIL")
       failit()
       id.kill(1)
       exit()
    id.sendline('\n')
    #Abort Power On Auto Provisioning and continue with normal setup ?(yes/no)[n]:
    print("*********in  BSP ready to REBOOT **************")
    id.sendline("reboot")
    index = -1
    index=id.expect(['Power On Auto Provisioning',pexpect.EOF,pexpect.TIMEOUT],timeout=1000)
    if (index >= 0):
       id.sendline("yes")
    index = -1
    index=id.expect(["secure password",pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.sendline("no")
    index = -1
    index=id.expect(["password",pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.sendline("lab")
    index = -1
    index=id.expect(["password",pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.sendline("lab")
    index = -1
    index=id.expect(["basic configuration",pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.sendline("no")
    index = -1
    index=id.expect(["logon:",pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.sendline("admin")
    index = -1
    index=id.expect(["Password: ",pexpect.EOF,pexpect.TIMEOUT])
    if index >=0 :
       id.sendline("lab")
    id.sendline("show version")
    index = -1
    print("We should now be in NXOS ready to reload")
    index=id.expect(["BIOS:      version",pexpect.EOF,pexpect.TIMEOUT])
    if index >=0 :
      id.sendline(" ")   # Pass by "--More--"
    print("********** Copy upgrade images to bootflash *****")
    if index >= 0 :
      print("********* COPY SCP CISCO SOURCES *****")
      command='copy scp://cisco@'+LOCAL_NET+A_PATH+upg+B_PATH+'-'+KICK+upg+'.bin' + ' bootflash: vrf management'
      #copyscpCiscoSource(id, command)
      id.sendline(command)
      index = -1
      index=id.expect(["yes/no",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0:
         id.sendline("yes")
      index = -1
      index=id.expect(["password:",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0:
         id.sendline("devtest-")
      index= -1
      time.sleep(200)
      command='copy scp://cisco@'+LOCAL_NET+A_PATH+upg+B_PATH+'.'+ISAN+upg+'.bin' + ' bootflash: vrf management'
      #copyscpCiscoSource(id, command)
      id.sendline(command)
      index = -1
      index=id.expect(["yes/no",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0:
         id.sendline("yes")
      index = -1
      index=id.expect(["password:",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0:
         id.sendline("devtest-")
      index= -1
      time.sleep(200)
      time.sleep(500)
      print("************ INSTALL  ALL ********************")
      id.sendline("install all kickstart bootflash:"+C_PATH+"-"+KICK+upg+'.bin'+" system bootflash:"+C_PATH+"."+ISAN+upg+'.bin')
      time.sleep(500)
      index = -1
      index=id.expect(["y/n",pexpect.EOF,pexpect.TIMEOUT])
      if index == 0 :
         id.sendline("n")
         answer = "n"
      index = -1
      index=id.expect(["Failed to process",pexpect.EOF,pexpect.TIMEOUT],timeout=300)
      if index == 0 :
         failit()
    else :
      failit()
    print ("************* Recover and Reload **************")
    if answer == "n":
       recoverNexusCommands(id)
    id.sendline("reload")
    index = -1
    index=id.expect(["y/n [n]",pexpect.EOF,pexpect.TIMEOUT])
    if index >=0 :
       id.sendline("y")
    print ("Back to BSP - TAB and EFI Network")
    index=id.expect(["TAB.*",pexpect.EOF,pexpect.TIMEOUT])
    if index >= 0 :
       id.send("\t")       # Tab in less than 5 seconds.
       id.send("Ctrl+I")   # Tab in less than 5 seconds.
    index = -1
    index=id.expect(["EFI Network",pexpect.EOF,pexpect.TIMEOUT])
    if index >=0 :
       id.send("3")
    print("Embedded ONIE")
    index=id.expect(["GNU GRUB",pexpect.EOF,pexpect.TIMEOUT],timeout=500)
    if index >=0 :
       id.sendline("v")     #Uses "v" as a down arrow
       id.sendline("\r\n")  #Select embed ONIE
    #Wait a long time for defaults to bring us back to BSPa
    index=id.expect(["n3000 login:",pexpect.EOF,pexpect.TIMEOUT],timeout=500)
    if index >=0 :
       id.sendline("root")  #If successful, we are back to BSP
    index=id.expect(["root@n3000:.#",pexpect.EOF,pexpect.TIMEOUT])
    print("BSP SHOULD BE BACK NOW")
    if index >=0 :
       print("We are done, so kill the Telnet connection.")
       print("Option = "+arg)
       print(CSI+"30;42m"+"###########################################"+CSI+"0m")
       print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
       print(CSI+"30;42m"+"#    B I O S   U P G R A D E   I S        #"+CSI+"0m")
       print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
       print(CSI+"30;42m"+"#         C O M P L E T E ! ! !           #"+CSI+"0m")
       print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
       print(CSI+"30;42m"+"###########################################"+CSI+"0m")
       id.kill(0)

    #Should we have something  similar to below
    #verifyMessageLog(["Raise", "System shutdown", "CLEAR", "System shutdown"], 0)

#############################################################
# Main Entrance
arg = ip
Test_BIOS(arg)         #  Telnet

# End of test/script
###########################################################
