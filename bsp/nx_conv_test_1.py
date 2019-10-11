#!/usr/bin/env python
##########################################################
#  3132 Migration Tool Testing script
#       Performs Migration related tests
#  File:   conv_TEST0025.1.py
#  Date:   05/05/2015
#  Author: Robin Randall
###########################################################
# Test TEST0025.1
#  1. Given we just booted up
#  2. Check for the following options 
#  3. Conversion Tool will not continue w/o i, k, & l options
###########################################################
import os, sys, re, math, time, shutil
import pexpect,string
###########################################################

global logs, switch, protocol, nxos

def usage() :
    print ("\nnxos-migration-tool test script")
    print ("Copyright (C) 2015 Cisco Systems, Inc. all rights reserved")
    print ("Usage: [python] conv_TEST.py <switch> [-p <IPV4 | IPV6 | TFTP | LOCAL>] [-n <nxos_image_label>] [SHOWLOG]")
    print ("-p - protocol to be used for fetching images and license")
    print ("-n - nxos image version number to be booted on the system upon completion of conversion")
    print ("Examples:       conv_TEST.py c3132qx-1 -p IPV6 -n 179")
    print ("                conv_TEST.py c3132qx-5 -p TFTP -n 182")
    print ("        python  conv_TEST.py n3048tp-3 -p LOCAL -n 180 SHOWLOG")

n=len(sys.argv)

#Initialize to defaults
logs = "";
switch = ""
protocol = "IPV4";
nxos = "179";

switch = str(sys.argv[1])
print switch

if n > 2 and sys.argv[2].upper() == 'SHOWLOG' :
	print sys.argv[2]
	show='SHOWLOG'

elif n > 3 and n < 7:
	print (sys.argv[2]+" "+sys.argv[3]+" "+sys.argv[4]+" "+sys.argv[5])
	if sys.argv[2].upper() == '-P':
		print str(sys.argv[3])
		protocol = str(sys.argv[3])
	if sys.argv[4].upper() == '-N':
		print str(sys.argv[5])
		nxos = str(sys.argv[5])
	else:
		usage()
		exit(0)

#elif n == 6 and sys.argv[5] != 'SHOWLOG':
#	print ("Protocol: " + sys.argv[2]+" Name: "+sys.argv[3]+" NXOS: "+sys.argv[4]+" Version: "+sys.argv[5])
#	protocol = str(sys.argv[3])
#	nxos = str(sys.argv[5])

elif n == 7:
	print ("Protocol: " + sys.argv[2]+" Name: "+sys.argv[3]+" NXOS: "+sys.argv[4]+" Version: "+sys.argv[5]+" "+sys.argv[6])
	protocol = str(sys.argv[3])
	nxos = str(sys.argv[5])

else:
	print n
	usage()
	exit(0)
   
'''
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
else:
   usage()
   exit(0)
if len(sys.argv) > 2:
   if sys.argv[1].upper() == "SHOWLOG":
      show = "SHOWLOG"
   if sys.argv[2].upper() == "SHOWLOG":
      show = "SHOWLOG"
'''

# In case /var/log/messages got deleted, this ensures it is there
# cleanMessageLog   "shutil.move" command can do this.
CSI="\x1B["
LOG_NUM = 0
'''
LOG_MESSAGE_FILE = "/var/log/messages"
SENSORS_CONF_FILE = "/etc/sensors.d/sensors.conf"
SENSORS_CONF_FILE_BAK = "/etc/sensors.d/sensors.conf.bak"
TMP_SENSORS_CONF_FILE = "/tmp/sensors.conf"
TMP_SENSORS_DATA = "/tmp/sensors.data"
TEMP_SENSOR = "temp"
TEMP_SET = "set "
TEMP_MAX = "_max"
'''

def passit() :
    print CSI+"30;42m" +"PASS"+CSI+"0m"

def failit() :
    print CSI+"30;41m" +"FAIL"+CSI+"0m"
'''
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
'''
def Test_0025_1(arg):
	print ("*********************************************")
	print ("*         conv_TEST0025.1.py                 ")
	print ("*********************************************")
	print ("*   using  "+arg+" option                   *")
	print ("*********************************************")


	# Configuration variables which can be changed to give 
	# different test combinations with different networks
	DHCP_IPV4 = '//10.6.54.61'
	DHCP_IPV6 = '//[2001:192:10:1::85]//'
	TFTP_NET  = '//172.19.211.47//'
	LOCAL_NET = '172.19.211.47'
	A_PATH    = '/auto/n3keagleinteg/daily_build/eagle_integ/nexus/'
	B_PATH    = '/src/build/images/final/n3000-uk9'
	C_PATH    = 'n3000-uk9'
	ISAN      = '6.0.2.U7.0.'
	KICK      = 'kickstart.6.0.2.U7.0.'
	    
	if protocol == 'IPV4' :
		#os.system('cp ' + A_PATH + nxos + B_PATH + '-' + KICK + nxos + '.bin /users/miktsai/www')
		#os.system('cp ' + A_PATH + nxos + B_PATH + '.' + ISAN + nxos + '.bin /users/miktsai/www')
		os.system('cp /ws/rsangle-sjc/shared/dublin_mr.1 /users/miktsai/www')
# Access testbed_db to get data for connection
	f_TB = open("/ws/rsangle-sjc/eos/bsp/scripts/testbed_db","r")
	print f_TB
	flds = []
	for line in f_TB.readlines() :
		#print(line)
		if line.find(switch) >= 0 :
		   flds = line.split(' ')
	print(flds[0])
	print(flds[1])
	print(flds[2]) 
	id=pexpect.spawn("telnet "+flds[1]+" "+flds[2]) 
	#    id=pexpect.spawn("telnet 172.27.244.253 6053") 
	logout = file('message.log','w')
	id.logfile = logout
	if logs == "SHOWLOG" :
	   id.logfile=sys.stdout
	if id == 0:
	   print("Connection refused, leaving.")
	   id.kill(0)
	else:
	   id.expect("Escape character")
	   id.sendline("\r")
	   try:
		  id.expect('root@n3000:/#')
	   except:
		  print("Unrecognized prompt, leaving.")
		  id.kill(1)
		  exit()
	   '''id.sendline("uname -a")
	   print (id.readline())

	   try:
		  index=id.expect(["3.14.29ltsi-yocto-standard",pexpect.EOF,pexpect.TIMEOUT])
	   except:
		  print "Unexpected kernel version, FAIL"
		  failit()
		  id.kill(1)
		  exit()
		'''	

	#Now in BSP box via TELNET ************************************
	#cleanMessageLog()
	print ("Switch to root directory")
	id.sendline("cd /")
	if protocol == "LOCAL":
	   print ("****** Create license if LOCAL **********")
	   id.sendline("rm good.lic")
	   s_n = ''
	   id.sendline("pfm_util -d")
	   id.expect("S/N\s+:\s*(.*?)\r\n.*")
	   s_n = id.match.groups(1)
	   id.sendline("echo HOSTIDS/N    :  " + s_n[0] + " > good.lic")
	   id.sendline("cat good.lic")
	   id.sendline("pwd")



	print ("****** good good good ******")
	if protocol == 'IPV4' :
		print "Reached IPv4"
		command='nxos-migration-tool -s http://wwwin-people.cisco.com/miktsai/' + C_PATH + '.' + ISAN + nxos + '.bin' + ' -k http://wwwin-people.cisco.com/miktsai/' + C_PATH + '-' + KICK + nxos + '.bin' + ' -l http://wwwin-people.cisco.com/miktsai/' + switch + '.lic\r'
		print "Command: " + command
	'''elif protocol == 'IPV6' :
	  command='nxos-migration-tool -s http:'+DHCP_IPV6 + A_PATH+'.'+ ISAN +' -k http:'+ DHCP_IPV6+ A_PATH+'.'+ KICK +' -l http:'+ DHCP_IPV6 +'pxe/'+ LICENSE
	elif protocol == 'TFTP' :
	  command='nxos-migration-tool -s tftp:'+TFTP_NET + B_PATH+'/'+ C_PATH +'.'+ ISAN +' -k tftp:'+ TFTP_NET + B_PATH+'/'+C_PATH+'.'+ KICK +' -l tftp:'+ TFTP_NET + B_PATH+'/'+ LICENSE
	elif protocol == 'LOCAL' :
	  index=-1
	  id.sendline("cd /") 
	  id.sendline("scp cisco@"+LOCAL_NET+":/"+B_PATH+"/"+C_PATH+"."+ISAN+" .")
	  index=id.expect(["yes/no",pexpect.EOF,pexpect.TIMEOUT])
	  if index == 0 :
		 id.sendline("yes")
	  id.expect(["[pP]assword:",pexpect.EOF,pexpect.TIMEOUT],timeout=100)
	  id.sendline("devtest-")
	  time.sleep(10)
	  id.sendline("scp cisco@"+LOCAL_NET+":/"+B_PATH+"/"+C_PATH+"."+KICK+" .")
	  index=-1
	  index=id.expect(["yes/no",pexpect.EOF,pexpect.TIMEOUT])
	  if index == 0 :
		 id.sendline("yes")
	  id.expect(["[pP]assword:",pexpect.EOF,pexpect.TIMEOUT],timeout=100)
	  id.sendline("devtest-")
	  time.sleep(10)
	  command='nxos-migration-tool -s '+C_PATH+'.'+ISAN+' -k '+C_PATH+'.'+KICK+' -l '+LICENSE
	else :
	  usage()
	  exit(0)   
	  '''
	print command
	id.sendline(command)
	time.sleep(10)	
	'''try:
	   print("Tool invoked, messed up here?")
	   print (id.readline())
	   id.expect("Starting Cisco Nexus migration process. All disk contents will be erased.")
	except:
	   print "Tool not invoked correctly, FAIL"
	   failit()
	   id.kill(1)
	   exit()'''
	try:
	   print (id.readline())
	   index = id.expect("Do you want to continue? (y/n) :")
	except:
	   print "Tool did not ask for confirmation, FAIL"
	   failit()
	   id.kill(1)
	   exit()
	id.sendline("y")
	try:
	   index = id.expect(["Reboot Now",pexpect.EOF,pexpect.TIMEOUT],timeout=3000)
	except:
	   print("Migration tool failed, Test FAIL")
	   failit()
	   id.kill(1)
	   exit()
	id.sendline('\n')
	#Abort Power On Auto Provisioning and continue with normal setup ?(yes/no)[n]:
	print("*********at Linux ready to REBOOT **************")
	id.sendline("reboot")
	index = -1
	index=id.expect(['Power On Auto Provisioning',pexpect.EOF,pexpect.TIMEOUT],timeout=3000)
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
	index=id.expect(["BIOS:      version",pexpect.EOF,pexpect.TIMEOUT])
	if index >= 0 :
	   passit()
	   print("We should now be in NXOS ready to reload")
	   id.sendline(" ")   # Pass by "--More--"
	   id.sendline("reload")
	else :
	   failit()
	index = -1
	index=id.expect(["Do you want to continue\? \(y\/n\) [n] ",pexpect.EOF,pexpect.TIMEOUT])
	if index >= 0 :
	   id.sendline("y")
	index = -1
	print ("TAB and EFI Network")
	index=id.expect(["TAB.*",pexpect.EOF,pexpect.TIMEOUT])
	if index >= 0 :
	   id.send("\t")       # Tab in less than 5 seconds.
	   id.send("Ctrl+I")   # Tab in less than 5 seconds.
	index = -1
	index=id.expect(["EFI Network",pexpect.EOF,pexpect.TIMEOUT]) 
	if index >=0 :
	   id.send("3")
	print("Embedded ONIE")
	index=id.expect(["GNU GRUB",pexpect.EOF,pexpect.TIMEOUT],timeout=2000)
	if index >=0 :
	   id.sendline("v")     #Uses "v" as a down arrow
	   id.sendline("\r\n")  #Select embed ONIE
	#Wait a long time for defaults to bring us back to BSPa
	index=id.expect(["n3000 login:",pexpect.EOF,pexpect.TIMEOUT],timeout=3000)
	if index >=0 :
	   id.sendline("root")  #If successful, we are back to BSP
	index=id.expect(["root@n3000:.#",pexpect.EOF,pexpect.TIMEOUT])
	if index >=0 :
	   id.sendcontrol(']')
	   id.sendline('d')
	   print("We are done, so kill the Telnet connection.")
	   print("Option = "+arg)
	   print(CSI+"30;42m"+"###########################################"+CSI+"0m")
	   print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
	   print(CSI+"30;42m"+"#    N X O S   M I G R A T I O N   I S    #"+CSI+"0m")
	   print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
	   print(CSI+"30;42m"+"#         C O M P L E T E ! ! !           #"+CSI+"0m")
	   print(CSI+"30;42m"+"#                                         #"+CSI+"0m")
	   print(CSI+"30;42m"+"###########################################"+CSI+"0m")
	   id.kill(0)



#############################################################
# Main Entrance
arg = sys.argv[1].upper()
print sys.argv[1] + sys.argv[2] + sys.argv[3] + sys.argv[4]
Test_0025_1(arg)         #  Telnet

# End of test/script
###########################################################
