#!/usr/bin/env python

import os, sys, re, math, time, shutil
import pexpect, string, commands
###########################################################

global prompt, logs, switch, switch_type, id

n = len(sys.argv)

logs = "SHOWLOG"
#switch = "n3172pq-1"
switch = "c3172tq-10gt-2"
#switch = "c3132qx-3"
#switch = 'c3064pq-x-2'
#switch = "n3048tp-3"
#BSP, BSP login and loader are OK. Verify other prompts
prompt = ['root@n3000', 'n3000 login:', 'loader>', 'ONIE:/', 'ONIE-RECOVERY:/', 'iPXE>']

#Find if we are using 30xx or 31xx
def find_switch_type():
	global switch_type
	if '30' in switch:
		print "We are working on a 30xx - " + switch
		switch_type = 0
	else:
		print "We are working on a 31xx - " + switch
		switch_type = 1

def prep_BSP_image():
	command = "ls -rt /auto/WindRiver/caches/yocto/dizzy/nightly/latest/onie-image-fatty-n3000-*.bin | tail -1"
	print command
	output = commands.getoutput(command)
	#print output

	command = "rm -rf /users/miktsai/www/" + switch + ".bin"
	os.system(command)
	
	command = "cp " + output + " /users/miktsai/www/" + switch + ".bin"
	os.system(command)

def F2_Boot_menu():
	#Go 3 times to the right
	for i in range(0,3):
		id.send("\x1b[C")
		time.sleep(5)
    
    #Go 7 times down to reach Boot menu
	for i in range(0, 7):
		id.send("\x1b[B")
		time.sleep(5)
       
    #Hit Return to select Boot menu
	id.send('\r\n')
	time.sleep(5)

def F2_save_and_exit():
    #We need to save our changes and get out
    #Go 2 times to the right
    id.send("\x1b[C")
    time.sleep(5)
    id.send("\x1b[C")
    time.sleep(5)
    #Hit Return twice to save and exit
    id.send('\r\n')
    time.sleep(5)
    id.send('\r\n')
    time.sleep(5)
    
def pxe_ONIE_BSP():
	global id
	
	if switch_type == 1:
		index=id.expect(["TAB.*",pexpect.EOF,pexpect.TIMEOUT])
		if index >= 0 :
		   id.send("\t")       # Tab in less than 5 seconds.
		   id.send("Ctrl+I")   # Tab in less than 5 seconds.
		index = -1
		index=id.expect(["EFI Network",pexpect.EOF,pexpect.TIMEOUT]) 
		if index >=0 :
		   id.send("3")
	index=id.expect(["GNU GRUB",pexpect.EOF,pexpect.TIMEOUT],timeout=2000)
	if index >=0 :
	   id.sendline("v")     #Uses "v" as a down arrow
	   id.sendline("\r\n")  #Select embed ONIE
	print("Embedded ONIE")
	#Wait a long time for defaults to bring us back to BSPa
	index=id.expect(["n3000 login:",pexpect.EOF,pexpect.TIMEOUT],timeout=3000)
	if index >=0 :
	   id.sendline("root")  #If successful, we are back to BSP
	index=id.expect(["root@n3000:.#",pexpect.EOF,pexpect.TIMEOUT])
	if index >=0 :
	   id.sendcontrol(']')
	   id.sendline('d')
	   print("We are done, so kill the Telnet connection.")
	   id.kill(0)	

# When we see BSP
def reboot_30xx_bsp():
	global id
	print "30xx reboot sequence initiated"
	print "We saw BSP"	
	
	id.sendline("reboot")
	print ("Getting ready for F2")
	index=id.expect(["Press <DEL> or <F2>",pexpect.EOF,pexpect.TIMEOUT])
	if index >= 0 :
		id.send("\x1b2m")
		time.sleep(5)
    
	F2_Boot_menu()
	
	#Go up 4 times to highlight EFI Network
	for i in range(0, 4):
		id.send("\x1b[A")
		time.sleep(5)

	#Hit Return to select EFI Network
	id.send('\r\n')
	time.sleep(5)
    
	F2_save_and_exit()
	
	pxe_ONIE_BSP()

    
# When we see loader
def reboot_30xx_loader():
	global id
	print "30xx reboot sequence initiated"
	print "We saw loader"	
		
	id.sendline("reboot")
	print ("Getting ready for F2")    
	index=id.expect(["Press <DEL> or <F2>",pexpect.EOF,pexpect.TIMEOUT])
	if index >= 0 :
		id.send("\x1b2m")
		time.sleep(5)
    
	F2_Boot_menu()
	
    #Go down 2 times to highlight EFI Network
	id.send("\x1b[B")
	time.sleep(5)
	id.send("\x1b[B")
	time.sleep(5)
    
    #Hit Return to select EFI Network
	id.send('\r\n')
	time.sleep(5)
    
	F2_save_and_exit()
	
	pxe_ONIE_BSP()


# When we see ONIE
def reboot_30xx_ONIE():
	global id
	print "30xx reboot sequence initiated"
	print "We saw ONIE"	
		
	id.sendline("reboot")
	print ("Getting ready for F2")    
	index=id.expect(["Press <DEL> or <F2>",pexpect.EOF,pexpect.TIMEOUT])
	if index >= 0 :
		id.send("\x1b2m")
		time.sleep(5)

	F2_Boot_menu()

	#Go up 2 times to highlight EFI Network
	id.send("\x1b[A")
	time.sleep(5)
	id.send("\x1b[A")
	time.sleep(5)

	#Hit Return to select EFI Network
	id.send('\r\n')
	time.sleep(5)

	F2_save_and_exit()
	
	pxe_ONIE_BSP()

# When we see ONIE-RECOVERY
# ONIE-RECOVERY prompt is seen only when we are in PXE
def reboot_30xx_ONIE_recovery():
	global id
	print "30xx reboot sequence initiated"
	print "We saw ONIE"	
		
	id.sendline("reboot")
	#Do nothing 
	pxe_ONIE_BSP()
	
# When we see iPXE
def reboot_30xx_pxe():
	global id
	print "30xx reboot sequence initiated"
	print "We saw ONIE"	
		
	id.sendline("reboot")
    #Do nothing after this, we assume PXE is setup correctly
	pxe_ONIE_BSP()
	
def reboot_31xx():
	global id
	print "31xx reboot sequence initiated"
	print "Let's reboot, hit TAB and 3 and we're done"

	id.sendline("reboot")
	pxe_ONIE_BSP()


def clean():
	global switch_type, id
	f_TB = open("/ws/rsangle-sjc/eos/bsp/scripts/testbed_db","r")
	print f_TB
	flds = []
	for line in f_TB.readlines() :
		#print(line)
		if line.find(switch) >= 0 :
		   flds = line.split(' ')
	#print(flds[0])
	#print(flds[1])
	#print(flds[2]) 
	id=pexpect.spawn("telnet "+flds[1]+" "+flds[2]) 
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
	
	if switch_type == 0:
		#Power cycle the hell out of 30xx because it's so hard to deal with
		command = "ssh rsangle@171.68.248.90 '/ws/rsangle-sjc/csg-NXOS/bin/rreset " + switch + "'"
		print command
		os.system(command)
		index = id.expect (prompt, timeout=120)
		
	elif switch_type == 1:
		index = id.expect (prompt, timeout=5)
	
	#index = 0 --> BSP prompt
	if index == 0:
		print "We got BSP, let's reboot and boot desired image"
		
		if switch_type == 0:
			reboot_30xx_bsp()
		elif switch_type == 1:
			reboot_31xx()
			
	#index = 1 --> login: prompt
	elif index == 1:
		print "We need to login and then reboot"
		id.sendline("root")
		
		if switch_type == 0:
			reboot_30xx_bsp()
		elif switch_type == 1:
			reboot_31xx()
		
	#index = 2 --> loader> prompt
	elif index == 2:
		print "We are at loader, rebooting"
		if switch_type == 0:
			reboot_30xx_loader()
		elif switch_type == 1:
			reboot_31xx()
			
	#index = 3 --> ONIE
	elif index == 3:
		print "ONIE"
		if switch_type == 0:
			reboot_30xx_ONIE()
		elif switch_type == 1:
			reboot_31xx()

	#index = 4 --> ONIE-RECOVERY
	elif index == 4:
		print "ONIE-RECOVERY"
		if switch_type == 0:
			reboot_30xx_ONIE_recovery()
		elif switch_type == 1:
			reboot_31xx()
			
	#index = 5 --> PXE
	elif index == 5:
		print "Device is at PXE prompt"
		if switch_type == 0:
			reboot_30xx_pxe()
		elif switch_type == 1:
			reboot_31xx()

	#Looks like we have an unrecognized prompt, let's just power cycle the box
	else:
		if switch_type == 1:
			print "Looks like the box is hung, let's just power cycle it"
			command = "ssh rsangle@171.68.248.90 '/ws/rsangle-sjc/csg-NXOS/bin/rreset " + switch + "'"
			print command
			os.system(command)
			reboot_31xx()
		elif switch_type == 0:
			print "30xx is in a weird state, can't recover"

		 
###########################################################

find_switch_type()
prep_BSP_image()
clean()

###########################################################
