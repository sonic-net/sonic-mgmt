#!/usr/bin/env python
import sys
sys.path.insert(0,'/usr/local/lib/python3.6/dist-packages/')
sys.path.insert(0,'/usr/lib/python3/dist-packages/')
import requests
import argparse
import time
import getpass
import json
import os
import requests
import uuid
import subprocess
import re
import random
import time
import datetime

def parse_arguments():
    """Parse the command line arguments"""
    try:
        parser = argparse.ArgumentParser(description='Reserve/Release devices in laas-robot-lab.cisco.com server')
        subparsers = parser.add_subparsers(help='Sub-commands')
        reserve_parser = subparsers.add_parser('reserve', help=('reserve devices'))
        reserve_parser.add_argument('-D','--domain', action='store', help='Domain name where devices are to be reserved')
        reserve_parser.add_argument('-u','--user', action='store', help='device will be reserved on given user name')
        reserve_parser.add_argument('-x','--device', action='store', help='device to be reserved')
        reserve_parser.add_argument('-p','--profile', action='store', help='profile to be reserved')
        reserve_parser.add_argument('-n','--num', action='store', help='no. of devices to be reserved in a given profile')
        reserve_parser.add_argument('-d','--duration', action='store', help='device reservation time')
        reserve_parser.add_argument('-t','--topology_id', action='store', help='topology id')
        reserve_parser.set_defaults(which='reserve')
        reserve_parser = subparsers.add_parser('release', help=('release devices'))
        reserve_parser.add_argument('-D','--domain', action='store', help='Domain name where devices are to be released')
        reserve_parser.set_defaults(which='release')
        #reserve_parser.add_argument('-t','--topology_id', action='store', help='topology id')
        reserve_parser.add_argument('-u','--uuid', action='store', help='uuid')
        return parser.parse_args()
    except argparse.ArgumentError as err:
        print str(err)
        sys.exit(1)

def validate_domain(domain_name):
  if not domain_name:
      print "Domain name cant be empty! Please enter. "
      return False
  else:
      domain_name = domain_name.strip()
      #Dont accept domain name thats just only empty spaces.
      if not domain_name:
         print "Domain name cant be empty! Please given non-empty name for the domain."
         return False 
  return True

def check_device_or_profile(device,profile,num):
    if all(v is None for v in [device, profile]):
      print "Either enter device name {-x} or profile name {-p} to be reserved"
      return False
    if device and profile:
      print "Either device or profile to be entered, not both" 
      return False
    if profile: 
      if not num:
         print "No. of devices to be entered, along with profile parameter, please verify"
         return False 
    return True
 
def validate_args(domain, device, profile, num, user):
    if args.device == None:
       return True

    #check if domain name is entered or not 
    if not validate_domain(domain): return False 
    #check if device or profile name is entered, if profile check number of devices too
    if not check_device_or_profile(device,profile,num): return False
    if not user:
        print "Please enter Username who owns the reservation"
        return False
    return True

def release(topology_id):
    if topology_id == None:
        toponame = 'iwantopo_' + str(time.time()) 
    else :
        toponame = 'iwantopo_' + topology_id 

    print ("Topology is " + toponame)
    print ("vmcloud release -t " + str(toponame))
    os.system(" /auto/iol/vmcloud/bin/vmcloud release -t " + toponame)

def release_2(uuid):
    cmd1 = "http://laas-robot-lab.cisco.com:9080/vmcloud/v1/topologies/" + str(uuid) + "?release=true"
    r1 = requests.delete(cmd1, auth=(getpass.getuser(),''))
    print (cmd1)
    print (r1)
    print (r1.text)

def get_second(time1):
    datepattern = re.compile("\d{2}:\d{2}:\d{2}")
    matcher = datepattern.search(time1)

    if matcher != None:
        y = matcher.group(0)
        #print (y) 
        x = datetime.datetime.strptime(y,'%H:%M:%S')
        cur_t = (x.second + x.minute*60 + x.hour*3600)
        return cur_t
    else:
        return None

def get_delay(tb_time):
    tb_time = get_second(tb_time)

    cur_output = subprocess.check_output(" date -u", shell=True)
    cur_time = get_second(cur_output)

    #print (tb_time)
    #print (cur_time)
    if tb_time == None or cur_time == None:
        return None

    if tb_time > cur_time :
       tb_delay = tb_time - cur_time
    elif tb_time + 240 > cur_time :
       tb_delay = 240
    else :
       tb_delay = 86400 - cur_time + tb_time

    return tb_delay

def get_device1(cmd, find_free):
    pattern = "th.-[0-9]"
    pattern2 = "\"Free\""
    #print (cmd)
    r = requests.get(cmd, auth=(getpass.getuser(),''))
    #print (r.text)
    j = 0
    device = None
    m = re.findall(pattern, r.text)
    for m1 in m:
        if find_free == True :
            cmd2 = "http://laas-robot-lab.cisco.com:9060/laas-ng/v2/nodes?fields=status&name=" + m1
            r2 = requests.get(cmd2, auth=(getpass.getuser(),''))
            m2 = re.search(pattern2, r2.text)
            #print (cmd2)
            #print (r2.text)
            #print (m1)
            #print (m2)
            if m2 != None:
                return m1

        r1 = random.randint(0, j)
        j = j + 1
        if r1 == 0:
           device = m1
    return device

# this function will first look for a free device randomly. if none available
# it will look for any device randomly
def get_device(domain):
    cmd = "http://laas-robot-lab.cisco.com:9080/vmcloud/v1/profiles?domain=" + str(domain)
    device = get_device1(cmd, True)
    if device == None:
        cmd = "http://laas-robot-lab.cisco.com:9080/vmcloud/v1/profiles?domain=" + str(domain)
        device = get_device1(cmd, False)
    return device

def generate_topo_file(device, profile, num):
    ts = time.time()
    filename = 'dev_'+ str(ts)+'.virl'
    file = open(str(filename),'w')
    file.write("<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n")    
    file.write('<topology xmlns="http://www.cisco.com/VIRL" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" schemaVersion="0.6" xsi:schemaLocation="http://www.cisco.com/VIRL http://cide.cisco.com/vmmaestro/schema/virl.xsd">\n')
    if device != None:
       #if single device reservation
       file.write('<node name="Device1" type="SIMPLE" location="-71,129" subtype="' + str(device) + '" vmImage=""/></topology>\n')
    else:
       count = 1 
       while (count <= int(num)):
          #if multiple reservation
          file.write('<node name="Device' + str(count) + '" type="SIMPLE" location="-71,129" subtype="' + str(profile) + '" vmImage=""/>') 
          count = count + 1
       file.write('</topology>\n') 
    file.close() 
    return filename

def get_uuid(input):
    uuid4hex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    res = uuid4hex.search(input)
    print(input)
    if res != None:
        #print(res)
        #print (res.group(0))
        return res.group(0)
    else:
        return None
    

def reserve(domain, device, user, duration, topology_id):
    if device == None:
       device = get_device(domain)
       print ("Device is " + device)

    if device == None:
       exit(1)

    virlfile = generate_topo_file(device, None, 1) 

    if topology_id == None:
        toponame = 'iwantopo_' + str(time.time()) 
    else :
        toponame = 'iwantopo_' + topology_id 

    print ("Topology is " + toponame)

    """Duration in minutes """
    if not args.duration: duration = 480

    f = open(virlfile, 'r')
    virlfile_content = f.read()
    virl = { 'virl': (virlfile, virlfile_content, 'application/octet-stream') }
    cmd1 = "http://laas-robot-lab.cisco.com:9080/vmcloud/v1/topologies?name=" + str(toponame) + "&mode=reserve&force=false&duration=" + str(duration) + "&case=fixed&async=true" + "&domain=" + str(domain)
    #print (virl)
    #print (cmd1)
    r1 = requests.post(cmd1, auth=(getpass.getuser(),''), files = virl)
    print(r1)
    print(r1.text)

    cmd1 = 'http://laas-robot-lab.cisco.com:9080/vmcloud/v1/topologies?allusers=false'
    r1 = requests.get(cmd1, auth=(getpass.getuser(),''))
    print(r1)
    print(r1.text)

    tb_delay = get_delay(r1.text)
    if tb_delay == None:
        delete_topofile(virlfile) 
        sys.exit()

    print "Sleep ", tb_delay
    time.sleep(tb_delay)

    uuid = get_uuid(r1.text)
    print "UUID: ", uuid

    #if uuid != None:
       #release_2(uuid)

    delete_topofile(virlfile) 

def delete_topofile(virlfile): 
    os.unlink(virlfile)

if __name__ == "__main__":
    args = parse_arguments()
#    r = requests.get('http://laas-robot-lab.cisco.com:9060/laas-ng/v1/login')
#    print (r.text)
    if (args.which == 'release'):
        #if args.topology_id != None:
        #    release(args.topology_id)

        if args.uuid != None:
            release_2(args.uuid)
    if (args.which == 'reserve'):
       #Validate entered arguments
       res = validate_args(args.domain, args.device, args.profile, args.num, args.user)
       if not res: exit(1)
       reserve(args.domain, args.device, args.user, args.duration, args.topology_id)

