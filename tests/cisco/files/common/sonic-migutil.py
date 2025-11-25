#! /usr/bin/python3

import fnmatch
import os
import sys
import logging as log
import socket
import fcntl
import struct
import subprocess
import time
from subprocess import check_output
import signal
import argparse

XR_TFTP_PATH = "/www/pages"
onie_image  = "Unknown"
sonic_image = "Unknown"
headless_file_enable = "/usr/local/etc/reset_board.sh"
headless_file_disable = "/usr/local/etc/reset_board.sh.disable"
sonic_dhcp_conf = "/usr/local/etc/sonic.dhcp.conf"

def sonic_image_discovery():
    """
    This API locates ONIE and SONiC images
    at XR TFTP path
    """
    global onie_image
    global sonic_image
    log.info("Discover SONiC images ...")
    for file in os.listdir(XR_TFTP_PATH):
        if fnmatch.fnmatch(file, '*.pxe'):
           onie_image = os.path.join(XR_TFTP_PATH, file)
        if fnmatch.fnmatch(file, '*.bin'):
           sonic_image = os.path.join(XR_TFTP_PATH, file)

    if not os.path.isfile(onie_image):
        log.error("ONIE image not found at:{}".format(XR_TFTP_PATH))
        sys.exit(1)

    if not os.path.isfile(sonic_image):
        log.error("SONiC image not found at:{}".format(XR_TFTP_PATH))
        sys.exit(1)

    log.info("Found ONIE image: {}".format(onie_image))
    log.info("Found SONiC image: {}".format(sonic_image))

def cleanup():
    """
    Remove SONiC and ONIE image from tftp path
    """
    if os.path.isfile(onie_image):
        os.remove(onie_image)

    if os.path.isfile(sonic_image):
        os.remove(sonic_image)

def enable_headless_reload():
    """
    XR RP depends on XR headless feature.
    That is when RP goes down XR shelfmanager brings LC also down
    """
    log.info("Enable headless reload")
    try:
       os.rename(headless_file_disable, headless_file_enable)
    except(FileNotFoundError):
       log.info("{}: File not found".format(headless_file_disable))

def disable_headless_reload():
    """
    Disable LC going down when RP reloads.
    """
    log.info("Disable headless reload")
    try:
       os.rename(headless_file_enable, headless_file_disable)
    except(FileNotFoundError):
       log.info("{}: File not found".format(headless_file_enable))

def create_dhcp_conf(ip):
    """
    Create SONiC dhcp configuration for RP ipxe and ONIE discovery
    can download image from internal DHCP service
    """
    log.info("Create SONiC dhcp config for ip = {}".format(ip))
    filename = sonic_dhcp_conf
    with  open(filename, 'w') as myfile:
          myfile.write("default-lease-time 600;\n")
          myfile.write("max-lease-time 7200;\n")
          myfile.write("ddns-update-style none;\n")
          myfile.write("log-facility local7;\n")
          myfile.write("subnet 1.0.0.0 netmask 255.255.255.0 {\n")
          myfile.write("    range 1.0.0.1 1.0.0.50;\n")
          myfile.write("    next-server {};\n".format(ip))
          myfile.write("}\n")
          myfile.write("host rp_pxe {\n")
          myfile.write("    hardware ethernet 00:00:01:1e:00:00;\n")
          myfile.write("    fixed-address 1.0.0.33;\n")
          myfile.write("    if exists user-class and option user-class = \"iPXE\" {\n")
          myfile.write("    filename = \"http://{}:80/{}\";\n".format(ip, os.path.basename(onie_image)))
          myfile.write("}}\n")
          myfile.write("host rp_onie {\n")
          myfile.write("    hardware ethernet 00:00:01:1e:00:00;\n")
          myfile.write("    fixed-address 1.0.0.33;\n")
          myfile.write("    option default-url = \"http://{}/{}\";\n".format(ip, os.path.basename(sonic_image)))
          myfile.write("}\n")

    log.info("DHCP config file: {} ...created".format(filename))

def get_eobc_ip_address():
    """
    Get XR LC's eobc channel ip address
    """
    if_name="eth-vf1"
    address = os.popen('ip addr show eth-vf1 | \
                        grep "\<inet\>" | awk \'{ print $2 }\' | \
                        awk -F "/" \'{ print $1 }\'').read().strip()
    parts = address.split(".")
    if len(parts) != 4:
        log.error("Invalid ip address={} for interface={}".format(address, if_name))
        sys.exit(1)
    for item in parts:
        if not 0 <= int(item) <= 255:
            log.error("Invalid content in ip address={} for interface={}".format(address, if_name))
            sys.exit(1)
    log.info("Found EOBC ip address: {}".format(address))
    return address

def is_process_running(proc):
   """
   Check process is running by process name
   """
   ps = subprocess.Popen("ps -ef", shell=True, stdout=subprocess.PIPE)
   ps_pid = ps.pid
   output = ps.stdout.read().decode()
   ps.stdout.close()
   ps.wait()

   for line in output.split("\n"):
      if line != "" and line != None:
        fields = line.split()
        pid = fields[0]
        pname = fields[7]

        if proc in pname:
           return True
   return False

def star_dhcp_service():
    """
    Start DHCP service
    """
    os.system("/usr/sbin/dhcpd -cf {} -f eth-vf1 start >& /dev/null &".format(sonic_dhcp_conf))
    time.sleep(10)
    if not is_process_running("dhcpd"):
        log.error("Failed to start DHCP process")
        sys.exit(1)
    log.info("DHCP process started ...")

def get_process_id(pname):
    """
    Get PID by process name
    """
    try:
       pid = check_output(["pidof", pname]).decode().split('\n')
       proc_id = pid[0]
    except:
       log.info("Unexpected error to get process id: {}".format(sys.exc_info()))
       proc_id = -1
    return proc_id

def stop_process_by_pid(pid):
    """
    Send SIGTERM to process by PID
    """
    log.info("Stopping process PID:{}".format(pid))
    os.kill(int(pid), signal.SIGTERM)
    os.remove(sonic_dhcp_conf)

def start_reimage_service():
    """
    Start XR LC reimage service
    1. Locate ONIE and SONiC image
    2. Start the DHCP service with sonic migration DHCP config file
    3. Disable headless reboot
    """
    # Discover SONiC and ONIE image
    sonic_image_discovery()

    #Start DHCP service
    if not os.path.isfile(sonic_dhcp_conf):
        addr = get_eobc_ip_address()
        create_dhcp_conf(addr)

    if not is_process_running("dhcpd"):
        log.info("start DHCPD process")
        star_dhcp_service()

    #Disable headless reload
    disable_headless_reload()

def stop_reimage_service():
    """
    Stop XR LC SONiC reimage service
    1. Stop DHCP service
    2. Enable headless reboot for XR
    """
    # Enable headless reload
    enable_headless_reload()

    #Stop DHCP service
    id = get_process_id("dhcpd")
    if id != -1:
        stop_process_by_pid(id)
    else:
        log.info("DHCP server is not running")

def verify_reimage_service():
    """
    Verify readiness of SONiC reimage service in LC XR
    """
    #Check valid images are present
    sonic_image_discovery()

    #Check headless is disabled
    if os.path.isfile(headless_file_enable):
       log.error("Headless reload setup ... not ok")
    else:
       log.info("Headless reload setup ... ok")

    #Check DHCP conf file exist
    if not os.path.isfile(sonic_dhcp_conf):
       log.error("DHCP config setup ... not ok")
    else:
       log.info("DHCP config setup ... ok")

    #Check DHCP service is running
    if not is_process_running("dhcpd"):
       log.error("DHCP daemon status ... not ok")
    else:
       log.info("DHCP daemon status ... ok")

def is_rp():
    """
    Find XR card is RP
    """
    with open("/proc/cmdline") as f:
        data = f.read()

    if "boardtype=RP" in data:
        return True
    else:
        return False

def run_cmd(cmd):
    log.debug("running: {}".format(cmd))
    output_stream = os.popen(cmd)
    op = output_stream.read()
    output_stream.close()
    return op

def rp_config_to_internal_ipxe():
    """
    Configure scratch register for RP reload to internal ipxe
    """
    log.info("Configure reload to internal ipxe")
    run_cmd("pcimemwrite 0xA2401100 4 0x00000004")
    op = run_cmd("pcimemread 0xA2401100 4 | grep 'a2401100 :'| awk '{print $3}'")
    if not "00000004" in op:
        log.error("RP internal ipxe configuration failed")
    else:
        log.info("Internal ipxe config done")

def get_pd_slot(pi_slot):
    pd_slot = [ 2, 4, 6, 8, 10, 12, 14, 16 ]
    return pd_slot[pi_slot] 

def lc_reload_to_internal_ipxe(pi_slot):
    '''
    Reload slot is physical slot
    '''
    log.info("Reloading LC{} to internal ipxe".format(pi_slot))
    slot = get_pd_slot(pi_slot)
    run_cmd("echo IPXE > /sys/bus/platform/devices/xil-lc.{}/bios/boot_mode".format(slot))
    time.sleep(1)
    run_cmd("echo 0x8 > /sys/bus/platform/devices/xil-lc.{}/cfg7".format(slot))
    time.sleep(1)
    run_cmd("echo 0x80 > /sys/bus/platform/devices/xil-lc.{}/cfg7".format(slot))
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Migration tool kit",
                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--start", action='store_true', help="start sonic reimage service")
    parser.add_argument("--stop", action='store_true', help="stop sonic reimage service")
    parser.add_argument("--verify", action='store_true', help="Verify reimage service rediness")
    parser.add_argument("--rpconfigipxe", action='store_true', help="RP reload to ipxe")
    parser.add_argument("--lcipxereload", help="LC reload to ipxe")

    args = parser.parse_args()

    # Setup logging
    FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
    log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)

    if args.start:
        if is_rp():
            log.error("This action not supported")
            sys.exit(1)
        start_reimage_service()

    if args.stop:
        if is_rp():
            log.error("This action not supported")
            sys.exit(1)
        stop_reimage_service()

    if args.verify:
        if is_rp():
            log.error("This action not supported")
            sys.exit(1)
        verify_reimage_service()

    if args.rpconfigipxe:
        if not is_rp():
            log.error("This action not supported")
            sys.exit(1)
        rp_config_to_internal_ipxe()

    # This command runs on SONiC
    if args.lcipxereload:
        lc_reload_to_internal_ipxe(args.lcipxereload)
