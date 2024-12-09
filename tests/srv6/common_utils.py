import os
import subprocess
import logging
import getpass
import json

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.interface_utils import check_interface_status_of_up_ports

logger = logging.getLogger(__name__)

#
# Flags used at run time
#
run_inside_docker = False
debug_flag = False


def set_debug_flag(flag):
    global debug_flag
    debug_flag = flag


def get_debug_flag():
    return debug_flag


def set_run_inside_docker(flag):
    global run_inside_docker
    run_inside_docker = flag


def get_run_inside_docker():
    global run_inside_docker
    return run_inside_docker


#
# This is the IP to accessing host from sonic-mgmt
#
def get_hostip_and_user():
    hostip, hostuser = "172.17.0.1", getpass.getuser()
    return hostip, hostuser


#
# Debug print util function for printing out debug information
#
def debug_print(msg, force=False):
    if not get_debug_flag() and not force:
        return
    logger.info(msg)
    print(msg)


#
# a util function to run command. add ssh if it is running inside sonic-mgmt docker.
#
def run_command_with_return(cmd, force=False):
    if get_run_inside_docker():
        # add host access
        hostip, user = get_hostip_and_user()
        cmd = 'ssh  -q -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" {}@{} "{}"'.format(
            user, hostip, cmd
        )
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    output, stderr = process.communicate()
    if stderr != "" and stderr is not None:
        # It is an error, use force print
        debug_print("{} : get error {}".format(cmd, stderr), force=True)

    debug_print("cmd : {}, stderr : {}, output : {}".format(cmd, stderr, output), force)
    return output, stderr


#
# Goal is to run the following command to set up tcpdump
# For example
# ssh ubuntu@172.17.0.1 "nohup tcpdump -i VM0100-t0 -w /tmp/Vm0100-t0.pcap > /tmp/tcpdump.log 2>&1 &"
#
def enable_tcpdump(intf_list, file_loc, prefix, use_docker=False, set_debug=False):
    # Enable flags baased on input flags
    set_run_inside_docker(use_docker)
    set_debug_flag(set_debug)
    for intf in intf_list:
        cmd = "tcpdump -i {} -w {}/{}_{}.pcap > /tmp/{}_{}.log 2>&1 &".format(
            intf, file_loc, prefix, intf, prefix, intf
        )
        if get_run_inside_docker():
            cmd = "nohup {}".format(cmd)
        debug_print("Run {}".format(cmd), force=True)
        run_command_with_return(cmd)
        run_command_with_return("ps aux | grep tcpdump", force=True)
    # Disable flags
    set_debug_flag(False)
    set_run_inside_docker(False)


#
# Remove all existing tcpdump sessions
#
def disable_tcpdump(use_docker=False, set_debug=False):
    set_run_inside_docker(use_docker)
    run_command_with_return("pkill tcpdump")
    set_run_inside_docker(False)


#
# Helper funct to remove files at the remote host
#
def remove_files(vmhost, files):
    cmd = "ls {}".format(files)
    res = vmhost.shell(cmd, module_ignore_errors=True)["stdout_lines"]
    for f in res:
        logger.debug("Removing {}".format(f))
        cmd = "sudo rm -f {}".format(f)
        vmhost.shell(cmd, module_ignore_errors=True)


#
# Initialize the testbed's configurations
#
def setup_config_for_testbed(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, test_vm_names, filepath
):

    curr_path = os.getcwd()
    logger.info("Set up the testbed")

    """
    Copy over predefined configurations to all 4 test VM nodes to set up 5 nodes topology
    """
    for vm in test_vm_names:
        json_file = curr_path + "/srv6/{}/{}.json".format(filepath, vm)
        vmhost = nbrhosts[vm]["host"]
        vmhost.copy(src=json_file, dest="/tmp")
        vmhost.command(
            "sudo cp /etc/sonic/config_db.json /etc/sonic/config_db.json.back"
        )
        vmhost.command("sudo config reload /tmp/{}.json -y".format(vm))

    for vm in test_vm_names:
        vmhost = nbrhosts[vm]["host"]
        pytest_assert(
            wait_until(1200, 20, 0, check_interface_status_of_up_ports, vmhost),
            "Not all ports that are admin up on are operationally up on {}".format(vm),
        )
    return True


def check_bgp_neighbor_func(nbrhost, neighbor, state):
    # Idle/Established
    cmd = "vtysh -c 'show bgp neighbors {} json'".format(neighbor)
    try:
        text = nbrhost.command(cmd)["stdout"]
    except Exception as e:
        logger.debug("The command is nil: exception {}".format(e))
        return False

    if not text:
        return False
    json_str_cleaned = text.strip()
    json_data = json.loads(json_str_cleaned)
    bgpState = json_data[neighbor]["bgpState"]
    if bgpState == state:
        return True
    return False
