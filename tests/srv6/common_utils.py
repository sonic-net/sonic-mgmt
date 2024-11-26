import subprocess
import logging
import getpass

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
        cmd1 = "ssh  -q -o \"UserKnownHostsFile=/dev/null\" -o \"StrictHostKeyChecking=no\" "
        cmd2 = "{}@{} \"{}\"".format(user, hostip, cmd)
        cmd = cmd1 + cmd2
    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True
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
        cmd = (
            "tcpdump -i {} -w {}/{}_{}.pcap > /tmp/{}_{}.log 2>&1 &"
            .format(intf, file_loc, prefix, intf, prefix, intf)
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
