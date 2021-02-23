import logging
import time

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

def join_master(duthost, master_vip):
    """
    Joins DUT to Kubernetes master

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master

    If join fails, test will fail at the assertion to check_connected
    """
    logger.info("Joining DUT to Kubernetes master")
    dut_join_cmds = ['sudo config kube server disable on',
                     'sudo config kube server ip {}'.format(master_vip),
                     'sudo config kube server disable off']
    duthost.shell_cmds(cmds=dut_join_cmds)
    pytest_assert(poll_for_status_change(duthost, True),"DUT failed to successfully join Kubernetes master")
    

def make_vip_unreachable(duthost, master_vip):
    """
    Makes Kubernetes master VIP unreachable from SONiC DUT by configuring iptables rules. Cleans preexisting iptables rules for VIP. 

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master
    """
    logger.info("Making Kubernetes master VIP unreachable from DUT")
    clean_vip_iptables_rules(duthost, master_vip)
    duthost.shell('sudo iptables -A INPUT -s {} -j DROP'.format(master_vip))
    duthost.shell('sudo iptables -A OUTPUT -d {} -j DROP'.format(master_vip))


def make_vip_reachable(duthost, master_vip):
    """
    Makes Kubernetes master VIP reachable from SONiC DUT by removing any iptables rules associated with the VIP. 

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master
    """
    logger.info("Making Kubernetes master VIP reachable from DUT")
    clean_vip_iptables_rules(duthost, master_vip)


def clean_vip_iptables_rules(duthost, master_vip):
    """
    Removes all iptables rules associated with the VIP.

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master
    """
    iptables_rules = duthost.shell('sudo iptables -S | grep {} || true'.format(master_vip))["stdout_lines"]
    logger.info('iptables rules: {}'.format(iptables_rules))
    for line in iptables_rules:
        if line: 
            duthost.shell('sudo iptables -D {}'.format(line[2:]))


def check_connected(duthost):
    """
    Checks if the DUT already shows status 'connected' to Kubernetes master
    
    Args:
        duthost: DUT host object
    
    Returns:
        True if connected, False if not connected
    """
    kube_server_status = duthost.shell('show kube server')["stdout_lines"]
    logger.info("Kube server status: {}".format(kube_server_status))
    for line in kube_server_status:
        if line.startswith("KUBERNETES_MASTER SERVER connected"):
            return line.endswith("true")
    logger.info("Kubernetes server check_connected failed to check server status")


def poll_for_status_change(duthost, exp_status, poll_wait_secs=5, min_wait_time=20, max_wait_time=120):
    """
    Polls to see if kube server connected status updates as expected

    Args:
        duthost: DUT host object
        exp_status: expected server connected status once processes are synced
        poll_wait_secs: seconds between each server connected status poll. Default: 5 seconds
        min_wait_time: seconds before starting poll of server connected status. Default: 20 seconds
        max_wait_time: maximum amount of time to spend polling for status change. Default: 120 seconds

    Returns: 
        True if server connected status updates as expected by max_wait_time
        False if server connected status fails to update as expected by max_wait_time
    """
    time.sleep(min_wait_time)
    timeout_wait_secs = max_wait_time - min_wait_time
    while (timeout_wait_secs > 0):
       if (check_connected(duthost) == exp_status):
           logging.info("Time taken to update Kube server status: {} seconds".format(timeout_wait_secs))
           return True
       time.sleep(poll_wait_secs)
       timeout_wait_secs -= poll_wait_secs
    return False
