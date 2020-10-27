import logging
import time

logger = logging.getLogger(__name__)

WAIT_FOR_SYNC = 60


def join_master(duthost, master_vip):
    """
    Joins DUT to Kubernetes master

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master

    If join fails, test will fail at the assertion to check_connected
    """
    logger.info("Joining DUT to Kubernetes master")
    duthost.shell('sudo config kube server disable on')
    duthost.shell('sudo config kube server ip {}'.format(master_vip))
    duthost.shell('sudo config kube server disable off')
    time.sleep(WAIT_FOR_SYNC)
    assert check_connected(duthost)
    

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
    iptables_rules = duthost.shell('sudo iptables -S | grep {} || true'.format(master_vip))["stdout"].split("\n")
    logger.info('iptables rules: {}'.format(iptables_rules))
    for line in iptables_rules:
        if line: 
            duthost.shell('sudo iptables -D {}'.format(line[2:]))


def shutdown_all_api_server(k8shosts):
    """
    Shuts down the API server on each backend master server.

    Args:
        k8shosts:  Shortcut fixture for getting Kubernetes hosts
    """
    for i in range(1, len(k8shosts)):
        k8shost = k8shosts['m{}'.format(i)]['host']
        logger.info("Shutting down API Server on master node m{}".format(i))
        k8shost.shutdown_api_server()


def start_all_api_server(k8shosts):
    """
    Starts the API server on each backend master server.

    Args:
        k8shosts:  Shortcut fixture for getting Kubernetes hosts
    """
    for i in range(1, len(k8shosts)):
        k8shost = k8shosts['m{}'.format(i)]['host']
        logger.info("Starting API Server on master node m{}".format(i))
        k8shost.start_api_server()


def check_connected(duthost):
    """
    Checks if the DUT already shows status 'connected' to Kubernetes master

    Args:
        duthost: DUT host object
    
    Returns:
        True if connected, False if not connected
    """
    kube_server_status = duthost.shell('show kube server')["stdout"].split("\n")
    logger.info("Kube server status: {}".format(kube_server_status))
    for line in kube_server_status:
        if line.startswith("KUBERNETES_MASTER SERVER connected"):
            return line.endswith("true")
    logger.info("Kubernetes server check_connected failed to check server status")
