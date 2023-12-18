import os
import sys
import logging
import json

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from tests.common.plugins.pdu_controller.pdu_manager import pdu_manager_factory     # noqa E402

logger = logging.getLogger(__name__)


def get_pdu_managers(sonichosts, conn_graph_facts):
    """Get PDU managers for all the devices to be upgraded.

    Args:
        sonichosts (SonicHosts): Instance of class SonicHosts
        conn_graph_facts (dict): Connection graph dict.

    Returns:
        dict: A dict of PDU managers. Key is device hostname. Value is the PDU manager object for the device.
    """
    pdu_managers = {}
    for hostname in sonichosts.hostnames:
        pdu_links = conn_graph_facts["device_pdu_links"][hostname]
        pdu_hostnames = [peer_info["peerdevice"] for peer_info in pdu_links.values()]
        pdu_vars = {}
        for pdu_hostname in pdu_hostnames:
            pdu_vars[pdu_hostname] = sonichosts.get_host_visible_vars(pdu_hostname)

        pdu_managers[hostname] = pdu_manager_factory(hostname, None, conn_graph_facts, pdu_vars)
    return pdu_managers


def check_reachability(localhost, sonichosts):
    hosts_reachability = {}

    logger.info("Check ICMP ping")
    for hostname, ip in zip(sonichosts.hostnames, sonichosts.ips):
        hosts_reachability[hostname] = True
        logger.info("Ping {} @{} from localhost".format(hostname, ip))
        ping_failed = localhost.command(
            "timeout 2 ping {} -c 1".format(ip), module_ignore_errors=True
        ).get("localhost", {}).get("failed")
        if ping_failed:
            logger.info("Ping {} @{} from localhost failed.".format(hostname, ip))
            hosts_reachability[hostname] = False

    logger.info("Check if ansible can SSH to sonichosts")
    for hostname, ping_result in sonichosts.ping(module_ignore_errors=True).items():
        if ping_result["failed"]:
            logger.info("SSH to {} failed.".format(hostname))
            hosts_reachability[hostname] = False

    logger.info("Hosts reachability: {}".format(json.dumps(hosts_reachability, indent=2)))

    return hosts_reachability
