"""
A helper module for PTF tests.
"""

import pytest
import random
import os
import logging

from ipaddress import ip_address, IPv4Address
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def downstream_links(rand_selected_dut, tbinfo):
    """
    Returns a dictionary of all the links that are downstream from the DUT.

    Args:
        rand_selected_dut: DUT fixture
        tbinfo: testbed information fixture
    Returns:
        links: Dictionary of links downstream from the DUT
    """
    links = dict()
    duthost = rand_selected_dut

    def filter(interface, neighbor, mg_facts, tbinfo):
        if ((tbinfo["topo"]["type"] == "t0" and "Server" in neighbor["name"])
                or (tbinfo["topo"]["type"] == "t1" and "T0" in neighbor["name"])):
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "downstream_port": port
            }

    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="module")
def upstream_links(rand_selected_dut, tbinfo, nbrhosts):
    """
    Returns a dictionary of all the links that are upstream from the DUT.

    Args:
        rand_selected_dut: DUT fixture
        tbinfo: testbed information fixture
        nbrhosts: neighbor host fixture
    Returns:
        links: Dictionary of links upstream from the DUT
    """
    links = dict()
    duthost = rand_selected_dut

    def filter(interface, neighbor, mg_facts, tbinfo):
        if ((tbinfo["topo"]["type"] == "t0" and "T1" in neighbor["name"])
                or (tbinfo["topo"]["type"] == "t1" and "T2" in neighbor["name"])):
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ip_address(item["addr"]), IPv4Address):
                        # The address of neighbor device
                        local_ipv4_addr = item["addr"]
                        # The address of DUT
                        peer_ipv4_addr = item["peer_addr"]
                        break
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "local_ipv4_addr": local_ipv4_addr,
                "peer_ipv4_addr": peer_ipv4_addr,
                "upstream_port": port,
                "host": nbrhosts[neighbor["name"]]["host"]
            }

    find_links(duthost, tbinfo, filter)
    return links


def apply_dscp_cfg_setup(duthost, dscp_mode):
    """
    Applies the DSCP decap configuration to the DUT.

    Args:
        duthost: DUT fixture
        dscp_mode: DSCP mode to apply
    """

    default_decap_mode = duthost.shell("redis-cli -n 0 hget 'TUNNEL_DECAP_TABLE:IPINIP_TUNNEL' 'dscp_mode'")["stdout"]
    logger.info("Current DSCP decap mode: {}".format(default_decap_mode))

    if default_decap_mode == dscp_mode:
        logger.info("Current DSCP decap mode: {} matches required decap mode - no reload required"
                    .format(default_decap_mode))
        return

    for asic_id in duthost.get_frontend_asic_ids():
        swss = "swss{}".format(asic_id if asic_id is not None else '')
        logger.info("DSCP decap mode required to be changed to {} on asic {}".format(dscp_mode, asic_id))
        cmds = ["docker exec {} cp /usr/share/sonic/templates/ipinip.json.j2 ".format(swss) +
                "/usr/share/sonic/templates/ipinip.json.j2.tmp",
                "docker exec {} sed -i 's/\"dscp_mode\":\"{}\"/\"dscp_mode\":\"{}\"/g\' ".
                format(swss, default_decap_mode, dscp_mode) + "/usr/share/sonic/templates/ipinip.json.j2"]
        # sed -i 's/"dscp_mode":"uniform"/"dscp_mode":"pipe"/g' ipinip.json.j2 - this is the command to change
        duthost.shell_cmds(cmds=cmds)
        logger.info("DSCP decap mode changed from {} to {} on asic {}".format(default_decap_mode, dscp_mode, asic_id))

    logger.info("SETUP: Reload required for dscp decap mode changes to take effect.")
    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


def apply_dscp_cfg_teardown(duthost):
    """
    Removes the previously applied DSCP decap configuration from the DUT.

    Args:
        duthost: DUT fixture
    """
    reload_required = False
    for asic_id in duthost.get_frontend_asic_ids():
        swss = 'swss{}'.format(asic_id if asic_id is not None else '')
        try:
            file_out = duthost.shell("docker exec {} ls /usr/share/sonic/templates/ipinip.json.j2.tmp".format(swss))
        except Exception:
            continue
        if file_out["rc"] == 0:
            cmd1 = "docker exec {} cp /usr/share/sonic/templates/ipinip.json.j2.tmp ".format(swss) + \
                "/usr/share/sonic/templates/ipinip.json.j2"
            reload_required = True
            logger.info("DSCP decap mode required to be changed to default on asic {}".format(asic_id))
            duthost.shell(cmd1)

    if reload_required:
        logger.info("TEARDOWN: Reload required for dscp decap mode changes to take effect.")
        config_reload(duthost, safe_reload=True)


def find_links(duthost, tbinfo, filter):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        filter(interface, neighbor, mg_facts, tbinfo)


def select_random_link(links):
    """
    Selects a random link from the links dictionary.

    Args:
        links: Dictionary of links
    Returns:
        link: Random link
    """
    if not links:
        return None
    link = random.choice(list(links.values()))
    return link


def get_stream_ptf_ports(stream_links):
    """
    Returns a list of upstream/downstream PTF ports.

    Args:
        stream_links: Dictionary of upstream/downstream links
    Returns:
        ports: List of upstream PTF ports
    """
    ports = []
    for link in list(stream_links.values()):
        if "ptf_port_id" in link:
            ports.append(link.get("ptf_port_id"))
    return ports


def get_dut_pair_port_from_ptf_port(duthost, tbinfo, ptf_port_id):
    """
    Given a ptf port ID, find the corresponding port name on the DUT ex. Ethernet0
    """
    ext_minig_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for dut_port, ptf_port in ext_minig_facts['minigraph_ptf_indices'].items():
        if ptf_port == int(ptf_port_id):
            return dut_port

    return None


def fetch_test_logs_ptf(ptfhost, ptf_location, dest_dir):
    """
    Fetch test logs from ptfhost after individual test run
    """
    log_dir = ptf_location
    curr_dir = os.getcwd()
    logFiles = {'src': log_dir, 'dest': curr_dir + dest_dir, 'flat': True, 'fail_on_missing': False}
    ptfhost.fetch(**logFiles)

    return logFiles['dest']
