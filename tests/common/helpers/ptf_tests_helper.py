"""
A helper module for PTF tests.
"""

import pytest
import random

from ipaddress import ip_address, IPv4Address
from tests.common.config_reload import config_reload


@pytest.fixture(scope="module")
def downstream_links(duthost, tbinfo):
    """
    Returns a dictionary of all the links that are downstream from the DUT.

    Args:
        duthost: DUT fixture
        tbinfo: testbed information fixture
    Returns:
        links: Dictionary of links downstream from the DUT
    """
    links = dict()

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
def upstream_links(duthost, tbinfo, nbrhosts):
    """
    Returns a dictionary of all the links that are upstream from the DUT.

    Args:
        duthost: DUT fixture
        tbinfo: testbed information fixture
        nbrhosts: neighbor host fixture
    Returns:
        links: Dictionary of links upstream from the DUT
    """
    links = dict()

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

    default_decap_mode = duthost.shell("redis-cli -n 0 hget 'TUNNEL_DECAP_TABLE:IPINIP_TUNNEL' 'dscp_mode'")
    ["stdout"].strip()

    if default_decap_mode == dscp_mode:
        return

    for asic_id in duthost.get_frontend_asic_ids():
        swss = "swss{}".format(asic_id if asic_id is not None else '')
        cmds = [
            "docker exec {} cp /usr/share/sonic/templates/ipinip.json.j2 /usr/share/sonic/templates/ipinip.json.j2.tmp"
            .format(swss),
            "docker exec {} sed -i 's/{}/{}/g' /usr/share/sonic/templates/ipinip.json.j2 "
            .format(swss, default_decap_mode, dscp_mode)
        ]
        duthost.shell_cmds(cmds=cmds)

    config_reload(duthost, safe_reload=True)


def apply_dscp_cfg_teardown(duthost):
    """
    Removes the previously applied DSCP decap configuration from the DUT.

    Args:
        duthost: DUT fixture
    """
    reload_required = False
    for asic_id in duthost.get_frontend_asic_ids():
        swss = 'swss{}'.format(asic_id if asic_id is not None else '')
        file_exists = duthost.shell("docker exec {} ls /usr/share/sonic/templates/ipinip.json.j2.tmp"
                                    .format(swss))["rc"] == 0
        if not file_exists:
            continue
        cmds = [
            'docker exec {} cp /usr/share/sonic/templates/ipinip.json.j2.tmp /usr/share/sonic/templates/ipinip.json.j2'
            .format(swss)
        ]
        reload_required = True
        duthost.shell_cmds(cmds=cmds)

    if reload_required:
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
