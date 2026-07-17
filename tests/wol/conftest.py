import pytest
import random
import ipaddress
import logging
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py  # noqa: F401
from tests.common.fixtures.ptfhost_utils import setup_ptf_ip_responder, teardown_ptf_ip_responder


ARP_RESPONDER_PATH = "/tmp/new_arp_responder_conf.json"


@pytest.fixture(scope="module")
def get_connected_dut_intf_to_ptf_index(duthost, tbinfo):
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = [(k, v) for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx]

    yield connected_dut_intf_to_ptf_index


@pytest.fixture(scope="module")
def vlan_brief(duthost):
    return duthost.get_vlan_brief()


@pytest.fixture(scope="module")
def random_vlan(vlan_brief):
    vlan_names = list(vlan_brief.keys())
    random_vlan = random.choice(vlan_names)
    logging.info("Test with vlan {}".format(random_vlan))
    return random_vlan


@pytest.fixture(scope="module")
def random_intf_pair(get_connected_dut_intf_to_ptf_index, vlan_brief, random_vlan):
    vlan_members = vlan_brief[random_vlan]['members']
    random_dut_intf, random_ptf_intf = random.choice(list(filter(
        lambda item: item[0] in vlan_members, get_connected_dut_intf_to_ptf_index)))
    logging.info("Test with random dut intf {} and ptf intf index {}"
                 .format(random_dut_intf, random_ptf_intf))
    return (random_dut_intf, random_ptf_intf)


def vlan_n2i(vlan_name):
    """
        Convert vlan name to vlan id
    """
    return vlan_name.replace("Vlan", "")


@pytest.fixture(scope="module")
def get_intf_pair_under_vlan(get_connected_dut_intf_to_ptf_index, vlan_brief, random_vlan):
    vlan_members = vlan_brief[random_vlan]['members']
    items_in_vlan = list(filter(lambda item: item[0] in vlan_members, get_connected_dut_intf_to_ptf_index))
    logging.info("Intf pair under vlan {}: {}".format(random_vlan, items_in_vlan))
    return list(items_in_vlan)


@pytest.fixture(scope="class")
def random_intf_pair_to_remove_under_vlan(duthost, random_vlan, random_intf_pair):
    duthost.del_member_from_vlan(vlan_n2i(random_vlan), random_intf_pair[0])
    logging.info("Intf pair {} removed from vlan {}".format(random_intf_pair, random_vlan))

    yield random_intf_pair

    duthost.add_member_to_vlan(vlan_n2i(random_vlan), random_intf_pair[0], False)
    logging.info("Intf pair {} added back to vlan {}".format(random_intf_pair, random_vlan))


def setup_ip_on_ptf(duthost, ptfhost, ip, intf_pairs):
    ptfhost.remove_ip_addresses()
    setup_ptf_ip_responder(
        duthost, ptfhost, ARP_RESPONDER_PATH,
        [(ip, dut_intf, ptf_index) for dut_intf, ptf_index in intf_pairs])


def remove_ip_on_ptf(duthost, ptfhost):
    teardown_ptf_ip_responder(duthost, ptfhost, ARP_RESPONDER_PATH)


@pytest.fixture(scope="class")
def dst_ip_intf(request, duthost, ptfhost, vlan_brief, random_vlan, random_intf_pair_to_remove_under_vlan):
    ip = request.param
    if ip == "ipv4" or ip == "ipv6":
        vlan_intf = ipaddress.ip_interface(vlan_brief[random_vlan]["interface_" + ip][0])
        ip = vlan_intf.network.broadcast_address.__str__()
    if ip and isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        duthost.shell("config interface ip add {} {}".format(random_intf_pair_to_remove_under_vlan[0], vlan_intf))
        setup_ip_on_ptf(duthost, ptfhost, ip, [random_intf_pair_to_remove_under_vlan])

    yield ip

    if ip and isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        remove_ip_on_ptf(duthost, ptfhost)
        duthost.shell("config interface ip remove {} {}".format(random_intf_pair_to_remove_under_vlan[0], vlan_intf))


@pytest.fixture(scope="class")
def remaining_intf_pair_under_vlan(get_intf_pair_under_vlan, random_intf_pair_to_remove_under_vlan):
    return list(filter(lambda item: item != random_intf_pair_to_remove_under_vlan, get_intf_pair_under_vlan))


@pytest.fixture(scope="class")
def dst_ip_vlan(request, duthost, ptfhost, get_connected_dut_intf_to_ptf_index, vlan_brief, random_vlan):
    ip = request.param
    if ip == "ipv4" or ip == "ipv6":
        vlan_intf = ipaddress.ip_interface(vlan_brief[random_vlan]["interface_" + ip][0])
        ip = vlan_intf.network.broadcast_address.__str__()
    if ip and isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        vlan_members = vlan_brief[random_vlan]['members']
        setup_ip_on_ptf(duthost, ptfhost, ip,
                        filter(lambda item: item[0] in vlan_members, get_connected_dut_intf_to_ptf_index))

    yield ip

    if ip and isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        remove_ip_on_ptf(duthost, ptfhost)


@pytest.fixture(scope="function")
def random_intf_pair_down(duthost, random_intf_pair):
    duthost.shutdown(random_intf_pair[0])
    logging.info("Shut down intf pair {}".format(random_intf_pair))

    yield random_intf_pair

    duthost.no_shutdown(random_intf_pair[0])
    logging.info("Bring up intf pair {}".format(random_intf_pair))
