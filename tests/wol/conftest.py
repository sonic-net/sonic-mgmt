import pytest
import random
import ipaddress
import logging


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


@pytest.fixture(scope="function")
def random_vlan(vlan_brief):
    vlan_names = list(vlan_brief.keys())
    random_vlan = random.choice(vlan_names)
    logging.info("Test with vlan {}".format(random_vlan))
    return random_vlan


@pytest.fixture(scope="function")
def random_intf_pair(get_connected_dut_intf_to_ptf_index, vlan_brief, random_vlan):
    vlan_members = vlan_brief[random_vlan]['members']
    random_dut_intf, random_ptf_intf = random.choice(list(filter(
        lambda item: item[0] in vlan_members, get_connected_dut_intf_to_ptf_index)))
    logging.info("Test with random dut intf {} and ptf intf index {}"
                 .format(random_dut_intf, random_ptf_intf))
    return (random_dut_intf, random_ptf_intf)


def random_ip_from_network(network):
    return network.network_address + random.randrange(network.num_addresses)


@pytest.fixture(scope="function")
def dst_ip(request, duthost, ptfhost, vlan_brief, random_vlan, random_intf_pair):
    ip = request.param
    if ip:
        vlan_intf = ipaddress.ip_interface(vlan_brief[random_vlan]["interface_" + ip][0])
        ip = random_ip_from_network(vlan_intf.network)
        logging.info("Test with ip {} from vlan interface {}".format(ip, vlan_intf))
        ptfhost.shell("ip addr add {} dev eth{}".format(ip, random_intf_pair[1]))
        logging.info("Configure ip {} on eth{} of ptf".format(ip, random_intf_pair[1]))

    yield ip

    if ip:
        ptfhost.shell("ip addr del {} dev eth{}".format(ip, random_intf_pair[1]))
        logging.info("Remove ip {} on eth{} of ptf".format(ip, random_intf_pair[1]))


def vlan_n2i(vlan_name):
    """
        Convert vlan name to vlan id
    """
    return vlan_name.replace("Vlan", "")


@pytest.fixture(scope="function")
def get_connected_intf_pair_under_vlan(get_connected_dut_intf_to_ptf_index, vlan_brief, random_vlan):
    vlan_members = vlan_brief[random_vlan]['members']
    items_in_vlan = list(filter(lambda member: member in vlan_members, get_connected_dut_intf_to_ptf_index))
    logging.info("Intf pair under vlan {}: {}".format(random_vlan, items_in_vlan))
    return list(items_in_vlan)


@pytest.fixture(scope="function")
def random_intf_pair_to_remove_under_vlan(duthost, random_vlan, get_connected_intf_pair_under_vlan):
    intf_pair_to_remove = random.choice(get_connected_intf_pair_under_vlan)
    logging.info("Intf pair to remove under vlan {}: {}".format(random_vlan, intf_pair_to_remove))
    duthost.del_member_from_vlan(vlan_n2i(random_vlan), intf_pair_to_remove[0])
    logging.info("Intf pair {} removed from vlan {}".format(intf_pair_to_remove, random_vlan))

    yield intf_pair_to_remove

    duthost.add_member_to_vlan(vlan_n2i(random_vlan), intf_pair_to_remove[0], False)
    logging.info("Intf pair {} added back to vlan {}".format(intf_pair_to_remove, random_vlan))


@pytest.fixture(scope="function")
def remaining_intf_pair_under_vlan(get_connected_intf_pair_under_vlan, random_intf_pair_to_remove_under_vlan):
    return list(filter(lambda item: item != random_intf_pair_to_remove_under_vlan, get_connected_intf_pair_under_vlan))


@pytest.fixture(scope="function")
def get_connected_intf_pair_not_under_vlan(get_connected_dut_intf_to_ptf_index, remaining_intf_pair_under_vlan):
    return list(filter(lambda item: item not in remaining_intf_pair_under_vlan, get_connected_dut_intf_to_ptf_index))
