import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import time
import re
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

ETHERNET_RIF = 'ethernet'
VLAN_RIF = 'vlan'
PO_RIF = 'po'
SUB_PORT_RIF = "sub_port"
PO_SUB_PORT_RIF = "po_sub_port"
CONIFIG_LOOPBACK_ACTION_REG = "config interface ip loopback-action {} {}"
ACTION_FORWARD = "forward"
ACTION_DROP = "drop"
NUM_OF_TOTAL_PACKETS = 10
logger = logging.getLogger(__name__)


def generate_and_verify_traffic(duthost, ptfadapter, rif_interface, src_port_index, ip_src='', ip_dst='',
                                pkt_action=None):
    """
    Send packet from PTF to DUT and and verify packet on PTF host
    :param duthost: DUT host object
    :param ptfadapter: PTF adapter
    :param rif_interface: rif interface on dut
    :param src_port_index: Source port index from which pkt will be sent
    :param ip_src: Source IP address of the pkt
    :param ip_dst: Destination IP address of the pkt
    :param pkt_action: Packet action (forward or drop)
    :return: None
    """

    vlan_vid = None
    dl_vlan_enable = False
    # Get VLAN ID from name of rif interface
    if '.' in rif_interface:
        # this should be the sub-port interface
        vlan_vid = int(rif_interface.split('.')[1])
        dl_vlan_enable = True
    elif rif_interface.startswith("Vlan"):
        vlan_vid = int(rif_interface[4:])
        dl_vlan_enable = True

    ip_dst = ip_dst.split('/')[0]
    eth_dst = duthost.facts["router_mac"]
    eth_src = ptfadapter.dataplane.get_mac(0, src_port_index)
    duthost.shell("sudo ip neigh replace {} lladdr {} dev {}".format(ip_dst, eth_src, rif_interface))
    logger.info("Traffic info is: eth_dst- {}, eth_src- {}, ip_src- {}, ip_dst- {}, vlan_vid- {}".format(
        eth_dst, eth_src, ip_src, ip_dst, vlan_vid))
    pkt = testutils.simple_ip_packet(
        eth_dst=eth_dst,
        eth_src=eth_src,
        ip_src=ip_src,
        ip_dst=ip_dst,
        vlan_vid=vlan_vid,
        dl_vlan_enable=dl_vlan_enable,
        ip_ttl=121
    )
    exp_pkt = pkt.copy()
    exp_pkt.payload.ttl = 120
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

    ptfadapter.dataplane.flush()
    time.sleep(1)
    logger.info("Verify the traffic for {}".format(rif_interface))
    testutils.send_packet(ptfadapter, src_port_index, pkt, count=NUM_OF_TOTAL_PACKETS)
    if pkt_action == ACTION_DROP:
        testutils.verify_no_packet(ptfadapter, exp_pkt, src_port_index)
    else:
        testutils.verify_packet(ptfadapter, exp_pkt, src_port_index)


def get_tested_up_ports(duthost, ptf_ifaces_map, count=10):
    """
    Get the specified number of up ports
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param count: The number of ports
    :return: The dictionary of the up ports.
    Examples:
    {
       '1': {
            'vlan': 100,
            'ip_addresses': {}
            'portchannel': None
            'ptf_port': 'eth0'
       },
        ...
    }
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    up_ports = get_all_up_ports(config_facts)
    logger.info("Ports infos: {}".format(config_facts['PORT']))
    port_index_map = config_facts['port_index_map']
    port_configuration = {}

    index = 0
    for port in up_ports:
        if index >= count:
            break
        port_dict = {'port': port, 'vlan': None, 'portchannel': None, 'ip_addr': None, 'ptf_port': None}
        port_index = port_index_map[port]

        ip_addresses = config_facts.get('INTERFACE', {}).get(port, {})
        port_dict['ip_addr'] = ip_addresses
        port_dict['portchannel'] = get_portchannel_of_port(config_facts, port)
        port_dict['vlan'] = get_vlan_of_port(config_facts, port)

        ptf_port = ptf_ifaces_map[port_index]
        port_dict['ptf_port'] = ptf_port

        port_configuration[port_index] = port_dict
        index += 1
    return port_configuration


def get_all_up_ports(config_facts):
    """
    Get all ports which are up
    :param config_facts: DUT running config facts
    :return: List of ports which is up
    """
    split_port_alias_pattern = r"etp\d+[a-z]"
    split_up_ports = [p for p, v in list(config_facts['PORT'].items()) if v.get('admin_status', None) == 'up' and
                      not re.match(split_port_alias_pattern, v['alias'])]
    non_split_up_ports = [p for p, v in list(config_facts['PORT'].items()) if v.get('admin_status', None) == 'up' and
                          re.match(split_port_alias_pattern, v['alias'])]
    return split_up_ports + non_split_up_ports


def get_portchannel_of_port(config_facts, port):
    """
    Check if the port is a member of port channel, if it is then return the portchannel, else return Noe
    :param config_facts: DUT running config facts
    :param port: the port which need to check
    :return: portchannel or None
    """
    portchannels = list(config_facts['PORTCHANNEL'].keys()) if 'PORTCHANNEL' in config_facts else []
    for portchannel in portchannels:
        portchannel_members = config_facts['PORTCHANNEL'][portchannel].get('members')
        if port in portchannel_members:
            return portchannel


def get_vlan_of_port(config_facts, port):
    """
    Check if the port is a member of vlan, if it is then return the vlan, else return None
    :param config_facts: DUT running config facts
    :param port: the port which need to check
    :return: vlan or None
    """
    vlan_dict = list(config_facts['VLAN'].items()) if 'VLAN' in config_facts else {}
    for vlan_name, vlan in vlan_dict:
        if port in list(config_facts['VLAN_MEMBER'][vlan_name].keys()):
            return vlan['vlanid']
    return None


def remove_orig_dut_port_config(duthost, orig_ports_configuration):
    """
    Remove the original port configurations for DUT
    :param duthost: DUT host object
    :param orig_ports_configuration: original ports configuration parameters
    """
    for _, port_dict in list(orig_ports_configuration.items()):
        port = port_dict['port']
        if port_dict['vlan']:
            remove_dut_vlan_member(duthost, port, port_dict['vlan'])
        elif port_dict['portchannel']:
            remove_dut_portchannel_member(duthost, port, port_dict['portchannel'])
        elif port_dict['ip_addr']:
            for ip in port_dict['ip_addr']:
                remove_dut_ip_from_port(duthost, port, ip)
    remove_acl_tables(duthost)


def get_portchannel_peer_port_map(duthost, orig_ports_configuration, tbinfo, nbrhosts):
    """
    Get the portchannel peer port map.
    :param duthost: DUT host object
    :param orig_ports_configuration: original ports configuration parameters
    :param tbinfo: Testbed object
    :param nbrhosts: nbrhosts fixture.
    :return: The dictionary of vm/ports mapping.
    """
    peer_ports_map = {}
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']
    for _, port_dict in list(orig_ports_configuration.items()):
        port = port_dict['port']
        if port_dict['portchannel']:
            vm_host, peer_port = get_peer_port_info(nbrhosts, vm_neighbors, port)
            if vm_host not in peer_ports_map:
                peer_ports_map[vm_host] = []
            peer_ports_map[vm_host].append(peer_port)
    return peer_ports_map


def get_peer_port_info(nbrhosts, vm_neighbors, intf):
    """
    Get the peer port info
    :param nbrhosts: nbrhosts fixture.
    :param vm_neighbors: vm neighbors infos
    :param intf: the intf on the dut
    :return: Return the vm host connect to the intf, and the peer port of intf
    """
    peer_device = vm_neighbors[intf]['name']
    vm_host = nbrhosts[peer_device]['host']
    peer_port = vm_neighbors[intf]['port']
    return vm_host, peer_port


def remove_acl_tables(duthost):
    """
    Remove all the acl tables
    :param duthost: DUT host object
    :return: None
    """
    acl_table_list = duthost.show_and_parse('show acl table')
    for acl_table in acl_table_list:
        if acl_table["name"]:
            logger.info("Removing ACL table {}".format(acl_table["name"]))
            duthost.shell("config acl remove table {}".format(acl_table["name"]))


def apply_config(duthost, ptfhost, ports_configuration):
    """
    Apply the configuration on the DUT and PTF host
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param ports_configuration: ports configuration parameters
    """
    apply_ptf_config(ptfhost, ports_configuration)
    apply_dut_config(duthost, ports_configuration)


def recover_config(duthost, ptfhost, ports_configuration):
    """
    Remove the configuration on the DUT and PTF host
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param ports_configuration: ports configuration parameters
    """
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    remove_ptf_config(ptfhost, ports_configuration)


def apply_dut_config(duthost, ports_configuration):
    """
    Apply the configuration on the DUT host
    :param duthost: DUT host object
    :param ports_configuration: ports configuration parameters
    """
    for _, port_conf in list(ports_configuration.items()):
        port = port_conf['port']
        port_type = port_conf['type']
        ip_addr = port_conf['ip_addr']
        if port_type == ETHERNET_RIF:
            add_ip_dut_port(duthost, port, ip_addr)
        elif port_type == VLAN_RIF:
            add_dut_vlan(duthost, port, port_conf['vlan_id'], ip_addr)
        elif port_type == PO_RIF:
            add_dut_portchannel(duthost, port, port_conf['po_id'], ip_addr)
        elif port_type == SUB_PORT_RIF:
            add_dut_sub_port(duthost, port, port_conf['vlan_id'], ip_addr, sub_port_type="eth")
        elif port_type == PO_SUB_PORT_RIF:
            add_dut_po_sub_port(duthost, port, port_conf['po_id'], port_conf['vlan_id'], ip_addr)


def apply_ptf_config(ptfhost, ports_configuration):
    """
    Apply the configuration on the PTF host
    :param ptfhost: PTF host object
    :param ports_configuration: ports configuration parameters
    """
    for _, port_conf in list(ports_configuration.items()):
        port_type = port_conf['type']
        ptf_port = port_conf['ptf_port']

        if port_type == PO_SUB_PORT_RIF or port_type == PO_RIF:
            add_ptf_bond(ptfhost, ptf_port, port_conf['po_id'], port_conf['ptf_ip_addr'])

    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)


def remove_ptf_config(ptfhost, ports_configuration):
    """
    Remove the configuration on the PTF host
    :param ptfhost: PTF host object
    :param ports_configuration: ports configuration parameters
    """
    for _, port_conf in list(ports_configuration.items()):
        port_type = port_conf['type']
        ptf_port = port_conf['ptf_port']
        if port_type == PO_SUB_PORT_RIF or port_type == PO_RIF:
            remove_ptf_bond(ptfhost, ptf_port, port_conf['po_id'], port_conf['ptf_ip_addr'])

    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)


def add_ip_dut_port(duthost, port, ip_addr):
    """
    Add ip address for the port on DUT host
    :param duthost: DUT host object
    :param port: port name
    :param ip_addr: ip address
    """
    duthost.shell('config interface ip add {} {}'.format(port, ip_addr))


def remove_dut_ip_from_port(duthost, port, ip_addr):
    """
    Remove ip address from the port on DUT host
    :param duthost: DUT host object
    :param port: port name
    :param ip_addr: ip address
    """
    duthost.shell('config interface ip remove {} {}'.format(port, ip_addr))


def add_dut_vlan(duthost, port, vlan_id, ip_addr):
    """
    Create vlan and add port to vlan member and config the ip address on the vlan
    :param duthost: DUT host object
    :param port: Port which will be added to the vlan
    :param vlan_id: Vlan id
    :param ip_addr: ip address
    """
    duthost.shell('config vlan add {}'.format(vlan_id))
    duthost.shell('config vlan member add {} {}'.format(vlan_id, port))
    add_ip_dut_port(duthost, "Vlan{}".format(vlan_id), ip_addr)


def add_dut_portchannel(duthost, port, po_id, ip_addr):
    """
    Create port channel on the dut, add port to the port channel member and config ip address for the portchannel
    :param duthost: DUT host object
    :param port: Port which will be added to the portchannel
    :param po_id: portchannel id
    :param ip_addr: ip address
    """
    lag_port = "PortChannel{}".format(po_id)
    duthost.shell('config portchannel add {}'.format(lag_port))
    duthost.shell('config portchannel member add {} {}'.format(lag_port, port))
    add_ip_dut_port(duthost, lag_port, ip_addr)


def add_dut_sub_port(duthost, port, vlan_id, ip_addr, sub_port_type="po"):
    """
    Add sub port and configure the ip address on the sub port
    :param duthost: DUT host object
    :param port: Ethernet or PortChannel port
    :param vlan_id: Vlan id of the sub port
    :param ip_addr: Ip address
    :param sub_port_type: sub port type, can be eth, po
    """
    if sub_port_type != "eth":
        port = port.replace("PortChannel", "Po")
    subport = '{}.{}'.format(port, vlan_id)
    duthost.shell('config subinterface add {} {}'.format(subport, vlan_id))
    add_ip_dut_port(duthost, subport, ip_addr)


def add_dut_po_sub_port(duthost, port, po_id, vlan_id, ip_addr):
    """
    Add port channel sub port interface and config the ip address for it
    :param duthost: DUT host object
    :param port: port which will be add to the port channel
    :param po_id: port channel id
    :param vlan_id: vlan id
    :param ip_addr: ip address
    """
    lag_port = "PortChannel{}".format(po_id)
    duthost.shell('config portchannel add {}'.format(lag_port))
    duthost.shell('config portchannel member add {} {}'.format(lag_port, port))
    add_dut_sub_port(duthost, lag_port, vlan_id, ip_addr)


def add_dut_portchannel_member(duthost, port, lag_port):
    """
    Add the port to the portchannel member
    :param duthost: DUT host object
    :param port: port which will be added to the port channel.
    :param lag_port: port channel
    """
    duthost.shell('config portchannel member add {} {}'.format(lag_port, port))


def remove_dut_portchannel_member(duthost, port, lag_port):
    """
    Remove the port from the portchannel member
    :param duthost: DUT host object
    :param port: port which will be removed from the port channel.
    :param lag_port: port channel
    """
    duthost.shell('config portchannel member del {} {}'.format(lag_port, port))


def add_dut_vlan_member(duthost, port, vlan_id):
    """
    Add the port to the vlan member
    :param duthost: DUT host object
    :param port: port which will be added to the vlan.
    :param vlan_id: vlan id
    """
    duthost.shell('config vlan member add {} {}'.format(vlan_id, port))


def remove_dut_vlan_member(duthost, port, vlan_id):
    """
    Remove the port from the vlan member
    :param duthost: DUT host object
    :param port: port which will be removed from the vlan.
    :param vlan_id: vlan id
    """
    duthost.shell('config vlan member del {} {}'.format(vlan_id, port))


def add_ptf_bond(ptfhost, port, bond_id, ip_addr):
    """
    Add bond on the ptf host
    :param ptfhost: PTF host object
    :param port: the ptf port which will be added to the bond
    :param bond_id: bond id
    :param ip_addr: ip address
    """
    try:
        bond_port = 'bond{}'.format(bond_id)
        ptfhost.shell("ip link add {} type bond".format(bond_port))
        ptfhost.shell("ip link set {} type bond miimon 100 mode 802.3ad".format(bond_port))
        ptfhost.shell("ip link set {} down".format(port))
        ptfhost.shell("ip link set {} master {}".format(port, bond_port))
        ptfhost.shell("ip link set dev {} up".format(bond_port))
        ptfhost.shell("ifconfig {} mtu 9216 up".format(bond_port))
    except Exception as e:
        logger.error("Err when add bond on ptf host: {}".format(e))


def remove_ptf_bond(ptfhost, port, bond_id, ip_addr):
    """
    Remove bond on the ptf host
    :param ptfhost: PTF host object
    :param port: the ptf port which will be removed from the bond
    :param bond_id: bond id
    """
    try:
        ptfhost.shell("ip link set bond{} nomaster".format(bond_id))
        ptfhost.shell("ip link set {} nomaster".format(port))
        ptfhost.shell("ip link set {} up".format(port))
        ptfhost.shell("ip link del bond{}".format(bond_id))
    except Exception as e:
        logger.error("Err when remove bond on ptf host: {}".format(e))


def verify_traffic(duthost, ptfadapter, rif_interfaces, ports_configuration, action_list):
    """
    Verify traffic can be forwarded or dropped as expect
    :param duthost: DUT host object
    :param ptfadapter: PTF adapter object
    :param rif_interfaces: List of rif interfaces
    :param ports_configuration: ports configuration parameters
    :param action_list: List of actions will be configure on the rif interface, the value can be forward, drop
    """
    ip_src = "11.11.11.11"
    for rif_interface, pkt_action in zip(rif_interfaces, action_list):
        port_conf = ports_configuration[rif_interface]
        src_port = port_conf['ptf_port']
        ip_dst = port_conf['ptf_ip_addr']
        port_index = port_conf['port_index']
        logger.info("Sending traffic from {}".format(src_port))
        generate_and_verify_traffic(duthost, ptfadapter, rif_interface, port_index, ip_src, ip_dst,
                                    pkt_action=pkt_action)


def config_loopback_action(duthost, rif_interfaces, action_list, ignore_err=False):
    """
    Config the loopback action for the rif interfaces
    :param duthost: DUT host object
    :param rif_interfaces: List of rif interfaces
    :param action_list: List of actions will be configure on the rif interface
    :param ignore_err:  ignore the ansible err or not
    """
    for rif_interface, action in zip(rif_interfaces, action_list):
        duthost.shell(CONIFIG_LOOPBACK_ACTION_REG.format(rif_interface, action), module_ignore_errors=ignore_err)


def clear_rif_counter(duthost):
    """
    Clear the rif counters
    :param duthost: DUT host object
    """
    duthost.shell("sonic-clear rifcounters")


def show_loopback_action(duthost):
    """
    Get the loopback action for every rif interface
    :param duthost: DUT host object
    :return: loopback action for every rif interface
    Example:
    {
    "Ethernet0": "drop",
    "Vlan11": "drop",
    "PortChannel11": "drop"
    }
    """
    res = duthost.shell("show ip interfaces loopback-action")
    interfaces_loopback_actions = res['stdout'].splitlines()[2:]
    interface_loopback_action_map = {}
    for interface_loopback_action in interfaces_loopback_actions:
        interface = interface_loopback_action.split(" ")[0].strip()
        action = interface_loopback_action.split(" ")[-1].strip()
        interface_loopback_action_map[interface] = action
    return interface_loopback_action_map


def verify_interface_loopback_action(duthost, rif_interfaces, expected_actions):
    """
    Verify the loopback action on the rif interfaces is configured as expected value
    :param duthost: DUT host object
    :param rif_interfaces: List of rif interface
    :param expected_actions: drop or forward
    """
    interface_loopback_action_map = show_loopback_action(duthost)
    for rif_interface, expected_action in zip(rif_interfaces, expected_actions):
        loopback_action = interface_loopback_action_map[rif_interface]
        pytest_assert(loopback_action == expected_action,
                      "The loopback action on {} is {}, expected action is {}".format(rif_interface, loopback_action,
                                                                                      expected_action))


def get_rif_tx_err_count(duthost):
    """
    Get the TX ERR count for every rif interface
    :param duthost: DUT host object
    :return: rx err count for every rif interface
    Example:
    {
    "Ethernet0": 0,
    "Vlan11": 10,
    "PortChannel11": 10
    }
    """
    rif_counter_list = duthost.show_and_parse('show interfaces counters rif')
    rif_tx_err_map = {counter["iface"]: counter["tx_err"] for counter in rif_counter_list}
    return rif_tx_err_map


def verify_rif_tx_err_count(duthost, rif_interfaces, expect_counts):
    """
    Verify the TX ERR count on the rif interfaces is increased as expected
    :param duthost: DUT host object
    :param rif_interfaces: List of rif interface
    :param expect_counts: expected TX ERR for for every rif interface
    """
    rif_tx_err_map = get_rif_tx_err_count(duthost)
    for rif_interface, expected_count in zip(rif_interfaces, expect_counts):
        tx_err_count = int(rif_tx_err_map[rif_interface])
        pytest_assert(tx_err_count == expected_count,
                      "The TX ERR count on {} is {}, expect TX ERR count is {}".format(rif_interface, tx_err_count,
                                                                                       expected_count))


def shutdown_rif_interfaces(duthost, rif_interfaces):
    """
    Shutdown interfaces on the DUT
    :param duthost: DUT host object
    :param rif_interfaces: rif interfaces list
    """
    duthost.shutdown_multiple(rif_interfaces)
    pytest_assert(wait_until(60, 1, 0, check_interface_state, duthost, rif_interfaces, 'down'),
                  "DUT's port {} didn't go down as expected".format(rif_interfaces))


def startup_rif_interfaces(duthost, rif_interfaces):
    """
    Start up interfaces on the DUT
    :param duthost: DUT host object
    :param rif_interfaces: rif interfaces list
    """
    duthost.no_shutdown_multiple(rif_interfaces)
    pytest_assert(wait_until(60, 1, 0, check_interface_state, duthost, rif_interfaces),
                  "DUT's port {} didn't go up as expected".format(rif_interfaces))


def check_interface_state(duthost, rif_interfaces, state='up'):
    """
    Check interface status

    :param duthost: DUT host object
    :param rif_interfaces: rif interfaces list
    :return: Bool value which confirm ports state
    """
    ports_down = duthost.interface_facts(up_ports=rif_interfaces)['ansible_facts']['ansible_interface_link_down_ports']
    if 'down' in state:
        return all(interface in ports_down for interface in rif_interfaces)

    return all(interface not in ports_down for interface in rif_interfaces)
