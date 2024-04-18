import logging
import time
import pytest
import binascii
import netaddr
import struct

from tests.common.helpers.assertions import pytest_require, pytest_assert

import scapy

from ptf.mask import Mask
import ptf.packet as packet

from scapy.all import socket

from scapy.fields import MACField, ShortEnumField, FieldLenField, ShortField
from scapy.data import ETHER_ANY
from scapy.layers.dhcp6 import _DHCP6OptGuessPayload

from tests.common import constants

import ptf.testutils as testutils

from ipaddress import ip_network, IPv6Network, IPv4Network
from tests.arp.arp_utils import increment_ipv6_addr, increment_ipv4_addr

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import format_and_apply_template, load_and_apply_json_patch
from tests.generic_config_updater.gu_utils import expect_acl_rule_match, expect_acl_rule_removed
from tests.generic_config_updater.gu_utils import expect_acl_table_match_multiple_bindings
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401
from tests.common.utilities import get_upstream_neigh_type, get_downstream_neigh_type


pytestmark = [
    pytest.mark.topology('t0', 'm0'),
]

logger = logging.getLogger(__name__)

CREATE_CUSTOM_TABLE_TYPE_FILE = "create_custom_table_type.json"
CREATE_CUSTOM_TABLE_TEMPLATE = "create_custom_table.j2"
CREATE_FORWARD_RULES_TEMPLATE = "create_forward_rules.j2"
CREATE_INITIAL_DROP_RULE_TEMPLATE = "create_initial_drop_rule.j2"
CREATE_SECONDARY_DROP_RULE_TEMPLATE = "create_secondary_drop_rule.j2"
CREATE_THREE_DROP_RULES_TEMPLATE = "create_three_drop_rules.j2"
CREATE_ARP_FORWARD_RULE_FILE = "create_arp_forward_rule.json"
CREATE_NDP_FORWARD_RULE_FILE = "create_ndp_forward_rule.json"
CREATE_DHCP_FORWARD_RULE_FILE = "create_dhcp_forward_rule_both.json"
REPLACE_RULES_TEMPLATE = "replace_rules.j2"
REPLACE_NONEXISTENT_RULE_FILE = "replace_nonexistent_rule.json"
REMOVE_RULE_TEMPLATE = "remove_rule.j2"
REMOVE_TABLE_FILE = "remove_table.json"
REMOVE_NONEXISTENT_TABLE_FILE = "remove_nonexistent_table.json"
REMOVE_TABLE_TYPE_FILE = "remove_table_type.json"

IP_SOURCE = "192.168.0.3"
IPV6_SOURCE = "fc02:1000::3"

DST_IP_FORWARDED_ORIGINAL = "103.23.2.1"
DST_IPV6_FORWARDED_ORIGINAL = "103:23:2:1::1"

DST_IP_FORWARDED_REPLACEMENT = "103.23.2.2"
DST_IPV6_FORWARDED_REPLACEMENT = "103:23:2:2::1"

DST_IP_FORWARDED_SCALE_PREFIX = "103.23.4."
DST_IPV6_FORWARDED_SCALE_PREFIX = "103:23:4:"

DST_IP_BLOCKED = "103.23.3.1"
DST_IPV6_BLOCKED = "103:23:3:1::1"

MAX_IP_RULE_PRIORITY = 9900
MAX_DROP_RULE_PRIORITY = 9000

# DHCP Constants

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
BROADCAST_IP = '255.255.255.255'
DEFAULT_ROUTE_IP = '0.0.0.0'
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DHCP_PKT_BOOTP_MIN_LEN = 300

# DHCPv6 Constants

IPv6 = scapy.layers.inet6.IPv6
DHCP6_Solicit = scapy.layers.dhcp6.DHCP6_Solicit
DHCP6_RelayForward = scapy.layers.dhcp6.DHCP6_RelayForward
DHCP6OptRelayMsg = scapy.layers.dhcp6.DHCP6OptRelayMsg

DHCP6OptClientId = scapy.layers.dhcp6.DHCP6OptClientId
DHCP6OptOptReq = scapy.layers.dhcp6.DHCP6OptOptReq
DHCP6OptElapsedTime = scapy.layers.dhcp6.DHCP6OptElapsedTime
DHCP6OptIA_NA = scapy.layers.dhcp6.DHCP6OptIA_NA
DUID_LL = scapy.layers.dhcp6.DUID_LL
DHCP6OptIfaceId = scapy.layers.dhcp6.DHCP6OptIfaceId

BROADCAST_MAC_V6 = '33:33:00:01:00:02'
BROADCAST_IP_V6 = 'ff02::1:2'
DHCP_CLIENT_PORT_V6 = 546
DHCP_SERVER_PORT_V6 = 547

dhcp6opts = {79: "OPTION_CLIENT_LINKLAYER_ADDR",  # RFC6939
             }


class _LLAddrField(MACField):
    pass


class DHCP6OptClientLinkLayerAddr(_DHCP6OptGuessPayload):  # RFC6939
    name = "DHCP6 Option - Client Link Layer address"
    fields_desc = [ShortEnumField("optcode", 79, dhcp6opts),
                   FieldLenField("optlen", None, length_of="clladdr",
                                 adjust=lambda pkt, x: x + 2),
                   ShortField("lltype", 1),  # ethernet
                   _LLAddrField("clladdr", ETHER_ANY)]

# Fixtures


@pytest.fixture(scope="module")
def setup(rand_selected_dut, rand_unselected_dut, tbinfo, vlan_name, topo_scenario, ptfadapter, ptfhost):
    """Setup various variables neede for different tests"""

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    is_dualtor = False
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = rand_selected_dut.get_dut_iface_mac(vlan_name)
        is_dualtor = True
    else:
        router_mac = rand_selected_dut.facts['router_mac']

    topo = tbinfo["topo"]["type"]
    if topo_scenario == "m0_vlan_scenario":
        topo = "m0_vlan"
    elif topo_scenario == "m0_l3_scenario":
        topo = "m0_l3"

    res = rand_selected_dut.shell('cat /sys/class/net/{}/address'.format(vlan_name))
    v4_vlan_mac = res['stdout']
    switch_loopback_ip = mg_facts['minigraph_lo_interfaces'][0]['addr']

    # Get the list of upstream/downstream ports
    downstream_ports = []
    upstream_ports = []
    downstream_port_ids = []
    upstream_port_ids = []

    if topo == "m0_l3":
        upstream_neigh_type = get_upstream_neigh_type(topo)
        downstream_neigh_type = get_downstream_neigh_type(topo)
        pytest_require(upstream_neigh_type is not None and downstream_neigh_type is not None,
                       "Cannot get neighbor type for unsupported topo: {}".format(topo))
        for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
            port_id = mg_facts["minigraph_ptf_indices"][interface]
            if downstream_neigh_type in neighbor["name"].upper():
                downstream_ports.append(interface)
                downstream_port_ids.append(port_id)
            elif upstream_neigh_type in neighbor["name"].upper():
                upstream_ports.append(interface)
                upstream_port_ids.append(port_id)
    else:
        downstream_ports = list(mg_facts["minigraph_vlans"][vlan_name]["members"])
        # Put all portchannel members into dst_ports
        upstream_port_ids = []
        upstream_ports = []
        for _, v in mg_facts['minigraph_portchannels'].items():
            for member in v['members']:
                upstream_port_ids.append(mg_facts['minigraph_ptf_indices'][member])
                upstream_ports.append(member)

    for port in downstream_ports:
        if port in mg_facts['minigraph_port_name_to_alias_map']:
            break
        else:
            continue
    block_src_port = port

    unblocked_src_port = downstream_ports[1]
    scale_ports = downstream_ports[:]
    block_src_port_indice = mg_facts['minigraph_ptf_indices'][block_src_port]
    block_src_port_alias = mg_facts['minigraph_port_name_to_alias_map'][block_src_port]
    unblocked_src_port_indice = mg_facts['minigraph_ptf_indices'][unblocked_src_port]
    scale_ports_indices = [mg_facts['minigraph_ptf_indices'][port_name] for port_name in scale_ports]

    # stop garp service for single tor
    if 'dualtor' not in tbinfo['topo']['name']:
        logging.info("Stopping GARP service on single tor")
        ptfhost.shell("supervisorctl stop garp_service", module_ignore_errors=True)

    # If running on a dual ToR testbed, any uplink for either ToR is an acceptable
    # source or destination port
    if 'dualtor' in tbinfo['topo']['name'] and rand_unselected_dut is not None:
        peer_mg_facts = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in list(peer_mg_facts['minigraph_neighbors'].items()):
            if topo == "t0" and "T1" in neighbor["name"]:
                port_id = peer_mg_facts["minigraph_ptf_indices"][interface]
                upstream_port_ids.append(port_id)

    # Generate destination IP's for scale test
    scale_dest_ips = {}
    for i in range(1, 75):
        ipv4_rule_name = "FORWARD_RULE_" + str(i)
        ipv6_rule_name = "V6_FORWARD_RULE_" + str(i)
        ipv4_address = DST_IP_FORWARDED_SCALE_PREFIX + str(i)
        ipv6_address = DST_IPV6_FORWARDED_SCALE_PREFIX + str(i) + "::1"
        scale_dest_ips[ipv4_rule_name] = ipv4_address
        scale_dest_ips[ipv6_rule_name] = ipv6_address

    vlan_ips = {}

    for vlan_interface_info_dict in mg_facts['minigraph_vlan_interfaces']:
        if netaddr.IPAddress(str(vlan_interface_info_dict['addr'])).version == 6:
            vlan_ips["V6"] = vlan_interface_info_dict['addr']
        elif netaddr.IPAddress(str(vlan_interface_info_dict['addr'])).version == 4:
            vlan_ips["V4"] = vlan_interface_info_dict['addr']

    config_facts = rand_selected_dut.config_facts(host=rand_selected_dut.hostname, source="running")['ansible_facts']

    vlans = config_facts['VLAN']
    topology = tbinfo['topo']['name']
    dut_mac = ''
    for vlan_details in list(vlans.values()):
        if 'dualtor' in topology:
            dut_mac = vlan_details['mac'].lower()
        else:
            dut_mac = rand_selected_dut.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0]
        break

    # Obtain MAC address of an uplink interface because vlan mac may be different than that of physical interfaces
    res = rand_selected_dut.shell('cat /sys/class/net/{}/address'.format(upstream_ports[0]))
    uplink_mac = res['stdout']

    """ update_payload method which is automatically called in ptfadapter on .send() or any .verify_packet() method
        is bugged for dhcp_discover packets.  Need to override it to do nothing."""

    def new_update_payload(pkt):
        return pkt

    ptfadapter.update_payload = new_update_payload

    setup_information = {
        "blocked_src_port_name": block_src_port,
        "blocked_src_port_indice": block_src_port_indice,
        "blocked_src_port_alias": block_src_port_alias,
        "unblocked_src_port_indice": unblocked_src_port_indice,
        "scale_port_names": scale_ports,
        "scale_port_indices": scale_ports_indices,
        "scale_dest_ips": scale_dest_ips,
        "dst_port_indices": upstream_port_ids,
        "router_mac": router_mac,
        "bind_ports": downstream_ports,
        "dut_mac": dut_mac,
        "vlan_ips": vlan_ips,
        "is_dualtor": is_dualtor,
        "switch_loopback_ip": switch_loopback_ip,
        "ipv4_vlan_mac": v4_vlan_mac,
        "uplink_mac": uplink_mac,
        "topo": topo,
    }

    return setup_information


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for acl config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Get config facts for the duthost"""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module")
def intfs_for_test(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo, config_facts):
    """Get the interfaces that will be used in our ARP test"""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    external_ports = [p for p in list(mg_facts['minigraph_ports'].keys()) if 'BP' not in p]
    ports = list(sorted(external_ports, key=lambda item: int(item.replace('Ethernet', ''))))

    is_storage_backend = 'backend' in tbinfo['topo']['name']

    if tbinfo['topo']['type'] == 't0':
        if is_storage_backend:
            vlan_sub_intfs = mg_facts['minigraph_vlan_sub_interfaces']
            intfs_to_t1 = [_['attachto'].split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0] for _ in vlan_sub_intfs]
            ports_for_test = [_ for _ in ports if _ not in intfs_to_t1]

            intf1 = ports_for_test[0]
        else:
            if 'PORTCHANNEL_MEMBER' in config_facts:
                portchannel_members = []
                for _, v in list(config_facts['PORTCHANNEL_MEMBER'].items()):
                    portchannel_members += list(v.keys())
                ports_for_test = [x for x in ports if x not in portchannel_members]
            else:
                ports_for_test = ports

            intf1 = ports_for_test[0]
    else:
        # Select first port that is admin 'up'
        intf_status = asic.show_interface(command='status')['ansible_facts']['int_status']

        intf1 = None
        for a_port in ports:
            if intf_status[a_port]['admin_state'] == 'up':
                if intf1 is None:
                    intf1 = a_port
                else:
                    break

        if intf1 is None:
            pytest.skip("Not enough interfaces on this host/asic (%s/%s) to support test." % (duthost.hostname,
                                                                                              asic.asic_index))

    logger.info("Selected int is {0}".format(intf1))

    intf1_indice = mg_facts['minigraph_ptf_indices'][intf1]

    return intf1, intf1_indice


@pytest.fixture(params=['IPV4', 'IPV6'])
def prepare_ptf_intf_and_ip(request, rand_selected_dut, config_facts, intfs_for_test, ptfhost):
    """
    Calculate IP addresses and interface to use for test.  Add the ip address to the ptf port.
    """

    ip_type = request.param

    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")

    intf1_name, intf1_index = intfs_for_test
    ptf_intf_name = ptf_ports_available_in_topo[intf1_index]

    # Calculate the IPv6 address to assign to the PTF port
    vlan_addrs = list(list(config_facts['VLAN_INTERFACE'].items())[0][1].keys())
    intf_ipv6_addr = None
    intf_ipv4_addr = None

    for addr in vlan_addrs:
        try:
            if type(ip_network(addr, strict=False)) is IPv6Network:
                intf_ipv6_addr = ip_network(addr, strict=False)
            elif type(ip_network(addr, strict=False)) is IPv4Network:
                intf_ipv4_addr = ip_network(addr, strict=False)
        except ValueError:
            continue

    # Increment address by 3 to offset it from the intf on which the address may be learned
    if intf_ipv4_addr is not None:
        ptf_intf_ipv4_addr = increment_ipv4_addr(intf_ipv4_addr.network_address, incr=3)
    else:
        ptf_intf_ipv4_addr = None

    if intf_ipv6_addr is not None:
        ptf_intf_ipv6_addr = increment_ipv6_addr(intf_ipv6_addr.network_address, incr=3)
    else:
        ptf_intf_ipv6_addr = None

    logger.info("Using {}, {}, and PTF interface {}".format(ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name))

    if ip_type == "IPV4":
        ip_for_test = ptf_intf_ipv4_addr
        add_command = "ifconfig {} {}".format(ptf_intf_name, ip_for_test)
        remove_command = "ifconfig {} 0.0.0.0".format(ptf_intf_name)
        clear_command = "sonic-clear arp"
    elif ip_type == "IPV6":
        ip_for_test = ptf_intf_ipv6_addr
        add_command = "ifconfig {} inet6 add {}".format(ptf_intf_name, ip_for_test)
        remove_command = "ifconfig {} inet6 del {}".format(ptf_intf_name, ip_for_test)
        clear_command = "sonic-clear ndp"

    ptfhost.shell(add_command)

    rand_selected_dut.shell(clear_command)

    # give table time to clear before starting test

    time.sleep(10)

    yield ip_for_test, ptf_intf_name, intf1_index, intf1_name

    ptfhost.shell(remove_command)

    rand_selected_dut.shell(clear_command)


def generate_link_local_addr(mac):
    """Generate ipv6 link local"""
    parts = mac.split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::{}".format(":".join(ipv6Parts))
    return ipv6


def generate_dhcp_packets(rand_selected_dut, setup, ptfadapter):
    """Generate a DHCP Discovery packet, as well as the expected relay packet"""
    # Create discover packet

    client_mac = ptfadapter.dataplane.get_mac(0, setup["blocked_src_port_indice"]).decode()

    my_chaddr = binascii.unhexlify(client_mac.replace(':', ''))
    my_chaddr += b'\x00\x00\x00\x00\x00\x00'

    discover_packet = testutils.dhcp_discover_packet(
        eth_client=client_mac, set_broadcast_bit=True)

    discover_packet[packet.Ether].dst = BROADCAST_MAC
    discover_packet[packet.IP].sport = DHCP_CLIENT_PORT

    # testutils.dhcp_discover_packet is bugged and forms chaddr wrong.  We need to overwrite it.

    discover_packet[packet.BOOTP].chaddr = my_chaddr

    # Create discover relayed packet

    ether = packet.Ether(dst=BROADCAST_MAC, src=setup["uplink_mac"], type=0x0800)
    ip = packet.IP(src=DEFAULT_ROUTE_IP, dst=BROADCAST_IP, len=328, ttl=64)
    udp = packet.UDP(sport=DHCP_SERVER_PORT, dport=DHCP_SERVER_PORT, len=308)
    bootp = packet.BOOTP(op=1,
                         htype=1,
                         hlen=6,
                         hops=1,
                         xid=0,
                         secs=0,
                         flags=0x8000,
                         ciaddr=DEFAULT_ROUTE_IP,
                         yiaddr=DEFAULT_ROUTE_IP,
                         siaddr=DEFAULT_ROUTE_IP,
                         giaddr=setup["vlan_ips"]["V4"] if not setup["is_dualtor"] else setup["switch_loopback_ip"],
                         chaddr=my_chaddr)
    circuit_id_string = rand_selected_dut.hostname + ":" + setup["blocked_src_port_alias"]
    option82 = struct.pack('BB', 1, len(circuit_id_string))
    option82 += circuit_id_string.encode('utf-8')
    remote_id_string = setup["ipv4_vlan_mac"]
    option82 += struct.pack('BB', 2, len(remote_id_string))
    option82 += remote_id_string.encode('utf-8')
    if setup["is_dualtor"]:
        link_selection = bytes(list(map(int, setup["vlan_ips"]["V4"].split('.'))))
        option82 += struct.pack('BB', 5, 4)
        option82 += link_selection
    bootp /= packet.DHCP(options=[('message-type', 'discover'),
                                  (82, option82),
                                  ('end')])
    # If our bootp layer is too small, pad it
    pad_bytes = DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
    if pad_bytes > 0:
        bootp /= packet.PADDING('\x00' * pad_bytes)

    discover_relay_pkt = ether / ip / udp / bootp

    # Mask off fields we don't care to match

    masked_discover = Mask(discover_relay_pkt)

    masked_discover.set_do_not_care_scapy(packet.Ether, "dst")

    masked_discover.set_do_not_care_scapy(packet.IP, "version")
    masked_discover.set_do_not_care_scapy(packet.IP, "ihl")
    masked_discover.set_do_not_care_scapy(packet.IP, "tos")
    masked_discover.set_do_not_care_scapy(packet.IP, "len")
    masked_discover.set_do_not_care_scapy(packet.IP, "id")
    masked_discover.set_do_not_care_scapy(packet.IP, "flags")
    masked_discover.set_do_not_care_scapy(packet.IP, "frag")
    masked_discover.set_do_not_care_scapy(packet.IP, "ttl")
    masked_discover.set_do_not_care_scapy(packet.IP, "proto")
    masked_discover.set_do_not_care_scapy(packet.IP, "chksum")
    masked_discover.set_do_not_care_scapy(packet.IP, "src")
    masked_discover.set_do_not_care_scapy(packet.IP, "dst")
    masked_discover.set_do_not_care_scapy(packet.IP, "options")

    masked_discover.set_do_not_care_scapy(packet.UDP, "chksum")
    masked_discover.set_do_not_care_scapy(packet.UDP, "len")

    masked_discover.set_do_not_care_scapy(packet.BOOTP, "sname")
    masked_discover.set_do_not_care_scapy(packet.BOOTP, "file")

    return discover_packet, masked_discover


def generate_dhcpv6_packets(setup, ptfadapter):
    """Generate a DHCPv6 solicit packet, as well as the expected relay packet"""

    client_mac = ptfadapter.dataplane.get_mac(0, setup["blocked_src_port_indice"]).decode()
    client_link_local = generate_link_local_addr(client_mac)

    solicit_packet = packet.Ether(src=client_mac, dst=BROADCAST_MAC_V6)
    solicit_packet /= IPv6(src=client_link_local, dst=BROADCAST_IP_V6)
    solicit_packet /= packet.UDP(sport=DHCP_CLIENT_PORT_V6, dport=DHCP_SERVER_PORT_V6)
    solicit_packet /= DHCP6_Solicit(trid=12345)
    solicit_packet /= DHCP6OptClientId(duid=DUID_LL(lladdr=client_mac))
    solicit_packet /= DHCP6OptIA_NA()
    solicit_packet /= DHCP6OptOptReq(reqopts=[23, 24, 29])
    solicit_packet /= DHCP6OptElapsedTime(elapsedtime=0)

    # build expected relay forward packet

    solicit_relay_forward_packet = packet.Ether(src=setup["uplink_mac"])
    solicit_relay_forward_packet /= IPv6()
    solicit_relay_forward_packet /= packet.UDP(
        sport=DHCP_SERVER_PORT_V6, dport=DHCP_SERVER_PORT_V6)
    solicit_relay_forward_packet /= DHCP6_RelayForward(msgtype=12,
                                                       linkaddr=setup["vlan_ips"]["V6"],
                                                       peeraddr=client_link_local)
    solicit_relay_forward_packet /= DHCP6OptRelayMsg(message=[DHCP6_Solicit(trid=12345) /
                                                              DHCP6OptClientId(duid=DUID_LL(lladdr=client_mac)) /
                                                              DHCP6OptIA_NA()/DHCP6OptOptReq(reqopts=[23, 24, 29]) /
                                                              DHCP6OptElapsedTime(elapsedtime=0)])
    if setup["is_dualtor"]:
        solicit_relay_forward_packet /= DHCP6OptIfaceId(ifaceid=socket.inet_pton(socket.AF_INET6,
                                                                                 setup["vlan_ips"]["V6"]))
    solicit_relay_forward_packet /= DHCP6OptClientLinkLayerAddr()

    masked_packet = Mask(solicit_relay_forward_packet)
    masked_packet.set_do_not_care_scapy(packet.Ether, "dst")
    masked_packet.set_do_not_care_scapy(packet.Ether, "src")
    masked_packet.set_do_not_care_scapy(IPv6, "src")
    masked_packet.set_do_not_care_scapy(IPv6, "dst")
    masked_packet.set_do_not_care_scapy(IPv6, "fl")
    masked_packet.set_do_not_care_scapy(IPv6, "tc")
    masked_packet.set_do_not_care_scapy(IPv6, "plen")
    masked_packet.set_do_not_care_scapy(IPv6, "nh")
    masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
    masked_packet.set_do_not_care_scapy(packet.UDP, "len")
    masked_packet.set_do_not_care_scapy(
        scapy.layers.dhcp6.DHCP6_RelayForward, "linkaddr")
    masked_packet.set_do_not_care_scapy(
        DHCP6OptClientLinkLayerAddr, "clladdr")

    return solicit_packet, masked_packet


def dynamic_acl_send_and_verify_dhcp_packets(rand_selected_dut, setup, ptfadapter):
    """Send and verify proper relay of dhcp and dhcpv6 packets"""

    dhcp_discovery, expected_dhcp_discovery = generate_dhcp_packets(rand_selected_dut, setup, ptfadapter)

    dhcpv6_solicit, expected_dhcpv6_solicit = generate_dhcpv6_packets(setup, ptfadapter)

    ptfadapter.dataplane.flush()

    testutils.send(ptfadapter, setup["blocked_src_port_indice"], dhcp_discovery)
    verify_expected_packet_behavior(expected_dhcp_discovery, ptfadapter, setup, expect_drop=False)

    ptfadapter.dataplane.flush()

    testutils.send(ptfadapter, setup["blocked_src_port_indice"], dhcpv6_solicit)
    verify_expected_packet_behavior(expected_dhcpv6_solicit, ptfadapter, setup, expect_drop=False)


def verify_expected_packet_behavior(exp_pkt, ptfadapter, setup, expect_drop):
    """Verify that a packet was either dropped or forwarded"""
    if expect_drop:
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["dst_port_indices"])
    else:
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=setup["dst_port_indices"], timeout=20)


def generate_packets(setup, dst_ip=DST_IP_FORWARDED_ORIGINAL, dst_ipv6=DST_IPV6_FORWARDED_ORIGINAL):
    """Generate packets that match the destination IP of given ips.
    If no IP is given, default to our original forwarding ips"""

    packets = {}

    packets["IPV4"] = testutils.simple_tcp_packet(eth_dst=setup["router_mac"],
                                                  ip_src=IP_SOURCE,
                                                  ip_dst=dst_ip,
                                                  ip_ttl=64)

    packets["IPV6"] = testutils.simple_tcpv6_packet(eth_dst=setup["router_mac"],
                                                    ipv6_src=IPV6_SOURCE,
                                                    ipv6_dst=dst_ipv6)

    return packets


def build_exp_pkt(input_pkt):
    """
    Generate the expected packet for given packet
    """
    pkt_copy = input_pkt.copy()
    if pkt_copy.haslayer('IP'):
        pkt_copy['IP'].ttl -= 1
    exp_pkt = Mask(pkt_copy)
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    if input_pkt.haslayer('IP'):
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(packet.IPv6, "hlim")

    return exp_pkt


@pytest.fixture(scope="module")
def dynamic_acl_create_table_type(rand_selected_dut):
    """Create a new ACL table type that can be used"""

    output = load_and_apply_json_patch(rand_selected_dut, CREATE_CUSTOM_TABLE_TYPE_FILE)

    expect_op_success(rand_selected_dut, output)

    yield

    dynamic_acl_remove_table_type(rand_selected_dut)


@pytest.fixture(scope="module")
def dynamic_acl_create_table(rand_selected_dut, dynamic_acl_create_table_type, setup):
    """Create a new ACL table type that can be used"""

    extra_vars = {
        'bind_ports': setup['bind_ports']
        }

    output = format_and_apply_template(rand_selected_dut, CREATE_CUSTOM_TABLE_TEMPLATE, extra_vars)

    expected_bindings = setup["bind_ports"]
    expected_first_line = ["DYNAMIC_ACL_TABLE",
                           "DYNAMIC_ACL_TABLE_TYPE",
                           setup["bind_ports"][0],
                           "DYNAMIC_ACL_TABLE",
                           "ingress",
                           "Active"]

    expect_op_success(rand_selected_dut, output)

    expect_acl_table_match_multiple_bindings(rand_selected_dut,
                                             "DYNAMIC_ACL_TABLE",
                                             expected_first_line,
                                             expected_bindings)

    yield

    dynamic_acl_remove_table(rand_selected_dut)


def dynamic_acl_create_forward_rules(duthost):
    """Create forward ACL rules"""

    IPV4_SUBNET = DST_IP_FORWARDED_ORIGINAL + "/32"
    IPV6_SUBNET = DST_IPV6_FORWARDED_ORIGINAL + "/128"

    extra_vars = {
        'ipv4_subnet': IPV4_SUBNET,
        'ipv6_subnet': IPV6_SUBNET
        }

    output = format_and_apply_template(duthost, CREATE_FORWARD_RULES_TEMPLATE, extra_vars)

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP: " + IPV4_SUBNET, "Active"]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6: " + IPV6_SUBNET, "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
    expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)


def dynamic_acl_create_secondary_drop_rule(duthost, setup, blocked_port_name=None):
    """Create a drop rule in the format required when an ACL table has rules in it already"""

    blocked_name = setup["blocked_src_port_name"] if blocked_port_name is None else blocked_port_name

    extra_vars = {
        'blocked_port': blocked_name
    }

    output = format_and_apply_template(duthost, CREATE_SECONDARY_DROP_RULE_TEMPLATE, extra_vars)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "RULE_3",
                             "9995",
                             "DROP",
                             "IN_PORTS: " + blocked_name,
                             "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)


def dynamic_acl_create_drop_rule_initial(duthost, setup):
    """Create a drop rule in the format required when an ACL table does not have any rules in it yet"""

    extra_vars = {
        'blocked_port': setup["blocked_src_port_name"]
    }

    output = format_and_apply_template(duthost, CREATE_INITIAL_DROP_RULE_TEMPLATE, extra_vars)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "RULE_3",
                             "9997",
                             "DROP",
                             "IN_PORTS: " + setup["blocked_src_port_name"],
                             "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)


def dynamic_acl_create_three_drop_rules(duthost, setup):
    """Create 3 drop rules in the format required when an ACL table does not have any rules in it yet"""

    if len(setup["scale_port_names"]) < 3:
        pytest.skip("Not enough downstream ports to create three drop rules, skipping this test")

    extra_vars = {
        'blocked_port_1': setup["scale_port_names"][0],
        'blocked_port_2': setup["scale_port_names"][1],
        'blocked_port_3': setup["scale_port_names"][2]

    }

    output = format_and_apply_template(duthost, CREATE_THREE_DROP_RULES_TEMPLATE, extra_vars)

    expected_rule_3_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_3",
                               "9997",
                               "DROP",
                               "IN_PORTS: " + extra_vars['blocked_port_1'],
                               "Active"]
    expected_rule_4_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_4",
                               "9996",
                               "DROP",
                               "IN_PORTS: " + extra_vars['blocked_port_2'],
                               "Active"]
    expected_rule_5_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_5",
                               "9995",
                               "DROP",
                               "IN_PORTS: " + extra_vars['blocked_port_3'],
                               "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_3", expected_rule_3_content)
    expect_acl_rule_match(duthost, "RULE_4", expected_rule_4_content)
    expect_acl_rule_match(duthost, "RULE_5", expected_rule_5_content)


def dynamic_acl_create_arp_forward_rule(duthost):
    """Create an ARP forward rule with the highest priority"""

    output = load_and_apply_json_patch(duthost, CREATE_ARP_FORWARD_RULE_FILE)

    expect_op_success(duthost, output)

    expected_rule_content = ["DYNAMIC_ACL_TABLE", "ARP_RULE", "9997", "FORWARD", "ETHER_TYPE: 0x0806", "Active"]

    expect_acl_rule_match(duthost, "ARP_RULE", expected_rule_content)


def dynamic_acl_create_ndp_forward_rule(duthost):
    "Create an NDP forwarding rule with high priority"

    output = load_and_apply_json_patch(duthost, CREATE_NDP_FORWARD_RULE_FILE)

    expect_op_success(duthost, output)

    expected_rule_content = ["DYNAMIC_ACL_TABLE", "NDP_RULE", "9996", "FORWARD", "IP_PROTOCOL: 58", "Active"]

    expect_acl_rule_match(duthost, "NDP_RULE", expected_rule_content)


def dynamic_acl_create_dhcp_forward_rule(duthost):
    """Create DHCP forwarding rules"""

    output = load_and_apply_json_patch(duthost, CREATE_DHCP_FORWARD_RULE_FILE)

    expect_op_success(duthost, output)

    expected_v6_rule_content = ["DYNAMIC_ACL_TABLE",
                                "DHCPV6_RULE", "9998",
                                "FORWARD",
                                "IP_PROTOCOL: 17",
                                "L4_DST_PORT_RANGE: 547-548",
                                "ETHER_TYPE: 0x86DD",
                                "Active"]

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "DHCP_RULE", "9999",
                             "FORWARD",
                             "IP_PROTOCOL: 17",
                             "L4_DST_PORT: 67",
                             "ETHER_TYPE: 0x0800",
                             "Active"]

    expect_acl_rule_match(duthost, "DHCP_RULE", expected_rule_content)

    expect_acl_rule_match(duthost, "DHCPV6_RULE", expected_v6_rule_content)


def dynamic_acl_verify_packets(setup, ptfadapter, packets, packets_dropped, src_port=None):
    """Verify that the given packets are either dropped/forwarded correctly

    Args:
        packets: the packets that we are sending
        packets_dropped: whether or not we are expecting to drop or forward these packets
        src_port: optionally give a different src_port than what we have in setup"""
    if packets_dropped:
        action_type = "dropped"
    else:
        action_type = "forwarded"

    if src_port is None:
        src_port = setup["blocked_src_port_indice"]

    for rule, pkt in list(packets.items()):
        logger.info("Testing that {} packets are correctly {}".format(rule, action_type))
        exp_pkt = build_exp_pkt(pkt)
        # Send and verify packet
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt, port_id=src_port)
        verify_expected_packet_behavior(exp_pkt, ptfadapter, setup, expect_drop=packets_dropped)


def dynamic_acl_remove_third_drop_rule(duthost):
    """Remove the third drop rule of the three created for the drop rule removal test"""

    extra_vars = {
        'rule_name': "RULE_5"
        }

    output = format_and_apply_template(duthost, REMOVE_RULE_TEMPLATE, extra_vars)
    expect_op_success(duthost, output)

    expect_acl_rule_removed(duthost, "RULE_5")


def dynamic_acl_replace_nonexistent_rule(duthost):
    """Verify that replacing a non-existent rule fails"""

    output = load_and_apply_json_patch(duthost, REPLACE_NONEXISTENT_RULE_FILE)

    expect_op_failure(output)


def dynamic_acl_replace_rules(duthost):
    """
    Replace our forward rules on the ACL table"""

    REPLACEMENT_IPV4_SUBNET = DST_IP_FORWARDED_REPLACEMENT + "/32"
    REPLACEMENT_IPV6_SUBNET = DST_IPV6_FORWARDED_REPLACEMENT + "/128"

    extra_vars = {
        'ipv4_subnet': REPLACEMENT_IPV4_SUBNET,
        'ipv6_subnet': REPLACEMENT_IPV6_SUBNET
        }

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_1",
                               "9999",
                               "FORWARD",
                               "DST_IP: " + REPLACEMENT_IPV4_SUBNET,
                               "Active"]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_2",
                               "9998",
                               "FORWARD",
                               "DST_IPV6: " + REPLACEMENT_IPV6_SUBNET,
                               "Active"]

    output = format_and_apply_template(duthost, REPLACE_RULES_TEMPLATE, extra_vars)

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
    expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)


def dynamic_acl_apply_forward_scale_rules(duthost, setup):
    """Apply a large amount of forward rules to the duthost"""

    priority = MAX_IP_RULE_PRIORITY
    value_dict = {}
    expected_rule_contents = {}

    for rule_name, dest_ip in setup["scale_dest_ips"].items():
        if "V6" in rule_name:
            subnet = dest_ip + "/128"
            dst_type = "DST_IPV6"
        else:
            subnet = dest_ip + "/32"
            dst_type = "DST_IP"
        full_rule_name = "DYNAMIC_ACL_TABLE|" + rule_name
        rule_vals = {
            dst_type: subnet,
            "PRIORITY": str(priority),
            "PACKET_ACTION": "FORWARD"
        }
        value_dict[full_rule_name] = rule_vals
        expected_content = ["DYNAMIC_ACL_TABLE",
                            rule_name,
                            str(priority),
                            "FORWARD",
                            dst_type + ": " + subnet,
                            "Active"]
        expected_rule_contents[rule_name] = expected_content
        priority -= 1

    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": value_dict
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for rule_name, expected_content in expected_rule_contents.items():
            expect_acl_rule_match(duthost, rule_name, expected_content)

    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_apply_drop_scale_rules(duthost, setup):
    """Apply a large amount of drop rules to the duthost"""

    priority = MAX_DROP_RULE_PRIORITY
    json_patch = []

    rule_name = "DROP_RULE"
    full_rule_name = "/ACL_RULE/DYNAMIC_ACL_TABLE|"+rule_name
    all_ports = ",".join(setup["scale_port_names"])
    rule_vals = {
        "PRIORITY": str(priority),
        "PACKET_ACTION": "DROP",
        "IN_PORTS": all_ports
    }
    patch = {
        "op": "add",
        "path": full_rule_name,
        "value": rule_vals
    }
    json_patch.append(patch)
    expected_content = ["DYNAMIC_ACL_TABLE", rule_name, str(priority), "DROP", "IN_PORTS: " + all_ports, "Active"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, rule_name, expected_content)

    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_remove_ip_forward_rule(duthost, ip_type):
    """Remove selected forward rule from the acl table"""

    if ip_type == "IPV4":
        rule_name = "RULE_1"
    else:
        rule_name = "RULE_2"

    extra_vars = {
        "rule_name": rule_name
    }

    output = format_and_apply_template(duthost, REMOVE_RULE_TEMPLATE, extra_vars)

    expect_op_success(duthost, output)

    expect_acl_rule_removed(duthost, rule_name)


def dynamic_acl_remove_table(duthost):
    """Remove an ACL Table Type from the duthost"""

    output = load_and_apply_json_patch(duthost, REMOVE_TABLE_FILE)

    expect_op_success(duthost, output)


def dynamic_acl_remove_nonexistent_table(duthost):
    """Remove a nonexistent ACL Table from the duthost, verify it fails"""

    output = load_and_apply_json_patch(duthost, REMOVE_NONEXISTENT_TABLE_FILE)

    expect_op_failure(output)


def dynamic_acl_remove_table_type(duthost):
    """Remove an ACL Table definition from the duthost"""

    output = load_and_apply_json_patch(duthost, REMOVE_TABLE_TYPE_FILE)

    expect_op_success(duthost, output)


def test_gcu_acl_arp_rule_creation(rand_selected_dut,
                                   ptfadapter,
                                   setup,
                                   dynamic_acl_create_table,
                                   prepare_ptf_intf_and_ip,
                                   toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Test that we can create a blanket ARP/NDP packet forwarding rule with GCU, and that ARP/NDP packets
    are correctly forwarded while all others are dropped."""

    ip_address_for_test, _, ptf_intf_index, port_name = prepare_ptf_intf_and_ip

    is_ipv4_test = type(ip_network(ip_address_for_test, strict=False)) is IPv4Network

    if is_ipv4_test:
        show_cmd = "show arp"
        ipv6_ping_option = ""
        dynamic_acl_create_arp_forward_rule(rand_selected_dut)
    else:
        show_cmd = "nbrshow -6 -ip"
        ipv6_ping_option = "-6"
        dynamic_acl_create_ndp_forward_rule(rand_selected_dut)

    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup, port_name)

    rand_selected_dut.shell("ping -c 3 {} {}".format(ipv6_ping_option, ip_address_for_test), module_ignore_errors=True)

    time.sleep(10)
    output = rand_selected_dut.show_and_parse("{} {}".format(show_cmd, ip_address_for_test))

    pytest_assert(len(output) >= 1, "MAC for {} was not learned!".format(ip_address_for_test))
    pytest_assert(output[0]["iface"] == port_name, "MAC was learned for wrong port!")

    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True,
                               src_port=ptf_intf_index)


def test_gcu_acl_dhcp_rule_creation(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table,
                                    toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Verify that DHCP and DHCPv6 forwarding rules can be created, and that dhcp packets are properly forwarded
    whereas others are dropped"""

    if setup["topo"] == "m0_l3":
        pytest.skip("M0 L3 sets up destination ports differently than what we want for DHCP, skipping test.")

    dynamic_acl_create_dhcp_forward_rule(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)

    dynamic_acl_send_and_verify_dhcp_packets(rand_selected_dut, setup, ptfadapter)

    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)


def test_gcu_acl_drop_rule_creation(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table,
                                    toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Test that we can create a drop rule via GCU, and that once this drop rule is in place packets
    that match the drop rule are dropped and packets that do not match the drop rule are forwarded"""

    dynamic_acl_create_drop_rule_initial(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=False,
                               src_port=setup["unblocked_src_port_indice"])


def test_gcu_acl_drop_rule_removal(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table,
                                   toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Test that once a drop rule is removed, packets that were previously being dropped are now forwarded"""

    dynamic_acl_create_three_drop_rules(rand_selected_dut, setup)
    dynamic_acl_remove_third_drop_rule(rand_selected_dut)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=False,
                               src_port=setup["scale_port_indices"][2])


def test_gcu_acl_forward_rule_priority_respected(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table,
                                                 toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Test that forward rules and drop rules can be created at the same time, with the forward rules having
    higher priority than drop.  Then, perform a traffic test to confirm that packets that match both the forward
    and drop rules are correctly forwarded, as the forwarding rules have higher priority"""

    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup, ptfadapter, packets=generate_packets(setup), packets_dropped=False)
    dynamic_acl_verify_packets(setup, ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)


def test_gcu_acl_forward_rule_replacement(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table,
                                          toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Test that forward rules can be created, and then afterwards can have their match pattern updated to a new value.
    Confirm that packets sent that match this new value are correctly forwarded, and that packets that are sent that
    match the old, replaced value are correctly dropped."""

    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_replace_rules(rand_selected_dut)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup,
                                                        DST_IP_FORWARDED_REPLACEMENT,
                                                        DST_IPV6_FORWARDED_REPLACEMENT),
                               packets_dropped=False)
    dynamic_acl_verify_packets(setup, ptfadapter, packets=generate_packets(setup), packets_dropped=True)


@pytest.mark.parametrize("ip_type", ["IPV4", "IPV6"])
def test_gcu_acl_forward_rule_removal(rand_selected_dut, ptfadapter, setup, ip_type, dynamic_acl_create_table,
                                      toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Test that if a forward rule is created, and then removed, that packets associated with that rule are properly
    no longer forwarded, and packets associated with the remaining rule are forwarded"""
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_remove_ip_forward_rule(rand_selected_dut, ip_type)
    forward_packets = generate_packets(setup)
    drop_packets = forward_packets.copy()
    if ip_type == "IPV4":
        other_type = "IPV6"
    else:
        other_type = "IPV4"
    # generate_packets returns ipv4 and ipv6 packets. remove vals from two dicts so that only correct packets remain
    drop_packets.pop(other_type)
    forward_packets.pop(ip_type)
    dynamic_acl_verify_packets(setup, ptfadapter, drop_packets, packets_dropped=True)
    dynamic_acl_verify_packets(setup, ptfadapter, forward_packets, packets_dropped=False)


def test_gcu_acl_scale_rules(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table,
                             toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Perform a scale test, creating 150 forward rules with top priority,
    and then creating a drop rule for every single VLAN port on our device.
    Select any one of our blocked ports, as well as the ips for two of our forward rules,
    and confirm that packet forwarding and dropping works as expected even with this large amount of rules"""

    dynamic_acl_apply_forward_scale_rules(rand_selected_dut, setup)
    dynamic_acl_apply_drop_scale_rules(rand_selected_dut, setup)

    # select one of our src ports blocked by these scale rules
    blocked_scale_port = setup["scale_port_indices"][0]

    # select ipv4 and ipv6 destination ips from our forwarding rules
    v4_dest = setup["scale_dest_ips"]["FORWARD_RULE_10"]
    v6_dest = setup["scale_dest_ips"]["V6_FORWARD_RULE_10"]

    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               generate_packets(setup, v4_dest, v6_dest),
                               packets_dropped=False,
                               src_port=blocked_scale_port)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True,
                               src_port=blocked_scale_port)


def test_gcu_acl_nonexistent_rule_replacement(rand_selected_dut,
                                              toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Confirm that replacing a nonexistent rule results in operation failure"""
    dynamic_acl_replace_nonexistent_rule(rand_selected_dut)


def test_gcu_acl_nonexistent_table_removal(rand_selected_dut,
                                           toggle_all_simulator_ports_to_rand_selected_tor):  # noqa F811
    """Confirm that removing a nonexistent table results in operation failure"""
    dynamic_acl_remove_nonexistent_table(rand_selected_dut)
