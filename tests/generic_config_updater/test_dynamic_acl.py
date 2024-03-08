import logging
import pytest

from tests.common.helpers.assertions import pytest_require

from ptf.mask import Mask
import ptf.packet as scapy

from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, \
                      ICMPv6NDOptSrcLLAddr, in6_getnsmac, \
                      in6_getnsma, inet_pton, inet_ntop, socket

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

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)

CREATE_CUSTOM_TABLE_TYPE_FILE = "create_custom_table_type.json"
CREATE_CUSTOM_TABLE_TEMPLATE = "create_custom_table.j2"
CREATE_FORWARD_RULES_TEMPLATE = "create_forward_rules.j2"
CREATE_INITIAL_DROP_RULE_TEMPLATE = "create_initial_drop_rule.j2"
CREATE_SECONDARY_DROP_RULE_TEMPLATE = "create_secondary_drop_rule.j2"
CREATE_THREE_DROP_RULES_TEMPLATE = "create_three_drop_rules.j2"
CREATE_ARP_FORWARD_RULE_FILE = "create_arp_forward_rule.json"
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


@pytest.fixture(scope="module")
def setup(rand_selected_dut, tbinfo, vlan_name):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = rand_selected_dut.get_dut_iface_mac(vlan_name)
    else:
        router_mac = rand_selected_dut.facts['router_mac']

    list_ports = mg_facts["minigraph_vlans"][vlan_name]["members"]

    # Get all vlan ports
    vlan_ports = list(mg_facts['minigraph_vlans'].values())[0]['members']
    block_src_port = vlan_ports[0]
    unblocked_src_port = vlan_ports[1]
    scale_ports = vlan_ports[:]
    block_src_port_indice = mg_facts['minigraph_ptf_indices'][block_src_port]
    unblocked_src_port_indice = mg_facts['minigraph_ptf_indices'][unblocked_src_port]
    scale_ports_indices = [mg_facts['minigraph_ptf_indices'][port_name] for port_name in scale_ports]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])

    # Generate destination IP's for scale test
    scale_dest_ips = {}
    for i in range(1, 75):
        ipv4_rule_name = "FORWARD_RULE_" + str(i)
        ipv6_rule_name = "V6_FORWARD_RULE_" + str(i)
        ipv4_address = DST_IP_FORWARDED_SCALE_PREFIX + str(i)
        ipv6_address = DST_IPV6_FORWARDED_SCALE_PREFIX + str(i) + "::1"
        scale_dest_ips[ipv4_rule_name] = ipv4_address
        scale_dest_ips[ipv6_rule_name] = ipv6_address

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

    setup_information = {
        "blocked_src_port_name": block_src_port,
        "blocked_src_port_indice": block_src_port_indice,
        "unblocked_src_port_indice": unblocked_src_port_indice,
        "scale_port_names": scale_ports,
        "scale_port_indices": scale_ports_indices,
        "scale_dest_ips": scale_dest_ips,
        "dst_port_indices": dst_port_indices,
        "router_mac": router_mac,
        "bind_ports": list_ports,
        "dut_mac": dut_mac,
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


@pytest.fixture
def proxy_arp_enabled(rand_selected_dut, config_facts):
    """
    Tries to enable proxy ARP for each VLAN on the ToR

    Also checks CONFIG_DB to see if the attempt was successful

    During teardown, restores the original proxy ARP setting

    Yields:
        (bool) True if proxy ARP was enabled for all VLANs,
               False otherwise
    """
    duthost = rand_selected_dut
    pytest_require(duthost.has_config_subcommand('config vlan proxy_arp'), "Proxy ARP command does not exist on device")

    proxy_arp_check_cmd = 'sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|Vlan{}" proxy_arp'
    proxy_arp_config_cmd = 'config vlan proxy_arp {} {}'
    vlans = config_facts['VLAN']
    vlan_ids = [vlans[vlan]['vlanid'] for vlan in list(vlans.keys())]
    old_proxy_arp_vals = {}
    new_proxy_arp_vals = []

    # Enable proxy ARP/NDP for the VLANs on the DUT
    for vid in vlan_ids:
        old_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        old_proxy_arp_vals[vid] = old_proxy_arp_res['stdout']

        duthost.shell(proxy_arp_config_cmd.format(vid, 'enabled'))

        logger.info("Enabled proxy ARP for Vlan{}".format(vid))
        new_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        new_proxy_arp_vals.append(new_proxy_arp_res['stdout'])

    yield all('enabled' in val for val in new_proxy_arp_vals)

    proxy_arp_del_cmd = 'sonic-db-cli CONFIG_DB HDEL "VLAN_INTERFACE|Vlan{}" proxy_arp'
    for vid, proxy_arp_val in list(old_proxy_arp_vals.items()):
        if 'enabled' not in proxy_arp_val:
            # Delete the DB entry instead of using the config command to satisfy check_dut_health_status
            duthost.shell(proxy_arp_del_cmd.format(vid))


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module")
def intfs_for_test(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo, config_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    external_ports = [p for p in list(mg_facts['minigraph_ports'].keys()) if 'BP' not in p]
    ports = list(sorted(external_ports, key=lambda item: int(item.replace('Ethernet', ''))))
    po1 = None
    po2 = None

    is_storage_backend = 'backend' in tbinfo['topo']['name']

    if tbinfo['topo']['type'] == 't0':
        if is_storage_backend:
            vlan_sub_intfs = mg_facts['minigraph_vlan_sub_interfaces']
            intfs_to_t1 = [_['attachto'].split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0] for _ in vlan_sub_intfs]
            ports_for_test = [_ for _ in ports if _ not in intfs_to_t1]

            intf1 = ports_for_test[0]
            intf2 = ports_for_test[1]
        else:
            if 'PORTCHANNEL_MEMBER' in config_facts:
                portchannel_members = []
                for _, v in list(config_facts['PORTCHANNEL_MEMBER'].items()):
                    portchannel_members += list(v.keys())
                ports_for_test = [x for x in ports if x not in portchannel_members]
            else:
                ports_for_test = ports

            # Select two interfaces for testing which are not in portchannel
            intf1 = ports_for_test[0]
            intf2 = ports_for_test[1]

    logger.info("Selected ints are {0} and {1}".format(intf1, intf2))

    if tbinfo['topo']['type'] == 't1' and is_storage_backend:
        intf1_indice = mg_facts['minigraph_ptf_indices'][intf1.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0]]
        intf2_indice = mg_facts['minigraph_ptf_indices'][intf2.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0]]
    else:
        intf1_indice = mg_facts['minigraph_ptf_indices'][intf1]
        intf2_indice = mg_facts['minigraph_ptf_indices'][intf2]

    asic.config_ip_intf(intf1, "10.10.1.2/28", "add")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "add")

    yield intf1, intf2, intf1_indice, intf2_indice

    asic.config_ip_intf(intf1, "10.10.1.2/28", "remove")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "remove")

    if tbinfo['topo']['type'] != 't0':
        if po1:
            asic.config_portchannel_member(po1, intf1, "add")
        if po2:
            asic.config_portchannel_member(po2, intf2, "add")


@pytest.fixture(scope='module')
def ip_and_intf_info(config_facts, intfs_for_test, ptfhost, ptfadapter):
    """
    Calculate IP addresses and interface to use for test
    """
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")

    intf1_name, _, intf1_index, _, = intfs_for_test
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
        ptf_intf_ipv4_hosts = intf_ipv4_addr.hosts()
    else:
        ptf_intf_ipv4_addr = None
        ptf_intf_ipv4_hosts = None

    if intf_ipv6_addr is not None:
        ptf_intf_ipv6_addr = increment_ipv6_addr(intf_ipv6_addr.network_address, incr=3)
    else:
        ptf_intf_ipv6_addr = None

    logger.info("Using {}, {}, and PTF interface {}".format(ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name))

    return ptf_intf_ipv4_addr, ptf_intf_ipv4_hosts, ptf_intf_ipv6_addr, ptf_intf_name, intf1_index, intf1_name


def generate_link_local_addr(mac):
    parts = mac.split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::{}".format(":".join(ipv6Parts))
    return ipv6

# Need to check if we need this for v6 as well, otherwise remove v6 ipversion and param


@pytest.fixture(params=['v4'])
def packets_for_test(request, ptfadapter, duthost, config_facts, tbinfo, ip_and_intf_info):
    ip_version = request.param
    src_addr_v4, _, src_addr_v6, _, ptf_intf_index, _ = ip_and_intf_info
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    vlans = config_facts['VLAN']
    topology = tbinfo['topo']['name']
    dut_mac = ''
    for vlan_details in list(vlans.values()):
        if 'dualtor' in topology:
            dut_mac = vlan_details['mac'].lower()
        else:
            dut_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0]
        break

    if ip_version == 'v4':
        tgt_addr = increment_ipv4_addr(src_addr_v4)
        out_pkt = testutils.simple_arp_packet(
                                eth_dst='ff:ff:ff:ff:ff:ff',
                                eth_src=ptf_intf_mac,
                                ip_snd=src_addr_v4,
                                ip_tgt=tgt_addr,
                                arp_op=1,
                                hw_snd=ptf_intf_mac
                            )
        exp_pkt = testutils.simple_arp_packet(
                                eth_dst=ptf_intf_mac,
                                eth_src=dut_mac,
                                ip_snd=tgt_addr,
                                ip_tgt=src_addr_v4,
                                arp_op=2,
                                hw_snd=dut_mac,
                                hw_tgt=ptf_intf_mac
        )
    elif ip_version == 'v6':
        tgt_addr = increment_ipv6_addr(src_addr_v6)
        ll_src_addr = generate_link_local_addr(ptf_intf_mac.decode())
        multicast_tgt_addr = in6_getnsma(inet_pton(socket.AF_INET6, tgt_addr))
        multicast_tgt_mac = in6_getnsmac(multicast_tgt_addr)
        out_pkt = Ether(src=ptf_intf_mac, dst=multicast_tgt_mac)
        out_pkt /= IPv6(dst=inet_ntop(socket.AF_INET6, multicast_tgt_addr), src=ll_src_addr)
        out_pkt /= ICMPv6ND_NS(tgt=tgt_addr)
        out_pkt /= ICMPv6NDOptSrcLLAddr(lladdr=ptf_intf_mac)

        exp_pkt = Ether(src=dut_mac, dst=ptf_intf_mac)
        exp_pkt /= IPv6(dst=ll_src_addr, src=generate_link_local_addr(dut_mac))
        exp_pkt /= ICMPv6ND_NA(tgt=tgt_addr, S=1, R=1, O=0)
        exp_pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=dut_mac)
        exp_pkt = Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, 'fl')
    return ip_version, out_pkt, exp_pkt


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
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    if input_pkt.haslayer('IP'):
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

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


def dynamic_acl_create_secondary_drop_rule(duthost, setup):
    """Create a drop rule in the format required when an ACL table has rules in it already"""

    extra_vars = {
        'blocked_port': setup["blocked_src_port_name"]
    }

    output = format_and_apply_template(duthost, CREATE_SECONDARY_DROP_RULE_TEMPLATE, extra_vars)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "RULE_3",
                             "9996",
                             "DROP",
                             "IN_PORTS: " + setup["blocked_src_port_name"],
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


def dynamic_acl_verify_packets(setup, ptfadapter, packets, packets_dropped, src_port=None):
    """Verify that the given packets are either dropped/forwarded correctly

    Args:
        packets: the packets that we are sending
        packets_dropped: whether or not we are expecting to drop or forward these packets
        src_port_blocked: whether or not to send it on the source port that we block in our drop rules"""
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
    expected_rule_contents = {}
    rule_number = 1

    for port_name in setup["scale_port_names"]:
        rule_name = "DROP_RULE_" + str(rule_number)
        full_rule_name = "/ACL_RULE/DYNAMIC_ACL_TABLE|"+rule_name
        rule_vals = {
            "PRIORITY": str(priority),
            "PACKET_ACTION": "DROP",
            "IN_PORTS": port_name
        }
        patch = {
            "op": "add",
            "path": full_rule_name,
            "value": rule_vals
        }
        json_patch.append(patch)
        expected_content = ["DYNAMIC_ACL_TABLE", rule_name, str(priority), "DROP", "IN_PORTS: " + port_name, "Active"]
        expected_rule_contents[rule_name] = expected_content
        priority -= 1
        rule_number += 1

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for rule_name, expected_content in expected_rule_contents.items():
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
                                   packets_for_test,
                                   ip_and_intf_info,
                                   proxy_arp_enabled):
    """Test that we can create a blanket ARP packet forwarding rule with GCU, and that ARP packets
    are correctly forwarded while all others are dropped"""

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index, port_name = ip_and_intf_info

    ip_version, outgoing_packet, expected_packet = packets_for_test

    setup["blocked_src_port_name"] = port_name
    setup["blocked_src_port_indice"] = ptf_intf_index

    dynamic_acl_create_arp_forward_rule(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=10)

    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)


def test_gcu_acl_drop_rule_creation(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
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


def test_gcu_acl_drop_rule_removal(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Test that once a drop rule is removed, packets that were previously being dropped are now forwarded"""

    dynamic_acl_create_three_drop_rules(rand_selected_dut, setup)
    dynamic_acl_remove_third_drop_rule(rand_selected_dut)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=False,
                               src_port=setup["scale_port_indices"][2])


def test_gcu_acl_forward_rule_priority_respected(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Test that forward rules and drop rules can be created at the same time, with the forward rules having
    higher priority than drop.  Then, perform a traffic test to confirm that packets that match both the forward
    and drop rules are correctly forwarded, as the forwarding rules have higher priority"""

    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup, ptfadapter, packets=generate_packets(setup), packets_dropped=False)
    dynamic_acl_verify_packets(setup, ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)


def test_gcu_acl_forward_rule_replacement(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
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
def test_gcu_acl_forward_rule_removal(rand_selected_dut, ptfadapter, setup, ip_type, dynamic_acl_create_table):
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


def test_gcu_acl_scale_rules(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
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


def test_gcu_acl_nonexistent_rule_replacement(rand_selected_dut):
    """Confirm that replacing a nonexistent rule results in operation failure"""
    dynamic_acl_replace_nonexistent_rule(rand_selected_dut)


def test_gcu_acl_nonexistent_table_removal(rand_selected_dut):
    """Confirm that removing a nonexistent table results in operation failure"""
    dynamic_acl_remove_nonexistent_table(rand_selected_dut)
