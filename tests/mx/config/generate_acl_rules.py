#! /usr/bin/python3

import ipaddress
import json
import os
import re
import yaml

from functools import reduce

try:
    from .port_utils import get_port_alias_to_name_map
except ImportError:
    from port_utils import get_port_alias_to_name_map

TOPO_MX_YAML = '../../../ansible/vars/topo_mx.yml'
MX_VLAN_CONFIG = './mx_vlan_conf.json'

ACL_ACTION_ACCEPT = "ACCEPT"
ACL_ACTION_DROP = "DROP"

ACL_TABLE_BMC_NORTHBOUND = "bmc_acl_northbound"
ACL_TABLE_BMC_NORTHBOUND_V6 = "bmc_acl_northbound_v6"
ACL_TABLE_BMC_SOUTHBOUND_V6 = "bmc_acl_southbound_v6"

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

ICMP_TYPE_ECHO_REQUEST = 8
ICMP_TYPE_ECHO_REPLY = 0
ICMP_CODE_ECHO_REQUEST = 0
ICMP_CODE_ECHO_REPLY = 0

ICMPV6_TYPE_ECHO_REQUEST = 128
ICMPV6_TYPE_ECHO_REPLY = 129
ICMPV6_TYPE_ROUTER_SOLICITATION = 133
ICMPV6_TYPE_ROUTER_ADVERTISEMENT = 134
ICMPV6_TYPE_NEIGHBOR_SOLICITATION = 135
ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT = 136
ICMPV6_CODE_ECHO_REQUEST = 0
ICMPV6_CODE_ECHO_REPLY = 0
ICMPV6_CODE_ROUTER_SOLICITATION = 0
ICMPV6_CODE_ROUTER_ADVERTISEMENT = 0
ICMPV6_CODE_NEIGHBOR_SOLICITATION = 0
ICMPV6_CODE_NEIGHBOR_ADVERTISEMENT = 0

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67

DHCPV6_CLIENT_PORT = 546
DHCPV6_SERVER_PORT = 547
DHCPV6_MULTICAST_IP = "ff02::1:2/128"

IP2ME_TYPE_IP_INTF = "IPInterface"
IP2ME_TYPE_LO_IP_INTF = "LoopbackIPInterface"
IP2ME_TYPE_MGMT_IP_INTF = "ManagementIPInterface"
IP2ME_TYPE_VLAN_INTF = "VlanInterface"

IP_PROTOCOL_ICMP = "IP_ICMP"
IP_PROTOCOL_ICMPV6 = "IP_ICMPV6"
IP_PROTOCOL_TCP = "IP_TCP"
IP_PROTOCOL_UDP = "IP_UDP"
IP_PROTOCOL_MAP = {
    IP_PROTOCOL_ICMP: 1,
    IP_PROTOCOL_TCP: 6,
    IP_PROTOCOL_UDP: 17,
    IP_PROTOCOL_ICMPV6: 58,
}

TCP_FLAG_ACK = "TCP_ACK"
TCP_FLAG_SYN = "TCP_SYN"

AUTO_GENERATED_FOLDER = "auto_generated_files"


class IP2ME(object):
    def __init__(self, addr, type):
        self.addr = addr
        self.type = type


def minimum_supernet(ip_list):
    supernet = ipaddress.ip_network(ip_list[0])
    for ip in ip_list:
        while not supernet.supernet_of(ipaddress.ip_network(ip)):
            supernet = supernet.supernet()
    return supernet


def ip_merge(ip_list, exclude_list=None):
    result = [minimum_supernet(ip_list)]
    while exclude_list:
        exclude_net = ipaddress.ip_network(exclude_list[0])
        if any([exclude_net.overlaps(res) for res in result]):
            while all([not exclude_net.supernet().overlaps(ipaddress.ip_network(ip)) for ip in ip_list]):
                exclude_net = exclude_net.supernet()
            result = reduce(lambda x, y: x + y, [list(res.address_exclude(exclude_net)) if res.overlaps(exclude_net) else [res] for res in result])
        exclude_list = [ex for ex in exclude_list if not exclude_net.supernet_of(ipaddress.ip_network(ex))]
    result.sort(key=lambda x: (x.prefixlen, int(x.network_address)))
    return result


def acl_entry(seq_id, action=ACL_ACTION_DROP, ethertype=None, interfaces=None,
              src_ip=None, dst_ip=None, ip_protocol=None, tcp_flags=None,
              icmp_type=None, icmp_code=None, l4_src_port=None, l4_dst_port=None):
    rule = {
        "config": {"sequence-id": seq_id},
        "actions": {"config": {"forwarding-action": action}},
    }
    if src_ip or dst_ip or ip_protocol:
        ip_cfg = {}
        if src_ip:
            ip_cfg["source-ip-address"] = src_ip
        if dst_ip:
            ip_cfg["destination-ip-address"] = dst_ip
        if ip_protocol:
            if ip_protocol in IP_PROTOCOL_MAP:
                ip_protocol = IP_PROTOCOL_MAP[ip_protocol]
            ip_cfg["protocol"] = str(ip_protocol)
        rule["ip"] = {"config": ip_cfg}
    if interfaces:
        rule["input_interface"] = {"interface_ref": {"config": {"interface": ",".join(interfaces)}}}
    if ethertype:
        rule["l2"] = {"config": {"ethertype": ethertype}}
    if icmp_code is not None or icmp_type is not None:
        icmp_cfg = {}
        if icmp_type is not None:
            icmp_cfg["type"] = icmp_type
        if icmp_code is not None:
            icmp_cfg["code"] = icmp_code
        rule["icmp"] = {"config": icmp_cfg}
    if tcp_flags or l4_src_port or l4_dst_port:
        transport_cfg = {}
        if tcp_flags:
            transport_cfg["tcp-flags"] = tcp_flags
        if l4_src_port:
            transport_cfg["source-port"] = str(l4_src_port)
        if l4_dst_port:
            transport_cfg["destination-port"] = str(l4_dst_port)
        rule["transport"] = {"config": transport_cfg}
    return rule


def ip2me_list(vlan_count):
    # Loopback0 or MGMT
    ipv4_list = [IP2ME(ipaddress.ip_network('10.1.0.32'), IP2ME_TYPE_LO_IP_INTF)]
    ipv6_list = [IP2ME(ipaddress.ip_network('fc00:1::32'), IP2ME_TYPE_LO_IP_INTF)]
    # VLAN Interface
    with open(MX_VLAN_CONFIG) as f:
        vlan_config = json.load(f)[str(vlan_count)]
        for vlan_id, vlan_cfg in vlan_config.items():
            if 'interface_ipv4' in vlan_cfg:
                ipv4_list.append(IP2ME(ipaddress.ip_network(vlan_cfg['interface_ipv4'].split('/')[0]), IP2ME_TYPE_VLAN_INTF))
            if 'interface_ipv6' in vlan_cfg:
                ipv6_list.append(IP2ME(ipaddress.ip_network(vlan_cfg['interface_ipv6'].split('/')[0]), IP2ME_TYPE_VLAN_INTF))
    # P2P
    with open(TOPO_MX_YAML) as f:
        topo_mx = yaml.safe_load(f)
        neighbors = topo_mx['configuration']
        for neigh_name, neigh_cfg in neighbors.items():
            for ip_addr in neigh_cfg['bgp']['peers'][64001]:
                ip_net = ipaddress.ip_network(ip_addr)
                if type(ip_net) is ipaddress.IPv4Network:
                    ipv4_list.append(IP2ME(ip_net, IP2ME_TYPE_IP_INTF))
                elif type(ip_net) is ipaddress.IPv6Network:
                    ipv6_list.append(IP2ME(ip_net, IP2ME_TYPE_IP_INTF))
    return ipv4_list, ipv6_list


def gen_northbound_acl_entries_v4(rack_topo, hwsku):
    port_alias_to_name, _, _ = get_port_alias_to_name_map(hwsku)
    shelfs = rack_topo['shelfs']
    rms = [shelf['rm'] for shelf in shelfs]
    bmc_groups = reduce(lambda x, y: x + y, [shelf['bmc'] for shelf in shelfs])
    bmc_hosts = reduce(lambda x, y: x + y, [bmc_gp['hosts'] for bmc_gp in bmc_groups])
    rm_ips = [rm.get('ipv4_subnet', None) or rm['ipv4_addr'] for rm in rms]
    bmc_ips = [bg['config']['ipv4_subnet'] for bg in bmc_groups if bg['config'].get('ipv4_subnet', None) is not None] + \
              [bh['ipv4_addr'] for bh in bmc_hosts if bh.get('ipv4_addr', None) is not None]

    acl_entries = {}

    # Allow ICMP Echo Request and Reply packet from BMC to Mx VLAN interface,
    # so that BMC and Mx can ping each other.
    ipv4_list, _ = ip2me_list(rack_topo['config']['vlan_count'])
    sequence_id = 101
    for ip2me in filter(lambda x: x.type == IP2ME_TYPE_VLAN_INTF, ipv4_list):
        acl_entries["{:04d}_IP2ME".format(sequence_id)] = \
            acl_entry(sequence_id, ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV4, dst_ip=format(ip2me.addr))
        sequence_id += 5

    # Allow DHCP broadcast packets from BMC to Mx
    sequence_id = 501
    acl_entries["{:04d}_DHCP_BROADCAST".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV4,
                  ip_protocol=IP_PROTOCOL_UDP, l4_dst_port=DHCP_SERVER_PORT,
                  src_ip="0.0.0.0/32", dst_ip="255.255.255.255/32")

    # IN_PORTS = BMC, DST_IP = BMC => DROP
    sequence_id = 1001
    bmc_intfs = [port_alias_to_name[host['port_alias']] for host in bmc_hosts]
    bmc_nets = ip_merge(bmc_ips, rm_ips)
    for bmc_net in bmc_nets:
        acl_entries["{:04d}_IN_PORTS_BMC_DST_IP_BMC".format(sequence_id)] = \
            acl_entry(sequence_id, dst_ip=format(bmc_net), interfaces=bmc_intfs, ethertype=ETHERTYPE_IPV4)
        sequence_id += 5

    # For same shelf:
    #   - SRC_IP = RM, DST_IP = BMC => ACCEPT
    #   - SRC_IP = BMC, DST_IP = RM => ACCEPT
    sequence_id = max(sequence_id, 1101)
    if len(shelfs) == 1:
        shelf = shelfs[0]
        rm = shelf['rm']
        rm_ip = ipaddress.ip_network(rm.get('ipv4_subnet', None) or rm['ipv4_addr'])
        acl_entries["{:04d}_SRC_IP_RM".format(sequence_id)] = \
            acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(rm_ip), ethertype=ETHERTYPE_IPV4)
        sequence_id += 5
        acl_entries["{:04d}_DST_IP_RM".format(sequence_id)] = \
            acl_entry(sequence_id, ACL_ACTION_ACCEPT, dst_ip=format(rm_ip), ethertype=ETHERTYPE_IPV4)
        sequence_id += 5
    else:
        for shelf in shelfs:
            rm = shelf['rm']
            rm_ip = ipaddress.ip_network(rm.get('ipv4_subnet', None) or rm['ipv4_addr'])
            rm_ports = [port_alias_to_name[rm['port_alias']]]
            for bmc_gp in shelf['bmc']:
                bmc_ports = [port_alias_to_name[host['port_alias']] for host in bmc_gp['hosts']]
                if bmc_gp.get('config', {}).get('ipv4_subnet', None):
                    bmc_ip = ipaddress.ip_network(bmc_gp['config']['ipv4_subnet'])
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC".format(sequence_id, shelf['id'])] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=rm_ports, src_ip=format(rm_ip), dst_ip=format(bmc_ip), ethertype=ETHERTYPE_IPV4)
                    sequence_id += 5
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM".format(sequence_id, shelf['id'])] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=bmc_ports, src_ip=format(bmc_ip), dst_ip=format(rm_ip), ethertype=ETHERTYPE_IPV4)
                    sequence_id += 5
                else:
                    gp_bmc_ips = [bh['ipv4_addr'] for bh in bmc_gp['hosts']]
                    gp_bmc_nets = ip_merge(gp_bmc_ips, list(set(bmc_ips) - set(gp_bmc_ips)) + rm_ips)
                    for gp_bmc_net in gp_bmc_nets:
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC".format(sequence_id, shelf['id'])] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=rm_ports, src_ip=format(rm_ip), dst_ip=format(gp_bmc_net), ethertype=ETHERTYPE_IPV4)
                        sequence_id += 5
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM".format(sequence_id, shelf['id'])] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=bmc_ports, src_ip=format(gp_bmc_net), dst_ip=format(rm_ip), ethertype=ETHERTYPE_IPV4)
                        sequence_id += 5

    # All other ipv4 packages => DROP
    sequence_id = 9990
    acl_entries["{:04d}_DROP_ALL".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV4)
    sequence_id += 5

    return {"acl-entries": {"acl-entry": acl_entries}}


def gen_northbound_acl_entries_v6(rack_topo, hwsku):
    port_alias_to_name, _, _ = get_port_alias_to_name_map(hwsku)
    shelfs = rack_topo['shelfs']
    rms = [shelf['rm'] for shelf in shelfs]
    rm_intfs = [port_alias_to_name[rm['port_alias']] for rm in rms]
    rm_support_ipv6 = any([rm.get('ipv6_subnet', None) or rm.get('ipv6_addr', None) for rm in rms])
    bmc_groups = reduce(lambda x, y: x + y, [shelf['bmc'] for shelf in shelfs])
    bmc_hosts = reduce(lambda x, y: x + y, [bmc_gp['hosts'] for bmc_gp in bmc_groups])
    bmc_intfs = [port_alias_to_name[host['port_alias']] for host in bmc_hosts]
    rm_ips = [rm.get('ipv6_subnet', None) or rm['ipv6_addr'] for rm in rms if rm.get('ipv6_subnet', None) or rm.get('ipv6_addr', None) is not None]
    bmc_ips = [bg['config']['ipv6_subnet'] for bg in bmc_groups if bg['config'].get('ipv6_subnet', None) is not None] + \
              [bh['ipv6_addr'] for bh in bmc_hosts if bh.get('ipv6_addr', None) is not None]

    acl_entries = {}

    '''
    # IP2Me Rules
    sequence_id = 101
    _, ipv6_list = ip2me_list(rack_topo['config']['vlan_count'])
    for ip2me in ipv6_list:
        if ip2me.type != IP2ME_TYPE_IP_INTF:  # P2P IP not needed in northbound
            acl_entries["{:04d}_IP2ME".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_ACCEPT, dst_ip=format(ip2me.addr), ethertype=ETHERTYPE_IPV6)
            sequence_id += 5
    '''

    # If IPv6 is supported on any RM
    sequence_id = 1001
    if rm_support_ipv6:
        # IN_PORTS = BMC, DST_IP = BMC => DROP
        # (Avoid one BMC send package to another BMC)
        bmc_nets = ip_merge(bmc_ips, rm_ips)
        for bmc_net in bmc_nets:
            acl_entries["{:04d}_IN_PORTS_BMC_DST_IP_BMC".format(sequence_id)] = \
                acl_entry(sequence_id, ACL_ACTION_DROP, dst_ip=format(bmc_net), interfaces=bmc_intfs, ethertype=ETHERTYPE_IPV6)
            sequence_id += 5

        # IN_PORTS = RM, DST_IP = RM => DROP
        # (Avoid one RM send package to another RM)
        rm_nets = ip_merge(rm_ips, bmc_ips)
        for rm_net in rm_nets:
            acl_entries["{:04d}_IN_PORTS_RM_DST_IP_RM".format(sequence_id)] = \
                acl_entry(sequence_id, ACL_ACTION_DROP, dst_ip=format(rm_net), interfaces=rm_intfs, ethertype=ETHERTYPE_IPV6)
            sequence_id += 5

    sequence_id = 8001
    if rm_support_ipv6:
        # For same shelf: (Only needed if IPv6 is supported on RM)
        #   - SRC_IP = RM, DST_IP = BMC => ACCEPT
        #   - SRC_IP = BMC, DST_IP = RM => ACCEPT
        for shelf in shelfs:
            rm = shelf['rm']
            rm_ip = ipaddress.ip_network(rm.get('ipv6_subnet', None) or rm['ipv6_addr'])
            rm_ports = [port_alias_to_name[rm['port_alias']]]
            for bmc_gp in shelf['bmc']:
                bmc_ports = [port_alias_to_name[host['port_alias']] for host in bmc_gp['hosts']]
                if bmc_gp.get('config', {}).get('ipv6_subnet', None):
                    bmc_ip = ipaddress.ip_network(bmc_gp['config']['ipv6_subnet'])
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC".format(sequence_id, shelf['id'])] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=rm_ports, src_ip=format(rm_ip), dst_ip=format(bmc_ip), ethertype=ETHERTYPE_IPV6)
                    sequence_id += 5
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM".format(sequence_id, shelf['id'])] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=bmc_ports, src_ip=format(bmc_ip), dst_ip=format(rm_ip), ethertype=ETHERTYPE_IPV6)
                    sequence_id += 5
                else:
                    gp_bmc_ips = [bh['ipv6_addr'] for bh in bmc_gp['hosts']]
                    gp_bmc_nets = ip_merge(gp_bmc_ips, list(set(bmc_ips) - set(gp_bmc_ips)) + rm_ips)
                    for gp_bmc_net in gp_bmc_nets:
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC".format(sequence_id, shelf['id'])] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=rm_ports, src_ip=format(rm_ip), dst_ip=format(gp_bmc_net), ethertype=ETHERTYPE_IPV6)
                        sequence_id += 5
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM".format(sequence_id, shelf['id'])] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, interfaces=bmc_ports, src_ip=format(gp_bmc_net), dst_ip=format(rm_ip), ethertype=ETHERTYPE_IPV6)
                        sequence_id += 5

    '''
    # Allow NDP between Mx and BMC
    sequence_id = 9001  # icmp_type = 133: Router Solicitation
    acl_entries["{:04d}_ALLOW_NDP".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, ip_protocol=IP_PROTOCOL_ICMPV6, icmp_type=133, icmp_code=0, ethertype=ETHERTYPE_IPV6)
    sequence_id = 9002  # icmp_type = 135: Neighbor Solicitation
    acl_entries["{:04d}_ALLOW_NDP".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, ip_protocol=IP_PROTOCOL_ICMPV6, icmp_type=135, icmp_code=0, ethertype=ETHERTYPE_IPV6)
    sequence_id = 9003  # icmp_type = 136: Neighbor Advertisement
    acl_entries["{:04d}_ALLOW_NDP".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, ip_protocol=IP_PROTOCOL_ICMPV6, icmp_type=136, icmp_code=0, ethertype=ETHERTYPE_IPV6)

    # Allow DHCPv6 packets from BMC to Mx
    sequence_id = 9011
    acl_entries["{:04d}_ALLOW_DHCPv6".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, dst_ip="ff02::1:2/128", ip_protocol=IP_PROTOCOL_UDP, ethertype=ETHERTYPE_IPV6)
    '''

    # All other ipv6 packets => DROP
    # (Prevent BMC send package to upstream)
    # (If RM doesn't support IPv6, this rule can also prevent one BMC send package to another BMC)
    sequence_id = 9990  # priority = 10
    acl_entries["{:04d}_DROP_ALL".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6)
    sequence_id += 5

    return {"acl-entries": {"acl-entry": acl_entries}}


def gen_southbound_acl_entries_v6(rack_topo, hwsku):
    acl_entries = {}

    # IP2Me Rules
    sequence_id = 101
    _, ipv6_list = ip2me_list(rack_topo['config']['vlan_count'])
    for ip2me in ipv6_list:
        acl_entries["{:04d}_IP2ME".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_ACCEPT, dst_ip=format(ip2me.addr), ethertype=ETHERTYPE_IPV6)
        sequence_id += 5

    # Allow NDP between Mx and M0
    sequence_id = 201  # icmp_type = 135: Neighbor Solicitation
    acl_entries["{:04d}_ICMPV6_NEIGHBOR_SOLICITATION".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, ip_protocol=IP_PROTOCOL_ICMPV6, ethertype=ETHERTYPE_IPV6,
                  icmp_type=ICMPV6_TYPE_NEIGHBOR_SOLICITATION, icmp_code=ICMPV6_CODE_NEIGHBOR_SOLICITATION)
    sequence_id = 202  # icmp_type = 136: Neighbor Advertisement
    acl_entries["{:04d}_ICMPV6_NEIGHBOR_ADVERTISEMENT".format(sequence_id)] = \
        acl_entry(sequence_id, action=ACL_ACTION_ACCEPT, ip_protocol=IP_PROTOCOL_ICMPV6, ethertype=ETHERTYPE_IPV6,
                  icmp_type=ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT, icmp_code=ICMPV6_CODE_NEIGHBOR_ADVERTISEMENT)

    # By default, drop all the southbound traffic:
    # MARCH_ALL => DROP
    sequence_id = 9990  # priority = 10
    acl_entries["{:04d}_DROP_ALL".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6)
    sequence_id += 5

    return {"acl-entries": {"acl-entry": acl_entries}}


def gen_acl_rules(topo_file, hwsku):
    with open(topo_file) as f:
        rack_topo = yaml.safe_load(f)

    acl_set = {}
    acl_tables = rack_topo['config']['acl_tables']
    if ACL_TABLE_BMC_NORTHBOUND in acl_tables:
        acl_set[acl_tables[ACL_TABLE_BMC_NORTHBOUND]] = gen_northbound_acl_entries_v4(rack_topo, hwsku)
    if ACL_TABLE_BMC_NORTHBOUND_V6 in acl_tables:
        acl_set[acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6]] = gen_northbound_acl_entries_v6(rack_topo, hwsku)
    if ACL_TABLE_BMC_SOUTHBOUND_V6 in acl_tables:
        acl_set[acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6]] = gen_southbound_acl_entries_v6(rack_topo, hwsku)
    acl_rules = {"acl": {"acl-sets": {"acl-set": acl_set}}}

    if not os.path.exists(AUTO_GENERATED_FOLDER):
        os.makedirs(AUTO_GENERATED_FOLDER)

    # generate static ACL rule files
    static_acl_rule_file = os.path.join(AUTO_GENERATED_FOLDER, rack_topo['config']['static_acl_rule_file'])
    with open(static_acl_rule_file, 'w') as fout:
        json.dump(acl_rules, fout, sort_keys=True, indent=4)

    # generate dynamic ACL rule template files
    if 'dynamic_acl_rule_template_file' in rack_topo['config']:
        DYN_NORTHBOUND_VAR_NAME = "dynamic_northbound_v6"
        DYN_SOUTHBOUND_VAR_NAME = "dynamic_southbound_v6"

        def gen_pattern(acl_table):
            return r'"' + acl_table + r'": {' + "\n" + \
                   r'( *)"acl-entries": {' + "\n" + \
                   r'(.*)"acl-entry": {' + "\n"

        def gen_replace(acl_table):
            dyn_var_name = DYN_NORTHBOUND_VAR_NAME if "northbound" in acl_table.lower() else DYN_SOUTHBOUND_VAR_NAME
            return r'"' + acl_table + r'": {' + "\n" + \
                   r'\1"acl-entries": {' + "\n" + \
                   r'\2"acl-entry": {' + "\n" + \
                   r'\2    {% for acl_name, acl_rule in ' + dyn_var_name + r'.items() %}' + "\n" + \
                   r'\2    "{{ acl_name }}": {{ acl_rule }},' + "\n" + \
                   r'\2    {% endfor %}' + "\n"

        dynamic_acl_rule_template_file = os.path.join(AUTO_GENERATED_FOLDER, rack_topo['config']['dynamic_acl_rule_template_file'])
        with open(static_acl_rule_file, 'r') as fin:
            filedata = fin.read()
        with open(dynamic_acl_rule_template_file, 'w') as fout:
            if ACL_TABLE_BMC_NORTHBOUND_V6 in acl_tables:
                pattern = gen_pattern(acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6])
                filedata = re.sub(pattern, gen_replace(acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6]), filedata)
            if ACL_TABLE_BMC_SOUTHBOUND_V6 in acl_tables:
                pattern = gen_pattern(acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6])
                filedata = re.sub(pattern, gen_replace(acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6]), filedata)
            fout.write(filedata)


def gen_bmc_otw_acl_rules():
    gen_acl_rules("bmc_otw_topo.yaml", "Nokia-7215")


def gen_bmc_ares_acl_rules():
    gen_acl_rules("bmc_ares_topo.yaml", "Nokia-7215")


def main():
    gen_bmc_otw_acl_rules()
    gen_bmc_ares_acl_rules()


if __name__ == '__main__':
    main()
