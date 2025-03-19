import json
import ipaddress

import macaddress

ipp = ipaddress.ip_address
maca = macaddress.MAC

ENI_START = 1
ENI_COUNT = 64# 64
ENI_MAC_STEP = '00:00:00:18:00:00'
ENI_STEP = 1
ENI_L2R_STEP = 1000

PAL = ipp("221.1.0.1")
PAR = ipp("221.2.0.1")

ACL_TABLE_MAC_STEP = '00:00:00:02:00:00'
ACL_POLICY_MAC_STEP = '00:00:00:00:00:32'

ACL_RULES_NSG = 1000  # 1000
ACL_TABLE_COUNT = 5

IP_PER_ACL_RULE = 25  # 128
IP_MAPPED_PER_ACL_RULE = IP_PER_ACL_RULE # 40
IP_ROUTE_DIVIDER_PER_ACL_RULE = 64 # 8, must be a power of 2 number

IP_STEP1 = int(ipp('0.0.0.1'))
#IP_STEP2 = int(ipp('0.0.1.0'))
#IP_STEP3 = int(ipp('0.1.0.0'))
#IP_STEP4 = int(ipp('1.0.0.0'))
IP_STEP_ENI = int(ipp('0.64.0.0')) # IP_STEP4
IP_STEP_NSG = int(ipp('0.2.0.0')) # IP_STEP3 * 4
IP_STEP_ACL = int(ipp('0.0.0.50')) # IP_STEP2 * 2
IP_STEPE = int(ipp('0.0.0.2'))


IP_L_START = ipp('1.1.0.1')
IP_R_START = ipp('1.4.0.1')

MAC_L_START = maca('00:1A:C5:00:00:01')
MAC_R_START = maca('00:1B:6E:00:00:01')
IPS_PER_RANGE = ACL_RULES_NSG * ACL_TABLE_COUNT * IP_PER_ACL_RULE * 2

def build_node_ips(count, vpc, nodetype="client"):
    if nodetype in "client":
        ip = ipp(int(IP_R_START) + (IP_STEP_NSG * count) + int(ipp('0.64.0.0')) * (vpc - 1))
    if nodetype in "server":
        ip = ipp(int(IP_L_START) + int(ipp('0.64.0.0')) * (vpc - 1))

    return str(ip)

def build_node_vlan(index, nodetype="client"):

    hero_b2b = False

    if nodetype == 'client':
        vlan = ENI_L2R_STEP + index + 1
        #vlan = ENI_L2R_STEP + index
    else:
        ENI_STEP = 1
        if hero_b2b is True:
            vlan = 0
        else:
            vlan = ENI_STEP + index

    return vlan

def cidr_calculator(ip, cidr):
    ip_address = ip
    cidr_mask = cidr
    network = ipaddress.ip_network(ip_address)
    try:
        network = ipaddress.ip_network(f'{ip_address}/{cidr_mask}', strict=False)
    except ValueError:
        print("Invalid ip address or CIDR mask")
    return str(network.network_address)

def find_card_slot(first_cps_card, first_tcpbg_card, server_vlan):

    if first_tcpbg_card != 0:
        test_role = ""
        if (server_vlan - 1) % 4 == 3:
            # TCP BG
            test_role = "tcpbg"
            card_slot = int((server_vlan - 1) / 64) + first_tcpbg_card
        else:
            # CPS
            test_role = "cps"
            card_slot = int((server_vlan - 1) / 32) + first_cps_card
    else:
        test_role = "cps"
        card_slot = int((server_vlan  - 1) / 8) + first_cps_card  # 8 CS cards for cps

    return card_slot,test_role

def find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role):

    if test_role == "cps":
        if int((server_vlan - 1) % num_cps_cards) == num_cps_cards-1:
            card_port = 2
        else:
            card_port = 1
    elif test_role == "tcpbg":
        if int((server_vlan - 1) % num_cps_cards) == num_cps_cards - 1:
            card_port = 1
        else:
            card_port = 2

    return card_port


def find_testrole(test_role, server_vlan):
    if test_role == 'tcpbg':
        if (server_vlan % 8) == 0:
            print("BG test flipped")
            client_role = 's'
            server_role = 'c'
        else:
            print("BG test role normal")
            client_role = 'c'
            server_role = 's'
    else:
        print("Normal assignment")
        client_role = 'c'
        server_role = 's'

    return client_role, server_role

def create_uhdIp_list(cidr):

    ip_list = []

    for eni in range(ENI_START, ENI_COUNT + 1):
        ip_dict_temp = {}
        ip_client = build_node_ips(0, eni, nodetype="client")
        vlan_client = build_node_vlan(eni - 1, nodetype="client")
        network_broadcast = cidr_calculator(ip_client, cidr)
        ip_server = build_node_ips(0, eni, nodetype="server")
        vlan_server = build_node_vlan(eni - 1, nodetype="server")

        ip_dict_temp['eni'] = eni
        ip_dict_temp['ip_client'] = ip_client
        ip_dict_temp['vlan_client'] = vlan_client
        ip_dict_temp['network_broadcast'] = network_broadcast
        ip_dict_temp['ip_server'] = ip_server
        ip_dict_temp['vlan_server'] = vlan_server

        ip_list.append(ip_dict_temp)

    return ip_list

def create_profiles():

    return {
        "layer_1_profiles": [
            {"name": "autoneg", "link_speed": "speed_100_gbps", "choice": "autonegotiation"},
            {"name": "manual_RS", "link_speed": "speed_100_gbps", "choice": "manual",
             "manual": {"fec_mode": "reed_solomon"}},
            {"name": "autoneg_400", "link_speed": "speed_400_gbps", "choice": "autonegotiation"},
            {"name": "manual_RS_400", "link_speed": "speed_400_gbps", "choice": "manual",
             "manual": {"fec_mode": "reed_solomon"}},
            {"name": "manual_NONE", "link_speed": "speed_100_gbps", "choice": "manual", "manual": {"fec_mode": "none"}}
        ]
    }

def create_front_panel_ports(count, num_dpus):

    fp_list = []
    front_panel_port = 9
    channel = 1

    # TODO num_channels will need an update
    for i in range(1, count // 2 + 1):
        for nodetype in ['s', 'c']:
            new_dict = {
                "name": f"Ixload_port_{i}{nodetype}",
                "choice": "front_panel_port",
                "front_panel_port": {
                    "front_panel_port": front_panel_port,
                    "channel": channel,
                    "num_channels": 2,
                    "layer_1_profile_name": "manual_RS"
                }
            }
            fp_list.append(new_dict)
            channel += 2
            if channel > 7:
                channel = 1
                front_panel_port += 1

    # TODO add num_dpuPorts then build this part
    dpu_port_1 = {"name": "dpu_port_1", "choice": "front_panel_port",
        "front_panel_port": {"front_panel_port": 28, "layer_1_profile_name": "manual_RS_400"}}
    #dpu_port_2 = {"name": "dpu_port_2", "choice": "front_panel_port",
    #              "front_panel_port": {"front_panel_port": 27, "layer_1_profile_name": "manual_RS_400"}}

    fp_list.append(dpu_port_1)
    #fp_list.append(dpu_port_2)

    return fp_list

def create_arp_bypass(fp_ports_list, ip_list, cards_dict, subnet_mask):

    connections_list = []
    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)

    """
    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        if cards_dict['num_tcpbg_cards'] > 0:
            first_tcpbg_card = cards_dict['num_cps_cards'] + 1
        else:
            first_tcpbg_card = 0
    """
    num_cps_cards = cards_dict['num_cps_cards']

    card_temp = 0
    for eni, ip in enumerate(ip_list):

        arp_bypass_dict = {
            'name': "ARP Bypass {}".format(eni+1),
            'functions': [{"choice": "connect_arp", "connect_arp": {}}],
            'endpoints': []
        }

        client_vlan = build_node_vlan(eni, nodetype="client")
        server_vlan = build_node_vlan(eni, nodetype="server")

        client_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)
        client_port = find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role)
        #server_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)

        if cards_dict['num_tcpbg_cards'] > 0:
            client_role,server_role = find_testrole(test_role,server_vlan)
        else:
            client_role = 'c'
            server_role = 's'


        arp_bypass_dict['endpoints'].append(
            {'choice': 'front_panel', 'front_panel': {'port_name': 'Ixload_port_{}{}'.format(client_card, server_role), 'vlan': {'choice': 'vlan', 'vlan': server_vlan}}}
        )
        arp_bypass_dict['endpoints'].append(
            {'choice': 'front_panel', 'front_panel': {'port_name': 'Ixload_port_{}{}'.format(client_card, client_role), 'vlan': {'choice': 'vlan', 'vlan': client_vlan}}}
        )

        connections_list.append(arp_bypass_dict)

    return connections_list

def create_connections(fp_ports_list, ip_list, subnet_mask, cards_dict, arp_bypass_list):

    connections_list = arp_bypass_list

    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)
    """
    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        first_tcpbg_card = cards_dict['num_cps_cards'] + 1
    """

    # TODO loopback IP need updated for multiple DPUs for example: 'dst_ip': {'choice': 'ipv4', 'ipv4': '221.0.0.1'}
    for eni, ip in enumerate(ip_list):

        server_dict_temp = {
            'name': 'Ixload Server {}'.format(eni+1),
            'functions': [],
            'endpoints': []
        }

        client_dict_temp = {
            'name': 'Ixload Client {}'.format(eni+1),
            'functions': [],
            'endpoints': []
        }

        client_vlan = build_node_vlan(eni, nodetype="client")
        server_vlan = build_node_vlan(eni, nodetype="server")

        client_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)
        #client_cps_port = find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role)
        server_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)

        dpu_port = 1 if server_vlan <= 128 else 2

        # Server side
        """
        if server_vlan == 256:
            overlay_ip_addr = 0
        else:
            overlay_ip_addr = eni+1
        """
        overlay_ip_addr = eni

        if server_vlan <= 128:
            lb_ip = 1
        else:
            lb_ip = 2

        client_role,server_role = find_testrole(test_role,server_vlan)

        server_conn_tmp = {"choice": "connect_vlan_vxlan", "connect_vlan_vxlan": {
            "vlan_endpoint_settings": {
                "outgoing_vxlan_header": {
                    "src_mac": {"choice": "mac", "mac": "80:09:02:01:00:01"},
                    "dst_mac": {"choice": "mac", "mac": "94:6d:ae:8b:9b:14"},
                    "src_ip": {"choice": "ipv4", "ipv4": "221.1.0.{}".format(overlay_ip_addr)},
                    "dst_ip": {"choice": "ipv4", "ipv4": "221.0.0.{}".format(lb_ip)},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni", "vni": server_vlan}, "protocols": {"accept": ["tcp"]},
                                        "routing_method": "ip_routing",
                                        "ip_routing": {"destination_ips": {"choice": "ipv4", "ipv4": "{}".format(ip_list[eni]['ip_server'])}}}
        }}
        server_dict_temp['functions'].append(server_conn_tmp)
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel","front_panel": {"port_name": "Ixload_port_{}{}".format(server_card, server_role),"vlan": {"choice": "vlan","vlan": server_vlan}},"tags": ["vlan"]},
        )
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel","front_panel": {"port_name": "dpu_port_{}".format(dpu_port)},"tags": ["vxlan"]}
        )

        ## Client Side
        client_conn_tmp = {"choice": "connect_vlan_vxlan", "connect_vlan_vxlan": {
            "vlan_endpoint_settings": {
                "outgoing_vxlan_header": {
                    "src_mac": {"choice": "mac", "mac": "80:09:02:01:00:02"},
                    "dst_mac": {"choice": "mac", "mac": "94:6d:ae:8b:9b:14"},
                    "src_ip": {"choice": "ipv4", "ipv4": "221.2.0.{}".format(overlay_ip_addr)},
                    "dst_ip": {"choice": "ipv4", "ipv4": "221.0.0.{}".format(lb_ip)},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni", "vni": client_vlan}, "protocols": {"accept": ["tcp"]},
                                        "routing_method": "ip_routing",
                                        "ip_routing": {"destination_ips": {"choice": "ipv4_range",
                                                                           "ipv4_range": {
                                                                               "start": "{}".format(ip_list[eni]['network_broadcast']),
                                                                               "count": 1,
                                                                               "subnet_bits": subnet_mask
                                                                           }}}}
        }}
        client_dict_temp['functions'].append(client_conn_tmp)
        client_dict_temp['endpoints'].append(
            {"choice": "front_panel","front_panel": {"port_name": "Ixload_port_{}{}".format(client_card, client_role),"vlan": {"choice": "vlan","vlan": client_vlan}},"tags": ["vlan"]},
        )
        client_dict_temp['endpoints'].append(
            {"choice": "front_panel","front_panel": {"port_name": "dpu_port_{}".format(dpu_port)},"tags": ["vxlan"]}
        )

        # Add server and client settings to connections_list
        connections_list.append(server_dict_temp)
        connections_list.append(client_dict_temp)

    return connections_list

def set_first_stateful_cards(cards_dict):

    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        if cards_dict['num_tcpbg_cards'] > 0:
            first_tcpbg_card = cards_dict['num_cps_cards'] + 1
        else:
            first_tcpbg_card = 0

    return first_cps_card, first_tcpbg_card
