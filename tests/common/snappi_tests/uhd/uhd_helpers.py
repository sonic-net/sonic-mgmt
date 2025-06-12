import ipaddress
import macaddress
import logging

logger = logging.getLogger(__name__)


class NetworkConfigSettings:
    def __init__(self):
        self.ipp = ipaddress.ip_address
        self.maca = macaddress.MAC

        self.subnet_mask = 10
        self.ENI_START = 1
        self.ENI_COUNT = 256
        self.ENI_MAC_STEP = '00:00:00:18:00:00'
        self.ENI_STEP = 1
        self.ENI_L2R_STEP = 1000

        self.PAL = self.ipp("221.1.0.1")
        self.PAR = self.ipp("221.2.0.1")

        self.ACL_TABLE_MAC_STEP = '00:00:00:02:00:00'
        self.ACL_POLICY_MAC_STEP = '00:00:00:00:00:32'

        self.ACL_RULES_NSG = 1000
        self.ACL_TABLE_COUNT = 5

        self.IP_PER_ACL_RULE = 25
        self.IP_MAPPED_PER_ACL_RULE = self.IP_PER_ACL_RULE
        self.IP_ROUTE_DIVIDER_PER_ACL_RULE = 64

        self.IP_STEP1 = int(self.ipp('0.0.0.1'))
        self.IP_STEP_ENI = int(self.ipp('0.64.0.0'))
        self.IP_STEP_NSG = int(self.ipp('0.2.0.0'))
        self.IP_STEP_ACL = int(self.ipp('0.0.0.50'))
        self.IP_STEPE = int(self.ipp('0.0.0.2'))

        self.IP_L_START = self.ipp('1.1.0.1')
        self.IP_R_START = self.ipp('1.4.0.1')

        self.MAC_L_START = self.maca('00:1A:C5:00:00:01')
        self.MAC_R_START = self.maca('00:1B:6E:00:00:01')
        self.IPS_PER_RANGE = self.ACL_RULES_NSG * self.ACL_TABLE_COUNT * self.IP_PER_ACL_RULE * 2

        self.uhd_post_url = 'connect/api/v1/config'
        self.uhd_num_channels = 2

        self.speed_100_gbps = "speed_100_gbps"
        self.speed_400_gbps = "speed_400_gbps"
        self.layer1_profile_names = ['autoneg', 'manual_RS', 'manual_NONE', 'autoneg_400', 'manual_RS_400']
        self.l47_tg_clientmac = ''
        self.l47_tg_servermac = ''
        self.first_staticArpMac = ''
        self.dut_mac = ''

    def set_mac_addresses(self, clientmac, servermac, dutmac):

        self.l47_tg_clientmac = str(self.maca(clientmac)).replace('-', ':')
        self.l47_tg_servermac = str(self.maca(servermac)).replace('-', ':')
        self.dut_mac = str(self.maca(dutmac)).replace('-', ':')

        ip_tmp = self.l47_tg_servermac
        ip = ip_tmp.split(':')
        ip[3] = '02'
        self.first_staticArpMac = ":".join(ip)

        return


def build_node_ips(count, vpc, config, nodetype="client"):
    if nodetype in "client":
        ip = config.ipp(int(config.IP_R_START) + (config.IP_STEP_NSG * count) + int(config.IP_STEP_ENI) * (vpc - 1))
    if nodetype in "server":
        ip = config.ipp(int(config.IP_L_START) + int(config.IP_STEP_ENI) * (vpc - 1))

    return str(ip)


def build_node_vlan(index, config, nodetype="client"):

    hero_b2b = False

    if nodetype == 'client':
        vlan = config.ENI_L2R_STEP + index + 1
    else:
        # config.ENI_STEP = 1
        if hero_b2b is True:
            vlan = 0
        else:
            vlan = config.ENI_STEP + index

    return vlan


def cidr_calculator(ip, cidr):
    ip_address = ip
    cidr_mask = cidr
    network = ipaddress.ip_network(ip_address)
    try:
        network = ipaddress.ip_network(f'{ip_address}/{cidr_mask}', strict=False)
    except ValueError:
        logger.info("Invalid ip address or CIDR mask")
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
        card_slot = int((server_vlan - 1) / 8) + first_cps_card  # 8 CS cards for cps

    return card_slot, test_role


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
            client_role = 's'
            server_role = 'c'
        else:
            client_role = 'c'
            server_role = 's'
    else:
        client_role = 'c'
        server_role = 's'

    return client_role, server_role


def create_uhdIp_list(cidr, config):

    ip_list = []

    for eni in range(config.ENI_START, config.ENI_COUNT + 1):
        ip_dict_temp = {}
        ip_client = build_node_ips(0, eni, config, nodetype="client")
        vlan_client = build_node_vlan(eni - 1, config, nodetype="client")
        network_broadcast = cidr_calculator(ip_client, cidr)
        ip_server = build_node_ips(0, eni, config, nodetype="server")
        vlan_server = build_node_vlan(eni - 1, config, nodetype="server")

        ip_dict_temp['eni'] = eni
        ip_dict_temp['ip_client'] = ip_client
        ip_dict_temp['vlan_client'] = vlan_client
        ip_dict_temp['network_broadcast'] = network_broadcast
        ip_dict_temp['ip_server'] = ip_server
        ip_dict_temp['vlan_server'] = vlan_server

        ip_list.append(ip_dict_temp)

    return ip_list


def create_profiles(config):

    return {
        "layer_1_profiles": [
            {"name": "{}".format(config.layer1_profile_names[0]), "link_speed": config.speed_100_gbps,
             "choice": "autonegotiation"},
            {"name": "{}".format(config.layer1_profile_names[1]), "link_speed": config.speed_100_gbps,
             "choice": "manual",
             "manual": {"fec_mode": "reed_solomon"}},
            {"name": "{}".format(config.layer1_profile_names[3]), "link_speed": config.speed_400_gbps,
             "choice": "autonegotiation"},
        ]
    }


def create_front_panel_ports(count, config, cards_dict):

    # l47 Front Panel
    fp_list = []
    front_panel_port = 9
    channel = 1
    num_channels = config.uhd_num_channels

    # TODO num_channels will need an update
    for i in range(1, count // 2 + 1):
        for nodetype in ['s', 'c']:
            new_dict = {
                "name": f"l47_port_{i}{nodetype}",
                "choice": "front_panel_port",
                "front_panel_port": {
                    "front_panel_port": front_panel_port,
                    "channel": channel,
                    "num_channels": num_channels,
                    "layer_1_profile_name": "{}".format(config.layer1_profile_names[1])
                }
            }
            fp_list.append(new_dict)
            channel += 2
            if channel > 7:
                channel = 1
                front_panel_port += 1

    # l47 Front Panel DPU
    # TODO add num_dpuPorts then build this part
    dpu_port_1 = {"name": "l47_port_1", "choice": "port_group",
        "port_group":  # noqa: E128
        {  # noqa: E128
            "ports": [
            {  # noqa: E122
            "front_panel_port": cards_dict['dpu_ports_list'][0], "layer_1_profile_name": "{}".format(  # noqa: E122
                config.layer1_profile_names[3]),  # noqa: E122
            "switchover_port": {"front_panel_port": cards_dict['dpu_ports_list'][1],  # noqa: E122
                                "layer_1_profile_name": "{}".format(config.layer1_profile_names[3])}  # noqa: E122
            }
            ]
        }
    }

    fp_list.append(dpu_port_1)

    return fp_list


def create_arp_bypass(fp_ports_list, ip_list, config, cards_dict, subnet_mask):

    connections_list = []
    num_cps_cards = cards_dict['num_cps_cards']
    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)

    """
    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        if cards_dict['num_tcpbg_cards'] > 0:
            first_tcpbg_card = cards_dict['num_cps_cards'] + 1
        else:
            first_tcpbg_card = 0
    """

    for eni, ip in enumerate(ip_list):

        arp_bypass_dict = {
            'name': "ARP Bypass {}".format(eni+1),
            'functions': [{"choice": "connect_arp", "connect_arp": {}}],
            'endpoints': []
        }

        client_vlan = build_node_vlan(eni, config, nodetype="client")
        server_vlan = build_node_vlan(eni, config, nodetype="server")

        client_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)
        client_port = find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role)  # noqa: F841
        # server_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)

        if cards_dict['num_tcpbg_cards'] > 0:
            client_role, server_role = find_testrole(test_role, server_vlan)
        else:
            client_role = 'c'
            server_role = 's'

        arp_bypass_dict['endpoints'].append(
            {'choice': 'front_panel', 'front_panel': {'port_name': 'l47_port_{}{}'.format(client_card,
                                        server_role), 'vlan': {'choice': 'vlan', 'vlan': server_vlan}}}  # noqa: E128
        )
        arp_bypass_dict['endpoints'].append(
            {'choice': 'front_panel', 'front_panel': {'port_name': 'l47_port_{}{}'.format(client_card,
                                        client_role), 'vlan': {'choice': 'vlan', 'vlan': client_vlan}}}  # noqa: E128
        )

        connections_list.append(arp_bypass_dict)

    return connections_list


def create_connections(fp_ports_list, ip_list, subnet_mask, config, cards_dict, arp_bypass_list):

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
            'name': 'l47 Server {}'.format(eni+1),
            'functions': [],
            'endpoints': []
        }

        client_dict_temp = {
            'name': 'l47 Client {}'.format(eni+1),
            'functions': [],
            'endpoints': []
        }

        client_vlan = build_node_vlan(eni, config, nodetype="client")
        server_vlan = build_node_vlan(eni, config, nodetype="server")

        client_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)
        # client_cps_port = find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role)
        server_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)

        # TODO needed when there are multiple DPU Ports
        # dpu_port = 1 if server_vlan <= 128 else 2
        dpu_port = 1

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

        client_role, server_role = find_testrole(test_role, server_vlan)

        # TODO VNIs need to be +1000 for production
        production = True  # turn ON for now
        if production is True:
            vni_index = 1000
        else:
            vni_index = 0

        server_conn_tmp = {"choice": "connect_vlan_vxlan", "connect_vlan_vxlan": {
            "vlan_endpoint_settings": {
                "outgoing_vxlan_header": {
                    "src_mac": {"choice": "mac", "mac": "{}".format(config.l47_tg_servermac)},
                    "dst_mac": {"choice": "mac", "mac": "{}".format(config.dut_mac)},
                    "src_ip": {"choice": "ipv4", "ipv4": "221.1.0.{}".format(overlay_ip_addr)},
                    "dst_ip": {"choice": "ipv4", "ipv4": "221.0.0.{}".format(lb_ip)},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni", "vni": server_vlan + vni_index},
                    "protocols": {"accept": ["tcp"]}, "routing_method": "ip_routing",  # noqa: E128
                    "ip_routing": {"destination_ips": {"choice": "ipv4",
                    "ipv4": "{}".format(ip_list[eni]['ip_server'])}}}  # noqa: E128
        }}
        server_dict_temp['functions'].append(server_conn_tmp)
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {
            "port_name": "l47_port_{}{}".format(server_card, server_role),  # noqa: E122
            "vlan": {"choice": "vlan", "vlan": server_vlan}}, "tags": ["vlan"]},  # noqa: E122
        )
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {"port_name": "l47_port_{}".format(dpu_port)},
             "tags": ["vxlan"]}
        )

        # Client Side
        # TODO vni_index
        client_conn_tmp = {"choice": "connect_vlan_vxlan", "connect_vlan_vxlan": {
            "vlan_endpoint_settings": {
                "outgoing_vxlan_header": {
                    "src_mac": {"choice": "mac", "mac": "{}".format(config.l47_tg_clientmac)},
                    "dst_mac": {"choice": "mac", "mac": "{}".format(config.dut_mac)},
                    "src_ip": {"choice": "ipv4", "ipv4": "221.2.0.{}".format(overlay_ip_addr)},
                    "dst_ip": {"choice": "ipv4", "ipv4": "221.0.0.{}".format(lb_ip)},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni", "vni": client_vlan}, "protocols": {"accept": ["tcp"]},
                                        "routing_method": "ip_routing",
                                        "ip_routing": {"destination_ips": {"choice": "ipv4_range",
                                        "ipv4_range": {  # noqa: E128
                                            "start": "{}".format(ip_list[eni]['network_broadcast']),
                                            "count": 1, "subnet_bits": subnet_mask
                                        }}}}
        }}

        client_dict_temp['functions'].append(client_conn_tmp)
        client_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {
                "port_name": "l47_port_{}{}".format(client_card, client_role),
                "vlan": {"choice": "vlan", "vlan": client_vlan}}, "tags": ["vlan"]},
        )

        client_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {"port_name": "l47_port_{}".format(dpu_port)},
             "tags": ["vxlan"]}
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
