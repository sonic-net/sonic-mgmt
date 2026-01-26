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

        self.VTEP_IP = self.ipp("221.0.0.1")
        self.PAL = self.ipp("221.1.0.1")
        self.PAR = self.ipp("221.2.0.1")
        self.STATIC = self.ipp("221.0.0.1")
        self.STATICL = self.ipp("221.1.0.0")
        self.STATICR = self.ipp("221.2.0.0")

        self.ACL_TABLE_MAC_STEP = '00:00:00:02:00:00'
        self.ACL_POLICY_MAC_STEP = '00:00:00:00:00:32'

        self.ENI_VNI_NVGRE_START = 1000
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
        self.IPv6_R_START = self.ipp('2603:100:3E8::104:1')
        self.IPv6_Range_Increment = self.ipp('0:0:1::40:0')

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

        # PrivateLink
        self.NVGRE_COUNT = 32
        self.NVGRE_SUBMASK = 48
        self.NVGRE_VSID = 100
        self.NVGRE_IP = self.ipp('2603:100:3e8::0:0')
        self.NVGRE_IP_STEP = self.ipp(ipaddress.ip_address('0:0:1::0:0'))
        self.PAL_PL = self.ipp("221.2.0.0")
        self.PAR_PL = self.ipp("221.1.0.0")

    def dec2hex(self, dec):
        hex_str = hex(dec)[2:]
        return hex_str

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


def find_lb_ip(config, cards_dict, server_vlan):

    card_slot_step = config.ENI_COUNT // cards_dict['num_cps_cards']
    index = int((server_vlan - 1) / card_slot_step)

    return str(ipaddress.ip_address(int(config.STATIC) + index))


def find_dpu_port(config, cards_dict, vlan):

    num_dpu_cards = cards_dict['num_dpus_ports']
    ENI_COUNT = config.ENI_COUNT
    first_cps_card = 1

    dpu_slot_step = ENI_COUNT // num_dpu_cards

    if cards_dict['switchover_port'] is False:
        dpu_slot = int((vlan - 1) / dpu_slot_step) + first_cps_card
    else:
        dpu_slot = 1

    return dpu_slot


def find_card_slot(config, cards_dict, first_cps_card, first_tcpbg_card, server_vlan):

    card_slot_step = config.ENI_COUNT // (len(cards_dict['l47_ports']) // 2)

    if first_tcpbg_card != 0:
        test_role = ""
        if (server_vlan - 1) % 4 == 3:
            # TCP BG
            test_role = "tcpbg"
            card_slot = int((server_vlan - 1) / (card_slot_step * 2)) + first_tcpbg_card
        else:
            # CPS
            test_role = "cps"
            card_slot = int((server_vlan - 1) / card_slot_step) + first_cps_card
    else:
        test_role = "cps"
        card_slot_step = config.ENI_COUNT // cards_dict['num_cps_cards']
        card_slot = int((server_vlan - 1) / card_slot_step) + first_cps_card  # 8 CS cards for cps

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


def create_uhdIp_list(cidr, config, cards_dict):

    ip_list = []

    incr = 0
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
        ip_dict_temp['underlay_ip_l'] = str(ipaddress.ip_address(int(config.STATICL) + incr))
        ip_dict_temp['network_broadcast'] = network_broadcast
        ip_dict_temp['ip_server'] = ip_server
        ip_dict_temp['vlan_server'] = vlan_server
        ip_dict_temp['underlay_ip_r'] = str(ipaddress.ip_address(int(config.STATICR) + incr))
        ip_dict_temp['lb_ip'] = find_lb_ip(config, cards_dict, vlan_server)
        ip_dict_temp['_ip'] = find_lb_ip(config, cards_dict, vlan_server)

        ip_dict_temp['dpu_port'] = find_dpu_port(config, cards_dict, vlan_server)

        incr += 1
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
    num_channels = config.uhd_num_channels

    ethpass_ports = cards_dict['ethpass_ports']
    if len(ethpass_ports) > 0:
        for port in ethpass_ports:
            ethpass_dict = {
                "name": f"l47_port_11{port['FrontPanel']}",
                "choice": "front_panel_port",
                "front_panel_port": {
                    "front_panel_port": int(port['FrontPanel']),
                    "layer_1_profile_name": "{}".format(config.layer1_profile_names[3])
                }
            }
            fp_list.append(ethpass_dict)

    l47_ports_length = len(cards_dict['l47_ports'])
    data_index = 0
    for i in range(1, count // 2 + 1):
        for nodetype in ['s', 'c']:
            if data_index < l47_ports_length:  # Check against actual list length
                if not cards_dict['l47_ports'][data_index]['Channel']:
                    new_dict = {
                        "name": f"l47_port_{i}{nodetype}",
                        "choice": "front_panel_port",
                        "front_panel_port": {
                            "front_panel_port": int(cards_dict['l47_ports'][data_index]['FrontPanel']),
                            "layer_1_profile_name": "{}".format(config.layer1_profile_names[1])
                        }
                    }
                else:
                    new_dict = {
                        "name": f"l47_port_{i}{nodetype}",
                        "choice": "front_panel_port",
                        "front_panel_port": {
                            "front_panel_port": int(cards_dict['l47_ports'][data_index]['FrontPanel']),
                            "channel": int(cards_dict['l47_ports'][data_index]['Channel']),
                            "num_channels": num_channels,
                            "layer_1_profile_name": "{}".format(config.layer1_profile_names[1])
                        }
                    }
                fp_list.append(new_dict)
            data_index += 1

    # l47 Front Panel DPU
    # TODO add num_dpuPorts then build this part

    dpu_ports_length = len(cards_dict['dpu_ports'])
    dpu_port = 0
    switchover_port = 0
    for i in range(1, dpu_ports_length + 1):
        if cards_dict['dpu_ports'][i - 1]['SwitchOverPort'] == 'True':
            switchover_port = int(cards_dict['dpu_ports'][i - 1]['FrontPanel'])
        else:
            dpu_port = int(cards_dict['dpu_ports'][i - 1]['FrontPanel'])

    if switchover_port == 0:
        for x, dpu in enumerate(cards_dict['dpu_ports']):
            dpu_port_ = {"name": f"l47_dpuPort_{x + 1}", "choice": "port_group", "front_panel_port": {
                "front_panel_port": int(cards_dict['dpu_ports'][x]['FrontPanel']),
                "layer_1_profile_name": "{}".format(config.layer1_profile_names[3])
            }
            }
            fp_list.append(dpu_port_)
    else:
        dpu_port_1 = {"name": "l47_dpuPort_1", "choice": "port_group",
                      "port_group":  # noqa: E128
                          {  # noqa: E127
                              "ports": [
                                  {  # noqa: E122
                                      "front_panel_port": dpu_port, "layer_1_profile_name": "{}".format(  # noqa: E122
                                      config.layer1_profile_names[3]),  # noqa: E122
                                      "switchover_port": {"front_panel_port": switchover_port,  # noqa: E122
                                                          "layer_1_profile_name": "{}".format(
                                                              config.layer1_profile_names[3])}
                                  }
                              ]
                          }
                      }

        fp_list.append(dpu_port_1)

    return fp_list


def create_arp_bypass_pl(fp_ports_list, ip_list, config, cards_dict, subnet_mask):

    connections_list = []
    num_cps_cards = cards_dict['num_cps_cards']
    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)
    vrange_count = config.ENI_COUNT//num_cps_cards
    vlan_start = (config.ENI_L2R_STEP + 1) - vrange_count

    """
    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        if cards_dict['num_tcpbg_cards'] > 0:
            first_tcpbg_card = cards_dict['num_cps_cards'] + 1
        else:
            first_tcpbg_card = 0
    """

    vlan_start_tmp = vlan_start
    for port in range(num_cps_cards):

        vlan_start_tmp += vrange_count
        arp_bypass_dict = {
            'name': "ARP Bypass {}".format(port+1),
            'functions': [{"choice": "connect_arp", "connect_arp": {}}],
            'endpoints': []
        }

        # Test role will all use client instead of one client and one server
        client_role = 'c'

        arp_bypass_dict['endpoints'].append(
            {'choice': 'front_panel', 'front_panel': {'port_name': 'l47_port_{}{}'.format(9, client_role),
                                                      'vlan': {'choice': 'vlan_range', 'vlan_range':
                                                          {'start': vlan_start_tmp, 'count': vrange_count,  # noqa: E128
                                                           'step': 1}}}}
        )
        arp_bypass_dict['endpoints'].append(
            {'choice': 'front_panel', 'front_panel': {'port_name': 'l47_port_{}{}'.format(port+1, client_role),
                                                      'vlan': {'choice': 'vlan_range', 'vlan_range':
                                                          {'start': vlan_start_tmp,  # noqa: E128
                                                           'count': vrange_count, 'step': 1}}}}
        )

        connections_list.append(arp_bypass_dict)

    return connections_list


def create_connections_pl(fp_ports_list, ip_list, subnet_mask, config, cards_dict, arp_bypass_list,
                          vxlan_port, vxlan_src_port):

    connections_list = arp_bypass_list

    num_cps_cards = cards_dict['num_cps_cards']

    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)
    """
    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        first_tcpbg_card = cards_dict['num_cps_cards'] + 1
    """

    # TODO loopback IP need updated for multiple DPUs for example: 'dst_ip': {'choice': 'ipv4', 'ipv4': '221.0.0.1'}
    # ip6 = int(config.NVGRE_IP)  # noqa: F841
    ip6_step = int(config.NVGRE_IP_STEP)
    nvgre_count = config.NVGRE_COUNT
    nvgre_eni = config.ENI_START
    vtep_ip = config.VTEP_IP
    vtep_ip_tmp = 0
    underlay_ip = config.PAL_PL
    underlay_ip_tmp = 0
    vlan_endpoint_ip = config.PAR_PL
    vlanEP_ip_tmp = 0
    # ip_start = config.IP_L_START  # noqa: F841
    # ip_tmp = 0
    client_vlan_start = config.ENI_L2R_STEP + 1
    client_vlan_tmp = 0
    # vxlan_vni_start = config.ENI_L2R_STEP * 2
    vxlan_vni_start = config.ENI_L2R_STEP
    vxlan_vni_tmp = 0
    nvgre_ip = "2603:100:%s:0::0" % (config.dec2hex(config.ENI_VNI_NVGRE_START))
    nvgre_ip_tmp = 0

    for port in range(num_cps_cards):

        server_dict_temp = {
            'name': 'l47 Server {}'.format(port+1),
            'functions': [],
            'endpoints': []
        }

        client_dict_temp = {
            'name': 'l47 Client {}'.format(port+1),
            'functions': [],
            'endpoints': []
        }

        # client_vlan = build_node_vlan(eni, config, nodetype="client")
        # server_vlan = build_node_vlan(eni, config, nodetype="server")

        # client_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)
        # client_cps_port = find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role)
        # server_card, test_role = find_card_slot(first_cps_card, first_tcpbg_card, server_vlan)

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
        # overlay_ip_addr = eni

        # if server_vlan <= 128:
        #    lb_ip = 1
        # else:
        #    lb_ip = 2

        # client_role, server_role = find_testrole(test_role, server_vlan)

        # TODO VNIs need to be +1000 for production
        production = True  # turn ON for now
        if production is True:
            vni_index = 1000
        else:
            vni_index = 0  # noqa: F841

        nvgre_ip_tmp = str(ipaddress.ip_address(nvgre_ip) + (ip6_step * (port * nvgre_count)))
        vtep_ip_tmp = vtep_ip + (1 * port)
        underlay_ip_tmp = underlay_ip + (config.NVGRE_COUNT * port)
        server_conn_tmp = {
            "choice": "connect_vlan_nvgre",
            "connect_vlan_nvgre": {
                "vlan_endpoint_settings": {
                    "outgoing_nvgre_header": {
                        "src_mac": {"choice": "mac", "mac": "{}".format(config.l47_tg_servermac)},
                        "dst_mac": {"choice": "mac", "mac": "{}".format(config.dut_mac)},
                        "src_ip": {"choice": "ipv4_range", "ipv4_range": {'start': "{}".format(underlay_ip_tmp),
                                                                          'count': nvgre_count, 'step': '0.0.0.1'}},
                        "dst_ip": {"choice": "ipv4", "ipv4": "{}".format(vtep_ip_tmp)},
                    }
                },
                "nvgre_endpoint_settings": {
                    "vsid": {"choice": "vsid", "vsid": config.NVGRE_VSID},
                    "protocols": {"accept": ["tcp"]}, "routing_method": "ip_routing",  # noqa: E128
                    "ip_routing": {"destination_ips": {"choice": "ipv6_range",
                    "ipv6_range": {'start': "{}".format(ipaddress.ip_address(nvgre_ip_tmp)),  # noqa: E128
                                   'subnet_bits': config.NVGRE_SUBMASK, 'count': nvgre_count,
                                   'step': "{}".format(str(ipaddress.ip_address(ip6_step)))}}}
                }
            }
        }
        server_dict_temp['functions'].append(server_conn_tmp)
        nvgre_eni_temp = nvgre_eni + (nvgre_count * port)
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {
                "port_name": "l47_port_{}s".format(port + 1),  # noqa: E122
                "vlan": {"choice": "vlan_range", "vlan_range": {"start": nvgre_eni_temp, "count": 32, "step": 1}}},
             "tags": ["vlan"]},
        )
        dpu_port = 2
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {"port_name": "dpu_port_{}".format(dpu_port)},
             "tags": ["nvgre"]}
        )

        # Client Side
        # TODO vni_index
        # client_start = config.IP_L_START
        # ip_tmp = client_start + (int(ipaddress.ip_address('8.0.0.0')) * port)
        vlanEP_ip_tmp = vlan_endpoint_ip + (nvgre_count * port)
        vxlan_vni_tmp = vxlan_vni_start + (nvgre_count * port)

        client_conn_tmp = {"choice": "connect_vlan_vxlan", "connect_vlan_vxlan": {
            "vlan_endpoint_settings": {
                "outgoing_vxlan_header": {
                    "src_mac": {"choice": "mac", "mac": "{}".format(config.l47_tg_clientmac)},
                    "dst_mac": {"choice": "mac", "mac": "{}".format(config.dut_mac)},
                    "src_ip": {"choice": "ipv4_range", "ipv4_range": {'start': "{}".format(vlanEP_ip_tmp),
                                                                      'count': nvgre_count, 'step': '0.0.0.1'}},
                    "dst_ip": {"choice": "ipv4", "ipv4": "{}".format(vtep_ip_tmp)},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni_range", "vni_range": {'start': vxlan_vni_tmp,
                                        'count': nvgre_count, 'step': 1}}, "protocols": {"accept": ["tcp"]},
                                        "routing_method": "ip_routing", "ip_routing": {"destination_ips":
                                        {"choice": "ipv4_range", "ipv4_range": {  # noqa: E128
                                        # "start": "{}".format(ip_tmp),  # noqa: E122
                                        "count": config.NVGRE_COUNT, "step": "0.64.0.0"}}},  # noqa: E122
                                        "udp_src_port": vxlan_port, "udp_dst_port": vxlan_src_port}
        }}

        client_vlan_tmp = client_vlan_start + (nvgre_count * port)
        client_dict_temp['functions'].append(client_conn_tmp)
        client_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {
                "port_name": "l47_port_{}c".format(port+1),
                "vlan": {"choice": "vlan_range", "vlan_range": {'start': client_vlan_tmp, 'count': nvgre_count,
                                                                'step': 1}}}, "tags": ["vlan"]},
        )

        dpu_port = 1
        client_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {"port_name": "dpu_port_{}".format(dpu_port)},
             "tags": ["vxlan"]}
        )

        # Add server and client settings to connections_list
        connections_list.append(server_dict_temp)
        connections_list.append(client_dict_temp)

    return connections_list


def create_arp_bypass(fp_ports_list, ip_list, config, cards_dict, subnet_mask):

    connections_list = []
    num_cps_cards = cards_dict['num_cps_cards']
    ethpass_ports = cards_dict['ethpass_ports']
    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)

    """
    if cards_dict['num_cps_cards'] > 0:
        first_cps_card = 1
        if cards_dict['num_tcpbg_cards'] > 0:
            first_tcpbg_card = cards_dict['num_cps_cards'] + 1
        else:
            first_tcpbg_card = 0
    """
    eth_bypass_dict = {
        'name': "Eth Bypass",
        'functions': [{"choice": "connect_ethernet", "connect_ethernet": {}}],
        'endpoints': []
    }

    if len(ethpass_ports) > 0:
        for port in ethpass_ports:
            eth_bypass_dict['endpoints'].append(
                {'choice': 'front_panel', 'front_panel':
                    {'port_name': 'l47_port_11{}'.format(port['FrontPanel']), 'vlan': {'choice': 'non_vlan'}}}
            )
        connections_list.append(eth_bypass_dict)

    for eni, ip in enumerate(ip_list):

        arp_bypass_dict = {
            'name': "ARP Bypass {}".format(eni+1),
            'functions': [{"choice": "connect_arp", "connect_arp": {}}],
            'endpoints': []
        }

        client_vlan = build_node_vlan(eni, config, nodetype="client")
        server_vlan = build_node_vlan(eni, config, nodetype="server")

        client_card, test_role = find_card_slot(config, cards_dict, first_cps_card, first_tcpbg_card, server_vlan)
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


def create_connections(fp_ports_list, ip_list, subnet_mask, config, cards_dict, arp_bypass_list,
                       vxlan_port=0, vxlan_src_port=0):

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

        client_vlan = ip_list[eni]['vlan_client']
        server_vlan = ip_list[eni]['vlan_server']

        client_card, test_role = find_card_slot(config, cards_dict, first_cps_card, first_tcpbg_card, server_vlan)
        # client_cps_port = find_port(num_cps_cards, first_cps_card, first_tcpbg_card, server_vlan, test_role)
        server_card, test_role = find_card_slot(config, cards_dict, first_cps_card, first_tcpbg_card, server_vlan)

        # TODO needed when there are multiple DPU Ports
        # dpu_port = 1 if server_vlan <= 128 else 2
        # dpu_port = 1

        # Server side
        """
        if server_vlan == 256:
            overlay_ip_addr = 0
        else:
            overlay_ip_addr = eni+1
        """
        # overlay_ip_addr = eni

        """
        if server_vlan <= 128:
            lb_ip = 1
        else:
            lb_ip = 2
        """

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
                    "src_ip": {"choice": "ipv4", "ipv4": "{}".format(ip_list[eni]['underlay_ip_l'])},
                    "dst_ip": {"choice": "ipv4", "ipv4": "{}".format(ip_list[eni]['lb_ip'])},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni", "vni": server_vlan + vni_index},
                    "protocols": {"accept": ["tcp"]}, "routing_method": "ip_routing",  # noqa: E128
                    "ip_routing": {"destination_ips": {"choice": "ipv4",
                    "ipv4": "{}".format(ip_list[eni]['ip_server'])}},  # noqa: E128
                                        "udp_src_port": vxlan_port, "udp_dst_port": vxlan_src_port}  # noqa: E128
        }}
        server_dict_temp['functions'].append(server_conn_tmp)
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {
            "port_name": "l47_port_{}{}".format(server_card, server_role),  # noqa: E122
            "vlan": {"choice": "vlan", "vlan": server_vlan}}, "tags": ["vlan"]},  # noqa: E122
        )
        server_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {"port_name": "l47_dpuPort_{}".format(ip_list[eni]['dpu_port'])},
             "tags": ["vxlan"]}
        )

        # Client Side
        # TODO vni_index
        client_conn_tmp = {"choice": "connect_vlan_vxlan", "connect_vlan_vxlan": {
            "vlan_endpoint_settings": {
                "outgoing_vxlan_header": {
                    "src_mac": {"choice": "mac", "mac": "{}".format(config.l47_tg_clientmac)},
                    "dst_mac": {"choice": "mac", "mac": "{}".format(config.dut_mac)},
                    "src_ip": {"choice": "ipv4", "ipv4": "{}".format(ip_list[eni]['underlay_ip_r'])},
                    "dst_ip": {"choice": "ipv4", "ipv4": "{}".format(ip_list[eni]['lb_ip'])},
                }
            },
            "vxlan_endpoint_settings": {"vni": {"choice": "vni", "vni": client_vlan}, "protocols": {"accept": ["tcp"]},
                                        "routing_method": "ip_routing",
                                        "ip_routing": {"destination_ips": {"choice": "ipv4_range",
                                        "ipv4_range": {  # noqa: E128
                                            "start": "{}".format(ip_list[eni]['network_broadcast']),
                                            "count": 1, "subnet_bits": subnet_mask
                                        }}}, "udp_src_port": vxlan_port, "udp_dst_port": vxlan_src_port}
        }}

        client_dict_temp['functions'].append(client_conn_tmp)
        client_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {
                "port_name": "l47_port_{}{}".format(client_card, client_role),
                "vlan": {"choice": "vlan", "vlan": client_vlan}}, "tags": ["vlan"]},
        )

        client_dict_temp['endpoints'].append(
            {"choice": "front_panel", "front_panel": {"port_name": "l47_dpuPort_{}".format(ip_list[eni]['dpu_port'])},
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
