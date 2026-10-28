import ipaddress
import macaddress
import logging

logger = logging.getLogger(__name__)

# UHD Connect API schema versions. 4.0 flattened connection endpoints, moved the
# endpoint VLAN and the outgoing tunnel header onto the function, and made endpoint
# tags positional (one per function).
UHD_API_V3 = '3.0'
UHD_API_V4 = '4.0'
UHD_API_VERSIONS = (UHD_API_V3, UHD_API_V4)


class NetworkConfigSettings:
    def __init__(self, vxlan_endpoint_vni=1000, uhd_api_version=UHD_API_V4):
        """
        Addressing constants and the UHD Connect API version used to build the UHD config.
        Args:
            vxlan_endpoint_vni (int): first client VLAN / VXLAN VNI (ENI_L2R_STEP)
            uhd_api_version (str): UHD Connect API schema version, one of UHD_API_VERSIONS (default 4.0)
        """
        if uhd_api_version not in UHD_API_VERSIONS:
            raise ValueError("unsupported uhd_api_version {!r}, expected one of {}".format(
                uhd_api_version, UHD_API_VERSIONS))
        self.uhd_api_version = uhd_api_version
        self.ipp = ipaddress.ip_address
        self.maca = macaddress.MAC

        self.subnet_mask = 10
        self.ENI_START = 1
        self.ENI_COUNT = 256
        self.ENI_MAC_STEP = '00:00:00:18:00:00'
        self.ENI_STEP = 1
        self.ENI_L2R_STEP = vxlan_endpoint_vni
        self.ENI_PER_PORT = 64

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
    if nodetype == "client":
        ip = config.ipp(int(config.IP_R_START) + (config.IP_STEP_NSG * count) + int(config.IP_STEP_ENI) * (vpc - 1))
    if nodetype == "server":
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

    # l47 Front Panel DPU: one port group per DPU port, or a single group carrying the switchover port
    dpu_profile = config.layer1_profile_names[3]
    dpu_ports = [int(p['FrontPanel']) for p in cards_dict['dpu_ports'] if p['SwitchOverPort'] != 'True']
    switchover_ports = [int(p['FrontPanel']) for p in cards_dict['dpu_ports'] if p['SwitchOverPort'] == 'True']
    if switchover_ports:
        fp_list.append(_port_group("l47_dpuPort_1", dpu_ports[-1], dpu_profile, switchover_ports[-1]))
    else:
        for x, port in enumerate(dpu_ports):
            fp_list.append(_port_group("l47_dpuPort_{}".format(x + 1), port, dpu_profile))

    return fp_list


def _port_group(name, front_panel_port, profile, switchover_port=None):
    """
    Build a single-port port_group entry for front_panel_ports.
    Args:
        name (str): port group name referenced by connection endpoints
        front_panel_port (int): DPU-facing front panel port number
        profile (str): layer 1 profile name
        switchover_port (int): optional HA switchover front panel port, same profile
    Returns:
        dict: front_panel_ports entry
    """
    port = {"front_panel_port": front_panel_port, "layer_1_profile_name": profile}
    if switchover_port is not None:
        port["switchover_port"] = {"front_panel_port": switchover_port, "layer_1_profile_name": profile}
    return {"name": name, "choice": "port_group", "port_group": {"ports": [port]}}


def build_tunnel_connection(name, vlan_port, vlan, tunnel, tunnel_port, header, tunnel_settings, udp_ports, config):
    """
    Build a connect_vlan_vxlan / connect_vlan_nvgre connection in the schema of the configured UHD API version.
    Args:
        name (str): connection name
        vlan_port (str): name of the VLAN-side front panel port (traffic generator)
        vlan (dict): VlanIdOption matched on the VLAN side
        tunnel (str): 'vxlan' or 'nvgre'
        tunnel_port (str): name of the tunnel-side front panel port (DPU)
        header (dict): outgoing tunnel header (src_mac, dst_mac, src_ip, dst_ip)
        tunnel_settings (dict): vni/vsid, protocols and routing settings
        udp_ports (dict): VXLAN udp_src_port/udp_dst_port overrides, or {}
        config (NetworkConfigSettings): carries uhd_api_version
    Returns:
        dict: connection entry
    """
    function = "connect_vlan_{}".format(tunnel)
    tunnel_key = "{}_endpoint_settings".format(tunnel)
    header_key = "outgoing_{}_header".format(tunnel)
    header = dict(header)
    tunnel_settings = dict(tunnel_settings)
    if config.uhd_api_version == UHD_API_V4:
        header.update(udp_ports)
        tunnel_settings[header_key] = header
        body = {"vlan_endpoint_settings": {"vlan": vlan}, tunnel_key: tunnel_settings}
        endpoints = [{"port_name": vlan_port, "tags": ["vlan"]},
                     {"port_name": tunnel_port, "tags": [tunnel]}]
    else:
        tunnel_settings.update(udp_ports)
        body = {"vlan_endpoint_settings": {header_key: header}, tunnel_key: tunnel_settings}
        endpoints = [{"choice": "front_panel", "front_panel": {"port_name": vlan_port, "vlan": vlan}, "tags": ["vlan"]},
                     {"choice": "front_panel", "front_panel": {"port_name": tunnel_port}, "tags": [tunnel]}]
    return {"name": name, "functions": [{"choice": function, function: body}], "endpoints": endpoints}


def build_passthrough_connection(name, function, port1, vlan1, port2, vlan2, config):
    """
    Build a connect_arp / connect_ethernet connection between two front panel ports.
    Args:
        name (str): connection name
        function (str): 'connect_arp' or 'connect_ethernet'
        port1 (str): first front panel port name
        vlan1 (dict): VlanIdOption matched on port1
        port2 (str): second front panel port name
        vlan2 (dict): VlanIdOption matched on port2
        config (NetworkConfigSettings): carries uhd_api_version
    Returns:
        dict: connection entry
    """
    if config.uhd_api_version == UHD_API_V4:
        body = {"vlan_endpoint_settings_port1": {"vlan": vlan1}, "vlan_endpoint_settings_port2": {"vlan": vlan2}}
        endpoints = [{"port_name": port1, "tags": ["vlan"]}, {"port_name": port2, "tags": ["vlan"]}]
    else:
        body = {}
        endpoints = [{"choice": "front_panel", "front_panel": {"port_name": port1, "vlan": vlan1}},
                     {"choice": "front_panel", "front_panel": {"port_name": port2, "vlan": vlan2}}]
    return {"name": name, "functions": [{"choice": function, function: body}], "endpoints": endpoints}


def _vlan(vlan_id):
    return {"choice": "vlan", "vlan": vlan_id}


def _vlan_range(start, count):
    return {"choice": "vlan_range", "vlan_range": {"start": start, "count": count, "step": 1}}


def _udp_ports(vxlan_port, vxlan_src_port):
    """VXLAN UDP port overrides; empty when both are 0 so UHD keeps its defaults. Mapping kept from the original."""
    if vxlan_port == 0 and vxlan_src_port == 0:
        return {}
    return {"udp_src_port": vxlan_port, "udp_dst_port": vxlan_src_port}


def _tunnel_header(config, src_mac, src_ip, dst_ip):
    return {"src_mac": {"choice": "mac", "mac": src_mac},
            "dst_mac": {"choice": "mac", "mac": config.dut_mac},
            "src_ip": src_ip, "dst_ip": dst_ip}


def _eth_bypass_connections(config, ethpass_ports):
    """
    Ethernet bypass between the two EthernetPass front panel ports.
    Args:
        config (NetworkConfigSettings): carries uhd_api_version
        ethpass_ports (list): CSV rows with EthernetPass == 'True'
    Returns:
        list: [Eth Bypass connection], or [] when no EthernetPass ports are configured
    """
    if not ethpass_ports:
        return []
    if len(ethpass_ports) != 2:
        raise ValueError("Eth Bypass needs exactly two EthernetPass ports, got {}".format(len(ethpass_ports)))
    non_vlan = {"choice": "non_vlan"}
    port1, port2 = ["l47_port_11{}".format(p['FrontPanel']) for p in ethpass_ports]
    return [build_passthrough_connection("Eth Bypass", "connect_ethernet", port1, non_vlan, port2, non_vlan, config)]


def create_arp_bypass_pl(fp_ports_list, ip_list, config, cards_dict, subnet_mask):
    """PrivateLink bypass connections: only the Ethernet bypass, no per-ENI ARP bypass."""
    return _eth_bypass_connections(config, cards_dict['ethpass_ports'])


def create_connections_pl(fp_ports_list, ip_list, subnet_mask, config, cards_dict, arp_bypass_list,
                          vxlan_port, vxlan_src_port):
    """
    PrivateLink connections: per CPS card one NVGRE server connection and one VXLAN client connection,
    each covering NVGRE_COUNT VLANs with ranges.
    """
    connections_list = list(arp_bypass_list)
    nvgre_count = config.NVGRE_COUNT
    ip6_step = int(config.NVGRE_IP_STEP)
    nvgre_ip = ipaddress.ip_address("2603:100:%s:0::0" % config.dec2hex(config.ENI_VNI_NVGRE_START))
    client_ip_step = int(ipaddress.ip_address('8.0.0.0'))
    udp_ports = _udp_ports(vxlan_port, vxlan_src_port)

    for port in range(cards_dict['num_cps_cards']):
        offset = nvgre_count * port
        vtep_ip = {"choice": "ipv4", "ipv4": str(config.VTEP_IP + port)}

        server_header = _tunnel_header(
            config, config.l47_tg_servermac,
            {"choice": "ipv4_range", "ipv4_range": {"start": str(config.PAL_PL + offset), "count": nvgre_count,
                                                    "step": "0.0.0.1"}},
            vtep_ip)
        server_settings = {
            "vsid": {"choice": "vsid", "vsid": config.NVGRE_VSID},
            "protocols": {"accept": ["tcp"]},
            "routing_method": "ip_routing",
            "ip_routing": {"destination_ips": {"choice": "ipv6_range", "ipv6_range": {
                "start": str(nvgre_ip + ip6_step * offset), "subnet_bits": config.NVGRE_SUBMASK,
                "count": nvgre_count, "step": str(ipaddress.ip_address(ip6_step))}}},
        }
        connections_list.append(build_tunnel_connection(
            "l47 Server {}".format(port + 1), "l47_port_{}s".format(port + 1),
            _vlan_range(config.ENI_START + offset, nvgre_count), "nvgre", "l47_dpuPort_1",
            server_header, server_settings, {}, config))

        client_header = _tunnel_header(
            config, config.l47_tg_clientmac,
            {"choice": "ipv4_range", "ipv4_range": {"start": str(config.PAR_PL + offset), "count": nvgre_count,
                                                    "step": "0.0.0.1"}},
            vtep_ip)
        client_settings = {
            "vni": {"choice": "vni_range", "vni_range": {"start": config.ENI_L2R_STEP + offset,
                                                         "count": nvgre_count, "step": 1}},
            "protocols": {"accept": ["tcp"]},
            "routing_method": "ip_routing",
            "ip_routing": {"destination_ips": {"choice": "ipv4_range", "ipv4_range": {
                "start": str(config.IP_L_START + client_ip_step * port), "count": nvgre_count, "step": "0.64.0.0"}}},
        }
        connections_list.append(build_tunnel_connection(
            "l47 Client {}".format(port + 1), "l47_port_{}c".format(port + 1),
            _vlan_range(config.ENI_L2R_STEP + 1 + offset, nvgre_count), "vxlan", "l47_dpuPort_1",
            client_header, client_settings, udp_ports, config))

    return connections_list


def create_arp_bypass(fp_ports_list, ip_list, config, cards_dict, subnet_mask):
    """vnet2vnet bypass connections: the Ethernet bypass plus one connect_arp per ENI between its two l47 ports."""
    connections_list = _eth_bypass_connections(config, cards_dict['ethpass_ports'])
    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)

    for eni, ip in enumerate(ip_list):
        client_vlan = build_node_vlan(eni, config, nodetype="client")
        server_vlan = build_node_vlan(eni, config, nodetype="server")
        card, test_role = find_card_slot(config, cards_dict, first_cps_card, first_tcpbg_card, server_vlan)
        client_role, server_role = find_testrole(test_role, server_vlan)
        connections_list.append(build_passthrough_connection(
            "ARP Bypass {}".format(eni + 1), "connect_arp",
            "l47_port_{}{}".format(card, server_role), _vlan(server_vlan),
            "l47_port_{}{}".format(card, client_role), _vlan(client_vlan), config))

    return connections_list


def create_connections(fp_ports_list, ip_list, subnet_mask, config, cards_dict, arp_bypass_list,
                       vxlan_port=0, vxlan_src_port=0):
    """vnet2vnet connections: per ENI one VXLAN server connection and one VXLAN client connection."""
    connections_list = list(arp_bypass_list)
    first_cps_card, first_tcpbg_card = set_first_stateful_cards(cards_dict)
    udp_ports = _udp_ports(vxlan_port, vxlan_src_port)
    vni_index = 1000

    for eni, ip in enumerate(ip_list):
        client_vlan = ip['vlan_client']
        server_vlan = ip['vlan_server']
        card, test_role = find_card_slot(config, cards_dict, first_cps_card, first_tcpbg_card, server_vlan)
        client_role, server_role = find_testrole(test_role, server_vlan)
        dpu_port = "l47_dpuPort_{}".format(ip['dpu_port'])
        lb_ip = {"choice": "ipv4", "ipv4": ip['lb_ip']}

        server_header = _tunnel_header(config, config.l47_tg_servermac,
                                       {"choice": "ipv4", "ipv4": ip['underlay_ip_l']}, lb_ip)
        server_settings = {
            "vni": {"choice": "vni", "vni": server_vlan + vni_index},
            "protocols": {"accept": ["tcp"]},
            "routing_method": "ip_routing",
            "ip_routing": {"destination_ips": {"choice": "ipv4", "ipv4": ip['ip_server']}},
        }
        connections_list.append(build_tunnel_connection(
            "l47 Server {}".format(eni + 1), "l47_port_{}{}".format(card, server_role), _vlan(server_vlan),
            "vxlan", dpu_port, server_header, server_settings, udp_ports, config))

        client_header = _tunnel_header(config, config.l47_tg_clientmac,
                                       {"choice": "ipv4", "ipv4": ip['underlay_ip_r']}, lb_ip)
        client_settings = {
            "vni": {"choice": "vni", "vni": client_vlan},
            "protocols": {"accept": ["tcp"]},
            "routing_method": "ip_routing",
            "ip_routing": {"destination_ips": {"choice": "ipv4_range", "ipv4_range": {
                "start": ip['network_broadcast'], "count": 1, "subnet_bits": subnet_mask}}},
        }
        connections_list.append(build_tunnel_connection(
            "l47 Client {}".format(eni + 1), "l47_port_{}{}".format(card, client_role), _vlan(client_vlan),
            "vxlan", dpu_port, client_header, client_settings, udp_ports, config))

    return connections_list


def set_first_stateful_cards(cards_dict):
    """
    First card slot used by CPS traffic and by TCP background traffic.
    Args:
        cards_dict (dict): card counts, reads num_cps_cards and num_tcpbg_cards
    Returns:
        tuple: (first_cps_card, first_tcpbg_card); first_tcpbg_card is 0 when there are no TCP BG cards
    """
    first_cps_card = 1
    first_tcpbg_card = cards_dict['num_cps_cards'] + 1 if cards_dict['num_tcpbg_cards'] > 0 else 0

    return first_cps_card, first_tcpbg_card
