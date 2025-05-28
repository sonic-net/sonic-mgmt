import pytest
import ipaddress
from ipaddress import ip_address, IPv4Address, IPv6Address
from tests.snappi_tests.dataplane.imports import *
from snappi_tests.reboot.files.reboot_helper import get_macs
from tests.common.snappi_tests.snappi_fixtures import (
    snappi_api_serv_ip,
    snappi_api_serv_port,
    snappi_api,
    get_snappi_ports,
    get_snappi_ports_single_dut,
    get_snappi_ports_multi_dut,
)  # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.common_helpers import get_addrs_in_subnet


@pytest.fixture(scope="module")
def set_primary_chassis(snappi_api, fanout_graph_facts_multidut, duthosts):
    primary_chassis = duthosts[0].host.options['variable_manager']._hostvars[duthosts[0].hostname].get('chassis_chain', None)
    if len(fanout_graph_facts_multidut) == 1 and primary_chassis:
        slave_chassis = [fanout_graph_facts_multidut[fanout]['device_info']['mgmtip'] for fanout in fanout_graph_facts_multidut] 
    elif len(fanout_graph_facts_multidut) > 1:
        slave_chassis = []
        for fanout in fanout_graph_facts_multidut:
            if 'primary' in fanout_graph_facts_multidut[fanout]['device_info']['Type'].lower():
                primary_chassis = fanout_graph_facts_multidut[fanout]['device_info']['mgmtip']
            else:
                slave_chassis.append(fanout_graph_facts_multidut[fanout]['device_info']['mgmtip'])
        if not primary_chassis:
            pytest_assert(False, "No primary chassis found in the ansible/ devices.csv file")
    else:
        return False
    ixnconfig = snappi_api.ixnet_specific_config
    chassis_chain1 = ixnconfig.chassis_chains.add()
    chassis_chain1.primary = primary_chassis
    chassis_chain1.topology = chassis_chain1.STAR
    slaves = [chassis_chain1.secondary.add(location = slave, sequence_id = index, cable_length = '6') for index, slave in enumerate(slave_chassis, start=2)]
    

def setup_snappi_port_configs(duthosts, get_snappi_ports, snappi_extra_params=None):
    """
    Adding IP addresses and IP gateway addresses from the minigraph vlan interface details to snappi ports

    Example:
        {
            'ipAddress': '192.168.1.9',
            'ipGateway': '192.168.1.2',
            'prefix': 24,
            'subnet': '192.168.1.0/24',
            'src_mac_address': 'aa:00:00:00:00:05',
            'router_mac_address': '9c:69:ed:6f:9f:a0',
            'speed': '800000',
            'snappi_speed_type': 'speed_800_gbps',
            'peer_port': 'Ethernet16',
            'location': '10.36.84.31/2',
            'duthost': <MultiAsicSonicHost sonic-s6100-dut2>,
            'api_server_ip': '10.36.84.33',
            'asic_type': 'broadcom',
            'asic_value': None
        }
    """
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    if snappi_extra_params.interface_type == "bgp" or snappi_extra_params.interface_type == "ip":
        port_list = get_duthost_bgp_details(duthosts, get_snappi_ports)
    elif snappi_extra_params.interface_type == "vlan":
        port_list = get_duthost_vlan_details(duthosts, get_snappi_ports)
    return port_list

def get_duthost_bgp_details(duthosts, get_snappi_ports):
    """
    Example:
    {
    'ip': '10.36.84.31',
    'port_id': '1.5',
    'peer_port': 'Ethernet68',
    'peer_device': 'sonic-s6100-dut1',
    'speed': '100000',
    'location': '10.36.84.31/1.5',
    'intf_config_changed': False,
    'api_server_ip': '10.36.84.32',
    'asic_type': 'broadcom',
    'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
    'snappi_speed_type': 'speed_100_gbps',
    'asic_value': None,
    'router_mac_address': '9c:69:ed:6f:92:51',
    'src_mac_address': '10:17:00:00:00:11',
    'bgp': {'ipAddress': '204::2', 'ipGateway': '204::1', 'asn': 65200},
    'prefix': 126,
    'subnet': '204::1/126'
    }
    """
    for duthost in duthosts:
        config_facts = duthost.config_facts(host=duthost.hostname,source="running")['ansible_facts']
        bgp_neighbors = config_facts['BGP_NEIGHBOR']
        interfaces = config_facts['INTERFACE']
        # Get the IP address of the peer port
        gateway_to_bgp = {
        v['local_addr']: {'ipAddress': k, 'ipGateway': v['local_addr'], 'asn': int(v['asn'])}
        for k, v in bgp_neighbors.items()
        }
            
        peer_to_gateway = {
            port: (str(ipaddress.ip_interface(ip).ip), ipaddress.ip_interface(ip).network.prefixlen)
            for port, ip_info in interfaces.items()
            for ip in ip_info
        }
        mac_address_generator = get_macs("101700000011", len(get_snappi_ports))
        for index, port in enumerate(get_snappi_ports):
            if port['duthost'] == duthost:
                # Get the IP address of the peer port
                port['router_mac_address'] = port['duthost'].facts['router_mac']
                port['src_mac_address'] = mac_address_generator[index]
                port['ipGateway'] = peer_to_gateway.get(port['peer_port'])[0]
                #port['bgp'] = gateway_to_bgp.get(peer_to_gateway.get(port['peer_port'])[0])
                port['ipAddress'] = gateway_to_bgp.get(port['ipGateway'])['ipAddress']
                port['asn'] = gateway_to_bgp.get(port['ipGateway'])['asn']
                port['prefix'] = peer_to_gateway.get(port['peer_port'])[1]
                port['subnet'] = str(peer_to_gateway.get(port['peer_port'])[0])+"/"+str(peer_to_gateway.get(port['peer_port'])[1])
    return get_snappi_ports

def get_duthost_vlan_details(duthosts, get_snappi_ports):
    """
    Loop through each duthosts to get its vlan details

    Usage:
        duthost_vlan_interface, subnet_tracker, all_vlan_gateway_ip = get_duthost_vlan_details(duthosts)

    Return:
       - duthost_vlan_interface: A dict object containing individual duthost as keys with all the dut's vlan details
       - subnet_tracker:         A list of subnets for calling ip_address_generator() to generate source ip addresses in the subnet
       - all_vlan_gateway_ip:    A list of all the vlan IP addresses for ip_address_generator() to exclude
                                 when providing the ip addresses

       duthost_vlan_interface, subnet_tracker, all_vlan_gateway_ip
    """

    duthost_vlan_interface = {}

    # subnet_tracker is for ip address generator to know how many ip addresses to provide
    subnet_tracker = set()

    # Keep track of all gateway IP addresses to exclude from generating src ip addresses
    all_vlan_gateway_ip = set()

    duthost_vlan_interface = {
        dut.hostname: {"vlan_id": "", "vlan_ip": "", "subnet": "", "ip_prefix": ""}
        for dut in duthosts
    }

    for dut in duthosts:
        # NOTE! This only gets the first vlan interface
        duthost_configdb_vlan_interface = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']["VLAN_INTERFACE"]
        vlan_id = list(duthost_configdb_vlan_interface.keys())[0]
        vlan_ipprefix = list(duthost_configdb_vlan_interface[vlan_id].keys())[0]
        ipn = IPNetwork(vlan_ipprefix)
        vlan_ipaddr, prefix_len = str(ipn.ip), ipn.prefixlen
        subnet = str(IPNetwork(str(ipn.network) + '/' + str(prefix_len)))
        duthost_vlan_interface[dut.hostname] = {
            "vlan_id": vlan_id,
            "vlan_ip": vlan_ipaddr,
            "subnet": subnet,
            "ip_prefix": prefix_len,
        }

        all_vlan_gateway_ip.add(vlan_ipaddr)
        # subnet_tracker is for ip address generator
        subnet_tracker.add(subnet)

    subnet_tracker = list(subnet_tracker)
    all_vlan_gateway_ip = list(all_vlan_gateway_ip)
    mac_address_generator = get_macs("AA0000000000", count=len(get_snappi_ports))
    ip_addresses = get_addrs_in_subnet(
        subnet_tracker[0],
        number_of_ip=len(get_snappi_ports),
        exclude_ips=all_vlan_gateway_ip,
    )
    port_list = []

    for index, port in enumerate(get_snappi_ports):
        speed = port["speed"]
        src_mac_address = mac_address_generator[index]

        # The src port's gateway mac is the router_mac for ALL VLANs
        router_mac_address = port["duthost"].facts["router_mac"]

        port_name = port["location"]
        hostname = port["duthost"].hostname
        vlan_details = duthost_vlan_interface[hostname]
        port_list.append(
            {
                "ipAddress": ip_addresses[index],
                "ipGateway": vlan_details["vlan_ip"],
                "prefix": vlan_details["ip_prefix"],
                "subnet": vlan_details["subnet"],
                "src_mac_address": src_mac_address,
                "router_mac_address": router_mac_address,
                "speed": speed,
                "snappi_speed_type": port["snappi_speed_type"],
                "peer_port": port["peer_port"],
                "location": port["location"],
                "duthost": port["duthost"],
                "api_server_ip": port["api_server_ip"],
                "asic_type": port["asic_type"],
                "asic_value": port["asic_value"],
            }
        )
    return port_list


def get_ti_stats(ixnet):
    tiStatistics = StatViewAssistant(ixnet, "Traffic Item Statistics")
    tdf = pd.DataFrame(tiStatistics.Rows.RawData, columns=tiStatistics.ColumnHeaders)
    selected_columns = [
        "Tx Frames",
        "Rx Frames",
        "Frames Delta",
        "Loss %",
        "Tx Frame Rate",
        "Rx Frame Rate",
    ]
    tmp = tdf[selected_columns]
    return tmp


def get_fanout_port_groups(snappi_ports, fanout_per_port):
    if fanout_per_port > 1:
        num_groups = int(len(snappi_ports) / fanout_per_port)
        group_list = []
        for i in range(fanout_per_port):
            group = []
            for j in range(num_groups):
                group.append(snappi_ports[i + j * fanout_per_port])
            pytest_assert(
                len(group) % 2 == 0,
                "Must have Even number of front panel ports to have equal Tx and Rx ports",
            )
            group_list.append(tuple(group))
    else:
        group_list = [snappi_ports]
    return group_list


def create_traffic_items(
    config, tx_flow_name, rx_flow_name, line_rate=10, frame_size=1024, is_rdma=False, flow_name=None
):
    if flow_name is None:
        test_flow = config.flows.flow(name="{} - {}".format(tx_flow_name, rx_flow_name))[-1]
    else:
        test_flow = config.flows.flow(name="{}".format(flow_name))[-1]
    if isinstance(tx_flow_name, list):
        test_flow.tx_rx.device.tx_names = tx_flow_name
    else:
        test_flow.tx_rx.device.tx_names = [tx_flow_name]
    if isinstance(rx_flow_name, list):
        test_flow.tx_rx.device.rx_names = rx_flow_name
    else:
        test_flow.tx_rx.device.rx_names = [rx_flow_name]
    test_flow.metrics.enable = True
    test_flow.metrics.loss = True
    test_flow.size.fixed = frame_size
    test_flow.rate.percentage = line_rate
    if is_rdma:
        _, ipv4 = test_flow.packet.ethernet().ipv4()
        ipv4.priority.dscp.phb.values = [
            ipv4.priority.dscp.phb.DEFAULT,
        ]
        ipv4.priority.dscp.phb.value = 4
        ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
    return config


def create_snappi_config(snappi_api, tx_ports, rx_ports, is_rdma=False):
    config = snappi_api.config()
    for index, tx_port in enumerate(tx_ports):
        config.ports.port(name="Tx_%d" % index, location=tx_port["location"])
    for index, rx_port in enumerate(rx_ports):
        config.ports.port(name="Rx_%d" % index, location=rx_port["location"])
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = "port settings"
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = False
    layer1.auto_negotiation.link_training = False
    layer1.speed = "speed_" + str(int(int(tx_ports[0]["speed"]) / 1000)) + "_gbps"
    layer1.auto_negotiate = False
    if is_rdma:
        pfc = layer1.flow_control.ieee_802_1qbb
        pfc.pfc_delay = 0
        if pfcQueueGroupSize == 8:
            pfc.pfc_class_0 = 0
            pfc.pfc_class_1 = 1
            pfc.pfc_class_2 = 2
            pfc.pfc_class_3 = 3
            pfc.pfc_class_4 = 4
            pfc.pfc_class_5 = 5
            pfc.pfc_class_6 = 6
            pfc.pfc_class_7 = 7
        elif pfcQueueGroupSize == 4:
            pfc.pfc_class_0 = pfcQueueValueDict[0]
            pfc.pfc_class_1 = pfcQueueValueDict[1]
            pfc.pfc_class_2 = pfcQueueValueDict[2]
            pfc.pfc_class_3 = pfcQueueValueDict[3]
            pfc.pfc_class_4 = pfcQueueValueDict[4]
            pfc.pfc_class_5 = pfcQueueValueDict[5]
            pfc.pfc_class_6 = pfcQueueValueDict[6]
            pfc.pfc_class_7 = pfcQueueValueDict[7]
        else:
            pytest_assert(False, "pfcQueueGroupSize value is not 4 or 8")

    # Tx
    macs_tx = get_macs("101700000011", len(tx_ports))
    macs_rx = get_macs("001700000011", len(rx_ports))

    network = ipaddress.ip_network(tx_ports[0]["subnet"], strict=False)
    is_v4_subnet = isinstance(network, ipaddress.IPv4Network)

    def configure_devices(config, ports, is_ipv4=True, role="Tx"):
        device_names = []
        for index, port_data in enumerate(ports):
            device = config.devices.device(name=f"{role} Topology {index}")[-1]
            eth = device.ethernets.add()
            eth.connection.port_name = f"{role}_{index}"
            eth.name = f"{role}_Ethernet_{index}"
            eth.mac = port_data["src_mac_address"]

            if is_ipv4:
                ip_layer = eth.ipv4_addresses.add()
                ip_layer.name = f"{role}_IPv4_{index}"
            else:
                ip_layer = eth.ipv6_addresses.add()
                ip_layer.name = f"{role}_IPv6_{index}"

            ip_layer.address = port_data["ipAddress"]
            ip_layer.gateway = port_data["ipGateway"]
            ip_layer.prefix = int(port_data["prefix"])
            device_names.append(device.name)
        return device_names

    tx_flow_name = configure_devices(config, tx_ports, is_v4_subnet, "Tx")
    rx_flow_name = configure_devices(config, rx_ports, is_v4_subnet, "Rx")

    return config, tx_flow_name, rx_flow_name



def create_bgp_snappi_config(snappi_api, tx_ports, rx_ports):
    snappi_ports = tx_ports + rx_ports
    config = snappi_api.config()
    for index, snappi_port in enumerate(tx_ports):
        config.ports.port(name="Tx_Port_%d" % index, location=snappi_port["location"])
    for index, snappi_port in enumerate(rx_ports):
        config.ports.port(name="Rx_Port_%d" % index, location=snappi_port["location"])
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = "port settings"
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = False
    layer1.auto_negotiation.link_training = False
    layer1.speed = "speed_" + str(int(int(snappi_ports[0]["speed"]) / 1000)) + "_gbps"
    layer1.auto_negotiate = False

    network = ipaddress.ip_network(snappi_ports[0]["subnet"], strict=False)
    is_v4_subnet = isinstance(network, ipaddress.IPv4Network)

    def configure_devices(config, ports, is_ipv4, role):
        device_names = []
        for index, port_data in enumerate(ports):
            device = config.devices.device(name=f"{role} Topology {index}")[-1]
            eth = device.ethernets.add()
            eth.connection.port_name = f"{role}_Port_{index}"
            eth.name = f"{role} Ethernet_{index}"
            eth.mac = port_data["src_mac_address"]

            if is_ipv4:
                ip_layer = eth.ipv4_addresses.add()
                ip_layer.name = f"{role} IPv4_{index}"
            else:
                ip_layer = eth.ipv6_addresses.add()
                ip_layer.name = f"{role} IPv6_{index}"

            ip_layer.address = port_data["ipAddress"]
            ip_layer.gateway = port_data["ipGateway"]
            ip_layer.prefix = int(port_data["prefix"])
            if role == "Rx":
                if is_ipv4:
                    bgpv4_stack = device.bgp
                    bgpv4_stack.router_id = port_data["ipGateway"]
                    bgpv4_int = bgpv4_stack.ipv4_interfaces.add()
                    bgpv4_int.ipv4_name = ip_layer.name
                    bgpv4_peer = bgpv4_int.peers.add()
                    bgpv4_peer.name = f"{role} BGP_{index}"
                    bgpv4_peer.as_type = 'ebgp'
                    bgpv4_peer.peer_address = port_data["ipGateway"]
                    bgpv4_peer.as_number = port_data["asn"]
                    route_range1 = bgpv4_peer.v4_routes.add(name=f"{role} Network Group_{index}")
                    route_range1.addresses.add(address='200.1.0.1', prefix=32, count=1000)
                    device_names.append(route_range1.name)
                elif not is_ipv4:
                    bgpv6_stack = device.bgp
                    bgpv6_stack.router_id = '1.1.1.1'
                    bgpv6_int = bgpv6_stack.ipv6_interfaces.add()
                    bgpv6_int.ipv6_name = ip_layer.name
                    bgpv6_peer = bgpv6_int.peers.add()
                    bgpv6_peer.name = f"{role} BGP+_{index}"
                    bgpv6_peer.as_type = 'ebgp'
                    bgpv6_peer.peer_address = port_data["ipGateway"]
                    bgpv6_peer.as_number = port_data["asn"]
                    route_range2 = bgpv6_peer.v6_routes.add(name=f"{role} Network Group_{index}")
                    route_range2.addresses.add(address='3000::1', prefix=128, count=1000)
                    device_names.append(route_range2.name)
            else:
                device_names.append(ip_layer.name)
        return device_names
    tx_flow_name = configure_devices(config, tx_ports, is_v4_subnet, "Tx")
    rx_flow_name = configure_devices(config, rx_ports, is_v4_subnet, "Rx")
    return config, tx_flow_name, rx_flow_name
