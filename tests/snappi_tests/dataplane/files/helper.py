import pytest
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
from tests.common.snappi_tests.common_helpers import get_addrs_in_subnet


@pytest.fixture(scope="module")
def setup_snappi_port_configs(duthosts, get_snappi_ports):
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

    duthost_vlan_interface, subnet_tracker, all_vlan_gateway_ip = (
        get_duthost_vlan_details(duthosts)
    )
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


def get_duthost_vlan_details(duthosts):
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
        vlan_interface = dut.minigraph_facts(host=dut.hostname)["ansible_facts"][
            "minigraph_vlan_interfaces"
        ][0]

        duthost_vlan_interface[dut.hostname] = {
            "vlan_id": vlan_interface["attachto"],
            "vlan_ip": vlan_interface["addr"],
            "subnet": vlan_interface["subnet"],
            "ip_prefix": vlan_interface["prefixlen"],
        }

        all_vlan_gateway_ip.add(vlan_interface["addr"])
        # subnet_tracker is for ip address generator
        subnet_tracker.add(vlan_interface["subnet"])

    return (duthost_vlan_interface, list(subnet_tracker), list(all_vlan_gateway_ip))


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


def create_snappi_config(snappi_api, fanout_port_group):
    half_ports = int(len(fanout_port_group) / 2)
    tx_ports = fanout_port_group[:half_ports]
    rx_ports = fanout_port_group[half_ports:]
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
    layer1.speed = (
        "speed_" + str(int(int(fanout_port_group[0]["speed"]) / 1000)) + "_gbps"
    )
    layer1.auto_negotiate = False
    # Tx
    tx_flow_name = []
    for index, tx_port in enumerate(tx_ports):
        d1 = config.devices.device(name="Tx Topology {}".format(index))[-1]
        eth = d1.ethernets.add()
        eth.connection.port_name = "Tx_%d" % index
        eth.name = "Tx_Ethernet_%d" % index
        eth.mac = tx_port["src_mac_address"]
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = "Tx_IPv4_%d" % index
        ipv4.address = tx_port["ipAddress"]
        ipv4.gateway = tx_port["ipGateway"]
        ipv4.prefix = tx_port["prefix"]
        tx_flow_name.append(d1.name)

    # Rx
    rx_flow_name = []
    for index, rx_port in enumerate(rx_ports):
        d2 = config.devices.device(name="Rx Topology {}".format(index))[-1]
        eth = d2.ethernets.add()
        eth.connection.port_name = "Rx_%d" % index
        eth.name = "Rx_Ethernet_%d" % index
        eth.mac = rx_port["src_mac_address"]
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = "Rx_IPv4_%d" % index
        ipv4.address = rx_port["ipAddress"]
        ipv4.gateway = rx_port["ipGateway"]
        ipv4.prefix = rx_port["prefix"]
        rx_flow_name.append(d2.name)

    test_flow = config.flows.flow(name="IPv4 Traffic")[-1]
    test_flow.tx_rx.device.tx_names = tx_flow_name
    test_flow.tx_rx.device.rx_names = rx_flow_name
    test_flow.metrics.enable = True
    test_flow.metrics.loss = True
    test_flow.size.fixed = 512
    test_flow.rate.percentage = 100
    return config

