from tests.snappi_tests.dataplane.imports import *          # noqa: F403, F401, F405
logger = logging.getLogger(__name__)


@dataclass
class IxNetConfigParams:
    traffic_name: str = "TestTraffic"
    frame_size: int = 512
    frame_rate: int = 100
    frame_ordering_mode: str = "RFC2889"
    traffic_type: str = "ipv4"
    traffic_mesh: str = "fullMesh"          # manyToMany oneToOne
    bidirectional: bool = True
    duration: int = 20
    latency_bins: Optional[Dict[str, List[Any]]] = None  # type: ignore
    # latency_bin={"NumberOfBins": 5,"BinLimits": [0.5, 0.75, 1.0, 1.25, 2147483647.0]}
    # Add more as needed


@pytest.fixture(scope="module")
def set_primary_chassis(snappi_api, fanout_graph_facts_multidut, duthosts):    # noqa F811
    primary_chassis = duthosts[0].host.options['variable_manager'] \
        ._hostvars[duthosts[0].hostname].get('chassis_chain_primary', None)
    if len(fanout_graph_facts_multidut) == 1 and primary_chassis:
        slave_chassis = [
            fanout_graph_facts_multidut[fanout]['device_info']['mgmtip']
            for fanout in fanout_graph_facts_multidut
        ]
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
    slaves = [    # noqa F841
        chassis_chain1.secondary.add(
            location=slave,
            sequence_id=index,
            cable_length='6'
        )
        for index, slave in enumerate(slave_chassis, start=2)
    ]


def get_autoneg_fec(duthosts, get_snappi_ports):
    duthost_processed = []
    for port in get_snappi_ports:
        if port['duthost'] not in duthost_processed:
            autonegs = json.loads(port['duthost'].command("intfutil -c autoneg -j")['stdout'])
            fecs = json.loads(port['duthost'].command("intfutil -c fec -j")['stdout'])
        duthost_processed.append(port['duthost'])

        port['autoneg'] = True if autonegs[port["peer_port"]]["Auto-Neg Mode"] == 'enabled' else False
        port['fec'] = True if fecs[port["peer_port"]]["FEC Admin"] == 'rs' else False
    return get_snappi_ports


def get_duthost_interface_details(duthosts, get_snappi_ports, subnet_type, protocol_type):    # noqa F811
    """
    Depending on the protocol type, call the respective function to get the interface details

    Args:
        duthosts: List of duthost objects
        get_snappi_ports: List of snappi port details
        subnet_type: 'ipv4' or 'ipv6'
        protocol_type: 'ip' or 'bgp' or 'vlan'

    Returns:
        List of snappi port details with interface information populated
    """
    if protocol_type.lower() == 'ip':
        return get_duthost_ip_details(duthosts, get_snappi_ports, subnet_type)
    elif protocol_type.lower() == 'bgp':
        return get_duthost_bgp_details(duthosts, get_snappi_ports, subnet_type)
    elif protocol_type.lower() == 'vlan':
        return get_duthost_vlan_details(duthosts, get_snappi_ports, subnet_type)
    else:
        pytest_assert(False, f"Unsupported protocol type: {protocol_type}")


def get_duthost_ip_details(duthosts, get_snappi_ports, subnet_type):  # noqa F811
    """
    Example:
    {
        'ip': '10.36.84.32',
        'port_id': '3',
        'peer_port': 'Ethernet64',
        'peer_device': 'sonic-s6100-dut2',
        'speed': '100000',
        'location': '10.36.84.32/1.1',
        'intf_config_changed': False,
        'api_server_ip': '10.36.78.134',
        'asic_type': 'broadcom',
        'duthost': <MultiAsicSonicHost sonic-s6100-dut2>,
        'snappi_speed_type': 'speed_100_gbps',
        'asic_value': None,
        'autoneg': False,
        'fec': True,
        'ipAddress': '400::2',
        'ipGateway': '400::1',
        'prefix': '126',
        'src_mac_address': '10:17:00:00:00:13',
        'subnet': '400::1/126'
    }
    """
    get_autoneg_fec(duthosts, get_snappi_ports)
    mac_address_generator = get_macs("101700000011", len(get_snappi_ports))
    for duthost in duthosts:
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        doOnce = True
        for index, port in enumerate(get_snappi_ports):
            if port['duthost'] == duthost:
                if doOnce:
                    # Note: Just get the dut mac address once
                    mac = duthost.get_dut_iface_mac(port['peer_port'])
                    doOnce = False
                peer_port = port['peer_port']
                int_addrs = list(config_facts['INTERFACE'][peer_port].keys())
                if subnet_type.lower() == 'ipv4':
                    subnet = [ele for ele in int_addrs if "." in ele]
                    port['ipAddress'] = get_addrs_in_subnet(subnet[0], 1, exclude_ips=[subnet[0].split("/")[0]])[0]
                elif subnet_type.lower() == 'ipv6':
                    subnet = [ele for ele in int_addrs if ":" in ele]
                    port['ipAddress'] = get_addrs_in_subnet(subnet[0], 1, exclude_ips=[subnet[0].split("/")[0]])[0]
                else:
                    pytest.fail(f'Invalid subnet type: {subnet_type}')
                if not subnet:
                    pytest_assert(False, "No IP address found for peer port {}".format(peer_port))
                port['ipGateway'], port['prefix'] = subnet[0].split("/")
                port['router_mac_address'] = mac
                port['src_mac_address'] = mac_address_generator[index]
                port['subnet'] = subnet[0]
    return get_snappi_ports


def get_duthost_bgp_details(duthosts, get_snappi_ports, subnet_type):    # noqa F811
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
    'ipAddress': '204::2',
    'ipGateway': '204::1',
    'asn': 65200},
    'prefix': 126,
    'subnet': '204::1/126'
    }
    """
    get_autoneg_fec(duthosts, get_snappi_ports)
    for duthost in duthosts:
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        bgp_neighbors = config_facts['BGP_NEIGHBOR']
        interfaces = config_facts['INTERFACE']
        # Get the IP address of the peer port
        gateway_to_bgp = {
            v['local_addr']: {
                'ipAddress': k,
                'ipGateway': v['local_addr'],
                'asn': int(v['asn'])
            }
            for k, v in bgp_neighbors.items()
        }
        peer_to_gateway = {}
        subnet_type = subnet_type.lower()
        for port, int_info in interfaces.items():
            for ip_cidr in int_info:
                try:
                    ip_obj = ipaddress.ip_interface(ip_cidr)
                except ValueError:
                    continue  # skip non-IP keys

                if ((subnet_type == 'ipv4' and ip_obj.version == 4) or
                        (subnet_type == 'ipv6' and ip_obj.version == 6)):
                    peer_to_gateway[port] = (str(ip_obj.ip), ip_obj.network.prefixlen)
        mac_address_generator = get_macs("101700000011", len(get_snappi_ports))
        for index, port in enumerate(get_snappi_ports):
            if port['duthost'] == duthost:
                # Get the IP address of the peer port
                port['router_mac_address'] = port['duthost'].facts['router_mac']
                port['src_mac_address'] = mac_address_generator[index]
                port['ipGateway'] = peer_to_gateway.get(port['peer_port'])[0]
                port['ipAddress'] = gateway_to_bgp.get(port['ipGateway'])['ipAddress']
                port['asn'] = gateway_to_bgp.get(port['ipGateway'])['asn']
                port['prefix'] = peer_to_gateway.get(port['peer_port'])[1]
                port['subnet'] = str(peer_to_gateway.get(port['peer_port'])[0]) \
                                    + "/" + str(peer_to_gateway.get(port['peer_port'])[1])  # noqa: E127
    return get_snappi_ports


def get_duthost_vlan_details(duthosts, get_snappi_ports, subnet_type):   # noqa F811
    """
    Loop through each duthosts to get its vlan details

    Usage:
        duthost_vlan_interface, subnet_tracker, all_vlan_gateway_ip = get_duthost_vlan_details(duthosts)

    Return:
       - duthost_vlan_interface: A dict object containing individual duthost as keys with all the dut's vlan details
       - subnet_tracker:         A list of subnets for calling ip_address_generator()
                                 to generate source ip addresses in the subnet
       - all_vlan_gateway_ip:    A list of all the vlan IP addresses for ip_address_generator() to exclude
                                 when providing the ip addresses

       duthost_vlan_interface, subnet_tracker, all_vlan_gateway_ip
    """
    get_autoneg_fec(duthosts, get_snappi_ports)
    duthost_vlan_interface = {
        dut.hostname: {"vlan_id": "", "vlan_ip": "", "subnet": "", "ip_prefix": ""}
        for dut in duthosts
    }
    port_list = []
    for dut_index, dut in enumerate(duthosts):
        # subnet_tracker is for ip address generator to know how many ip addresses to provide
        subnet_tracker = set()
        # Keep track of all gateway IP addresses to exclude from generating src ip addresses
        all_vlan_gateway_ip = set()
        # NOTE! This only gets the first vlan interface
        facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']
        duthost_configdb_vlan_interface = facts["VLAN_INTERFACE"]
        vlan_id = list(duthost_configdb_vlan_interface.keys())[0]
        vlan_ip_dict = duthost_configdb_vlan_interface[vlan_id]
        if subnet_type.lower() == 'ipv4':
            for subnet in vlan_ip_dict.keys():
                if '.' in subnet:
                    vlan_ipprefix = subnet
                    break
        elif subnet_type.lower() == 'ipv6':
            for subnet in vlan_ip_dict.keys():
                if ':' in subnet:
                    vlan_ipprefix = subnet
                    break
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
        mac_address_generator = get_macs("AA0%d00000000" % dut_index, count=len(get_snappi_ports))
        ip_addresses = get_addrs_in_subnet(
            subnet_tracker[0],
            number_of_ip=len(get_snappi_ports),
            exclude_ips=all_vlan_gateway_ip,
        )
        snappi_ports = get_snappi_ports
        for index, port in enumerate(snappi_ports):
            if port['duthost'] == dut:
                speed = port["speed"]
                src_mac_address = mac_address_generator[index]

                # The src port's gateway mac is the router_mac for ALL VLANs
                router_mac_address = port["duthost"].facts["router_mac"]

                hostname = port["duthost"].hostname
                vlan_details = duthost_vlan_interface[hostname]
                port_list.append(
                    {
                        "ipAddress": ip_addresses[index],
                        "ipGateway": vlan_details["vlan_ip"],
                        "prefix": vlan_details["ip_prefix"],
                        "subnet": vlan_details["subnet"],
                        "peer_device": port["peer_device"],
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
                        "port_id": port["port_id"],
                        "fec": port["fec"],
                        "autoneg": port["autoneg"]
                    }
                )
            else:
                continue
    return port_list


def get_snappi_stats(ixnet, view_name, columns=None):
    stat_obj = StatViewAssistant(ixnet, view_name)
    tdf = pd.DataFrame(stat_obj.Rows.RawData, columns=stat_obj.ColumnHeaders)
    selected_columns = columns if columns else stat_obj.ColumnHeaders
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


def create_snappi_l1config(snappi_api, get_snappi_ports, snappi_extra_params):
    snappi_ports = get_snappi_ports
    config = snappi_api.config()
    _ = [config.ports.port(name=f"Port_{p['port_id']}", location=p["location"]) for p in snappi_ports]
    for role, pconfig in snappi_extra_params.protocol_config.items():
        for index, port_data in enumerate(pconfig['ports']):
            layer1 = config.layer1.layer1()[-1]
            layer1.name = f"{port_data['port_id']}"
            layer1.port_names = [f"Port_{port_data['port_id']}"]
            layer1.speed = port_data['snappi_speed_type']
            layer1.ieee_media_defaults = False
            layer1.auto_negotiation.rs_fec = port_data['fec']
            layer1.auto_negotiation.link_training = False
            layer1.auto_negotiate = port_data['autoneg']
            if pconfig.get("is_rdma", False):
                pfc = layer1.flow_control.ieee_802_1qbb
                pfc.pfc_delay = 0
                if pfcQueueGroupSize == 8:
                    for i in range(8):
                        setattr(pfc, f'pfc_class_{i}', i)
                elif pfcQueueGroupSize == 4:
                    for i in range(8):
                        setattr(pfc, f'pfc_class_{i}', pfcQueueValueDict[i])
    return config


@pytest.fixture(scope="module")
def create_snappi_config(snappi_api, get_snappi_ports):
    def _create_snappi_config(snappi_extra_params):
        config = create_snappi_l1config(snappi_api, get_snappi_ports, snappi_extra_params)
        pytest_assert(snappi_extra_params.protocol_config, "No protocol configuration provided in snappi_extra_params")
        snappi_obj_handles = {k: {"ip": [], "network_group": []} for k in snappi_extra_params.protocol_config}
        count = 0
        for role, pconfig in snappi_extra_params.protocol_config.items():
            is_ipv4 = True if pconfig['subnet_type'] == 'IPv4' else False
            for index, port_data in enumerate(pconfig['ports']):
                device = config.devices.device(name=f"{role} Topology {index}")[-1]
                eth = device.ethernets.add(name=f"{role} Ethernet_{index}", mac=port_data["src_mac_address"])
                eth.connection.port_name = f"Port_{port_data['port_id']}"
                ip_name = f"{role} {'IPv4' if is_ipv4 else 'IPv6'}_{index}"
                ip_layer = getattr(eth, 'ipv4_addresses' if is_ipv4 else 'ipv6_addresses').add(
                    name=ip_name,
                    address=port_data["ipAddress"],
                    gateway=port_data["ipGateway"],
                    prefix=int(port_data["prefix"])
                )
                snappi_obj_handles[role]["ip"].append(ip_layer.name)

                if pconfig.get("protocol_type", False) and pconfig['protocol_type'] == "bgp":
                    bgp = device.bgp
                    bgp.router_id = port_data["ipGateway"] if is_ipv4 else '1.1.1.1'
                    iface = bgp.ipv4_interfaces.add() if is_ipv4 else bgp.ipv6_interfaces.add()
                    setattr(iface, 'ipv4_name' if is_ipv4 else 'ipv6_name', ip_layer.name)
                    peer = iface.peers.add(
                        name=f"{role} BGP{'' if is_ipv4 else '+'}_{index}",
                        as_type='ebgp',
                        peer_address=port_data["ipGateway"],
                        as_number=port_data["asn"]
                    )

                    if pconfig.get("route_ranges", []):
                        if is_ipv4:
                            routes = peer.v4_routes.add(name=f"{role}_Network_Group_{index}")
                        else:
                            routes = peer.v6_routes.add(name=f"{role}_Network_Group_{index}")
                        for rr in pconfig['route_ranges'][count]:
                            routes.addresses.add(
                                address=rr[0],
                                prefix=rr[1],
                                count=rr[2],
                            )
                        count += 1
                        snappi_obj_handles[role]["network_group"].append(routes.name)
        return config, snappi_obj_handles
    return _create_snappi_config


def create_traffic_items(config, snappi_extra_params):
    tconfigs = snappi_extra_params.traffic_flow_config
    for indx, traffic in enumerate(tconfigs):
        test_flow = config.flows.flow(name=traffic.get("flow_name", "Flow {}".format(indx)))[-1]
        test_flow.tx_rx.device.tx_names = traffic["tx_names"]
        test_flow.tx_rx.device.rx_names = traffic["rx_names"]
        test_flow.metrics.enable = True
        test_flow.metrics.loss = True
        if "mesh_type" in traffic:
            test_flow.tx_rx.device.mode = traffic["mesh_type"]         # "mesh", one_to_one

        # Default: "continuous" Enum: "fixed_packets" "fixed_seconds" "burst" "continuous"
        if "traffic_duration_fixed_seconds" in traffic:
            test_flow.duration.fixed_seconds.seconds = traffic["traffic_duration_fixed_seconds"]
        elif "traffic_duration_fixed_packets" in traffic:
            test_flow.duration.fixed_packets.packets = traffic["traffic_duration_fixed_packets"]
        test_flow.size.fixed = traffic["frame_size"]
        test_flow.rate.percentage = traffic["line_rate"]
        if traffic.get("is_rdma", False):
            _, ipv4 = test_flow.packet.ethernet().ipv4()
            ipv4.priority.dscp.phb.values = [
                ipv4.priority.dscp.phb.DEFAULT,
            ]
            ipv4.priority.dscp.phb.value = 4
            ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
        if traffic.get("latency", False):
            # Latency Config
            test_flow.metrics.latency.enable = True
            test_flow.metrics.latency.mode = test_flow.metrics.latency.STORE_FORWARD
    return config


def wait_with_message(message, duration):
    """Displays a countdown while waiting."""
    for remaining in range(duration, 0, -1):
        logger.info(f"{message} {remaining} seconds remaining.")
        # sys.stdout.flush()
        time.sleep(1)
    logger.info("")  # Ensure line break after countdown.


@pytest.fixture(scope="function")
def get_dut_to_dut_port(duthosts,  # noqa: F811
                        conn_graph_facts,  # noqa: F811
                        fanout_graph_facts_multidut,  # noqa: F811
                        ):
    def _get_dut_to_dut_port(conn_graph_facts, bt1_device_names):
        device_conn = conn_graph_facts['device_conn']
        bt1_ports = []
        bt1_info = {}
        bt1_device_names = [bt1_device_names]
        for bt1_device_name in bt1_device_names:
            for duthost in duthosts:
                if duthost.hostname != bt1_device_name:
                    for port in device_conn[duthost.hostname].keys():
                        if device_conn[duthost.hostname][port]['peerdevice'] == bt1_device_name:
                            bt1_ports.append(port)
                        else:
                            continue
            if not bt1_ports:
                pytest_assert(False, f"No ports found for {bt1_device_name} in the connection graph.")
            bt1_info[bt1_device_name] = bt1_ports
        return bt1_info
    return _get_dut_to_dut_port


def configure_acl_for_route_withdrawl(destination_ip_list, table_name):
    destination_ips = [
        f"{item[0].split('/')[0].rsplit(':', 1)[0]}:{'/' + str(item[1])}"
        for item in destination_ip_list
    ]
    acl_dict = {
        "acl": {
            "acl-sets": {
                "acl-set": {
                    table_name: {
                        "acl-entries": {
                            "acl-entry": {
                                "1": {
                                    "actions": {
                                        "config": {
                                            "forwarding-action": "DROP"
                                        }
                                    },
                                    "config": {
                                        "sequence-id": 1
                                    },
                                    "ip": {
                                        "config": {
                                            "source-ip-address": "::/0"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # Add one entry for each destination_ip, starting from sequence-id 5, 6, ...
    for idx, destination_ip in enumerate(destination_ips, start=2):
        acl_dict["acl"]["acl-sets"]["acl-set"][table_name]["acl-entries"]["acl-entry"][str(idx)] = {
            "actions": {
                "config": {
                    "forwarding-action": "DROP"
                }
            },
            "config": {
                "sequence-id": idx
            },
            "ip": {
                "config": {
                    "destination-ip-address": destination_ip
                }
            }
        }
    return acl_dict


def get_stats(api, stat_name, columns=None, return_type='stat_obj'):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    def deep_getattr(obj, attr, default=None):
        try:
            for part in attr.split('.'):
                obj = getattr(obj, part)
            return obj
        except AttributeError:
            return default
    request = api.metrics_request()
    if stat_name == "Data Plane Port Statistics":
        ixnet = api._ixnetwork
        dp_metrics = StatViewAssistant(ixnet, stat_name)
        df = pd.DataFrame(dp_metrics.Rows.RawData, columns=dp_metrics.ColumnHeaders)
        df = df[columns] if columns else df
        cols = ['Tx Frame Rate', 'Rx Frame Rate']
        df[cols] = df[cols].apply(pd.to_numeric, errors='coerce')
        if return_type == 'print':
            logger.info("\n%s" % tabulate(df, headers="keys", tablefmt="psql"))
        elif return_type == 'df':
            return df
    if stat_name == "Traffic Item Statistics":
        request.flow.flow_names = []
        stat_obj = api.get_metrics(request).flow_metrics
        column_headers = [
            "bytes_rx", "bytes_tx", "frames_rx", "frames_rx_rate", "frames_tx", "frames_tx_rate",
            "loss", "name", "port_rx", "port_tx", "rx_l1_rate_bps", "rx_rate_bps", "rx_rate_bytes", "rx_rate_kbps",
            "rx_rate_mbps", "transmit", "tx_l1_rate_bps", "tx_rate_bps", "tx_rate_bytes", "tx_rate_kbps",
            "tx_rate_mbps", "latency.average_ns", "latency.maximum_ns", "latency.minimum_ns"
        ]
    elif stat_name == "Port Statistics":
        request.port.port_names = []
        stat_obj = api.get_metrics(request).port_metrics
        column_headers = [
            "bytes_rx", "bytes_rx_rate", "bytes_tx", "bytes_tx_rate", "capture", "frames_rx", "frames_rx_rate",
            "frames_tx", "frames_tx_rate", "link", "location", "name"]
    rows = [
        [deep_getattr(stat, column, None) for column in column_headers]
        for stat in stat_obj
    ]
    tdf = pd.DataFrame(rows, columns=column_headers)
    selected_columns = columns if columns else column_headers
    df = tdf[selected_columns]
    if return_type == 'print':
        logger.info("\n%s" % tabulate(df, headers="keys", tablefmt="psql"))
    elif return_type == 'df':
        return df
    else:
        return stat_obj


def seconds_elapsed(start_seconds):
    return int(round(time.time() - start_seconds))


def timed_out(start_seconds, timeout):
    return seconds_elapsed(start_seconds) > timeout


def wait_for(func, condition_str, interval_seconds=None, timeout_seconds=None):
    """
    Keeps calling the `func` until it returns true or `timeout_seconds` occurs
    every `interval_seconds`. `condition_str` should be a constant string
    implying the actual condition being tested.
    Usage
    -----
    If we wanted to poll for current seconds to be divisible by `n`, we would
    implement something similar to following:
    ```
    import time
    def wait_for_seconds(n, **kwargs):
        condition_str = 'seconds to be divisible by %d' % n
        def condition_satisfied():
            return int(time.time()) % n == 0
        poll_until(condition_satisfied, condition_str, **kwargs)
    ```
    """
    if interval_seconds is None:
        interval_seconds = settings.interval_seconds
    if timeout_seconds is None:
        timeout_seconds = settings.timeout_seconds
    start_seconds = int(time.time())

    logger.info("Waiting for %s ..." % condition_str)
    while True:
        res = func()
        if res:
            logger.info("Done waiting for %s" % condition_str)
            break
        if res is None:
            raise Exception("Wait aborted for %s" % condition_str)
        if timed_out(start_seconds, timeout_seconds):
            msg = "Time out occurred while waiting for %s" % condition_str
            raise Exception(msg)

        time.sleep(interval_seconds)


def get_all_port_names(duthost):
    """
    Get all port names on the DUT as a list
    """
    result = duthost.command("show interfaces status")
    output = result["stdout"]
    interfaces = []
    for line in output.splitlines():
        if line.lstrip().startswith("Ethernet"):
            iface = line.split()[0]
            interfaces.append(iface)
    return interfaces


def all_ports_startup(duthost):
    """
    Startup all interfaces on the DUT
    """
    interfaces = get_all_port_names(duthost)
    logger.info("Starting up all interfaces on DUT {} ".format(duthost.hostname))
    duthost.command("sudo config interface startup {} \n".format(','.join(interfaces)))
    wait(60, "For links to come up")


def all_ports_shutdown(duthost):
    """
    Shutdown all interfaces on the DUT
    """
    interfaces = get_all_port_names(duthost)
    logger.info("Shutting down all interfaces on DUT {} ".format(duthost.hostname))
    duthost.command("sudo config interface shutdown {} \n".format(','.join(interfaces)))
    wait(60, "For links to come up")


def is_traffic_running(snappi_api, flow_names=[]):
    """
    Returns true if traffic in start state
    """
    request = snappi_api.metrics_request()
    request.flow.flow_names = flow_names
    flow_stats = snappi_api.get_metrics(request).flow_metrics
    return all([int(fs.frames_tx_rate) > 0 for fs in flow_stats])


def is_traffic_stopped(snappi_api, flow_names=[]):
    """
    Returns true if traffic in stop state
    """
    fq = snappi_api.metrics_request()
    fq.flow.flow_names = flow_names
    metrics = snappi_api.get_metrics(fq).flow_metrics
    return all([m.transmit == "stopped" for m in metrics])


def is_traffic_converged(snappi_api, flow_names=[], threshold=0.1):
    """
    Returns true if traffic has converged within the threshold
    """
    request = snappi_api.metrics_request()
    request.flow.flow_names = flow_names
    flow_stats = snappi_api.get_metrics(request).flow_metrics
    for fs in flow_stats:
        tx_rate = float(fs.frames_tx_rate)
        rx_rate = float(fs.frames_rx_rate)
        if tx_rate == 0:
            return False
        loss_percentage = ((tx_rate - rx_rate) / tx_rate) * 100
        if loss_percentage > threshold:
            return False
    return True


def start_stop(snappi_api, operation="start", op_type="protocols", waittime=20):
    logger.info("%s %s", operation.capitalize(), op_type)

    cs = snappi_api.control_state()

    state_map = {
        ("protocols", "start"): cs.protocol.all.START,
        ("protocols", "stop"): cs.protocol.all.STOP,
        ("traffic", "start"): cs.traffic.flow_transmit.START,
        ("traffic", "stop"): cs.traffic.flow_transmit.STOP,
    }

    if (op_type, operation) not in state_map:
        raise ValueError(f"Invalid combination: op_type={op_type}, operation={operation}")

    if op_type == "protocols":
        cs.protocol.all.state = state_map[(op_type, operation)]
    elif op_type == "traffic":
        cs.traffic.flow_transmit.state = state_map[(op_type, operation)]

    snappi_api.set_control_state(cs)

    if op_type == "traffic" and operation == "stop":
        wait_for(lambda: is_traffic_stopped(snappi_api), "Traffic to Stop", interval_seconds=1, timeout_seconds=180)
    elif op_type == "traffic" and operation == "start":
        wait_for(lambda: is_traffic_running(snappi_api), "Traffic to Start", interval_seconds=5, timeout_seconds=180)
    else:
        wait(waittime, f"For {op_type} To {operation}")


def check_bgp_state(snappi_api, subnet_type):
    req = snappi_api.metrics_request()
    if subnet_type == "IPv4":
        req.bgpv4.peer_names = []
        bgpv4_metrics = snappi_api.get_metrics(req).bgpv4_metrics
        assert bgpv4_metrics[-1].session_state == "up", "BGP v4 Session State is not UP"
        logger.info("BGP v4 Session State is UP")
    elif subnet_type == "IPv6":
        req.bgpv6.peer_names = []
        bgpv6_metrics = snappi_api.get_metrics(req).bgpv6_metrics
        assert bgpv6_metrics[-1].session_state == "up", "BGP v6 Session State is not UP"
        logger.info("BGP v6 Session State is UP")
