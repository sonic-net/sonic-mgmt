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

        for port, ip_info in interfaces.items():
            for ip in ip_info:
                if subnet_type == 'IPv4' and not ipaddress.ip_address(ip.split('/')[0]).version == 4:
                    continue
                ip_obj = ipaddress.ip_interface(ip)
                ip_address = str(ip_obj.ip)
                prefix_length = ip_obj.network.prefixlen
                peer_to_gateway[port] = (ip_address, prefix_length)
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


def get_duthost_vlan_details(duthosts, get_snappi_ports):   # noqa F811
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
        facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']
        duthost_configdb_vlan_interface = facts["VLAN_INTERFACE"]
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
    snappi_ports = natsorted(get_snappi_ports, key=lambda x: x['location'])

    for index, port in enumerate(snappi_ports):
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
            if pconfig['is_rdma']:
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

                if pconfig['protocol_type'] == "bgp":
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
                    if pconfig['network_group'] and 'route_ranges' in pconfig:
                        route_range = pconfig['route_ranges']
                        if is_ipv4:
                            routes = peer.v4_routes.add(name=f"Network_Group_{index}")
                        else:
                            routes = peer.v6_routes.add(name=f"Network_Group_{index}")
                        for rr in route_range:
                            routes.addresses.add(
                                address=rr[0],
                                prefix=rr[1],
                                count=rr[2],
                            )
                        snappi_obj_handles[role]["network_group"].append(routes.name)
        return config, snappi_obj_handles
    return _create_snappi_config


def create_traffic_items(config, snappi_extra_params):
    tconfigs = snappi_extra_params.traffic_flow_config
    for traffic in tconfigs:
        test_flow = config.flows.flow(name="{}".format(traffic["flow_name"]))[-1]
        test_flow.tx_rx.device.tx_names = traffic["tx_names"]
        test_flow.tx_rx.device.rx_names = traffic["rx_names"]
        test_flow.metrics.enable = True
        test_flow.metrics.loss = True
        test_flow.size.fixed = traffic["frame_size"]
        test_flow.rate.percentage = traffic["line_rate"]
        if traffic["is_rdma"]:
            _, ipv4 = test_flow.packet.ethernet().ipv4()
            ipv4.priority.dscp.phb.values = [
                ipv4.priority.dscp.phb.DEFAULT,
            ]
            ipv4.priority.dscp.phb.value = 4
            ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
    return config


def setup_ixnetwork_config(ixnet, port_config_list, port_distrbution, config: IxNetConfigParams):
    # Assign Ports
    port_list = [
        {"xpath": f"/vport[{i+1}]", "location": port['location'], "name": f"Port-{i:02d}"}
        for i, port in enumerate(port_config_list)
    ]
    logger.info("Assigning Ports...")
    ixnet.ResourceManager.ImportConfig(json.dumps(port_list), False)

    # Assign IPs
    vports = ixnet.Vport.find()
    port_w, port_e = port_distrbution
    eth_w = (
        ixnet.Topology.add(Name="West", Vports=vports[port_w])
        .DeviceGroup.add(Name="Device West", Multiplier="1")
        .Ethernet.add()
    )
    eth_e = (
        ixnet.Topology.add(Name="East", Vports=vports[port_e])
        .DeviceGroup.add(Name="Device East", Multiplier="1")
        .Ethernet.add()
    )
    if config.traffic_type == "ipv4":
        ip_w = eth_w.Ipv4.add(Name="Ipv4 West")
        ip_e = eth_e.Ipv4.add(Name="Ipv4 East")
        bgp_w = ip_w.BgpIpv4Peer.add(Name='BGP W')
        bgp_e = ip_e.BgpIpv4Peer.add(Name='BGP E')
    else:
        ip_w = eth_w.Ipv6.add(Name="Ipv6 West")
        ip_e = eth_e.Ipv6.add(Name="Ipv6 East")
        bgp_w = ip_w.BgpIpv6Peer.add(Name='BGP+ W')
        bgp_e = ip_e.BgpIpv6Peer.add(Name='BGP+ E')
    ip, gw, asn = map(list, zip(*[[pc['ipAddress'], pc['ipGateway'], pc['asn']] for pc in port_config_list]))
    ip_w.Address.ValueList(ip[port_w])
    ip_w.GatewayIp.ValueList(gw[port_w])
    ip_e.Address.ValueList(ip[port_e])
    ip_e.GatewayIp.ValueList(gw[port_e])
    bgp_w.DutIp.ValueList(gw[port_w])
    bgp_w.Type.Single('external')
    bgp_w.LocalAs2Bytes.ValueList(asn[port_w])
    bgp_e.DutIp.ValueList(gw[port_e])
    bgp_e.Type.Single('external')
    bgp_e.LocalAs2Bytes.ValueList(asn[port_e])
    # Start protocols
    logger.info("Starting protocols...")
    start_protocols(ixnet)

    # Create traffic
    ixnet.Traffic.FrameOrderingMode = config.frame_ordering_mode
    trafficItem = ixnet.Traffic.TrafficItem.add(
        Name=config.traffic_name,
        BiDirectional=config.bidirectional,
        SrcDestMesh=config.traffic_mesh,
        TrafficType=config.traffic_type,
    )

    if config.bidirectional:
        trafficItem.EndpointSet.add(Sources=ixnet.Topology.find(), Destinations=ixnet.Topology.find())
    else:
        trafficItem.EndpointSet.add(
            Sources=ixnet.Topology.find(Name="East"),
            Destinations=ixnet.Topology.find(Name="West")
        )

    configElement = trafficItem.ConfigElement.find()[0]
    configElement.FrameRate.update(Rate=config.frame_rate, Type="percentLineRate")
    configElement.TransmissionControl.update(Duration=20, Type="continous")
    configElement.FrameRateDistribution.PortDistribution = "applyRateToAll"
    configElement.FrameSize.FixedSize = config.frame_size

    tracking = trafficItem.Tracking.find()[0]
    tracking.TrackBy = ["sourceDestPortPair0"]

    if config.latency_bins:
        lbin = tracking.LatencyBin.find()
        lbin.Enabled = True
        lbin.NumberOfBins = config.latency_bins.get("NumberOfBins")
        lbin.BinLimits = config.latency_bins.get("BinLimits")
        start_traffic(ixnet, generate_apply_traffic=True)
        logger.info("Creating Traffic Flow Latency Bin Filtering View...")
        # bin_view = ixnet.Statistics.View.add(
        #     Caption=config.latency_bins.get("Caption", "Bin Statistics"),
        #     Visible=True,
        #     Type="layer23TrafficFlow"
        # )
        # Configure the Layer23 Traffic Flow Filter
        fdd = binView.Layer23TrafficFlowFilter.find()
        fdd.update(
            AggregatedAcrossPorts=False,
            PortFilterIds=binView.AvailablePortFilter.find(),
            TrafficItemFilterId=binView.AvailableTrafficItemFilter.find()[0],
            EgressLatencyBinDisplayOption="showLatencyBinStats",
        )
        fdd.EnumerationFilter.add(
            SortDirection="ascending",
            TrackingFilterId=binView.AvailableTrackingFilter.find()[0],
        )
        [
            setattr(stat, "Enabled", True)
            for stat in binView.Statistic.find()
            if "Store-Forward Avg Latency (ns)" in stat.Caption
        ]
        binView.Enabled = True
        stop_traffic(ixnet)


def start_protocols(ixnet):
    try:
        ixnet.StartAllProtocols(Arg1="sync")
        logger.info("Verifying protocols...")
        view = StatViewAssistant(ixnet, "Protocols Summary")
        view.CheckCondition("Sessions Not Started", StatViewAssistant.EQUAL, 0, 180)
        view.CheckCondition("Sessions Down", StatViewAssistant.EQUAL, 0, 180)
        logger.info("Protocols up and running.")
    except Exception as e:
        logger.info("ERROR:Protocols session are down.")
        raise Exception(str(e))


def stop_protocols(ixnet):
    ixnet.StopAllProtocols(Arg1="sync")
    try:
        logger.info("Verify protocol sessions stopped")
        protocolsSummary = StatViewAssistant(ixnet, "Protocols Summary")
        protocolsSummary.CheckCondition("Sessions Down", StatViewAssistant.EQUAL, 0, 180)
        protocolsSummary.CheckCondition("Sessions Up", StatViewAssistant.EQUAL, 0, 180)
    except Exception as e:
        logger.info("ERROR:Protocols session are down.")
        raise Exception(str(e))


def start_traffic(ixnet, generate_apply_traffic=False):
    """Starts the traffic and ensures frames are being transmitted."""
    if generate_apply_traffic:
        logger.info("Generating Traffic")
        ixnet.Traffic.TrafficItem.find()[0].Generate()
        logger.info("Applying Traffic")
        ixnet.Traffic.Apply()

    logger.info("\tStarting traffic...")
    ixnet.Traffic.StartStatelessTrafficBlocking()
    ti = StatViewAssistant(ixnet, "Traffic Item Statistics")

    if not ti.CheckCondition("Tx Frames", StatViewAssistant.GREATER_THAN, 0):
        raise Exception("Traffic did not start properly.")
    logger.info("\tTraffic started successfully.")


def stop_traffic(ixnet, timeout=180, interval=3):
    """Stops traffic and ensures it is fully stopped within the timeout period."""
    if ixnet.Traffic.IsTrafficRunning:
        logger.info("\tStopping traffic...")
        ixnet.Traffic.StopStatelessTrafficBlocking()

        for _ in range(0, timeout, interval):
            if not ixnet.Traffic.IsTrafficRunning:
                logger.info("\tTraffic successfully stopped.")
                return
            time.sleep(interval)

        raise TimeoutError("\tTraffic did not stop within the timeout period.")


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
    request = api.metrics_request()
    if stat_name == "Traffic Item Statistics":
        request.flow.flow_names = []
        stat_obj = api.get_metrics(request).flow_metrics
        column_headers = [
            "bytes_rx",
            "bytes_tx",
            "frames_rx",
            "frames_rx_rate",
            "frames_tx",
            "frames_tx_rate",
            "loss",
            "name",
            "port_rx",
            "port_tx",
            "rx_l1_rate_bps",
            "rx_rate_bps",
            "rx_rate_bytes",
            "rx_rate_kbps",
            "rx_rate_mbps",
            "transmit",
            "tx_l1_rate_bps",
            "tx_rate_bps",
            "tx_rate_bytes",
            "tx_rate_kbps",
            "tx_rate_mbps",
        ]
    elif stat_name == "Port Statistics":
        request.port.port_names = []
        stat_obj = api.get_metrics(request).port_metrics
        column_headers = [
            "bytes_rx",
            "bytes_rx_rate",
            "bytes_tx",
            "bytes_tx_rate",
            "capture",
            "frames_rx",
            "frames_rx_rate",
            "frames_tx",
            "frames_tx_rate",
            "link",
            "location",
            "name"
        ]
    rows = [
        [getattr(stat, column, None) for column in column_headers]
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


def start_stop(snappi_api, operation="start", op_type="protocols"):
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
    wait(20, f"For {op_type} To {operation}")


def check_bgp_state(snappi_api, type):
    req = snappi_api.metrics_request()
    if type == "bgpv4":
        req.bgpv4.peer_names = []
        bgpv4_metrics = snappi_api.get_metrics(req).bgpv4_metrics
        assert bgpv4_metrics[-1].session_state == "up", "BGP v4 Session State is not UP"
        logger.info("BGP v4 Session State is UP")
    elif type == "bgpv6":
        req.bgpv6.peer_names = []
        bgpv6_metrics = snappi_api.get_metrics(req).bgpv6_metrics
        assert bgpv6_metrics[-1].session_state == "up", "BGP v6 Session State is not UP"
        logger.info("BGP v6 Session State is UP")
