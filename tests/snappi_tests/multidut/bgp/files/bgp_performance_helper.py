import logging
import json
from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)  # noqa: F401
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import create_ip_list, snappi_api_serv_ip  # noqa: F401
from tests.snappi_tests.variables import T2_SNAPPI_AS_NUM, T2_DUT_AS_NUM, PERFORMANCE_PORTS, \
     v4_prefix_length, v6_prefix_length, AS_PATHS, t2_dut_ipv4_list, t2_dut_ipv6_list, \
     t2_snappi_ipv4_list, t2_snappi_ipv6_list, BGP_TYPE, DUT_TRIGGER, SNAPPI_TRIGGER, router_ids, \
     t1_t2_device_hostnames        # noqa: F401

logger = logging.getLogger(__name__)

rx_port_count = 0
route_names = []
total_routes = 0


def run_bgp_route_install_test(api,
                               duthosts,
                               snappi_extra_params):
    """
    Run BGP route install test test

    Args:
        api (pytest fixture): snappi API
        duthosts: Duthosts fixture
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, _ in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                snappi_ports,
                                                traffic_type,
                                                route_range,
                                                test_name,
                                                )

        get_route_install_time(api,
                               duthosts,
                               snappi_ports,
                               snappi_bgp_config,
                               iteration,
                               traffic_type,
                               route_range,
                               test_name
                               )


def run_bgp_route_delete_test(api,
                              duthosts,
                              snappi_extra_params):
    """
    Run BGP route delete test test

    Args:
        api (pytest fixture): snappi API
        duthosts: Duthosts fixture
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, _ in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                snappi_ports,
                                                traffic_type,
                                                route_range,
                                                test_name,
                                                )

        get_route_delete_time(api,
                              duthosts,
                              snappi_ports,
                              snappi_bgp_config,
                              iteration,
                              traffic_type,
                              route_range,
                              test_name
                              )


def duthost_bgp_config(duthosts,
                       snappi_ports):
    """
    Configures BGP on the DUT with snappi_ports

    Args:
        duthosts (pytest fixture): duthosts fixture
        snappi_ports (pytest fixture): Ports mapping info of T0 testbed
    """

    interfaces = dict()
    loopback_interfaces = dict()
    loopback_interfaces.update({"Loopback0": {}})
    loopback_interfaces.update({"Loopback0|1.1.1.1/32": {}})
    loopback_interfaces.update({"Loopback0|1::1/128": {}})

    logger.info('Dut AS Number: {}'.format(T2_DUT_AS_NUM))
    logger.info('Snappi AS Number: {}'.format(T2_SNAPPI_AS_NUM))

    for duthost in duthosts:
        for index, port in enumerate(PERFORMANCE_PORTS['Traffic_Tx_Ports'] + PERFORMANCE_PORTS['Uplink BGP Session']):
            bgp_neighbors = {}
            device_neighbors = {}
            device_neighbor_metadatas = {}
            if duthost.hostname == port['hostname']:
                interface_name = {port['port_name']: {}}
                v4_interface = {f"{port['port_name']}|{t2_dut_ipv4_list[index]}/{v4_prefix_length}": {}}
                v6_interface = {f"{port['port_name']}|{t2_dut_ipv6_list[index]}/{v6_prefix_length}": {}}
                interfaces.update(interface_name)
                interfaces.update(v4_interface)
                interfaces.update(v6_interface)
                logger.info('Configuring IPs {}/{} , {}/{} on {} in {}'.
                            format(t2_dut_ipv4_list[index], v4_prefix_length,
                                   t2_dut_ipv6_list[index], v6_prefix_length, port['port_name'], duthost.hostname))
                device_neighbor = {
                                    port['port_name']:
                                    {
                                        "name": "snappi_port"+str(index),
                                        "port": port['port_name'],
                                    },
                                }
                device_neighbors.update(device_neighbor)
                device_neighbor_metadata = {
                                                "snappi_port"+str(index):
                                                {
                                                    "hwsku": "Ixia",
                                                    "mgmt_addr": t2_snappi_ipv4_list[index],
                                                    "type": "AZNGHub"
                                                },
                                            }
                bgp_neighbor = {
                                    t2_snappi_ipv4_list[index]:
                                    {
                                        "admin_status": "up",
                                        "asn": T2_SNAPPI_AS_NUM,
                                        "holdtime": "10",
                                        "keepalive": "3",
                                        "local_addr": t2_dut_ipv4_list[index],
                                        "name": "snappi_port"+str(index),
                                        "nhopself": "0",
                                        "rrclient": "0"
                                    },
                                    t2_snappi_ipv6_list[index]:
                                    {
                                        "admin_status": "up",
                                        "asn": T2_SNAPPI_AS_NUM,
                                        "holdtime": "10",
                                        "keepalive": "3",
                                        "local_addr": t2_dut_ipv6_list[index],
                                        "name": "snappi_port"+str(index),
                                        "nhopself": "0",
                                        "rrclient": "0"
                                    },
                                }
                bgp_neighbors.update(bgp_neighbor)
                device_neighbor_metadatas.update(device_neighbor_metadata)

                if port['asic_value'] is not None:
                    sup_config_db_name = 'config_db.json'
                    sup_config_db_data = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
                    config_db_name = 'config_db'+list(port['asic_value'])[-1]+'.json'
                    config_db_data = json.loads(duthost.shell("sonic-cfggen -d -n {} --print-data".
                                                format(port['asic_value']))['stdout'])

                    if "INTERFACE" not in config_db_data.keys():
                        config_db_data["INTERFACE"] = interfaces
                        sup_config_db_data["INTERFACE"] = interfaces
                    else:
                        config_db_data["INTERFACE"].update(interfaces)
                        sup_config_db_data["INTERFACE"].update(interfaces)

                    if "LOOPBACK_INTERFACE" not in config_db_data.keys():
                        config_db_data["LOOPBACK_INTERFACE"] = loopback_interfaces
                        sup_config_db_data["LOOPBACK_INTERFACE"] = loopback_interfaces
                    else:
                        config_db_data["LOOPBACK_INTERFACE"].update(loopback_interfaces)
                        sup_config_db_data["LOOPBACK_INTERFACE"].update(loopback_interfaces)

                    if "DEVICE_NEIGHBOR" not in config_db_data.keys():
                        config_db_data["DEVICE_NEIGHBOR"] = device_neighbors
                        sup_config_db_data["DEVICE_NEIGHBOR"] = device_neighbors
                    else:
                        config_db_data["DEVICE_NEIGHBOR"].update(device_neighbors)
                        sup_config_db_data["DEVICE_NEIGHBOR"].update(device_neighbors)

                    if 'DEVICE_NEIGHBOR_METADATA' not in config_db_data.keys():
                        config_db_data["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadatas
                        sup_config_db_data["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadatas
                    else:
                        config_db_data["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadatas)
                        sup_config_db_data["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadatas)

                    if "BGP_NEIGHBOR" not in config_db_data.keys():
                        config_db_data["BGP_NEIGHBOR"] = bgp_neighbors
                        sup_config_db_data["BGP_NEIGHBOR"] = bgp_neighbors
                    else:
                        config_db_data["BGP_NEIGHBOR"].update(bgp_neighbors)
                        sup_config_db_data["BGP_NEIGHBOR"].update(bgp_neighbors)

                    with open("/tmp/temp_config_sup.json", 'w') as fp:
                        json.dump(sup_config_db_data, fp, indent=4)
                    duthost.copy(src="/tmp/temp_config_sup.json", dest="/etc/sonic/%s" % sup_config_db_name)

                else:
                    config_db_name = 'config_db.json'
                    config_db_data = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
                    if "INTERFACE" not in config_db_data.keys():
                        config_db_data["INTERFACE"] = interfaces
                    else:
                        config_db_data["INTERFACE"].update(interfaces)

                    if "LOOPBACK_INTERFACE" not in config_db_data.keys():
                        config_db_data["LOOPBACK_INTERFACE"] = loopback_interfaces
                    else:
                        config_db_data["LOOPBACK_INTERFACE"].update(loopback_interfaces)

                    if "DEVICE_NEIGHBOR" not in config_db_data.keys():
                        config_db_data["DEVICE_NEIGHBOR"] = device_neighbors
                    else:
                        config_db_data["DEVICE_NEIGHBOR"].update(device_neighbors)

                    if 'DEVICE_NEIGHBOR_METADATA' not in config_db_data.keys():
                        config_db_data["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadatas
                    else:
                        config_db_data["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadatas)

                    if "BGP_NEIGHBOR" not in config_db_data.keys():
                        config_db_data["BGP_NEIGHBOR"] = bgp_neighbors
                    else:
                        config_db_data["BGP_NEIGHBOR"].update(bgp_neighbors)

                with open("/tmp/temp_config.json", 'w') as fp:
                    json.dump(config_db_data, fp, indent=4)
                duthost.copy(src="/tmp/temp_config.json", dest="/etc/sonic/%s" % config_db_name)
                # duthost.shell("sudo config reload -f -y \n")
                pytest_assert('Error' not in duthost.shell("sudo config reload -f -y \n")['stderr'],
                              'Error while reloading config in {} !!!!!'.format(duthost.hostname))
        duthost.shell("sudo config reload -f -y \n")
    wait(DUT_TRIGGER, "For configs to be loaded on the duts")


def __snappi_bgp_config(api,
                        snappi_ports,
                        traffic_type,
                        route_range,
                        test_name,
                        ):
    """
    Creating  BGP config on TGEN

    Args:
        api (pytest fixture): snappi API
        duthosts: multipath + 1
        snappi_ports :  Number of IPv4/IPv6 Routes
        traffic_type: IPv4 or IPv6 routes
        route_range: speed of the port used for test
    """
    global route_names
    global total_routes
    global rx_port_count
    total_routes = 0
    ipv4_src, ipv6_src = [], []
    ipv4_dest, ipv6_dest = [], []
    snappi_tx_ports = []
    snappi_rx_ports = []
    conv_config = api.convergence_config()
    config = conv_config.config
    if 'Single BGP Session' in test_name:
        rx_port_count = 1
    else:
        rx_port_count = len(PERFORMANCE_PORTS['Uplink BGP Session'])

    for var_ports in PERFORMANCE_PORTS['Traffic_Tx_Ports']:
        for port in snappi_ports:
            if port['peer_port'] == var_ports['port_name'] and port['peer_device'] == var_ports['hostname']:
                port['asic_value'] = var_ports['asic_value']
                snappi_tx_ports.append(port)

    for var_ports in PERFORMANCE_PORTS['Uplink BGP Session'][:rx_port_count]:
        for port in snappi_ports:
            if port['peer_port'] == var_ports['port_name'] and port['peer_device'] == var_ports['hostname']:
                port['asic_value'] = var_ports['asic_value']
                snappi_rx_ports.append(port)

    # Adding Ports
    for index, snappi_tx_port in enumerate(snappi_tx_ports):
        if snappi_tx_port['peer_device'] == t1_t2_device_hostnames[1]:
            lc = 'Uplink'
        elif snappi_tx_port['peer_device'] == t1_t2_device_hostnames[2]:
            lc = 'Downlink'
        snappi_tx_port['name'] = 'Snappi_Tx_Port_{}_{}_{}'.format(index, lc, snappi_tx_port['asic_value'])
        config.ports.port(name=snappi_tx_port['name'], location=snappi_tx_port['location'])

    for index, snappi_rx_port in enumerate(snappi_rx_ports):
        if snappi_rx_port['peer_device'] == t1_t2_device_hostnames[1]:
            lc = 'Uplink'
        elif snappi_rx_port['peer_device'] == t1_t2_device_hostnames[2]:
            lc = 'Downlink'
        snappi_rx_port['name'] = 'Snappi_Rx_Port_{}_{}_{}'.format(index, lc, snappi_rx_port['asic_value'])
        config.ports.port(name=snappi_rx_port['name'], location=snappi_rx_port['location'])

    sum_of_rx_speed = rx_port_count * int(snappi_tx_ports[0]['speed'].split('_')[1])
    port_speed = int(snappi_tx_ports[0]['speed'].split('_')[1])
    tx_port_count = len(PERFORMANCE_PORTS['Uplink BGP Session'])
    line_rate = int(100 * ((sum_of_rx_speed/tx_port_count) / port_speed))
    if line_rate > 100:
        line_rate = 100
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = snappi_tx_ports[0]['speed']
    layer1.auto_negotiate = False

    for index, port in enumerate(snappi_tx_ports):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        device = config.devices.device(name="T3_Device_{}".format(index))[-1]
        eth = device.ethernets.add()
        eth.port_name = port['name']
        eth.name = 'T3_Ethernet_%d' % index
        eth.mac = "00:11:00:00:00:%s" % m
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T3_IPv4_%d' % index
        ipv4.address = t2_snappi_ipv4_list[index]
        ipv4.gateway = t2_dut_ipv4_list[index]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T3_IPv6_%d' % index
        ipv6.address = t2_snappi_ipv6_list[index]
        ipv6.gateway = t2_dut_ipv6_list[index]
        ipv6.prefix = v6_prefix_length
        ipv4_src.append(ipv4.name)
        ipv6_src.append(ipv6.name)

    for index, port in enumerate(snappi_rx_ports, len(snappi_tx_ports)):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        device = config.devices.device(name="T3_Device_Rx_{}".format(index))[-1]
        eth = device.ethernets.add()
        eth.port_name = port['name']
        eth.name = 'T3_Ethernet_%d' % index
        eth.mac = "00:10:00:00:00:%s" % m
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T3_IPv4_%d' % index
        ipv4.address = t2_snappi_ipv4_list[index]
        ipv4.gateway = t2_dut_ipv4_list[index]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T3_IPv6_%d' % index
        ipv6.address = t2_snappi_ipv6_list[index]
        ipv6.gateway = t2_dut_ipv6_list[index]
        ipv6.prefix = v6_prefix_length

        bgpv4 = device.bgp
        bgpv4.router_id = router_ids[index]
        bgpv4_int = bgpv4.ipv4_interfaces.add()
        bgpv4_int.ipv4_name = ipv4.name
        bgpv4_peer = bgpv4_int.peers.add()
        bgpv4_peer.name = 'T3_BGP_%d' % index
        bgpv4_peer.as_type = BGP_TYPE
        bgpv4_peer.peer_address = t2_dut_ipv4_list[index]
        bgpv4_peer.as_number = int(T2_SNAPPI_AS_NUM)

        if 'IPv4' in route_range.keys():
            route_range1 = bgpv4_peer.v4_routes.add(name="T3_IPv4_Routes_%d" % (index))
            for route_index, routes in enumerate(route_range['IPv4']):
                route_range1.addresses.add(
                    address=routes[0], prefix=routes[1], count=routes[2])
            ipv4_dest.append(route_range1.name)
            as_path = route_range1.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = AS_PATHS

        bgpv6 = device.bgp
        bgpv6.router_id = t2_snappi_ipv4_list[index]
        bgpv6_int = bgpv6.ipv6_interfaces.add()
        bgpv6_int.ipv6_name = ipv6.name
        bgpv6_peer = bgpv6_int.peers.add()
        bgpv6_peer.name = 'T3_BGP+_%d' % index
        bgpv6_peer.as_type = BGP_TYPE
        bgpv6_peer.peer_address = t2_dut_ipv6_list[index]
        bgpv6_peer.as_number = int(T2_SNAPPI_AS_NUM)

        if 'IPv6' in route_range.keys():
            route_range2 = bgpv6_peer.v6_routes.add(name="T3_IPv6_Routes_%d" % (index))
            for route_index, routes in enumerate(route_range['IPv6']):
                route_range2.addresses.add(
                    address=routes[0], prefix=routes[1], count=routes[2])
            ipv6_dest.append(route_range2.name)
            as_path = route_range2.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = AS_PATHS

    def createTrafficItem(traffic_name, source, destination):
        logger.info('{} Source : {}'.format(traffic_name, source))
        logger.info('{} Destination : {}'.format(traffic_name, destination))
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = source
        flow1.tx_rx.device.rx_names = destination
        flow1.size.fixed = 1024
        flow1.rate.percentage = line_rate/2
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    if 'IPv4' in traffic_type and 'IPv6' in traffic_type:
        route_names = ipv4_dest + ipv6_dest
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4_Traffic", ipv4_src, ipv4_dest)
        createTrafficItem("IPv6_Traffic", ipv6_src, ipv6_dest)
    elif 'IPv6' in traffic_type and 'IPv4' not in traffic_type:
        route_names = ipv6_dest
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv6 Traffic", ipv6_src, ipv6_dest)
    elif 'IPv4' in traffic_type and 'IPv6' not in traffic_type:
        route_names = ipv4_dest
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4 Traffic", ipv4_src, ipv4_dest)
    return conv_config


def get_flow_stats(cvg_api):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = []
    return cvg_api.get_results(request).flow_metric


def get_route_install_time(api,
                           duthosts,
                           snappi_ports,
                           snappi_bgp_config,
                           iteration,
                           traffic_type,
                           route_range,
                           test_name
                           ):
    """
    Args:
        api (pytest fixture): snappi API
        duthosts (pytest fixture): duthosts fixture
        snappi_bgp_config: __tgen_bgp_config
        iteration: number of iterations for running convergence test on a port
        traffic_type: IPv4 or IPv6 traffic
        route_range: V4 and V6 route combination
        test_name: Test name
    """
    global route_names

    snappi_bgp_config.rx_rate_threshold = 95/rx_port_count
    api.set_config(snappi_bgp_config)

    test_platform = TestPlatform(snappi_ports[0]['api_server_ip'])
    username = duthosts[0].host.options['variable_manager']\
               ._hostvars[duthosts[0].hostname]['secret_group_vars']['snappi_api_server']['user']    # noqa: E127
    password = duthosts[0].host.options['variable_manager']\
               ._hostvars[duthosts[0].hostname]['secret_group_vars']['snappi_api_server']['password']   # noqa: E127
    test_platform.Authenticate(username, password)
    session = SessionAssistant(IpAddress=snappi_ports[0]['api_server_ip'],
                               UserName=username, SessionId=test_platform.Sessions.find()[-1].Id, Password=password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(router_ids[index])
            logger.info('Setting Router id {} for {}'.format(router_ids[index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue

    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
    for i in range(0, iteration):
        logger.info(
            '|---- Route Install test, Iteration : {} ----|'.format(i+1))
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.START
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Protocols To start")
        logger.info('Verifying protocol sessions state')
        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
        protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)

        """ withdraw all routes before starting traffic """
        logger.info('Withdraw All Routes before starting traffic')
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.WITHDRAW
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Routes to be withdrawn")

        """ Start Traffic """
        logger.info('Starting Traffic')
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.START
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Traffic To start")
        flow_stats = get_flow_stats(api)
        tx_frame_rate = flow_stats[0].frames_tx_rate
        rx_frame_rate = flow_stats[0].frames_rx_rate
        pytest_assert(tx_frame_rate != 0, "Traffic has not started")
        pytest_assert(rx_frame_rate == 0, "Rx Rate must be zero")
        """ Advertise All Routes """
        logger.info('Advertising all Routes from {}'.format(route_names))
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.ADVERTISE
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For all routes to be ADVERTISED")
        flows = get_flow_stats(api)
        for flow in flows:
            tx_frate.append(flow.frames_tx_rate)
            rx_frate.append(flow.frames_rx_rate)
        assert abs(sum(tx_frate) - sum(rx_frate)) < 500, \
            "Traffic has not convergedv, TxFrameRate:{},RxFrameRate:{}"\
            .format(sum(tx_frate), sum(rx_frate))
        logger.info("Traffic has converged after route advertisement")

        request = api.convergence_request()
        request.convergence.flow_names = []
        convergence_metrics = api.get_results(request).flow_convergence
        logger.info('|--------------------------------------|')
        for metrics in convergence_metrics:
            logger.info('Route Install Time (ms): {}'.format(
                metrics.control_plane_data_plane_convergence_us/1000))
        logger.info('|--------------------------------------|')

        avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
        avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
        """ Stop traffic at the end of iteration """
        logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Traffic To stop")
        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.STOP
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Protocols To STOP")
    table.append(test_name)
    table.append(traffic_type)
    table.append(total_routes)
    table.append(rx_port_count)
    table.append(iteration)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    columns = ['Test Name', 'Traffic Type', 'No. of Routes', 'BGP Sessions',
               'Iterations', 'Frames Delta', 'BGP Route Install Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))


def get_route_delete_time(api,
                          duthosts,
                          snappi_ports,
                          snappi_bgp_config,
                          iteration,
                          traffic_type,
                          route_range,
                          test_name):
    """
    Args:
        api (pytest fixture): snappi API
        duthosts (pytest fixture): duthosts fixture
        snappi_bgp_config: __tgen_bgp_config
        iteration: number of iterations for running convergence test on a port
        traffic_type: IPv4 or IPv6 traffic
        route_range: V4 and V6 route combination
        test_name: Test name
    """
    global route_names

    snappi_bgp_config.rx_rate_threshold = 95/rx_port_count
    api.set_config(snappi_bgp_config)

    test_platform = TestPlatform(snappi_ports[0]['api_server_ip'])
    username = duthosts[0].host.options['variable_manager']\
               ._hostvars[duthosts[0].hostname]['secret_group_vars']['snappi_api_server']['user']    # noqa: E127
    password = duthosts[0].host.options['variable_manager']\
               ._hostvars[duthosts[0].hostname]['secret_group_vars']['snappi_api_server']['password']   # noqa: E127
    test_platform.Authenticate(username, password)
    session = SessionAssistant(IpAddress=snappi_ports[0]['api_server_ip'],
                               UserName=username, SessionId=test_platform.Sessions.find()[-1].Id, Password=password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(router_ids[index])
            logger.info('Setting Router id {} for {}'.format(router_ids[index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue

    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    table, avg, tx_frate, rx_frate = [], [], [], []
    for i in range(0, iteration):
        logger.info(
            '|---- Route Install test, Iteration : {} ----|'.format(i+1))
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.START
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Protocols To start")
        logger.info('Verifying protocol sessions state')
        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
        protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)

        """ Start Traffic """
        logger.info('Starting Traffic')
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.START
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Traffic To start")
        """ withdraw all routes before starting traffic """
        logger.info('Withdraw All Routes before starting traffic')
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.WITHDRAW
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Routes to be withdrawn")
        TI_Statistics = StatViewAssistant(ixnetwork, 'User Defined Statistics')
        lastStreamPacketTimestamp = TI_Statistics.Rows[0]["Last TimeStamp"]
        eventStartTimestamp = TI_Statistics.Rows[0]['Event Start Timestamp']
        time = float(lastStreamPacketTimestamp.split(':')[-1]) - float(eventStartTimestamp.split(':')[-1])
        flow_stats = get_flow_stats(api)
        tx_frame_rate = flow_stats[0].frames_tx_rate
        rx_frame_rate = flow_stats[0].frames_rx_rate
        pytest_assert(tx_frame_rate != 0, "Traffic has not started")
        pytest_assert(rx_frame_rate == 0, "Rx Rate must be zero")

        logger.info('|--------------------------------------|')
        logger.info('Route Delete Time: {} (ms)'.format(int(round(time, 3) * 1000)))
        logger.info('|--------------------------------------|')

        """ Advertise All Routes at the end of iteration """
        logger.info('Advertising all Routes from {}'.format(route_names))
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.ADVERTISE
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For all routes to be ADVERTISED")
        flows = get_flow_stats(api)
        for flow in flows:
            tx_frate.append(flow.frames_tx_rate)
            rx_frate.append(flow.frames_rx_rate)
        assert abs(sum(tx_frate) - sum(rx_frate)) < 500, \
            "Traffic has not convergedv, TxFrameRate:{},RxFrameRate:{}"\
            .format(sum(tx_frate), sum(rx_frate))
        logger.info("Traffic has converged after route advertisement")
        avg.append(int(round(time, 3) * 1000))
        """ Stop traffic at the end of iteration """
        logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Traffic To stop")
        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.STOP
        api.set_state(cs)
        wait(SNAPPI_TRIGGER, "For Protocols To STOP")
    table.append(test_name)
    table.append(traffic_type)
    table.append(total_routes)
    table.append(rx_port_count)
    table.append(iteration)
    table.append(mean(avg))
    columns = ['Test Name', 'Traffic Type', 'No. of Routes', 'BGP Sessions',
               'Iterations', 'BGP Route Delete Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))
