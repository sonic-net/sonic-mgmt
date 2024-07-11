import logging
import json

from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)  # noqa: F401
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import create_ip_list  # noqa: F401
from tests.snappi_tests.variables import T2_SNAPPI_AS_NUM, T2_DUT_AS_NUM, t2_ports, \
     v4_prefix_length, v6_prefix_length, AS_PATHS, t2_dut_ipv4_list, t2_dut_ipv6_list, \
     t2_snappi_ipv4_list, t2_snappi_ipv6_list, BGP_TYPE, TIMEOUT  # noqa: F401

logger = logging.getLogger(__name__)

route_names = []
total_routes = 0


def run_bgp_route_install_test(api,
                               duthosts,
                               traffic_type,
                               snappi_extra_params):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        traffic_type : IPv4 or IPv6 traffic choice
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa F821

    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    iteration = snappi_extra_params.iteration

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    """ Create snappi config """
    for route_range in route_ranges:
        snappi_bgp_config = __snappi_bgp_config(api,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_route_install_time(api,
                               snappi_bgp_config,
                               iteration,
                               traffic_type,
                               route_range)


def run_bgp_route_delete_test(api,
                              duthosts,
                              traffic_type,
                              snappi_extra_params):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        traffic_type : IPv4 or IPv6 traffic choice
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa F821

    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    iteration = snappi_extra_params.iteration

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    """ Create snappi config """
    for route_range in route_ranges:
        snappi_bgp_config = __snappi_bgp_config(api,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_route_delete_time(api,
                              snappi_bgp_config,
                              iteration,
                              traffic_type,
                              route_range)


def duthost_bgp_config(duthosts,
                       snappi_ports):
    """
    Configures BGP on the DUT with snappi_ports

    Args:
        duthosts (pytest fixture): duthosts fixture
        snappi_ports (pytest fixture): Ports mapping info of T0 testbed
    """

    for index, port in enumerate(t2_ports):
        for duthost in duthosts:
            if duthost.hostname == port['hostname']:
                duthost.shell('sudo config interface ip add Loopback0 1::1/124')
                if port['asic_value'] is None:
                    intf_config = (
                        "sudo config interface ip add %s %s/%s\n"
                        "sudo config interface ip add %s %s/%s\n"
                    )
                    intf_config %= (port['port_name'], t2_dut_ipv4_list[index], v4_prefix_length,
                                    port['port_name'], t2_dut_ipv6_list[index], v6_prefix_length)
                else:
                    intf_config = (
                        "sudo config interface -n %s ip add %s %s/%s\n"
                        "sudo config interface -n %s ip add %s %s/%s\n"
                    )
                    intf_config %= (port['asic_value'], port['port_name'], t2_dut_ipv4_list[index], v4_prefix_length,
                                    port['asic_value'], port['port_name'], t2_dut_ipv6_list[index], v6_prefix_length)
                duthost.shell(intf_config)

                logger.info('Configuring IPs {} / {} on {} in {}'.
                            format(t2_dut_ipv4_list[index],
                                   t2_dut_ipv4_list[index], port['port_name'], port['hostname']))
                duthost.shell('sudo config save -y \n')

    logger.info('Dut AS Number: {}'.format(T2_DUT_AS_NUM))
    logger.info('Snappi AS Number: {}'.format(T2_SNAPPI_AS_NUM))

    for duthost in duthosts:
        for index, port in enumerate(t2_ports):
            bgp_neighbors = {}
            device_neighbors = {}
            device_neighbor_metadatas = {}
            if duthost.hostname == port['hostname']:
                device_neighbor = \
                                {
                                    port['port_name']:
                                        {
                                            "name": "snappi_port"+str(index),
                                            "port": port['port_name'],
                                        },
                                }
                device_neighbors.update(device_neighbor)
                device_neighbor_metadata = \
                    {
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
                duthost.shell("sudo config reload -f -y \n")

    for duthost in duthosts:
        for index, port in enumerate(t2_ports):
            if duthost.hostname == port['hostname']:
                if port['asic_value'] is not None:
                    route_map_config = (
                        "vtysh -n %s"
                        "-c 'configure terminal' "
                        "-c 'route-map RM_SET_SRC6 permit 10' "
                        "-c 'on-match next' "
                        "-c 'set ipv6 next-hop prefer-global' "
                        "-c 'exit' "
                        "-c 'ip nht resolve-via-default' "
                        "-c 'ipv6 nht resolve-via-default' "
                        "-c 'ipv6 protocol bgp route-map RM_SET_SRC6' "
                        "-c 'exit' "
                    )
                    route_map_config %= (
                                            port['asic_value'][-1]
                                        )
                    duthost.shell(route_map_config)
                else:
                    route_map_config = (
                        "vtysh -n"
                        "-c 'configure terminal' "
                        "-c 'route-map RM_SET_SRC6 permit 10' "
                        "-c 'on-match next' "
                        "-c 'set ipv6 next-hop prefer-global' "
                        "-c 'exit' "
                        "-c 'ip nht resolve-via-default' "
                        "-c 'ipv6 nht resolve-via-default' "
                        "-c 'ipv6 protocol bgp route-map RM_SET_SRC6' "
                        "-c 'exit' "
                    )
                duthost.shell(route_map_config)
                logger.info('Applying RM_SET_SRC6 route map in {}'.format(duthost.hostname))


def __snappi_bgp_config(api,
                        snappi_ports,
                        traffic_type,
                        route_range):
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
    total_routes = 0
    ipv4_src, ipv6_src = [], []
    ipv4_dest, ipv6_dest = [], []

    snappi_test_ports = []
    conv_config = api.convergence_config()
    config = conv_config.config

    for var_ports in t2_ports:
        for port in snappi_ports:
            if port['peer_port'] == var_ports['port_name'] and port['peer_device'] == var_ports['hostname']:
                snappi_test_ports.append(port)

    # Adding Ports
    for index, snappi_test_port in enumerate(snappi_test_ports):
        snappi_test_port['name'] = 'Test_Port_%d' % index
        config.ports.port(name='Test_Port_%d' % index, location=snappi_test_port['location'])

    line_rate = int(100 * int(int(snappi_test_ports[0]['speed'].split('_')[1]) /
                    (len(t2_ports)-1)) / int(snappi_test_ports[0]['speed'].split('_')[1]))
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = snappi_test_ports[0]['speed']
    layer1.auto_negotiate = False

    for index, port in enumerate(snappi_test_ports):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        device = config.devices.device(name="Device {}".format(index))[-1]
        if index == 0:
            eth = device.ethernets.add()
            eth.port_name = port['name']
            eth.name = 'Ethernet_%d' % index
            eth.mac = "00:10:00:00:00:%s" % m
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'IPv4_%d' % index
            ipv4.address = t2_snappi_ipv4_list[index]
            ipv4.gateway = t2_dut_ipv4_list[index]
            ipv4.prefix = v4_prefix_length
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'IPv6_%d' % index
            ipv6.address = t2_snappi_ipv6_list[index]
            ipv6.gateway = t2_dut_ipv6_list[index]
            ipv6.prefix = v6_prefix_length

            bgpv4 = device.bgp
            bgpv4.router_id = t2_snappi_ipv4_list[index]
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP_%d' % index
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = t2_dut_ipv4_list[index]
            bgpv4_peer.as_number = int(T2_SNAPPI_AS_NUM)

            route_range1 = bgpv4_peer.v4_routes.add(name="IPv4_Routes_%d" % (index))
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
            bgpv6_peer.name = 'BGP+_%d' % index
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = t2_dut_ipv6_list[index]
            bgpv6_peer.as_number = int(T2_SNAPPI_AS_NUM)

            route_range2 = bgpv6_peer.v6_routes.add(name="IPv6_Routes_%d" % (index))
            for route_index, routes in enumerate(route_range['IPv6']):
                route_range2.addresses.add(
                    address=routes[0], prefix=routes[1], count=routes[2])
            ipv6_dest.append(route_range2.name)
            as_path = route_range2.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = AS_PATHS
        else:
            eth = device.ethernets.add()
            eth.port_name = port['name']
            eth.name = 'Ethernet_%d' % index
            eth.mac = "00:10:00:00:00:%s" % m
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'IPv4_%d' % index
            ipv4.address = t2_snappi_ipv4_list[index]
            ipv4.gateway = t2_dut_ipv4_list[index]
            ipv4.prefix = v4_prefix_length
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'IPv6_%d' % index
            ipv6.address = t2_snappi_ipv6_list[index]
            ipv6.gateway = t2_dut_ipv6_list[index]
            ipv6.prefix = v6_prefix_length
            ipv4_src.append(ipv4.name)
            ipv6_src.append(ipv6.name)

    def createTrafficItem(traffic_name, source, destination):

        logger.info('{} Source : {}'.format(traffic_name, source))
        logger.info('{} Destination : {}'.format(traffic_name, destination))
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = source
        flow1.tx_rx.device.rx_names = destination
        flow1.size.fixed = 1024
        flow1.rate.percentage = line_rate
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    if traffic_type == 'IPv4':
        route_names = ipv4_dest
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4_Traffic", ipv4_src, ipv4_dest)
    else:
        route_names = ipv6_dest
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv6 Traffic", ipv6_src, ipv6_dest)
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
                           snappi_bgp_config,
                           iteration,
                           traffic_type,
                           route_range):
    """
    Args:
        api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        iteration: number of iterations for running convergence test on a port
        traffic_type: IPv4 or IPv6 traffic
    """
    global route_names
    snappi_bgp_config.rx_rate_threshold = 90
    api.set_config(snappi_bgp_config)
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
    for i in range(0, iteration):
        logger.info(
            '|---- Route Install test, Iteration : {} ----|'.format(i+1))
        """ withdraw all routes before starting traffic """
        logger.info('Withdraw All Routes before starting traffic')
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.WITHDRAW
        api.set_state(cs)
        wait(TIMEOUT, "For Routes to be withdrawn")
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.START
        api.set_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        """ Start Traffic """
        logger.info('Starting Traffic')
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.START
        api.set_state(cs)
        wait(TIMEOUT, "For Traffic To start")
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
        wait(TIMEOUT, "For all routes to be ADVERTISED")
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
        wait(TIMEOUT, "For Traffic To stop")
        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.STOP
        api.set_state(cs)
        wait(TIMEOUT, "For Protocols To STOP")
    table.append(traffic_type)
    table.append(total_routes)
    table.append(iteration)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    columns = ['Route Type', 'No. of Routes',
               'Iterations', 'Frames Delta', 'BGP Route Install Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))


def get_route_delete_time(api,
                          snappi_bgp_config,
                          iteration,
                          traffic_type,
                          route_range):
    """
    Args:
        api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        iteration: number of iterations for running convergence test on a port
        traffic_type: IPv4 or IPv6 traffic
    """
    global route_names
    snappi_bgp_config.rx_rate_threshold = 90
    api.set_config(snappi_bgp_config)
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    table, avg, avg_delta = [], [], []
    for i in range(0, iteration):
        logger.info(
            '|---- Route Delete test, Iteration : {} ----|'.format(i+1))
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.START
        api.set_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        """ Start Traffic """
        logger.info('Starting Traffic')
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.START
        api.set_state(cs)
        wait(TIMEOUT, "For Traffic To start")
        flow_stats = get_flow_stats(api)
        tx_frame_rate = flow_stats[0].frames_tx_rate
        rx_frame_rate = flow_stats[0].frames_rx_rate
        pytest_assert(tx_frame_rate != 0, "Tx Rate is 0, Traffic has not started !!!")
        pytest_assert(flow_stats[0].loss == 0, "There is traffic loss")

        """ withdraw all routes before starting traffic """
        logger.info('Withdraw All Routes before starting traffic')
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.WITHDRAW
        api.set_state(cs)
        wait(TIMEOUT, "For Routes to be withdrawn")

        flows = get_flow_stats(api)
        tx_frame_rate = flow_stats[0].frames_tx_rate
        rx_frame_rate = flow_stats[0].frames_rx_rate
        pytest_assert(tx_frame_rate != 0, "Tx Rate is 0, Traffic has not started !!!")
        pytest_assert(rx_frame_rate == 0, "Rx Rate is not zero after withdrawing routes")

        request = api.convergence_request()
        request.convergence.flow_names = []
        convergence_metrics = api.get_results(request).flow_convergence
        logger.info('|--------------------------------------|')
        for metrics in convergence_metrics:
            logger.info('Route Delete Time (ms): {}'.format(
                metrics.control_plane_data_plane_convergence_us/1000))
        logger.info('|--------------------------------------|')
        avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
        avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
        """ Advertise All Routes at the end of iteration """
        logger.info('Advertising all Routes from {}'.format(route_names))
        cs = api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.ADVERTISE
        api.set_state(cs)
        wait(5, "For all routes to be ADVERTISED")
        """ Stop traffic at the end of iteration """
        logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
        cs = api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        api.set_state(cs)
        wait(5, "For Traffic To stop")
        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = api.convergence_state()
        cs.protocol.state = cs.protocol.STOP
        api.set_state(cs)
        wait(5, "For Protocols To STOP")
    table.append(traffic_type)
    table.append(total_routes)
    table.append(iteration)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    columns = ['Route Type', 'No. of Routes',
               'Iterations', 'Frames Delta', 'BGP Route Delete Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))
