import logging
from tabulate import tabulate
from statistics import mean
import json
from tests.common.utilities import wait
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
logger = logging.getLogger(__name__)

TGEN_AS_NUM = 65200
DUT_AS_NUM = 65100
TIMEOUT = 30
BGP_TYPE = 'ebgp'
temp_tg_port = dict()
lacpdu_interval_dict = {0: 'Auto', 1: 'Fast', 30: 'Slow'}
lacpdu_timeout_dict = {0: 'Auto', 3: 'Short', 90: 'Long'}
aspaths = [65002, 65003]


def run_lacp_add_remove_link_physically(snappi_api,
                                        duthost,
                                        tgen_ports,
                                        iteration,
                                        port_count,
                                        number_of_routes,):
    """
    Run Local link failover test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        port_count: total number of ports used in test
        number_of_routes:  Number of IPv4/IPv6 Routes
    """

    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        tgen_ports,
                                        number_of_routes,)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_lacp_add_remove_link_physically(snappi_api,
                                        tgen_bgp_config,
                                        tgen_ports,
                                        iteration,
                                        port_count,
                                        number_of_routes,)


def run_lacp_timers_effect(snappi_api,
                           duthost,
                           tgen_ports,
                           iteration,
                           port_count,
                           number_of_routes,
                           lacpdu_interval_period,
                           lacpdu_timeout,):
    """
    Run Local link failover test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        port_count: total number of ports used in test
        number_of_routes:  Number of IPv4/IPv6 Routes
        port_speed: speed of the port used for test
    """

    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        tgen_ports,
                                        number_of_routes,
                                        lacpdu_interval_period,
                                        lacpdu_timeout,)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_lacp_add_remove_link_physically(snappi_api,
                                        tgen_bgp_config,
                                        tgen_ports,
                                        iteration,
                                        port_count,
                                        number_of_routes,)


def run_lacp_add_remove_link_from_dut(snappi_api,
                                      duthost,
                                      tgen_ports,
                                      iteration,
                                      port_count,
                                      number_of_routes,):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        port_count: total number of ports used in test
        number_of_routes:  Number of IPv4/IPv6 Routes
    """

    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        tgen_ports,
                                        number_of_routes)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_lacp_add_remove_link_from_dut(snappi_api,
                                      duthost,
                                      tgen_bgp_config,
                                      tgen_ports,
                                      iteration,
                                      port_count,
                                      number_of_routes,)


def duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count: total number of ports used in test
    """
    global temp_tg_port
    temp_tg_port = tgen_ports
    for i in range(0, port_count):
        intf_config = (
            "sudo config interface ip remove %s %s/%s \n"
            "sudo config interface ip remove %s %s/%s \n"
        )
        intf_config %= (tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ip'], tgen_ports[i]['prefix'],
                        tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ipv6'], tgen_ports[i]['ipv6_prefix'])
        logger.info('Removing configured IP and IPv6 Address from %s' %
                    (tgen_ports[i]['peer_port']))
        duthost.shell(intf_config)

    tx_portchannel_config = (
        "sudo config portchannel add PortChannel1 \n"
        "sudo config portchannel member add PortChannel1 %s\n"
        "sudo config interface ip add PortChannel1 %s/%s\n"
        "sudo config interface ip add PortChannel1 %s/%s\n"
    )
    tx_portchannel_config %= (tgen_ports[0]['peer_port'], tgen_ports[0]
                              ['peer_ip'], tgen_ports[0]['prefix'], tgen_ports[0]['peer_ipv6'],
                              tgen_ports[0]['ipv6_prefix'])
    logger.info('Configuring %s to PortChannel1 with IPs %s,%s' % (
        tgen_ports[0]['peer_port'], tgen_ports[0]['peer_ip'], tgen_ports[0]['peer_ipv6']))
    duthost.shell(tx_portchannel_config)
    duthost.shell("sudo config portchannel add PortChannel2 \n")
    for i in range(1, port_count):
        rx_portchannel_config = (
            "sudo config portchannel member add PortChannel2 %s\n"
        )
        rx_portchannel_config %= (tgen_ports[i]['peer_port'])
        logger.info('Configuring %s to PortChannel2' %
                    (tgen_ports[i]['peer_port']))
        duthost.shell(rx_portchannel_config)
    duthost.shell("sudo config interface ip add PortChannel2 %s/%s \n" %
                  (tgen_ports[1]['peer_ip'], tgen_ports[1]['prefix']))
    duthost.shell("sudo config interface ip add PortChannel2 %s/%s \n" %
                  (tgen_ports[1]['peer_ipv6'], tgen_ports[1]['ipv6_prefix']))

    logger.info('Saving the config in config_db.json before adding BGP configuration in the config_db.json')
    duthost.command("sudo config save -y")

    loopback_interfaces = {
        "Loopback0": {},
        "Loopback0|1.1.1.1/32": {},
        "Loopback0|1::1/128": {},
    }
    config_db = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    portchannel_ports = [tgen_ports[1]]
    bgp_neighbors = {
        addr: {
            "admin_status": "up",
            "asn": TGEN_AS_NUM,
            "holdtime": "10",
            "keepalive": "3",
            "local_addr": ip_version,
            "name": "snappi-sonic",
            "nhopself": "0",
            "rrclient": "0",
        }
        for port in portchannel_ports
        for addr, ip_version in [(port['ip'], port['peer_ip']), (port['ipv6'], port['peer_ipv6'])]
    }

    device_neighbors = {
        port['peer_port']: {
            "name": "snappi-sonic",
            "port": "Ethernet1"
        }
        for port in tgen_ports[1:]
    }

    device_neighbor_metadatas = {
        "snappi-sonic": {
            "hwsku": "snappi-sonic",
            "mgmt_addr": "172.16.149.206",
            "type": "TORRouter"
        }
    }
    config_db_keys = config_db.keys()  # noqa: F841
    config_db.setdefault("LOOPBACK_INTERFACE", {}).update(loopback_interfaces)
    config_db.setdefault("BGP_NEIGHBOR", {}).update(bgp_neighbors)
    config_db.setdefault("DEVICE_NEIGHBOR_METADATA", {}).update(device_neighbor_metadatas)
    config_db.setdefault("DEVICE_NEIGHBOR", {}).update(device_neighbors)
    with open("/tmp/temp_config.json", 'w') as fp:
        json.dump(config_db, fp, indent=4)
    duthost.copy(src="/tmp/temp_config.json", dest="/etc/sonic/config_db.json")
    logger.info("Reloading config on DUT {}".format(duthost.hostname))

    error = duthost.command("sudo config reload -f -y \n")['stderr']
    if 'Error' in error:
        pytest_assert('Error' not in duthost.shell("sudo config reload -y \n")['stderr'],
                      'Error while reloading config in {} !!!!!'.format(duthost.hostname))
    wait(60, "For DUT to come back online after config reload")
    logger.info('Config Reload Successful in {} !!!'.format(duthost.hostname))


def __tgen_bgp_config(snappi_api,
                      port_count,
                      tgen_ports,
                      number_of_routes,
                      lacpdu_interval_period=0,
                      lacpdu_timeout=0,):
    """
    Creating  BGP config on TGEN

    Args:
        snappi_api (pytest fixture): snappi API
        port_count: total number of ports used in test
        number_of_routes:  Number of IPv4/IPv6 Routes
        lacpdu_interval_period: LACP update packet interval ( 0 - Auto, 1- Fast, 30 - Slow )
        lacpdu_timeout: LACP Timeout value (0 - Auto, 3 - Short, 90 - Long)
    """
    config = snappi_api.config()
    temp_tg_port = tgen_ports
    for i in range(1, port_count+1):
        config.ports.port(name='Test_Port_%d' %
                          i, location=temp_tg_port[i-1]['location'])

    lag0 = config.lags.lag(name="lag0")[-1]
    lag0.protocol.lacp.actor_system_id = "00:10:00:00:11:11"

    lp = lag0.ports.port(port_name='Test_Port_1')[-1]
    lp.ethernet.name = "eth0"
    lp.ethernet.mac = "00:11:02:00:10:01"
    lp.lacp.lacpdu_periodic_time_interval = lacpdu_interval_period
    lp.lacp.lacpdu_timeout = lacpdu_timeout

    lag1 = config.lags.lag(name="lag1")[-1]
    for i in range(2, port_count+1):
        lagport = lag1.ports.port(port_name='Test_Port_%d' % i)[-1]
        if len(str(hex(i).split('0x')[1])) == 1:
            m = '0'+hex(i).split('0x')[1]
        else:
            m = hex(i).split('0x')[1]
        lag1.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m

        lagport.lacp.lacpdu_periodic_time_interval = lacpdu_interval_period
        lagport.lacp.lacpdu_timeout = lacpdu_timeout

        lagport.ethernet.name = "eth%d" % i
        lagport.ethernet.mac = "00:10:04:00:00:%s" % m
    logger.info('|-------------- LACP Timers --------------|')
    logger.info('LACPDU Periodic Time Interval :{} - {}'.format(
        lacpdu_interval_period, lacpdu_interval_dict[lacpdu_interval_period]))
    logger.info('LACPDU Timeout :{} - {}'.format(lacpdu_timeout,
                lacpdu_timeout_dict[lacpdu_timeout]))
    logger.info('|-----------------------------------------|')
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = temp_tg_port[0]['speed']
    layer1.auto_negotiate = False

    # Source
    config.devices.device(name='Tx')
    eth_1 = config.devices[0].ethernets.add()
    eth_1.connection.port_name = lag0.name
    eth_1.name = 'Ethernet 1'
    eth_1.mac = "00:14:0a:00:00:01"
    ipv4_1 = eth_1.ipv4_addresses.add()
    ipv4_1.name = 'IPv4_1'
    ipv4_1.address = temp_tg_port[0]['ip']
    ipv4_1.gateway = temp_tg_port[0]['peer_ip']
    ipv4_1.prefix = int(temp_tg_port[0]['prefix'])
    ipv6_1 = eth_1.ipv6_addresses.add()
    ipv6_1.name = 'IPv6_1'
    ipv6_1.address = temp_tg_port[0]['ipv6']
    ipv6_1.gateway = temp_tg_port[0]['peer_ipv6']
    ipv6_1.prefix = int(temp_tg_port[0]['ipv6_prefix'])

    # Destination
    config.devices.device(name="Rx")
    eth_2 = config.devices[1].ethernets.add()
    eth_2.connection.port_name = lag1.name
    eth_2.name = 'Ethernet 2'
    eth_2.mac = "00:14:01:00:00:01"
    ipv4_2 = eth_2.ipv4_addresses.add()
    ipv4_2.name = 'IPv4_2'
    ipv4_2.address = temp_tg_port[1]['ip']
    ipv4_2.gateway = temp_tg_port[1]['peer_ip']
    ipv4_2.prefix = int(temp_tg_port[1]['prefix'])
    ipv6_2 = eth_2.ipv6_addresses.add()
    ipv6_2.name = 'IPv6_2'
    ipv6_2.address = temp_tg_port[1]['ipv6']
    ipv6_2.gateway = temp_tg_port[1]['peer_ipv6']
    ipv6_2.prefix = int(temp_tg_port[1]['ipv6_prefix'])

    bgpv4 = config.devices[1].bgp
    bgpv4.router_id = temp_tg_port[1]['peer_ip']
    bgpv4_int = bgpv4.ipv4_interfaces.add()
    bgpv4_int.ipv4_name = ipv4_2.name
    bgpv4_peer = bgpv4_int.peers.add()
    bgpv4_peer.name = 'BGP %d' % i
    bgpv4_peer.as_type = BGP_TYPE
    bgpv4_peer.peer_address = temp_tg_port[1]['peer_ip']
    bgpv4_peer.as_number = int(TGEN_AS_NUM)
    route_range1 = bgpv4_peer.v4_routes.add(name="IPv4_Routes")
    route_range1.addresses.add(
        address='200.1.0.1', prefix=32, count=number_of_routes)
    as_path = route_range1.as_path
    as_path_segment = as_path.segments.add()
    as_path_segment.type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = aspaths
    bgpv6 = config.devices[1].bgp
    bgpv6.router_id = temp_tg_port[1]['peer_ip']
    bgpv6_int = bgpv6.ipv6_interfaces.add()
    bgpv6_int.ipv6_name = ipv6_2.name
    bgpv6_peer = bgpv6_int.peers.add()
    bgpv6_peer.name = r'BGP+_2'
    bgpv6_peer.as_type = BGP_TYPE
    bgpv6_peer.peer_address = temp_tg_port[1]['peer_ipv6']
    bgpv6_peer.as_number = int(TGEN_AS_NUM)
    route_range2 = bgpv6_peer.v6_routes.add(name="IPv6_Routes")
    route_range2.addresses.add(
        address='3000::1', prefix=64, count=number_of_routes)
    as_path = route_range2.as_path
    as_path_segment = as_path.segments.add()
    as_path_segment.type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = aspaths

    def createTrafficItem(traffic_name, src, dest):
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = [src]
        flow1.tx_rx.device.rx_names = [dest]
        flow1.size.fixed = 1024
        flow1.rate.percentage = 50
        flow1.metrics.enable = True
        flow1.metrics.loss = True
    createTrafficItem("IPv4_1-IPv4_Routes", ipv4_1.name, route_range1.name)
    createTrafficItem("IPv6_1-IPv6_Routes", ipv6_1.name, route_range2.name)
    return config


def get_flow_stats(snappi_api):
    """
    Args:
        snappi_api (pytest fixture): Snappi API
    """
    req = snappi_api.metrics_request()
    req.flow.flow_names = []
    return snappi_api.get_metrics(req).flow_metrics


def get_port_stats(snappi_api, port_name):
    """
    Args:
        snappi_api (pytest fixture): Snappi API
    """
    request = snappi_api.metrics_request()
    request.port.port_names = [port_name]
    return snappi_api.get_metrics(request).port_metrics


def print_port_stats(snappi_api, port_names, tgen_ports):
    table1 = []
    for i, j in enumerate(port_names):
        port_table = []
        port_stats = get_port_stats(snappi_api, j)
        port_table.append(tgen_ports[i]['peer_port'])
        port_table.append(j)
        port_table.append(port_stats[0].frames_tx_rate)
        port_table.append(port_stats[0].frames_rx_rate)
        table1.append(port_table)
    columns = ['Dut Port', 'Tgen Port', 'Tx. Frame Rate', 'Rx. Frame Rate']
    logger.info("\n%s" %
                tabulate(table1, headers=columns, tablefmt="psql"))


def get_lacp_add_remove_link_physically(snappi_api,
                                        bgp_config,
                                        tgen_ports,
                                        iteration,
                                        port_count,
                                        number_of_routes,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of Routes
    """
    rx_port_names = []
    for i in range(1, len(bgp_config.ports)):
        rx_port_names.append(bgp_config.ports[i].name)
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/(port_count-2)
    all_port_names = rx_port_names[:]
    all_port_names.insert(0, 'Test_Port_1')
    snappi_api.set_config(bgp_config)

    def get_avg_cpdp_convergence_time(port_name):
        """
        Args:
            port_name: Name of the port
        """
        table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        for i in range(0, iteration):
            logger.info(
                '|---- {} Link Flap Iteration : {} ----|'.format(port_name, i+1))

            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(snappi_api)
            tx_rates = [fs.frames_tx_rate for fs in flow_stats]
            rx_rates = [fs.frames_rx_rate for fs in flow_stats]
            for i, fs in enumerate(flow_stats):
                pytest_assert(int(tx_rates[i]) > 0, f"Traffic has not started for {fs.name}")
                pytest_assert(int(tx_rates[i]) - int(rx_rates[i]) < 10, f"Loss observed in {fs.name}")
            logger.info('Traffic has started')
            """ Flapping Link """
            logger.info('Simulating Link Failure on {} link'.format(port_name))
            cs.choice = cs.PORT
            cs.port.choice = cs.port.LINK
            cs.port.link.port_names = [port_name]
            cs.port.link.state = cs.port.link.DOWN
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Link to go down")
            print_port_stats(snappi_api, all_port_names, tgen_ports)
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_tx_rate)
            assert sum(tx_frate) == sum(rx_frate), \
                "Traffic has not converged after link flap: TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after link flap")
            """ Get control plane to data plane convergence value """
            request = snappi_api.metrics_request()
            request.convergence.flow_names = []
            convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms) for Flow  {} : {}'.format(
                    metrics.name, metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(
                int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
            """ Performing link up at the end of iteration """
            logger.info(
                'Simulating Link Up on {} at the end of iteration {}'.format(port_name, i+1))
            cs.choice = cs.PORT
            cs.port.choice = cs.port.LINK
            cs.port.link.port_names = [port_name]
            cs.port.link.state = cs.port.link.UP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "Forlink to come up")
            print_port_stats(snappi_api, all_port_names, tgen_ports)
            """ Stopping Traffic """
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To stop")
        table.append('%s Link Failure' % port_name)
        table.append(number_of_routes)
        table.append(iteration)
        table.append(mean(avg_delta))
        table.append(mean(avg))
        return table
    table = []
    """ Iterating link flap test on all the rx ports """
    for i, port_name in enumerate(rx_port_names):
        table.append(get_avg_cpdp_convergence_time(port_name))
    columns = ['Event Name', 'No. of Routes', 'Iterations',
               'Frames Delta', 'Avg Calculated Data Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def get_lacp_add_remove_link_from_dut(snappi_api,
                                      duthost,
                                      bgp_config,
                                      tgen_ports,
                                      iteration,
                                      port_count,
                                      number_of_routes,):
    """
    Args:
        api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of Routes
    """

    rx_snappi_port_names, rx_dut_port = [], []
    for i in range(1, len(bgp_config.ports)):
        rx_snappi_port_names.append(bgp_config.ports[i].name)
        rx_dut_port.append(tgen_ports[i]['peer_port'])
    all_port_names = rx_snappi_port_names[:]
    all_port_names.insert(0, 'Test_Port_1')
    snappi_api.set_config(bgp_config)

    def get_avg_cpdp_convergence_time(rx_snappi_port_name, dut_port_name):
        """
        Args:
            port_name: Name of the port
        """
        table, tx_frate, rx_frate = [], [], []
        convergence_time_list, delta_frames_list = [], []
        print("Starting all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        for i in range(0, iteration):
            # convergence_time_list, delta_frames_list = [], []
            logger.info(
                '|---- {} Link Flap Iteration : {} ----|'.format(dut_port_name, i+1))
            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(snappi_api)
            tx_rates = [fs.frames_tx_rate for fs in flow_stats]
            rx_rates = [fs.frames_rx_rate for fs in flow_stats]
            for i, fs in enumerate(flow_stats):
                pytest_assert(int(tx_rates[i]) > 0, f"Traffic has not started for {fs.name}")
                pytest_assert(int(tx_rates[i]) == int(rx_rates[i]), f"Loss observed in {fs.name}")
            logger.info('Traffic has started with no loss')
            logger.info('Port Stats before {} failover'.format(dut_port_name))
            print_port_stats(snappi_api, all_port_names, tgen_ports)
            """ Flapping Link """
            logger.info(
                'Simulating Link Failure on {} '.format(dut_port_name))
            duthost.shell(
                "sudo config portchannel member del PortChannel2 %s\n" % (dut_port_name))
            wait(TIMEOUT, "For Link to go down and traffic to stabilize")
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_tx_rate)
                delta_frames = int(flow.frames_tx) - int(flow.frames_rx)
                delta_frames_list.append(delta_frames)
                convergence_time = 1000 * (delta_frames) / (flow.frames_tx_rate)
                logger.info('Frames Delta for Flow {} : {}'.format(
                    flow.name, delta_frames))
                logger.info('Tx Frame Rate for Flow {} : {}'.format(
                    flow.name, flow.frames_tx_rate))
                logger.info('Calculated Packet loss duration (ms) for Flow {} : {}'.format(
                    flow.name, convergence_time))
                logger.info('\n')
                convergence_time_list.append(convergence_time)
            assert sum(tx_frate) == sum(rx_frate), \
                "Traffic has not converged after link flap: TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after link flap with no loss")
            logger.info('Port Stats after {} failover'.format(dut_port_name))
            print_port_stats(snappi_api, all_port_names, tgen_ports)
            """ Performing link up at the end of iteration """
            logger.info('Simulating Link Up on {} from dut side at the end of iteration {}'.format(
                dut_port_name, i+1))
            duthost.shell(
                "sudo config portchannel member add PortChannel2 %s\n" % (dut_port_name))
            """ Stopping Traffic """
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To stop")
        table.append('%s Link Failure' % dut_port_name)
        table.append(number_of_routes)
        table.append(iteration)
        table.append(mean(delta_frames_list))
        table.append(mean(convergence_time_list))
        return table
    table = []
    """ Iterating link flap test on all the rx ports """
    for tgen_port_name, dut_port_name in zip(rx_snappi_port_names, rx_dut_port):
        table.append(get_avg_cpdp_convergence_time(
            tgen_port_name, dut_port_name))
    columns = ['Event Name', 'No. of Routes', 'Iterations', 'Frames Delta', 'Avg Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))
