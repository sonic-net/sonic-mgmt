from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)
from tests.common.helpers.assertions import pytest_assert
logger = logging.getLogger(__name__)

TGEN_AS_NUM = 65200
DUT_AS_NUM = 65100
TIMEOUT = 30
BGP_TYPE = 'ebgp'
temp_tg_port=dict()
lacpdu_interval_dict = { 0:'Auto',1:'Fast',30:'Slow'}
lacpdu_timeout_dict = { 0:'Auto',3:'Short',90:'Long'}
aspaths = [65002, 65003]

def run_lacp_add_remove_link_physically(cvg_api,
                                        duthost,
                                        tgen_ports,
                                        iteration,
                                        port_count,
                                        number_of_routes,
                                        port_speed,):
    """
    Run Local link failover test

    Args:
        cvg_api (pytest fixture): snappi API
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
    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        port_count,
                                        number_of_routes,
                                        port_speed,)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_lacp_add_remove_link_physically(cvg_api,
                                            tgen_bgp_config,
                                            iteration,
                                            port_count,
                                            number_of_routes,)

    """ Cleanup the dut configs after getting the convergence numbers """
    cleanup_config(duthost)

def run_lacp_timers_effect(cvg_api,
                            duthost,
                            tgen_ports,
                            iteration,
                            port_count,
                            number_of_routes,
                            port_speed,
                            lacpdu_interval_period,
                            lacpdu_timeout,):
    """
    Run Local link failover test

    Args:
        cvg_api (pytest fixture): snappi API
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
    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        port_count,
                                        number_of_routes,
                                        port_speed,
                                        lacpdu_interval_period,
                                        lacpdu_timeout,)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_lacp_add_remove_link_physically(cvg_api,
                                            tgen_bgp_config,
                                            iteration,
                                            port_count,
                                            number_of_routes,)

    """ Cleanup the dut configs after getting the convergence numbers """
    cleanup_config(duthost)

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
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))
    global temp_tg_port
    temp_tg_port = tgen_ports
    for i in range(0, port_count):
        intf_config = (
            "sudo config interface ip remove %s %s/%s \n"
            "sudo config interface ip remove %s %s/%s \n"
        )
        intf_config %= (tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ip'], tgen_ports[i]['prefix'], tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ipv6'], tgen_ports[i]['ipv6_prefix'])
        logger.info('Removing configured IP and IPv6 Address from %s' % (tgen_ports[i]['peer_port']))
        duthost.shell(intf_config)

    tx_portchannel_config = (
    "sudo config portchannel add PortChannel1 \n"
    "sudo config portchannel member add PortChannel1 %s\n"
    "sudo config interface ip add PortChannel1 %s/%s\n"
    "sudo config interface ip add PortChannel1 %s/%s\n"
    )
    tx_portchannel_config %= (tgen_ports[0]['peer_port'], tgen_ports[0]['peer_ip'], tgen_ports[0]['prefix'], tgen_ports[0]['peer_ipv6'], 64)
    logger.info('Configuring %s to PortChannel1 with IPs %s,%s' % (tgen_ports[0]['peer_port'], tgen_ports[0]['peer_ip'], tgen_ports[0]['peer_ipv6']))
    duthost.shell(tx_portchannel_config)
    duthost.shell("sudo config portchannel add PortChannel2 \n")
    for i in range(1, port_count):
        rx_portchannel_config = (
        "sudo config portchannel member add PortChannel2 %s\n"
        )
        rx_portchannel_config %= (tgen_ports[i]['peer_port'])
        logger.info('Configuring %s to PortChannel2' % (tgen_ports[i]['peer_port']))
        duthost.shell(rx_portchannel_config)
    duthost.shell("sudo config interface ip add PortChannel2 %s/%s \n"%(tgen_ports[1]['peer_ip'], tgen_ports[1]['prefix']))
    duthost.shell("sudo config interface ip add PortChannel2 %s/%s \n"%(tgen_ports[1]['peer_ipv6'], 64))
    bgp_config = (
    "vtysh "
    "-c 'configure terminal' "
    "-c 'router bgp %s' "
    "-c 'no bgp ebgp-requires-policy' "
    "-c 'bgp bestpath as-path multipath-relax' "
    "-c 'neighbor %s remote-as %s' "
    "-c 'neighbor %s remote-as %s' "
    "-c 'address-family ipv4 unicast' "
    "-c 'neighbor %s activate' "
    "-c 'address-family ipv6 unicast' "
    "-c 'neighbor %s activate' "
    "-c 'exit' "
    )
    bgp_config %= (DUT_AS_NUM, tgen_ports[1]['ip'], TGEN_AS_NUM, tgen_ports[1]['ipv6'], TGEN_AS_NUM, tgen_ports[1]['ip'],tgen_ports[1]['ipv6'])
    logger.info('Configuring BGP v4 and v6 Neighbor %s, %s' %(tgen_ports[i]['ip'],tgen_ports[i]['ipv6']))
    duthost.shell(bgp_config)


def __tgen_bgp_config(cvg_api,
                      port_count,
                      number_of_routes,
                      port_speed,
                      lacpdu_interval_period = 0,
                      lacpdu_timeout = 0,):
    """
    Creating  BGP config on TGEN

    Args:
        cvg_api (pytest fixture): snappi API
        port_count: total number of ports used in test
        number_of_routes:  Number of IPv4/IPv6 Routes
        port_speed: speed of the port used for test
        lacpdu_interval_period: LACP update packet interval ( 0 - Auto, 1- Fast, 30 - Slow )
        lacpdu_timeout: LACP Timeout value (0 - Auto, 3 - Short, 90 - Long)
    """
    conv_config = cvg_api.convergence_config()
    config = conv_config.config
    for i in range(1, port_count+1):
        config.ports.port(name='Test_Port_%d' % i, location=temp_tg_port[i-1]['location'])

    lag0 = config.lags.lag(name="lag0")[-1]
    lp = lag0.ports.port(port_name='Test_Port_1')[-1]
    lp.protocol.lacp.actor_system_id = "00:10:00:00:11:11"
    lp.protocol.lacp.lacpdu_periodic_time_interval = lacpdu_interval_period
    lp.protocol.lacp.lacpdu_timeout = lacpdu_timeout
    lp.ethernet.name= "eth0"
    lp.ethernet.mac = "00:11:02:00:10:01"
    lag1 = config.lags.lag(name="lag1")[-1]
    for i in range(2,port_count+1):
        lagport = lag1.ports.port(port_name='Test_Port_%d' % i)[-1]
        if len(str(hex(i).split('0x')[1])) == 1:
            m = '0'+hex(i).split('0x')[1]
        else:
            m = hex(i).split('0x')[1]
        lagport.protocol.lacp.actor_system_id = "00:10:00:00:00:11"
        #
        lagport.protocol.lacp.lacpdu_periodic_time_interval = lacpdu_interval_period
        lagport.protocol.lacp.lacpdu_timeout = lacpdu_timeout
        #
        lagport.ethernet.name = "eth%d"%i
        lagport.ethernet.mac = "00:10:04:00:00:%s" % m
    logger.info('|-------------- LACP Timers --------------|')
    logger.info('LACPDU Periodic Time Interval :{} - {}'.format(lacpdu_interval_period,lacpdu_interval_dict[lacpdu_interval_period]))
    logger.info('LACPDU Timeout :{} - {}'.format(lacpdu_timeout,lacpdu_timeout_dict[lacpdu_timeout]))
    logger.info('|-----------------------------------------|')
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = port_speed
    layer1.auto_negotiate = False

    #Source
    config.devices.device(name='Tx')
    eth_1 = config.devices[0].ethernets.add()
    eth_1.port_name = lag0.name
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

    #Destination
    config.devices.device(name="Rx")
    eth_2 = config.devices[1].ethernets.add()
    eth_2.port_name = lag1.name
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
    route_range1.addresses.add(address='200.1.0.1', prefix=32, count=number_of_routes)
    as_path = route_range1.as_path
    as_path_segment = as_path.segments.add()
    as_path_segment.type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = aspaths
    bgpv6 = config.devices[1].bgp
    bgpv6.router_id = temp_tg_port[1]['peer_ip']
    bgpv6_int = bgpv6.ipv6_interfaces.add()
    bgpv6_int.ipv6_name = ipv6_2.name
    bgpv6_peer = bgpv6_int.peers.add()
    bgpv6_peer.name  = r'BGP+_2'
    bgpv6_peer.as_type = BGP_TYPE
    bgpv6_peer.peer_address = temp_tg_port[1]['peer_ipv6']
    bgpv6_peer.as_number = int(TGEN_AS_NUM)
    route_range2 = bgpv6_peer.v6_routes.add(name="IPv6_Routes")
    route_range2.addresses.add(address='3000::1', prefix=64, count=number_of_routes)
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
    #createTrafficItem("IPv6_1-IPv6_Routes", ipv6_1.name, route_range2.name)
    return conv_config


def get_flow_stats(cvg_api):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = []
    return cvg_api.get_results(request).flow_metric

def get_lacp_add_remove_link_physically(cvg_api,
                                        bgp_config,
                                        iteration,
                                        port_count,
                                        number_of_routes,):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of Routes
    """
    rx_port_names = []
    for i in range(1, len(bgp_config.config.ports)):
        rx_port_names.append(bgp_config.config.ports[i].name)
    bgp_config.rx_rate_threshold = 90/(port_count-2)
    cvg_api.set_config(bgp_config)

    def get_avg_cpdp_convergence_time(port_name):
        """
        Args:
            port_name: Name of the port
        """
        table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = cvg_api.convergence_state()
        cs.protocol.state = cs.protocol.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        for i in range(0, iteration):
            logger.info('|---- {} Link Flap Iteration : {} ----|'.format(port_name, i+1))

            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.START
            cvg_api.set_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(cvg_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0, "Traffic has not started"
            logger.info('Traffic has started')
            """ Flapping Link """
            logger.info('Simulating Link Failure on {} link'.format(port_name))
            cs = cvg_api.convergence_state()
            cs.link.port_names = [port_name]
            cs.link.state = cs.link.DOWN
            cvg_api.set_state(cs)
            wait(TIMEOUT-20, "For Link to go down")
            flows = get_flow_stats(cvg_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_tx_rate)
            assert sum(tx_frate) == sum(rx_frate), "Traffic has not converged after link flap: TxFrameRate:{},RxFrameRate:{}".format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after link flap")
            """ Get control plane to data plane convergence value """
            request = cvg_api.convergence_request()
            request.convergence.flow_names = []
            convergence_metrics = cvg_api.get_results(request).flow_convergence
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
            """ Performing link up at the end of iteration """
            logger.info('Simulating Link Up on {} at the end of iteration {}'.format(port_name, i+1))
            cs = cvg_api.convergence_state()
            cs.link.port_names = [port_name]
            cs.link.state = cs.link.UP
            cvg_api.set_state(cs)
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
    columns = ['Event Name', 'No. of Routes', 'Iterations', 'Frames Delta' ,'Avg Calculated Data Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))

def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        duthost (pytest fixture): duthost fixture
    """
    logger.info('Cleaning up config')
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db_backup.json","/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    pytest_assert(wait_until(360, 10, 1, duthost.critical_services_fully_started), "Not all critical services are fully started")
    logger.info('Convergence Test Completed')