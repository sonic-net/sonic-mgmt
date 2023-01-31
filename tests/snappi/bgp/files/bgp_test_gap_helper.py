from tabulate import tabulate
from tests.common.utilities import (wait, wait_until)
from tests.common.helpers.assertions import pytest_assert
import json
import logging
logger = logging.getLogger(__name__)

TGEN_AS_NUM = 65200
DUT_AS_NUM = 65100
TIMEOUT = 40
BGP_TYPE = 'ebgp'
temp_tg_port = dict()
NG_LIST = []
aspaths = [65002, 65003]


def run_bgp_convergence_performance(cvg_api,
                                    duthost,
                                    tgen_ports,
                                    multipath,
                                    start_routes,
                                    routes_step,
                                    stop_routes,
                                    route_type,):
    """
    Run Remote link failover test

    Args:
        cvg_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        multipath: ecmp value for BGP config
        start_routes: starting value of no of routes
        routes_step: incremental step value for the routes
        stop_routes: ending route count value
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath + 1
    """ Create bgp config on dut """

    duthost_bgp_3port_config(duthost,
                             tgen_ports,
                             port_count,)
    """
        Run the convergence test by withdrawing all the route ranges
        one by one and calculate the convergence values
    """
    get_convergence_for_remote_link_failover(cvg_api,
                                             multipath,
                                             start_routes,
                                             routes_step,
                                             stop_routes,
                                             route_type,
                                             duthost,)

    """ Cleanup the dut configs after getting the convergence numbers """
    cleanup_config(duthost)


def run_bgp_scalability_v4_v6(cvg_api,
                              duthost,
                              localhost,
                              tgen_ports,
                              multipath,
                              ipv4_routes,
                              ipv6_routes,
                              ipv6_prefix,):
    """
    Run Remote link failover test

    Args:
        cvg_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        multipath: ecmp value for BGP config
        ipv4_routes: no of ipv4 routes
        ipv6_routes: no of ipv6 routes
        ipv6_prefix: ipv6 prefix length
    """

    port_count = multipath + 1

    if ipv4_routes == 0 and ipv6_routes == 0:
        assert False, "Both v4 and v6 route counts can't be zero"
    elif ipv4_routes > 1 and ipv6_routes > 1:
        dual_stack_flag = 1
    else:
        dual_stack_flag = 0
    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        port_count,
                                        ipv4_routes,
                                        ipv6_routes,
                                        ipv6_prefix,
                                        dual_stack_flag,)

    if ipv4_routes + ipv6_routes > 16000:
        limit_flag = 1
    else:
        limit_flag = 0
    """
        Run the BGP Scalability test
    """
    get_bgp_scalability_result(cvg_api, localhost, tgen_bgp_config, limit_flag, duthost)


def duthost_bgp_3port_config(duthost,
                             tgen_ports,
                             port_count,):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
    """
    duthost.command('sudo crm config polling interval 30')
    duthost.command('sudo crm config thresholds ipv4 route high 85')
    duthost.command('sudo crm config thresholds ipv4 route low 70')
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))
    global temp_tg_port
    temp_tg_port = tgen_ports
    for i in range(0, port_count):
        intf_config = (
            "sudo config interface ip remove %s %s/%s \n"
            "sudo config interface ip remove %s %s/%s \n"
        )
        intf_config %= (
            tgen_ports[i]['peer_port'],
            tgen_ports[i]['peer_ip'], tgen_ports[i]['prefix'],
            tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ipv6'],
            tgen_ports[i]['ipv6_prefix']
        )
        logger.info('Removing configured IP and IPv6 Address from %s' % (tgen_ports[i]['peer_port']))
        duthost.shell(intf_config)

    for i in range(0, port_count):
        portchannel_config = (
            "sudo config portchannel add PortChannel%s \n"
            "sudo config portchannel member add PortChannel%s %s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
        )
        portchannel_config %= (
            i + 1,
            i + 1,
            tgen_ports[i]['peer_port'],
            i + 1,
            tgen_ports[i]['peer_ip'],
            tgen_ports[i]['prefix'],
            i + 1,
            tgen_ports[i]['peer_ipv6'],
            64
        )
        logger.info('Configuring %s to PortChannel%s with IPs %s,%s' % (tgen_ports[i]['peer_port'],
                    i + 1, tgen_ports[i]['peer_ip'], tgen_ports[i]['peer_ipv6']))
        duthost.shell(portchannel_config)
    logger.info('Configuring BGP in config_db.json')
    bgp_neighbors = dict()
    for i in range(1, port_count):
        bgp_neighbors[tgen_ports[i]['ipv6']] = {"rrclient": "0", "name": "ARISTA08T0",
                                                "local_addr": tgen_ports[i]['peer_ipv6'],
                                                "nhopself": "0", "holdtime": "90",
                                                "asn": TGEN_AS_NUM, "keepalive": "30"}
        bgp_neighbors[tgen_ports[i]['ip']] = {"rrclient": "0", "name": "ARISTA08T0",
                                              "local_addr": tgen_ports[i]['peer_ip'],
                                              "nhopself": "0", "holdtime": "90", "asn": TGEN_AS_NUM, "keepalive": "30"}

    cdf = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    for neighbor, neighbor_info in bgp_neighbors.items():
        cdf["BGP_NEIGHBOR"][neighbor] = neighbor_info

    cdf["DEVICE_METADATA"]['localhost']['bgp_asn'] = DUT_AS_NUM
    with open("/tmp/sconfig_db.json", 'w') as fp:
        json.dump(cdf, fp, indent=4)
    duthost.copy(src="/tmp/sconfig_db.json", dest="/tmp/config_db_temp.json")
    cdf = json.loads(duthost.shell("sonic-cfggen -j /tmp/config_db_temp.json --print-data")['stdout'])
    logger.info(cdf)
    duthost.command("sudo cp {} {} \n".format("/tmp/config_db_temp.json", "/etc/sonic/config_db.json"))
    logger.info('Reloading config to apply BGP config')
    duthost.shell("sudo config reload -y \n")
    wait(TIMEOUT + 20, "For Config to reload \n")


def duthost_bgp_scalability_config(duthost, tgen_ports, multipath):
    """
    Configures BGP on the DUT with N-1 ecmp
    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    global temp_tg_port
    port_count = multipath + 1
    duthost.command('sudo crm config polling interval 30')
    duthost.command('sudo crm config thresholds ipv4 route high 85')
    duthost.command('sudo crm config thresholds ipv4 route low 70')
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))
    temp_tg_port = tgen_ports
    for i in range(1, port_count + 1):
        intf_config = (
            "sudo config interface ip remove %s %s/%s \n"
            "sudo config interface ip remove %s %s/%s \n"
        )
        intf_config %= (tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ip'], tgen_ports[i]['prefix'],
                        tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ipv6'], tgen_ports[i]['ipv6_prefix'])
        logger.info('Removing configured IP and IPv6 Address from %s' % (tgen_ports[i]['peer_port']))
        duthost.shell(intf_config)

    for i in range(1, port_count + 1):
        portchannel_config = (
            "sudo config portchannel add PortChannel%s \n"
            "sudo config portchannel member add PortChannel%s %s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
        )
        portchannel_config %= (i + 1, i + 1, tgen_ports[i]['peer_port'], i + 1, tgen_ports[i]['peer_ip'],
                               tgen_ports[i]['prefix'], i + 1, tgen_ports[i]['peer_ipv6'],
                               tgen_ports[i]['ipv6_prefix'])
        logger.info('Configuring %s to PortChannel%s' % (tgen_ports[i]['peer_port'], i + 1))
        duthost.shell(portchannel_config)
    bgp_neighbors = dict()
    logger.info('Configuring BGP in config_db.json')
    '''
    bgp_neighbors = {tgen_ports[1]['ipv6']: {"rrclient": "0", "name": "ARISTA08T0",
                                             "local_addr": tgen_ports[1]['peer_ipv6'], "nhopself": "0",
                                             "holdtime": "90", "asn": TGEN_AS_NUM,"keepalive": "30"},
                     tgen_ports[1]['ip']: {"rrclient": "0", "name": "ARISTA08T0",
                                           "local_addr": tgen_ports[1]['peer_ip'], "nhopself": "0",
                                           "holdtime": "90", "asn": TGEN_AS_NUM,"keepalive": "30"}}
    '''
    bgp_neighbors[tgen_ports[2]['ipv6']] = {"rrclient": "0", "name": "ARISTA08T0",
                                            "local_addr": tgen_ports[2]['peer_ipv6'],
                                            "nhopself": "0", "holdtime": "90", "asn": TGEN_AS_NUM, "keepalive": "30"}
    bgp_neighbors[tgen_ports[2]['ip']] = {"rrclient": "0", "name": "ARISTA08T0",
                                          "local_addr": tgen_ports[2]['peer_ip'],
                                          "nhopself": "0", "holdtime": "90", "asn": TGEN_AS_NUM, "keepalive": "30"}
    cdf = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    for neighbor, neighbor_info in bgp_neighbors.items():
        cdf["BGP_NEIGHBOR"][neighbor] = neighbor_info
    cdf["DEVICE_METADATA"]['localhost']['bgp_asn'] = DUT_AS_NUM
    with open("/tmp/sconfig_db.json", 'w') as fp:
        json.dump(cdf, fp, indent=4)
    duthost.copy(src="/tmp/sconfig_db.json", dest="/tmp/config_db_temp.json")
    cdf = json.loads(duthost.shell("sonic-cfggen -j /tmp/config_db_temp.json --print-data")['stdout'])
    logger.info(cdf)
    duthost.command("sudo cp {} {} \n".format("/tmp/config_db_temp.json", "/etc/sonic/config_db.json"))
    logger.info('Reloading config to apply BGP config')
    duthost.shell("sudo config reload -f -y \n")
    wait(TIMEOUT + 20, "For Config to reload \n")


def __tgen_bgp_config(cvg_api,
                      port_count,
                      v4_routes,
                      v6_routes,
                      v6_prefix,
                      dual_stack_flag,):
    """
    Creating  BGP config on TGEN

    Args:
        cvg_api (pytest fixture): snappi API
        port_count: multipath + 1
        v4_routes: no of v4 routes
        v6_routes: no of v6 routes
        v6_prefix: IPv6 prefix value
        dual_stack_flag: notation for dual or single stack
    """
    conv_config = cvg_api.convergence_config()
    cvg_api.enable_scaling(True)
    config = conv_config.config
    p1, p2 = (
        config.ports.port(name="Source", location=temp_tg_port[1]['location'])
        .port(name="Destination", location=temp_tg_port[2]['location'])
    )
    lag1 = config.lags.lag(name="lag1")[-1]
    lp1 = lag1.ports.port(port_name=p1.name)[-1]
    lp1.protocol.lacp.actor_system_id = "00:11:03:00:00:03"
    lp1.ethernet.name = "lag_Ethernet 1"
    lp1.ethernet.mac = "00:13:01:00:00:01"

    lag2 = config.lags.lag(name="lag2")[-1]
    lp2 = lag2.ports.port(port_name=p2.name)[-1]
    lp2.protocol.lacp.actor_system_id = "00:11:03:00:00:04"
    lp2.ethernet.name = "lag_Ethernet 2"
    lp2.ethernet.mac = "00:13:01:00:00:02"

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = "speed_100_gbps"
    layer1.auto_negotiate = False

    # Source
    config.devices.device(name='Tx')
    eth_1 = config.devices[0].ethernets.add()
    eth_1.port_name = lag1.name
    eth_1.name = 'Ethernet 1'
    eth_1.mac = "00:14:0a:00:00:01"
    ipv4_1 = eth_1.ipv4_addresses.add()
    ipv4_1.name = 'IPv4_1'
    ipv4_1.address = temp_tg_port[1]['ip']
    ipv4_1.gateway = temp_tg_port[1]['peer_ip']
    ipv4_1.prefix = int(temp_tg_port[1]['prefix'])
    ipv6_1 = eth_1.ipv6_addresses.add()
    ipv6_1.name = 'IPv6_1'
    ipv6_1.address = temp_tg_port[1]['ipv6']
    ipv6_1.gateway = temp_tg_port[1]['peer_ipv6']
    ipv6_1.prefix = int(temp_tg_port[1]['ipv6_prefix'])
    # Destination
    config.devices.device(name="Rx")
    eth_2 = config.devices[1].ethernets.add()
    eth_2.port_name = lag2.name
    eth_2.name = 'Ethernet 2'
    eth_2.mac = "00:14:01:00:00:01"
    ipv4_2 = eth_2.ipv4_addresses.add()
    ipv4_2.name = 'IPv4_2'
    ipv4_2.address = temp_tg_port[2]['ip']
    ipv4_2.gateway = temp_tg_port[2]['peer_ip']
    ipv4_2.prefix = int(temp_tg_port[2]['prefix'])
    ipv6_2 = eth_2.ipv6_addresses.add()
    ipv6_2.name = 'IPv6_2'
    ipv6_2.address = temp_tg_port[2]['ipv6']
    ipv6_2.gateway = temp_tg_port[2]['peer_ipv6']
    ipv6_2.prefix = int(temp_tg_port[2]['ipv6_prefix'])
    bgpv4 = config.devices[1].bgp
    bgpv4.router_id = temp_tg_port[1]['peer_ip']
    bgpv4_int = bgpv4.ipv4_interfaces.add()
    bgpv4_int.ipv4_name = ipv4_2.name
    bgpv4_peer = bgpv4_int.peers.add()
    bgpv4_peer.name = 'BGP_2'
    bgpv4_peer.as_type = BGP_TYPE
    bgpv4_peer.peer_address = temp_tg_port[2]['peer_ip']
    bgpv4_peer.as_number = int(TGEN_AS_NUM)
    route_range1 = bgpv4_peer.v4_routes.add(name="IPv4_Routes")
    route_range1.addresses.add(address='200.1.0.1', prefix=32, count=v4_routes)
    as_path = route_range1.as_path
    as_path_segment = as_path.segments.add()
    as_path_segment.type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = aspaths
    bgpv6 = config.devices[1].bgp
    bgpv6.router_id = temp_tg_port[2]['peer_ip']
    bgpv6_int = bgpv6.ipv6_interfaces.add()
    bgpv6_int.ipv6_name = ipv6_2.name
    bgpv6_peer = bgpv6_int.peers.add()
    bgpv6_peer.name = r'BGP+_2'
    bgpv6_peer.as_type = BGP_TYPE
    bgpv6_peer.peer_address = temp_tg_port[2]['peer_ipv6']
    bgpv6_peer.as_number = int(TGEN_AS_NUM)
    route_range2 = bgpv6_peer.v6_routes.add(name="IPv6_Routes")
    route_range2.addresses.add(address='3000::1', prefix=v6_prefix, count=v6_routes)
    as_path = route_range2.as_path
    as_path_segment = as_path.segments.add()
    as_path_segment.type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = aspaths

    def createTrafficItem(traffic_name, src, dest, rate):
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = [src]
        flow1.tx_rx.device.rx_names = [dest]
        flow1.size.fixed = 1024
        flow1.rate.percentage = rate
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    if dual_stack_flag == 1:
        createTrafficItem("IPv4_1-IPv4_Routes", ipv4_1.name, route_range1.name, 50)
        createTrafficItem("IPv6_1-IPv6_Routes", ipv6_1.name, route_range2.name, 50)
    else:
        if v4_routes == 0:
            createTrafficItem("IPv6_1-IPv6_Routes", ipv6_1.name, route_range2.name, 100)
        elif v6_routes == 0:
            createTrafficItem("IPv4_1-IPv4_Routes", ipv4_1.name, route_range1.name, 100)
    return conv_config


def get_flow_stats(cvg_api):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = []
    return cvg_api.get_results(request).flow_metric


def get_convergence_for_remote_link_failover(cvg_api,
                                             multipath,
                                             start_routes,
                                             routes_step,
                                             stop_routes,
                                             route_type,
                                             duthost):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        iteration: number of iterations for running convergence test on a port
        start_routes: starting value of no of routes
        routes_step: incremental step value for the routes
        stop_routes: ending route count value
        route_type: IPv4 or IPv6 routes
    """
    table = []
    global NG_LIST

    def tgen_config(routes):
        conv_config = cvg_api.convergence_config()
        config = conv_config.config
        for i in range(1, multipath + 2):
            config.ports.port(name='Test_Port_%d' % i, location=temp_tg_port[i - 1]['location'])
            c_lag = config.lags.lag(name="lag%d" % i)[-1]
            lp = c_lag.ports.port(port_name='Test_Port_%d' % i)[-1]
            lp.ethernet.name = 'lag_eth_%d' % i
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0' + hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            lp.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m
            lp.ethernet.name = "lag_Ethernet %s" % i
            lp.ethernet.mac = "00:10:01:00:00:%s" % m
            config.devices.device(name='Topology %d' % i)

        config.options.port_options.location_preemption = True
        layer1 = config.layer1.layer1()[-1]
        layer1.name = 'port settings'
        layer1.port_names = [port.name for port in config.ports]
        layer1.ieee_media_defaults = False
        layer1.auto_negotiation.rs_fec = True
        layer1.auto_negotiation.link_training = False
        layer1.speed = "speed_100_gbps"
        layer1.auto_negotiate = False

        def create_v4_topo():
            eth = config.devices[0].ethernets.add()
            eth.port_name = config.lags[0].name
            eth.name = 'Ethernet 1'
            eth.mac = "00:00:00:00:00:01"
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'IPv4 1'
            ipv4.address = temp_tg_port[0]['ip']
            ipv4.gateway = temp_tg_port[0]['peer_ip']
            ipv4.prefix = int(temp_tg_port[0]['prefix'])
            rx_flow_name = []
            for i in range(2, 4):
                NG_LIST.append('Network_Group%s' % i)
                if len(str(hex(i).split('0x')[1])) == 1:
                    m = '0' + hex(i).split('0x')[1]
                else:
                    m = hex(i).split('0x')[1]

                ethernet_stack = config.devices[i - 1].ethernets.add()
                ethernet_stack.port_name = config.lags[i - 1].name
                ethernet_stack.name = 'Ethernet %d' % i
                ethernet_stack.mac = "00:00:00:00:00:%s" % m
                ipv4_stack = ethernet_stack.ipv4_addresses.add()
                ipv4_stack.name = 'IPv4 %d' % i
                ipv4_stack.address = temp_tg_port[i - 1]['ip']
                ipv4_stack.gateway = temp_tg_port[i - 1]['peer_ip']
                ipv4_stack.prefix = int(temp_tg_port[i - 1]['prefix'])
                bgpv4 = config.devices[i - 1].bgp
                bgpv4.router_id = temp_tg_port[i - 1]['peer_ip']
                bgpv4_int = bgpv4.ipv4_interfaces.add()
                bgpv4_int.ipv4_name = ipv4_stack.name
                bgpv4_peer = bgpv4_int.peers.add()
                bgpv4_peer.name = 'BGP %d' % i
                bgpv4_peer.as_type = BGP_TYPE
                bgpv4_peer.peer_address = temp_tg_port[i - 1]['peer_ip']
                bgpv4_peer.as_number = int(TGEN_AS_NUM)
                route_range = bgpv4_peer.v4_routes.add(name=NG_LIST[-1])
                route_range.addresses.add(address='200.1.0.1', prefix=32, count=routes)
                as_path = route_range.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = aspaths
                rx_flow_name.append(route_range.name)
            return rx_flow_name

        def create_v6_topo():
            eth = config.devices[0].ethernets.add()
            eth.port_name = config.lags[0].name
            eth.name = 'Ethernet 1'
            eth.mac = "00:00:00:00:00:01"
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'IPv6 1'
            ipv6.address = temp_tg_port[0]['ipv6']
            ipv6.gateway = temp_tg_port[0]['peer_ipv6']
            ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
            rx_flow_name = []
            for i in range(2, 4):
                NG_LIST.append('Network_Group%s' % i)
                if len(str(hex(i).split('0x')[1])) == 1:
                    m = '0' + hex(i).split('0x')[1]
                else:
                    m = hex(i).split('0x')[1]
                ethernet_stack = config.devices[i - 1].ethernets.add()
                ethernet_stack.port_name = config.lags[i - 1].name
                ethernet_stack.name = 'Ethernet %d' % i
                ethernet_stack.mac = "00:00:00:00:00:%s" % m
                ipv6_stack = ethernet_stack.ipv6_addresses.add()
                ipv6_stack.name = 'IPv6 %d' % i
                ipv6_stack.address = temp_tg_port[i - 1]['ipv6']
                ipv6_stack.gateway = temp_tg_port[i - 1]['peer_ipv6']
                ipv6_stack.prefix = int(temp_tg_port[i - 1]['ipv6_prefix'])
                bgpv6 = config.devices[i - 1].bgp
                bgpv6.router_id = temp_tg_port[i - 1]['peer_ip']
                bgpv6_int = bgpv6.ipv6_interfaces.add()
                bgpv6_int.ipv6_name = ipv6_stack.name
                bgpv6_peer = bgpv6_int.peers.add()
                bgpv6_peer.name = 'BGP+_%d' % i
                bgpv6_peer.as_type = BGP_TYPE
                bgpv6_peer.peer_address = temp_tg_port[i - 1]['peer_ipv6']
                bgpv6_peer.as_number = int(TGEN_AS_NUM)
                route_range = bgpv6_peer.v6_routes.add(name=NG_LIST[-1])
                route_range.addresses.add(address='3000::1', prefix=64, count=routes)
                as_path = route_range.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = aspaths
                rx_flow_name.append(route_range.name)
            return rx_flow_name

        conv_config.rx_rate_threshold = 90 / (multipath)
        if route_type == 'IPv4':
            rx_flows = create_v4_topo()
            flow = config.flows.flow(name='IPv4_Traffic_%d' % routes)[-1]
        elif route_type == 'IPv6':
            rx_flows = create_v6_topo()
            flow = config.flows.flow(name='IPv6_Traffic_%d' % routes)[-1]
        else:
            raise Exception('Invalid route type given')
        flow.tx_rx.device.tx_names = [config.devices[0].name]
        flow.tx_rx.device.rx_names = rx_flows
        flow.size.fixed = 1024
        flow.rate.percentage = 100
        flow.metrics.enable = True
        flow.metrics.loss = True
        return conv_config
    for j in range(start_routes, stop_routes, routes_step):
        logger.info('|--------------------CP/DP Test with No.of Routes : {} ----|'.format(j))
        bgp_config = tgen_config(j)
        route_name = NG_LIST[0]
        bgp_config.rx_rate_threshold = 90 / (multipath - 1)
        cvg_api.set_config(bgp_config)

        def get_cpdp_convergence_time(route_name):
            """
            Args:
                route_name: name of the route

            """
            table, tx_frate, rx_frate = [], [], []
            run_traffic(cvg_api, duthost)
            flow_stats = get_flow_stats(cvg_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0, "Traffic has not started"
            """ Withdrawing routes from a BGP peer """
            logger.info('Withdrawing Routes from {}'.format(route_name))
            cs = cvg_api.convergence_state()
            cs.route.names = [route_name]
            cs.route.state = cs.route.WITHDRAW
            cvg_api.set_state(cs)
            wait(TIMEOUT, "For routes to be withdrawn")
            flows = get_flow_stats(cvg_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            assert abs(sum(tx_frate) - sum(rx_frate)) < 500, "Traffic has not converged after lroute withdraw \
                       TxFrameRate:{},RxFrameRate:{}".format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after route withdraw")

            """ Get control plane to data plane convergence value """
            request = cvg_api.convergence_request()
            request.convergence.flow_names = []
            convergence_metrics = cvg_api.get_results(request).flow_convergence
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): \
                            {}'.format(metrics.control_plane_data_plane_convergence_us / 1000))
            stop_traffic(cvg_api)
            table.append(route_type)
            table.append(j)
            table.append(int(metrics.control_plane_data_plane_convergence_us / 1000))
            return table
        """ Iterating route withdrawal on all BGP peers """
        table.append(get_cpdp_convergence_time(route_name))

    columns = ['Route Type', 'No. of Routes', 'Control to Data Plane Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def restart_traffic(cvg_api):
    """ Stopping Protocols """
    logger.info("L2/3 traffic apply failed,Restarting protocols and traffic")
    cs = cvg_api.convergence_state()
    cs.protocol.state = cs.protocol.STOP
    cvg_api.set_state(cs)
    wait(TIMEOUT - 10, "For Protocols To stop")
    cs = cvg_api.convergence_state()
    cs.protocol.state = cs.protocol.START
    cvg_api.set_state(cs)
    wait(TIMEOUT - 10, "For Protocols To start")
    cs = cvg_api.convergence_state()
    cs.transmit.state = cs.transmit.START
    cvg_api.set_state(cs)
    wait(TIMEOUT, "For Traffic To start and stabilize")


def run_traffic(cvg_api, duthost):
    warning = 0
    """ Starting Protocols """
    logger.info("Starting all protocols ...")
    cs = cvg_api.convergence_state()
    cs.protocol.state = cs.protocol.START
    cvg_api.set_state(cs)
    wait(TIMEOUT - 10, "For Protocols To start")
    """ Starting Traffic """
    logger.info('Starting Traffic')
    try:
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.START
        cvg_api.set_state(cs)
        wait(TIMEOUT + 10, "For Traffic To start and stabilize")
    except Exception as e:
        logger.info(e)
        restart_traffic(cvg_api)
    finally:
        duthost.shell("sudo cp /var/log/syslog /host/scale_syslog.99")
        var = duthost.shell("sudo cat /host/scale_syslog.99")['stdout']
        if 'ROUTE THRESHOLD_EXCEEDED' in var:
            logger.info('ROUTE_THRESHOLD_EXCEEDED FOUND in syslog!!!!!!!!')
            warning = 1
        else:
            logger.info('ROUTE_THRESHOLD_EXCEEDED NOT FOUND in syslog !!!!!!!!!!!')
        duthost.shell("sudo rm -rf /host/scale_syslog.99")
    return warning


def stop_traffic(cvg_api):
    logger.info('Stopping Traffic')
    cs = cvg_api.convergence_state()
    cs.transmit.state = cs.transmit.STOP
    cvg_api.set_state(cs)
    wait(TIMEOUT - 20, "For Traffic To stop")
    """ Stopping Protocols """
    logger.info("Stopping all protocols ...")
    cs = cvg_api.convergence_state()
    cs.protocol.state = cs.protocol.STOP
    cvg_api.set_state(cs)
    wait(TIMEOUT - 20, "For Protocols To STOP")


def get_bgp_scalability_result(cvg_api, localhost, bgp_config, flag, duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        cvg_api (pytest fixture): snappi API
        bgp_config: tgen_bgp_config
    """
    cvg_api.set_config(bgp_config)
    warning = run_traffic(cvg_api, duthost)
    if warning == 1:
        msg = "THRESHOLD_EXCEEDED warning message observed in syslog"
    else:
        msg = "THRESHOLD_EXCEEDED warning message not observed in syslog"
    flow_stats = get_flow_stats(cvg_api)
    tx_frame_rate = flow_stats[0].frames_tx_rate
    assert tx_frame_rate != 0, "Traffic has not started"
    flow_stats = get_flow_stats(cvg_api)
    logger.info('|---- Tx Frame Rate: {} ----|'.format(flow_stats[0].frames_tx_rate))
    logger.info('|---- Rx Frame Rate: {} ----|'.format(flow_stats[0].frames_rx_rate))
    logger.info('|---- Loss % : {} ----|'.format(flow_stats[0].loss))
    if flag == 1:
        assert float(flow_stats[0].loss) > 0.1, "FAIL: Loss must have been observed for greater than 16k routes"
        logger.info('PASSED : {}% Loss observerd in traffic item for 100k routes and \
                    {}'.format(float(flow_stats[0].loss), msg))
    else:
        assert float(flow_stats[0].loss) <= 0.1, "FAIL: Loss observerd in traffic item"
        logger.info('PASSED : No Loss observerd in traffic item and {}'.format(msg))
    stop_traffic(cvg_api)


def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        duthost (pytest fixture): duthost fixture
    """
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db_backup.json", "/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    logger.info("Wait until all critical services are fully started")
    pytest_assert(wait_until(360, 10, 1, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")
    logger.info('Convergence Test Completed')
