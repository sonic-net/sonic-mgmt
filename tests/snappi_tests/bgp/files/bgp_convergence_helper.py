import logging
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)
from tests.common.helpers.assertions import pytest_assert
logger = logging.getLogger(__name__)

TGEN_AS_NUM = 65200
DUT_AS_NUM = 65100
TIMEOUT = 90
WAIT_INTERVAL = 30
BGP_TYPE = 'ebgp'
temp_tg_port = dict()
NG_LIST = []
aspaths = [65002, 65003]


def _asn_from_port_entry(port_entry, skip_duthost_bgp_config, fixture_keys, default):
    """
    When skip_duthost_bgp_config is True, prefer ASN from tgen_ports (dut_asn / peer_asn
    from config_facts, or optional DUT_AS_NUM / TGEN_AS_NUM keys); else use module default.
    """
    if not skip_duthost_bgp_config:
        return int(default)
    for key in fixture_keys:
        val = port_entry.get(key)
        if val is not None:
            return int(val)
    return int(default)


def run_bgp_local_link_failover_test(snappi_api,
                                     duthost,
                                     tgen_ports,
                                     iteration,
                                     multipath,
                                     number_of_routes,
                                     route_type,):
    """
    Run Local link failover test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath+1

    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        number_of_routes,
                                        route_type,)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_convergence_for_local_link_failover(snappi_api,
                                            tgen_bgp_config,
                                            iteration,
                                            multipath,
                                            number_of_routes,
                                            route_type,)

    """ Cleanup the dut configs after getting the convergence numbers """
    cleanup_config(duthost)


def run_bgp_remote_link_failover_test(snappi_api,
                                      duthost,
                                      tgen_ports,
                                      iteration,
                                      multipath,
                                      number_of_routes,
                                      route_type,):
    """
    Run Remote link failover test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath+1
    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        number_of_routes,
                                        route_type,)

    """
        Run the convergence test by withdrawing all the route ranges
        one by one and calculate the convergence values
    """
    get_convergence_for_remote_link_failover(snappi_api,
                                             tgen_bgp_config,
                                             iteration,
                                             multipath,
                                             number_of_routes,
                                             route_type,)

    """ Cleanup the dut configs after getting the convergence numbers """
    cleanup_config(duthost)


def run_rib_in_convergence_test(snappi_api,
                                duthost,
                                tgen_ports,
                                iteration,
                                multipath,
                                number_of_routes,
                                route_type,
                                timeout=None,
                                skip_cleanup=None,
                                skip_duthost_bgp_config=False,):
    """
    Run RIB-IN Convergence test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
        timeout: optional timeout in seconds for convergence steps (default: TIMEOUT)
        skip_cleanup: Skip the cleanup integrated in the test since main test does revert of config.
        skip_duthost_bgp_config: Use existing config from config_db to run test.
    """
    if timeout is None:
        timeout = TIMEOUT

    port_count = multipath+1

    """ Set global temp_tg_port for __tgen_bgp_config (used by tgen BGP config) """
    global temp_tg_port
    temp_tg_port = tgen_ports

    """ Create bgp config on dut """
    if not skip_duthost_bgp_config:
        duthost_bgp_config(duthost,
                           tgen_ports,
                           port_count,
                           route_type,)

    """  Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        number_of_routes,
                                        route_type,
                                        skip_duthost_bgp_config=skip_duthost_bgp_config,)

    """
        Run the convergence test by withdrawing all routes at once and
        calculate the convergence values
    """
    get_rib_in_convergence(snappi_api,
                           tgen_bgp_config,
                           iteration,
                           multipath,
                           number_of_routes,
                           route_type,
                           timeout,)

    if not skip_cleanup:
        """ Cleanup the dut configs after getting the convergence numbers """
        cleanup_config(duthost)


def run_RIB_IN_capacity_test(snappi_api,
                             duthost,
                             tgen_ports,
                             multipath,
                             start_value,
                             step_value,
                             route_type,):
    """
    Run RIB-IN Capacity test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        multipath: ecmp value for BGP config
        start_value: start value of number of routes
        step_value: step value of routes to be incremented at every iteration
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath+1
    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,)

    """ Run the RIB-IN capacity test by increasig the route count step by step """
    get_RIB_IN_capacity(snappi_api,
                        multipath,
                        start_value,
                        step_value,
                        route_type,)

    """ Cleanup the dut configs after getting the convergence numbers """
    cleanup_config(duthost)


def duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
        multipath: ECMP value for BGP config
        route_type: IPv4 or IPv6 routes
    """
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format(
        "/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))
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

    for i in range(0, port_count):
        portchannel_config = (
            "sudo config portchannel add PortChannel%s \n"
            "sudo config portchannel member add PortChannel%s %s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
        )
        portchannel_config %= (i+1, i+1, tgen_ports[i]['peer_port'], i+1, tgen_ports[i]
                               ['peer_ip'], tgen_ports[i]['prefix'], i+1, tgen_ports[i]['peer_ipv6'], 64)
        logger.info('Configuring %s to PortChannel%s with IPs %s,%s' % (
            tgen_ports[i]['peer_port'], i+1, tgen_ports[i]['peer_ip'], tgen_ports[i]['peer_ipv6']))
        duthost.shell(portchannel_config)
    bgp_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'no bgp ebgp-requires-policy' "
        "-c 'bgp bestpath as-path multipath-relax' "
        "-c 'maximum-paths %s' "
        "-c 'exit' "
    )
    bgp_config %= (DUT_AS_NUM, port_count-1)
    duthost.shell(bgp_config)
    if route_type == 'IPv4':
        for i in range(1, port_count):
            bgp_config_neighbor = (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s remote-as %s' "
                "-c 'address-family ipv4 unicast' "
                "-c 'neighbor %s activate' "
                "-c 'exit' "
            )
            bgp_config_neighbor %= (
                DUT_AS_NUM, tgen_ports[i]['ip'], TGEN_AS_NUM, tgen_ports[i]['ip'])
            logger.info('Configuring BGP v4 Neighbor %s' % tgen_ports[i]['ip'])
            duthost.shell(bgp_config_neighbor)
    else:
        for i in range(1, port_count):
            bgp_config_neighbor = (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s remote-as %s' "
                "-c 'address-family ipv6 unicast' "
                "-c 'neighbor %s activate' "
                "-c 'exit' "
            )
            bgp_config_neighbor %= (
                DUT_AS_NUM, tgen_ports[i]['ipv6'], TGEN_AS_NUM, tgen_ports[i]['ipv6'])
            logger.info('Configuring BGP v6 Neighbor %s' %
                        tgen_ports[i]['ipv6'])
            duthost.shell(bgp_config_neighbor)


def __tgen_bgp_config(snappi_api,
                      port_count,
                      number_of_routes,
                      route_type,
                      skip_duthost_bgp_config=False,):
    """
    Creating  BGP config on TGEN

    Args:
        snappi_api (pytest fixture): snappi API
        port_count: multipath + 1
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
        skip_duthost_bgp_config: boolean (true) if DUT is preconfigured
    """
    global NG_LIST
    config = snappi_api.config()

    if skip_duthost_bgp_config and port_count > 0:
        ref_dut_as = _asn_from_port_entry(
            temp_tg_port[0], True, ('dut_asn', 'DUT_AS_NUM'), DUT_AS_NUM)
        for idx in range(1, port_count):
            other = _asn_from_port_entry(
                temp_tg_port[idx], True, ('dut_asn', 'DUT_AS_NUM'), DUT_AS_NUM)
            pytest_assert(
                other == ref_dut_as,
                'tgen_ports dut_asn mismatch: index 0 has {}, index {} has {}'.format(
                    ref_dut_as, idx, other))
        logger.info(
            'TGEN BGP: DUT AS %s from tgen_ports (dut_asn / default); '
            'emulated BGP as_number per peer from peer_asn / TGEN_AS_NUM',
            ref_dut_as)

    for i in range(1, port_count+1):
        config.ports.port(name='Test_Port_%d' %
                          i, location=temp_tg_port[i-1]['location'])
        c_lag = config.lags.lag(name="lag%d" % i)[-1]
        lp = c_lag.ports.port(port_name='Test_Port_%d' % i)[-1]
        lp.ethernet.name = 'lag_eth_%d' % i
        if len(str(hex(i).split('0x')[1])) == 1:
            m = '0'+hex(i).split('0x')[1]
        else:
            m = hex(i).split('0x')[1]
        c_lag.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m
        lp.ethernet.name = "lag_Ethernet %s" % i
        lp.ethernet.mac = "00:10:01:00:00:%s" % m
        config.devices.device(name='Topology %d' % i)

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = False
    layer1.auto_negotiation.link_training = False
    layer1.speed = temp_tg_port[0]['speed']
    layer1.auto_negotiate = False

    def create_v4_topo():
        eth = config.devices[0].ethernets.add()
        eth.connection.port_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'IPv4 1'
        ipv4.address = temp_tg_port[0]['ip']
        ipv4.gateway = temp_tg_port[0]['peer_ip']
        ipv4.prefix = int(temp_tg_port[0]['prefix'])
        tx_flow_name = [ipv4.name]
        rx_flow_names = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group%s' % i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]

            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.connection.port_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv4_stack = ethernet_stack.ipv4_addresses.add()
            ipv4_stack.name = 'IPv4 %d' % i
            ipv4_stack.address = temp_tg_port[i-1]['ip']
            ipv4_stack.gateway = temp_tg_port[i-1]['peer_ip']
            ipv4_stack.prefix = int(temp_tg_port[i-1]['prefix'])
            bgpv4 = config.devices[i-1].bgp
            bgpv4.router_id = temp_tg_port[i-1]['peer_ip']
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4_stack.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP %d' % i
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = temp_tg_port[i-1]['peer_ip']
            bgpv4_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range = bgpv4_peer.v4_routes.add(name=NG_LIST[-1])
            route_range.addresses.add(
                address='200.1.0.1', prefix=32, count=number_of_routes)
            as_path = route_range.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = aspaths
            rx_flow_names.append(route_range.name)
        return (tx_flow_name, rx_flow_names)

    def create_v6_topo():
        eth = config.devices[0].ethernets.add()
        eth.connection.port_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'IPv6 1'
        ipv6.address = temp_tg_port[0]['ipv6']
        ipv6.gateway = temp_tg_port[0]['peer_ipv6']
        ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
        tx_flow_name = [ipv6.name]
        rx_flow_names = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group%s' % i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.connection.port_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv6_stack = ethernet_stack.ipv6_addresses.add()
            ipv6_stack.name = 'IPv6 %d' % i
            ipv6_stack.address = temp_tg_port[i-1]['ipv6']
            ipv6_stack.gateway = temp_tg_port[i-1]['peer_ipv6']
            ipv6_stack.prefix = int(temp_tg_port[i-1]['ipv6_prefix'])

            bgpv6 = config.devices[i-1].bgp
            bgpv6.router_id = temp_tg_port[i-1]['peer_ip']
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6_stack.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'BGP+_%d' % i
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = temp_tg_port[i-1]['peer_ipv6']
            bgpv6_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range = bgpv6_peer.v6_routes.add(name=NG_LIST[-1])
            route_range.addresses.add(
                address='3000::1', prefix=64, count=number_of_routes)
            as_path = route_range.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = aspaths
            rx_flow_names.append(route_range.name)
        return (tx_flow_name, rx_flow_names)

    def create_v4v6_topo():
        """Create topology with 125k IPv4 and 125k IPv6 routes (250k total)."""
        num_v4 = number_of_routes // 2
        num_v6 = number_of_routes - num_v4
        eth = config.devices[0].ethernets.add()
        eth.connection.port_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'IPv4 1'
        ipv4.address = temp_tg_port[0]['ip']
        ipv4.gateway = temp_tg_port[0]['peer_ip']
        ipv4.prefix = int(temp_tg_port[0]['prefix'])
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'IPv6 1'
        ipv6.address = temp_tg_port[0]['ipv6']
        ipv6.gateway = temp_tg_port[0]['peer_ipv6']
        ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
        v4_tx_flow_name = [ipv4.name]
        v6_tx_flow_name = [ipv6.name]
        v4_rx_flow_names = []
        v6_rx_flow_names = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group_v4_%s' % i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.connection.port_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv4_stack = ethernet_stack.ipv4_addresses.add()
            ipv4_stack.name = 'IPv4 %d' % i
            ipv4_stack.address = temp_tg_port[i-1]['ip']
            ipv4_stack.gateway = temp_tg_port[i-1]['peer_ip']
            ipv4_stack.prefix = int(temp_tg_port[i-1]['prefix'])
            ipv6_stack = ethernet_stack.ipv6_addresses.add()
            ipv6_stack.name = 'IPv6 %d' % i
            ipv6_stack.address = temp_tg_port[i-1]['ipv6']
            ipv6_stack.gateway = temp_tg_port[i-1]['peer_ipv6']
            ipv6_stack.prefix = int(temp_tg_port[i-1]['ipv6_prefix'])
            bgpv4 = config.devices[i-1].bgp
            bgpv4.router_id = temp_tg_port[i-1]['peer_ip']
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4_stack.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP %d' % i
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = temp_tg_port[i-1]['peer_ip']
            bgpv4_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range_v4 = bgpv4_peer.v4_routes.add(name=NG_LIST[-1])
            route_range_v4.addresses.add(
                address='200.1.0.1', prefix=32, count=num_v4)
            as_path_v4 = route_range_v4.as_path
            as_path_segment_v4 = as_path_v4.segments.add()
            as_path_segment_v4.type = as_path_segment_v4.AS_SEQ
            as_path_segment_v4.as_numbers = aspaths
            v4_rx_flow_names.append(route_range_v4.name)

            NG_LIST.append('Network_Group_v6_%s' % i)
            bgpv6 = config.devices[i-1].bgp
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6_stack.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'BGP+_%d' % i
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = temp_tg_port[i-1]['peer_ipv6']
            bgpv6_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range_v6 = bgpv6_peer.v6_routes.add(name=NG_LIST[-1])
            route_range_v6.addresses.add(
                address='3000::1', prefix=64, count=num_v6)
            as_path_v6 = route_range_v6.as_path
            as_path_segment_v6 = as_path_v6.segments.add()
            as_path_segment_v6.type = as_path_segment_v6.AS_SEQ
            as_path_segment_v6.as_numbers = aspaths
            v6_rx_flow_names.append(route_range_v6.name)
        return (v4_tx_flow_name, v6_tx_flow_name, v4_rx_flow_names, v6_rx_flow_names)

    def createTrafficItem(traffic_name, src, dest, rate):
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = src
        flow1.tx_rx.device.rx_names = dest
        flow1.size.fixed = 1024
        flow1.rate.percentage = rate
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    if route_type == 'IPv4':
        tx_flow, rx_flow = create_v4_topo()
        createTrafficItem("IPv4 Traffic", tx_flow, rx_flow, 100)
    elif route_type == 'IPv6':
        tx_flow, rx_flow = create_v6_topo()
        createTrafficItem("IPv6 Traffic", tx_flow, rx_flow, 100)
    elif route_type == 'IPv4v6':
        v4_tx_flow, v6_tx_flow, v4_rx_flow, v6_rx_flow = create_v4v6_topo()
        createTrafficItem("IPv4 Traffic", v4_tx_flow, v4_rx_flow, 50)
        createTrafficItem("IPv6 Traffic", v6_tx_flow, v6_rx_flow, 50)
    else:
        raise Exception('Invalid route type given')
    return config


def get_flow_stats(snappi_api):
    """
    Args:
        snappi_api (pytest fixture): Snappi API
    """
    req = snappi_api.metrics_request()
    req.flow.flow_names = []
    return snappi_api.get_metrics(req).flow_metrics


def get_convergence_for_local_link_failover(snappi_api,
                                            bgp_config,
                                            iteration,
                                            multipath,
                                            number_of_routes,
                                            route_type,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
    """
    rx_port_names = []
    for i in range(1, len(bgp_config.ports)):
        rx_port_names.append(bgp_config.ports[i].name)
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/(multipath-1)
    snappi_api.set_config(bgp_config)
    """ Starting Protocols """
    logger.info("Starting all protocols ...")
    cs = snappi_api.control_state()
    cs.protocol.all.state = cs.protocol.all.START
    snappi_api.set_control_state(cs)
    wait(TIMEOUT, "For Protocols To start")

    def get_avg_dpdp_convergence_time(port_name):

        """
        Args:
            port_name: Name of the port
        """

        table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
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
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0, "Traffic has not started"
            """ Flapping Link """
            logger.info('Simulating Link Failure on {} link'.format(port_name))
            cs.choice = cs.PORT
            cs.port.choice = cs.port.LINK
            cs.port.link.port_names = [port_name]
            cs.port.link.state = cs.port.link.DOWN
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Link to go down")
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            assert abs(sum(tx_frate) - sum(rx_frate)) < 500, \
                "Traffic has not converged after link flap: TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after link flap")
            """ Get control plane to data plane convergence value """
            request = snappi_api.metrics_request()
            request.convergence.flow_names = []
            convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(
                    metrics.control_plane_data_plane_convergence_us/1000))
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
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT-10, "For Traffic To Stop")
        table.append('%s Link Failure' % port_name)
        table.append(route_type)
        table.append(number_of_routes)
        table.append(iteration)
        table.append(mean(avg_delta))
        table.append(mean(avg))
        return table
    table = []
    """ Iterating link flap test on all the rx ports """
    for i, port_name in enumerate(rx_port_names):
        table.append(get_avg_dpdp_convergence_time(port_name))
    columns = ['Event Name', 'Route Type', 'No. of Routes', 'Iterations',
               'Delta Frames', 'Avg Calculated Data Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def get_convergence_for_remote_link_failover(snappi_api,
                                             bgp_config,
                                             iteration,
                                             multipath,
                                             number_of_routes,
                                             route_type,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
    """
    route_names = NG_LIST
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/(multipath-1)
    snappi_api.set_config(bgp_config)

    def get_avg_cpdp_convergence_time(route_name):
        """
        Args:
            route_name: name of the route

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
                '|---- {} Route Withdraw Iteration : {} ----|'.format(route_name, i+1))
            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0, "Traffic has not started"

            """ Withdrawing routes from a BGP peer """
            logger.info('Withdrawing Routes from {}'.format(route_name))
            cs = snappi_api.control_state()
            cs.protocol.route.state = cs.protocol.route.WITHDRAW
            cs.protocol.route.names = [route_name]
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For routes to be withdrawn")
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            assert abs(sum(tx_frate) - sum(rx_frate)) < 500, \
                "Traffic has not converged after route withdraw TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after route withdraw")

            """ Get control plane to data plane convergence value """
            request = snappi_api.metrics_request()
            request.convergence.flow_names = []
            convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(
                    metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(
                int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
            """ Advertise the routes back at the end of iteration """
            cs = snappi_api.control_state()
            cs.protocol.route.state = cs.protocol.route.ADVERTISE
            cs.protocol.route.names = [route_name]
            snappi_api.set_control_state(cs)
            logger.info('Readvertise {} routes back at the end of iteration {}'.format(
                route_name, i+1))
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To Stop")
        table.append('%s route withdraw' % route_name)
        table.append(route_type)
        table.append(number_of_routes)
        table.append(iteration)
        table.append(mean(avg_delta))
        table.append(mean(avg))
        return table
    table = []
    """ Iterating route withdrawal on all BGP peers """
    for route in route_names:
        table.append(get_avg_cpdp_convergence_time(route))

    columns = ['Event Name', 'Route Type', 'No. of Routes', 'Iterations',
               'Frames Delta', 'Avg Control to Data Plane Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def get_rib_in_convergence(snappi_api,
                           bgp_config,
                           iteration,
                           multipath,
                           number_of_routes,
                           route_type,
                           timeout=None):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of IPv4/IPv6/IPv4v6 Routes
        route_type: IPv4 or IPv6 or IPv4v6 routes
        timeout: timeout for route withdraw and advertisement.
    """
    if timeout is not None:
        TIMEOUT = timeout

    global NG_LIST
    route_names = NG_LIST
    logger.info('Route list:{}'.format(route_names))
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/multipath
    snappi_api.set_config(bgp_config)
    # Outstanding sonic-mgmt issue 23744.
    logger.info('Setting AS-SEQ manually via restPy')
    ix = snappi_api._ixnetwork

    for topo in ix.Topology.find():
        for dg in topo.DeviceGroup.find():
            for ng in dg.NetworkGroup.find():
                for ipp in ng.Ipv4PrefixPools.find():
                    for bgp_prop in ipp.BgpIPRouteProperty.find():
                        for seg in bgp_prop.BgpAsPathSegmentList.find():
                            seg.SegmentType.Single('asseq')
                for ipp in ng.Ipv6PrefixPools.find():
                    for bgp_prop in ipp.BgpV6IPRouteProperty.find():
                        for seg in bgp_prop.BgpAsPathSegmentList.find():
                            seg.SegmentType.Single('asseq')

    table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
    for i in range(0, iteration):
        logger.info(
            '|---- RIB-IN Convergence test, Iteration : {} ----|'.format(i+1))
        """ withdraw all routes before starting traffic """
        logger.info('Withdraw All Routes before starting traffic')
        cs = snappi_api.control_state()
        cs.protocol.route.names = route_names
        cs.protocol.route.state = cs.protocol.route.WITHDRAW
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Routes to be withdrawn")
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(WAIT_INTERVAL, "For Protocols To start")
        """ Start Traffic """
        logger.info('Starting Traffic')
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        snappi_api.set_control_state(cs)
        wait(WAIT_INTERVAL, "For Traffic To start")
        flow_stats = get_flow_stats(snappi_api)
        tx_frame_rate = flow_stats[0].frames_tx_rate
        rx_frame_rate = flow_stats[0].frames_rx_rate
        assert tx_frame_rate != 0, "Traffic has not started"
        assert rx_frame_rate == 0

        """ Advertise All Routes """
        logger.info('Advertising all Routes from {}'.format(route_names))
        cs = snappi_api.control_state()
        cs.protocol.route.names = route_names
        cs.protocol.route.state = cs.protocol.route.ADVERTISE
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For all routes to be ADVERTISED")
        flows = get_flow_stats(snappi_api)
        for flow in flows:
            tx_frate.append(flow.frames_tx_rate)
            rx_frate.append(flow.frames_rx_rate)
        assert abs(sum(tx_frate) - sum(rx_frate)) < 500, \
            "Traffic has not converged, TxFrameRate:{},RxFrameRate:{}"\
            .format(sum(tx_frate), sum(rx_frate))
        logger.info("Traffic has converged after route advertisement")

        """ Get RIB-IN convergence """
        request = snappi_api.metrics_request()
        request.convergence.flow_names = []
        convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
        for metrics in convergence_metrics:
            logger.info('RIB-IN Convergence time (ms): {}'.format(
                metrics.control_plane_data_plane_convergence_us/1000))
        avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
        avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
        """ Stop traffic at the end of iteration """
        logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        snappi_api.set_control_state(cs)
        wait(WAIT_INTERVAL, "For Traffic To stop")
        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.STOP
        snappi_api.set_control_state(cs)
        wait(WAIT_INTERVAL, "For Protocols To STOP")
    table.append('Advertise All BGP Routes')
    table.append(route_type)
    table.append(number_of_routes)
    table.append(iteration)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    NG_LIST = []
    columns = ['Event Name', 'Route Type', 'No. of Routes',
               'Iterations', 'Frames Delta', 'Avg RIB-IN Convergence Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))


def get_RIB_IN_capacity(snappi_api,
                        multipath,
                        start_value,
                        step_value,
                        route_type,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        temp_tg_port (pytest fixture): Ports mapping info of T0 testbed
        multipath: ecmp value for BGP config
        start_value:  Start value of the number of BGP routes
        step_value: Step value of the number of BGP routes to be incremented
        route_type: IPv4 or IPv6 routes
    """
    def tgen_capacity(routes):
        config = snappi_api.config()
        config.events.cp_events.enable = True
        config.events.dp_events.enable = True
        config.events.dp_events.rx_rate_threshold = 90/(multipath-1)
        for i in range(1, 3):
            config.ports.port(name='Test_Port_%d' %
                              i, location=temp_tg_port[i-1]['location'])
            c_lag = config.lags.lag(name="lag%d" % i)[-1]
            lp = c_lag.ports.port(port_name='Test_Port_%d' % i)[-1]
            lp.ethernet.name = 'lag_eth_%d' % i
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            c_lag.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m
            lp.ethernet.name = "lag_Ethernet %s" % i
            lp.ethernet.mac = "00:10:01:00:00:%s" % m
            config.devices.device(name='Topology %d' % i)

        config.options.port_options.location_preemption = True
        layer1 = config.layer1.layer1()[-1]
        layer1.name = 'port settings'
        layer1.port_names = [port.name for port in config.ports]
        layer1.ieee_media_defaults = False
        layer1.auto_negotiation.rs_fec = False
        layer1.auto_negotiation.link_training = False
        layer1.speed = temp_tg_port[0]['speed']
        layer1.auto_negotiate = False

        def create_v4_topo():
            eth = config.devices[0].ethernets.add()
            eth.connection.port_name = config.lags[0].name
            eth.name = 'Ethernet 1'
            eth.mac = "00:00:00:00:00:01"
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'IPv4 1'
            ipv4.address = temp_tg_port[0]['ip']
            ipv4.gateway = temp_tg_port[0]['peer_ip']
            ipv4.prefix = int(temp_tg_port[0]['prefix'])
            rx_flow_name = []
            for i in range(2, 3):
                if len(str(hex(i).split('0x')[1])) == 1:
                    m = '0'+hex(i).split('0x')[1]
                else:
                    m = hex(i).split('0x')[1]
                ethernet_stack = config.devices[i-1].ethernets.add()
                ethernet_stack.connection.port_name = config.lags[i-1].name
                ethernet_stack.name = 'Ethernet %d' % i
                ethernet_stack.mac = "00:00:00:00:00:%s" % m
                ipv4_stack = ethernet_stack.ipv4_addresses.add()
                ipv4_stack.name = 'IPv4 %d' % i
                ipv4_stack.address = temp_tg_port[i-1]['ip']
                ipv4_stack.gateway = temp_tg_port[i-1]['peer_ip']
                ipv4_stack.prefix = int(temp_tg_port[i-1]['prefix'])
                bgpv4 = config.devices[i-1].bgp
                bgpv4.router_id = temp_tg_port[i-1]['peer_ip']
                bgpv4_int = bgpv4.ipv4_interfaces.add()
                bgpv4_int.ipv4_name = ipv4_stack.name
                bgpv4_peer = bgpv4_int.peers.add()
                bgpv4_peer.name = 'BGP %d' % i
                bgpv4_peer.as_type = BGP_TYPE
                bgpv4_peer.peer_address = temp_tg_port[i-1]['peer_ip']
                bgpv4_peer.as_number = int(TGEN_AS_NUM)
                route_range = bgpv4_peer.v4_routes.add(
                    name="Network_Group%d" % i)
                route_range.addresses.add(
                    address='200.1.0.1', prefix=32, count=routes)
                as_path = route_range.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = aspaths
                rx_flow_name.append(route_range.name)
            return rx_flow_name

        def create_v6_topo():
            eth = config.devices[0].ethernets.add()
            eth.connection.port_name = config.lags[0].name
            eth.name = 'Ethernet 1'
            eth.mac = "00:00:00:00:00:01"
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'IPv6 1'
            ipv6.address = temp_tg_port[0]['ipv6']
            ipv6.gateway = temp_tg_port[0]['peer_ipv6']
            ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
            rx_flow_name = []
            for i in range(2, 3):
                if len(str(hex(i).split('0x')[1])) == 1:
                    m = '0'+hex(i).split('0x')[1]
                else:
                    m = hex(i).split('0x')[1]
                ethernet_stack = config.devices[i-1].ethernets.add()
                ethernet_stack.connection.port_name = config.lags[i-1].name
                ethernet_stack.name = 'Ethernet %d' % i
                ethernet_stack.mac = "00:00:00:00:00:%s" % m
                ipv6_stack = ethernet_stack.ipv6_addresses.add()
                ipv6_stack.name = 'IPv6 %d' % i
                ipv6_stack.address = temp_tg_port[i-1]['ipv6']
                ipv6_stack.gateway = temp_tg_port[i-1]['peer_ipv6']
                ipv6_stack.prefix = int(temp_tg_port[i-1]['ipv6_prefix'])

                bgpv6 = config.devices[i-1].bgp
                bgpv6.router_id = temp_tg_port[i-1]['peer_ip']
                bgpv6_int = bgpv6.ipv6_interfaces.add()
                bgpv6_int.ipv6_name = ipv6_stack.name
                bgpv6_peer = bgpv6_int.peers.add()
                bgpv6_peer.name = 'BGP+_%d' % i
                bgpv6_peer.as_type = BGP_TYPE
                bgpv6_peer.peer_address = temp_tg_port[i-1]['peer_ipv6']
                bgpv6_peer.as_number = int(TGEN_AS_NUM)
                route_range = bgpv6_peer.v6_routes.add(
                    name="Network Group %d" % i)
                route_range.addresses.add(
                    address='3000::1', prefix=64, count=routes)
                as_path = route_range.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = aspaths
                rx_flow_name.append(route_range.name)
            return rx_flow_name
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
        return config

    def run_traffic(routes):
        logger.info(
            '|-------------------- RIB-IN Capacity test, No.of Routes : {} ----|'.format(routes))
        conv_config = tgen_capacity(routes)
        snappi_api.set_config(conv_config)
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        """ Starting Traffic """
        logger.info('Starting Traffic')
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Traffic To start")

    try:
        for j in range(start_value, 100000000000, step_value):
            max_routes = start_value
            tx_frate, rx_frate = [], []
            run_traffic(j)
            flow_stats = get_flow_stats(snappi_api)
            logger.info('\n')
            logger.info('Loss% : {}'.format(flow_stats[0].loss))
            for flow in flow_stats:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            logger.info("Tx Frame Rate : {}".format(tx_frate))
            logger.info("Rx Frame Rate : {}".format(rx_frate))
            logger.info('\n')
            if float(flow_stats[0].loss) > 0.001:
                if j == start_value:
                    raise Exception(
                        'Traffic Loss Encountered in first iteration, reduce the start value and run the test')
                logger.info('Loss greater than 0.001 occured')
                logger.info('Reducing the routes and running test')
                b = j-step_value
                logger.info('Stopping Traffic')
                cs = snappi_api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
                snappi_api.set_control_state(cs)
                wait(TIMEOUT-20, "For Traffic To stop")
                break
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT-20, "For Traffic To stop")
        routes = []
        routes.append(b+int(step_value/8))
        routes.append(b+int(step_value/4))
        routes.append(b+int(step_value/2))
        routes.append(b+step_value-int(step_value/4))
        routes.append(b+step_value-int(step_value/8))
        for i in range(0, len(routes)):
            run_traffic(routes[i])
            flow_stats = get_flow_stats(snappi_api)
            logger.info('Loss% : {}'.format(flow_stats[0].loss))
            if float(flow_stats[0].loss) <= 0.001:
                max_routes = start_value
                pass
            else:
                max_routes = routes[i]-int(step_value/8)
                break
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT-20, "For Traffic To stop")
            """ Stopping Protocols """
            logger.info("Stopping all protocols ...")
            cs = snappi_api.control_state()
            cs.protocol.all.state = cs.protocol.all.START
            snappi_api.set_control_state(cs)
            wait(TIMEOUT-20, "For Protocols To STOP")
    except Exception as e:
        logger.info(e)
    finally:
        columns = ['Test Name', 'Maximum no. of Routes']
        logger.info("\n%s" % tabulate(
            [['RIB-IN Capacity Test', max_routes]], headers=columns, tablefmt="psql"))


def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        duthost (pytest fixture): duthost fixture
    """
    duthost.command("sudo cp {} {}".format(
        "/etc/sonic/config_db_backup.json", "/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    logger.info("Wait until all critical services are fully started")
    pytest_assert(wait_until(360, 10, 1, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")
    logger.info('Convergence Test Completed')
