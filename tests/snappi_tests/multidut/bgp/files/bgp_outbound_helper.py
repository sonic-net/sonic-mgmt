import logging
import random

from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)  # noqa: F401
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import create_ip_list  # noqa: F401
from tests.snappi_tests.variables import T1_SNAPPI_AS_NUM, T2_SNAPPI_AS_NUM, T1_DUT_AS_NUM, T2_DUT_AS_NUM, t1_ports, \
     t2_uplink_portchannel_members, t1_t2_dut_ipv4_list, v4_prefix_length, v6_prefix_length, \
     t1_t2_dut_ipv6_list, t1_t2_snappi_ipv4_list, \
     t1_t2_snappi_ipv6_list, t2_dut_portchannel_ipv4_list, t2_dut_portchannel_ipv6_list, \
     snappi_portchannel_ipv4_list, snappi_portchannel_ipv6_list, AS_PATHS, \
     BGP_TYPE, TIMEOUT, portchannel_count, t1_side_interconnected_port, t2_side_interconnected_port  # noqa: F401

logger = logging.getLogger(__name__)

ipv4_src, ipv6_src = [], []
ipv4_dest, ipv6_dest = [], []
total_routes = 0


def run_bgp_outbound(cvg_api,
                     traffic_type,
                     service_down,
                     snappi_extra_params):
    """
    Run Local link failover test

    Args:
        cvg_api (pytest fixture): snappi API
        traffic_type :
        snappi_extra_params :
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    duthosts = [duthost1, duthost2, duthost3]
    route_range = snappi_extra_params.ROUTE_RANGE
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    flap_event = snappi_extra_params.multi_dut_params.flap_event
    iteration = snappi_extra_params.iteration

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        duthosts,
                                        snappi_ports,
                                        traffic_type,
                                        route_range)

    get_install_time(duthosts,
                     cvg_api,
                     tgen_bgp_config,
                     flap_event,
                     service_down,
                     traffic_type,
                     iteration)


def duthost_bgp_config(duthosts,
                       snappi_ports):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthosts (pytest fixture): duthosts fixture
        snappi_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    # Add ips for t1 interfaces connected to tgen
    logger.info('--------------- T1 - Tgen Section --------------------')
    logger.info('\n')
    for index, port in enumerate(t1_ports[duthosts[0].hostname]):
        intf_config = (
            "sudo config interface ip add %s %s/%s\n"
            "sudo config interface ip add %s %s/%s\n"
        )
        intf_config %= (port, t1_t2_dut_ipv4_list[index], v4_prefix_length,
                        port, t1_t2_dut_ipv6_list[index], v6_prefix_length)
        duthosts[0].shell(intf_config)
        logger.info('Configuring IPs {} / {} on {} in {}'.
                    format(t1_t2_dut_ipv4_list[index],
                           t1_t2_dut_ipv6_list[index], port, duthosts[0].hostname))

    # configure Route map
    route_map_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'route-map RM_SET_SRC6 permit 10' "
        "-c 'on-match next' "
        "-c 'set ipv6 next-hop prefer-global' "
        "-c 'exit' "
        "-c 'ip nht resolve-via-default' "
        "-c 'ipv6 nht resolve-via-default' "
        "-c 'ipv6 protocol bgp route-map RM_SET_SRC6' "
    )
    duthosts[0].shell(route_map_config)
    # Configure bgp on t1
    logger.info('\n')
    logger.info('T1 Dut AS Number: {}'.format(T1_DUT_AS_NUM))
    logger.info('T1 Snappi AS Number: {}'.format(T1_SNAPPI_AS_NUM))
    if list(t1_ports.keys())[0] == duthosts[0].hostname:
        bgp_config = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'no router bgp 65100' "
            "-c 'router bgp %s' "
            "-c 'no bgp ebgp-requires-policy' "
            "-c 'bgp bestpath as-path multipath-relax' "
            "-c 'maximum-paths %s' "
            "-c 'exit' "
        )
        bgp_config %= (T1_DUT_AS_NUM, len(t1_ports[duthosts[0].hostname])+1)
        duthosts[0].shell(bgp_config)

    for index, custom_port in enumerate(t1_ports[duthosts[0].hostname]):
        for snappi_port in snappi_ports:
            if custom_port == snappi_port['peer_port'] and snappi_port['peer_device'] == duthosts[0].hostname:
                bgp_config_neighbor = (
                    "vtysh "
                    "-c 'configure terminal' "
                    "-c 'router bgp %s' "
                    "-c 'neighbor %s remote-as %s' "
                    "-c 'address-family ipv4 unicast' "
                    "-c 'neighbor %s activate' "
                    "-c 'neighbor %s remote-as %s' "
                    "-c 'address-family ipv6 unicast' "
                    "-c 'neighbor %s activate' "
                    "-c 'neighbor %s soft-reconfiguration inbound' "
                    "-c 'neighbor %s route-map RM_SET_SRC6 in' "
                    "-c 'maximum-paths 64' "
                    "-c 'exit' "
                )
                bgp_config_neighbor %= (
                    T1_DUT_AS_NUM, t1_t2_snappi_ipv4_list[index], T1_SNAPPI_AS_NUM, t1_t2_snappi_ipv4_list[index],
                    t1_t2_snappi_ipv6_list[index], T1_SNAPPI_AS_NUM, t1_t2_snappi_ipv6_list[index],
                    t1_t2_snappi_ipv6_list[index], t1_t2_snappi_ipv6_list[index]
                )
                duthosts[0].shell(bgp_config_neighbor)
                logger.info('Configuring BGPv4 and BGP+ Neighbor {} {} in {}'.
                            format(t1_t2_snappi_ipv4_list[index],
                                   t1_t2_snappi_ipv6_list[index], duthosts[0].hostname))

    logger.info('\n')
    # t1, t2 downlink interface config
    logger.info('---------------T1 - T2 Downlink Inter-Connectivity Section --------------------')
    logger.info('\n')
    index = len(t1_ports[duthosts[0].hostname])
    t1_intf_config = (
        "sudo config interface ip add %s %s/%s\n"
        "sudo config interface ip add %s %s/%s\n"
    )
    t1_intf_config %= (t1_side_interconnected_port, t1_t2_dut_ipv4_list[index], v4_prefix_length,
                       t1_side_interconnected_port, t1_t2_dut_ipv6_list[index], v6_prefix_length)
    duthosts[0].shell(t1_intf_config)
    logger.info('Configuring IPs {} {} to {} in {}'.format(t1_t2_dut_ipv4_list[index],
                t1_t2_dut_ipv6_list[index], t1_side_interconnected_port, duthosts[0].hostname))

    t2_downlink_intf_config = (
        "sudo config interface -n %s ip add %s %s/%s\n"
        "sudo config interface -n %s ip add %s %s/%s\n"
    )
    t2_downlink_intf_config %= (t2_side_interconnected_port['asic_value'], t2_side_interconnected_port['port_name'],
                                t1_t2_snappi_ipv4_list[index], v4_prefix_length,
                                t2_side_interconnected_port['asic_value'],
                                t2_side_interconnected_port['port_name'],
                                t1_t2_snappi_ipv6_list[index], v6_prefix_length)
    duthosts[2].shell(t2_downlink_intf_config)
    logger.info('Configuring IPs {} {} to {} -n {} in {}'.
                format(t1_t2_snappi_ipv4_list[index], t1_t2_snappi_ipv6_list[index],
                       t2_side_interconnected_port['port_name'], t2_side_interconnected_port['asic_value'],
                       duthosts[2].hostname))
    logger.info('\n')
    logger.info('T1 Dut AS Number: {}'.format(T1_DUT_AS_NUM))
    logger.info('T2 Dut AS Number: {}'.format(T2_DUT_AS_NUM))
    t1_bgp = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor %s remote-as %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor %s activate' "
        "-c 'neighbor %s remote-as %s' "
        "-c 'address-family ipv6 unicast' "
        "-c 'neighbor %s activate' "
        "-c 'neighbor %s soft-reconfiguration inbound' "
        "-c 'neighbor %s route-map RM_SET_SRC6 in' "
        "-c 'maximum-paths 64' "
        "-c 'exit' "
    )
    t1_bgp %= (
        T1_DUT_AS_NUM, t1_t2_snappi_ipv4_list[index], T2_DUT_AS_NUM, t1_t2_snappi_ipv4_list[index],
        t1_t2_snappi_ipv6_list[index], T2_DUT_AS_NUM, t1_t2_snappi_ipv6_list[index],
        t1_t2_snappi_ipv6_list[index], t1_t2_snappi_ipv6_list[index]
    )
    duthosts[0].shell(t1_bgp)
    logger.info('Configuring BGPv4 and BGP+ Neighbor {} {} in {}'.
                format(t1_t2_snappi_ipv4_list[index], t1_t2_snappi_ipv6_list[index], duthosts[0].hostname))

    t2_downlink_bgp = (
        "vtysh -n %s "
        "-c 'configure terminal' "
        "-c 'route-map RM_SET_SRC6 permit 10' "
        "-c 'on-match next' "
        "-c 'set ipv6 next-hop prefer-global' "
        "-c 'exit' "
        "-c 'ip nht resolve-via-default' "
        "-c 'ipv6 nht resolve-via-default' "
        "-c 'ipv6 protocol bgp route-map RM_SET_SRC6' "
        "-c 'router bgp %s' "
        "-c 'neighbor %s remote-as %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor %s activate' "
        "-c 'neighbor %s remote-as %s' "
        "-c 'address-family ipv6 unicast' "
        "-c 'neighbor %s activate' "
        "-c 'neighbor %s soft-reconfiguration inbound' "
        "-c 'neighbor %s route-map RM_SET_SRC6 in' "
        "-c 'maximum-paths 64' "
        "-c 'exit' "
    )
    t2_downlink_bgp %= (
        t2_side_interconnected_port['asic_value'][-1], T2_DUT_AS_NUM,
        t1_t2_dut_ipv4_list[index], T1_DUT_AS_NUM, t1_t2_dut_ipv4_list[index],
        t1_t2_dut_ipv6_list[index], T1_DUT_AS_NUM, t1_t2_dut_ipv6_list[index],
        t1_t2_dut_ipv6_list[index], t1_t2_dut_ipv6_list[index]
    )
    duthosts[2].shell(t2_downlink_bgp)
    logger.info('Configuring BGPv4 and BGP+ Neighbor {} {} in {} frr {}'.format(t1_t2_dut_ipv4_list[index],
                t1_t2_dut_ipv6_list[index], duthosts[2].hostname, t2_side_interconnected_port['asic_value'][-1]))

    logger.info('--------------- T2 Uplink - Tgen Section --------------------')

    index = 0
    for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
        for portchannel, ports in portchannel_info.items():
            duthosts[1].command('sudo config portchannel -n {} add {} \n'.
                                format(asic_value, portchannel))
            logger.info('\n')
            logger.info('Adding -n {} {} in {}'.format(asic_value, portchannel, duthosts[1].hostname))
            for port in ports:
                duthosts[1].command('sudo config portchannel -n {} member add {} {} \n'.
                                    format(asic_value, portchannel, port))
                logger.info('Adding member {} to {}'.format(port, portchannel))

            logger.info('Configuring IPs {} /  {}  to {}'.
                        format(t2_dut_portchannel_ipv4_list[index], t2_dut_portchannel_ipv6_list[index], portchannel))
            duthosts[1].command('sudo config interface -n {} ip add {} {}/{} \n'.
                                format(asic_value, portchannel, t2_dut_portchannel_ipv4_list[index], v4_prefix_length))
            duthosts[1].command('sudo config interface -n {} ip add {} {}/{} \n'.
                                format(asic_value, portchannel, t2_dut_portchannel_ipv6_list[index], v6_prefix_length))
            index = index + 1

    index = 0
    for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
        for portchannel, ports in portchannel_info.items():
            logger.info('\n')
            bgp_config = (
                "vtysh -n %s "
                "-c 'configure terminal' "
                "-c 'route-map RM_SET_SRC6 permit 10' "
                "-c 'on-match next' "
                "-c 'set ipv6 next-hop prefer-global' "
                "-c 'exit' "
                "-c 'ip nht resolve-via-default' "
                "-c 'ipv6 nht resolve-via-default' "
                "-c 'ipv6 protocol bgp route-map RM_SET_SRC6' "
                "-c 'router bgp %s' "
                "-c 'no bgp ebgp-requires-policy' "
                "-c 'bgp bestpath as-path multipath-relax' "
                "-c 'maximum-paths %s' "
                "-c 'exit' "
            )
            bgp_config %= (asic_value[-1], T2_DUT_AS_NUM, portchannel_count)
            duthosts[1].shell(bgp_config)

            bgp_config_neighbor = (
                "vtysh -n %s "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s remote-as %s' "
                "-c 'address-family ipv4 unicast' "
                "-c 'neighbor %s activate' "
                "-c 'neighbor %s remote-as %s' "
                "-c 'address-family ipv6 unicast' "
                "-c 'neighbor %s activate' "
                "-c 'neighbor %s soft-reconfiguration inbound' "
                "-c 'neighbor %s route-map RM_SET_SRC6 in' "
                "-c 'maximum-paths 64' "
                "-c 'exit' "
            )
            bgp_config_neighbor %= (
                asic_value[-1], T2_DUT_AS_NUM, snappi_portchannel_ipv4_list[index], T2_SNAPPI_AS_NUM,
                snappi_portchannel_ipv4_list[index], snappi_portchannel_ipv6_list[index], T2_SNAPPI_AS_NUM,
                snappi_portchannel_ipv6_list[index], snappi_portchannel_ipv6_list[index],
                snappi_portchannel_ipv6_list[index]
            )
            duthosts[1].shell(bgp_config_neighbor)
            logger.info('T2 Dut AS Number: {}'.format(T2_DUT_AS_NUM))
            logger.info('T2 Snappi AS Number: {}'.format(T2_SNAPPI_AS_NUM))
            logger.info('Configuring BGPv4 and BGP+ Neighbor {} {} in {} frr {}'.
                        format(snappi_portchannel_ipv4_list[index],
                               snappi_portchannel_ipv6_list[index], duthosts[1].hostname, asic_value[-1]))
            index = index + 1
        logger.info('\n')


def generate_mac_address():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def __tgen_bgp_config(cvg_api,
                      duthosts,
                      snappi_ports,
                      traffic_type,
                      route_range):
    """
    Creating  BGP config on TGEN

    Args:
        cvg_api (pytest fixture): snappi API
        duthosts: multipath + 1
        snappi_ports :  Number of IPv4/IPv6 Routes
        traffic_type: IPv4 or IPv6 routes
        route_range: speed of the port used for test
    """
    conv_config = cvg_api.convergence_config()
    config = conv_config.config
    # get all the t1 and uplink ports from variables
    t1_variable_ports = t1_ports[duthosts[0].hostname]
    t2_variable_ports = []
    port_tuple = []
    for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
        for portchannel, ports in portchannel_info.items():
            port_tuple.append(ports)
            for port in ports:
                t2_variable_ports.append(port)

    snappi_t1_ports = []
    snappi_t2_ports = []
    for snappi_port in snappi_ports:
        for port in t1_variable_ports:
            if snappi_port['peer_device'] == duthosts[0].hostname and snappi_port['peer_port'] == port:
                snappi_t1_ports.append(snappi_port)
        for port in t2_variable_ports:
            if snappi_port['peer_device'] == duthosts[1].hostname and snappi_port['peer_port'] == port:
                snappi_t2_ports.append(snappi_port)
    # Adding Ports
    for index, snappi_test_port in enumerate(snappi_t1_ports):
        snappi_test_port['name'] = 'Test_Port_%d' % index
        config.ports.port(name='Test_Port_%d' % index, location=snappi_test_port['location'])
    for index, snappi_test_port in enumerate(snappi_t2_ports, len(snappi_t1_ports)):
        snappi_test_port['name'] = 'Test_Port_%d' % index
        config.ports.port(name='Test_Port_%d' % index, location=snappi_test_port['location'])

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = snappi_ports[0]['speed']
    layer1.auto_negotiate = False

    temp = 0
    for lag_count, port_set in enumerate(port_tuple):
        lag = config.lags.lag(name="LAG %d" % lag_count)[-1]
        lag.protocol.lacp.actor_system_id = generate_mac_address()
        m = '0' + hex(lag_count % 15+1).split('0x')[1]

        for index, port in enumerate(port_set):
            n = '0'+hex(index % 15+1).split('0x')[1]
            for snappi_t2_port in snappi_t2_ports:
                if port == snappi_t2_port['peer_port']:
                    lp = lag.ports.port(port_name=snappi_t2_port['name'])[-1]
                    lp.ethernet.name = "Eth%d" % temp
                    lp.ethernet.mac = "00:%s:00:00:00:%s" % (n, m)
                    logger.info('\n')
                    temp += 1

        device = config.devices.device(name="T2 Device {}".format(lag_count))[-1]
        eth = device.ethernets.add()
        eth.port_name = lag.name
        eth.name = 'T2_Ethernet_%d' % lag_count
        eth.mac = "00:00:00:00:00:%s" % m

        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T2_IPv4_%d' % lag_count
        ipv4.address = snappi_portchannel_ipv4_list[lag_count]
        ipv4.gateway = t2_dut_portchannel_ipv4_list[lag_count]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T2_IPv6_%d' % lag_count
        ipv6.address = snappi_portchannel_ipv6_list[lag_count]
        ipv6.gateway = t2_dut_portchannel_ipv6_list[lag_count]
        ipv6.prefix = v6_prefix_length

        bgpv4 = device.bgp
        bgpv4.router_id = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv4_int = bgpv4.ipv4_interfaces.add()
        bgpv4_int.ipv4_name = ipv4.name
        bgpv4_peer = bgpv4_int.peers.add()
        bgpv4_peer.name = 'T2_BGP_%d' % lag_count
        bgpv4_peer.as_type = BGP_TYPE
        bgpv4_peer.peer_address = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv4_peer.as_number = int(T2_SNAPPI_AS_NUM)

        route_range1 = bgpv4_peer.v4_routes.add(name="T2_IPv4_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv4']):
            route_range1.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])

        ipv4_dest.append(route_range1.name)

        bgpv6 = device.bgp
        bgpv6.router_id = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv6_int = bgpv6.ipv6_interfaces.add()
        bgpv6_int.ipv6_name = ipv6.name
        bgpv6_peer = bgpv6_int.peers.add()
        bgpv6_peer.name = 'T2_BGP+_%d' % lag_count
        bgpv6_peer.as_type = BGP_TYPE
        bgpv6_peer.peer_address = t2_dut_portchannel_ipv6_list[lag_count]
        bgpv6_peer.as_number = int(T2_SNAPPI_AS_NUM)

        route_range2 = bgpv6_peer.v6_routes.add(name="T2_IPv6_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv6']):
            route_range2.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])

        ipv6_dest.append(route_range2.name)

    for index, port in enumerate(snappi_t1_ports):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        device = config.devices.device(name="T1 Device {}".format(index))[-1]
        eth = device.ethernets.add()
        eth.port_name = port['name']
        eth.name = 'T1_Ethernet_%d' % index
        eth.mac = "00:10:00:00:00:%s" % m
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T1_IPv4_%d' % index
        ipv4.address = t1_t2_snappi_ipv4_list[index]
        ipv4.gateway = t1_t2_dut_ipv4_list[index]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T1_IPv6_%d' % index
        ipv6.address = t1_t2_snappi_ipv6_list[index]
        ipv6.gateway = t1_t2_dut_ipv6_list[index]
        ipv6.prefix = v6_prefix_length
        ipv4_src.append(ipv4.name)
        ipv6_src.append(ipv6.name)

        if index != 0:
            bgpv4 = device.bgp
            bgpv4.router_id = t1_t2_snappi_ipv4_list[index]
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'T1_BGP_%d' % index
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = t1_t2_dut_ipv4_list[index]
            bgpv4_peer.as_number = int(T1_SNAPPI_AS_NUM)

            route_range1 = bgpv4_peer.v4_routes.add(name="T1_IPv4_Routes_%d" % (index))
            for route_index, routes in enumerate(route_range['IPv4']):
                route_range1.addresses.add(
                    address=routes[0], prefix=routes[1], count=routes[2])
            ipv4_dest.append(route_range1.name)
            as_path = route_range1.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = AS_PATHS

            bgpv6 = device.bgp
            bgpv6.router_id = t1_t2_snappi_ipv4_list[index]
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'T1_BGP+_%d' % index
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = t1_t2_dut_ipv6_list[index]
            bgpv6_peer.as_number = int(T1_SNAPPI_AS_NUM)

            route_range2 = bgpv6_peer.v6_routes.add(name="T1_IPv6_Routes_%d" % (index))
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
        flow1.rate.percentage = 10
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    global total_routes
    if traffic_type == 'IPv4':
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4_Traffic", [ipv4_src[0]], ipv4_dest)
    else:
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv6 Traffic", [ipv6_src[0]], ipv6_dest)
    return conv_config


def get_flow_stats(cvg_api):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = []
    return cvg_api.get_results(request).flow_metric


def get_install_time(duthosts,
                     cvg_api,
                     bgp_config,
                     flap_event,
                     service_down,
                     traffic_type,
                     iteration):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        cvg_api (pytest fixture): Snappi API
        bgp_config: __tgen_bgp_config
        flap_event: contains hostname and port / services that needs to be flapped
        service_down(bool): If services on the dut needs to be brought down
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
    """
    cvg_api.set_config(bgp_config)
    avg_pld = []
    delta_frames = 0
    for i in range(0, iteration):
        logger.info(
            '|--------------------------- Iteration : {} -----------------------|'.format(i+1))
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = cvg_api.convergence_state()
        cs.protocol.state = cs.protocol.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Protocols To start")

        logger.info('Starting Traffic')
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Traffic To start")

        flow_stats = get_flow_stats(cvg_api)
        logger.info('Loss %: {}'.format(int(flow_stats[0].loss)))
        pytest_assert(int(flow_stats[0].loss) == 0, 'Loss Observed in traffic flow before link Flap')
        # Flap the required test port
        if service_down is False:
            if duthosts[0].hostname == flap_event['hostname']:
                logger.info(' Shutting down {} port of {} dut !!'.
                            format(flap_event['port_name'], flap_event['hostname']))
                duthosts[0].command('sudo config interface shutdown {} \n'.
                                    format(flap_event['port_name']))
            elif 'sonic-sonic' == flap_event['hostname'] and isinstance(flap_event['port_name'], str):
                cs = cvg_api.convergence_state()
                cs.link.port_names = [flap_event['port_name']]
                cs.link.state = cs.link.DOWN
                cvg_api.set_state(cs)
                logger.info('Shutting down snappi port : {}'.format(flap_event['port_name']))
                wait(TIMEOUT, "For link to shutdown")
            elif 'sonic-sonic' == flap_event['hostname'] and isinstance(flap_event['port_name'], list):
                cs = cvg_api.convergence_state()
                cs.link.port_names = flap_event['port_name']
                cs.link.state = cs.link.DOWN
                cvg_api.set_state(cs)
                logger.info('Shutting down all LAG member ports : {}'.format(flap_event['port_name']))
                wait(TIMEOUT, "For link to shutdown")
        else:
            # todo
            pass
        flow_stats = get_flow_stats(cvg_api)
        pkt_loss_duration = 1000*((flow_stats[0].frames_tx - flow_stats[0].frames_rx)/flow_stats[0].frames_tx_rate)
        delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
        pkt_loss_duration = 1000*(delta_frames/flow_stats[0].frames_tx_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('|-------------------------------------|')
        logger.info('|PACKET LOSS DURATION (ms): {}'.format(pkt_loss_duration))
        logger.info('|-------------------------------------|')
        avg_pld.append(pkt_loss_duration)

        flow_stats = get_flow_stats(cvg_api)
        pytest_assert(float((int(flow_stats[0].frames_tx_rate) - int(flow_stats[0].frames_tx_rate)) /
                      int(flow_stats[0].frames_tx_rate)) < 0.005,
                      'Traffic has not converged after link flap')
        if service_down is False:
            if duthosts[0].hostname == flap_event['hostname']:
                logger.info(' Starting up {} port of {} dut !!'.
                            format(flap_event['port_name'], flap_event['hostname']))
                duthosts[0].command('sudo config interface startup {} \n'.
                                    format(flap_event['port_name']))
            elif 'sonic-sonic' == flap_event['hostname'] and isinstance(flap_event['port_name'], str):
                cs = cvg_api.convergence_state()
                cs.link.port_names = [flap_event['port_name']]
                cs.link.state = cs.link.UP
                cvg_api.set_state(cs)
                logger.info('Starting up  snappi port : {}'.format(flap_event['port_name']))
                wait(TIMEOUT, "For link to startup")
            elif 'sonic-sonic' == flap_event['hostname'] and isinstance(flap_event['port_name'], list):
                cs = cvg_api.convergence_state()
                cs.link.port_names = flap_event['port_name']
                cs.link.state = cs.link.UP
                cvg_api.set_state(cs)
                logger.info('Starting up all LAG member ports : {}'.format(flap_event['port_name']))
                wait(TIMEOUT, "For link to startup")
        else:
            # todo
            pass
        flow_stats = get_flow_stats(cvg_api)
        pytest_assert(float((int(flow_stats[0].frames_tx_rate) - int(flow_stats[0].frames_tx_rate)) /
                      int(flow_stats[0].frames_tx_rate)) < 0.005,
                      'Loss observed after bringing the link back up')

        logger.info('Stopping Traffic')
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Traffic To stop")

        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = cvg_api.convergence_state()
        cs.protocol.state = cs.protocol.STOP
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Protocols To stop")
        logger.info('\n')

    columns = ['Event Name', 'Iterations', 'Traffic Type', 'Route Count', 'Avg Calculated Packet Loss Duration (ms)']
    logger.info("\n%s" % tabulate([[f"{flap_event['hostname']}:{flap_event['port_name']} \
                Link Flap", iteration, traffic_type, total_routes, mean(avg_pld)]], headers=columns, tablefmt="psql"))
