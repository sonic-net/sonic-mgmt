from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

# TODO: Try to get DUT bgp AS number if already configured
DUT_AS_NUM = 65100
TGEN_AS_NUM = 501
BGP_TYPE = 'ebgp'
PACKETS = 100000


def run_bgp_community_test(snappi_api,
                           duthost,
                           tgen_ports):
    """
    Run BGP Community test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    # Create bgp config on dut
    __duthost_bgp_config(duthost,
                         tgen_ports)

    # Create bgp config on TGEN
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    # Create BGP community configuration on DUT and TGEN
    tgen_community_config = __bgp_community_config(duthost,
                                                   tgen_bgp_config)

    # Verity test results
    __verify_test(duthost,
                  snappi_api,
                  tgen_community_config)

    # Cleanup
    __cleanup_community_config(duthost)

    __common_cleanup(duthost,
                     tgen_ports)


def run_bgp_group_as_path_modified(snappi_api,
                                   duthost,
                                   tgen_ports):
    """
    Run BGP Community test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    # Create bgp config on dut
    __duthost_bgp_config(duthost,
                         tgen_ports)

    # Create bgp config on TGEN
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    # Create BGP community configuration on DUT and TGEN
    as_path_modified_config = __bgp_as_path_modified_config(duthost,
                                                            tgen_bgp_config)

    # Verity test results
    __verify_test(duthost,
                  snappi_api,
                  as_path_modified_config)

    # Cleanup
    __cleanup_as_path_config(duthost)

    __common_cleanup(duthost,
                     tgen_ports)


def __duthost_bgp_config(duthost,
                         tgen_ports):
    """
    BGP Config on duthost

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    intf1_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'ip address %s/%s' "
    )
    intf1_config %= (tgen_ports[0]['peer_port'],
                     tgen_ports[0]['peer_ip'],
                     tgen_ports[0]['prefix'])
    duthost.shell(intf1_config)

    bgp_config_501 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor LC501 peer-group' "
        "-c 'neighbor LC501 remote-as %s' "
        "-c 'neighbor %s peer-group LC501' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor %s activate' "
    )
    bgp_config_501 %= (DUT_AS_NUM,
                       TGEN_AS_NUM,
                       tgen_ports[0]['ip'],
                       tgen_ports[0]['ip'])
    duthost.shell(bgp_config_501)

    intf2_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'ip address %s/%s' "
    )
    intf2_config %= (tgen_ports[1]['peer_port'],
                     tgen_ports[1]['peer_ip'],
                     tgen_ports[1]['prefix'])
    duthost.shell(intf2_config)

    # ipv6 config
    intf1_v6_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'ipv6 address %s/%s' "
    )
    intf1_v6_config %= (tgen_ports[0]['peer_port'],
                        tgen_ports[0]['peer_ipv6'],
                        tgen_ports[0]['ipv6_prefix'])
    duthost.shell(intf1_v6_config)

    bgpv6_config_501 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor LC501v6 peer-group' "
        "-c 'neighbor LC501v6 remote-as %s' "
        "-c 'neighbor %s peer-group LC501v6' "
        "-c 'address-family ipv6 unicast' "
        "-c 'neighbor %s activate' "
    )
    bgpv6_config_501 %= (DUT_AS_NUM,
                         TGEN_AS_NUM,
                         tgen_ports[0]['ipv6'],
                         tgen_ports[0]['ipv6'])
    duthost.shell(bgpv6_config_501)

    intf2_v6_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'ipv6 address %s/%s' "
    )
    intf2_v6_config %= (tgen_ports[1]['peer_port'],
                        tgen_ports[1]['peer_ipv6'],
                        tgen_ports[1]['ipv6_prefix'])
    duthost.shell(intf2_v6_config)


def __tgen_bgp_config(snappi_api,
                      tgen_ports):
    """
    BGP & Config on TGEN
    Args:
        snappi_api (pytest fixture): Snappi API
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    config = snappi_api.config()

    tgen1, tgen2 = (
        config.ports
        .port(name='tgen1', location=tgen_ports[0]['location'])
        .port(name='tgen2', location=tgen_ports[1]['location'])
    )

    # L1 Config
    config.options.port_options.location_preemption = True
    ly = config.layer1.layer1()[-1]
    ly.name = 'ly'
    ly.port_names = [tgen1.name, tgen2.name]
    ly.speed = tgen_ports[0]['speed']
    ly.auto_negotiate = False

    # Device Config
    d1, d2 = config.devices.device(name='d1').device(name='d2')
    d1.container_name = tgen1.name
    d2.container_name = tgen2.name

    eth1, eth2 = d1.ethernet, d2.ethernet
    eth1.name, eth2.name = "eth1", "eth2"

    ip1, ip2 = eth1.ipv4, eth2.ipv4
    ip1.name, ip2.name = "ip1", "ip2"

    ip1.address = tgen_ports[0]['ip']
    ip1.gateway = tgen_ports[0]['peer_ip']
    ip1.prefix = tgen_ports[0]['prefix']

    ip2.address = tgen_ports[1]['ip']
    ip2.gateway = tgen_ports[1]['peer_ip']
    ip2.prefix = tgen_ports[1]['prefix']

    bgp501 = ip1.bgpv4
    bgp501.name = "bgp501"
    bgp501.dut_address = tgen_ports[0]['peer_ip']
    bgp501.as_number = TGEN_AS_NUM
    bgp501.as_type = BGP_TYPE

    # v6 config
    ip1v6, ip2v6 = eth1.ipv6, eth2.ipv6
    ip1v6.name, ip2v6.name = "ip1v6", "ip2v6"

    ip1v6.address = tgen_ports[0]['ipv6']
    ip1v6.gateway = tgen_ports[0]['peer_ipv6']
    ip1v6.prefix = tgen_ports[0]['ipv6_prefix']

    ip2v6.address = tgen_ports[1]['ipv6']
    ip2v6.gateway = tgen_ports[1]['peer_ipv6']
    ip2v6.prefix = tgen_ports[1]['ipv6_prefix']

    bgp501v6 = ip1v6.bgpv6
    bgp501v6.name = "bgp501v6"
    bgp501v6.dut_address = tgen_ports[0]['peer_ipv6']
    bgp501v6.as_number = TGEN_AS_NUM
    bgp501v6.as_type = BGP_TYPE

    return config


def __bgp_community_config(duthost,
                           config):
    """
    BGP Community Config on duthost and TGEN
    Args:
        snappi_api (pytest fixture): Snappi API
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Route Range Config
    bgp501_rr_with_community, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_with_community")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route range("200.1.0.0") from AS 501 with community 1:2
    bgp501_rr_with_community.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                         prefix="16")

    manual_as_community = (
        bgp501_rr_with_community.communities.bgpcommunity()[-1])
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number = 1
    manual_as_community.as_custom = 2

    # Advertise another route range("20.1.0.0") from AS 501 without community
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix="16")

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Route Range Config
    bgp501v6_rr_with_community, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_with_community")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route range("4000::1") from AS 501 with community 1:2
    bgp501v6_rr_with_community.addresses.bgpv6routeaddress(address="4000::1",
                                                           prefix="64")

    manual_as_community = (
        bgp501v6_rr_with_community.communities.bgpcommunity()[-1])
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number = 1
    manual_as_community.as_custom = 2

    # Advertise another route range("6000::1") from AS 501 without community
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix="64")

    # Create two flows Permit(Traffic with Community list) & Deny
    permit, deny, permit_ipv6, deny_ipv6 = (
        config.flows
        .flow(name='permit')
        .flow(name='deny')
        .flow(name='permit_ipv6')
        .flow(name='deny_ipv6')
    )

    permit.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    permit.tx_rx.device.rx_names = [bgp501_rr_with_community.name]

    deny.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    permit.rate.percentage = 1
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = 1
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_with_community.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = 1
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = 1
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'bgp community-list 10 permit 1:2' "
        "-c 'route-map LA permit 30' "
        "-c 'match community 10'"
    )
    duthost.shell(community_config)

    return config


def __bgp_as_path_modified_config(duthost,
                                  config):
    """
    BGP group AS config on duthost and TGEN
    Args:
        snappi_api (pytest fixture): Snappi API
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Route Range Config
    bgp501_rr_with_as_100, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_with_as_100")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route range("200.1.0.0") from AS 501 with additional AS 100
    bgp501_rr_with_as_100.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                      prefix="16")

    as_path = bgp501_rr_with_as_100.as_path
    as_path_segment = as_path.as_path_segments.bgpaspathsegment()[-1]
    as_path_segment.segment_type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = [100]

    # Advertise another route range("20.1.0.0")
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix="16")

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Route Range Config
    bgp501v6_rr_with_as_100, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_with_as_100")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route range("4000::1") from AS 501 with additional AS 100
    bgp501v6_rr_with_as_100.addresses.bgpv6routeaddress(address="4000::1",
                                                        prefix="64")

    as_path = bgp501v6_rr_with_as_100.as_path
    as_path_segment = as_path.as_path_segments.bgpaspathsegment()[-1]
    as_path_segment.segment_type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = [100]

    # Advertise another route range("6000::1")
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix="64")

    permit, deny, permit_ipv6, deny_ipv6 = (
        config.flows
        .flow(name='permit')
        .flow(name='deny')
        .flow(name='permit_ipv6')
        .flow(name='deny_ipv6')
    )

    permit.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    permit.tx_rx.device.rx_names = [bgp501_rr_with_as_100.name]

    deny.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    permit.rate.percentage = 1
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = 1
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_with_as_100.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = 1
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = 1
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'bgp as-path access-list permit_100 permit 100' "
        "-c 'route-map LA permit 30' "
        "-c 'match as-path permit_100'"
    )
    duthost.shell(community_config)

    return config


def __verify_test(duthost,
                  snappi_api,
                  config):
    """
    Test Verification

    Args:
        duthost (pytest fixture): duthost fixture
        snappi_api (pytest fixture): Snappi API
        config: tgen_config
    """

    snappi_api.set_config(config)

    # unconfigure applied route-map if exists already
    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'no neighbor LC501 route-map LA in' "
    )
    route_map %= (DUT_AS_NUM)
    duthost.shell(route_map)

    # Start traffic
    ts = snappi_api.transmit_state()
    ts.state = ts.START
    snappi_api.set_transmit_state(ts)

    # Check there is no traffic loss for 'permit' & 'deny'
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_no_loss(snappi_api,
                                              ['permit', 'deny'],
                                              PACKETS * 2)),
                  'No loss expected')

    # Apply route-map to permit only routes with community
    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor LC501 route-map LA in' "
    )
    route_map %= (DUT_AS_NUM)
    duthost.shell(route_map)

    # Start traffic
    ts = snappi_api.transmit_state()
    ts.state = ts.START
    snappi_api.set_transmit_state(ts)

    # Check there is no traffic loss for 'permit' flow
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_no_loss(snappi_api,
                                              ['permit'],
                                              PACKETS)),
                  'No loss expected')

    # Check 100% traffic loss for 'deny' flow
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_total_loss(snappi_api, ['deny'])),
                  'total loss expected')


def __check_for_no_loss(snappi_api,
                        flow_names,
                        expected):
    """
    Returns True if there is no traffic loss else False

    Args:
        snappi_api (pytest fixture): Snappi API
        flow_names: List of flow_names to check for validation
        expected: Expected Packets Count
    """
    request = snappi_api.metrics_request()
    request.flow.flow_names = flow_names
    flow_results = snappi_api.get_metrics(request).flow_metrics
    flow_rx = sum([f.frames_rx for f in flow_results])
    return flow_rx == expected


def __check_for_total_loss(snappi_api,
                           flow_names):
    """
    Returns True if there is 100% traffic loss else False

    Args:
        snappi_api (pytest fixture): Snappi API
        flow_names: List of flow_names to check for validation
    """
    request = snappi_api.metrics_request()
    request.flow.flow_names = flow_names
    flow_results = snappi_api.get_metrics(request).flow_metrics
    flow_rx = sum([f.frames_rx for f in flow_results])
    return flow_rx == 0


def __cleanup_community_config(duthost):
    """
    BGP Config on duthost

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    # Remove community config
    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp community-list 10 permit 1:2' "
        "-c 'no route-map LA permit 30' "
    )
    duthost.shell(community_config)


def __cleanup_as_path_config(duthost):
    """
    BGP Config on duthost

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    # Remove community config
    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp as-path access-list permit_100 permit 100' "
        "-c 'no route-map LA permit 30' "
    )
    duthost.shell(community_config)


def __common_cleanup(duthost,
                     tgen_ports):

    # Remove bgp neighbor config
    bgp_config_501 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'no neighbor LC501 peer-group' "
        "-c 'no neighbor LC501v6 peer-group' "
    )
    bgp_config_501 %= (DUT_AS_NUM)
    duthost.shell(bgp_config_501)

    # Remove interface ip config
    intf1_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'no ip address %s/%s' "
        "-c 'no ipv6 address %s/%s' "
    )
    intf1_config %= (tgen_ports[0]['peer_port'],
                     tgen_ports[0]['peer_ip'],
                     tgen_ports[0]['prefix'],
                     tgen_ports[0]['peer_ipv6'],
                     tgen_ports[0]['ipv6_prefix'])
    duthost.shell(intf1_config)

    intf2_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'no ip address %s/%s' "
        "-c 'no ipv6 address %s/%s' "
    )
    intf2_config %= (tgen_ports[1]['peer_port'],
                     tgen_ports[1]['peer_ip'],
                     tgen_ports[1]['prefix'],
                     tgen_ports[0]['peer_ipv6'],
                     tgen_ports[0]['ipv6_prefix'])
    duthost.shell(intf2_config)

