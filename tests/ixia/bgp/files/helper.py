from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

DUT_AS_NUM = 65100
TGEN1_AS_NUM = 501
TGEN2_AS_NUM = 502
BGP_TYPE = 'ebgp'
PACKETS = 100000


def run_bgp_community_test(api,
                           duthost,
                           tgen_ports):
    """
    Run BGP Community test
    """
    # Create bgp config on dut
    __duthost_bgp_config(duthost,
                         tgen_ports)

    # Create bgp config on TGEN
    tgen_bgp_config = __tgen_bgp_config(api,
                                        tgen_ports)

    # Create BGP community configuration on DUT and TGEN
    tgen_community_config = __bgp_community_config(duthost,
                                                   tgen_bgp_config)

    # Verity test results
    __verify_test(duthost,
                  api,
                  tgen_community_config)

    __cleanup_config(duthost,
                     tgen_ports)


def __duthost_bgp_config(duthost,
                         tgen_ports):
    """
    BGP Config on duthost
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
                       TGEN1_AS_NUM,
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

    bgp_config_502 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor LC502 peer-group' "
        "-c 'neighbor LC502 remote-as %s' "
        "-c 'neighbor %s peer-group LC502' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor %s activate' "
    )
    bgp_config_502 %= (DUT_AS_NUM,
                       TGEN2_AS_NUM,
                       tgen_ports[1]['ip'],
                       tgen_ports[1]['ip'])
    duthost.shell(bgp_config_502)


def __tgen_bgp_config(api,
                      tgen_ports):
    """
    BGP & Config on TGEN
    """
    config = api.config()

    tx, rx = (
        config.ports
        .port(name='tx', location=tgen_ports[0]['location'])
        .port(name='rx', location=tgen_ports[1]['location'])
    )

    ly = config.layer1.layer1()[-1]
    ly.name = 'ly'
    ly.port_names = [tx.name, rx.name]
    ly.speed = tgen_ports[0]['speed']
    ly.auto_negotiate = False

    # Device Config
    d1, d2 = config.devices.device(name='d501').device(name='d502')
    d1.container_name = tx.name
    d2.container_name = rx.name
    eth1, eth2 = d1.ethernet, d2.ethernet
    eth1.name, eth2.name = "eth1", "eth2"
    ip1, ip2 = eth1.ipv4, eth2.ipv4
    ip1.name, ip2.name = "ip1", "ip2"
    bgp501, bgp502 = ip1.bgpv4, ip2.bgpv4
    bgp501.name, bgp502.name = "bgp501", "bgp502"

    ip1.address.value = tgen_ports[0]['ip']
    ip1.gateway.value = tgen_ports[0]['peer_ip']
    ip1.prefix.value = tgen_ports[0]['prefix']

    ip2.address.value = tgen_ports[1]['ip']
    ip2.gateway.value = tgen_ports[1]['peer_ip']
    ip2.prefix.value = tgen_ports[1]['prefix']

    bgp501.dut_ipv4_address.value = tgen_ports[0]['peer_ip']
    bgp501.as_number.value = TGEN1_AS_NUM
    bgp501.as_type = BGP_TYPE

    bgp502.dut_ipv4_address.value = tgen_ports[1]['peer_ip']
    bgp502.as_number.value = TGEN2_AS_NUM
    bgp502.as_type = BGP_TYPE

    return config


def __bgp_community_config(duthost,
                           config):
    """
    BGP Community Config on duthost and TGEN
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4
    bgp502 = config.devices[1].ethernet.ipv4.bgpv4

    # Route Range Config
    bgp501_rr_with_community, bgp501_rr2 = (
        bgp501.bgpv4_route_ranges
        .bgpv4routerange()
        .bgpv4routerange()
    )
    bgp502_rr1 = bgp502.bgpv4_route_ranges.bgpv4routerange()[-1]

    # Advertise one route range("200.1.0.0") from AS 501 with community 1:2
    bgp501_rr_with_community.name = "bgp501_rr_with_community"
    bgp501_rr_with_community.address.value = "200.1.0.0"
    bgp501_rr_with_community.prefix.value = "16"
    manual_as_community = bgp501_rr_with_community.community.bgpcommunity()[-1]
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number.value = "1"
    manual_as_community.as_custom.value = "2"

    # Advertise another route range("20.1.0.0") from AS 501 without
    bgp501_rr2.name = "bgp501_rr2"
    bgp501_rr2.address.value = "20.1.0.0"
    bgp501_rr2.prefix.value = "16"

    # Advertise route range("100.1.0.0" from AS 502)
    bgp502_rr1.name = "bgp502_rr1"
    bgp502_rr1.address.value = "100.1.0.0"
    bgp502_rr1.prefix.value = "16"

    # Create two flows Permit(Traffic with Community list) & Deny
    permit, deny = config.flows.flow(name='permit').flow(name='deny')
    permit.rate.percentage = 1
    permit.duration.fixed_packets.packets = PACKETS
    deny.rate.percentage = 1
    deny.duration.fixed_packets.packets = PACKETS

    permit.tx_rx.device.tx_names = [bgp502_rr1.name]
    permit.tx_rx.device.rx_names = [bgp501_rr_with_community.name]

    deny.tx_rx.device.tx_names = [bgp502_rr1.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'bgp community-list 10 permit 1:2' "
        "-c 'route-map LA permit 30' "
        "-c 'match community 10'"
    )
    duthost.shell(community_config)

    return config


def __verify_test(duthost,
                  api,
                  config):
    """
    Test Verification
    """
    api.set_config(config)

    # unconfigure route-map if exists already
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
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    # Check there is no traffic loss for 'permit' & 'deny'
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_no_loss(api,
                                              ['permit', 'deny'],
                                              PACKETS * 2)),
                  'No loss expected')

    # Add route-map to permit only routes with community
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
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    # Check there is no traffic loss for 'permit' flow
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_no_loss(api,
                                              ['permit'],
                                              PACKETS)),
                  'No loss expected')

    # Check 100% traffic loss for 'deny' flow
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_total_loss(api, ['deny'])),
                  'total loss expected')


def __check_for_no_loss(api, flow_names, expected):
    """
    Returns True if there is no traffic loss else False
    """
    request = api.metrics_request()
    request.flow.flow_names = flow_names
    flow_results = api.get_metrics(request).flow_metrics
    flow_rx = sum([f.frames_rx for f in flow_results])
    return flow_rx == expected


def __check_for_total_loss(api, flow_names):
    """
    Returns True if there is 100% traffic loss else False
    """
    request = api.metrics_request()
    request.flow.flow_names = flow_names
    flow_results = api.get_metrics(request).flow_metrics
    flow_rx = sum([f.frames_rx for f in flow_results])
    return flow_rx == 0


def __cleanup_config(duthost,
                     tgen_ports):
    """
    BGP Config on duthost
    """
    # Remove community config
    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp community-list 10 permit 1:2' "
        "-c 'no route-map LA permit 30' "
    )
    duthost.shell(community_config)

    # Remove bgp neighbor config
    bgp_config_501 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'no neighbor LC501 peer-group' "
    )
    bgp_config_501 %= (DUT_AS_NUM)
    duthost.shell(bgp_config_501)

    bgp_config_502 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'no neighbor LC502 peer-group' "
    )
    bgp_config_502 %= (DUT_AS_NUM)
    duthost.shell(bgp_config_502)

    # Remove interface ip config
    intf1_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'no ip address %s/%s' "
    )
    intf1_config %= (tgen_ports[0]['peer_port'],
                     tgen_ports[0]['peer_ip'],
                     tgen_ports[0]['prefix'])
    duthost.shell(intf1_config)

    intf2_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface %s' "
        "-c 'no ip address %s/%s' "
    )
    intf2_config %= (tgen_ports[1]['peer_port'],
                     tgen_ports[1]['peer_ip'],
                     tgen_ports[1]['prefix'])
    duthost.shell(intf2_config)


