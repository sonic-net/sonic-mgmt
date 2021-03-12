from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import logging

logger = logging.getLogger(__name__)

DUT_AS_NUM = 10086
TGEN_AS_NUM = 501
BGP_TYPE = 'ebgp'
PACKETS = 100000
LINE_RATE = 1
COMMUNITY = "1:2"
MED = 50
GROUP_AS = [100]


def config_setup(duthost,
                 tgen_ports):
    """
    BGP Config on duthost

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info("|--Remove Any Existing BGP Process on DUT--|")
    try:
        duthost.shell(
            "vtysh "
            "-c 'configure terminal' "
            "-c 'no router bgp' "
        )
    except Exception:
        logger.info("No BGP process is configured")

    logger.info("|--Interface Configuration On DUT--|")
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

    # ipv6 interface config
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

    logger.info("|--BGP Configuration On DUT--|")
    bgp_config_501 = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'no bgp default ipv4-unicast' "
        "-c 'no bgp ebgp-requires-policy' "
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

    # ipv6 next hop route-map
    next_hop = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'route-map NEXTHOP permit 1' "
        "-c 'on-match next' "
        "-c 'set ipv6 next-hop prefer-global' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv6 unicast' "
        "-c 'neighbor LC501v6 route-map NEXTHOP in' "
    )
    next_hop %= (DUT_AS_NUM)
    duthost.shell(next_hop)


def run_bgp_peer_routing_policies_test(snappi_api,
                                       duthost,
                                       tgen_ports):
    """
    Run BGP Peer Routing Policies Test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info("|--Create BGP TGEN Configuration--|")
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    logger.info("|--Updating TGEN Config with BGP Route Attributes--|")
    tgen_bgp_policies_config = __tgen_bgp_policies_config(tgen_bgp_config)

    logger.info("|--BGP Policy Route Map Configuration on DUT--|")
    __bgp_policies_route_map_config(duthost)

    logger.info("|--Verify Test--|")
    __verify_test(duthost,
                  snappi_api,
                  tgen_bgp_policies_config)


def run_bgp_community_test(snappi_api,
                           duthost,
                           tgen_ports):
    """
    Run BGP Community List Filtering Test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info("|--Create BGP TGEN Configuration--|")
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    logger.info("|--Updating TGEN Config with BGP Community Attribute--|")
    tgen_bgp_community_config = __tgen_bgp_community_config(tgen_bgp_config)

    logger.info("|--BGP Community Route Map Configuration on DUT--|")
    __bgp_community_route_map_config(duthost)

    logger.info("|--Verify Test--|")
    __verify_test(duthost,
                  snappi_api,
                  tgen_bgp_community_config)


def run_bgp_prefix_list_test(snappi_api,
                             duthost,
                             tgen_ports):
    """
    Run BGP Prefix List Filtering Test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info("|--Create BGP TGEN Configuration--|")
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    logger.info("|--Updating TGEN Config with with Prefix Lists--|")
    tgen_bgp_prefix_list_config = __tgen_bgp_prefix_list_config(
        tgen_bgp_config)

    logger.info("|--BGP Prefix List Route Map Configuration on DUT--|")
    __bgp_prefix_list_route_map_config(duthost)

    logger.info("|--Verify Test--|")
    __verify_test(duthost,
                  snappi_api,
                  tgen_bgp_prefix_list_config)


def run_bgp_metric_filter(snappi_api,
                          duthost,
                          tgen_ports):
    """
    Run BGP Metric Filter Test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """

    logger.info("|--Create BGP TGEN Configuration--|")
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    logger.info("|--Updating TGEN Config with Metric/MED Attribute--|")
    tgen_bgp_metric_config = __tgen_bgp_metric_config(tgen_bgp_config)

    logger.info("|--BGP Metric Route Map Configuration on DUT--|")
    __bgp_metric_route_map_config(duthost)

    logger.info("|--Verify Test--|")
    __verify_test(duthost,
                  snappi_api,
                  tgen_bgp_metric_config)


def run_bgp_group_as_path_modified(snappi_api,
                                   duthost,
                                   tgen_ports):
    """
    Run BGP group-as-path Modified Test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info("|--Create BGP TGEN Configuration--|")
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    logger.info("|--Updating TGEN Config with Group AS-PATH Attribute--|")
    tgen_as_path_modified_config = __tgen_bgp_as_path_modified_config(
        tgen_bgp_config)

    logger.info("|--BGP AS-PATH Route Map Configuration on DUT--|")
    __bgp_as_path_route_map_config(duthost)

    logger.info("|--Verify Test--|")
    __verify_test(duthost,
                  snappi_api,
                  tgen_as_path_modified_config)


def run_bgp_origin_code_modification(snappi_api,
                                     duthost,
                                     tgen_ports):
    """
    Run BGP Origin Code Modification Test

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info("|--Create BGP TGEN Configuration--|")
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports)

    logger.info("|--Updating TGEN Config with Origin Attribute--|")
    tgen_bgp_origin_config = __tgen_bgp_origin_config(tgen_bgp_config)

    logger.info("|--BGP Origin Route Map Configuration on DUT--|")
    __bgp_origin_route_map_config(duthost)

    logger.info("|--Verify Test--|")
    __verify_test(duthost,
                  snappi_api,
                  tgen_bgp_origin_config)


# Common TGEN BGP Config
def __tgen_bgp_config(snappi_api,
                      tgen_ports):
    """
    BGP Config on TGEN
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

    # BGPv4
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

    # BGPv6
    bgp501v6 = ip1v6.bgpv6
    bgp501v6.name = "bgp501v6"
    bgp501v6.dut_address = tgen_ports[0]['peer_ipv6']
    bgp501v6.as_number = TGEN_AS_NUM
    bgp501v6.as_type = BGP_TYPE

    return config


def __tgen_bgp_policies_config(config):
    """
    BGP Attributes Config on TGEN
    Args:
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Routes Config
    bgp501_rr_with_policies, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_with_policies")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route("200.1.0.0") from AS 501 attributes
    bgp501_rr_with_policies.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                        prefix=16)

    # Community
    manual_as_community = (
        bgp501_rr_with_policies.communities.bgpcommunity()[-1])
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number = int(COMMUNITY.split(":")[0])
    manual_as_community.as_custom = int(COMMUNITY.split(":")[1])
    # Metric
    bgp501_rr_with_policies.advanced.multi_exit_discriminator = MED
    # AS PATH
    as_path = bgp501_rr_with_policies.as_path
    as_path_segment = as_path.as_path_segments.bgpaspathsegment()[-1]
    as_path_segment.segment_type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = GROUP_AS
    # Origin
    bgp501_rr_with_policies.advanced.origin = (
        bgp501_rr_with_policies.advanced.EGP)

    # Advertise another route("20.1.0.0") from AS 501
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix=16)

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Routes Config
    bgp501v6_rr_with_policies, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_with_policies")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route("4000::1") from AS 501 with Attributes
    bgp501v6_rr_with_policies.addresses.bgpv6routeaddress(address="4000::1",
                                                          prefix=64)

    # Community
    manual_as_community = (
        bgp501v6_rr_with_policies.communities.bgpcommunity()[-1])
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number = int(COMMUNITY.split(":")[0])
    manual_as_community.as_custom = int(COMMUNITY.split(":")[1])
    # Metric
    bgp501v6_rr_with_policies.advanced.multi_exit_discriminator = MED
    # AS PATH
    as_path = bgp501v6_rr_with_policies.as_path
    as_path_segment = as_path.as_path_segments.bgpaspathsegment()[-1]
    as_path_segment.segment_type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = GROUP_AS
    # Origin
    bgp501v6_rr_with_policies.advanced.origin = (
        bgp501v6_rr_with_policies.advanced.EGP)

    # Advertise another route("6000::1") from AS 501
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix=64)

    # Create four flows
    permit, deny, permit_ipv6, deny_ipv6 = (
        config.flows
        .flow(name='permit')
        .flow(name='deny')
        .flow(name='permit_ipv6')
        .flow(name='deny_ipv6')
    )

    permit.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    permit.tx_rx.device.rx_names = [bgp501_rr_with_policies.name]

    deny.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    permit.rate.percentage = LINE_RATE
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = LINE_RATE
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_with_policies.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = LINE_RATE
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = LINE_RATE
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    return config


def __bgp_policies_route_map_config(duthost):
    """
    BGP Policy Route MAP Config on duthost
    Args:
        duthost : duthost fixture
    """
    # Remove route_map if exists already
    duthost.shell(
            "vtysh "
            "-c 'configure terminal' "
            "-c 'no route-map LA' "
            "-c 'no route-map LAv6' "
        )

    as_path_access_list = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp as-path access-list PERMIT_100' "
    )
    try:
        duthost.shell(as_path_access_list)
    except Exception:
        pass

    community = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp community-list 10' "
    )
    try:
        duthost.shell(community)
    except Exception:
        pass

    # Configure route_map
    policy_route_map_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'bgp community-list 10 permit 1:2' "
        "-c 'bgp as-path access-list PERMIT_100 permit 100' "
        "-c 'route-map LA permit 30' "
        "-c 'match community 10' "
        "-c 'match as-path PERMIT_100' "
        "-c 'match metric 50' "
        "-c 'match origin egp' "
        "-c 'route-map LAv6 permit 30' "
        "-c 'match community 10' "
        "-c 'match as-path PERMIT_100' "
        "-c 'match metric 50' "
        "-c 'match origin egp' "
    )
    duthost.shell(policy_route_map_config)


def __tgen_bgp_community_config(config):
    """
    BGP Community Config on TGEN
    Args:
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Routes Config
    bgp501_rr_with_community, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_with_community")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route("200.1.0.0") from AS 501 with community 1:2
    bgp501_rr_with_community.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                         prefix=16)

    manual_as_community = (
        bgp501_rr_with_community.communities.bgpcommunity()[-1])
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number = int(COMMUNITY.split(":")[0])
    manual_as_community.as_custom = int(COMMUNITY.split(":")[1])

    # Advertise another route("20.1.0.0") from AS 501 without community
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix=16)

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Routes Config
    bgp501v6_rr_with_community, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_with_community")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route("4000::1") from AS 501 with community 1:2
    bgp501v6_rr_with_community.addresses.bgpv6routeaddress(address="4000::1",
                                                           prefix=64)

    manual_as_community = (
        bgp501v6_rr_with_community.communities.bgpcommunity()[-1])
    manual_as_community.community_type = manual_as_community.MANUAL_AS_NUMBER
    manual_as_community.as_number = int(COMMUNITY.split(":")[0])
    manual_as_community.as_custom = int(COMMUNITY.split(":")[1])

    # Advertise another route("6000::1") from AS 501 without community
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix=64)

    # Create four flows
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

    permit.rate.percentage = LINE_RATE
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = LINE_RATE
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_with_community.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = LINE_RATE
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = LINE_RATE
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    return config


def __bgp_community_route_map_config(duthost):
    """
    BGP Community Route MAP Config on duthost
    Args:
        duthost : duthost fixture
    """
    # Remove route_map if exists already
    remove_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'no neighbor LC501 route-map LA in' "
        "-c 'address-family ipv6 unicast' "
        "-c 'no neighbor LC501v6 route-map LAv6 in' "
        "-c 'neighbor LC501v6 route-map NEXTHOP in' "
        "-c 'no route-map LA' "
        "-c 'no route-map LAv6' "
    )
    remove_route_map %= (DUT_AS_NUM)
    duthost.shell(remove_route_map)

    community = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp community-list 10' "
    )
    try:
        duthost.shell(community)
    except Exception:
        pass

    # Configure route_map
    community_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'bgp community-list 10 permit 1:2' "
        "-c 'route-map LA permit 30' "
        "-c 'match community 10' "
        "-c 'route-map LAv6 permit 30' "
        "-c 'match community 10' "
    )
    duthost.shell(community_config)


def __tgen_bgp_prefix_list_config(config):
    """
    BGP Prefix Config on TGEN
    Args:
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Routes Config
    bgp501_rr1, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr1")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route("200.1.0.0")
    bgp501_rr1.addresses.bgpv4routeaddress(address="200.1.0.0",
                                           prefix=16)

    # Advertise another route("20.1.0.0")
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix=16)

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Routes Config
    bgp501v6_rr1, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr1")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route("4000::1")
    bgp501v6_rr1.addresses.bgpv6routeaddress(address="4000::1",
                                             prefix=64)

    # Advertise another route("6000::1")
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix=64)

    # Create four flows
    permit, deny, permit_ipv6, deny_ipv6 = (
        config.flows
        .flow(name='permit')
        .flow(name='deny')
        .flow(name='permit_ipv6')
        .flow(name='deny_ipv6')
    )

    permit.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    permit.tx_rx.device.rx_names = [bgp501_rr1.name]

    deny.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    permit.rate.percentage = LINE_RATE
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = LINE_RATE
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr1.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = LINE_RATE
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = LINE_RATE
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    return config


def __bgp_prefix_list_route_map_config(duthost):
    """
    BGP Prefix List Route MAP Config on duthost
    Args:
        duthost : duthost fixture
    """

    # Remove route_map if exists already
    remove_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'no neighbor LC501 route-map LA in' "
        "-c 'address-family ipv6 unicast' "
        "-c 'no neighbor LC501v6 route-map LAv6 in' "
        "-c 'neighbor LC501v6 route-map NEXTHOP in' "
        "-c 'no route-map LA' "
        "-c 'no route-map LAv6' "
    )
    remove_route_map %= (DUT_AS_NUM)
    duthost.shell(remove_route_map)

    # Configure route_map
    prefix_list_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no ip prefix-list PERMIT_IP' "
        "-c 'no ipv6 prefix-list PERMIT_IPV6' "
        "-c 'ip prefix-list PERMIT_IP permit 200.1.0.0/16' "
        "-c 'ipv6 prefix-list PERMIT_IPV6 permit 4000::1/64' "
        "-c 'route-map LA permit 30' "
        "-c 'match ip address prefix-list PERMIT_IP' "
        "-c 'route-map LAv6 permit 30' "
        "-c 'match ipv6 address prefix-list PERMIT_IPV6' "
    )
    duthost.shell(prefix_list_config)


def __tgen_bgp_metric_config(config):
    """
    BGP Metric config on TGEN
    Args:
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Routes Config
    bgp501_rr_metric_100, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_metric_100")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route("200.1.0.0") from AS 501 with metric/MED 100
    bgp501_rr_metric_100.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                     prefix=16)

    bgp501_rr_metric_100.advanced.multi_exit_discriminator = MED

    # Advertise another route("20.1.0.0")
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix=16)

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Routes Config
    bgp501v6_rr_metric_100, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_metric_100")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route("4000::1") from AS 501 with additional AS 100
    bgp501v6_rr_metric_100.addresses.bgpv6routeaddress(address="4000::1",
                                                       prefix=64)

    bgp501v6_rr_metric_100.advanced.multi_exit_discriminator = MED

    # Advertise another route("6000::1")
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix=64)

    # Create four flows
    permit, deny, permit_ipv6, deny_ipv6 = (
        config.flows
        .flow(name='permit')
        .flow(name='deny')
        .flow(name='permit_ipv6')
        .flow(name='deny_ipv6')
    )

    permit.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    permit.tx_rx.device.rx_names = [bgp501_rr_metric_100.name]

    deny.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    permit.rate.percentage = LINE_RATE
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = LINE_RATE
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_metric_100.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = LINE_RATE
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = LINE_RATE
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    return config


def __bgp_metric_route_map_config(duthost):
    """
    BGP Metric Route MAP Config on duthost
    Args:
        duthost : duthost fixture
    """
    # Remove route_map if exists already
    remove_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'no neighbor LC501 route-map LA in' "
        "-c 'address-family ipv6 unicast' "
        "-c 'no neighbor LC501v6 route-map LAv6 in' "
        "-c 'neighbor LC501v6 route-map NEXTHOP in' "
        "-c 'no route-map LA' "
        "-c 'no route-map LAv6' "
    )
    remove_route_map %= (DUT_AS_NUM)
    duthost.shell(remove_route_map)

    # Configure route_map
    metric_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'route-map LA permit 30' "
        "-c 'match metric 50' "
        "-c 'route-map LAv6 permit 30' "
        "-c 'match metric 50' "
    )
    duthost.shell(metric_config)


def __tgen_bgp_as_path_modified_config(config):
    """
    BGP group AS config on duthost and TGEN
    Args:
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Routes Config
    bgp501_rr_with_as_100, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_with_as_100")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route("200.1.0.0") from AS 501 with additional AS 100
    bgp501_rr_with_as_100.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                      prefix=16)

    as_path = bgp501_rr_with_as_100.as_path
    as_path_segment = as_path.as_path_segments.bgpaspathsegment()[-1]
    as_path_segment.segment_type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = GROUP_AS

    # Advertise another route("20.1.0.0")
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix=16)

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Routes Config
    bgp501v6_rr_with_as_100, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_with_as_100")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route("4000::1") from AS 501 with additional AS 100
    bgp501v6_rr_with_as_100.addresses.bgpv6routeaddress(address="4000::1",
                                                        prefix=64)

    as_path = bgp501v6_rr_with_as_100.as_path
    as_path_segment = as_path.as_path_segments.bgpaspathsegment()[-1]
    as_path_segment.segment_type = as_path_segment.AS_SEQ
    as_path_segment.as_numbers = GROUP_AS

    # Advertise another route("6000::1")
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix=64)

    # Create four flows
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

    permit.rate.percentage = LINE_RATE
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = LINE_RATE
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_with_as_100.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = LINE_RATE
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = LINE_RATE
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    return config


def __bgp_as_path_route_map_config(duthost):
    """
    BGP AS PATH Route MAP Config on duthost
    Args:
        duthost : duthost fixture
    """
    # Remove route_map if exists already
    remove_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'no neighbor LC501 route-map LA in' "
        "-c 'address-family ipv6 unicast' "
        "-c 'no neighbor LC501v6 route-map LAv6 in' "
        "-c 'neighbor LC501v6 route-map NEXTHOP in' "
        "-c 'no route-map LA' "
        "-c 'no route-map LAv6' "
    )
    remove_route_map %= (DUT_AS_NUM)
    duthost.shell(remove_route_map)

    remove_as_path = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp as-path access-list PERMIT_100' "
    )
    try:
        duthost.shell(remove_as_path)
    except Exception:
        pass

    # Configure route_map
    as_path_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'bgp as-path access-list PERMIT_100 permit 100' "
        "-c 'route-map LA permit 30' "
        "-c 'match as-path PERMIT_100' "
        "-c 'route-map LAv6 permit 30' "
        "-c 'match as-path PERMIT_100' "
    )
    duthost.shell(as_path_route_map)


def __tgen_bgp_origin_config(config):
    """
    BGP Origin config on TGEN
    Args:
        config : tgen config
    """

    bgp501 = config.devices[0].ethernet.ipv4.bgpv4

    # Routes Config
    bgp501_rr_origin_egp, bgp501_rr2 = (
        bgp501.bgpv4_routes
        .bgpv4route(name="bgp501_rr_origin_egp")
        .bgpv4route(name="bgp501_rr2")
    )

    # Advertise one route("200.1.0.0") from AS 501 with ORIGIN EGP
    bgp501_rr_origin_egp.addresses.bgpv4routeaddress(address="200.1.0.0",
                                                     prefix=16)

    bgp501_rr_origin_egp.advanced.origin = bgp501_rr_origin_egp.advanced.EGP

    # Advertise another route("20.1.0.0")
    bgp501_rr2.addresses.bgpv4routeaddress(address="20.1.0.0",
                                           prefix=16)

    # ipv6
    bgp501v6 = config.devices[0].ethernet.ipv6.bgpv6

    # Routes Config
    bgp501v6_rr_origin_egp, bgp501v6_rr2 = (
        bgp501v6.bgpv6_routes
        .bgpv6route(name="bgp501v6_rr_origin_egp")
        .bgpv6route(name="bgp501v6_rr2")
    )

    # Advertise one route("4000::1") from AS 501 with ORIGIN EGP
    bgp501v6_rr_origin_egp.addresses.bgpv6routeaddress(address="4000::1",
                                                       prefix=64)

    bgp501v6_rr_origin_egp.advanced.origin = (
        bgp501v6_rr_origin_egp.advanced.EGP)

    # Advertise another route("6000::1")
    bgp501v6_rr2.addresses.bgpv6routeaddress(address="6000::1",
                                             prefix=64)

    # Create four flows
    permit, deny, permit_ipv6, deny_ipv6 = (
        config.flows
        .flow(name='permit')
        .flow(name='deny')
        .flow(name='permit_ipv6')
        .flow(name='deny_ipv6')
    )

    permit.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    permit.tx_rx.device.rx_names = [bgp501_rr_origin_egp.name]

    deny.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv4.name]
    deny.tx_rx.device.rx_names = [bgp501_rr2.name]

    permit.rate.percentage = LINE_RATE
    permit.duration.fixed_packets.packets = PACKETS

    deny.rate.percentage = LINE_RATE
    deny.duration.fixed_packets.packets = PACKETS

    permit_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    permit_ipv6.tx_rx.device.rx_names = [bgp501v6_rr_origin_egp.name]

    deny_ipv6.tx_rx.device.tx_names = [config.devices[1].ethernet.ipv6.name]
    deny_ipv6.tx_rx.device.rx_names = [bgp501v6_rr2.name]

    permit_ipv6.rate.percentage = LINE_RATE
    permit_ipv6.duration.fixed_packets.packets = PACKETS

    deny_ipv6.rate.percentage = LINE_RATE
    deny_ipv6.duration.fixed_packets.packets = PACKETS

    return config


def __bgp_origin_route_map_config(duthost):
    """
    BGP Origin Route MAP Config on duthost
    Args:
        duthost : duthost fixture
    """

    # Remove route_map if exists already
    remove_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'no neighbor LC501 route-map LA in' "
        "-c 'address-family ipv6 unicast' "
        "-c 'no neighbor LC501v6 route-map LAv6 in' "
        "-c 'neighbor LC501v6 route-map NEXTHOP in' "
        "-c 'no route-map LA' "
        "-c 'no route-map LAv6' "
    )
    remove_route_map %= (DUT_AS_NUM)
    duthost.shell(remove_route_map)

    # Configure route_map
    origin_route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'route-map LA permit 30' "
        "-c 'match origin egp' "
        "-c 'route-map LAv6 permit 30' "
        "-c 'match origin egp' "
    )
    duthost.shell(origin_route_map)


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
    logger.info("|--Apply TGEN Config--|")
    snappi_api.set_config(config)

    # Start traffic
    logger.info("|--Start Traffic--|")
    ts = snappi_api.transmit_state()
    ts.state = ts.START
    snappi_api.set_transmit_state(ts)

    # Check there is no loss for 'permit', 'permit_ipv6', 'deny' & deny_ipv6
    logger.info(
        "|--Asserting No Loss For All Flows Before Applying Route-Map--|")
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_no_loss(snappi_api,
                                              ['permit', 'permit_ipv6',
                                               'deny', 'deny_ipv6'],
                                              PACKETS * 4)),
                  'No loss expected')

    logger.info("|--Apply Route-Map--|")
    # Apply route-map to permit only expected routes
    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor LC501 route-map LA in' "
        "-c 'address-family ipv6 unicast' "
        "-c 'neighbor LC501v6 route-map LAv6 in' "
    )
    route_map %= (DUT_AS_NUM)
    duthost.shell(route_map)

    # Start traffic
    logger.info("|--Start Traffic--|")
    ts = snappi_api.transmit_state()
    ts.state = ts.START
    snappi_api.set_transmit_state(ts)

    # Check there is no traffic loss for 'permit' and 'permit_ipv6' flow
    logger.info(
        "|--Assert No Loss For Flows With Permit--|")
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_no_loss(snappi_api,
                                              ['permit', 'permit_ipv6'],
                                              PACKETS * 2)),
                  'No loss expected')

    # Check 100% traffic loss for 'deny'  and 'deny_ipv6' flow
    logger.info(
        "|--Assert 100 Percent Loss For Flows Without Permit--|")
    pytest_assert(wait_until(60, 2,
                  lambda: __check_for_total_loss(
                      snappi_api, ['deny', 'deny_ipv6'])),
                  'total loss expected')

    # Stop traffic
    logger.info("|--Stopping Traffic After Test--|")
    ts = snappi_api.transmit_state()
    ts.state = ts.STOP
    snappi_api.set_transmit_state(ts)


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


def config_cleanup(duthost,
                   tgen_ports):

    # Remove bgp neighbor config
    bgp_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no router bgp' "
    )
    duthost.shell(bgp_config)

    # Remove any leftover config if not removed
    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp community-list 10' "
    )
    try:
        duthost.shell(route_map)
    except Exception:
        pass

    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no bgp as-path access-list PERMIT_100' "
    )
    try:
        duthost.shell(route_map)
    except Exception:
        pass

    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no ip prefix-list PERMIT_IP' "
    )
    try:
        duthost.shell(route_map)
    except Exception:
        pass

    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no ipv6 prefix-list PERMIT_IPV6' "
    )
    try:
        duthost.shell(route_map)
    except Exception:
        pass

    route_map = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no route-map LA permit 30' "
        "-c 'no route-map LAv6 permit 30' "
    )
    try:
        duthost.shell(route_map)
    except Exception:
        pass

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
                     tgen_ports[1]['peer_ipv6'],
                     tgen_ports[1]['ipv6_prefix'])
    duthost.shell(intf2_config)

