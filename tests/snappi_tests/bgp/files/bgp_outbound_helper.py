import logging
import random
import paramiko
import time
import math
import os
from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from statistics import mean
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.utilities import (wait, wait_until)  # noqa: F401
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import create_ip_list  # noqa: F401
# Unified topology imports
from tests.snappi_tests.variables import (
    AS_PATHS, BGP_TYPE, SNAPPI_TRIGGER, DUT_TRIGGER, DUT_TRIGGER_SHORT, FANOUT_PRESENCE,
    NUM_REGIONAL_HUBS,
    COMMUNITY_LOWER_TIER_LEAK, COMMUNITY_LOWER_TIER_DROP, COMMUNITY_UPPER_TIER,
    V4_PREFIX_LENGTH, V6_PREFIX_LENGTH,
    detect_topology_and_vendor,
    get_lower_tier_info,
    get_uplink_fanout_info, get_uplink_portchannel_members,
    get_as_numbers, get_bgp_ips_for_topology,
)

logger = logging.getLogger(__name__)
total_routes = 0
fanout_uplink_snappi_info = []


def get_topology_and_vendor(hostnames):
    """
    Detect topology type and vendor from DUT hostnames.
    Wrapper around variables.detect_topology_and_vendor.

    Args:
        hostnames (list): List of DUT hostnames

    Returns:
        tuple: (topology_type, vendor) - e.g., ('T2_CHASSIS', 'NOKIA')
    """
    logger.info("DUT Hostnames: {}".format(hostnames))
    topology_type, vendor = detect_topology_and_vendor(hostnames)
    logger.info("Detected topology: {}, vendor: {}".format(topology_type, vendor))
    return topology_type, vendor


def get_ip_lists_for_topology(topology_type, vendor):
    """
    Get IP address lists based on topology type and vendor.
    Uses the unified get_bgp_ips_for_topology function.

    Args:
        topology_type (str): TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor (str): 'NOKIA', 'ARISTA', or 'CISCO'

    Returns:
        dict: Dictionary containing all IP lists for the topology
    """
    bgp_ips = get_bgp_ips_for_topology(topology_type, vendor)
    return {
        'lower_tier_dut_ipv4': bgp_ips['dut_ipv4_list'],
        'lower_tier_snappi_ipv4': bgp_ips['snappi_ipv4_list'],
        'lower_tier_dut_ipv6': bgp_ips['dut_ipv6_list'],
        'lower_tier_snappi_ipv6': bgp_ips['snappi_ipv6_list'],
        'portchannel_dut_ipv4': bgp_ips['dut_portchannel_ipv4_list'],
        'portchannel_snappi_ipv4': bgp_ips['snappi_portchannel_ipv4_list'],
        'portchannel_dut_ipv6': bgp_ips['dut_portchannel_ipv6_list'],
        'portchannel_snappi_ipv6': bgp_ips['snappi_portchannel_ipv6_list'],
        'router_ids': bgp_ips['router_ids'],
    }


def get_as_numbers_for_topology():
    """
    Get AS numbers for topology (unified for both topologies).

    Returns:
        dict: Dictionary containing AS numbers
    """
    as_nums = get_as_numbers()
    return {
        'backup_t2_snappi_as': as_nums['backup_t2_snappi_as'],
        'lower_tier_dut_as': as_nums['lower_tier_dut_as'],
        'upper_tier_snappi_as': as_nums['upper_tier_snappi_as'],
        'dut_as': as_nums['dut_as'],
    }


def run_bgp_outbound_uplink_blackout_test(api,
                                          snappi_extra_params,
                                          creds, record_property):
    """
    Run outbound test for uplink blackout with multiple blackout percentages.
    Supports running multiple blackout scenarios (e.g., 100% and 50%) in a single
    setup/teardown cycle for efficiency.

    Args:
        api (pytest fixture): snappi API
        creds (dict): DUT credentials
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
            - BLACKOUT_PERCENTAGES: list of blackout percentages to test (e.g., [100, 50])
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    # Build unique duthosts list, filtering None values
    duthosts = list({dut for dut in [duthost1, duthost2] if dut is not None})
    t1_hostname = snappi_extra_params.multi_dut_params.t1_hostname
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    blackout_percentages = snappi_extra_params.multi_dut_params.BLACKOUT_PERCENTAGES
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    # Detect topology type and vendor
    topology_type, vendor = get_topology_and_vendor([dut.hostname for dut in duthosts if dut])

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                t1_hostname,
                                                duthosts,
                                                topology_type,
                                                vendor,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_blackout(duthosts,
                                     topology_type,
                                     vendor,
                                     api,
                                     snappi_bgp_config,
                                     traffic_type,
                                     iteration,
                                     blackout_percentages,
                                     route_range,
                                     test_name,
                                     creds, record_property)


def run_bgp_outbound_tsa_tsb_test(api,
                                  snappi_extra_params,
                                  creds,
                                  is_supervisor,
                                  record_property):
    """
    Run outbound test with TSA TSB on the dut

    Args:
        api (pytest fixture): snappi API
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    # Build unique duthosts list, filtering None values
    duthosts = list({dut for dut in [duthost1, duthost2, duthost3] if dut is not None})
    t1_hostname = snappi_extra_params.multi_dut_params.t1_hostname
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    device_name = snappi_extra_params.device_name
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    # Detect topology type and vendor
    topology_type, vendor = get_topology_and_vendor([dut.hostname for dut in duthosts if dut])

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                t1_hostname,
                                                duthosts,
                                                topology_type,
                                                vendor,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_tsa_tsb(duthosts,
                                    topology_type,
                                    vendor,
                                    api,
                                    snappi_bgp_config,
                                    traffic_type,
                                    iteration,
                                    device_name,
                                    route_range,
                                    test_name,
                                    creds,
                                    is_supervisor,
                                    record_property=record_property)


def run_bgp_outbound_ungraceful_restart(api,
                                        creds,
                                        is_supervisor,
                                        snappi_extra_params,
                                        record_property):
    """
    Run outbound test with ungraceful restart on the dut
    Args:
        api (pytest fixture): snappi API
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    # Build unique duthosts list, filtering None values
    duthosts = list({dut for dut in [duthost1, duthost2, duthost3] if dut is not None})
    t1_hostname = snappi_extra_params.multi_dut_params.t1_hostname
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    device_name = snappi_extra_params.device_name
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    # Detect topology type and vendor
    topology_type, vendor = get_topology_and_vendor([dut.hostname for dut in duthosts if dut])

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                t1_hostname,
                                                duthosts,
                                                topology_type,
                                                vendor,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_ungraceful_restart(duthosts,
                                               topology_type,
                                               vendor,
                                               api,
                                               snappi_bgp_config,
                                               traffic_type,
                                               iteration,
                                               device_name,
                                               route_range,
                                               test_name,
                                               creds,
                                               is_supervisor,
                                               record_property)


def run_bgp_outbound_process_restart_test(api,
                                          creds,
                                          snappi_extra_params,
                                          record_property):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        creds (dict): DUT credentials
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    # Build unique duthosts list, filtering None values
    duthosts = list({dut for dut in [duthost1, duthost2] if dut is not None})
    t1_hostname = snappi_extra_params.multi_dut_params.t1_hostname
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    process_names = snappi_extra_params.multi_dut_params.process_names
    host_name = snappi_extra_params.multi_dut_params.host_name
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    # Detect topology type and vendor
    topology_type, vendor = get_topology_and_vendor([dut.hostname for dut in duthosts if dut])

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                t1_hostname,
                                                duthosts,
                                                topology_type,
                                                vendor,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_process_crash(duthosts,
                                          topology_type,
                                          vendor,
                                          api,
                                          snappi_bgp_config,
                                          traffic_type,
                                          iteration,
                                          process_names,
                                          host_name,
                                          route_range,
                                          test_name,
                                          creds,
                                          record_property)


def run_bgp_outbound_link_flap_test(api,
                                    creds,
                                    snappi_extra_params,
                                    record_property):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa: F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    # Build unique duthosts list, filtering None values
    duthosts = list({dut for dut in [duthost1, duthost2] if dut is not None})
    t1_hostname = snappi_extra_params.multi_dut_params.t1_hostname
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    iteration = snappi_extra_params.iteration
    flap_details = snappi_extra_params.multi_dut_params.flap_details
    test_name = snappi_extra_params.test_name

    # Detect topology type and vendor
    topology_type, vendor = get_topology_and_vendor([dut.hostname for dut in duthosts if dut])

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                t1_hostname,
                                                duthosts,
                                                topology_type,
                                                vendor,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_link_flap(duthosts,
                                      t1_hostname,
                                      topology_type,
                                      vendor,
                                      api,
                                      snappi_bgp_config,
                                      flap_details,
                                      traffic_type,
                                      iteration,
                                      route_range,
                                      test_name,
                                      creds, record_property)


def generate_mac_address():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def __snappi_bgp_config(api,
                        t1_hostname,
                        duthosts,
                        topology_type,
                        vendor,
                        snappi_ports,
                        traffic_type,
                        route_range):
    """
    Creating  BGP config on TGEN

    Args:
        api (pytest fixture): snappi API
        duthosts(pytest fixture): duthosts fixture
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'
        snappi_ports : Snappi port list
        traffic_type: IPv4 or IPv6 traffic
        route_range: v4 and v6 route combination
    """
    global fanout_uplink_snappi_info
    ipv4_src, ipv6_src = [], []
    ipv4_dest, ipv6_dest = [], []
    global total_routes
    total_routes = 0
    config = api.config()

    # Get topology-aware variables using unified accessor functions
    lower_tier_info = get_lower_tier_info(topology_type, vendor)
    t1_variable_ports = lower_tier_info.get('ports', [])
    uplink_portchannel_members = get_uplink_portchannel_members(topology_type, vendor)
    ip_lists = get_ip_lists_for_topology(topology_type, vendor)
    as_numbers = get_as_numbers_for_topology()

    t2_variable_ports = []
    port_tuple = []
    rh_portchannels = [f"PortChannel{i}" for i in range(NUM_REGIONAL_HUBS)]

    for asic_value, portchannel_info in uplink_portchannel_members.items():
        for portchannel, ports in portchannel_info.items():
            port_tuple.append((portchannel, ports))
            for port in ports:
                t2_variable_ports.append(port)
    snappi_t1_ports = []
    snappi_t2_ports = []
    for snappi_port in snappi_ports:
        for port in t1_variable_ports:
            if snappi_port['peer_device'] == t1_hostname and snappi_port['peer_port'] == port:
                snappi_t1_ports.append(snappi_port)
        for port in t2_variable_ports:
            if snappi_port['peer_device'] == duthosts[0].hostname and snappi_port['peer_port'] == port:
                snappi_t2_ports.append(snappi_port)

    # Adding Ports
    for index, snappi_test_port in enumerate(snappi_t1_ports):
        if index == 0:
            snappi_test_port['name'] = 'Snappi_Tx_Port'
        else:
            snappi_test_port['name'] = 'Snappi_Backup_T2_%d' % index
        config.ports.port(name=snappi_test_port['name'], location=snappi_test_port['location'])
    for _, snappi_test_port in enumerate(snappi_t2_ports):
        po = 1
        for asic_value, portchannel_info in uplink_portchannel_members.items():
            for portchannel, portchannel_members in portchannel_info.items():
                for index, mem_port in enumerate(portchannel_members, 1):
                    if snappi_test_port['peer_port'] == mem_port and \
                       snappi_test_port['peer_device'] == duthosts[0].hostname:
                        snappi_test_port['name'] = 'Snappi_Uplink_PO_{}_Link_{}'.format(po, index)
                        fanout_uplink_snappi_info.append(snappi_test_port)
                        config.ports.port(name=snappi_test_port['name'], location=snappi_test_port['location'])
                    else:
                        continue
                po = po + 1
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
    for lag_count, (portchannel_name, port_set) in enumerate(port_tuple):
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

        device = config.devices.device(name="T3 Device {}".format(lag_count))[-1]
        eth = device.ethernets.add()
        eth.connection.port_name = lag.name
        eth.name = 'T3_Ethernet_%d' % lag_count
        eth.mac = "00:00:00:00:00:%s" % m

        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T3_IPv4_%d' % lag_count
        ipv4.address = ip_lists['portchannel_snappi_ipv4'][lag_count]
        ipv4.gateway = ip_lists['portchannel_dut_ipv4'][lag_count]
        ipv4.prefix = V4_PREFIX_LENGTH
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T3_IPv6_%d' % lag_count
        ipv6.address = ip_lists['portchannel_snappi_ipv6'][lag_count]
        ipv6.gateway = ip_lists['portchannel_dut_ipv6'][lag_count]
        ipv6.prefix = V6_PREFIX_LENGTH

        bgpv4 = device.bgp
        bgpv4.router_id = ip_lists['portchannel_dut_ipv4'][lag_count]
        bgpv4_int = bgpv4.ipv4_interfaces.add()
        bgpv4_int.ipv4_name = ipv4.name
        bgpv4_peer = bgpv4_int.peers.add()
        bgpv4_peer.name = 'T3_BGP_%d' % lag_count
        bgpv4_peer.as_type = BGP_TYPE
        bgpv4_peer.peer_address = ip_lists['portchannel_dut_ipv4'][lag_count]
        bgpv4_peer.as_number = int(as_numbers['upper_tier_snappi_as'])

        route_range1 = bgpv4_peer.v4_routes.add(name="AH_IPv4_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv4']):
            route_range1.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])
        ipv4_dest.append(route_range1.name)

        if portchannel_name in rh_portchannels:
            default_ipv4_route_range = bgpv4_peer.v4_routes.add(name="RH_Def_IPv4_Routes_%d" % (lag_count))
            non_default_ipv4_route_range = bgpv4_peer.v4_routes.add(name="RH_NoDef_IPv4_Routes_%d" % (lag_count))
            default_ipv4_route_range.addresses.add(
                    address="0.0.0.0", prefix=0, count=1)
            non_default_ipv4_route_range.addresses.add(
                    address="80.1.1.1", prefix=22, count=4000)
            ipv4_dest.append(non_default_ipv4_route_range.name)

        for community in COMMUNITY_UPPER_TIER:
            manual_as_community = non_default_ipv4_route_range.communities.add()
            manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
            manual_as_community.as_number = int(community.split(":")[0])
            manual_as_community.as_custom = int(community.split(":")[1])

        bgpv6 = device.bgp
        bgpv6.router_id = ip_lists['portchannel_dut_ipv4'][lag_count]
        bgpv6_int = bgpv6.ipv6_interfaces.add()
        bgpv6_int.ipv6_name = ipv6.name
        bgpv6_peer = bgpv6_int.peers.add()
        bgpv6_peer.name = 'T3_BGP+_%d' % lag_count
        bgpv6_peer.as_type = BGP_TYPE
        bgpv6_peer.peer_address = ip_lists['portchannel_dut_ipv6'][lag_count]
        bgpv6_peer.as_number = int(as_numbers['upper_tier_snappi_as'])

        route_range2 = bgpv6_peer.v6_routes.add(name="AH_IPv6_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv6']):
            route_range2.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])

        # Add AH Routes
        ipv6_dest.append(route_range2.name)

        if portchannel_name in rh_portchannels:
            default_ipv6_route_range = bgpv6_peer.v6_routes.add(name="RH_Def_IPv6_Routes_%d" % (lag_count))
            default_ipv6_route_range.addresses.add(address="::", prefix=0, count=1)
            non_default_ipv6_route_range = bgpv6_peer.v6_routes.add(name="RH_NoDef_IPv6_Routes_%d" % (lag_count))
            non_default_ipv6_route_range.addresses.add(address="3000::1", prefix=80, count=1000)
            # Add RH non default
            ipv6_dest.append(non_default_ipv6_route_range.name)
        for community in COMMUNITY_UPPER_TIER:
            manual_as_community = non_default_ipv6_route_range.communities.add()
            manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
            manual_as_community.as_number = int(community.split(":")[0])
            manual_as_community.as_custom = int(community.split(":")[1])

    for index, port in enumerate(snappi_t1_ports):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        if index == 0:
            device = config.devices.device(name="T0 Device {}".format(index))[-1]
            eth = device.ethernets.add()
            eth.connection.port_name = port['name']
            eth.name = 'T0_Ethernet_%d' % index
            eth.mac = "00:10:00:00:00:%s" % m
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'T0_IPv4_%d' % index
            ipv4.address = ip_lists['lower_tier_snappi_ipv4'][index]
            ipv4.gateway = ip_lists['lower_tier_dut_ipv4'][index]
            ipv4.prefix = V4_PREFIX_LENGTH
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'T0_IPv6_%d' % index
            ipv6.address = ip_lists['lower_tier_snappi_ipv6'][index]
            ipv6.gateway = ip_lists['lower_tier_dut_ipv6'][index]
            ipv6.prefix = V6_PREFIX_LENGTH
            ipv4_src.append(ipv4.name)
            ipv6_src.append(ipv6.name)
        else:
            device = config.devices.device(name="Backup T2 Device {}".format(index))[-1]
            eth = device.ethernets.add()
            eth.connection.port_name = port['name']
            eth.name = 'Backup_T2_Ethernet_%d' % index
            eth.mac = "00:10:00:00:00:%s" % m
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'Backup_T2_IPv4_%d' % index
            ipv4.address = ip_lists['lower_tier_snappi_ipv4'][index]
            ipv4.gateway = ip_lists['lower_tier_dut_ipv4'][index]
            ipv4.prefix = V4_PREFIX_LENGTH
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'Backup_T2_IPv6_%d' % index
            ipv6.address = ip_lists['lower_tier_snappi_ipv6'][index]
            ipv6.gateway = ip_lists['lower_tier_dut_ipv6'][index]
            ipv6.prefix = V6_PREFIX_LENGTH

            bgpv4 = device.bgp
            bgpv4.router_id = ip_lists['lower_tier_snappi_ipv4'][index]
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'Backup_T2_BGP_%d' % index
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = ip_lists['lower_tier_dut_ipv4'][index]
            bgpv4_peer.as_number = int(as_numbers['backup_t2_snappi_as'])

            if 'IPv4' in route_range.keys():
                route_range1 = bgpv4_peer.v4_routes.add(name="Backup_T2_IPv4_Routes_%d" % (index))
                for route_index, routes in enumerate(route_range['IPv4']):
                    route_range1.addresses.add(
                        address=routes[0], prefix=routes[1], count=routes[2])

                    for community in COMMUNITY_LOWER_TIER_DROP:
                        manual_as_community = route_range1.communities.add()
                        manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
                        manual_as_community.as_number = int(community.split(":")[0])
                        manual_as_community.as_custom = int(community.split(":")[1])
                ipv4_dest.append(route_range1.name)

                default_ipv4_route_range = bgpv4_peer.v4_routes.add(name="Backup_T2_Def_IPv4_Routes_%d" % (index))
                non_default_ipv4_route_range = bgpv4_peer.v4_routes.add(name="BackupT2_NoDef_IPv4_Routes_%d" % (index))
                default_ipv4_route_range.addresses.add(address="0.0.0.0", prefix=0, count=1)
                non_default_ipv4_route_range.addresses.add(address="80.1.1.1", prefix=22, count=4000)
                ipv4_dest.append(non_default_ipv4_route_range.name)

                for rh_v4_route_range in [default_ipv4_route_range, non_default_ipv4_route_range]:
                    as_path = rh_v4_route_range.as_path
                    as_path_segment = as_path.segments.add()
                    as_path_segment.type = as_path_segment.AS_SEQ
                    as_path_segment.as_numbers = AS_PATHS
                    for community in COMMUNITY_LOWER_TIER_LEAK:
                        manual_as_community = rh_v4_route_range.communities.add()
                        manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
                        manual_as_community.as_number = int(community.split(":")[0])
                        manual_as_community.as_custom = int(community.split(":")[1])

            bgpv6 = device.bgp
            bgpv6.router_id = ip_lists['lower_tier_snappi_ipv4'][index]
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'Backup_T2_BGP+_%d' % index
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = ip_lists['lower_tier_dut_ipv6'][index]
            bgpv6_peer.as_number = int(as_numbers['backup_t2_snappi_as'])

            if 'IPv6' in route_range.keys():
                route_range2 = bgpv6_peer.v6_routes.add(name="Backup_T2_IPv6_Routes_%d" % (index))
                for route_index, routes in enumerate(route_range['IPv6']):
                    route_range2.addresses.add(
                        address=routes[0], prefix=routes[1], count=routes[2])
                ipv6_dest.append(route_range2.name)

                for community in COMMUNITY_LOWER_TIER_DROP:
                    manual_as_community = route_range2.communities.add()
                    manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
                    manual_as_community.as_number = int(community.split(":")[0])
                    manual_as_community.as_custom = int(community.split(":")[1])

                default_ipv6_route_range = bgpv6_peer.v6_routes.add(name="Backup_T2_Def_IPv6_Routes_%d" % (index))
                default_ipv6_route_range.addresses.add(address="::", prefix=0, count=1)
                non_default_ipv6_route_range = bgpv6_peer.v6_routes.add(name="Backup_T2_NoDef_IPv6_Routes_%d" % (index))
                non_default_ipv6_route_range.addresses.add(address="3000::1", prefix=80, count=1000)
                ipv6_dest.append(non_default_ipv6_route_range.name)

                for rh_v6_route_range in [default_ipv6_route_range, non_default_ipv6_route_range]:
                    as_path = rh_v6_route_range.as_path
                    as_path_segment = as_path.segments.add()
                    as_path_segment.type = as_path_segment.AS_SEQ
                    as_path_segment.as_numbers = AS_PATHS
                    for community in COMMUNITY_LOWER_TIER_LEAK:
                        manual_as_community = rh_v6_route_range.communities.add()
                        manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
                        manual_as_community.as_number = int(community.split(":")[0])
                        manual_as_community.as_custom = int(community.split(":")[1])

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

    if 'IPv4' in traffic_type and 'IPv6' in traffic_type:
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]

        createTrafficItem("IPv4_Traffic", [ipv4_src[0]], ipv4_dest)
        createTrafficItem("IPv6_Traffic", [ipv6_src[0]], ipv6_dest)
    elif 'IPv6' in traffic_type and 'IPv4' not in traffic_type:
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv6 Traffic", [ipv6_src[0]], ipv6_dest)
    elif 'IPv4' in traffic_type and 'IPv6' not in traffic_type:
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4 Traffic", [ipv4_src[0]], ipv4_dest)
    return config


def get_flow_stats(api):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    request = api.metrics_request()
    request.flow.flow_names = []
    return api.get_metrics(request).flow_metrics


def get_port_stats(api):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    request = api.metrics_request()
    return api.get_metrics(request).port_metrics


def flap_dut_port(creds, dut_ip, dut_port, state):
    """
    Flaps the specified T1 DUT port by bringing it up or down.

    Args:
        creds (dict): DUT credentials'.
        dut_ip (str): IP address of the DUT.
        dut_port (str): Name of the port to be flapped.
        state (str): Desired state of the port ('up' or 'down').

    Returns:
        bool: True if the command executed successfully, False otherwise.
    """
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(dut_ip, port=22, username=username, password=password, timeout=10)
        command = f'sudo config interface {"startup" if state == "up" else "shutdown"} {dut_port}'

        stdin, stdout, stderr = ssh.exec_command(command)
        stdout_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode().strip()

        if stderr_output:
            logger.error(f"Error executing command on {dut_ip}: {stderr_output}")
            return False

        logger.info(f"Command executed successfully: {stdout_output}")
        return True

    except paramiko.SSHException as e:
        logger.error(f"SSH connection error: {e}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False

    finally:
        ssh.close()


def get_convergence_for_link_flap(duthosts,
                                  t1_hostname,
                                  topology_type,
                                  vendor,
                                  api,
                                  bgp_config,
                                  flap_details,
                                  traffic_type,
                                  iteration,
                                  route_range,
                                  test_name,
                                  creds,
                                  record_property):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        flap_details: contains device name and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        test_name: Name of the test
        creds (pytest fixture): DUT credentials
    """
    # Get IP lists for router_ids and portchannel_count
    ip_lists = get_ip_lists_for_topology(topology_type, vendor)
    from tests.snappi_tests.variables import get_portchannel_count as get_pc_count
    pc_count = get_pc_count(topology_type, vendor)

    api.set_config(bgp_config)
    avg_pld = []
    avg_pld2 = []
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(ip_lists['router_ids'][index])
            device_name = topology.DeviceGroup.find()[0].Name
            logger.info('Setting Router id {} for {}'.format(ip_lists['router_ids'][index], device_name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    for i in range(0, iteration):
        logger.info(
            '|--------------------------- Iteration : {} -----------------------|'.format(i+1))
        logger.info("Starting all protocols ...")
        cs = api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        api.set_control_state(cs)

        wait(SNAPPI_TRIGGER, "For Protocols To start")
        logger.info('Verifying protocol sessions state')
        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
        protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)

        # NOTE: we sleep 60 seconds to make sure DUT is ready before receiving traffic, avoiding traffic lost
        time.sleep(60)

        logger.info('Starting Traffic')

        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        api.set_control_state(cs)

        wait(SNAPPI_TRIGGER, "For Traffic To start")

        flow_stats = get_flow_stats(api)
        port_stats = get_port_stats(api)
        logger.info('\n')
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
        logger.info('\n')
        for i in range(0, len(traffic_type)):
            logger.info('{} Loss %: {}'.format(flow_stats[i].name, int(flow_stats[i].loss)))
            pytest_assert(int(flow_stats[i].loss) == 0, f'Loss Observed in {flow_stats[i].name} before link Flap')

        sum_t2_rx_frame_rate = 0
        for port_stat in port_stats:
            if 'Snappi_Uplink' in port_stat.name:
                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)
        # Flap the required test port
        if t1_hostname == flap_details['device_name']:
            logger.info(' Shutting down {} port of {} dut({}) !!'.
                        format(flap_details['port_name'], flap_details['device_name'], flap_details['device_ip']))
            flap_dut_port(creds, flap_details['device_ip'], flap_details['port_name'], state='down')
            wait(DUT_TRIGGER, "For link to shutdown")
        elif 'Ixia' == flap_details['device_name']:
            if FANOUT_PRESENCE is False:
                ixn_port = ixnetwork.Vport.find(Name=flap_details['port_name'])[0]
                ixn_port.LinkUpDn("down")
                logger.info('Shutting down snappi port : {}'.format(flap_details['port_name']))
                wait(SNAPPI_TRIGGER, "For link to shutdown")
            else:
                # Find the uplink fanout port corresponding to this Ixia port
                uplink_fanout_port = None
                for port in fanout_uplink_snappi_info:
                    if flap_details['port_name'] == port['name']:
                        uplink_fanout_port = port['peer_port']
                        break
                pytest_assert(uplink_fanout_port is not None,
                              f"Unable to find uplink port for {flap_details['port_name']}")

                # Get topology-aware fanout info
                fanout_info = get_uplink_fanout_info(topology_type, vendor)
                pytest_assert(fanout_info, f'No fanout info found for {vendor} / {topology_type}')
                fanout_ip = fanout_info['fanout_ip']
                fanout_port = None
                for port_mapping in fanout_info['port_mapping']:
                    if uplink_fanout_port == port_mapping['uplink_port']:
                        fanout_port = port_mapping['fanout_port']
                        break

                pytest_assert(fanout_port is not None,
                              f'Unable to find fanout port for uplink {uplink_fanout_port}')
                flap_dut_port(creds, fanout_ip, fanout_port, state='down')
                logger.info(' Shutting down {} from {}'.format(fanout_port, fanout_ip))
                wait(DUT_TRIGGER, "For link to shutdown")
        flow_stats = get_flow_stats(api)
        for i in range(0, len(traffic_type)):
            pytest_assert(float((int(flow_stats[i].frames_tx_rate) - int(flow_stats[i].frames_rx_rate)) /
                          int(flow_stats[i].frames_tx_rate)) < 0.005,
                          'Traffic has not converged after link flap')
        logger.info('Traffic has converged after link flap')

        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION  After Link Down (ms): {}'.format(pkt_loss_duration))
        avg_pld.append(pkt_loss_duration)

        logger.info('Performing Clear Stats')
        ixnetwork.ClearStats()
        if t1_hostname == flap_details['device_name']:
            logger.info(' Starting up {} port of {} dut({}) !!'.
                        format(flap_details['port_name'], flap_details['device_name'], flap_details['device_ip']))
            flap_dut_port(creds, flap_details['device_ip'], flap_details['port_name'], state='up')
            wait(DUT_TRIGGER, "For link to startup")
        elif 'Ixia' == flap_details['device_name']:
            if FANOUT_PRESENCE is False:
                ixn_port = ixnetwork.Vport.find(Name=flap_details['port_name'])[0]
                ixn_port.LinkUpDn("up")
                logger.info('Starting up snappi port : {}'.format(flap_details['port_name']))
                wait(SNAPPI_TRIGGER, "For link to startup")
            else:
                # Recalculate fanout info for link-up (same logic as link-down)
                uplink_fanout_port = None
                for port in fanout_uplink_snappi_info:
                    if flap_details['port_name'] == port['name']:
                        uplink_fanout_port = port['peer_port']
                        break
                fanout_info = get_uplink_fanout_info(topology_type, vendor)
                fanout_ip = fanout_info['fanout_ip']
                fanout_port = None
                for port_mapping in fanout_info['port_mapping']:
                    if uplink_fanout_port == port_mapping['uplink_port']:
                        fanout_port = port_mapping['fanout_port']
                        break
                flap_dut_port(creds, fanout_ip, fanout_port, state='up')
                logger.info('Starting up {} from {}'.format(fanout_port, fanout_ip))
                wait(DUT_TRIGGER, "For link to startup")
        logger.info('\n')
        port_stats = get_port_stats(api)
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))

        flow_stats = get_flow_stats(api)
        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION After Link Up (ms): {}'.format(pkt_loss_duration))
        avg_pld2.append(pkt_loss_duration)
        logger.info('Stopping Traffic')

        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        api.set_control_state(cs)

        logger.info("Stopping all protocols ...")
        cs = api.control_state()
        cs.protocol.all.state = cs.protocol.all.STOP
        api.set_control_state(cs)

        logger.info('\n')

    convergence_result = [
        {
            "Test Name": f"{test_name} (link down)",
            "Iteration": iteration,
            "Traffic Type": traffic_type,
            "Uplink ECMP Paths": pc_count,
            "Route Count": total_routes,
            "Avg Calculated Packet Loss Duration (ms)": avg_pld
        },
        {
            "Test Name": f"{test_name} (link up)",
            "Iteration": iteration,
            "Traffic Type": traffic_type,
            "Uplink ECMP Paths": pc_count,
            "Route Count": total_routes,
            "Avg Calculated Packet Loss Duration (ms)": avg_pld2
        }
    ]

    record_property("convergence_result", convergence_result)


def kill_process_inside_container(duthost, container_name, process_id, creds):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        process_id: process id that needs to be killed inside container
        creds (dict): DUT credentials
    """
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')
    ip = duthost.mgmt_ip
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port=22, username=username, password=password)
    command = f'docker exec {container_name} kill {process_id}'
    stdin, stdout, stderr = ssh.exec_command(command)


def get_container_names(duthost):
    """
    Args:
        duthost (pytest fixture): duthost fixture
    """
    container_names = duthost.shell('docker ps --format \{\{.Names\}\}')['stdout_lines']   # noqa: W605
    return container_names


def check_container_status_up(duthost, container_name, timeout):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        timeout(secs): Maximum time limit for polling
    """
    start_time = time.time()
    while True:
        running_containers_list = get_container_names(duthost)
        if container_name in running_containers_list:
            logger.info('PASS: {} is RUNNING after process kill'.format(container_name))
            break
        logger.info('Polling for {} to come UP.....'.format(container_name))
        elapsed_time = time.time() - start_time
        pytest_assert(elapsed_time < timeout, "Container did not come up in {} \
                      seconds after process kill".format(timeout))
        time.sleep(5)


def check_container_status_down(duthost, container_name, timeout):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        timeout(secs): Maximum time limit for polling
    """
    start_time = time.time()
    while True:
        running_containers_list = get_container_names(duthost)
        if container_name not in running_containers_list:
            logger.info('PASS: {} is DOWN after process kill'.format(container_name))
            break
        logger.info('Polling for {} to go Down.....'.format(container_name))
        elapsed_time = time.time() - start_time
        pytest_assert(elapsed_time < timeout, "Container is still running for {} \
                      seconds after process kill".format(timeout))
        time.sleep(5)


def get_container_names_from_asic_count(duthost, container_name):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
    """
    container_names = []
    platform_summary = duthost.shell('show platform summary')['stdout_lines']
    for line in platform_summary:
        if 'ASIC Count' in line:
            count = int(line.split(':')[-1].lstrip())
    if count == 1:
        container_names.append(container_name)
    else:
        for i in range(0, count):
            container_names.append(container_name+str(i))

    return container_names


def get_convergence_for_process_crash(duthosts,
                                      topology_type,
                                      vendor,
                                      api,
                                      bgp_config,
                                      traffic_type,
                                      iteration,
                                      process_names,
                                      host_name,
                                      route_range,
                                      test_name,
                                      creds,
                                      record_property):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        process_names : Name of the container in which specific process needs to be killed
        host_name : Dut hostname
        test_name: Name of the test
        creds (dict): DUT credentials
    """
    # Get IP lists for router_ids and portchannel_count
    ip_lists = get_ip_lists_for_topology(topology_type, vendor)
    from tests.snappi_tests.variables import get_portchannel_count as get_pc_count
    pc_count = get_pc_count(topology_type, vendor)

    api.set_config(bgp_config)
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(ip_lists['router_ids'][index])
            device_name = topology.DeviceGroup.find()[0].Name
            logger.info('Setting Router id {} for {}'.format(ip_lists['router_ids'][index], device_name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue

    convergence_result = []
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')

    # Find the target duthost once
    target_duthost = None
    for duthost in duthosts:
        if duthost.hostname == host_name:
            target_duthost = duthost
            break

    if target_duthost is None:
        pytest_assert(False, f"Could not find duthost with hostname {host_name}")

    # Start protocols once at the beginning
    logger.info("Starting all protocols ...")
    cs = api.control_state()
    cs.protocol.all.state = cs.protocol.all.START
    api.set_control_state(cs)

    wait(SNAPPI_TRIGGER, "For Protocols To start")
    logger.info('Verifying protocol sessions state')
    protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
    protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)

    # Wait for DUT to be ready before receiving traffic
    time.sleep(60)

    # Start traffic once at the beginning
    logger.info('Starting Traffic')
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
    api.set_control_state(cs)
    wait(SNAPPI_TRIGGER, "For Traffic To start")

    # Verify initial traffic flow
    flow_stats = get_flow_stats(api)
    for i in range(0, len(traffic_type)):
        logger.info('{} Loss %: {}'.format(flow_stats[i].name, int(flow_stats[i].loss)))
    logger.info('\n')
    port_stats = get_port_stats(api)
    logger.info('Rx Snappi Port Name : Rx Frame Rate')
    for port_stat in port_stats:
        if 'Snappi_Tx_Port' not in port_stat.name:
            logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
            pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
    pytest_assert(int(flow_stats[0].loss) == 0, 'Loss Observed in traffic flow before starting process kill tests')
    logger.info('\n')

    # Now iterate through all processes and containers
    for container_name, process_name in process_names.items():
        container_names = get_container_names_from_asic_count(target_duthost, container_name)
        for container in container_names:
            avg_pld = []
            for i in range(0, iteration):
                logger.info(
                    '|---------------------------{} Iteration : {} -----------------------|'.format(container, i+1))

                # Clear stats before each measurement
                logger.info('Performing Clear Stats')
                ixnetwork.ClearStats()
                wait(SNAPPI_TRIGGER, "For stats to clear and stabilize")

                # Verify traffic is flowing before kill
                flow_stats = get_flow_stats(api)
                port_stats = get_port_stats(api)
                for port_stat in port_stats:
                    if 'Snappi_Tx_Port' not in port_stat.name:
                        pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving \
                                      any packet before process kill'.format(port_stat.name))

                sum_t2_rx_frame_rate = 0
                for port_stat in port_stats:
                    if 'Snappi_Uplink' in port_stat.name:
                        sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)

                logger.info('Killing {}:{} service in {}'.format(container, process_name, host_name))
                PID = target_duthost.shell('docker exec {} pidof {} \n'.
                                           format(container, process_name))['stdout']
                all_containers = get_container_names(target_duthost)
                logger.info('Running containers before process kill: {}'.format(all_containers))
                kill_process_inside_container(target_duthost, container, PID, creds)
                check_container_status_down(target_duthost, container, timeout=60)
                check_container_status_up(target_duthost, container, timeout=DUT_TRIGGER)
                wait(DUT_TRIGGER, "For Flows to be evenly distributed")
                wait(DUT_TRIGGER, "For Flows to be evenly distributed")  # Syncd restart seems to take longer
                # Execute TSB command to bring the traffic back
                target_duthost.command("sudo TSB")
                wait(DUT_TRIGGER_SHORT, "For TSB")

                port_stats = get_port_stats(api)
                for port_stat in port_stats:
                    if 'Snappi_Tx_Port' not in port_stat.name:
                        logger.info('{}: {}'.format(port_stat.name, port_stat.frames_rx_rate))
                        pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet \
                                      after container is up'.format(port_stat.name))
                flow_stats = get_flow_stats(api)
                delta_frames = 0
                for i in range(0, len(traffic_type)):
                    delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
                pkt_loss_duration = 1000 * (delta_frames/sum_t2_rx_frame_rate)
                logger.info('Delta Frames : {}'.format(delta_frames))
                logger.info('PACKET LOSS DURATION (ms): {}'.format(pkt_loss_duration))
                avg_pld.append(pkt_loss_duration)
                logger.info('\n')

            convergence_result.append({
                "Test Name": test_name,
                "Container Name": container,
                "Process Name": process_name,
                "Iterations": iteration,
                "Traffic Type": traffic_type,
                "Uplink ECMP Paths": pc_count,
                "Route Count": total_routes,
                "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld)
            })

    # Stop traffic and protocols once at the end
    logger.info('Stopping Traffic')
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
    api.set_control_state(cs)
    wait(SNAPPI_TRIGGER, "For Traffic To stop")

    logger.info("Stopping all protocols ...")
    cs = api.control_state()
    cs.protocol.all.state = cs.protocol.all.STOP
    api.set_control_state(cs)
    wait(SNAPPI_TRIGGER, "For Protocols To stop")
    logger.info('\n')

    record_property("convergence_result", convergence_result)


def get_convergence_for_tsa_tsb(duthosts,
                                topology_type,
                                vendor,
                                api,
                                snappi_bgp_config,
                                traffic_type,
                                iteration,
                                device_name,
                                route_range,
                                test_name,
                                creds,
                                is_supervisor,
                                record_property):

    """
    Args:
        duthost (pytest fixture): duthost fixture
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'
        api (pytest fixture): Snappi API
        snappi_bgp_config: __snappi_bgp_config
        flap_details: contains device name and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        device_name: Device in which TSA, TSB needs to be performed
        route_range: V4 and v6 routes
        test_name: Name of the test
    """
    # Get IP lists for router_ids and portchannel_count
    ip_lists = get_ip_lists_for_topology(topology_type, vendor)
    from tests.snappi_tests.variables import get_portchannel_count as get_pc_count
    pc_count = get_pc_count(topology_type, vendor)

    api.set_config(snappi_bgp_config)
    avg_pld = []
    avg_pld2 = []
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(ip_lists['router_ids'][index])
            device_name = topology.DeviceGroup.find()[0].Name
            logger.info('Setting Router id {} for {}'.format(ip_lists['router_ids'][index], device_name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    logger.info('Issuing TSB before starting test to ensure DUT to be in proper state')
    for duthost in duthosts:
        if duthost.hostname == device_name:
            duthost.command('sudo TSB')
    wait(DUT_TRIGGER, "For TSB")
    try:
        for i in range(0, iteration):
            logger.info(
                '|--------------------------- Iteration : {} -----------------------|'.format(i+1))
            logger.info("Starting all protocols ...")
            cs = api.control_state()
            cs.protocol.all.state = cs.protocol.all.START
            api.set_control_state(cs)

            wait(SNAPPI_TRIGGER, "For Protocols To start")
            logger.info('Verifying protocol sessions state')
            protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
            protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)
            logger.info('Starting Traffic')
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            api.set_control_state(cs)
            wait(SNAPPI_TRIGGER, "For Traffic To start")
            flow_stats = get_flow_stats(api)
            port_stats = get_port_stats(api)

            logger.info('\n')
            logger.info('Rx Snappi Port Name : Rx Frame Rate')
            for port_stat in port_stats:
                if 'Snappi_Tx_Port' not in port_stat.name:
                    logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                    pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
            logger.info('\n')
            for i in range(0, len(traffic_type)):
                logger.info('{} Loss %: {}'.format(flow_stats[i].name, int(flow_stats[i].loss)))
                pytest_assert(int(flow_stats[i].loss) == 0, f'Loss Observed in {flow_stats[i].name} before link Flap')

            # Getting rx rate on uplink ports
            sum_t2_rx_frame_rate = 0
            for port_stat in port_stats:
                if 'Snappi_Uplink' in port_stat.name:
                    sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)

            logger.info('Issuing TSA on {}'.format(device_name))
            for duthost in duthosts:
                if duthost.hostname == device_name:
                    duthost.command('sudo TSA')
            wait(DUT_TRIGGER, "For TSA")
            flow_stats = get_flow_stats(api)
            for i in range(0, len(traffic_type)):
                logger.info(flow_stats[i].frames_tx_rate)
                logger.info(flow_stats[i].frames_rx_rate)
                pytest_assert(float((int(flow_stats[i].frames_tx_rate) - int(flow_stats[i].frames_rx_rate)) /
                              int(flow_stats[i].frames_tx_rate)) < 0.005,
                              'Traffic has not converged after TSA')
            logger.info('Traffic has converged after issuing TSA command in {}'.format(device_name))
            flow_stats = get_flow_stats(api)
            delta_frames = 0
            for i in range(0, len(traffic_type)):
                delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
            pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
            logger.info('Delta Frames : {}'.format(delta_frames))
            logger.info('PACKET LOSS DURATION  After TSA (ms): {}'.format(pkt_loss_duration))
            avg_pld.append(pkt_loss_duration)

            logger.info('Performing Clear Stats')
            ixnetwork.ClearStats()
            logger.info('Issuing TSB on {}'.format(device_name))
            for duthost in duthosts:
                if duthost.hostname == device_name:
                    duthost.command('sudo TSB')

            wait(DUT_TRIGGER, "For TSB")
            logger.info('\n')
            port_stats = get_port_stats(api)
            logger.info('Rx Snappi Port Name : Rx Frame Rate')
            for port_stat in port_stats:
                if 'Snappi_Tx_Port' not in port_stat.name:
                    logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                    pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))

            flow_stats = get_flow_stats(api)
            delta_frames = 0
            for i in range(0, len(traffic_type)):
                delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
            pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
            logger.info('Delta Frames : {}'.format(delta_frames))
            logger.info('PACKET LOSS DURATION After TSB (ms): {}'.format(pkt_loss_duration))
            avg_pld2.append(pkt_loss_duration)
            logger.info('Stopping Traffic')
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            api.set_control_state(cs)

            logger.info("Stopping all protocols ...")

            cs = api.control_state()
            cs.protocol.all.state = cs.protocol.all.STOP
            api.set_control_state(cs)

            logger.info('\n')

        convergence_result = [
            {
                "Test Name": f"{test_name} (TSA)",
                "Iterations": iteration,
                "Traffic Type": traffic_type,
                "Uplink ECMP Paths": pc_count,
                "Route Count": total_routes,
                "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld)
            },
            {
                "Test Name": f"{test_name} (TSB)",
                "Iterations": iteration,
                "Traffic Type": traffic_type,
                "Uplink ECMP Paths": pc_count,
                "Route Count": total_routes,
                "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld2)
            }
        ]

        record_property("convergence_result", convergence_result)

    except Exception as e:
        logger.info(e)
        logger.info('Since an exception occurred, Issuing TSB, to ensure DUT to be in proper state')
        for duthost in duthosts:
            if duthost.hostname == device_name:
                duthost.command('sudo TSB')
        wait(DUT_TRIGGER, "For TSB")


def flap_fanout_ports(fanout_ip_port_mapping, creds, state):
    """
    Flap (shutdown/startup) ports on fanout switches.

    Args:
        fanout_ip_port_mapping (dict): Mapping of fanout IP to list of port names
        creds (dict): Credentials for SSH connection
        state (str): 'down' to shutdown ports, 'up' to startup ports
    """
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')

    for fanout_ip, req_ports in fanout_ip_port_mapping.items():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(fanout_ip, port=22, username=username, password=password)
            if state == 'down':
                for port_name in req_ports:
                    time.sleep(0.05)
                    stdin, stdout, stderr = ssh.exec_command(f'sudo config interface shutdown {port_name}')
                    # Wait for command to complete
                    stdout.channel.recv_exit_status()
                    logger.info('Shutting down {}'.format(port_name))
            elif state == 'up':
                for port_name in req_ports:
                    time.sleep(0.05)
                    stdin, stdout, stderr = ssh.exec_command(f'sudo config interface startup {port_name}')
                    # Wait for command to complete
                    stdout.channel.recv_exit_status()
                    logger.info('Starting up {}'.format(port_name))
        finally:
            ssh.close()


def add_value_to_key(dictionary, key, value):
    if key in dictionary:
        dictionary[key] = dictionary[key] + [value]
    else:
        dictionary[key] = [value]


def get_convergence_for_blackout(duthosts,
                                 topology_type,
                                 vendor,
                                 api,
                                 snappi_bgp_config,
                                 traffic_type,
                                 iteration,
                                 blackout_percentages,
                                 route_range,
                                 test_name,
                                 creds, record_property):
    """
    Measure convergence for multiple blackout scenarios with a single setup/teardown.

    Args:
        duthosts: list of duthost fixtures
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'
        api (pytest fixture): Snappi API
        snappi_bgp_config: BGP config for snappi
        traffic_type: IPv4 / IPv6 traffic type
        iteration: Number of iterations per blackout percentage
        blackout_percentages: List of blackout percentages to test (e.g., [100, 50])
        route_range: Route range configuration
        test_name: Base name of the test
        creds: DUT credentials
        record_property: pytest record_property fixture
    """
    # Get IP lists for router_ids
    ip_lists = get_ip_lists_for_topology(topology_type, vendor)
    from tests.snappi_tests.variables import get_portchannel_count as get_pc_count
    pc_count = get_pc_count(topology_type, vendor)

    api.set_config(snappi_bgp_config)
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork

    # Set Router IDs
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(ip_lists['router_ids'][index])
            logger.info('Setting Router id {} for {}'.format(ip_lists['router_ids'][index],
                        topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue

    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')

    # Start protocols once
    logger.info("Starting all protocols ...")
    cs = api.control_state()
    cs.protocol.all.state = cs.protocol.all.START
    api.set_control_state(cs)
    wait(SNAPPI_TRIGGER, "For Protocols To start")
    logger.info('Verifying protocol sessions state')
    protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
    protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)

    # Start traffic once
    logger.info('Starting Traffic')
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
    api.set_control_state(cs)
    wait(SNAPPI_TRIGGER, "For Traffic To start")

    # Collect all convergence results
    all_convergence_results = []

    try:
        # Loop through each blackout percentage
        for blackout_percentage in blackout_percentages:
            blackout_test_name = f"{test_name} {blackout_percentage}% Blackout"
            logger.info('\n')
            logger.info('=' * 80)
            logger.info(f'Testing {blackout_percentage}% Blackout')
            logger.info('=' * 80)

            avg_pld = []
            avg_pld2 = []

            for i in range(0, iteration):
                logger.info(
                    '|--- Iteration : {} for {}% Blackout ---|'.format(i+1, blackout_percentage))

                # Verify traffic is running
                flow_stats = get_flow_stats(api)
                port_stats = get_port_stats(api)

                logger.info('\n')
                logger.info('Rx Snappi Port Name : Rx Frame Rate')
                for port_stat in port_stats:
                    if 'Snappi_Tx_Port' not in port_stat.name:
                        logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                        pytest_assert(port_stat.frames_rx_rate > 0,
                                      '{} is not receiving any packet'.format(port_stat.name))
                logger.info('\n')
                for j in range(0, len(traffic_type)):
                    logger.info('{} Loss %: {}'.format(flow_stats[j].name, int(flow_stats[j].loss)))
                    pytest_assert(int(flow_stats[j].loss) == 0,
                                  f'Loss Observed in {flow_stats[j].name} before link Flap')

                sum_t2_rx_frame_rate = 0
                for port_stat in port_stats:
                    if 'Snappi_Uplink' in port_stat.name:
                        sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)

                # Clear stats before flap
                logger.info('Performing Clear Stats before flap')
                ixnetwork.ClearStats()
                wait(2, "For stats to clear")

                # Link Down
                portchannel_dict = {}
                uplink_portchannel_members = get_uplink_portchannel_members(topology_type, vendor)
                for asic_value, portchannel_info in uplink_portchannel_members.items():
                    portchannel_dict.update(portchannel_info)
                number_of_po = math.ceil(blackout_percentage * len(portchannel_dict)/100)
                snappi_port_names = []
                rh_portchannels = [f"PortChannel{i}" for i in range(NUM_REGIONAL_HUBS)]
                uplink_ports = []

                # Build the list of uplink ports to flap based on blackout percentage
                # Track which portchannel indices are being flapped
                flapped_po_indices = []
                count = 0
                for idx, (key, value) in enumerate(portchannel_dict.items(), 1):
                    if key in rh_portchannels:
                        continue
                    if count < number_of_po:
                        count += 1
                        uplink_ports += value
                        flapped_po_indices.append(idx)

                # Find corresponding snappi port names based on flapped portchannel indices
                for snappi_port in fanout_uplink_snappi_info:
                    port_idx = int(snappi_port['name'].split('_')[3])
                    if port_idx in flapped_po_indices:
                        snappi_port_names.append(snappi_port['name'])

                if FANOUT_PRESENCE is False:
                    for snappi_port_name in snappi_port_names:
                        time.sleep(0.05)
                        ixn_port = ixnetwork.Vport.find(Name=snappi_port_name)[0]
                        ixn_port.LinkUpDn("down")
                        logger.info('Shutting down snappi port : {}'.format(snappi_port_name))
                    wait(SNAPPI_TRIGGER, "For links to shutdown")
                else:
                    required_fanout_mapping = {}
                    fanout_info = get_uplink_fanout_info(topology_type, vendor)
                    fanout_ip = fanout_info['fanout_ip']
                    for uplink_port in uplink_ports:
                        for port_mapping in fanout_info['port_mapping']:
                            if uplink_port == port_mapping['uplink_port']:
                                add_value_to_key(required_fanout_mapping,
                                                 fanout_ip, port_mapping['fanout_port'])
                    flap_fanout_ports(required_fanout_mapping, creds, state='down')
                    wait(DUT_TRIGGER, "For links to shutdown")

                flow_stats = get_flow_stats(api)
                for j in range(0, len(traffic_type)):
                    pytest_assert(float((int(flow_stats[j].frames_tx_rate) - int(flow_stats[j].frames_rx_rate)) /
                                  int(flow_stats[j].frames_tx_rate)) < 0.005,
                                  'Traffic has not converged after link flap')
                logger.info('Traffic has converged after link flap')

                delta_frames = 0
                for j in range(0, len(traffic_type)):
                    delta_frames = delta_frames + flow_stats[j].frames_tx - flow_stats[j].frames_rx
                pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
                logger.info('Delta Frames : {}'.format(delta_frames))
                logger.info('PACKET LOSS DURATION After Link Down (ms): {}'.format(pkt_loss_duration))
                avg_pld.append(pkt_loss_duration)

                logger.info('Performing Clear Stats')
                ixnetwork.ClearStats()

                # Link Up
                if FANOUT_PRESENCE is False:
                    for snappi_port_name in snappi_port_names:
                        time.sleep(0.05)
                        ixn_port = ixnetwork.Vport.find(Name=snappi_port_name)[0]
                        ixn_port.LinkUpDn("up")
                        logger.info('Starting up snappi port : {}'.format(snappi_port_name))
                    wait(SNAPPI_TRIGGER, "For links to startup")
                else:
                    flap_fanout_ports(required_fanout_mapping, creds, state='up')
                    wait(DUT_TRIGGER, "For links to startup")

                logger.info('\n')
                port_stats = get_port_stats(api)
                logger.info('Rx Snappi Port Name : Rx Frame Rate')
                for port_stat in port_stats:
                    if 'Snappi_Tx_Port' not in port_stat.name:
                        logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                        pytest_assert(port_stat.frames_rx_rate > 0,
                                      '{} is not receiving any packet'.format(port_stat.name))

                flow_stats = get_flow_stats(api)
                delta_frames = 0
                for j in range(0, len(traffic_type)):
                    delta_frames = delta_frames + flow_stats[j].frames_tx - flow_stats[j].frames_rx
                pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
                logger.info('Delta Frames : {}'.format(delta_frames))
                logger.info('PACKET LOSS DURATION After Link Up (ms): {}'.format(pkt_loss_duration))
                avg_pld2.append(pkt_loss_duration)
                logger.info('\n')

            # Add results for this blackout percentage
            all_convergence_results.extend([
                {
                    "Test Name": f"{blackout_test_name} (Link Down)",
                    "Iterations": iteration,
                    "Traffic type": traffic_type,
                    "Uplink ECMP Paths": pc_count,
                    "Route Count": total_routes,
                    "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld)
                },
                {
                    "Test Name": f"{blackout_test_name} (Link Up)",
                    "Iterations": iteration,
                    "Traffic type": traffic_type,
                    "Uplink ECMP Paths": pc_count,
                    "Route Count": total_routes,
                    "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld2)
                }
            ])

    finally:
        # Stop traffic and protocols (once at the end)
        logger.info('Stopping Traffic')
        cs = api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        api.set_control_state(cs)
        logger.info("Stopping all protocols ...")
        cs.protocol.all.state = cs.protocol.all.STOP
        api.set_control_state(cs)
        logger.info('\n')

    record_property("convergence_result", all_convergence_results)


def send_kernel_panic_command(duthost, creds):
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')
    ip = duthost.mgmt_ip
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port=22, username=username, password=password)
    command = 'echo c | sudo tee /proc/sysrq-trigger'
    stdin, stdout, stderr = ssh.exec_command(command)


def ping_device(duthost, timeout):
    response = os.system(f"ping -c 1 {duthost.mgmt_ip}")
    start_time = time.time()
    while True:
        response = os.system(f"ping -c 1 {duthost.mgmt_ip}")
        if response == 0:
            logger.info('PASS:PING SUCCESSFUL for {}'.format(duthost.hostname))
            break
        logger.info('Polling for {} to come UP.....'.format(duthost.hostname))
        elapsed_time = time.time() - start_time
        pytest_assert(elapsed_time < timeout,
                      "Unable to ping for {}".format(timeout))
        time.sleep(1)


def get_convergence_for_ungraceful_restart(duthosts,
                                           topology_type,
                                           vendor,
                                           api,
                                           snappi_bgp_config,
                                           traffic_type,
                                           iteration,
                                           device_name,
                                           route_range,
                                           test_name,
                                           creds,
                                           is_supervisor,
                                           record_property):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'
        api (pytest fixture): Snappi API
        snappi_bgp_config: __snappi_bgp_config
        flap_details: contains device name and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        device_name: Device in which restart needs to be performed
        route_range: V4 and v6 routes
        test_name: Name of the test
    """
    # Get IP lists for router_ids and portchannel_count
    ip_lists = get_ip_lists_for_topology(topology_type, vendor)
    from tests.snappi_tests.variables import get_portchannel_count as get_pc_count
    pc_count = get_pc_count(topology_type, vendor)

    api.set_config(snappi_bgp_config)
    avg_pld = []
    avg_pld2 = []

    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find(
            ).RouterId.Single(ip_lists['router_ids'][index])
            logger.info('Setting Router id {} for {}'.format(
                ip_lists['router_ids'][index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    for i in range(0, iteration):
        logger.info(
            '|--------------------------- Iteration : {} -----------------------|'.format(i+1))
        logger.info("Starting all protocols ...")
        wait(SNAPPI_TRIGGER, "For Protocols To start")

        cs = api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        api.set_control_state(cs)
        logger.info('Verifying protocol sessions state')
        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
        protocolsSummary.CheckCondition(
            'Sessions Down', StatViewAssistant.EQUAL, 0)
        logger.info('Starting Traffic')

        # NOTE: we sleep 60 seconds to make sure DUT is ready before receiving traffic, avoiding traffic lost
        time.sleep(60)

        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        api.set_control_state(cs)
        wait(SNAPPI_TRIGGER, "For Traffic To start")

        flow_stats = get_flow_stats(api)
        port_stats = get_port_stats(api)
        logger.info('\n')
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(
                    port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0,
                              '{} is not receiving any packet'.format(port_stat.name))
        logger.info('\n')
        for i in range(0, len(traffic_type)):
            logger.info('{} Loss %: {}'.format(
                flow_stats[i].name, int(flow_stats[i].loss)))
            pytest_assert(int(flow_stats[i].loss) == 0,
                          f'Loss Observed in {flow_stats[i].name}')

        # Getting rx rate on uplink ports
        sum_t2_rx_frame_rate = 0
        for port_stat in port_stats:
            if 'Snappi_Uplink' in port_stat.name:
                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + \
                    int(port_stat.frames_rx_rate)
        logger.info('Issuing Ungraceful restart')
        for duthost in duthosts:
            if duthost.hostname == device_name:
                send_kernel_panic_command(duthost, creds)
        wait(DUT_TRIGGER, "Issued ungraceful restart on {}".format(device_name))
        for i in range(0, len(traffic_type)):
            pytest_assert(float((int(flow_stats[i].frames_tx_rate) - int(flow_stats[i].frames_rx_rate)) /
                          int(flow_stats[i].frames_tx_rate)) < 0.005,
                          'Traffic has not converged after issuing kernel panic')
        logger.info(
            'Traffic has converged after issuing kernel panic command in {}'.format(device_name))
        flow_stats = get_flow_stats(api)
        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + \
                flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION  After Device is DOWN (ms): {}'.format(
            pkt_loss_duration))
        avg_pld.append(pkt_loss_duration)

        logger.info('Clearing Stats')
        ixnetwork.ClearStats()
        for duthost in duthosts:
            ping_device(duthost, timeout=300)
        wait(DUT_TRIGGER, "Contaniers on the DUT to stabalize after restart")

        flow_stats = get_flow_stats(api)
        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + \
                flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION  After device is UP (ms): {}'.format(
            pkt_loss_duration))
        avg_pld2.append(pkt_loss_duration)

        for duthost in duthosts:
            logger.info('Issuing TSB on {}'.format(duthost.hostname))
            duthost.command("sudo TSB")

        logger.info('Stopping Traffic')
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        api.set_control_state(cs)

        logger.info("Stopping all protocols ...")
        cs = api.control_state()
        cs.protocol.all.state = cs.protocol.all.STOP
        api.set_control_state(cs)
        logger.info('\n')

    convergence_result = [
        {
            "Test Name": f"{test_name} (Link DOWN)",
            "Iterations": iteration,
            "Traffic Type": traffic_type,
            "Uplink ECMP Paths": pc_count,
            "Route Count": total_routes,
            "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld)
        },
        {
            "Test Name": f"{test_name} (Link UP)",
            "Iterations": iteration,
            "Traffic Type": traffic_type,
            "Uplink ECMP Paths": pc_count,
            "Route Count": total_routes,
            "Avg Calculated Packet Loss Duration (ms)": mean(avg_pld2)
        }
    ]

    record_property("convergence_result", convergence_result)
