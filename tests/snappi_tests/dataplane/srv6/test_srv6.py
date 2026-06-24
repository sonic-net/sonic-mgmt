
import logging
import pytest
import re
from itertools import product
# from rich import print as pr
import collections

from tests.snappi_tests.srv6.files.srv6_telemetry import poll_srv6_perf_stats
from snappi_tests.dataplane.files.helper import create_traffic_items, start_stop, get_stats

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, fanout_graph_facts_multidut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api, get_snappi_ports, get_snappi_ports_single_dut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import get_snappi_ports_multi_dut, snappi_testbed_config # noqa F401
from tests.snappi_tests.dataplane.files.helper import get_duthost_interface_details
from tests.snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

from tests.snappi_tests.srv6.files.srv6_helper import Multi_Tier_Map, assign_sid_on_tgen_ports, \
    assign_sid_to_duts, create_snappi_flows, get_dut_list, set_dut_tier_level, get_t0_duts, get_pairings, \
    increment_hex, snappi_port_name_mapper, get_ingress_egress_stats, verify_nut_stats, remove_srv6_config

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("nut")]


class Common_vars:
    dut_hosts = []
    sid_list = []
    dut_tier = {}
    # This dict contains a blueprint of all DUTS, TGENs and how
    # they are connected.
    config_data = {}
    static_route_subnet_start = '5000'
    tgen_endpoint_sid_start = 100
    t0_sid_start = 200
    t1_sid_start = 1000
    ixia_src_ipv6_prefix_start = 'fc0a'
    dut_list = []
    port_name_mapper = {}
    tier = {}
    core_list = []
    spine_list = []
    leaf_list = []
    tgen_list = []
    # A dict containing all DUT ingress/egress stats to trace SRv6 path
    dut_stats = {}


@pytest.fixture(scope="session")
def local_script_setup_and_teardown():
    logger.info("Setup before ALL test cases")
    yield
    logger.info("Remove all SRv6 and SRv6 static routes ...")
    remove_srv6_config(Common_vars)


srv6_param_values = {
    "subnet_type":     ["IPv6"],
    # "test_duration":    [1 * 60, 5 * 60, 15 * 60, 60 * 60, 24 * 60 * 60, 2 * 24 * 60 * 60],
    "test_duration":    [10],
    "packet_size":      ['mix'],
    "collect_interval": [30],
    "topology":         ["nut-2tiers"],
}

srv6_param_names = ",".join(srv6_param_values.keys())
srv6_param_product = list(product(*srv6_param_values.values()))


@pytest.mark.parametrize(srv6_param_names, srv6_param_product)
def test_srv6_nut_test(snappi_api,                 # noqa F811
                       conn_graph_facts,           # noqa F811
                       fanout_graph_facts_multidut, # noqa F811
                       duthosts,
                       set_primary_chassis, # noqa F811
                       rand_one_dut_hostname,
                       rand_one_dut_portname_oper_up,
                       get_snappi_ports, # noqa F811
                       subnet_type, # noqa F811
                       packet_size, # noqa F811
                       test_duration, # noqa F811
                       collect_interval, # noqa F811
                       create_snappi_config, # noqa F811
                       topology,
                       db_reporter,
                       local_script_setup_and_teardown
                       ):
    Common_vars.dut_hosts = duthosts
    snappi_extra_params = SnappiTestParams()

    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports,
                                                 subnet_type, protocol_type='ip')

    # ['switch-t0-1', 'switch-t0-2', 'switch-t1-1', 'switch-t1-2']
    get_dut_list(conn_graph_facts, Common_vars)

    for index, dut in enumerate(duthosts):
        if dut.hostname not in Common_vars.dut_list:
            duthosts.pop(index)

    # Sort the snappi_port list in numerical natural order
    snappi_ports.sort(key=lambda p: [int(n) for n in re.findall(r'\d+', p['location'])])

    if len(snappi_ports) % 2 == 1:
        # If there are odd number of ports, then remove the last port
        del snappi_ports[-1]

    # Split ports in half
    half_of_total_ports = len(snappi_ports) // 2
    tx_ports = snappi_ports[:half_of_total_ports]
    rx_ports = snappi_ports[half_of_total_ports: 2 * half_of_total_ports]

    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"protocol_type": "ip", "ports": rx_ports, "subnet_type": subnet_type}
    }

    # For poll_srv6_perf_stats()
    dut_tg_port_map = collections.defaultdict(list)
    for intf in tx_ports + rx_ports:
        dut_tg_port_map[intf["duthost"]].append((intf["peer_port"], f"Port_{intf['port_id']}"))
    dut_tg_port_map = {duthost: dict(ports) for duthost, ports in dut_tg_port_map.items()}

    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    snappi_extra_params.traffic_flow_config = []

    # ====== SRv6 code begins =========

    # Initialize properties
    for dut_name in Common_vars.dut_list:
        Common_vars.config_data[dut_name] = {'dut_mac_address': None,
                                             'tier_level': None,
                                             'tgen_ports': [],
                                             'tx_ports': [],
                                             'dut_link_ip_addresses': {},
                                             'dut_link_port_connections': {},
                                             'static_routes': [],
                                             'my_sids': []}

    assign_sid_on_tgen_ports(conn_graph_facts, snappi_ports, Common_vars)
    set_dut_tier_level(Common_vars)
    assign_sid_to_duts(Common_vars)
    snappi_port_name_mapper(snappi_obj_handles, Common_vars)

    # ['switch-t0-1', 'switch-t0-2']
    t0_duts = get_t0_duts(conn_graph_facts, Common_vars)

    # For creating static routes. Need to pair up the DUT-to-DUT adjacencies
    # to create the port link ip addresses and static routes between the two DUTs.
    dut_connection_parings = []
    if len(t0_duts) > 1:
        topo = Multi_Tier_Map(conn_graph_facts)
        # ['switch-t0-1', 'switch-t1-1', 'switch-t2-1', 'switch-t1-2', 'switch-t0-2']
        topology_map = topo.all_paths(t0_duts[0], t0_duts[1])
        # [('switch-t0-1', 'switch-t1-1'), ('switch-t1-1', 'switch-t2-1'), ('switch-t2-1',
        # 'switch-t1-2'), ('switch-t1-2', 'switch-t0-2')]
        dut_connection_parings = get_pairings(topology_map[0])

    # Get all dut-to-dut links
    if conn_graph_facts.get('device_linked_ports', None):
        for dut, properties in conn_graph_facts['device_linked_ports'].items():
            # Get all the adjacent DUT links Ethernet port names
            # 'device_linked_ports': {'switch-t0-1': {}, 'switch-t0-2': {}}
            #                        {'switch-t0-1': {'Ethernet128': {'peerdevice': 'switch-t0-2',
            #                                                         'peerport': 'Ethernet128'}}
            if len(properties) == 0:
                continue

            # dut, properties:
            # dut -> switch-t0-1:
            # properties -> {'Ethernet128': {'peerdevice': 'switch-t1-1', 'peerport': 'Ethernet100',
            #                                'speed': '100000', 'fec_disable': False},
            # For each local dut port and attributes on who it's connected to
            for index, (dut_port, attributes) in enumerate(properties.items()):
                if len(attributes) == 0:
                    continue

                # DUT-to_DUT link IP addresses
                local_dut_link_ip = f'{Common_vars.static_route_subnet_start}::1/64'
                next_hop_ip = f'{Common_vars.static_route_subnet_start}::2/64'

                # Initialize dut_link_ip_addresses with dut dict() on current DUT and the adjacent DUT
                if attributes['peerdevice'] not in Common_vars.config_data[dut]['dut_link_ip_addresses']:
                    Common_vars.config_data[dut]['dut_link_ip_addresses'].update({attributes['peerdevice']: []})

                if dut not in Common_vars.config_data[attributes['peerdevice']]['dut_link_ip_addresses']:
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_ip_addresses'].update({dut: []})

                # Add link port connections and its IP addresses
                if attributes['peerdevice'] not in Common_vars.config_data[dut]['dut_link_port_connections']:
                    Common_vars.config_data[dut]['dut_link_port_connections'].update({attributes['peerdevice']: []})

                if attributes['peerdevice'] in Common_vars.dut_list:
                    if dut_port not in (
                        Common_vars.config_data[dut]['dut_link_port_connections'][attributes['peerdevice']]
                    ):
                        Common_vars.config_data[dut]['dut_link_port_connections'][attributes['peerdevice']]\
                            .append(dut_port)

                        # Add IP address
                        Common_vars.config_data[dut]['dut_link_ip_addresses'][attributes['peerdevice']]\
                            .append(local_dut_link_ip)

                # REVERSE: Adding link connection on adjacent DUT
                # {'peerdevice': 'switch-t1-1', 'peerport': 'Ethernet100', 'speed': '100000', 'fec_disable': False}
                # To the peerdevice as dut
                if dut not in Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections']:
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections'].update({dut: []})

                if attributes['peerport'] not in (
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections'][dut]
                ):
                    (
                        Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections']
                        [dut].append(attributes['peerport'])
                    )

                    # Add IP addresses on link connections between 2 DUTs
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_ip_addresses'][dut].append(next_hop_ip)

                Common_vars.static_route_subnet_start = increment_hex(str(Common_vars.static_route_subnet_start))

    # Create static routes from t0 DUT to tgen hosts
    for dut, properties in conn_graph_facts['device_conn'].items():
        # 'Ethernet128': {'peerdevice': 'switch-t1-1', 'peerport': 'Ethernet100',
        # 'speed': '100000', 'fec_disable': False},
        if len(conn_graph_facts['device_conn'][dut]) == 0:
            continue

        # Create static-routes from t0 to tgen hosts
        for index, dut_link_port_name in enumerate(Common_vars.config_data[dut]['tgen_ports']):
            # Create a static route for each tgen snappi host
            snappi_sid = Common_vars.config_data[dut]['tgen_ports'][index]['tgen_endpoint_sid']
            snappi_dest_host_ip = Common_vars.config_data[dut]['tgen_ports'][index]['ipAddress']
            snappi_dest_port = Common_vars.config_data[dut]['tgen_ports'][index]['peer_port']

            static_route = (f'sonic-db-cli CONFIG_DB hset "STATIC_ROUTE|fcbb:bbbb:{snappi_sid}::/48" '
                            f'nexthop {snappi_dest_host_ip} ifname {snappi_dest_port}')

            Common_vars.config_data[dut]['static_routes'].append(static_route)
            Common_vars.static_route_subnet_start = increment_hex(str(Common_vars.static_route_subnet_start))

    # Execute twice to make bi-directional traffic
    create_snappi_flows(conn_graph_facts, tx_ports, rx_ports, Common_vars)
    create_snappi_flows(conn_graph_facts, rx_ports, tx_ports, Common_vars)

    # Static routes for topologies with more than 1 DUT
    for dut_connection_pair in dut_connection_parings:
        # dut_connection: ('switch-t0-1', 'switch-t1-1')
        # [('switch-t0-1', 'switch-t1-1'), ('switch-t1-1', 'switch-t2-1'),
        #  ('switch-t2-1', 'switch-t1-2'), ('switch-t1-2', 'switch-t0-2')]

        for dut in dut_connection_pair:
            # Assign IP address to each port
            # 'dut_link_ip_addresses': {'switch-t0-1': ['5000::2/64', '5000::2/64', '5000::2/64', '5000::2/64',
            #                                           '5000::2/64', '5000::2/64', '5000::2/64', '5000::2/64']}
            for adjacent_dut, local_dut_ip_list in Common_vars.config_data[dut]['dut_link_port_connections'].items():
                for index, each_ip in enumerate(local_dut_ip_list):
                    adjacent_dut_sid = Common_vars.config_data[adjacent_dut]['my_sids'][index]

                    # 'dut_link_port_connections': {'switch-t0-1': ['Ethernet128', 'Ethernet129', 'Ethernet130',
                    # 'Ethernet131', 'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135']}
                    # next_hop_local_dut_port = (Common_vars.config_data[dut]['dut_link_port_connections']
                    #                            [adjacent_dut][index])
                    next_hop_local_dut_port = (
                        Common_vars.config_data[dut]['dut_link_port_connections'][adjacent_dut][index]
                    )

                    next_hop_ip = (
                        Common_vars.config_data[adjacent_dut]['dut_link_ip_addresses'][dut][index].split("/")[0]
                    )

                    to_route = f'fcbb:bbbb:{adjacent_dut_sid}::/48'
                    static_route = (f'sonic-db-cli CONFIG_DB hset "STATIC_ROUTE|{to_route}" '
                                    f'nexthop {next_hop_ip} ifname {next_hop_local_dut_port}')

                    if static_route not in Common_vars.config_data[dut]['static_routes']:
                        Common_vars.config_data[dut]['static_routes'].append(static_route)

    logger.info('--- MY-SIDS and SID-LOCATORS---')
    # Configure MY-SIDS on DUTs
    for dut in duthosts:
        count = 1
        for sid in Common_vars.config_data[dut.hostname]['my_sids']:
            logger.info(f'Configuring {dut.hostname}: sonic-db-cli CONFIG_DB hset '
                        f'"SRV6_MY_LOCATORS|loc{count}" prefix "fcbb:bbbb:{sid}::" func_len 0')

            dut.shell((f'sonic-db-cli CONFIG_DB hset "SRV6_MY_LOCATORS|loc{count}" '
                       f'prefix "fcbb:bbbb:{sid}::" func_len 0'))

            logger.info((f'    sonic-db-cli CONFIG_DB hset "SRV6_MY_SIDS|loc{count}|fcbb:bbbb:{sid}::/48" '
                         f'action uN decap_dscp_mode pipe'))

            dut.shell(f'sonic-db-cli CONFIG_DB hset "SRV6_MY_SIDS|loc{count}|fcbb:bbbb:{sid}::/48" '
                      f'action uN decap_dscp_mode pipe')
            count += 1

    logger.info('--- DUT-to-DUT interface IP addresses ---')
    # Configure DUT links in between DUTs
    for dut in duthosts:
        # 'dut_link_ip_addresses': {
        #     'switch-t1-1': ['5010::2/64', '5011::2/64', '5012::2/64', '5013::2/64',
        #                     '5014::2/64', '5015::2/64', '5016::2/64', '5017::2/64'],
        #     'switch-t1-2': ['5018::2/64', '5019::2/64', '501a::2/64', '501b::2/64',
        #                     '501c::2/64', '501d::2/64', '501e::2/64', '501f::2/64']
        # }
        # 'dut_link_port_connections': {
        #     'switch-t1-1': ['Ethernet128', 'Ethernet129', 'Ethernet130', 'Ethernet131',
        #                     'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135'],
        #     'switch-t1-2': ['Ethernet100', 'Ethernet101', 'Ethernet102', 'Ethernet103',
        #                     'Ethernet104', 'Ethernet105', 'Ethernet106', 'Ethernet107']
        # }
        for adjacent_dut, dut_ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for index, port in enumerate(dut_ports):
                ip_address = Common_vars.config_data[dut.hostname]['dut_link_ip_addresses'][adjacent_dut][index]

                # {'dut': 'switch-t0-1', 'ip_address': '5010::1/64', 'local_dut_port': 'Ethernet128',
                #  'port': 'Ethernet128'}
                logger.info(f'DUT:{dut.hostname}: sudo config int ip add {port} {ip_address}')
                dut.shell(f'sudo config int ip add {port} {ip_address}')

    # At this point, all DUTs are interconnected with links and IP addresses.
    # On each DUT, ping the adjacent link IP for the DUTs to learn ARPs.
    for dut in duthosts:
        for adjacent_dut, dut_ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for index, link in enumerate(dut_ports):
                adjacent_dut_link_ip = (
                    Common_vars.config_data[adjacent_dut]['dut_link_ip_addresses'][dut.hostname][index].split('/')[0]
                )

                logger.info((f'Ping adjacent DUT to learn ARP: {dut.hostname} -> {adjacent_dut}  '
                             f'pinging {adjacent_dut_link_ip}'))

                dut.shell(f'ping {adjacent_dut_link_ip} -c 2')

    logger.info('--- STATIC ROUTES FOR TGEN PORTS ---')
    # Configure static routes on DUTs
    # All static routes cli commands are created in a list already
    # 'sonic-db-cli CONFIG_DB hset "STATIC_ROUTE|fcbb:bbbb:1000::/48" nexthop 5010::1 ifname Ethernet128'
    for dut in duthosts:
        for static_route in Common_vars.config_data[dut.hostname]['static_routes']:
            logger.info(f'DUT:{dut.hostname} -> {static_route}')
            dut.shell(f'{static_route}')

    if packet_size == 'mix':
        # Temporarily use 64 for all flows until we implement the logic to support mixed
        # packet sizes in a single test run.
        # Use restpy to configure IMIX
        pket_size = 64
    else:
        pket_size = packet_size

    """
        Common_vars.config_data[dut.hostname]['tx_ports']
            {
                'my_snappi_port': '10.36.84.36/1.1',
                'my_dut_port': 'Ethernet64',
                'my_dut_sid_to_use': 200,
                'my_src_ip': 'fc0a::2',
                'my_src_ip_prefix': '126',
                'my_src_mac': '10:17:00:00:00:11',
                'my dest_mac': '8c:01:9d:fa:40:cc',
                'my_ipv6_srv6_dest': 'fcbb:bbbb:200:1000:3000:2000:300:108',
                'rx_port': '10.36.84.37/3.1',
                'rx_port_ip_address': 'fc2a::2'
            }

        'tgen_ports': [
            {
                'ip': '10.36.84.37',
                'port_id': '9',
                'peer_port': 'Ethernet80',
                'peer_device': 'switch-t0-2',
                'speed': '100000',
                'location': '10.36.84.37/3.1',
                'intf_config_changed': False,
                'api_server_ip': '10.36.84.36',
                'asic_type': 'broadcom',
                'duthost': 'switch-t0-2',
                'snappi_speed_type': 'speed_100_gbps',
                'asic_value': None,
                'autoneg': False,
                'fec': False,
                'ipAddress': 'fc2a::2',
                'ipGateway': 'fc2a::1',
                'prefix': '126',
                'router_mac_address': '8c:01:9d:fa:4b:10',
                'src_mac_address': '10:17:00:00:00:19',
                'subnet': 'fc2a::1/126',
                'tgen_endpoint_sid': 108
            }
    """

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)

    index = 0
    for dut in duthosts:
        for flow in Common_vars.config_data[dut.hostname]['tx_ports']:
            tx_snappi_port_name_for_raw_pkts = Common_vars.port_name_mapper[flow['my_snappi_port']]
            rx_snappi_port_name_for_raw_pkts = Common_vars.port_name_mapper[flow['rx_port']]

            flow_name = (f"{flow['my_snappi_port']}:{tx_snappi_port_name_for_raw_pkts} -> "
                         f"{flow['rx_port']}:{rx_snappi_port_name_for_raw_pkts}")
            test_flow = snappi_config.flows.add(name=flow_name)

            test_flow.tx_rx.port.tx_name = tx_snappi_port_name_for_raw_pkts
            test_flow.tx_rx.port.rx_name = rx_snappi_port_name_for_raw_pkts
            test_flow.size.fixed = pket_size
            test_flow.rate.percentage = 100
            test_flow.duration.continuous

            ethernet = test_flow.packet.add()
            ethernet.choice = "ethernet"
            ethernet.ethernet.src.value = flow['my_src_mac']
            ethernet.ethernet.dst.value = Common_vars.config_data[dut.hostname]['router_mac_address']

            ipv6_outer = test_flow.packet.add()
            ipv6_outer.choice = "ipv6"
            ipv6_outer.ipv6.src.value = flow['my_src_ip']
            ipv6_outer.ipv6.dst.value = flow['my_ipv6_srv6_dest']
            ipv6_outer.ipv6.hop_limit.value = 126

            ipv6_inner = test_flow.packet.add()
            ipv6_inner.choice = "ipv6"
            ipv6_inner.ipv6.src.value = flow['my_src_ip']
            ipv6_inner.ipv6.dst.value = flow['rx_port_ip_address']
            # inner has no next header
            ipv6_inner.ipv6.next_header.value = 59
            ipv6_inner.ipv6.hop_limit.value = 126

            index += 1

    snappi_api.set_config(snappi_config)
    start_stop(snappi_api, operation="start", op_type="protocols")

    logger.info('Wait for Arp to Resolve ...')
    if wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=2) != 0:
        pytest_assert(False, "ARP failed")

    for flow in snappi_api._ixnetwork.Traffic.TrafficItem.find():
        flow.Tracking.find()[0].TrackBy = ['trackingenabled0']

    if packet_size == 'mix':
        # Snappi doesn't support custom mix packet sizes yet
        # Using restpy to make the imix packets
        for flow in snappi_api._ixnetwork.Traffic.TrafficItem.find():
            logger.info(f'flow mixed packets: {flow.Name}')
            flow.ConfigElement.find()[0].FrameSize.PresetDistribution = 'cisco'
            flow.ConfigElement.find()[0].FrameSize.Type = 'weightedPairs'
            flow.ConfigElement.find()[0].FrameSize.WeightedPairs = [128, 1, 256, 98, 4096, 98]

    for duthost in duthosts:
        logger.info(f'sonic-clear counters on DUT: {duthost.hostname} ...')
        duthost.command("sonic-clear counters")

    logger.info('Starting traffic and polling stats ...')
    start_stop(snappi_api, operation="start", op_type="traffic")

    # poll_srv6_perf_stats blocks for the full duration, recording
    # samples every collect_interval seconds. db_reporter accumulates
    # them in memory.
    poll_srv6_perf_stats(
        dut_tg_port_map,
        duration_sec=test_duration,
        interval_sec=collect_interval,
        db_reporter=db_reporter,
    )

    # name: 'Tx: Port_4 -> Rx: Port_8 src_ipv6_1: 2004::2 dst_ipv6_1: fcbb:bbbb:1:008::
    #        src_ipv6_2: 2004::2 dst_ipv6_2: 2008::2'
    # port_rx: Port_8
    # port_tx: Port_4
    # rx_l1_rate_bps: 10000000064.0
    # rx_rate_bps: 8648648704.0
    # rx_rate_bytes: 1081081088.0
    # rx_rate_kbps: 8648648.704
    # rx_rate_mbps: 8648.649
    # transmit: started
    # tx_l1_rate_bps: 10000000064.0
    # tx_rate_bps: 8648648704.0
    # tx_rate_bytes: 1081081088.0
    # tx_rate_kbps: 8648648.704
    # tx_rate_mbps: 8648.649

    start_stop(snappi_api, operation="stop", op_type="traffic")

    stats = get_stats(api=snappi_api,
                      stat_name="Traffic Item Statistics",
                      columns=["frames_tx", "frames_rx", "loss"],
                      return_type='stat_obj')
    logger.info(f"\nTraffic Item Statistics: {stats}\n")

    # --------------- Trace SRv6 DUT paths for ingress/egress stats -----------------
    topo = Multi_Tier_Map(conn_graph_facts)
    # ['switch-t0-1', 'switch-t1-1', 'switch-t2-1', 'switch-t1-2', 'switch-t0-2']
    full_path_duts = topo.full_path()
    full_path_duts.pop(0)
    full_path_duts.pop(-1)

    for dut in Common_vars.dut_hosts:
        # 'dut_link_port_connections': {'switch-t1-2': ['Ethernet128', 'Ethernet129', 'Ethernet130', 'Ethernet131',
        #                               'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135']
        # }
        # Get all the link ports on the current dut to get the link port stats
        grep_for_ports = 'grep '
        for adjacent_dut, ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for port in ports:
                grep_for_ports += f'-e {port} '

        for tx_port in Common_vars.config_data[dut.hostname]['tx_ports']:
            grep_for_ports += f'-e {tx_port["my_dut_port"]} '

        cli_command = f'show int counters | {grep_for_ports}'
        logger.info(f'Getting DUT stats on: {dut.hostname} -> {cli_command}')
        dut_stats = ('IFACE STATE RX_OK RX_BPS RX_UTIL RX_ERR RX_DRP '
                     'RX_OVR TX_OK TX_BPS TX_UTIL TX_ERR TX_DRP TX_OVR\n')
        dut_stats += dut.shell(cli_command)['stdout']
        Common_vars.dut_stats[dut.hostname] = dut_stats
        logger.info(dut_stats)

    half_of_snappi_stats = len(stats) // 2
    from_t0_1_stats = stats[:half_of_snappi_stats]
    from_t0_2_stats = stats[half_of_snappi_stats: 2 * half_of_snappi_stats]

    # Now check DUT stats the other direction from t0-2 to t0-1
    aligned = get_ingress_egress_stats(full_path_duts, Common_vars)
    t0_1_stat_result = verify_nut_stats(aligned, from_t0_1_stats)
    full_path_duts.reverse()

    aligned = get_ingress_egress_stats(full_path_duts, Common_vars)
    t0_2_stat_result = verify_nut_stats(aligned, from_t0_2_stats)

    # ------------------------------------------------------------------------------

    test_failed = False
    for index, flow_stat in enumerate(stats):
        flow_name = flow_stat.name
        frames_tx = flow_stat.frames_tx
        frames_rx = flow_stat.frames_rx
        delta = int(frames_tx) - int(frames_rx)

        logger.info(f"{flow_name}: Frames Tx: {frames_tx}  Frames Rx: {frames_rx}  Delta: {delta}")

        if delta != 0 and test_failed is False:
            # Come in here just one time only
            test_failed = True

    if test_failed:
        remove_srv6_config(Common_vars)
        pytest_assert(False, "SRv6 NUT-test failed")

    if t0_1_stat_result is False:
        pytest_assert(False, "DUT stat counter failed")

    if t0_2_stat_result is False:
        pytest_assert(False, "DUT stat counter failed")

    db_reporter.report()
