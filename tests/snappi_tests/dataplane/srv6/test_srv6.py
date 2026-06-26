
import logging
import pytest
import re
from itertools import product
# from rich import print as pr
import collections

from snappi_tests.dataplane.files.helper import create_traffic_items, start_stop, get_stats

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, fanout_graph_facts_multidut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api, get_snappi_ports, get_snappi_ports_single_dut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import get_snappi_ports_multi_dut, snappi_testbed_config # noqa F401
from tests.snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

from tests.snappi_tests.srv6.files.srv6_telemetry import poll_srv6_perf_stats
from tests.snappi_tests.srv6.files.srv6_helper import Multi_Tier_Map, assign_sid_on_tgen_ports, \
    assign_sid_to_duts, create_snappi_flows, get_dut_list, set_dut_tier_level, get_t0_duts, \
    config_dut_sids, construct_dut_to_dut_links, construct_static_route_dut_to_tgen, construct_dut_peer_connections, \
    config_dut_interface_ip, dut_ping_neighbor_links, configure_dut_static_routes, config_traffic_flows, \
    get_dut_to_dut_pairs, get_dut_stat_counters, snappi_port_name_mapper, clear_dut_stats, \
    get_ingress_egress_stats, verify_nut_stats, set_duthost_interface_details, config_dut_ip_interface, \
    remove_srv6_config

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
    tgen_endpoint_sid_start = 101
    t0_dut_sid_start = 201
    ixia_src_ipv6_prefix_start = '1'
    dut_list = []
    t0_duts = []
    t1_dut = None
    port_name_mapper = {}
    tier = {}
    core_list = []
    spine_list = []
    leaf_list = []
    tgen_list = []
    # A dict containing all DUT ingress/egress stats to trace SRv6 path
    dut_stats = {}
    total_tgen_ports = 0


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
def test_srv6_nut_topology(snappi_api,                 # noqa F811
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

    snappi_ports = set_duthost_interface_details(duthosts, Common_vars, get_snappi_ports)
    config_dut_ip_interface(snappi_ports)

    # ['switch-t0-1', 'switch-t0-2', 'switch-t1-1', 'switch-t1-2']
    get_dut_list(conn_graph_facts, Common_vars)

    # Just in case snappi-sonic has more duts than links.csv
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
    Common_vars.total_tgen_ports = len(snappi_ports)

    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"protocol_type": "ip", "ports": rx_ports, "subnet_type": subnet_type}
    }

    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    snappi_extra_params.traffic_flow_config = []

    # For poll_srv6_perf_stats()
    dut_tg_port_map = collections.defaultdict(list)
    for intf in tx_ports + rx_ports:
        dut_tg_port_map[intf["duthost"]].append((intf["peer_port"], f"Port_{intf['port_id']}"))
    dut_tg_port_map = {duthost: dict(ports) for duthost, ports in dut_tg_port_map.items()}

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
                                             'my_sids': [],
                                             't1_sid_paths': {}
                                             }

    assign_sid_on_tgen_ports(conn_graph_facts, snappi_ports, Common_vars)
    set_dut_tier_level(Common_vars)

    # ['switch-t0-1', 'switch-t0-2']
    Common_vars.t0_duts = get_t0_duts(conn_graph_facts, Common_vars)
    assign_sid_to_duts(Common_vars)
    snappi_port_name_mapper(snappi_obj_handles, snappi_extra_params, Common_vars)
    dut_connection_peers = get_dut_to_dut_pairs(conn_graph_facts, Common_vars)
    construct_dut_to_dut_links(conn_graph_facts, Common_vars)
    construct_static_route_dut_to_tgen(conn_graph_facts, Common_vars)

    # Execute twice for bi-directional traffic
    create_snappi_flows(conn_graph_facts, tx_ports, rx_ports, Common_vars)
    create_snappi_flows(conn_graph_facts, rx_ports, tx_ports, Common_vars)

    construct_dut_peer_connections(dut_connection_peers, Common_vars)
    config_dut_sids(duthosts, Common_vars)
    config_dut_interface_ip(duthosts, Common_vars)

    # At this point, all DUTs are interconnected with links and IP addresses.
    # On each DUT, ping the adjacent link IP for the DUTs to learn ARPs.
    dut_ping_neighbor_links(duthosts, Common_vars)
    configure_dut_static_routes(duthosts, Common_vars)

    if packet_size == 'mix':
        # Temporarily use 64 for all flows until we implement the logic to support mixed
        # packet sizes in a single test run.
        # Use restpy to configure IMIX
        pket_size = 64
    else:
        pket_size = packet_size

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    config_traffic_flows(pket_size, duthosts, snappi_config, Common_vars)
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
            flow.ConfigElement.find()[0].FrameSize.PresetDistribution = 'cisco'
            flow.ConfigElement.find()[0].FrameSize.Type = 'weightedPairs'
            flow.ConfigElement.find()[0].FrameSize.WeightedPairs = [128, 1, 256, 98, 4096, 98]

    clear_dut_stats(duthosts)

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

    start_stop(snappi_api, operation="stop", op_type="traffic")

    snappi_stats = get_stats(api=snappi_api,
                             stat_name="Traffic Item Statistics",
                             columns=["frames_tx", "frames_rx", "loss"],
                             return_type='stat_obj')
    logger.info(f"\nTraffic Item Statistics: {snappi_stats}\n")

    get_dut_stat_counters(duthosts, conn_graph_facts, Common_vars)

    half_of_snappi_stats = len(snappi_stats) // 2
    from_t0_1_stats = snappi_stats[:half_of_snappi_stats]
    from_t0_2_stats = snappi_stats[half_of_snappi_stats: 2 * half_of_snappi_stats]

    # Trace SRv6 DUT paths for ingress/egress stats
    topo = Multi_Tier_Map(conn_graph_facts)
    # ['switch-t0-1', 'switch-t1-1', 'switch-t2-1', 'switch-t1-2', 'switch-t0-2']
    full_path_duts = topo.full_path()

    if len(full_path_duts) > 1:
        # Remove snappi tgen devices from full_path_duts
        # 2+ DUTS:  ['snappi-sonic', 'switch-t0-1', 'switch-t0-2', 'snappi-sonic2'] ->  ['switch-t0-1', 'switch-t0-2']
        # 1 DUT:    ['switch-t0-1']
        full_path_duts.pop(0)
        full_path_duts.pop(-1)

    aligned = get_ingress_egress_stats(full_path_duts, Common_vars)

    if len(Common_vars.dut_list) > 1:
        # Two t0s: each carries one direction's flows -> verify each half separately.
        t0_1_stat_result = verify_nut_stats(aligned, from_t0_1_stats)
        # Now check DUT stats the other direction from t0-2 to t0-1
        full_path_duts.reverse()
        aligned = get_ingress_egress_stats(full_path_duts, Common_vars)
        t0_2_stat_result = verify_nut_stats(aligned, from_t0_2_stats)
    else:
        # Single t0: the one dut carries all bidirectional flows. aligned already has
        # one row per flow (ingress/egress swap naturally for the reverse-direction
        # flows), so verify against the full snappi_stats -- no half-split, no reverse.
        t0_1_stat_result = verify_nut_stats(aligned, snappi_stats)
        t0_2_stat_result = True

    test_failed = False
    for index, flow_stat in enumerate(snappi_stats):
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
        remove_srv6_config(Common_vars)
        pytest_assert(False, "DUT stat counter failed")

    if t0_2_stat_result is False:
        remove_srv6_config(Common_vars)
        pytest_assert(False, "DUT stat counter failed")

    db_reporter.report()
