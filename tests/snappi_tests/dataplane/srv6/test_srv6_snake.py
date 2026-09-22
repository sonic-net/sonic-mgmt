
"""
REQUIREMENTS:
    - sonic_snappi-sonic_links.csv file:
        - Must include all 512 Ethernet interfaces of the DUT.
        - 32 TGEN ports connected to 32 DUT ports on each side.
        - All Ethernet interfaces must include the VLAN ID.
        - TGEN port connection to DUT port example:
            - switch-t0-1,Ethernet480,snappi-sonic,Port5.1,100000,482,Access
            - 482 is the VLAN ID of the DUT port, which is used to create the VRF and SID.
        - Snake ports example:
            - switch-t0-1,Ethernet479,switch-t0-1,Ethernet479,100000,481,Access
            - 481 is the VLAN ID of the DUT port, which is used to create the VRF and SID.
"""
import logging
import pytest
from itertools import product
import collections

from snappi_tests.dataplane.files.helper import create_traffic_items, start_stop, get_stats, dutconfig_checkpoint # noqa F401
from snappi_tests.dataplane.files.helper import get_autoneg_fec
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, fanout_graph_facts_multidut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api, get_snappi_ports, \
    get_snappi_ports_single_dut # noqa F401
from tests.common.snappi_tests.snappi_fixtures import get_snappi_ports_multi_dut, snappi_testbed_config # noqa F401
from tests.snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

from tests.snappi_tests.dataplane.srv6.files.srv6_telemetry import poll_srv6_perf_stats
from tests.snappi_tests.dataplane.srv6.files.srv6_helper import config_snake_traffic_flows, \
    snappi_port_name_mapper_snake, verify_dut_stat_counters_snake, clear_dut_stats, \
    config_snake_vlan_mac_port, config_snake_vrf, config_snake_vrf_bindings, config_snake_sids, \
    create_snake_tgen_sid_list, config_snake_static_routes, config_ip_neighbor_add_lladd_dev, \
    add_details_to_snappi_ports

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("nut")]


class Common_vars:
    dut_host = None
    dut_hostname = None
    conn_graph_facts = None  # noqa F811
    mac_address_prefix = '00:11:00:00'
    mac_src_prefix = '00:11:01:00'
    mac_src_byte = '00'
    ip_prefix = 'fc0a'
    # One /126 subnet per snake link, so consecutive subnets are 4 addresses apart
    ip_step = 4
    ip_subnet_prefix = '126'

    # Vlans are split evenly across the VRF groups: 32 VRFs x 16 vlans = 512 vlans
    # QA setup = 7 | sonic team setup = 32
    total_vrfs = 32
    vlans_per_vrf = 16
    # Each VRF group of vlans is split into 2 subgroups of 8 for SID assignment
    subgroups_per_vrf = 2
    # SIDs are numbered a block of VRFs at a time: 32 VRFs / 4 = 8 blocks of 16 SIDs
    vrfs_per_group = 4
    total_sids = 128

    sid_list = []
    # This dict contains a blueprint of all DUTS, TGENs and how
    # they are connected.
    config_data = {}
    sid_prefix = 'fcbb:bbbb'
    ixia_src_ipv6_prefix_start = '1'
    port_name_mapper = {}
    tgen_list = []
    # A dict containing all DUT ingress/egress stats to trace SRv6 path
    dut_stats = {}
    total_tgen_ports = 0
    snappi_tx_ports = []
    snappi_rx_ports = []
    config_dut_already = False
    debug_mode = False


srv6_param_values = {
    "subnet_type":     ["IPv6"],
    "test_duration":    [60],
    "packet_size":      [1500],
    "line_rate":        [95],
    "collect_interval": [30],
    "topology":         ["snake"],
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
                           line_rate, # noqa F811
                           test_duration, # noqa F811
                           collect_interval, # noqa F811
                           create_snappi_config, # noqa F811
                           topology,
                           db_reporter,
                           dutconfig_checkpoint # noqa F811
                           ):

    Common_vars.conn_graph_facts = conn_graph_facts
    snappi_extra_params = SnappiTestParams()
    get_autoneg_fec(duthosts, get_snappi_ports)

    if packet_size == 'mix':
        # Temporarily use 64 for all flows until we implement the logic to
        # support mixed packet sizes in a single test run.
        # Use restpy to configure IMIX
        pket_size = 64
    else:
        pket_size = packet_size

    Common_vars.dut_host = duthosts[0]
    Common_vars.dut_hostname = duthosts[0].hostname

    # Split ports in half
    half_of_total_ports = len(get_snappi_ports) // 2
    Common_vars.snappi_tx_ports = get_snappi_ports[:half_of_total_ports]
    Common_vars.snappi_rx_ports = get_snappi_ports[half_of_total_ports: 2 * half_of_total_ports]

    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": Common_vars.snappi_tx_ports, "subnet_type": 'IPv6'},
        "Rx": {"protocol_type": "ip", "ports": Common_vars.snappi_rx_ports, "subnet_type": 'IPv6'}
    }

    snappi_extra_params.traffic_flow_config = []

    # For poll_srv6_perf_stats()
    dut_tg_port_map = collections.defaultdict(list)
    for intf in Common_vars.snappi_tx_ports + Common_vars.snappi_rx_ports:
        dut_tg_port_map[intf["duthost"]].append((intf["peer_port"], f"Port_{intf['port_id']}"))
    dut_tg_port_map = {duthost: dict(ports) for duthost, ports in dut_tg_port_map.items()}

    if Common_vars.config_dut_already is False:
        Common_vars.config_dut_already = True

        Common_vars.config_data = {'vrf_groups': {},
                                   'tgen_ports_left': [],
                                   'tgen_ports_right': [],
                                   'static_routes': [],
                                   'neighbor_dev': []}

        config_snake_vlan_mac_port(Common_vars)  #
        config_snake_vrf(Common_vars)  #
        config_snake_vrf_bindings(Common_vars)
        config_snake_sids(Common_vars)  #
        create_snake_tgen_sid_list(Common_vars)
        config_snake_static_routes(Common_vars)  #
        config_ip_neighbor_add_lladd_dev(Common_vars)
        add_details_to_snappi_ports(Common_vars)

    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    snappi_port_name_mapper_snake(snappi_obj_handles, snappi_extra_params, Common_vars)
    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    config_snake_traffic_flows(pket_size, line_rate, snappi_config, Common_vars)
    snappi_api.set_config(snappi_config)
    start_stop(snappi_api, operation="start", op_type="protocols")

    logger.info('Wait for Arp to Resolve ...')
    if wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=2) != 0:
        pytest_assert(False, "ARP failed")

    if packet_size == 'mix':
        # Snappi doesn't support custom mix packet sizes yet
        # Using restpy to make the imix packets
        for flow in snappi_api._ixnetwork.Traffic.TrafficItem.find():
            flow.ConfigElement.find()[0].FrameSize.PresetDistribution = 'cisco'
            flow.ConfigElement.find()[0].FrameSize.Type = 'weightedPairs'
            flow.ConfigElement.find()[0].FrameSize.WeightedPairs = [128, 1, 256, 98, 4096, 98]

    clear_dut_stats(duthosts)

    logger.info('Starting traffic ...')
    start_stop(snappi_api, operation="start", op_type="traffic")

    # poll_srv6_perf_stats blocks for the full duration, recording
    # samples every collect_interval seconds. db_reporter accumulates
    # them in memory.
    logger.info('Polling stats ...')
    poll_srv6_perf_stats(
        dut_tg_port_map,
        duration_sec=test_duration,
        interval_sec=collect_interval,
        db_reporter=db_reporter,
    )

    start_stop(snappi_api, operation="stop", op_type="traffic", stop_timeout_seconds=300)
    logger.info('Stopped traffic ...')

    logger.info('get_stats ...')
    snappi_stats = get_stats(api=snappi_api,
                             stat_name="Traffic Item Statistics",
                             columns=["frames_tx", "frames_rx", "loss"],
                             return_type='stat_obj')

    logger.info(snappi_stats)

    tgen_flow_failures = []
    for snappi_flow_stat in snappi_stats:
        if int(snappi_flow_stat.frames_rx) < int(snappi_flow_stat.frames_tx):
            message = (f'TGEN ports: {snappi_flow_stat.name}: RX={snappi_flow_stat.frames_rx}  '
                       f'less than  TX={snappi_flow_stat.frames_tx}')
            tgen_flow_failures.append(message)
            logger.warning(message)

    verify_dut_stat_counters_snake(Common_vars, snappi_stats)

    if len(tgen_flow_failures) != 0:
        pytest_assert(False, ('Test failed. Expected tgen transmitted frames were not '
                              f'received on tgen ports: {tgen_flow_failures}'))

    db_reporter.report()
