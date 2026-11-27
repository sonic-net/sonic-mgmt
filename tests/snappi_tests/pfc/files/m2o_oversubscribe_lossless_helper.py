# uncompyle6 version 3.9.0
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 3.10.4 (tags/v3.10.4:9d38120, Mar 23 2022, 23:13:41) [MSC v.1929 64 bit (AMD64)]
# Embedded file name: /var/johnar/sonic-mgmt/tests/snappi/multi_dut_rdma/files/rdma_helper.py
# Compiled at: 2023-02-10 09:15:26
from math import ceil                                                                   # noqa: F401
import logging                                                                          # noqa: F401
import re
import sys
from tabulate import tabulate
from collections import namedtuple
from tests.common.helpers.assertions import pytest_assert, pytest_require               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts  # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id                          # noqa: F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, \
    stop_pfcwd, disable_packet_aging, sec_to_nanosec, get_interface_stats                     # noqa: F401
from tests.common.snappi_tests.port import select_ports                                       # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, \
     run_traffic                                         # noqa: F401
from tests.common.snappi_tests.variables import pfcQueueValueDict
from tests.common.snappi_tests.common_helpers import pfc_queue_group_size
from tests.snappi_tests.files.helper import get_number_of_streams
from tests.common.snappi_tests.snappi_fixtures import gen_data_flow_dest_ip
logger = logging.getLogger(__name__)

PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 35
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 22.5
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 10
DATA_FLOW_DELAY_SEC = 5
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05
UDP_PORT_START = 5000
# Number of non-MACsec devices created on the rx port per tx port (see __intf_config_macsec)
MACSEC_DEVICES_PER_TX_PORT = 7
# MACsec bytes (SecTAG + ICV) carried inside the configured frame size and removed by the DUT, and the
# per-frame L1 overhead (preamble + IFG) on the wire
MACSEC_OVERHEAD_BYTES = 32
L1_OVERHEAD_BYTES = 20


def macsec_egress_rate_scale(pkt_size=DATA_PKT_SIZE):
    """
    Ingress is MACsec, egress is plain. Ixia sends the same frame rate as without MACsec (the configured
    frame size includes the MACsec bytes), but the DUT strips MACSEC_OVERHEAD_BYTES per frame, so the same
    percentage of ingress line rate loads the plain egress port by this factor (< 1) only.
    """
    return (pkt_size - MACSEC_OVERHEAD_BYTES + L1_OVERHEAD_BYTES) / float(pkt_size + L1_OVERHEAD_BYTES)


def get_oversubscription_drop_percent(total_offered_percent, macsec_enabled=False, pkt_size=DATA_PKT_SIZE):
    """
    Share of the offered frames that exceeds the egress capacity, when total_offered_percent (sum of the
    flows' line-rate percents) is offered to one plain egress port. With a MACsec ingress the offered load is
    scaled by macsec_egress_rate_scale first.
    """
    offered = total_offered_percent * (macsec_egress_rate_scale(pkt_size) if macsec_enabled else 1.0)
    pytest_assert(offered > 0, "FAIL: total offered load must be > 0")
    return 100.0 * max(0.0, offered - 100.0) / offered


def macsec_pgid(src_index, prio, devices_per_tx_port=MACSEC_DEVICES_PER_TX_PORT):
    """
    PGID used to track a MACsec flow in the IxNetwork Flow Statistics.
    Each Tx port owns a block of devices_per_tx_port PGIDs, one per priority.
    """
    return src_index * devices_per_tx_port + prio


def macsec_priority(pgid, devices_per_tx_port=MACSEC_DEVICES_PER_TX_PORT):
    """Inverse of macsec_pgid: the priority of the flow tracked under pgid."""
    return pgid % devices_per_tx_port


MacsecFlowStatRow = namedtuple(
    'MacsecFlowStatRow',
    [
        'flow_name',
        'display_name',
        'flow_kind',
        'priority',
        'pgid',
        'tx_port',
        'rx_port',
        'tx_frames',
        'rx_frames',
        'loss_percent',
        'identity',
    ],
)


def _macsec_flow_kind(flow_name):
    if TEST_FLOW_NAME in flow_name:
        return 'test'
    if BG_FLOW_NAME in flow_name:
        return 'background'
    return 'other'


def _macsec_display_name(flow_name, priority):
    if TEST_FLOW_NAME in flow_name:
        kind = 'Test_flow'
    elif BG_FLOW_NAME in flow_name:
        kind = 'Background_flow'
    else:
        kind = 'Flow'
    match = re.search(r'(\d+) -> (\d+)', flow_name)
    if match:
        return '{}_prio{}_port{}->port{}'.format(
            kind, priority, match.group(1), match.group(2))
    return '{}_prio{}'.format(kind, priority)


def assert_macsec_flow_stat_identities_disjoint(flow_name_stats_identity_map):
    """Fail if a test flow and a background flow share the same MACsec stats identity."""
    test_identities = {
        identity
        for name, identity in flow_name_stats_identity_map.items()
        if TEST_FLOW_NAME in name
    }
    bg_identities = {
        identity
        for name, identity in flow_name_stats_identity_map.items()
        if BG_FLOW_NAME in name
    }
    pytest_assert(
        test_identities.isdisjoint(bg_identities),
        "FAIL: Test and Background Flows share a MACsec statistics identity")


def get_missing_macsec_flow_identities(parsed_stats, flow_name_stats_identity_map, flow_kind=None):
    """
    Return the (Tx Port, Rx Port, PGID) identities of configured flows that have no transmitting row
    in parsed_stats (e.g. the flow did not run, or IxNetwork did not report it).

    Args:
        parsed_stats (list): output of parse_macsec_flow_statistics / log_macsec_flow_statistics
        flow_name_stats_identity_map (dict): flow name -> (Tx Port, Rx Port, PGID)
        flow_kind (str): restrict the check to 'test' or 'background' flows (default: all flows)
    """
    seen_identities = {stat.identity for stat in parsed_stats}
    return {
        identity
        for flow_name, identity in flow_name_stats_identity_map.items()
        if (flow_kind is None or _macsec_flow_kind(flow_name) == flow_kind)
        and identity not in seen_identities
    }


def parse_macsec_flow_statistics(rows,
                                 flow_name_stats_identity_map,
                                 skip_zero_tx=True):
    """
    Match IxNetwork Flow Statistics rows to configured flows via flow_name_stats_identity_map.

    Args:
        rows (list): IxNetwork Flow Statistics rows (keyed by column name)
        flow_name_stats_identity_map (dict): flow name -> (Tx Port, Rx Port, PGID)
        skip_zero_tx (bool): ignore rows with no transmitted frames

    Returns:
        list[MacsecFlowStatRow]: one entry per matched row with Tx Frames > 0 (if skip_zero_tx).
    """
    identity_to_flow_name = {}
    for flow_name, identity in flow_name_stats_identity_map.items():
        pytest_assert(
            identity not in identity_to_flow_name,
            "FAIL: Flows '{}' and '{}' share the MACsec statistics identity {}".format(
                identity_to_flow_name.get(identity), flow_name, identity))
        identity_to_flow_name[identity] = flow_name
    parsed = []

    for row in rows:
        pgid = int(row['PGID'])
        identity = (row['Tx Port'], row['Rx Port'], pgid)
        if identity not in identity_to_flow_name:
            continue
        try:
            tx_frames = int(row['Tx Frames'])
            rx_frames = int(row['Rx Frames'])
        except (TypeError, ValueError):
            # Rows without a transmit side (e.g. 'Quick Flow Groups Egress Only') report blank Tx Frames
            continue
        if skip_zero_tx and tx_frames == 0:
            continue
        flow_name = identity_to_flow_name[identity]
        priority = macsec_priority(pgid)
        parsed.append(
            MacsecFlowStatRow(
                flow_name=flow_name,
                display_name=_macsec_display_name(flow_name, priority),
                flow_kind=_macsec_flow_kind(flow_name),
                priority=priority,
                pgid=pgid,
                tx_port=identity[0],
                rx_port=identity[1],
                tx_frames=tx_frames,
                rx_frames=rx_frames,
                loss_percent=100.0 * (tx_frames - rx_frames) / tx_frames,
                identity=identity,
            ))

    return parsed


def log_macsec_flow_statistics(rows,
                               flow_name_stats_identity_map,
                               skip_zero_tx=True,
                               header='MACsec flow statistics'):
    """
    Parse MACsec flow statistics, log a standard table, and return parsed rows for verification.

    Table columns:
        Snappi flow name, display_name, Priority, Tx port, Rx port, Tx frames, Rx frames, Loss
    """
    parsed = parse_macsec_flow_statistics(
        rows,
        flow_name_stats_identity_map,
        skip_zero_tx=skip_zero_tx,
    )
    table_rows = [
        [
            stat.flow_name,
            stat.display_name,
            stat.priority,
            stat.tx_port,
            stat.rx_port,
            stat.tx_frames,
            stat.rx_frames,
            '{:.2f}'.format(stat.loss_percent),
        ]
        for stat in parsed
    ]
    logger.info(
        "%s:\n%s",
        header,
        tabulate(
            table_rows,
            headers=[
                'Snappi flow name',
                'display_name',
                'Priority',
                'Tx port',
                'Rx port',
                'Tx frames',
                'Rx frames',
                'Loss',
            ],
            tablefmt='psql',
        ),
    )
    return parsed


def run_m2o_oversubscribe_lossless_test(api,
                                        testbed_config,
                                        port_config_list,
                                        conn_data,
                                        fanout_data,
                                        dut_port,
                                        pause_prio_list,
                                        test_prio_list,
                                        bg_prio_list,
                                        prio_dscp_map,
                                        snappi_extra_params=None):
    """
    Run PFC oversubsription lossless for many to one traffic pattern

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        pause_prio_list (list): priorities to pause for PFC pause storm
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority)
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        N/A
    """
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # initialize the (duthost, port) set.
    dut_asics_to_be_configured = set()

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    rx_port_id_list = [rx_port["port_id"]]
    egress_duthost = rx_port['duthost']
    dut_asics_to_be_configured.add((egress_duthost, rx_port['asic_value']))

    # Append the egress here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.egress_duthosts.append(egress_duthost)

    tx_port = [snappi_extra_params.multi_dut_params.multi_dut_ports[1],
               snappi_extra_params.multi_dut_params.multi_dut_ports[2]]

    # Append the ingress here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(tx_port[0]['duthost'])
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(tx_port[1]['duthost'])

    tx_port_id_list = [tx_port[0]["port_id"], tx_port[1]["port_id"]]
    # add ingress DUT into the set
    dut_asics_to_be_configured.add((tx_port[0]['duthost'], tx_port[0]['asic_value']))
    dut_asics_to_be_configured.add((tx_port[1]['duthost'], tx_port[1]['asic_value']))

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    # Disable PFC watchdog on the rx side and tx side of the DUT
    for duthost, asic in dut_asics_to_be_configured:
        stop_pfcwd(duthost, asic)
        disable_packet_aging(duthost)

    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT)
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT)
    no_of_bg_streams = get_number_of_streams(egress_duthost, tx_port, rx_port)
    port_id = 0
    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)
    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  rx_port_id_list=rx_port_id_list,
                  tx_port_id_list=tx_port_id_list,
                  pause_flow_name=PAUSE_FLOW_NAME,
                  pause_prio_list=pause_prio_list,
                  test_flow_name=TEST_FLOW_NAME,
                  test_flow_prio_list=test_prio_list,
                  test_flow_rate_percent=test_flow_rate_percent,
                  bg_flow_name=BG_FLOW_NAME,
                  bg_flow_prio_list=bg_prio_list,
                  bg_flow_rate_percent=bg_flow_rate_percent,
                  data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                  data_pkt_size=DATA_PKT_SIZE,
                  prio_dscp_map=prio_dscp_map,
                  no_of_bg_streams=no_of_bg_streams,
                  snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    """ Run traffic """
    flow_stats, switch_flow_stats, _ = run_traffic(duthost=egress_duthost,
                                                   api=api,
                                                   config=testbed_config,
                                                   data_flow_names=data_flow_names,
                                                   all_flow_names=all_flow_names,
                                                   exp_dur_sec=DATA_FLOW_DURATION_SEC + DATA_FLOW_DELAY_SEC,
                                                   snappi_extra_params=snappi_extra_params)

    dut_tx_port = rx_port['peer_port']
    ingress_dut1 = tx_port[0]['duthost']
    ingress_dut2 = tx_port[1]['duthost']
    ingress_port1 = tx_port[0]['peer_port']
    ingress_port2 = tx_port[1]['peer_port']
    # Fetch relevant statistics
    pkt_drop = get_interface_stats(egress_duthost, dut_tx_port)[egress_duthost.hostname][dut_tx_port]['tx_drp']
    rx_pkts_1 = get_interface_stats(ingress_dut1, ingress_port1)[ingress_dut1.hostname][ingress_port1]['rx_ok']
    rx_pkts_2 = get_interface_stats(ingress_dut2, ingress_port2)[ingress_dut2.hostname][ingress_port2]['rx_ok']
    # Calculate the total received packets
    total_rx_pkts = rx_pkts_1 + rx_pkts_2
    # Calculate the drop percentage
    drop_percentage = 100 * pkt_drop / total_rx_pkts
    pytest_assert(round(drop_percentage) == 0, 'FAIL: There should be no packet drops in ingress dut counters')

    """ Verify Results """
    verify_m2o_oversubscribe_lossless_result(flow_stats,
                                             tx_port,
                                             rx_port,
                                             snappi_extra_params=snappi_extra_params)


def __gen_traffic(testbed_config,
                  port_config_list,
                  rx_port_id_list,
                  tx_port_id_list,
                  pause_flow_name,
                  pause_prio_list,
                  test_flow_name,
                  test_flow_prio_list,
                  test_flow_rate_percent,
                  bg_flow_name,
                  bg_flow_prio_list,
                  bg_flow_rate_percent,
                  data_flow_dur_sec,
                  data_pkt_size,
                  prio_dscp_map,
                  no_of_bg_streams,
                  snappi_extra_params):
    """
    Generate configurations of flows under all to all traffic pattern, including
    test flows, background flows and pause storm. Test flows and background flows
    are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        pause_flow_name (str): name of pause storm
        pause_prio_list (list): priorities to pause for PFC frames
        test_flow_name (str): name prefix of test flows
        test_prio_list (list): priorities of test flows
        test_flow_rate_percent (int): rate percentage for each test flow
        bg_flow_name (str): name prefix of background flows
        bg_prio_list (list): priorities of background flows
        bg_flow_rate_percent (int): rate percentage for each background flow
        data_flow_dur_sec (int): duration of data flows in second
        pfc_storm_dur_sec (float): duration of the pause storm in second
        data_pkt_size (int): packet size of data flows in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """
    __gen_data_flows(testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     src_port_id_list=tx_port_id_list,
                     dst_port_id_list=rx_port_id_list,
                     flow_name_prefix=TEST_FLOW_NAME,
                     flow_prio_list=test_flow_prio_list,
                     flow_rate_percent=test_flow_rate_percent,
                     flow_dur_sec=data_flow_dur_sec,
                     data_pkt_size=data_pkt_size,
                     prio_dscp_map=prio_dscp_map,
                     snappi_extra_params=snappi_extra_params,
                     no_of_streams=1)

    __gen_data_flows(testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     src_port_id_list=tx_port_id_list,
                     dst_port_id_list=rx_port_id_list,
                     flow_name_prefix=BG_FLOW_NAME,
                     flow_prio_list=bg_flow_prio_list,
                     flow_rate_percent=bg_flow_rate_percent,
                     flow_dur_sec=data_flow_dur_sec,
                     data_pkt_size=data_pkt_size,
                     prio_dscp_map=prio_dscp_map,
                     snappi_extra_params=snappi_extra_params,
                     no_of_streams=no_of_bg_streams)


def __gen_data_flows(testbed_config,
                     port_config_list,
                     src_port_id_list,
                     dst_port_id_list,
                     flow_name_prefix,
                     flow_prio_list,
                     flow_rate_percent,
                     flow_dur_sec,
                     data_pkt_size,
                     prio_dscp_map,
                     snappi_extra_params,
                     no_of_streams=1):
    """
    Generate the configuration for data flows

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        src_port_id_list (list): IDs of source ports
        dst_port_id_list (list): IDs of destination ports
        flow_name_prefix (str): prefix of flows' names
        flow_prio_list (list): priorities of data flows
        flow_rate_percent (int): rate percentage for each flow
        flow_dur_sec (int): duration of each flow in second
        data_pkt_size (int): packet size of data flows in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """
    for src_index, src_port_id in enumerate(src_port_id_list):
        for dst_port_id in dst_port_id_list:
            if src_port_id == dst_port_id:
                continue
            __gen_data_flow(testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            src_port_id=src_port_id,
                            dst_port_id=dst_port_id,
                            flow_name_prefix=flow_name_prefix,
                            flow_prio=flow_prio_list,
                            flow_rate_percent=flow_rate_percent,
                            flow_dur_sec=flow_dur_sec,
                            data_pkt_size=data_pkt_size,
                            prio_dscp_map=prio_dscp_map,
                            snappi_extra_params=snappi_extra_params,
                            src_index=src_index,
                            num_src_ports=len(src_port_id_list),
                            no_of_streams=no_of_streams)


def __gen_data_flow(testbed_config,
                    port_config_list,
                    src_port_id,
                    dst_port_id,
                    flow_name_prefix,
                    flow_prio,
                    flow_rate_percent,
                    flow_dur_sec,
                    data_pkt_size,
                    prio_dscp_map,
                    snappi_extra_params,
                    src_index,
                    num_src_ports,
                    no_of_streams):
    """
    Generate the configuration for a data flow

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        src_port_id (int): ID of the source port
        dst_port_id (int): ID of destination port
        flow_name_prefix (str): prefix of flow' name
        flow_prio_list (list): priorities of the flow
        flow_rate_percent (int): rate percentage for the flow
        flow_dur_sec (int): duration of the flow in second
        data_pkt_size (int): packet size of the flow in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        src_index (int): position of the source port in the source port list
        num_src_ports (int): number of source (MACsec) ports
        no_of_streams (int): number of UDP streams for the flow

    Returns:
        N/A
    """
    ptype = "--snappi_macsec" in sys.argv
    tx_port_config = next((x for x in port_config_list if x.id == src_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == dst_port_id), None)
    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and tx_port_config.prefix_len == rx_port_config.prefix_len:
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    flow = testbed_config.flows.flow(name='{} {} -> {}'.format(flow_name_prefix, src_port_id, dst_port_id))[-1]

    # Priority used by this flow: first priority for the flow from port 1, second for port 2
    if 'Flow 1 -> 0' in flow.name:
        prio = flow_prio[0]
    elif 'Flow 2 -> 0' in flow.name:
        prio = flow_prio[1]
    else:
        prio = flow_prio[src_index]

    if ptype:
        # MACsec devices of the tx ports are the last devices in the config; the rx port has
        # MACSEC_DEVICES_PER_TX_PORT non-MACsec devices per tx port, one per priority.
        tx_device = testbed_config.devices[len(testbed_config.devices) - num_src_ports + src_index]
        rx_device = testbed_config.devices[src_index * MACSEC_DEVICES_PER_TX_PORT + prio]
        flow.tx_rx.device.tx_names = [tx_device.ethernets[0].ipv4_addresses[0].name]
        flow.tx_rx.device.rx_names = [rx_device.ethernets[0].ipv4_addresses[0].name]
        flow.tx_rx.device.mode = flow.tx_rx.device.ONE_TO_ONE
        flow.packet.ethernet().ipv4()
        ipv4 = flow.packet[-1]
        eth = flow.packet[-2]
        eth.src.value = tx_mac
        eth.dst.value = rx_mac
        # if pfcQueueGroupSize == 8:
        if pfc_queue_group_size() == 8:
            eth.pfc_queue.value = prio
        else:
            eth.pfc_queue.value = pfcQueueValueDict[prio]
        # MACsec flow statistics are tracked per PGID, keep the flow -> PGID mapping for verification.
        # flow_name_prio_map is deliberately not filled here: run_traffic uses it to select the rows it
        # polls for 'flows stopped', which is not suitable for this multi-ingress topology. The priority
        # is derived from the PGID (macsec_priority) when parsing the statistics.
        snappi_extra_params.flow_name_stats_identity_map[flow.name] = (
            testbed_config.ports[src_port_id].name,
            testbed_config.ports[dst_port_id].name,
            macsec_pgid(src_index, prio),
        )
    else:
        flow.tx_rx.port.tx_name = testbed_config.ports[src_port_id].name
        flow.tx_rx.port.rx_name = testbed_config.ports[dst_port_id].name
        eth, ipv4, udp = flow.packet.ethernet().ipv4().udp()

        eth.src.value = tx_mac
        eth.dst.value = rx_mac
        # if pfcQueueGroupSize == 8:
        if pfc_queue_group_size() == 8:
            if 'Background Flow' in flow.name:
                eth.pfc_queue.value = 1
            elif 'Test Flow 1 -> 0' in flow.name:
                eth.pfc_queue.value = flow_prio[0]
            elif 'Test Flow 2 -> 0' in flow.name:
                eth.pfc_queue.value = flow_prio[1]
        else:
            # Adding queue values based on flow_priorities for both test and background flows.
            if 'Flow 1 -> 0' in flow.name:
                eth.pfc_queue.value = pfcQueueValueDict[flow_prio[0]]
            elif 'Flow 2 -> 0' in flow.name:
                eth.pfc_queue.value = pfcQueueValueDict[flow_prio[1]]

        global UDP_PORT_START
        src_port = UDP_PORT_START
        UDP_PORT_START += no_of_streams
        udp.src_port.increment.start = src_port
        udp.src_port.increment.step = 1
        udp.src_port.increment.count = no_of_streams

        ipv4.src.value = tx_port_config.ip
        ipv4.dst.value = gen_data_flow_dest_ip(rx_port_config.ip)

    flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(DATA_FLOW_DELAY_SEC))
    ipv4.priority.choice = ipv4.priority.DSCP
    # Background flows have dynamic lossy priorities.
    ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
    if ptype and len(ipv4.priority.dscp.phb.values) > 1:
        # Single DSCP value per MACsec flow so it maps to a single PGID
        ipv4.priority.dscp.phb.values = ipv4.priority.dscp.phb.values[:1]
    logger.info('{} prio {} queue {} dscp {}'.format(flow.name, prio, eth.pfc_queue.value,
                                                     ipv4.priority.dscp.phb.values))

    ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
    flow.size.fixed = data_pkt_size
    flow.rate.percentage = flow_rate_percent
    flow.duration.fixed_seconds.seconds = flow_dur_sec
    flow.metrics.enable = True
    flow.metrics.loss = True


def verify_m2o_oversubscribe_lossless_result(rows,
                                             tx_port,
                                             rx_port,
                                             snappi_extra_params=None):
    """
    Verifies the required loss % from the Traffic Items Statistics (non-MACsec) or
    from the IxNetwork Flow Statistics (MACsec)

    Args:
        rows (list): Traffic Item Statistics from snappi config (non-MACsec), or
            IxNetwork Flow Statistics rows (MACsec)
        tx_port (list): Ingress Ports
        rx_port : Egress Port
        snappi_extra_params (SnappiTestParams obj): flow name to statistics identity / priority
            mappings (required for MACsec)
    Returns:
        N/A
    """
    if "--snappi_macsec" in sys.argv:
        pytest_assert(snappi_extra_params is not None,
                      "FAIL: snappi_extra_params is required to verify MACsec statistics")
        identity_map = snappi_extra_params.flow_name_stats_identity_map
        assert_macsec_flow_stat_identities_disjoint(identity_map)
        parsed_stats = log_macsec_flow_statistics(rows, identity_map)

        missing_identities = get_missing_macsec_flow_identities(parsed_stats, identity_map)
        pytest_assert(
            not missing_identities,
            "FAIL: No transmitting MACsec statistics rows for flows {}".format(
                sorted(missing_identities)))

        for stat in parsed_stats:
            pytest_assert(
                stat.tx_frames == stat.rx_frames,
                "FAIL: {} lost {} frames ({:.2f}% loss)".format(
                    stat.display_name,
                    stat.tx_frames - stat.rx_frames,
                    stat.loss_percent,
                ))
    else:
        for row in rows:
            if 'Test Flow 1 -> 0' in row.name:
                pytest_assert(int(row.loss) == 0, "{} must have 0% loss and having {}% loss".format(row.name, row.loss))
            elif 'Test Flow 2 -> 0' in row.name:
                pytest_assert(int(row.loss) == 0, "{} must have 0% loss and having {}% loss".format(row.name, row.loss))
            elif 'Background Flow 1 -> 0' in row.name:
                pytest_assert(int(row.loss) == 0, "{} must have 0% loss and having {}% loss".format(row.name, row.loss))
            elif 'Background Flow 2 -> 0' in row.name:
                pytest_assert(int(row.loss) == 0, "{} must have 0% loss and having {}% loss".format(row.name, row.loss))
