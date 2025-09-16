import time
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.packet_trim_helpers import (
    apply_trim_mode,
    TrimMode,
    verify_trimmed_traffic,
)
from tests.common.snappi_tests.traffic_generation import (
    setup_base_traffic_config,
    generate_srv6_encap_flow,
    run_traffic,
    clear_dut_interface_counters,
    clear_dut_que_counters,
)
from tests.common.snappi_tests.common_helpers import traffic_flow_mode, check_tx_drp_counts

logger = logging.getLogger(__name__)

FLOW_NAME = 'Packet-Trim Data Flow'
TX_PORT_NAME = None
RX_PORT_NAME = None
FLOW_RATE_PERCENT = 100  # line rate for packet trimming tests
PKT_SIZE = 4096 # 4kB packet size
UDP_PKT_LEN = 190
TOTAL_NUM_PKTS = 65535
EXP_FLOW_DUR_SEC = 20
SNAPPI_POLL_DELAY_SEC = 2
INNER_PKT_SRC_IP = "20.0.20.0"
INNER_PKT_DST_IP = "21.0.20.0"
SEQUENCE_CHECKING_THRESHOLD = 1


def run_packet_trimming_test(api,
                             testbed_config,
                             port_config_list,
                             conn_data,
                             fanout_data,
                             duthost,
                             dut_port,
                             prio_dscp_map,
                             snappi_test_params,
                             trim_mode=TrimMode.SYMMETRIC,
                             ):
    """
    Run a Packet Trimming Test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        flow_prio_list (list): priorities of flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    # Traffic flow:
    # tx_port(s) (TGEN) --- ingress DUT --- egress DUT --- rx_port (TGEN)

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    if snappi_test_params is None:
        snappi_test_params = SnappiTestParams()

    # Get the ID of the port to test
    port_id = 0
    if duthost and dut_port:
        port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                                  dut_port=dut_port,
                                  conn_data=conn_data,
                                  fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    flow_rate_percent = int(FLOW_RATE_PERCENT)

    snappi_test_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                    port_config_list=port_config_list,
                                                                    port_id=port_id,
                                                                    num_tx_ports=snappi_test_params.num_tx_links,
                                                                    num_rx_ports=snappi_test_params.num_rx_links,
                                                                    )

    apply_trim_mode(duthost=duthost,
                    trim_mode=trim_mode,
                    snappi_test_params=snappi_test_params
                    )

    if snappi_test_params.traffic_flow_config.data_flow_config is None:
        snappi_test_params.traffic_flow_config.data_flow_config = {
            'flow_name': FLOW_NAME,
            'flow_dur_sec': EXP_FLOW_DUR_SEC,
            'flow_rate_percent': flow_rate_percent,
            'flow_rate_pps': None,
            'flow_rate_bps': None,
            'flow_pkt_size': PKT_SIZE,
            'flow_pkt_count': None,
            'flow_delay_sec': 0,
            'flow_traffic_type': traffic_flow_mode.FIXED_DURATION,
        }

    generate_srv6_encap_flow(testbed_config=testbed_config,
                             snappi_test_params=snappi_test_params,
                             )

    # Clear all counters before running traffic
    clear_dut_que_counters(duthost=duthost)
    time.sleep(1)
    clear_dut_interface_counters(duthost=duthost)
    time.sleep(1)

    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]


    tgen_flow_stats, switch_flow_stats, in_flight_flow_metrics = run_traffic(duthost=duthost,
                                                                             api=api,
                                                                             config=testbed_config,
                                                                             data_flow_names=all_flow_names,
                                                                             all_flow_names=all_flow_names,
                                                                             exp_dur_sec=EXP_FLOW_DUR_SEC,
                                                                             snappi_extra_params=snappi_test_params,
                                                                             )
    import pdb; pdb.set_trace()
    if isinstance(snappi_test_params.base_flow_config["rx_port_config"].peer_port, str):
        switch_egress_ports = [snappi_test_params.base_flow_config["rx_port_config"].peer_port]
    else:
        switch_egress_ports = [switch_egress_port for switch_egress_port in snappi_test_params.base_flow_config["rx_port_config"].peer_port]
    tx_drops, _ = check_tx_drp_counts(duthost=duthost,
                                      ports=switch_egress_ports,
                                      )
    pytest_assert(tx_drops, f"Expected TX drops on egress port(s) {switch_egress_ports} but none seen")

    verify_trimmed_traffic(duthost=duthost,
                           switch_egress_ports=switch_egress_ports,
                           snappi_extra_params=snappi_test_params,
                           trim_mode=trim_mode,
                           )
