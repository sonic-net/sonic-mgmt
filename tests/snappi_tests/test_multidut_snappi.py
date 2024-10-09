import time
import pytest
import random
import logging
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut      # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, snappi_api, \
    snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config      # noqa: F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.port import select_ports
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map  # noqa: F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
logger = logging.getLogger(__name__)
SNAPPI_POLL_DELAY_SEC = 2

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.disable_loganalyzer
def __gen_all_to_all_traffic(testbed_config,
                             port_config_list,
                             conn_data,
                             fanout_data,
                             priority,
                             prio_dscp_map              # noqa: F811
                             ):

    rate_percent = 100 / (len(port_config_list) - 1)
    duration_sec = 2
    pkt_size = 1024

    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern="all to all",
                                                    rx_port_id=0)
    for tx_port_id in tx_port_id_list:
        for rx_port_id in rx_port_id_list:
            if tx_port_id == rx_port_id:
                continue

            tx_port_config = next((x for x in port_config_list if x.id == tx_port_id), None)
            rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)
            tx_mac = tx_port_config.mac
            if tx_port_config.gateway == rx_port_config.gateway and \
               tx_port_config.prefix_len == rx_port_config.prefix_len:
                """ If soruce and destination port are in the same subnet """
                rx_mac = rx_port_config.mac
            else:
                rx_mac = tx_port_config.gateway_mac

            tx_port_name = testbed_config.ports[tx_port_id].name
            rx_port_name = testbed_config.ports[rx_port_id].name

            flow = testbed_config.flows.flow(
                name="Flow {} -> {}".format(tx_port_id, rx_port_id))[-1]

            flow.tx_rx.port.tx_name = tx_port_name
            flow.tx_rx.port.rx_name = rx_port_name

            eth, ipv4, udp = flow.packet.ethernet().ipv4().udp()
            src_port = random.randint(5000, 6000)
            udp.src_port.increment.start = src_port
            udp.src_port.increment.step = 1
            udp.src_port.increment.count = 1

            eth.src.value = tx_mac
            eth.dst.value = rx_mac
            eth.pfc_queue.value = priority

            ipv4.src.value = tx_port_config.ip
            ipv4.dst.value = rx_port_config.ip
            ipv4.priority.choice = ipv4.priority.DSCP
            ipv4.priority.dscp.phb.values = prio_dscp_map[priority]
            ipv4.priority.dscp.ecn.value = (
                ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
            )

            flow.size.fixed = pkt_size
            flow.rate.percentage = rate_percent
            flow.duration.fixed_seconds.seconds = duration_sec

            flow.metrics.enable = True
            flow.metrics.loss = True

    return testbed_config


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_snappi(request,
                duthosts,
                snappi_api,                         # noqa: F811
                conn_graph_facts,                  # noqa: F811
                fanout_graph_facts_multidut,               # noqa: F811
                lossless_prio_list,    # noqa: F811
                get_snappi_ports,      # noqa: F811
                tbinfo,      # noqa: F811
                multidut_port_info,
                prio_dscp_map,                                                  # noqa: F811
                ):

    """
    Test if we can use Snappi API to generate traffic in a testbed

    Args:
        snappi_api (pytest fixture): Snappi session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
        pytest_assert(len(snappi_port_list) >= tx_port_count + rx_port_count,
                      "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

        pytest_assert(len(rdma_ports['tx_ports']) >= tx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_assert(len(rdma_ports['rx_ports']) >= rx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))
        snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                 tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio)

    pytest_require(len(port_config_list) >= 2, "This test requires at least 2 ports")

    config = __gen_all_to_all_traffic(testbed_config=testbed_config,
                                      port_config_list=port_config_list,
                                      conn_data=conn_graph_facts,
                                      fanout_data=fanout_graph_facts_multidut,
                                      priority=int(lossless_prio),
                                      prio_dscp_map=prio_dscp_map)

    pkt_size = config.flows[0].size.fixed
    rate_percent = config.flows[0].rate.percentage
    duration_sec = config.flows[0].duration.fixed_seconds.seconds

    port_speed = config.layer1[0].speed
    words = port_speed.split('_')
    pytest_assert(len(words) == 3 and words[1].isdigit(),
                  'Fail to get port speed from {}'.format(port_speed))

    port_speed_gbps = int(words[1])

    # """ Apply configuration """
    snappi_api.set_config(config)

    # """Wait for Arp"""
    wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=2)

    # """ Start traffic """
    ts = snappi_api.transmit_state()
    ts.state = ts.START
    snappi_api.set_transmit_state(ts)

    # """ Wait for traffic to finish """
    time.sleep(duration_sec)

    attempts = 0
    max_attempts = 20
    all_flow_names = [flow.name for flow in config.flows]

    while attempts < max_attempts:
        request = snappi_api.metrics_request()
        request.flow.flow_names = all_flow_names
        rows = snappi_api.get_metrics(request).flow_metrics

        """ If all the data flows have stopped """
        transmit_states = [row.transmit for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(2)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump per-flow statistics """
    request = snappi_api.metrics_request()
    request.flow.flow_names = all_flow_names
    rows = snappi_api.get_metrics(request).flow_metrics

    ts = snappi_api.transmit_state()
    ts.state = ts.STOP
    snappi_api.set_transmit_state(ts)

    """ Analyze traffic results """
    for row in rows:
        flow_name = row.name
        rx_frames = row.frames_rx
        tx_frames = row.frames_tx

        pytest_assert(rx_frames == tx_frames,
                      'packet losses for {} (Tx: {}, Rx: {})'.
                      format(flow_name, tx_frames, rx_frames))

        tput_bps = port_speed_gbps * 1e9 * rate_percent / 100.0
        exp_rx_frames = tput_bps * duration_sec / 8 / pkt_size

        deviation_thresh = 0.05
        ratio = float(exp_rx_frames) / rx_frames
        deviation = abs(ratio - 1)

        pytest_assert(deviation <= deviation_thresh,
                      'Expected / Actual # of pkts for flow {}: {} / {}'.
                      format(flow_name, exp_rx_frames, rx_frames))
