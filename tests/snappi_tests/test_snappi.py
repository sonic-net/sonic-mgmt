import time
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts                  # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config   # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.port import select_ports
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map  # noqa F401

SNAPPI_POLL_DELAY_SEC = 2

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.disable_loganalyzer
def __gen_all_to_all_traffic(testbed_config,
                             port_config_list,
                             dut_hostname,
                             conn_data,
                             fanout_data,
                             priority,
                             prio_dscp_map):        # noqa F811

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

            eth, ipv4 = flow.packet.ethernet().ipv4()
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


def test_snappi(snappi_api,                     # noqa F811
                snappi_testbed_config,          # noqa F811
                conn_graph_facts,               # noqa F811
                fanout_graph_facts,             # noqa F811
                rand_one_dut_lossless_prio,
                prio_dscp_map):                 # noqa F811
    """
    Test if we can use Snappi API generate traffic in a testbed

    Args:
        snappi_api (pytest fixture): Snappi session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        rand_one_dut_lossless_prio (str): name of lossless priority to test
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)

    Returns:
        N/A
    """
    testbed_config, port_config_list = snappi_testbed_config
    dut_hostname, lossless_prio = rand_one_dut_lossless_prio.split('|')

    pytest_require(len(port_config_list) >= 2, "This test requires at least 2 ports")

    config = __gen_all_to_all_traffic(testbed_config=testbed_config,
                                      port_config_list=port_config_list,
                                      dut_hostname=dut_hostname,
                                      conn_data=conn_graph_facts,
                                      fanout_data=fanout_graph_facts,
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
    wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)

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
