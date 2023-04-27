import time
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi.snappi_helpers import get_dut_port_id
from tests.common.snappi.common_helpers import disable_packet_aging
from tests.common.snappi.port import select_ports, select_tx_port
from tests.common.snappi.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)

FLOW_NAME = 'IP-IP Test Flow'
FLOW_AGGR_RATE_PERCENT = 95
LARGER_PKT_SIZE = 512
SMALLER_PKT_SIZE = 256
PKT_STEP_SIZE = LARGER_PKT_SIZE - SMALLER_PKT_SIZE
UDP_SRC_PORT = 63
UDP_DST_PORT = 63
UDP_PKT_LEN = 190
TOTAL_NUM_PKTS = 100000
EXP_FLOW_DUR_SEC = 3
PKT_SEND_DELAY = 2
SNAPPI_POLL_DELAY_SEC = 2
OUTER_PKT_SRC_IP = "15.0.20.20"
OUTER_PKT_DST_IP = "16.0.20.20"
STATIC_SRC_IP = "15.0.20.0"
STATIC_DST_IP = "16.0.20.0"
INNER_PKT_SRC_IP = "20.0.20.0"
INNER_PKT_DST_IP = "21.0.20.0"
DUT_INGRESS_GW_IP = "30.0.30.10"
DUT_EGRESS_GW_IP = "31.0.30.10"
NEIGHBOR_EGRESS_INTF_IP = "30.0.30.20"
NEIGHBOR_INGRESS_INTF_IP = "31.0.30.20"
IP_SUBNET = 24


def run_ipip_packet_reorder_test(api,
                                 testbed_config,
                                 port_config_list,
                                 conn_data,
                                 fanout_data,
                                 duthost,
                                 dut_port,
                                 flow_prio_list,
                                 prio_dscp_map):
    """
    Run a IP-IP Packet Reorder Test
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

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    disable_packet_aging(duthost)

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    flow_rate_percent = int(FLOW_AGGR_RATE_PERCENT / len(flow_prio_list))

    # Generate traffic config
    __gen_traffic(duthost=duthost,
                  testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  port_id=port_id,
                  flow_name=FLOW_NAME,
                  flow_prio_list=flow_prio_list,
                  flow_rate_percent=flow_rate_percent,
                  total_tx_pkts=TOTAL_NUM_PKTS,
                  larger_pkt_size=LARGER_PKT_SIZE,
                  smaller_pkt_size=SMALLER_PKT_SIZE,
                  pkt_step_size=PKT_STEP_SIZE,
                  prio_dscp_map=prio_dscp_map)

    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]

    # Run traffic
    flow_metrics = __run_traffic(api=api,
                                 config=testbed_config,
                                 all_flow_names=all_flow_names,
                                 timeout=EXP_FLOW_DUR_SEC)

    # Verify results i.e. no out of order packets
    __verify_results(api=api,
                     flow_metrics=flow_metrics,
                     exp_rx_pkts=TOTAL_NUM_PKTS)


def sec_to_nanosec(sec):
    return sec * 1e9


def __gen_traffic(duthost,
                  testbed_config,
                  port_config_list,
                  port_id,
                  flow_name,
                  flow_prio_list,
                  flow_rate_percent,
                  total_tx_pkts,
                  larger_pkt_size,
                  smaller_pkt_size,
                  pkt_step_size,
                  prio_dscp_map):
    """
    Generate configurations of flows, and device configurations on both the DUT, and ixia device which
    emulates a neighbor.
    Args:
        duthost (Ansible host instance): device under test
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        flow_name (str): name of flow
        flow_prio_list (list): priorities of the flow
        flow_rate_percent (int): rate percentage for each flow
        total_tx_pkts (int): total number of packets to transmit
        larger_pkt_size (int): packet size of larger data flow in bytes
        smaller_pkt_size (int): packet size of smaller data flow in bytes
        pkt_step_size (int): packet size step of flow in bytes
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """

    rx_port_id = port_id
    tx_port_id_list, _ = select_ports(port_config_list=port_config_list,
                                      pattern="many to one",
                                      rx_port_id=rx_port_id)

    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")

    tx_port_config = next((port_tx for port_tx in port_config_list if port_tx.id == tx_port_id), None)
    rx_port_config = next((port_rx for port_rx in port_config_list if port_rx.id == rx_port_id), None)

    # Configure interfaces and gateway on DUT
    __configure_DUT(duthost=duthost,
                    ingress_intf=tx_port_config.peer_port,
                    egress_intf=rx_port_config.peer_port)

    tx_port_name = testbed_config.ports[tx_port_id].name
    rx_port_name = testbed_config.ports[rx_port_id].name

    # Begin configuring flows
    ipip_flow = testbed_config.flows.flow(name="{} Packet".format(flow_name))[-1]
    ipip_flow.tx_rx.port.tx_name = tx_port_name
    ipip_flow.tx_rx.port.rx_name = rx_port_name
    eth, outer_ipv4, inner_ipv4, udp = ipip_flow.packet.ethernet().ipv4().ipv4().udp()

    # Configure ethernet header
    eth.src.value = "00:AA:00:00:04:00"
    eth.dst.value = "00:AA:00:00:00:AA"

    # Configure outer IPv4 header
    outer_ipv4.src.value = OUTER_PKT_SRC_IP
    outer_ipv4.dst.value = OUTER_PKT_DST_IP
    outer_ipv4.identification.choice = "increment"
    outer_ipv4.identification.increment.start = 1
    outer_ipv4.identification.increment.step = 1
    outer_ipv4.identification.increment.count = total_tx_pkts
    outer_ipv4.priority.choice = outer_ipv4.priority.DSCP
    outer_ipv4.priority.dscp.ecn.value = (
        outer_ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

    # Configure inner IPv4 header
    inner_ipv4.src.value = INNER_PKT_SRC_IP
    inner_ipv4.dst.value = INNER_PKT_DST_IP
    inner_ipv4.priority.choice = inner_ipv4.priority.DSCP
    inner_ipv4.priority.dscp.ecn.value = (
        inner_ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

    # Configure UDP header
    udp.src_port.value = UDP_SRC_PORT
    udp.dst_port.value = UDP_DST_PORT
    udp.length.value = UDP_PKT_LEN

    # Configure the appropriate priorities for each header
    for prio in flow_prio_list:
        eth.pfc_queue.values.append(prio)
        outer_ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        inner_ipv4.priority.dscp.phb.values = prio_dscp_map[prio]

    # Configure packet size and other variables
    ipip_flow.size.increment.start = smaller_pkt_size
    ipip_flow.size.increment.end = larger_pkt_size
    ipip_flow.size.increment.step = pkt_step_size
    ipip_flow.rate.percentage = flow_rate_percent
    ipip_flow.duration.fixed_packets.packets = total_tx_pkts

    ipip_flow.metrics.enable = True
    ipip_flow.metrics.loss = True

    # Configure a neighbor device on the ixia device
    neighbor_device = testbed_config.devices.device(name="ixia_neighbor_device")[-1]

    # set up neighbor egress interface
    neighbor_egress_port = neighbor_device.ethernets.add()
    neighbor_egress_port.port_name = tx_port_name
    neighbor_egress_port.name = "Ethernet0_ixia_egress_port"
    neighbor_egress_port.mac = "00:AA:00:00:04:00"
    neighbor_egress_ipv4 = neighbor_egress_port.ipv4_addresses.add()
    neighbor_egress_ipv4.name = "ixia_egress_ipv4"
    #neighbor_egress_ipv4.gateway_mac.choice = "auto"
    neighbor_egress_ipv4.address = NEIGHBOR_EGRESS_INTF_IP
    neighbor_egress_ipv4.gateway = DUT_INGRESS_GW_IP
    neighbor_egress_ipv4.prefix = IP_SUBNET

    # set up neighbor ingress interface
    neighbor_ingress_port = neighbor_device.ethernets.add()
    neighbor_egress_port.port_name = rx_port_name
    neighbor_ingress_port.name = "Ethernet4_ixia_ingress_port"
    neighbor_ingress_port.mac = "00:AA:00:00:00:AA"
    neighbor_ingress_ipv4 = neighbor_ingress_port.ipv4_addresses.add()
    neighbor_ingress_ipv4.name = "ixia_ingress_ipv4"
    #neighbor_ingress_ipv4.gateway_mac.choice = "auto"
    neighbor_ingress_ipv4.address = NEIGHBOR_INGRESS_INTF_IP
    neighbor_ingress_ipv4.gateway = DUT_EGRESS_GW_IP
    neighbor_ingress_ipv4.prefix = IP_SUBNET


def __configure_DUT(duthost,
                    ingress_intf,
                    egress_intf):

    """
    Configure interface, gateway and static IP addresses on DUT
    Args:
        duthost (Ansible host instance): device under test
        ingress_intf (str): ingress interface on DUT connected to ixia neighbor device ex. Ethernet4
        egress_intf (str): egress interface on DUT connected to ixia neighbor device ex. Ethernet8
    Returns:
        N/A
    """

    # Configure IP gateway for both ingress and egress ports on DUT
    duthost.shell("sudo config interface ip add {} {}/{}".format(ingress_intf, DUT_INGRESS_GW_IP, IP_SUBNET))
    duthost.shell("sudo config interface ip add {} {}/{}".format(egress_intf, DUT_EGRESS_GW_IP, IP_SUBNET))

    # Confirm that the gateway is configured on the interface
    ingress_config = duthost.shell("redis-cli -n 4 KEYS '*INTERFACE|{}|{}*'"
                                   .format(ingress_intf, DUT_INGRESS_GW_IP))['stdout']
    egress_config = duthost.shell("redis-cli -n 4 KEYS '*INTERFACE|{}|{}*'"
                                  .format(egress_intf, DUT_EGRESS_GW_IP))['stdout']
    pytest_assert(ingress_config == "INTERFACE|{}|{}/{}".format(ingress_intf, DUT_INGRESS_GW_IP, IP_SUBNET),
                  "Ingress interface {} is not configured with gateway {}".format(ingress_intf, DUT_INGRESS_GW_IP))
    pytest_assert(egress_config == "INTERFACE|{}|{}/{}".format(egress_intf, DUT_EGRESS_GW_IP, IP_SUBNET),
                  "Egress interface {} is not configured with gateway {}".format(egress_intf, DUT_EGRESS_GW_IP))

    # Configure static IPs on each of the gateways
    duthost.shell("sudo config route add prefix {}/{} nexthop {}"
                  .format(STATIC_SRC_IP, IP_SUBNET, NEIGHBOR_EGRESS_INTF_IP))
    duthost.shell("sudo config route add prefix {}/{} nexthop {}"
                  .format(STATIC_DST_IP, IP_SUBNET, NEIGHBOR_INGRESS_INTF_IP))

    # Confirm that the static routes are configured on the DUT
    static_out_str = duthost.shell("redis-cli -n 4 KEYS '*STATIC_ROUTE*'")['stdout_lines']
    for static_route in static_out_str:
        pytest_assert(STATIC_SRC_IP in static_route or STATIC_DST_IP in static_route,
                      "Static route not configured on DUT")


def __run_traffic(api,
                  config,
                  all_flow_names,
                  timeout):

    """
    Run traffic and dump per-flow statistics
    Args:
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        timeout (int): time to wait in seconds before snappi begins recovering metrics
    Returns:
        flow_metrics (list): list of flow metrics
    """

    api.set_config(config)

    logger.info('Wait for Arp to Resolve ...')
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    logger.info('Starting transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    time.sleep(timeout)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = all_flow_names
        rows = api.get_metrics(request).flow_metrics

        """ If all the flows have stopped """
        transmit_states = [row.transmit for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump per-flow statistics """
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    flow_metrics = api.get_metrics(request).flow_metrics
    logger.info('Stop transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)

    return flow_metrics


def __verify_results(api,
                     flow_metrics,
                     exp_rx_pkts):
    """
    Verify if we get expected experiment results
    Args:
        api (obj): snappi session
        flow_metrics (list): per-flow statistics
        exp_rx_pkts (int): total number of packets to receive
    Returns:
        N/A
    """

    # calculate total frames sent and received across all configured ports
    total_tx = sum([flow_metric.frames_tx for flow_metric in flow_metrics])
    total_rx = sum([flow_metric.frames_rx for flow_metric in flow_metrics])

    pytest_assert(total_tx == total_rx, "Number of total Tx packets = {} and Rx packets = {} are not equal."
                  .format(total_tx, total_rx))
    pytest_assert(total_rx == exp_rx_pkts, "Number of total Rx packets = {} are not equal to expected packets = {}"
                  .format(total_rx, exp_rx_pkts))

    # check for packet re-order
    restpy_session = api.assistant.Session  # handler to ix-network RESTPy session
    for stat in (restpy_session.StatViewAssistant('Flow Statistics').Rows):
        small_error = stat["Small Error"]
        big_error = stat["Big Error"]

        pytest_assert(small_error == 0, "Packet re-ordering detected. Small error = {}".format(small_error))
        pytest_assert(big_error == 0, "Packet re-ordering detected. Big error = {}".format(big_error))
