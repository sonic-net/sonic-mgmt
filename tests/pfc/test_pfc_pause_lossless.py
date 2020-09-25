import logging
import time
import pytest

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts

from tests.common.helpers.assertions import pytest_assert

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, ixia_api_server_session

from tests.common.ixia.ixia_helpers import configure_ports,\
    create_topology, start_protocols, create_ipv4_traffic,\
    create_pause_traffic, start_traffic, stop_traffic,\
    get_traffic_statistics, IxiaFanoutManager, clean_configuration

from tests.common.ixia.common_helpers import get_vlan_subnet, \
    get_addrs_in_subnet

#from tests.rdma.files.qos_fixtures import lossless_prio_dscp_map
from files.qos_fixtures import lossless_prio_dscp_map

pytestmark = [pytest.mark.disable_loganalyzer]

# Data packet size in bytes.
DATA_PKT_SIZE = 1024
START_DELAY = 1.5
RATE_PERCENTAGE = 50
TOLERANCE_THRESHOLD = .97

def run_pfc_exp(session, dut, tx_port, rx_port, port_bw, test_prio_list,
                test_dscp_list, bg_dscp_list, exp_dur, start_delay=START_DELAY,
                test_traffic_pause_expected=True,
                send_pause_frame=True) :
    """
    Run a PFC experiment.
    1. IXIA sends test traffic and background traffic from tx_port.
    2. IXIA sends PFC pause frames from rx_port to pause priorities.
    3. Background traffic should not be interruped - all background traffic
       will be received at the rx_port.
    4. No test traffic will be received at the rx_port when pause priority
       is equal to test traffic priority.

    Note: PFC pause frames should always be dropped, regardless of their
          pause priorities.

    Args:
        session (IxNetwork Session object): IxNetwork session.
        dut (object): Ansible instance of SONiC device under test (DUT).
        tx_port (object Ixia vport): IXIA port to transmit traffic.
        rx_port (object Ixia vport): IXIA port to receive traffic.
        port_bw (int): bandwidth (in Mbps) of tx_port and rx_port.
        test_prio_list (list of integers): PFC priorities of test traffic and
            PFC pause frames.
        test_dscp_list (list of integers): DSCP values of test traffic.
        bg_dscp_list (list of integers): DSCP values of background traffic.
        exp_dur (integer): experiment duration in second.
        start_delay (float): approximated initial delay to start the traffic.
        test_traffic_pause_expected (bool): Do you expect test traffic to
            be stopped? If yes, this should be true; false otherwise.
        send_pause_frame (bool): True/False depending on whether you want to
           send pause frame Rx port or not.

    Returns:
        This function returns nothing.
    """

    # Disable DUT's PFC watchdog.
    dut.shell('sudo pfcwd stop')

    vlan_subnet = get_vlan_subnet(dut)
    pytest_assert(vlan_subnet is not None,
                  "Fail to get Vlan subnet information")

    gw_addr = vlan_subnet.split('/')[0]
    # One for sender and the other one for receiver.
    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)

    topo_receiver = create_topology(session=session,
                                    name="Receiver",
                                    ports=list(rx_port),
                                    ip_start=vlan_ip_addrs[0],
                                    ip_incr_step='0.0.0.1',
                                    gw_start=gw_addr,
                                    gw_incr_step='0.0.0.0')

    # Assumption: Line rate percentage of background data traffic
    # is equal to Line rate percentage of test data traffic.
    pytest_assert(2 * RATE_PERCENTAGE <= 100,
        "Value of RATE_PERCENTAGE should not be more than 50!")

    topo_sender = create_topology(session=session,
                                  name="Sender",
                                  ports=list(tx_port),
                                  ip_start=vlan_ip_addrs[1],
                                  ip_incr_step='0.0.0.1',
                                  gw_start=gw_addr,
                                  gw_incr_step='0.0.0.0')
    start_protocols(session)

    test_traffic = create_ipv4_traffic(session=session,
                                       name='Test Data Traffic',
                                       source=topo_sender,
                                       destination=topo_receiver,
                                       pkt_size=DATA_PKT_SIZE,
                                       duration=exp_dur,
                                       rate_percent=RATE_PERCENTAGE,
                                       start_delay=start_delay,
                                       dscp_list=test_dscp_list,
                                       lossless_prio_list=test_prio_list)

    bg_priority_list = [b for b in range(8) if b not in test_prio_list]
    background_traffic = create_ipv4_traffic(session=session,
                                             name='Background Data Traffic',
                                             source=topo_sender,
                                             destination=topo_receiver,
                                             pkt_size=DATA_PKT_SIZE,
                                             duration=exp_dur,
                                             rate_percent=RATE_PERCENTAGE,
                                             start_delay=start_delay,
                                             dscp_list=bg_dscp_list,
                                             lossless_prio_list=bg_priority_list)

    # Pause time duration (in second) for each PFC pause frame.
    pause_dur_per_pkt = 65535 * 64 * 8.0 / (port_bw * 1000000)

    # Do not specify duration here as we want it keep running.
    if send_pause_frame:
        pfc_traffic = create_pause_traffic(session=session,
                                           name='PFC Pause Storm',
                                           source=rx_port,
                                           pkt_per_sec=1.1/pause_dur_per_pkt,
                                           start_delay=0,
                                           global_pause=False,
                                           pause_prio_list=test_prio_list)

    start_traffic(session)

    # Wait for test and background traffic to finish.
    time.sleep(exp_dur + start_delay + 1)

    # Capture traffic statistics.
    flow_statistics = get_traffic_statistics(session)
    logger.info(flow_statistics)

    exp_tx_bytes = (exp_dur * port_bw * 1000000 * (RATE_PERCENTAGE / 100.0)) / 8
    for row_number, flow_stat in enumerate(flow_statistics.Rows):
        tx_frames = int(flow_stat['Tx Frames'])
        rx_frames = int(flow_stat['Rx Frames'])
        rx_bytes  = int(flow_stat['Rx Bytes'])

        tolerance_ratio = rx_bytes / exp_tx_bytes
        if 'Test' in flow_stat['Traffic Item']:
            if test_traffic_pause_expected:
                pytest_assert(tx_frames > 0 and rx_frames == 0,
                    "Test traffic should be fully paused")
            else:
                pytest_assert(tx_frames > 0 and tx_frames == rx_frames,
                    "Test traffic packets should not be dropped")

                if ((tolerance_ratio < TOLERANCE_THRESHOLD) or
                    (tolerance_ratio > 1)) :
                    logger.error("Expected Tx/Rx = %s actual Rx = %s"
                        %(exp_tx_bytes, rx_bytes))

                    logger.error("tolerance_ratio = %s" %(tolerance_ratio))

                    pytest_assert(False,
                        "expected % of packets not received at the RX port")

        elif 'PFC' in flow_stat['Traffic Item']:
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                "PFC packets should be dropped")
        else:
            pytest_assert(tx_frames > 0 and tx_frames == rx_frames,
                "Background traffic should not be impacted")

            if ((tolerance_ratio < TOLERANCE_THRESHOLD) or
                (tolerance_ratio > 1)) :
                logger.error("Expected Tx/Rx = %s actual Rx = %s"
                    %(exp_tx_bytes, rx_bytes))

                logger.error("tolerance_ratio = %s" %(tolerance_ratio))

                pytest_assert(False,
                    "expected % of packets not received at the RX port")

    stop_traffic(session)


def test_pfc_pause_single_lossless_priority(conn_graph_facts,
                                            lossless_prio_dscp_map,
                                            duthost,
                                            ixia_dev,
                                            ixia_api_server_session,
                                            fanout_graph_facts):
    """
    RDMA PFC - Pauses on single lossless priority.
    1. On SONiC DUT enable PFC on any priorities Pi. (0 <= i <= 7).
    2. Disable the PFC watchdog on the SONiC DUT.
    3. On the Ixia Tx port create two flows - a) 'Test Data Traffic' and
       b) 'Background Data traffic'.
    4. The flow 'Test Data Traffic' can assume one of the lossless priority
       values Pi.
    5. The flow 'Background Data Traffic' can assume all the priority values
       which are not in 'Test Data Traffic'. For example if the priority of
       'Test Data Traffic' is 3, the priorities of the 'Background Data
       Traffic' should be 0, 1, 2, 4, 5, 6, 7.
    6. From Rx port send pause frames on priority Pi. Such that priority of
       'Test Data Traffic' at Tx end == Pause Priority at Rx end. That is,
       send pause frames on priority Pi.
    7. Start 'Test Data Traffic' and 'Background Data Traffic'.
    8. Repeat step 6 and 7 for each lossless priorities.
    9. Expected result -
       a. No 'Test Data Traffic' will flow. Since priority of
          'Test Data Traffic' equals to the priority of PFC pause frames.
       b. 'Background Data Traffic' will always flow.

    Note: Test and background traffic should be started after PFC pause storm.

    """
    port_list = list()
    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number=0)
    device_conn = conn_graph_facts['device_conn']

    for intf in fanout_devices.get_ports():
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed'])
        port_list.append(intf)

    # The topology should have at least two interfaces.
    pytest_assert(len(device_conn) >= 2,
        "The topology should have at least two interfaces")

    # Test pausing each lossless priority individually.
    session = ixia_api_server_session
    for prio in lossless_prio_dscp_map:
        for i in range(len(port_list)):
            for send_pause_frame in [True, False]:
                paused = send_pause_frame
                vports = configure_ports(session, port_list)

                rx_id = i
                tx_id = (i + 1) % len(port_list)

                rx_port = vports[rx_id]
                tx_port = vports[tx_id]
                rx_port_bw = port_list[rx_id]['speed']
                tx_port_bw = port_list[tx_id]['speed']

                pytest_assert(rx_port_bw == tx_port_bw)

                # All the DSCP values mapped to this priority.
                test_dscp_list = lossless_prio_dscp_map[prio]
                # The other DSCP values.
                bg_dscp_list = [x for x in range(64) if x not in test_dscp_list]

                exp_dur = 2

                run_pfc_exp(session=session,
                        dut=duthost,
                        tx_port=tx_port,
                        rx_port=rx_port,
                        port_bw=tx_port_bw,
                        test_prio_list=[prio],
                        test_dscp_list=test_dscp_list,
                        bg_dscp_list=bg_dscp_list,
                        exp_dur=exp_dur,
                        test_traffic_pause_expected=paused,
                        send_pause_frame=send_pause_frame)

                clean_configuration(session=session)


def test_pfc_pause_multi_lossless_priorities(conn_graph_facts,
                                             lossless_prio_dscp_map,
                                             duthost,
                                             ixia_dev,
                                             ixia_api_server_session,
                                             fanout_graph_facts):
    """
    RDMA PFC - Pauses on multiple lossless priorities.
    1. On SONiC DUT enable PFC on several priorities e.g priority 3 and 4.
    2. Disable the PFC watchdog on the SONiC DUT.
    3. On the Ixia Tx port create two flows - a) 'Test Data Traffic' and
       b) 'Background Data traffic'.
    4. Configure 'Test Data Traffic' such that it contains traffic items
       with all lossless priorities.
    5. Configure 'Background Data Traffic' it contains traffic items with
       all lossy priorities.
    6. From Rx port send pause frames on all lossless priorities. Then
       start 'Test Data Traffic' and 'Background Data Traffic'.
    7. When pause frames are started 'Test Data Traffic' will stop;
       and when pause frames are stopped 'Test Data Traffic' will start.
    8. 'Background Data Traffic' will always flow.
    9. Repeat the steps 4 to 8 on all ports.

    """
    port_list = list()
    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number=0)
    device_conn = conn_graph_facts['device_conn']

    for intf in fanout_devices.get_ports():
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed'])
        port_list.append(intf)

    # The topology should have at least two interfaces.
    pytest_assert(len(device_conn) >= 2,
        "The topology should have at least two interfaces")

    session = ixia_api_server_session
    for i in range(len(port_list)):
        for send_pause_frame in [True, False]:
            paused = send_pause_frame
            vports = configure_ports(session, port_list)

            rx_id = i
            tx_id = (i + 1) % len(port_list)

            rx_port = vports[rx_id]
            tx_port = vports[tx_id]
            rx_port_bw = port_list[rx_id]['speed']
            tx_port_bw = port_list[tx_id]['speed']
            pytest_assert(rx_port_bw == tx_port_bw)

            test_dscp_list = []
            test_priority_list = [prio for prio in lossless_prio_dscp_map]
            for prio in lossless_prio_dscp_map:
                test_dscp_list += lossless_prio_dscp_map[prio]

            bg_dscp_list = [x for x in range(64) if x not in test_dscp_list]
            exp_dur = 2


            run_pfc_exp(session=session,
                        dut=duthost,
                        tx_port=tx_port,
                        rx_port=rx_port,
                        port_bw=tx_port_bw,
                        test_prio_list=test_priority_list,
                        test_dscp_list=test_dscp_list,
                        bg_dscp_list=bg_dscp_list,
                        exp_dur=exp_dur,
                        test_traffic_pause_expected=paused,
                        send_pause_frame=send_pause_frame)

            clean_configuration(session=session)

