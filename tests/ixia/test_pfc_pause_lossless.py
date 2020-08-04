from tests.common.reboot import logger
import logging
import time
import pytest
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

from tests.common.ixia.qos_fixtures import lossless_prio_dscp_map

pytestmark = [pytest.mark.disable_loganalyzer]

# Data packet size in bytes.
DATA_PKT_SIZE = 1024


def run_pfc_exp(session, dut, tx_port, rx_port, port_bw, test_prio_list,\
                test_dscp_list, bg_dscp_list, exp_dur, paused,
                global_pause=False) :
    """
    Run a PFC experiment.
    1. IXIA sends test traffic and background traffic from tx_port
    2. IXIA sends PFC pause frames from rx_port to pause priorities.
    3. Background traffic should not be interruped - all background traffic
       will be received at the rx_port.
    4. No PFC traffic will be received at the rx_port.

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
        paused (bool): If test traffic should be paused.

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
                                       rate_percent=50,
                                       start_delay=1,
                                       dscp_list=test_dscp_list,
                                       lossless_prio_list=test_prio_list)

    bg_priority_list = [b for b in range(8) if b not in test_prio_list]
    background_traffic = create_ipv4_traffic(session=session,
                                             name='Background Data Traffic',
                                             source=topo_sender,
                                             destination=topo_receiver,
                                             pkt_size=DATA_PKT_SIZE,
                                             duration=exp_dur,
                                             rate_percent=50,
                                             start_delay=1,
                                             dscp_list=bg_dscp_list,
                                             lossless_prio_list=bg_priority_list)

    # Pause time duration (in second) for each PFC pause frame.
    pause_dur_per_pkt = 65535 * 64 * 8.0 / (port_bw * 1000000)

    pfc_traffic = create_pause_traffic(session=session,
                                       name='PFC Pause Storm',
                                       source=rx_port,
                                       pkt_per_sec=1.1/pause_dur_per_pkt,
                                       start_delay=0,
                                       global_pause=global_pause,
                                       pause_prio_list=test_prio_list)

    start_traffic(session)

    # Wait for test and background traffic to finish.
    time.sleep(exp_dur + 1.5)

    # Capture traffic statistics.
    flow_statistics = get_traffic_statistics(session)
    logger.info(flow_statistics)

    for row_number, flow_stat in enumerate(flow_statistics.Rows):
        tx_frames = int(flow_stat['Tx Frames'])
        rx_frames = int(flow_stat['Rx Frames'])

        if 'Test' in flow_stat['Traffic Item']:
            if paused:
                pytest_assert(tx_frames > 0 and rx_frames == 0,
                    "Test traffic should be fully paused")
            else:
                pytest_assert(tx_frames > 0 and tx_frames == rx_frames,
                    "Test traffic should not be impacted")

        elif 'PFC' in flow_stat['Traffic Item']:
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                "PFC packets should be dropped")
        else:
            pytest_assert(tx_frames > 0 and tx_frames == rx_frames,
                "Background traffic should not be impacted")

    stop_traffic(session)


def test_pfc_pause_lossless(testbed, conn_graph_facts, lossless_prio_dscp_map,\
                            duthost, ixia_dev, ixia_api_server_session,\
                            fanout_graph_facts):
    """
    RDMA PFC - Pauses on lossless priorities.
    1. On SONiC DUT enable PFC on any two Traffic Classes (TC) say, m and n.
       0 <= m,n <= 7.
    2. Disable the PFC watchdog on the SONiC DUT.
    3. On the Ixia Tx port create two flows - a) 'Test Data Traffic' and
       b) 'Background Data traffic'.
    4. The flow 'Test Data Traffic' can assume only one of the TC values -
       either m or n.
    5. The flow 'Background Data Traffic' can assume all TC values that is
       not taken 'Test Data Traffic' (including m or n). That is:
       a. Background data traffic can assume TC value n if 'Test Data Traffic'
          has the TC value m.
       b. Background data traffic can assume TC value m if 'Test Data Traffic'
          has the TC value n.
    6. Start 'Test Data Traffic' and 'Background Data Traffic'
    7. From Rx port send pause frames on priorities either m or n. Such that
       TC of 'Test Data Traffic' at Tx end == Pause Priority at Rx end.
    8. You may repeat the steps 6 and 7 several times.

    9. Expected result - 
       a. No 'Test Data Traffic' will flow. Since priority of
          that is always equal to the priority pause frame priority.
       b. 'Background Data Traffic' will always flow.
    """

    port_list = list()
    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number = 0)

    device_conn = conn_graph_facts['device_conn']
    for intf in fanout_devices.get_ports():
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed']) * 100
        port_list.append(intf)

    # The topology should have at least two interfaces.
    pytest_assert(len(device_conn)>=2,
        "The topology should have at least two interfaces")

    # Test pausing each lossless priority individually.
    session = ixia_api_server_session
    for prio in lossless_prio_dscp_map:
        for i in range(len(port_list)):
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
                        paused=True)

            clean_configuration(session=session)


def test_pauses_on_lossy_priorities (testbed,
                                     conn_graph_facts,
                                     lossless_prio_dscp_map,
                                     duthost,
                                     ixia_dev,
                                     ixia_api_server_session,
                                     fanout_graph_facts) :
    """
    RDMA PFC - Pauses on lossy priorities.
    1. On SONiC DUT enable PFC on any two Traffic Classes (TC) say, m and n.
       0 <= m,n <= 7.
    2. Disable the PFC watchdog on the SONiC DUT.
    3. On the Ixia Tx port create two flows - a) 'Test Data Traffic' and
       b) 'Background Data Traffic'.
    4. TC of 'Test Data Traffic' can take any value except m and n 
       priorities. 'Background Data Traffic' has the traffic classes m & n.
    5. From Ixia Rx port send pause frames on all other TC except m and n.
    6. Start 'Test Data traffic' and 'Background Data Traffic'
    7. Verify the following:
       a. Traffic classes for which pause frame is send is not affected,
          packet loss is %0. That is - Test Data Traffic has 0% loss.
       b. Traffic classes for which pause frame is not send i.e. (
          including PFC enabled class m and n) also remains un-affected.
          That is -'Background Data Traffic' has 0% loss.
    8. Stop all traffic.
    9. Repeat the steps 5, 6 for all priorities except m and n.
    10. Expected - sending pauses on lossy traffic does not have effect the
        any of the traffic flows.

    Note: value of traffic classes 0 <= traffic classes <= 7
        Value of test traffic class = {x : <= x <= 7 and x <> m, n}
        Value of background traffic class = {y :  <= x <= 7 and y <> x}
        Value of test traffic dscp = {d : 0 <= d <= 63}
        Value of test traffic dscp = {d : 0 <= d <= 63}
        Currently in this test cases m = 3, n = 4.

    """
    port_list = list()
    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number = 0)

    device_conn = conn_graph_facts['device_conn']
    for intf in fanout_devices.get_ports():
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed']) * 100
        port_list.append(intf)

    # The topology should have at least two interfaces.
    pytest_assert(len(device_conn)>=2,
        "The topology should have at least two interfaces")

    # Test pausing each lossless priority individually.
    session = ixia_api_server_session

    lossless_prio_map = [x for x in lossless_prio_dscp_map]
    prio_test_traffic = [y for y in range(8) if y not in lossless_prio_map]
    test_dscp_list = [d for d in range(64)]
    bg_dscp_list = test_dscp_list

    for prio in prio_test_traffic:
        for i in range(len(port_list)):
            vports = configure_ports(session, port_list)

            rx_id = i
            tx_id = (i + 1) % len(port_list)

            rx_port = vports[rx_id]
            tx_port = vports[tx_id]
            rx_port_bw = port_list[rx_id]['speed']
            tx_port_bw = port_list[tx_id]['speed']

            pytest_assert(rx_port_bw == tx_port_bw)

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
                        paused=False)

            clean_configuration(session=session)


def test_pfc_global_pause (testbed,
                           conn_graph_facts,
                           lossless_prio_dscp_map,
                           duthost,
                           ixia_dev,
                           ixia_api_server_session,
                           fanout_graph_facts) :
    """
    1. Generate lossy traffic on priorities P0, P1, P2, P5, P6, P7. Configure
       this as "Background Data Traffic" item on Ixia Tx port.
    2. Generate lossless traffic on priorities P3 an P4 (default in the SONiC
       DUT). Configure this as "Test Data Traffic" on Ixia Tx port.
    3. Start both Test Data Traffic and Background Data traffic.
    4. Start sending global pause frames from Ixia Rx ports.
    5. Wait and stop sending global pause frames after sometimes.
    6. Start sending pause frames on priorities P3 and P4.
    7. Stop sending pause frames on priorities P3 and P4 after sometimes.
    8. Repeat steps 4, 5, 6, and 7 several times.
    9. Expected Result -
       a. When global pause frames are sent both background traffic and
          test data traffic will flow.
       b. When pause frame on priority P3 and P4 is send test data
          traffic will stop.
       c. So background traffic will flow continuously, but test data traffic
          will start/stop alternately.
    """

    port_list = list()
    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number = 0)

    device_conn = conn_graph_facts['device_conn']
    for intf in fanout_devices.get_ports():
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed']) * 100
        port_list.append(intf)

    # The topology should have at least two interfaces.
    pytest_assert(len(device_conn)>=2,
        "The topology should have at least two interfaces")

    # Test pausing each lossless priority individually.
    #session = ixia_api_server_session

    lossless_prio_map = [x for x in lossless_prio_dscp_map]
    prio_test_traffic = [y for y in range(8)]
    test_dscp_list = [d for d in range(64)]

    session = ixia_api_server_session
    global_pause = False
    for prio in lossless_prio_dscp_map:
        for i in range(len(port_list)):
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

            # toggle golbal paues in iterations
            if global_pause == True :
                global_pause = False
                paused = True
            else :
                global_pause = True
                paused = False

            logger.info("global_pause = %s, pause = %s" %(global_pause, paused))

            run_pfc_exp(session=session,
                        dut=duthost,
                        tx_port=tx_port,
                        rx_port=rx_port,
                        port_bw=tx_port_bw,
                        test_prio_list=[prio],
                        test_dscp_list=test_dscp_list,
                        bg_dscp_list=bg_dscp_list,
                        exp_dur=exp_dur,
                        paused=paused,
                        global_pause=global_pause)

            clean_configuration(session=session)

