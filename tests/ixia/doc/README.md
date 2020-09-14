##  RUN PFC EXP
def run_pfc_exp(session, dut, tx_port, rx_port, port_bw, test_prio_list,
                test_dscp_list, bg_dscp_list, exp_dur, paused,
                global_pause=False) :
```
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
```
##  TEST PFC PAUSE LOSSLESS
def test_pfc_pause_lossless(testbed, conn_graph_facts, lossless_prio_dscp_map,
                            duthost, ixia_dev, ixia_api_server_session,
                            fanout_graph_facts):
```
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
```
##  TEST PAUSES ON LOSSY PRIORITIES 
def test_pauses_on_lossy_priorities (testbed,
                                     conn_graph_facts,
                                     lossless_prio_dscp_map,
                                     duthost,
                                     ixia_dev,
                                     ixia_api_server_session,
                                     fanout_graph_facts) :
```
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
```
##  TEST PFC GLOBAL PAUSE 
def test_pfc_global_pause (testbed,
                           conn_graph_facts,
                           lossless_prio_dscp_map,
                           duthost,
                           ixia_dev,
                           ixia_api_server_session,
                           fanout_graph_facts) :
```
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
```
