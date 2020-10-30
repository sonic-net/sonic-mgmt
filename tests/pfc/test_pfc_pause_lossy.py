import time
import pytest

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts 

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

START_DELAY = 1
TRAFFIC_DURATION = 3
PAUSE_LINE_RATE = 100
TRAFFIC_LINE_RATE = 50
BW_MULTIPLIER = 1000000
FRAME_SIZE = 1024
TOLERANCE_THRESHOLD = .97
TEST_FLOW_NAME = 'Test Data'
BACKGROUND_FLOW_NAME = 'Background Data'

def test_pfc_pause_lossy_traffic(api,
                                 duthost,
                                 conn_graph_facts,
                                 fanout_graph_facts,
                                 port_id,
                                 lossless_prio):
    """
    This test case checks the behaviour of the SONiC DUT when it receives 
    a PFC pause frame on lossy priorities.
                                +-----------+
    [Keysight Chassis Tx Port]  |           | [Keysight Chassis Rx Port]
    --------------------------->| SONiC DUT |<---------------------------
    Test Data Traffic +         |           |  PFC pause frame on 
    Background Dada Traffic     +-----------+  "lossy" priorities.
    1. Configure SONiC DUT with multipul lossless priorities. 
    2. On SONiC DUT enable PFC on several lossless priorities e.g priority 
       3 and 4.
    3. On the Keysight chassis Tx port create two flows - a) 'Test Data Traffic'
       and b) 'Background Data traffic'.
    4. Configure 'Test Data Traffic' such that it contains traffic items
       with all lossy priorities.
    5. Configure 'Background Data Traffic' it contains traffic items with
       all lossless priorities.
    6. From Rx port send pause frames on all lossless priorities. Then
       start 'Test Data Traffic' and 'Background Data Traffic'.
    7. Verify the following: 
       (a) When Pause Storm are running, Keysight Rx port is receiving
       both 'Test Data Traffic' and 'Background Data traffic'.
       (b) When Pause Storm are stoped, then also Keysight Rx port is receiving
       both 'Test Data Traffic' and 'Background Data traffic'.
    """

    from files.configs.pfc import run_test_pfc_lossy
    logger.info("port_id = %s" %(port_id))
    logger.info("lossless prio = %s" %(lossless_prio))

    start_delay_secs = START_DELAY
    pause_line_rate = PAUSE_LINE_RATE
    traffic_line_rate = TRAFFIC_LINE_RATE
    traffic_duration = TRAFFIC_DURATION
    frame_size = FRAME_SIZE
    test_flow_name = TEST_FLOW_NAME
    bw_multiplier = BW_MULTIPLIER
    background_flow_name = BACKGROUND_FLOW_NAME
    tolerance_threshold = TOLERANCE_THRESHOLD
 
    run_test_pfc_lossy(api=api,
                       duthost=duthost,
                       conn_graph_facts=conn_graph_facts,
                       fanout_graph_facts=fanout_graph_facts,
                       port_id=port_id,
                       lossless_prio=lossless_prio,
                       start_delay_secs=start_delay_secs,
                       pause_line_rate=pause_line_rate,
                       traffic_line_rate=traffic_line_rate,
                       traffic_duration=traffic_duration,
                       pause_frame_type='priority',
                       frame_size=frame_size,
                       test_flow_name=test_flow_name,
                       background_flow_name=background_flow_name,
                       bw_multiplier=bw_multiplier,
                       tolerance_threshold=tolerance_threshold)

 
