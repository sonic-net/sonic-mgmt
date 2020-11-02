import time
import pytest

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts 

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from files.configs.ecn import run_ecn_marking_at_egress

START_DELAY = 2
TRAFFIC_DURATION = 3
PAUSE_LINE_RATE = 100
TRAFFIC_LINE_RATE = 100
BW_MULTIPLIER = 1000000
FRAME_SIZE = 1024
ECN_THRESHOLD = 1024*100
TEST_FLOW_NAME = 'Test Data'

def test_ecn_marking_at_ecress(api,
                               duthost,
                               conn_graph_facts,
                               fanout_graph_facts,
                               port_id,
                               lossless_prio):

    start_delay_secs = START_DELAY
    pause_line_rate = PAUSE_LINE_RATE
    traffic_line_rate = TRAFFIC_LINE_RATE
    traffic_duration = TRAFFIC_DURATION
    frame_size = FRAME_SIZE
    test_flow_name = TEST_FLOW_NAME
    bw_multiplier = BW_MULTIPLIER
    ecn_thresholds = ECN_THRESHOLD 

    duthost.shell('sudo pfcwd stop')
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmin %s' %(ecn_thresholds))
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmax %s' %(ecn_thresholds))

    run_ecn_marking_at_egress(api=api,
                              duthost=duthost,
                              conn_graph_facts=conn_graph_facts,
                              fanout_graph_facts=fanout_graph_facts,
                              port_id=port_id,
                              lossless_prio=lossless_prio,
                              start_delay_secs=start_delay_secs,
                              pause_line_rate=pause_line_rate,
                              traffic_line_rate=traffic_line_rate,
                              traffic_duration=traffic_duration,
                              frame_size=frame_size,
                              test_flow_name=test_flow_name,
                              ecn_thresholds=ecn_thresholds)

