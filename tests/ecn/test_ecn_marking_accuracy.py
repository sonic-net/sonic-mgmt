import time
import pytest

from abstract_open_traffic_generator.result import FlowRequest, CaptureRequest
from abstract_open_traffic_generator.control import *

from tests.common.helpers.assertions import pytest_assert

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from files.configs.ecn import run_marking_accuracy

ECN_PMAX = 5.0/100
ECN_MIN_PKT = 500
ECN_MAX_PKT = ECN_MIN_PKT * 4
START_DELAY = 2
TRAFFIC_DURATION = 3
PAUSE_LINE_RATE = 100
TRAFFIC_LINE_RATE = 100
BW_MULTIPLIER = 1000000
FRAME_SIZE = 1024
TEST_FLOW_NAME = 'Test Data'
ECN_THRESHOLDS = ECN_MAX_PKT * 1024
OUTSTANDING_PACKETS = 10
ITERATION_COUNT = 10

# This calculation is TBD
EXPECTED_MIN_MARKRD_PACKETS = OUTSTANDING_PACKETS
EXPECTED_MAX_MARKRD_PACKETS = OUTSTANDING_PACKETS +\
    (ECN_MAX_PKT - ECN_MAX_PKT) * ECN_PMAX

def test_ecn_marking_accuracy(api,
                              duthost,
                              conn_graph_facts,
                              fanout_graph_facts,
                              port_id,
                              lossless_prio):

    start_delay_secs = START_DELAY
    traffic_duration = TRAFFIC_DURATION
    pause_line_rate = PAUSE_LINE_RATE
    traffic_line_rate = TRAFFIC_LINE_RATE
    frame_size = FRAME_SIZE
    test_flow_name = TEST_FLOW_NAME
    ecn_thresholds = ECN_THRESHOLDS
    outstanding_packets = OUTSTANDING_PACKETS
    iteration_count = ITERATION_COUNT
    ecn_max_pkt = ECN_MAX_PKT
    expected_min_marked_packets = EXPECTED_MIN_MARKRD_PACKETS
    expected_max_marked_packets = EXPECTED_MAX_MARKRD_PACKETS

    duthost.shell('sudo pfcwd stop')
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmax %s' %(ecn_thresholds))
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmin %s' %(ecn_thresholds/4))

    run_marking_accuracy(api=api,
                     duthost=duthost,
                     conn_graph_facts=conn_graph_facts,
                     fanout_graph_facts=fanout_graph_facts,
                     port_id=port_id,
                     lossless_prio=lossless_prio,
                     start_delay_secs=start_delay_secs,
                     pause_line_rate=pause_line_rate,
                     traffic_duration=traffic_duration,
                     traffic_line_rate=traffic_line_rate,
                     frame_size=frame_size,
                     test_flow_name=test_flow_name,
                     ecn_thresholds=ecn_thresholds,
                     outstanding_packets=outstanding_packets,
                     iteration_count=iteration_count,
                     ecn_max_pkt=ecn_max_pkt,
                     expected_min_marked_packets=expected_min_marked_packets,
                     expected_max_marked_packets=expected_max_marked_packets)


