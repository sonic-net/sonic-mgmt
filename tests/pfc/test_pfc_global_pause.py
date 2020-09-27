import time
import pytest

from abstract_open_traffic_generator.result import FlowRequest
from abstract_open_traffic_generator.control import FlowTransmit

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts 

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from files.configs.pfc import global_pause, one_hundred_gbe, serializer
from files.configs.pfc import start_delay, traffic_duration, pause_line_rate,\
    traffic_line_rate, port_bandwidth, bw_multiplier, frame_size

from files.qos_fixtures import lossless_prio_dscp_map


START_DELAY = [1]
TRAFFIC_DURATION = [3]
PAUSE_LINE_RATE = [100]
TRAFFIC_LINE_RATE = [50]
BW_MULTIPLIER = [1000000]
FRAME_SIZE = [1024]
TOLERANCE_THRESHOLD = .97

@pytest.mark.parametrize('start_delay', START_DELAY)
@pytest.mark.parametrize('traffic_duration', TRAFFIC_DURATION)
@pytest.mark.parametrize('pause_line_rate', PAUSE_LINE_RATE)
@pytest.mark.parametrize('traffic_line_rate', TRAFFIC_LINE_RATE)
@pytest.mark.parametrize('bw_multiplier', BW_MULTIPLIER)
@pytest.mark.parametrize('frame_size', FRAME_SIZE)
def test_pfc_global_pause(api, 
                          duthost, 
                          global_pause, 
                          start_delay, 
                          pause_line_rate,
                          traffic_line_rate,
                          traffic_duration,
                          port_bandwidth,
                          frame_size):
    """
                                +-----------+
    [Keysight Chassis Tx Port]  |           | [Keysight Chassis Rx Port]
    --------------------------->| SONiC DUT |<---------------------------
    Test Data Traffic +         |           |  PFC pause frame on 
    Background Dada Traffic     +-----------+  "lossy" priorities.

    """
    duthost.shell('sudo pfcwd stop')

    for base_config in global_pause:

        # create the configuration
        api.set_config(base_config)

        # start all flows
        api.set_flow_transmit(FlowTransmit(state='start'))

        exp_dur = start_delay + traffic_duration
        logger.info("Traffic is running for %s seconds" %(exp_dur))
        time.sleep(exp_dur)

        # stop all flows
        api.set_flow_transmit(FlowTransmit(state='stop'))

        # Get statistics
        test_stat = api.get_flow_results(FlowRequest())

        for rows in test_stat['rows'] :
            tx_frame_index = test_stat['columns'].index('frames_tx')
            rx_frame_index = test_stat['columns'].index('frames_rx')
            caption_index = test_stat['columns'].index('name')   
            if ((rows[caption_index] == 'Test Data') or
                (rows[caption_index] == 'Background Data')):

                tx_frames = rows[tx_frame_index]
                rx_frames = rows[rx_frame_index]
                if ((tx_frames != rx_frames) or (rx_frames == 0)) :
                    pytest_assert(False,
                        "Not all %s reached Rx End" %(rows[caption_index]))

                rx_bits = rx_frames * frame_size * 8.0
                exp_rx_bits = port_bandwidth * traffic_duration * traffic_line_rate
                tolerance_ratio = rx_bits / exp_rx_bits

                if ((tolerance_ratio < TOLERANCE_THRESHOLD) or
                    (tolerance_ratio > 1)) :

                    logger.error("tolerance_ratio = %s" %(tolerance_ratio))
                    pytest_assert(False,
                        "expected % of packets not received at the RX port")

