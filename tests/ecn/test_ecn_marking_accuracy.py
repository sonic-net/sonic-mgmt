import time
import pytest

from abstract_open_traffic_generator.result import FlowRequest, CaptureRequest
from abstract_open_traffic_generator.control import *
from abstract_open_traffic_generator.port import Capture

from tests.common.helpers.assertions import pytest_assert

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from files.configs.ecn import marking_accuracy, one_hundred_gbe, serializer
from files.configs.ecn import start_delay, traffic_duration, pause_line_rate,\
    traffic_line_rate, port_bandwidth, bw_multiplier, frame_size,\
    outstanding_packets

from files.qos_fixtures import lossless_prio_dscp_map, ecn_thresholds

ECN_PMAX = 5.0/100
ECN_MIN_PKT = 500
ECN_MAX_PKT = ECN_MIN_PKT * 4
START_DELAY = [2]
TRAFFIC_DURATION = [3]
PAUSE_LINE_RATE = [100]
TRAFFIC_LINE_RATE = [100]
BW_MULTIPLIER = [1000000]
FRAME_SIZE = [1024]
ECN_THRESHOLDS = [ECN_MAX_PKT * 1024]
OUTSTANDING_PACKETS = [10]
ITERATION_COUNT = 10

# This calculation is TBD
EXPECTED_MIN_MARKRD_PACKETS = OUTSTANDING_PACKETS[0]
EXPECTED_MAX_MARKRD_PACKETS = OUTSTANDING_PACKETS[0] + (ECN_MAX_PKT - ECN_MAX_PKT) * ECN_PMAX

@pytest.mark.parametrize('start_delay', START_DELAY)
@pytest.mark.parametrize('traffic_duration', TRAFFIC_DURATION)
@pytest.mark.parametrize('pause_line_rate', PAUSE_LINE_RATE)
@pytest.mark.parametrize('traffic_line_rate', TRAFFIC_LINE_RATE)
@pytest.mark.parametrize('bw_multiplier', BW_MULTIPLIER)
@pytest.mark.parametrize('frame_size', FRAME_SIZE)
@pytest.mark.parametrize('ecn_thresholds', ECN_THRESHOLDS)
@pytest.mark.parametrize('outstanding_packets', OUTSTANDING_PACKETS)
def test_ecn_marking_at_ecress(api,
                               duthost,
                               marking_accuracy,
                               start_delay,
                               pause_line_rate,
                               traffic_line_rate,
                               traffic_duration,
                               port_bandwidth,
                               frame_size,
                               outstanding_packets,
                               ecn_thresholds) :

    duthost.shell('sudo pfcwd stop')
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmax %s' %(ecn_thresholds))
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmin %s' %(ecn_thresholds/4))

    for base_config in marking_accuracy:
        packet_marked_stats = [] 
        for i in range(ITERATION_COUNT):
            rx_port=base_config.ports[1]
            rx_port.capture = Capture(choice=[], enable=True, format='pcapng')

            # create the configuration
            api.set_state(State(ConfigState(config=base_config, state='set')))

            # start capture
            api.set_state(State(PortCaptureState(port_names=[rx_port.name], state='start')))

            # start all flows
            api.set_state(State(FlowTransmitState(state='start')))

            exp_dur = start_delay + traffic_duration
            logger.info("Traffic is running for %s seconds" %(traffic_duration))
            time.sleep(exp_dur)

            # stop all flows
            api.set_state(State(FlowTransmitState(state='stop')))

            pcap_bytes = api.get_capture_results(CaptureRequest(port_name=rx_port.name))

            # Get statistics
            stat_captions =['Test Data']
            for row in api.get_flow_results(FlowRequest(flow_names=stat_captions)):
                if (row['name'] == 'Test Data') :
                    if ((row['frames_rx'] == 0) or (row['frames_tx'] != row['frames_rx'])):
                         logger.error("Tx = %s Rx = %s" % (row['frames_tx'], row['frames_rx']))
                         pytest_assert(False, "Not all %s reached Rx End")

            # write the pcap bytes to a local file
            with open('%s.pcap' % rx_port.name, 'wb') as fid:
                fid.write(b'%s'%(pcap_bytes))

            from scapy.all import rdpcap
            reader = rdpcap('%s.pcap' % rx_port.name)

            ip_packet = filter(lambda x : x.haslayer('IP'), reader)

            marked_packet = 0
            # check OUTSTANDING_PACKETS must be marked
            for cntr in range(OUTSTANDING_PACKETS[0]): 
                # last 3 bits of tos must be b'11' i.e 3   
                if (ip_packet[cntr]['IP'].getfieldval('tos') & 3 == 3):
                    marked_packet += 1
                else:
                    pytest_assert(False, "First %s packets must be ECN marked"\
                       %(OUTSTANDING_PACKETS[0])) 

            # check rest of the packets if they are marked
            for cntr in range(OUTSTANDING_PACKETS[0],ECN_MAX_PKT):
                # last 3 bits of tos must be b'11' i.e 3   
                if (ip_packet[cntr]['IP'].getfieldval('tos') & 3 == 3):
                    marked_packet += 1

            # count total number of marked packets
            if ((marked_packet <= EXPECTED_MIN_MARKRD_PACKETS) and
                (marked_packet > EXPECTED_MAX_MARKRD_PACKETS)):
                pytest_assert(False,
                    "Expected nummer of matched ECN packets not found")
            else:
                packet_marked_stats.append(marked_packet)      

            logger.info("iteration = %s outstanding packets = %s marked = %s"\
                %(i + 1, outstanding_packets, marked_packet))

        # end iteration
        logger.info("Iteration\tpacket marked")
        logger.info("---------\t-------------")
        for i in range(ITERATION_COUNT):
            logger.info("%s\t\t%s" %(i,  packet_marked_stats[i]))  

