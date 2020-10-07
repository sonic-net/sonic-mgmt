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

from files.configs.ecn import ecn_marking_at_ecress, one_hundred_gbe, serializer
from files.configs.ecn import start_delay, traffic_duration, pause_line_rate,\
    traffic_line_rate, port_bandwidth, bw_multiplier, frame_size
from files.qos_fixtures import lossless_prio_dscp_map, ecn_thresholds

START_DELAY = [2]
TRAFFIC_DURATION = [3]
PAUSE_LINE_RATE = [100]
TRAFFIC_LINE_RATE = [50]
BW_MULTIPLIER = [1000000]
FRAME_SIZE = [1024]
TOLERANCE_THRESHOLD = .97
ECN_THRESHOLD = [1024*10]

@pytest.mark.parametrize('start_delay', START_DELAY)
@pytest.mark.parametrize('traffic_duration', TRAFFIC_DURATION)
@pytest.mark.parametrize('pause_line_rate', PAUSE_LINE_RATE)
@pytest.mark.parametrize('traffic_line_rate', TRAFFIC_LINE_RATE)
@pytest.mark.parametrize('bw_multiplier', BW_MULTIPLIER)
@pytest.mark.parametrize('frame_size', FRAME_SIZE)
@pytest.mark.parametrize('ecn_thresholds', ECN_THRESHOLD)
def test_ecn_marking_at_ecress(api, 
                               duthost, 
                               ecn_marking_at_ecress, 
                               start_delay,
                               pause_line_rate,
                               traffic_line_rate, 
                               traffic_duration,
                               port_bandwidth,
                               frame_size,
                               ecn_thresholds) :

    duthost.shell('sudo pfcwd stop')
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmin %s' %(ecn_thresholds))
    duthost.shell('sudo ecnconfig -p AZURE_LOSSLESS -gmax %s' %(ecn_thresholds))

    for base_config in ecn_marking_at_ecress:
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
                     pytest_assert(False,
                         "Not all %s reached Rx End" %(rows[caption_index]))

        # write the pcap bytes to a local file
        with open('%s.pcap' % rx_port.name, 'wb') as fid:
            fid.write(b'%s'%(pcap_bytes)) 

        from scapy.all import rdpcap
        reader = rdpcap('%s.pcap' % rx_port.name)

        packet_marked_conjestion = 0
        total_ip_packets_received = 0  
        for r in reader:
            if r.haslayer('IP') :
                total_ip_packets_received +=1 
                x = r['IP'].getfieldval('tos')
                if (x & 3) == 3 :
                    packet_marked_conjestion += 1

        logger.info("Total IP packets received = %s" %(total_ip_packets_received))
        logger.info("Total number of IP packets ECN marked = %s" %(packet_marked_conjestion))

        conjestion_ratio = float(packet_marked_conjestion)/total_ip_packets_received
        logger.info("The tolerance ratio = %s" %(conjestion_ratio))

        if ((conjestion_ratio < TOLERANCE_THRESHOLD) or
            (conjestion_ratio > 1)):
            pytest_assert(False, 
                "Expected number of packets are not ECN conjestion marked")
        

