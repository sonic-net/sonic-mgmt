import logging
import time
import json
import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    stop_pfcwd, disable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt,\
    traffic_flow_mode, calc_pfc_pause_flow_rate      # noqa F401
from tests.common.snappi_tests.port import select_ports, select_tx_port # noqa F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics # noqa F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_background_flows, generate_pause_flows, run_traffic, verify_pause_flow, verify_basic_test_flow, \
    verify_background_flow, verify_pause_frame_count_dut, verify_egress_queue_frame_count, \
    verify_in_flight_buffer_pkts, verify_unset_cev_pause_frame_count, verify_tx_frame_count_dut, \
    verify_rx_frame_count_dut
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.read_pcap import validate_pfc_frame


logger = logging.getLogger(__name__)

dut_port_config = []
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
data_flow_pkt_size = 1024
DATA_FLOW_DURATION_SEC =300
data_flow_delay_sec = 1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_DUR_BASE_SEC = data_flow_delay_sec + DATA_FLOW_DURATION_SEC
TOLERANCE_THRESHOLD = 0.05
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4


def run_capacity_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 duthost,
                 dut_port,
                 global_pause,
                 pause_prio_list,
                 test_prio_list,
                 bg_prio_list,
                 prio_dscp_map,
                 test_traffic_pause,
                 snappi_extra_params=None):
    """
    Run a Capacity test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        global_pause (bool): if pause frame is IEEE 802.3X pause
        pause_prio_list (list): priorities to pause for pause frames
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        test_traffic_pause (bool): if test flows are expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)
    global DATA_FLOW_DURATION_SEC
    global data_flow_delay_sec

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,dut_port=dut_port,conn_data=conn_data,fanout_data=fanout_data)
    pytest_assert(port_id is not None,'Fail to get ID for port {}'.format(dut_port))

    # Single linecard and hence rx_dut and tx_dut are the same.
    # rx_dut and tx_dut are used to verify_pause_frame_count
    rx_dut = duthost
    tx_dut = duthost

    # Rate percent must be an integer
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,port_config_list=port_config_list,port_id=port_id)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    #if snappi_extra_params.headroom_test_params is not None:
    #    DATA_FLOW_DURATION_SEC += 10
    #    data_flow_delay_sec += 2
    #    # Set up pfc delay parameter
    #    l1_config = testbed_config.layer1[0]
    #    pfc = l1_config.flow_control.ieee_802_1qbb
    #    pfc.pfc_delay = snappi_extra_params.headroom_test_params[0]

    if snappi_extra_params.poll_device_runtime:
        # If the switch needs to be polled as traffic is running for stats,
        # then the test runtime needs to be increased for the polling delay
        DATA_FLOW_DURATION_SEC += ANSIBLE_POLL_DELAY_SEC
        data_flow_delay_sec = ANSIBLE_POLL_DELAY_SEC

    # Set default traffic flow configs if not set
    if snappi_extra_params.traffic_flow_config.data_flow_config is None:
        snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_name": TEST_FLOW_NAME,
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": test_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": None,
            "flow_delay_sec": data_flow_delay_sec,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }


    # Generate test flow config
    #generate_test_flows(testbed_config=testbed_config,test_flow_prio_list=test_prio_list,prio_dscp_map=prio_dscp_map,snappi_extra_params=snappi_extra_params)


    #flows = testbed_config.flows

    #all_flow_names = [flow.name for flow in flows]
    #data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]
    import time
    api.set_config(testbed_config)
    api._ixnetwork.StopAllProtocols()
    time.sleep(10)


    ipv4s = api._ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find().Ipv4.find()
    rocev2s = [ipv4.Rocev2.add(QpCount=2) for ipv4 in ipv4s]
    #rocev2Flows = [rocev2.Flows.add() for rocev2 in rocev2s]
    for i, rocev2 in enumerate(rocev2s):rocev2.AddDestinationPeers(rocev2s[:i] + rocev2s[i+1:])

    #api._ixnetwork.Traffic.TrafficItem.find().remove()
    api._ixnetwork.StartAllProtocols()
    time.sleep(10)
    api._ixnetwork.Traffic.AddRoCEv2FlowGroups()
    time.sleep(5)

    logger.info("Starting transmit on all flows ...")
    api._ixnetwork.Traffic.RoceV2Traffic.Generate()
    api._ixnetwork.Traffic.Apply()
    api._ixnetwork.Traffic.Start()                      #Where is blocking command
    time.sleep(10)
    rocev2FlowStatistics = api._assistant.StatViewAssistant('RoCEv2 Data Plane Port Statistics')
        

    import influxdb_client, os, time
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS            

    token = 'fgmCw-DWjdqgWCDbpxLhOKqJC-Aabb3v9cDlLeH4AlMjiHgnrI9DL2t_C2gGqN809mccByB74RqyXcmXqz3tBQ=='
    org = "keysight"
    url = "http://10.36.77.19:8086"
    bucket="mydb"
    client = influxdb_client.InfluxDBClient(url=url, token=token, org=org)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    #Get Code to Ixia  stats
    def stats_get_callback(ws, message):
        logger.info("{} Polling TGEN for in-flight traffic statistics after every 10 seconds".format(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
        data = json.loads(message)
        if data['key']=='RoCEv2 Data Plane Port Watch':
            sdata = [row[0] for row in data['value'][0]['pageValues']]
            logger.info(sdata)
            logger.info("DUT show platform psu")
            plat_psu = duthost.command("show platform psu --json")
            plat_psu = eval(plat_psu['stdout'])
            logger.info(plat_psu)

            #code to push data to DB
            
            for flow in sdata:
                point = (Point(flow[ccp.index('Port')]).tag("Port", "tagvalue1").field(ccp[ccp.index('Data Frames Tx')], flow[ccp.index('Data Frames Tx')]))
                write_api.write(bucket=bucket, org="keysight", record=point)
                time.sleep(1)


    object_to_watch = api._ixnetwork.Statistics.View.find(Caption='RoCEv2 Data Plane Port Statistics').Data
    ccp = object_to_watch.ColumnCaptions
    watch_assistant = api._assistant.WatchAssistant(Callback=stats_get_callback)
    watch_assistant.AddAttributeWatch(AttributesToWatch=['pageValues'], ObjectIdToWatch=object_to_watch, Topic='RoCEv2 Data Plane Port Watch',PollInterval=10000)
    watch_assistant.start()
    
    time.sleep(DATA_FLOW_DURATION_SEC)

    watch_assistant.stop()

    import pdb;pdb.set_trace()
    
    logger.info("Starting transmit on all flows ...")
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)


    


