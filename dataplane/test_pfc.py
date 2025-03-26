from tests.snappi_tests.dataplane.imports import *

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]


dut_port_config = []
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
data_flow_pkt_size = 1024
DATA_FLOW_DURATION_SEC = 15
data_flow_delay_sec = 1
PRE_PAUSE_FLOW = 'Pre-Pause'
pre_pause_packets = 100
pre_pause_pkt_size = 64
pause_pkt_size = 64
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_DUR_BASE_SEC = data_flow_delay_sec + DATA_FLOW_DURATION_SEC
TOLERANCE_THRESHOLD = 0.05
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4



SNAPPI_POLL_DELAY_SEC = 2
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4


def aresone_offset(x):
    res = int(float(x) * 0.078125)
    if res >= 20:
        raise Exception('odd time offset value: {} resulted in {} ns'.format(x, res))
    return res


def novus_offset(x):
    res = int(float(x >> 5) * 2.5)
    if res >= 20:
        raise Exception('odd time offset value: {} resulted in {} ns'.format(x, res))
    return res


# aresone - 0.625, novus - 2.5
IXIA_TIME_CONSTANTS = {
    "aresone": aresone_offset,
    "novus": novus_offset
}


def hw_pcap_to_dt(v):
    return pd.to_datetime(int(v * 10**6), unit='ns')


def hw_pcap_to_ns(v):
    return int(v * 10**6)


def decode_hw_ts(p, layer, card):
    if p.haslayer(layer):
        data = bytes(p[layer].payload)[:24]
        s1, s2, s3, s4, s5, s6, offset, p1, p2, p3, seq, ts = struct.unpack("!IIBBBBBBBBII", data)
        if s3 != 0x49 or s4 != 0x78 or s5 != 0x69:
            raise Exception('wrong ixia signature in {}: {}, {}, {}'.format(data, s3, s4, s5))

        t = ts * 20 + IXIA_TIME_CONSTANTS[card](offset)
        return t
    raise Exception('layer {} not present in {}'.format(layer, p))


def hw_pcap_to_dataframe(filename, card, limit=0, type="IP"):
    res = []
    n = 0
    for p in PcapReader(filename):
        if p.haslayer(type):
            res.append({
                "sent": decode_hw_ts(p, type, card),
                "received": hw_pcap_to_ns(p.time),
                "wirelen": p.wirelen,
                "timestamp": hw_pcap_to_dt(p.time),
                "type": "ip",
                "latency": hw_pcap_to_ns(p.time) - decode_hw_ts(p, type, card)
            })
        if p.haslayer(scapy.contrib.mac_control.MACControlClassBasedFlowControl):
            q = p[scapy.contrib.mac_control.MACControlClassBasedFlowControl]
            res.append({
                "received": hw_pcap_to_ns(p.time),
                "wirelen": p.wirelen,
                "timestamp": hw_pcap_to_dt(p.time),
                "type": "pfc",
                "c0_pause_time": q.c0_pause_time,
                "c0_enabled": q.c0_enabled,
            })
        n = n + 1
        if limit and n >= limit:
            break
    return pd.DataFrame.from_records(res)

def run_traffic(duthost,
                api,
                config,
                data_flow_names,
                all_flow_names,
                exp_dur_sec,
                snappi_extra_params):

    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        flow_metrics (snappi metrics object): per-flow statistics from TGEN (right after flows end)
        switch_device_results (dict): statistics from DUT on both TX and RX and per priority
        in_flight_flow_metrics (snappi metrics object): in-flight statistics per flow from TGEN
                                                        (right before flows end)
    """

    api.set_config(config)
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    pcap_type = snappi_extra_params.packet_capture_type
    base_flow_config = snappi_extra_params.base_flow_config
    switch_tx_lossless_prios = sum(base_flow_config["dut_port_config"][1].values(), [])
    switch_rx_port = snappi_extra_params.base_flow_config["tx_port_config"].peer_port
    switch_tx_port = snappi_extra_params.base_flow_config["rx_port_config"].peer_port
    switch_device_results = None
    in_flight_flow_metrics = None

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Starting packet capture ...")
        cs = api.control_state()
        cs.port.capture.port_names = snappi_extra_params.packet_capture_ports
        cs.port.capture.state = cs.port.capture.START
        api.set_control_state(cs)

    duthost.command("sonic-clear counters \n")

    duthost.command("sonic-clear queuecounters \n")

    logger.info("Starting transmit on all flows ...")
    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
    api.set_control_state(cs)


    # Test needs to run for at least 10 seconds to allow successive device polling
    if snappi_extra_params.poll_device_runtime and exp_dur_sec > 10:
        logger.info("Polling DUT for traffic statistics for {} seconds ...".format(exp_dur_sec))
        switch_device_results = {}
        switch_device_results["tx_frames"] = {}
        switch_device_results["rx_frames"] = {}
        for lossless_prio in switch_tx_lossless_prios:
            switch_device_results["tx_frames"][lossless_prio] = []
            switch_device_results["rx_frames"][lossless_prio] = []
        exp_dur_sec = exp_dur_sec + ANSIBLE_POLL_DELAY_SEC  # extra time to allow for device polling
        poll_freq_sec = int(exp_dur_sec / 10)

        for poll_iter in range(10):
            for lossless_prio in switch_tx_lossless_prios:
                switch_device_results["tx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_tx_port,
                                                                                                lossless_prio)[0])
                switch_device_results["rx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_rx_port,
                                                                                                lossless_prio)[0])
            time.sleep(poll_freq_sec)

            if poll_iter == 5:
                logger.info("Polling TGEN for in-flight traffic statistics...")
                in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
                flow_names = [metric.name for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                tx_frames = [metric.frames_tx for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                rx_frames = [metric.frames_rx for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                logger.info("In-flight traffic statistics for flows: {}".format(flow_names))
                logger.info("In-flight TX frames: {}".format(tx_frames))
                logger.info("In-flight RX frames: {}".format(rx_frames))
        logger.info("DUT polling complete")
    else:
        time.sleep(exp_dur_sec*(2/5))  # no switch polling required, only TGEN polling
        logger.info("Polling TGEN for in-flight traffic statistics...")
        in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)  # fetch in-flight metrics from TGEN
        time.sleep(exp_dur_sec*(3/5))

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        logger.info("Checking if all flows have stopped. Attempt #{}".format(attempts + 1))
        flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)

        # If all the data flows have stopped
        transmit_states = [metric.transmit for metric in flow_metrics]
        if len(flow_metrics) == len(data_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            logger.info("All test and background traffic flows stopped")
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,"Flows do not stop in {} seconds".format(max_attempts))

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.control_state()
        cs.port.capture.state = cs.port.capture.STOP
        api.set_control_state(cs)

        logger.info("Retrieving and saving packet capture to {}.pcapng".format(snappi_extra_params.packet_capture_file))
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
    logger.info("Stopping transmit on all remaining flows")

    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
    api.set_control_state(cs)

    return flow_metrics, switch_device_results, in_flight_flow_metrics

def run_response_time_traffic(duthost,
                           api,
                           config,
                           all_flow_names,
                           packet_count,
                           pause_rate,
                           snappi_extra_params):
    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        packet_count (int): Number of pre pause packets
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        per-flow statistics (list)
    """
    duthost.command('sudo pfcwd stop \n')
    time.sleep(10)
    base_flow_config = snappi_extra_params.base_flow_config

    # Enabling capture
    logger.info("Enabling packet capture on the pre-pause Rx Port ...")
    capture = config.captures.capture()[-1]
    capture.name = "Capture 1"
    capture.port_names = [base_flow_config["tx_port_name"], base_flow_config["rx_port_name"]]
    capture.format = capture.PCAP
    api.set_config(config)
    ixnetwork = api._ixnetwork
    card = "aresone"  if api._ixnetwork.Locations.find().DeviceType == 'Ixia AresONE' else "novus"

    ixnetwork.Traffic.EnableMinFrameSize = False
    ixnetwork.Traffic.EnableStaggeredStartDelay = False #
    ixnetwork.Globals.Statistics.Advanced.Timestamp.TimestampPrecision = 9

    port1 = ixnetwork.Vport.find(Name=base_flow_config["tx_port_name"])[0]
    port2 = ixnetwork.Vport.find(Name=base_flow_config["rx_port_name"])[0]
    # port2.Type = 'novusHundredGigLan'
    port2.TxMode = 'interleaved'
    port2.Capture.SoftwareEnabled = False
    port2.Capture.DataReceiveTimestamp = 'hwTimestamp'
    port2.Capture.HardwareEnabled = False
    port1.Capture.SoftwareEnabled = False
    port1.Capture.HardwareEnabled = True
    port1.Capture.DataReceiveTimestamp = 'hwTimestamp'
    port1.Capture.Filter.CaptureFilterEnable = True

    port1.Capture.Filter.CaptureFilterPattern = 'pattern1'
    if port1.Name == 'Port 1':
        port1.Capture.FilterPallette.Pattern1 = '15010102'
    else:
        port1.Capture.FilterPallette.Pattern1 = '16010102'
    port1.Capture.FilterPallette.PatternMask1 = 'FFFFFF00'
    port1.Capture.Filter.CaptureFilterExpressionString='P2'

    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    pre_pause_ti = ixnetwork.Traffic.TrafficItem.find(Name='Pre-Pause')[0]
    pre_pause_ti.TransmitMode = 'interleaved'

    # adding endpointset
    pre_pause_ti.ConfigElement.find()[0].TransmissionControl.Type = 'fixedFrameCount'
    pre_pause_ti.ConfigElement.find()[0].TransmissionControl.FrameCount = 100
    pre_pause_ti.EndpointSet.add(Name="Pause Storm", Sources=port2.Protocols.find(),
                                 Destinations=port1.Protocols.find())
    #pause traffic
    ce = pre_pause_ti.ConfigElement.find()[1]
    ce.TransmissionControl.Type = 'continuous'

    ce.FrameRate.Rate = pause_rate
    pfc_template = ixnetwork.Traffic.ProtocolTemplate.find(StackTypeId='^pfcPause$')
    ethernet_template = ce.Stack.find(StackTypeId='^ethernet$')
    PFC_stack = ce.Stack.read(ethernet_template.AppendProtocol(pfc_template))
    ethernet_template.Remove()
    PFC_stack.find(StackTypeId='^pfcPause$').Field.find()[4].SingleValue = 8
    PFC_stack.find(StackTypeId='^pfcPause$').Field.find()[5].SingleValue = '0'
    PFC_stack.find(StackTypeId='^pfcPause$').Field.find()[8].SingleValue = 'ffff'

    pre_pause_ti.Generate()
    ixnetwork.Traffic.Apply()
    logger.info("Starting transmit on pause and pre-pause ...")
    pre_pause_ti.StartStatelessTrafficBlocking()
    time.sleep(10)
    pre_pause_ti.StopStatelessTrafficBlocking()
    TI_Statistics = api._assistant.StatViewAssistant('Traffic Item Statistics')
    last_time_stamp = float(TI_Statistics.Rows[1]["Last TimeStamp"].split(':')[-1]) * 1000
    ce.TransmissionControl.StartDelayUnits = 'milliseconds'
    ce.TransmissionControl.StartDelay = int(last_time_stamp)

    logger.info("Starting transmit on test flow ...")
    test_flow_ti = ixnetwork.Traffic.TrafficItem.find(Name='Test Flow Prio 3')[0]
    test_flow_ti.Generate()
    pre_pause_ti.Generate()
    ixnetwork.Traffic.Apply()
    test_flow_ti.StartStatelessTrafficBlocking()
    time.sleep(10)
    # start capture on tx port of test flow
    logger.info("Starting packet capture ...")
    ixnetwork.StartCapture()

    # starting pause and pre-pause
    time.sleep(10)
    logger.info("Starting transmit on pause and pre-pause ...")
    pre_pause_ti.StartStatelessTrafficBlocking()

    TI_Statistics = api._assistant.StatViewAssistant('Traffic Item Statistics')
    t=0
    while True:
        TI_Statistics = api._assistant.StatViewAssistant('Traffic Item Statistics')
        if int(float(TI_Statistics.Rows[0]["Rx Frame Rate"])) == 0:
            logger.info('Test Flow stopped sending packets')
            break
        logger.info('Polling for Test Flow to stop transmitting ...........{} m sec'.format(t * 1000))
        pytest_assert(t<20, 'Test Flow is still transmitting for 10 seconds after starting pre-pause')
        time.sleep(0.05)
        t=t+0.05
    # TI_Statistics = StatViewAssistant(ixnetwork, 'Traffic Item Statistics')
    lastStreamPacketTimestamp = TI_Statistics.Rows[0]["Last TimeStamp"]

    print(' Stopping Traffic')
    ixnetwork.Traffic.StopStatelessTrafficBlocking()
    # Stopping and getting packets
    time.sleep(10)
    logger.info("Stopping packet capture ...")
    ixnetwork.StopCapture()
    time.sleep(20)

    pathp = ixnetwork.Globals.PersistencePath
    res = ixnetwork.SaveCaptureFiles(Arg1=pathp)[0]

    cf = "moveFile.cap"
    api._ixnetwork.parent.DownloadFile(res, cf)
    api._ixnetwork.Locations.find()
    host1_df = hw_pcap_to_dataframe(cf, card, 100, "IP")
    logger.info(host1_df)

    lineRate = 100
    ns_per_bit = 1.0 / lineRate
    ns_per_byte = ns_per_bit * 8
    numPrePauseFrames = 1

    prePausePacketSize = pre_pause_ti.ConfigElement.find()[0].FrameSize.FixedSize
    pausePacketTxDelay = numPrePauseFrames * (prePausePacketSize + 20)
    pausePacketTxDelay = pausePacketTxDelay - 20
    pausePacketTxDelay = pausePacketTxDelay - (prePausePacketSize / 2)

    packetTimeOnWire = ns_per_byte * (prePausePacketSize + 20)
    packetDurationOnWire = ns_per_byte * prePausePacketSize

    pd.DataFrame.from_records(host1_df)
    lastPrePausePacketTxTimeStamp = host1_df['sent'].loc[host1_df.index[packet_count - 1]]
    pauseFrameTimestamp = lastPrePausePacketTxTimeStamp + packetTimeOnWire
    pauseFrameTxTimestamp = pauseFrameTimestamp + packetDurationOnWire

    responseTime = float(lastStreamPacketTimestamp.split(':')[-1]) * 1000000000 - pauseFrameTxTimestamp
    logger.info('----------------------------------------------')
    logger.info("Last Pre Pause Timestamp   : {} ns|".format(float(lastPrePausePacketTxTimeStamp)))
    last_data_packet_timestamp = float(lastStreamPacketTimestamp.split(':')[-1])* 1000000000
    logger.info("Last Data Packet Timestamp : {} ns|".format(last_data_packet_timestamp))
    logger.info("Pause Tx Timestamp         : {} ns|".format(pauseFrameTxTimestamp))
    logger.info("Response Time              : {} ns|".format(responseTime))
    logger.info('----------------------------------------------')

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    flow_metrics = api.get_metrics(request).flow_metrics
    logger.info("Stopping transmit on all remaining flows")

    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
    api.set_control_state(ts)

    return flow_metrics





@pytest.mark.parametrize('intf_type', ['IP'])
def test_response_time(snappi_api,                   # noqa F811
                       snappi_testbed_config,        # noqa F811
                       conn_graph_facts,             # noqa F811
                       fanout_graph_facts,           # noqa F811
                       duthosts,
                       rand_one_dut_hostname,
                       rand_one_dut_portname_oper_up,
                       lossless_prio_list,           # noqa F811
                       lossy_prio_list,              # noqa F811
                       prio_dscp_map,
                       intf_type):               # noqa F811
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority
    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        intf_type (pytest paramenter): IP or VLAN interface type
    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,"Port is not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    test_prio_list = [3]
    bg_prio_list = [4]
    api=snappi_api
    conn_data=conn_graph_facts
    fanout_data=fanout_graph_facts
    pause_prio_list=test_prio_list
    test_traffic_pause=True
    snappi_extra_params=None                
    global_pause=False

   
    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    if snappi_extra_params is None:snappi_extra_params = SnappiTestParams()

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)
    global DATA_FLOW_DURATION_SEC

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,dut_port=dut_port,conn_data=conn_data,fanout_data=fanout_data)

    pytest_assert(port_id is not None,'Fail to get ID for port {}'.format(dut_port))

    # Rate percent must be an integer
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,port_config_list=port_config_list,port_id=port_id)
    snappi_extra_params.base_flow_config["tx_device_group_name"] = "Device " + snappi_extra_params.base_flow_config["tx_port_name"]
    snappi_extra_params.base_flow_config["rx_device_group_name"] = "Device " + snappi_extra_params.base_flow_config["rx_port_name"]

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    if snappi_extra_params.headroom_test_params is not None:
        DATA_FLOW_DURATION_SEC += 10
        # Set up pfc delay parameter
        l1_config = testbed_config.layer1[0]
        pfc = l1_config.flow_control.ieee_802_1qbb
        pfc.pfc_delay = snappi_extra_params.headroom_test_params[0]

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
            "flow_delay_sec": 0,
            "flow_traffic_type": traffic_flow_mode.CONTINUOUS
        }

    if snappi_extra_params.traffic_flow_config.background_flow_config is None and \
       snappi_extra_params.gen_background_traffic:
        snappi_extra_params.traffic_flow_config.background_flow_config = {
            "flow_name": PRE_PAUSE_FLOW,
            "flow_dur_sec": 1,
            "flow_rate_percent": 10,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": pre_pause_pkt_size,
            "flow_pkt_count": pre_pause_packets,
            "flow_delay_sec": 0,
            "flow_traffic_type": traffic_flow_mode.FIXED_PACKETS
        }

    if snappi_extra_params.traffic_flow_config.pause_flow_config is None:
        snappi_extra_params.traffic_flow_config.pause_flow_config = {
            "flow_name": PAUSE_FLOW_NAME,
            "flow_dur_sec": None,
            "flow_rate_percent": None,
            "flow_rate_pps": calc_pfc_pause_flow_rate(speed_gbps),
            "flow_rate_bps": None,
            "flow_pkt_size": pause_pkt_size,
            "flow_pkt_count": None,
            "flow_delay_sec": 4,
            "flow_traffic_type": traffic_flow_mode.CONTINUOUS
        }

    generate_test_flows(testbed_config=testbed_config,test_flow_prio_list=test_prio_list,prio_dscp_map=prio_dscp_map,snappi_extra_params=snappi_extra_params)
    # Generate background flow config
    if snappi_extra_params.gen_background_traffic:
        def generate_pre_pause_flows(testbed_config,snappi_extra_params,intf_type):
            """
            Generate background configurations of flows. Test flows and background flows are also known as data flows.
            Args:
                testbed_config (obj): testbed L1/L2/L3 configuration
                snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
                intf_type : IP or VLAN interface type
            """
            base_flow_config = snappi_extra_params.base_flow_config
            pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
            bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config
            pytest_assert(bg_flow_config is not None, "Cannot find background flow configuration")

            bg_flow = testbed_config.flows.flow(name='{}'.format(bg_flow_config["flow_name"]))[-1]
            bg_flow.tx_rx.port.tx_name = testbed_config.ports[base_flow_config["rx_port_id"]].name
            bg_flow.tx_rx.port.rx_name = testbed_config.ports[base_flow_config["tx_port_id"]].name

            eth, ipv4 = bg_flow.packet.ethernet().ipv4()
            if intf_type == 'VLAN' or intf_type == 'vlan':
                eth.src.value = base_flow_config["rx_mac"]
                eth.dst.value = base_flow_config["tx_port_config"].gateway_mac
            elif intf_type == 'IP' or intf_type == 'ip':
                eth.src.value = base_flow_config["tx_mac"]
                eth.dst.value = base_flow_config["rx_port_config"].gateway_mac
            else:
                pytest_assert(False, "Invalid interface type given")

            ipv4.src.value = base_flow_config["rx_port_config"].ip
            ipv4.dst.value = base_flow_config["tx_port_config"].ip

            bg_flow.size.fixed = bg_flow_config["flow_pkt_size"]
            bg_flow.rate.percentage = bg_flow_config["flow_rate_percent"]
            bg_flow.duration.fixed_packets.packets = bg_flow_config["flow_pkt_count"]
            bg_flow.metrics.enable = True
            bg_flow.metrics.loss = True          
  
        generate_pre_pause_flows(testbed_config=testbed_config,snappi_extra_params=snappi_extra_params,intf_type=intf_type,)
        

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    # Clear PFC, queue and interface counters before traffic run
    duthost.command("pfcstat -c")
    time.sleep(1)
    duthost.command("sonic-clear queuecounters")
    time.sleep(1)
    duthost.command("sonic-clear counters")
    time.sleep(1)

    """ Run traffic """
    tgen_flow_stats = run_response_time_traffic(duthost=duthost,
                                                api=api,
                                                config=testbed_config,
                                                all_flow_names=all_flow_names,
                                                packet_count=pre_pause_packets,
                                                pause_rate=calc_pfc_pause_flow_rate(speed_gbps),
                                                snappi_extra_params=snappi_extra_params)

    # Verify pre-pause flow
    pre_pause_flow_row = next(metric for metric in tgen_flow_stats if metric.name == PRE_PAUSE_FLOW)
    pre_pause_flow_rx_frames = pre_pause_flow_row.frames_rx
    pytest_assert(pre_pause_flow_rx_frames == pre_pause_packets,"Received desired number of pre pause packets")

pytestmark = [pytest.mark.topology('tgen')]
def ttest_pfc(snappi_api,                  # noqa F811
            snappi_testbed_config,       # noqa F811
            conn_graph_facts,            # noqa F811
            fanout_graph_facts,          # noqa F811
            duthosts,
            rand_one_dut_hostname,
            rand_one_dut_portname_oper_up,
            lossless_prio_list,          # noqa F811
            lossy_prio_list,
            all_prio_list,             # noqa F811
            prio_dscp_map):              # noqa F811
    """
    Test if PFC can pause multiple lossless priorities

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    api=snappi_api
    conn_data=conn_graph_facts
    fanout_data=fanout_graph_facts
    pause_prio_list=all_prio_list
    test_traffic_pause=True
    snappi_extra_params=None                
    global_pause=False


    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)
    global DATA_FLOW_DURATION_SEC
    global data_flow_delay_sec

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,'Fail to get ID for port {}'.format(dut_port))

    # Single linecard and hence rx_dut and tx_dut are the same.
    # rx_dut and tx_dut are used to verify_pause_frame_count
    rx_dut = duthost
    tx_dut = duthost

    # Rate percent must be an integer
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))

    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config,port_config_list,port_id)


    if snappi_extra_params.headroom_test_params is not None:
        DATA_FLOW_DURATION_SEC += 10
        data_flow_delay_sec += 2

        # Set up pfc delay parameter
        l1_config = testbed_config.layer1[0]
        pfc = l1_config.flow_control.ieee_802_1qbb
        pfc.pfc_delay = snappi_extra_params.headroom_test_params[0]

    if snappi_extra_params.poll_device_runtime:
        # If the switch needs to be polled as traffic is running for stats,
        # then the test runtime needs to be increased for the polling delay
        DATA_FLOW_DURATION_SEC += ANSIBLE_POLL_DELAY_SEC
        data_flow_delay_sec = ANSIBLE_POLL_DELAY_SEC

    if snappi_extra_params.packet_capture_type != packet_capture.NO_CAPTURE:
        # Setup capture config
        if snappi_extra_params.is_snappi_ingress_port_cap:
            # packet capture is required on the ingress snappi port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config["rx_port_name"]]
        else:
            # packet capture will be on the egress snappi port
            snappi_extra_params.packet_capture_ports = [snappi_extra_params.base_flow_config["tx_port_name"]]

        snappi_extra_params.packet_capture_file = snappi_extra_params.packet_capture_type.value

        config_capture_pkt(testbed_config=testbed_config,
                           port_names=snappi_extra_params.packet_capture_ports,
                           capture_type=snappi_extra_params.packet_capture_type,
                           capture_name=snappi_extra_params.packet_capture_file)
        logger.info("Packet capture file: {}.pcapng".format(snappi_extra_params.packet_capture_file))

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

    if snappi_extra_params.traffic_flow_config.background_flow_config is None and \
       snappi_extra_params.gen_background_traffic:
        snappi_extra_params.traffic_flow_config.background_flow_config = {
            "flow_name": BG_FLOW_NAME,
            "flow_dur_sec": DATA_FLOW_DURATION_SEC,
            "flow_rate_percent": bg_flow_rate_percent,
            "flow_rate_pps": None,
            "flow_rate_bps": None,
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": None,
            "flow_delay_sec": data_flow_delay_sec,
            "flow_traffic_type": traffic_flow_mode.FIXED_DURATION
        }

    if snappi_extra_params.traffic_flow_config.pause_flow_config is None:
        snappi_extra_params.traffic_flow_config.pause_flow_config = {
            "flow_name": PAUSE_FLOW_NAME,
            "flow_dur_sec": None,
            "flow_rate_percent": None,
            "flow_rate_pps": calc_pfc_pause_flow_rate(int(testbed_config.layer1[0].speed.split('_')[1])),
            "flow_rate_bps": None,
            "flow_pkt_size": 64,
            "flow_pkt_count": None,
            "flow_delay_sec": 0,
            "flow_traffic_type": traffic_flow_mode.CONTINUOUS
        }

    # PFC pause frame capture is requested
    valid_pfc_frame_test = True if snappi_extra_params.packet_capture_type == packet_capture.PFC_CAPTURE else False
    if valid_pfc_frame_test:
        snappi_extra_params.traffic_flow_config.pause_flow_config["flow_dur_sec"] = DATA_FLOW_DURATION_SEC + \
            data_flow_delay_sec + SNAPPI_POLL_DELAY_SEC + PAUSE_FLOW_DUR_BASE_SEC
        snappi_extra_params.traffic_flow_config.pause_flow_config["flow_traffic_type"] = \
            traffic_flow_mode.FIXED_DURATION

    # Generate test flow config
    generate_test_flows(testbed_config=testbed_config,test_flow_prio_list=test_prio_list,prio_dscp_map=prio_dscp_map,snappi_extra_params=snappi_extra_params)
    # Generate pause storm config
    generate_pause_flows(testbed_config=testbed_config,pause_prio_list=pause_prio_list,global_pause=global_pause,snappi_extra_params=snappi_extra_params)
    # Generate background flow config
    if snappi_extra_params.gen_background_traffic:
        generate_background_flows(testbed_config=testbed_config,bg_flow_prio_list=bg_prio_list,prio_dscp_map=prio_dscp_map,snappi_extra_params=snappi_extra_params)


    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    # Clear PFC, queue and interface counters before traffic run
    duthost.command("pfcstat -c")
    time.sleep(1)
    duthost.command("sonic-clear queuecounters")
    time.sleep(1)
    duthost.command("sonic-clear counters")
    time.sleep(1)

    # Reset pfc delay parameter
    pfc = testbed_config.layer1[0].flow_control.ieee_802_1qbb
    pfc.pfc_delay = 0

    tgen_flow_stats, switch_flow_stats, in_flight_flow_metrics = run_traffic(duthost=duthost,api=api,config=testbed_config,data_flow_names=data_flow_names,all_flow_names=all_flow_names,exp_dur_sec=DATA_FLOW_DURATION_SEC + data_flow_delay_sec,snappi_extra_params=snappi_extra_params)

    # Verify PFC pause frames
    if valid_pfc_frame_test:
        is_valid_pfc_frame, error_msg = validate_pfc_frame(snappi_extra_params.packet_capture_file + ".pcapng")
        pytest_assert(is_valid_pfc_frame, error_msg)
        return

    speed_gbps = int(testbed_config.layer1[0].speed.split('_')[1])
    # Verify pause flows
    verify_pause_flow(flow_metrics=tgen_flow_stats,pause_flow_name=PAUSE_FLOW_NAME)

    if snappi_extra_params.gen_background_traffic:
        # Verify background flows
        verify_background_flow(flow_metrics=tgen_flow_stats,speed_gbps=speed_gbps,tolerance=TOLERANCE_THRESHOLD,snappi_extra_params=snappi_extra_params)
        #*** Failed: Background Flow Prio 1 should not have any dropped packet          XXXXXXXXXX

    # Verify basic test flows metrics from ixia
    verify_basic_test_flow(flow_metrics=tgen_flow_stats,speed_gbps=speed_gbps,tolerance=TOLERANCE_THRESHOLD,test_flow_pause=test_traffic_pause,snappi_extra_params=snappi_extra_params)

    # Verify PFC pause frame count on the DUT
    # rx_dut is Ingress DUT receiving traffic.
    # tx_dut is Egress DUT sending traffic to IXIA and also receiving PFCs.
    verify_pause_frame_count_dut(rx_dut=rx_dut,tx_dut=tx_dut,test_traffic_pause=test_traffic_pause,global_pause=global_pause,snappi_extra_params=snappi_extra_params)

    # Verify in flight TX lossless packets do not leave the DUT when traffic is expected
    # to be paused, or leave the DUT when the traffic is not expected to be paused
    verify_egress_queue_frame_count(duthost=duthost,switch_flow_stats=switch_flow_stats,test_traffic_pause=test_traffic_pause,snappi_extra_params=snappi_extra_params)

    if test_traffic_pause and not snappi_extra_params.gen_background_traffic:
        # Verify TX frame count on the DUT when traffic is expected to be paused
        # and only test traffic flows are generated
        verify_tx_frame_count_dut(duthost=duthost,api=api,snappi_extra_params=snappi_extra_params)
        # ** Failed: Additional frames are transmitted outside of deviation. Possible PFC frames are counted.             XXXXXXXXXXXXXXX
        # Verify TX frame count on the DUT when traffic is expected to be paused
        # and only test traffic flows are generated
        verify_rx_frame_count_dut(duthost=duthost,api=api,snappi_extra_params=snappi_extra_params)
        # *** ZeroDivisionError: division by zero                                      XXXXXXXXXXXXXXXXXXXX
    import pdb;pdb.set_trace()
    '''
    if test_traffic_pause:
        # Verify in flight TX packets count relative to switch buffer size
        verify_in_flight_buffer_pkts(duthost=duthost,flow_metrics=in_flight_flow_metrics,snappi_extra_params=snappi_extra_params)
        # *** Failed: Total TX bytes 24205312 should be smaller than DUT buffer size 14628114          XXXXXXXXXXXXXXXXXXXX
    else:
        # Verify zero pause frames are counted when the PFC class enable vector is not set
        verify_unset_cev_pause_frame_count(duthost=duthost,snappi_extra_params=snappi_extra_params)
    '''
