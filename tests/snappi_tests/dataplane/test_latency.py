from tests.snappi_tests.dataplane.imports import *  # noqa F403
sys.path.append('../test_reporting/telemetry')
from snappi_tests.dataplane.files.helper import *  # noqa F403
from metric_definitions import *   # noqa E402
from reporter_factory import TelemetryReporterFactory  # noqa F403
from metrics import GaugeMetric  # noqa E402

common_labels = [
    Point("Test_Info")
    .tag("METRIC_LABEL_TESTBED", "TB-XYZ")
    .tag("METRIC_LABEL_TEST_BUILD", "2024.1103")
    .tag("METRIC_LABEL_TEST_CASE", os.path.basename(__file__))
    .tag("METRIC_LABEL_TEST_FILE", os.path.basename(__file__))
    .tag(
        "METRIC_LABEL_TEST_JOBID",
        f"{os.path.basename(__file__)}_{datetime.now():%Y%m%d_%H%M%S}"
    )
]

reporter = TelemetryReporterFactory.create_periodic_metrics_reporter(common_labels)

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("tgen")]

# Test Parameters
frame_sizes_rate = [
    (66, 56.59),
    (86, 69),
    (128, 96.91),
    (1500, 90),
    (4000, 90),
    (8000, 90),
]
num_iterations = 1
oversubscription_percentage = 10
DATA_FLOW_DURATION_SEC = 300

metrics = {
    "traffic": {
        "Store-Forward Avg Latency (ns)": GaugeMetric(
            METRIC_NAME_LATENCY_L3_AVG_NS, "Avg Latency", "frames", reporter
        ),
        "Store-Forward Min Latency (ns)": GaugeMetric(
            METRIC_NAME_LATENCY_L3_MIN_NS, "Min Latency", "frames", reporter
        ),
        "Store-Forward Max Latency (ns)": GaugeMetric(
            METRIC_NAME_LATENCY_L3_MAX_NS, "Max Latency", "frames", reporter
        ),
        "Loss %": GaugeMetric(
            METRIC_NAME_NO_LOSS_MAX_RATE, "Transmitted Loss %", "frames", reporter
        ),
    }
}


@pytest.fixture(scope="session", autouse=True)
def session_teardown(request):
    yield
    request.session.ixnet_session.remove()
    logger.info("\n=== Custom session teardown in Test Script ===")


@pytest.mark.parametrize("rfc2889", ['RFC2889', 'none'])
@pytest.mark.parametrize("frame_size_rate", frame_sizes_rate)
@pytest.mark.parametrize("num_iterations", [num_iterations])
def test_latency_measurement(
    request,
    snappi_api,
    set_primary_chassis,
    conn_graph_facts,
    fanout_graph_facts,
    duthosts,
    get_snappi_ports,
    setup_and_teardown,
    frame_size_rate,
    num_iterations,
    rfc2889
):
    ixnet, session_assistant, test_name = setup_and_teardown
    start_traffic(ixnet, generate_apply_traffic=True)
    tiStats = StatViewAssistant(ixnet, "Traffic Item Statistics")
    tdf = pd.DataFrame(tiStats.Rows.RawData, columns=tiStats.ColumnHeaders)
    tdf["Store-Forward Avg Latency (ns)"] = pd.to_numeric(tdf["Store-Forward Avg Latency (ns)"], errors="coerce")
    tdf["RTT (ns)"] = tdf["Store-Forward Avg Latency (ns)"] * 2
    logger.info("Dumping Traffic  Stats.\n{}".format(tabulate(tdf, headers="keys", tablefmt="psql")))

    flwStats = StatViewAssistant(ixnet, "Flow Statistics")
    # binStats = StatViewAssistant(ixnet, "Bin Statistics")
    applied_frame_size = ixnet.Traffic.TrafficItem.find()[0].HighLevelStream.find()[0].AppliedFrameSize
    logger.info(
        f"FrameOrderingMode: {ixnet.Traffic.FrameOrderingMode}, "
        f"Fetching Stats — Frame Size: {applied_frame_size}, "
        f"Rate: {frame_size_rate[1]}"
    )
    end_time = time.time() + DATA_FLOW_DURATION_SEC
    interval_sec = 30
    logger.info(f"Started polling Flow Statistics every {interval_sec:.2f}s for {DATA_FLOW_DURATION_SEC}s")
    frameordermode = ixnet.Traffic.FrameOrderingMode
    while time.time() < end_time:
        poll_start = time.time()
        flow_df = pd.DataFrame(flwStats.Rows.RawData, columns=flwStats.ColumnHeaders)
        # bin_df = pd.DataFrame(binStats.Rows.RawData, columns=binStats.ColumnHeaders)
        for _, row in flow_df.iterrows():
            labels = {
                METRIC_LABEL_DEVICE_ID: duthosts[0].hostname,
                METRIC_LABEL_DEVICE_EGRESS_PORT_ID: row["Tx Port"],
                METRIC_LABEL_DEVICE_INGRESS_PORT_ID: row["Rx Port"],
                METRIC_LABEL_DEVICE_TG_TRAFFIC_RATE: frame_size_rate[1],
                METRIC_LABEL_DEVICE_TG_FRAME_BYTES: applied_frame_size,
                METRIC_LABEL_DEVICE_TG_RFC2889_ENABLED: frameordermode,
            }
            for field, metric in metrics['traffic'].items():
                metric.record(labels, row[field])
        # pr(reporter.metrics)
        # logger.info(reporter.metrics)
        reporter.report()
        elapsed = time.time() - poll_start
        time.sleep(max(0, interval_sec - elapsed))

    logger.info(f"Finished polling after {DATA_FLOW_DURATION_SEC}s.")
    stop_traffic(ixnet)


@pytest.mark.parametrize("rfc2889", ['none'])
@pytest.mark.parametrize("frame_size_rate", frame_sizes_rate)
@pytest.mark.parametrize("num_iterations", [num_iterations])
def test_latency_oversubscription(
    request,
    snappi_api,
    set_primary_chassis,
    conn_graph_facts,
    fanout_graph_facts,
    duthosts,
    get_snappi_ports,
    setup_and_teardown,
    frame_size_rate,
    num_iterations,
    rfc2889
):
    ixnet, session_assistant, test_name = setup_and_teardown

    frame_size, rate = request.getfixturevalue("frame_size_rate")
    # Calculate oversubscription factor and total traffic rate
    port_speed = int(get_snappi_ports[0]['snappi_speed_type'].split('_')[1])
    total_traffic_rate = port_speed * (1 + oversubscription_percentage / 100)  # Gbps
    # Convert total traffic rate to frames per second (1e9 gigabits per second (Gbps))
    frame_rate_per_port = (total_traffic_rate * 1e9) / (frame_size * 8) / (len(get_snappi_ports) - 1)
    # Calculate frame rate percentage relative to port speed

    rate = (frame_rate_per_port * (frame_size * 8) / (port_speed * 1e9)) * 100
    request.session.rate = rate

    ixnet.Traffic.TrafficItem.find().ConfigElement.find().FrameRate.Rate = rate
    start_traffic(ixnet, generate_apply_traffic=True)

    time.sleep(20)

    tiStatistics = StatViewAssistant(ixnet, "Traffic Item Statistics")
    tdf = pd.DataFrame(tiStatistics.Rows.RawData, columns=tiStatistics.ColumnHeaders)
    tdf["Store-Forward Avg Latency (ns)"] = pd.to_numeric(tdf["Store-Forward Avg Latency (ns)"], errors="coerce")
    tdf["RTT (ns)"] = tdf["Store-Forward Avg Latency (ns)"] * 2

    flwStats = StatViewAssistant(ixnet, "Flow Statistics")
    # binStats = StatViewAssistant(ixnet, "Bin Statistics")
    applied_frame_size = ixnet.Traffic.TrafficItem.find()[0].HighLevelStream.find()[0].AppliedFrameSize
    logger.info(
        f"FrameOrderingMode: {str(ixnet.Traffic.FrameOrderingMode)}, "
        f"Fetching Stats — Frame Size: {applied_frame_size}, Rate: {frame_size_rate[1]}"
    )
    end_time = time.time() + DATA_FLOW_DURATION_SEC
    interval_sec = 30
    logger.info(f"Started polling Flow Statistics every {interval_sec:.2f}s for {DATA_FLOW_DURATION_SEC}s")
    frameordermode = ixnet.Traffic.FrameOrderingMode
    while time.time() < end_time:
        poll_start = time.time()
        flow_df = pd.DataFrame(flwStats.Rows.RawData, columns=flwStats.ColumnHeaders)
        # bin_df = pd.DataFrame(binStats.Rows.RawData, columns=binStats.ColumnHeaders)
        for _, row in flow_df.iterrows():
            labels = {
                METRIC_LABEL_DEVICE_ID: duthosts[0].hostname,
                METRIC_LABEL_DEVICE_EGRESS_PORT_ID: row["Tx Port"],
                METRIC_LABEL_DEVICE_INGRESS_PORT_ID: row["Rx Port"],
                METRIC_LABEL_DEVICE_TG_TRAFFIC_RATE: frame_size_rate[1],
                METRIC_LABEL_DEVICE_TG_FRAME_BYTES: applied_frame_size,
                METRIC_LABEL_DEVICE_TG_RFC2889_ENABLED: frameordermode,
            }
            for field, metric in metrics['traffic'].items():
                metric.record(labels, row[field])
        # pr(reporter.metrics)
        # logger.info(reporter.metrics)
        reporter.report()
        elapsed = time.time() - poll_start
        time.sleep(max(0, interval_sec - elapsed))
    stop_traffic(ixnet)


@pytest.fixture(scope="function", autouse=True)
def setup_and_teardown(request, duthosts, snappi_api, get_snappi_ports, set_primary_chassis):
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports)
    session_name = "LatencyMeasurement"
    frame_ordering = request.getfixturevalue("rfc2889")
    frame_size, rate = request.getfixturevalue("frame_size_rate")
    test_name = f"{request.node.originalname}_framesize{frame_size}_rate{rate}_frameorder{frame_ordering}"
    port_distrbution = (slice(0, len(get_snappi_ports) // 2), slice(len(get_snappi_ports) // 2, None))
    testplatform = TestPlatform(ip_address=snappi_api._address, rest_port=snappi_api._port)
    testplatform.Authenticate(snappi_api._username, snappi_api._password)
    config = IxNetConfigParams(
        frame_size=frame_size,
        frame_rate=rate,
        frame_ordering_mode=frame_ordering,
        latency_bins={
            "Caption": "Bin Statistics",
            "NumberOfBins": 5,
            "BinLimits": [0.6, 0.8, 1, 1.2, 2147483647.0],
        },
        traffic_type="ipv6",
    )

    if "test_latency_oversubscription" in test_name:
        testplatform.Sessions.find(Name=session_name).remove()
        session_name = "LatencyOversubscription"
        port_distrbution = (slice(-1, None), slice(None, -1))
        config.bidirectional = False
        config.traffic_mesh = "oneToOne"
        config.traffic_type = "ipv6"

    ixnet_session = testplatform.Sessions.find(Name=session_name)
    session_assistant = SessionAssistant(
        IpAddress=snappi_api._address,
        RestPort=snappi_api._port,
        UserName=snappi_api._username,
        Password=snappi_api._password,
        SessionName=session_name,
    )
    ixnet = session_assistant.Ixnetwork
    request.session.ixnet_session = session_assistant.Session

    if not ixnet_session:
        logger.info(f"Starting IxNetwork Session Id {session_assistant.Session}")
        logger.info("Session and ixnetwork initialized.")

        for ch in snappi_api._ixnet_specific_config.chassis_chains:
            ixnet.Locations.add(Hostname=ch.primary, ChainTopology="star")
            for se in ch.secondary:
                ixnet.Locations.add(Hostname=se.location, PrimaryDevice=ch.primary)
        setup_ixnetwork_config(ixnet, snappi_ports, port_distrbution, config)
    else:
        logger.info(f"Using Existing IxNetwork Session Id: {session_assistant.Session}")
        stop_traffic(ixnet)
        stop_protocols(ixnet)
        ixnet.Traffic.FrameOrderingMode = frame_ordering
        ixnet.Traffic.TrafficItem.find(Name=config.traffic_name).ConfigElement.find().FrameSize.FixedSize = frame_size
        ixnet.Traffic.TrafficItem.find(Name=config.traffic_name).ConfigElement.find().FrameRate.Rate = rate
        start_protocols(ixnet)

    yield ixnet, session_assistant, test_name
