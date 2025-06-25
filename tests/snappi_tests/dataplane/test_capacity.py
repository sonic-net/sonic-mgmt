from tests.snappi_tests.dataplane.imports import *  # noqa: F401

sys.path.append("../test_reporting/telemetry")
from snappi_tests.dataplane.files.helper import (
    create_snappi_config,
    create_traffic_items,
    set_primary_chassis,
    create_snappi_l1config,
    get_duthost_bgp_details,
)  # noqa: F401
from reporter_factory import TelemetryReporterFactory
from metric_definitions import *
from metrics import GaugeMetric

logger = logging.getLogger(__name__)
POLL_INTERVAL_SEC = 30
TRAFFIC_RATE = 56  # Some test parameter
FRAME_SIZE = 512
DATA_FLOW_DURATION_SEC = 120
TIMEOUT = 30


common_labels = [
    Point("Test_Info")
    .tag("METRIC_LABEL_TESTBED", "TB-XYZ")
    .tag("METRIC_LABEL_TEST_BUILD", "2024.1103")
    .tag("METRIC_LABEL_TEST_CASE", os.path.basename(__file__))
    .tag("METRIC_LABEL_TEST_FILE", os.path.basename(__file__))
    .tag(
        "METRIC_LABEL_TEST_JOBID",
        f'{os.path.basename(__file__)}_{datetime.now().strftime("%Y%m%d")}_{datetime.now().strftime("%H:%M:%S")}',
    )
]

reporter = TelemetryReporterFactory.create_periodic_metrics_reporter(common_labels)


pytestmark = [pytest.mark.topology("tgen")]


@pytest.mark.parametrize("subnet_type", ["IPv6"])
def test_capacity_ipv4(
    duthosts,
    snappi_api,
    set_primary_chassis,  # noqa: F811
    get_snappi_ports,  # noqa: F811
    create_snappi_l1config,  # noqa: F811
    subnet_type,
    fanout_graph_facts_multidut,
):
    """
    Demo Test Riff

    Args:
        duthosts (pytest fixture): list of DUTs
        snappi_api (pytest fixture): SNAPPI session
        fanout_graph_facts_multidut (pytest fixture): fanout graph
    Returns:
        N/A
    """

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.interface_type = "bgp"
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports)
    half_ports = int(len(snappi_ports) / 2)
    tx_ports = snappi_ports[:half_ports]
    rx_ports = snappi_ports[half_ports:]
    snappi_config = create_snappi_l1config
    snappi_extra_params.protocol_config = {
        "Tx": {"network_group": False, "protocol_type": "bgp", "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"network_group": False, "protocol_type": "bgp", "ports": rx_ports, "subnet_type": subnet_type},
    }
    snappi_config, snappi_obj_handles = create_snappi_config(snappi_config, snappi_extra_params)
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": TRAFFIC_RATE,
            "frame_size": FRAME_SIZE,
            "is_rdma": False,
            "flow_name": "Capacity_Traffic",
            "tx_names": snappi_obj_handles["Tx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["ip"],
        }
    ]

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    snappi_api.set_config(snappi_config)
    logger.info("Starting Protocol")
    cs = snappi_api.control_state()
    cs.protocol.all.state = cs.protocol.all.START
    snappi_api.set_control_state(cs)
    wait(TIMEOUT, "For Protocols To start")
    logger.info("Starting transmit on all flows ...")
    ts = snappi_api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    snappi_api.set_control_state(ts)
    time.sleep(30)
    poll_stats(duthosts, duration_sec=DATA_FLOW_DURATION_SEC, interval_sec=POLL_INTERVAL_SEC)
    reporter.report()
    logger.info("Stopping transmit on all flows ...")
    ts = snappi_api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
    snappi_api.set_control_state(ts)


def poll_stats(duthosts, duration_sec, interval_sec):
    """
    Poll IxNetwork statistics view at regular intervals (in seconds) for a given duration.

    Args:
        duthost: Device under test (passed to your stats collector)
        duration_sec: Total duration to poll for, in seconds
        interval_sec: Interval between polls, in seconds (e.g., 0.5 for 500ms)
    """
    metric_groups = get_metric_groups()

    def collect_and_report_metrics(duthost):
        """
        Collects metrics from the DUT and reports them to the specified reporter.
        """
        duthostname = duthost.hostname
        for group_name, group_data in metric_groups.items():
            command = group_data["command"]
            metrics = group_data["metrics"]
            preprocess = group_data.get("preprocess")
            process = group_data["process"]

            try:
                raw_output = duthost.command(command)["stdout"]
                json_output = json.loads(raw_output)
            except Exception as e:
                logger.error(f"[{duthostname}] Failed to run '{command}': {e}")
                continue

            processed_items = preprocess(json_output) if preprocess else json_output
            if isinstance(processed_items, dict):
                processed_items = [processed_items]

            for item in processed_items:
                labels, values = process(item, duthostname)
                for metric_key, value in values.items():
                    metric_obj = metrics.get(metric_key)
                    if metric_obj:
                        metric_obj.record(labels, value)
                    else:
                        logger.warning(f"Metric '{metric_key}' not found in the metrics dictionary")

    end_time = time.time() + duration_sec

    logger.info(f"Started polling every {interval_sec:.2f}s for {duration_sec}s")

    while time.time() < end_time:
        poll_start = time.time()
        try:
            for duthost in duthosts:
                collect_and_report_metrics(duthost)
                logger.info(f"Polled {duthost.hostname}at {time.strftime('%H:%M:%S')}, rows={len(reporter.metrics)}")
        except Exception as e:
            logger.exception(e, "Failed during polling or data collection")
        # Maintain fixed interval
        elapsed = time.time() - poll_start
        time.sleep(max(0, interval_sec - elapsed))

    logger.info(f"Finished polling after {duration_sec}s.")


# Define all metrics centrally
def get_metric_groups():
    metric_groups = {
        METRIC_GROUP.PORT_METRICS.value: {
            "metrics": {
                "STATE": GaugeMetric(name=METRIC_NAME_PORT_STATE, description="Xyz", unit="V", reporter=reporter),
                "RX_BPS": GaugeMetric(name=METRIC_NAME_PORT_RX_BPS, description="Xyz", unit="V", reporter=reporter),
                "RX_UTIL": GaugeMetric(
                    name=METRIC_NAME_PORT_RX_UTIL_PCT, description="Xyz", unit="V", reporter=reporter
                ),
                "RX_OK": GaugeMetric(
                    name=METRIC_NAME_PORT_RX_PACKETS_OK, description="Xyz", unit="V", reporter=reporter
                ),
                "RX_ERR": GaugeMetric(
                    name=METRIC_NAME_PORT_RX_PACKETS_ERR, description="Xyz", unit="V", reporter=reporter
                ),
                "RX_DRP": GaugeMetric(
                    name=METRIC_NAME_PORT_RX_PACKETS_DROP, description="Xyz", unit="V", reporter=reporter
                ),
                "RX_OVR": GaugeMetric(
                    name=METRIC_NAME_PORT_RX_PACKETS_OVERRUN, description="Xyz", unit="V", reporter=reporter
                ),
                "TX_BPS": GaugeMetric(name=METRIC_NAME_PORT_TX_BPS, description="Xyz", unit="V", reporter=reporter),
                "TX_UTIL": GaugeMetric(
                    name=METRIC_NAME_PORT_TX_UTIL_PCT, description="Xyz", unit="V", reporter=reporter
                ),
                "TX_OK": GaugeMetric(
                    name=METRIC_NAME_PORT_TX_PACKETS_OK, description="Xyz", unit="V", reporter=reporter
                ),
                "TX_ERR": GaugeMetric(
                    name=METRIC_NAME_PORT_TX_PACKETS_ERR, description="Xyz", unit="V", reporter=reporter
                ),
                "TX_DRP": GaugeMetric(
                    name=METRIC_NAME_PORT_TX_PACKETS_DROP, description="Xyz", unit="V", reporter=reporter
                ),
                "TX_OVR": GaugeMetric(
                    name=METRIC_NAME_PORT_TX_PACKETS_OVERRUN, description="Xyz", unit="V", reporter=reporter
                ),
            },
            "command": "portstat -s all -j",
            "preprocess": lambda data: [{"Port": port, **metrics_fileds} for port, metrics_fileds in data.items()],
            "process": lambda counters, duthostname: (
                {METRIC_LABEL_DEVICE_ID: duthostname, METRIC_LABEL_DEVICE_PORT_ID: counters.get("Port", "Unknown")},
                {key: counters.get(key, 0) for key in metric_groups[METRIC_GROUP.PORT_METRICS.value]["metrics"].keys()},
            ),
        },
        METRIC_GROUP.QUEUE_METRICS.value: {
            "metrics": {
                "bytes": GaugeMetric(
                    name=METRIC_NAME_QUEUE_WATERMARK_BYTES, description="Xyz", unit="V", reporter=reporter
                )
            },
            "command": "show queue watermark unicast --json",
            "preprocess": lambda data: [
                {"Port": port, "queue_id": k, "bytes": int(v)}
                for port, port_data in data.items()
                for k, v in port_data.items()
            ],
            "process": lambda queue, duthostname: (
                {
                    METRIC_LABEL_DEVICE_ID: duthostname,
                    METRIC_LABEL_DEVICE_PORT_ID: queue.get("Port", "Unknown"),
                    METRIC_LABEL_DEVICE_QUEUE_ID: queue.get("queue_id", "Unknown"),
                    METRIC_LABEL_DEVICE_QUEUE_CAST: "unicast",
                },
                {key: queue.get(key, 0) for key in metric_groups[METRIC_GROUP.QUEUE_METRICS.value]["metrics"].keys()},
            ),
        },
        METRIC_GROUP.PSU_METRICS.value: {
            "metrics": {
                "voltage": GaugeMetric(
                    name=METRIC_NAME_PSU_VOLTAGE,
                    description="Power supply unit voltage reading",
                    unit="V",
                    reporter=reporter,
                ),
                "current": GaugeMetric(
                    name=METRIC_NAME_PSU_CURRENT,
                    description="Power supply unit current reading",
                    unit="A",
                    reporter=reporter,
                ),
                "power": GaugeMetric(
                    name=METRIC_NAME_PSU_POWER,
                    description="Power supply unit power reading",
                    unit="W",
                    reporter=reporter,
                ),
                "status": GaugeMetric(
                    name=METRIC_NAME_PSU_STATUS, description="Power supply unit status", unit="N/A", reporter=reporter
                ),
                "led": GaugeMetric(
                    name=METRIC_NAME_PSU_LED, description="Power supply unit LED state", unit="N/A", reporter=reporter
                ),
            },
            "command": "show platform psu --json",
            "process": lambda psu, duthostname: (
                {
                    METRIC_LABEL_DEVICE_ID: duthostname,
                    METRIC_LABEL_DEVICE_PSU_ID: psu.get("name", "Unknown"),
                    METRIC_LABEL_DEVICE_PSU_MODEL: psu.get("model", "Unknown"),
                    METRIC_LABEL_DEVICE_PSU_SERIAL: psu.get("serial", "Unknown"),
                    METRIC_LABEL_DEVICE_PSU_HW_REV: psu.get("revision", "Unknown"),
                },
                {key: psu.get(key, 0) for key in metric_groups[METRIC_GROUP.PSU_METRICS.value]["metrics"].keys()},
            ),
        },
        METRIC_GROUP.TEMPERATURE_METRICS.value: {
            "metrics": {
                "Temperature": GaugeMetric(
                    name=METRIC_NAME_TEMPERATURE_READING,
                    description="Sensor temperature reading",
                    unit="V",
                    reporter=reporter,
                ),
                "High_TH": GaugeMetric(
                    name=METRIC_NAME_TEMPERATURE_HIGH_TH, description="High threshold", unit="V", reporter=reporter
                ),
                "Low_TH": GaugeMetric(
                    name=METRIC_NAME_TEMPERATURE_LOW_TH, description="Low threshold", unit="V", reporter=reporter
                ),
                "Crit_High_TH": GaugeMetric(
                    name=METRIC_NAME_TEMPERATURE_CRIT_HIGH_TH,
                    description="Critical high threshold",
                    unit="V",
                    reporter=reporter,
                ),
                "Crit_Low_TH": GaugeMetric(
                    name=METRIC_NAME_TEMPERATURE_CRIT_LOW_TH,
                    description="Critical low threshold",
                    unit="V",
                    reporter=reporter,
                ),
                "Warning": GaugeMetric(
                    name=METRIC_NAME_TEMPERATURE_WARNING, description="Warning level", unit="V", reporter=reporter
                ),
            },
            "command": "show platform temperature --json",
            "process": lambda temperature, duthostname: (
                {
                    METRIC_LABEL_DEVICE_ID: duthostname,
                    METRIC_LABEL_DEVICE_SENSOR_ID: temperature.get("Sensor", "Unknown"),
                },
                {
                    key: temperature.get(key, 0)
                    for key in metric_groups[METRIC_GROUP.TEMPERATURE_METRICS.value]["metrics"].keys()
                },
            ),
        },
    }
    return metric_groups
