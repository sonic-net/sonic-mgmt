from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
from itertools import product
from tests.common.telemetry import (
    METRIC_LABEL_DEVICE_ID,
    METRIC_LABEL_DEVICE_PORT_ID,
    METRIC_LABEL_DEVICE_PSU_ID,
    METRIC_LABEL_DEVICE_QUEUE_ID,
    METRIC_LABEL_DEVICE_SENSOR_ID,
)
from tests.common.telemetry.constants import (
    METRIC_LABEL_DEVICE_PSU_MODEL,
    METRIC_LABEL_DEVICE_PSU_SERIAL,
    METRIC_LABEL_DEVICE_PSU_HW_REV,
    METRIC_LABEL_DEVICE_QUEUE_CAST,
)
from tests.common.telemetry.metrics.device import DevicePortMetrics
from tests.common.telemetry.metrics.device import DevicePSUMetrics
from tests.common.telemetry.metrics.device import DeviceQueueMetrics
from tests.common.telemetry.metrics.device import DeviceTemperatureMetrics

logger = logging.getLogger(__name__)
POLL_INTERVAL_SEC = 30

ROUTE_RANGES = {"IPv6": [[["777:777:777::1", 64, 16]]], "IPv4": [[["100.1.1.1", 24, 16]]]}

capacity_param_values = {
    "subnet_type": ["IPv6"],
    "test_duration": [1 * 60, 5 * 60, 15 * 60, 60 * 60, 24 * 60 * 60, 2 * 24 * 60 * 60],
    "frame_size": [86, 128, 256, 512, 1024, 1518],
    "traffic_rate": [10, 25, 50, 75, 100],
}
# Create combinations of parameters as tuples
capacity_param_names = ",".join(capacity_param_values.keys())
capacity_param_product = list(product(*capacity_param_values.values()))


pytestmark = [pytest.mark.topology("nut")]


@pytest.mark.parametrize(capacity_param_values, capacity_param_product)
def test_switch_capacity(
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    db_reporter,
    set_primary_chassis,
    create_snappi_config,
    subnet_type,
    test_duration,
    frame_size,
    traffic_rate,
):
    """
    Assess the capacity limits of SONiC switches using SNAPPI-driven traffic tests.

    This test validates the maximum throughput and performance thresholds by
    configuring traffic flows and measuring switch behavior under load.

    Args:
        duthosts (list): List of DUT (Device Under Test) hosts as pytest fixture.
        snappi_api (object): SNAPPI API session for traffic configuration.
        get_snappi_ports (callable): Fixture/function to retrieve SNAPPI ports.
        fanout_graph_facts_multidut (dict): Fanout topology graph for multi-DUT setups.
        db_reporter (object): Database reporter for logging test results.
        set_primary_chassis (callable): Fixture to define primary chassis for tests.
        create_snappi_config (callable): Callback to create SNAPPI traffic config.
        subnet_type (str): Type of subnet configuration (e.g., 'IPv4', 'IPv6').
        test_duration (int): Duration of the traffic test in seconds.
        frame_size (int): Size of the traffic frames in bytes.
        traffic_rate (float): Traffic rate as a percentage of line rate.

    Returns:
        None: This function does not return a value but logs test metrics.
    """
    logger.info("XXX" * 50)
    logger.info(
        f"Testing {subnet_type} traffic at {traffic_rate}% line rate "
        f"for {test_duration} seconds with frame size {frame_size} bytes"
        )
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports, subnet_type, protocol_type="bgp")
    port_distrbution = (slice(0, len(snappi_ports) // 2), slice(len(snappi_ports) // 2, None))
    tx_ports, rx_ports = snappi_ports[port_distrbution[0]], snappi_ports[port_distrbution[1]]

    dut_tg_port_map = collections.defaultdict(list)
    for intf in tx_ports + rx_ports:
        dut_tg_port_map[intf["duthost"]].append((intf["peer_port"], f"Port_{intf['port_id']}"))
    dut_tg_port_map = {duthost: dict(ports) for duthost, ports in dut_tg_port_map.items()}
    ranges = ROUTE_RANGES[subnet_type]*(len(snappi_ports))
    snappi_extra_params.protocol_config = {
        "Tx": {
            "route_ranges": ranges,
            "protocol_type": "bgp",
            "ports": tx_ports,
            "subnet_type": subnet_type,
            "is_rdma": False,
        },
        "Rx": {
            "route_ranges": ranges,
            "protocol_type": "bgp",
            "ports": rx_ports,
            "subnet_type": subnet_type,
            "is_rdma": False,
        },
    }

    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": traffic_rate,
            "frame_size": frame_size,
            "is_rdma": False,
            "flow_name": "Switch_Capacity_Test",
            "tx_names": snappi_obj_handles["Tx"]["network_group"] + snappi_obj_handles["Rx"]["network_group"],
            "rx_names": snappi_obj_handles["Rx"]["network_group"] + snappi_obj_handles["Tx"]["network_group"],
            "mesh_type": "mesh",
        }
    ]

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    snappi_api.set_config(snappi_config)

    start_stop(snappi_api, operation="start", op_type="protocols")

    # ***************************************************************************
    # Using RestPy Code
    ixnet_traffic_params = {"BiDirectional": True, "SrcDestMesh": "fullMesh"}
    ixnet = snappi_api._ixnetwork
    ixnet.Traffic.TrafficItem.find().update(**ixnet_traffic_params)
    ixnet.Traffic.FrameOrderingMode = "RFC2889"
    # ***************************************************************************

    # Clear all switch counters.
    [duthost.command("sudo sonic-clear counters \n") for duthost in duthosts]

    start_stop(snappi_api, operation="start", op_type="traffic")
    poll_stats(dut_tg_port_map, duration_sec=test_duration, interval_sec=POLL_INTERVAL_SEC, db_reporter=db_reporter)
    db_reporter.report()
    logger.info("Stopping transmit on all flows ...")

    start_stop(snappi_api, operation="stop", op_type="traffic")
    start_stop(snappi_api, operation="stop", op_type="protocols")


def get_dut_stats(dut_tg_port_map):
    """
    Collect raw telemetry statistics from DUTs via CLI/telemetry show commands.

    This function executes pre-defined telemetry commands on each DUT and
    returns their parsed JSON output. It handles queue watermarks, PSU
    information, temperature readings, and per-port statistics.

    Args:
        dut_tg_port_map (dict):
            Mapping of DUT objects to interfaces dictionary.
            Example:
                {
                    duthost1: {"Ethernet0": "peer0", "Ethernet4": "peer1"},
                    duthost2: {"Ethernet8": "peer2"}
                }

    Returns:
        dict:
            Dictionary keyed by DUT hostname, with nested telemetry results.
            Example:
                {
                    "dut1": {
                        "queue": [...],
                        "psu": [...],
                        "temp": [...],
                        "portstat": {...}
                    },
                    "dut2": {...}
                }

    Workflow:
        1. Build set of telemetry commands to run.
        2. For each DUT:
             - Run commands via Ansible `command` module (`duthost.command`).
             - Parse JSON output.
             - For queue metrics, expand to (Port, queue_id, watermark) records.
             - Store results in nested result dictionary.
        3. Errors are logged and marked as `None` for that DUT/command.

    Notes:
        - `queue` output is filtered to only include queues belonging to DUT interfaces.
        - `portstat` combines stats for the DUT's relevant interfaces.
    """
    # Telemetry commands to collect from the DUT
    commands = {
        "queue": "show queue watermark unicast --json",
        "psu": "show platform psu --json",
        "temp": "show platform temperature --json",
        "portstat": "portstat -i {} -j",  # requires port list substitution
    }

    result = {}
    for duthost, interfaces in dut_tg_port_map.items():
        duthostname = duthost.hostname
        logger.info(f"Collecting initial stats from {duthostname}")
        result[duthostname] = {}

        for command_name, command in commands.items():
            logger.info(f"Running command '{command}' on {duthostname}")

            # Special case: portstat must include comma-separated port list
            if command_name == "portstat":
                command = command.format(",".join(interfaces.keys()))

            try:
                raw_output = duthost.command(command)["stdout"]
                json_output = json.loads(raw_output)

                # Special handling for queue: flatten per-port queue stats
                if command_name == "queue":
                    json_output = [
                        {"Port": d["Port"], "queue_id": key, "watermark_byte": d[key]}
                        for d in json_output
                        for key in d.keys()
                        if d["Port"] in interfaces.keys() and (key.startswith("UC") or key.startswith("MC"))
                    ]

                result[duthostname][command_name] = json_output

            except Exception as e:
                logger.error(f"[{duthostname}] Failed to run '{command}': {e}")
                result[duthostname][command_name] = None

    return result


def record_metrics(metric_obj, records, duthostname, label_template, label_map, field_map):
    """
    Record telemetry metrics in a generic, configurable way for any metric type.

    This function abstracts the logic of iterating over telemetry records
    (lists, dicts, or per-port stats), building label dictionaries,
    and recording metrics via the appropriate Device*Metrics object.
    It supports dynamic mappings for both labels (device, port, PSU, queues, sensors)
    and fields (bps, counters, status, voltage, etc).

    Args:
        metric_obj:
            A Device*Metrics object instance (e.g., DevicePortMetrics, DevicePSUMetrics).
        records (dict | list):
            Telemetry records retrieved from the DUT via CLI or telemetry API.
            - If dict: keys are record identifiers (e.g., port names).
            - If list: items are per-record dictionaries.
        duthostname (str):
            Hostname of the current DUT (Device Under Test).
        label_template (dict):
            Base set of labels (keys → telemetry label constants).
            Values are copied and extended with record-specific values.
        label_map (dict):
            Mapping of label constants → record key name or lambda.
            If string: `record[string]` is used
            If callable: `lambda record, key` is executed
        field_map (dict):
            Mapping of metric method names from metric_obj (e.g., "rx_bps")
            → record key name or lambda to extract value.

    Returns:
        None

    Notes:
        - If a mapping source is not found in the record, default values are used.
        - This function is designed to work seamlessly across diverse
          telemetry record types (port stats, PSU, queues, temperature, etc).
    """
    if not records:
        return

    # Handle dict style (like portstat) separately from list
    items = records.items() if isinstance(records, dict) else enumerate(records)

    for key, record in items:
        labels = label_template.copy()
        labels[METRIC_LABEL_DEVICE_ID] = duthostname

        # Populate label fields
        for label_key, src in label_map.items():
            if callable(src):
                labels[label_key] = src(record, key)
            else:
                labels[label_key] = record.get(src, "Unknown")

        # Record metric values
        for method_name, field in field_map.items():
            value = record.get(field, 0) if isinstance(record, dict) else 0
            getattr(metric_obj, method_name).record(value, labels)


def poll_stats(dut_tg_port_map, duration_sec, interval_sec, db_reporter):
    """
    Periodically poll DUT telemetry and record metrics into the reporter.

    Executes telemetry commands on DUTs (queue, PSU, temperature, port stats),
    parses their outputs, and records metrics using configuration-driven
    label and field mappings. The metrics are stored in db_reporter which can later
    be consumed by reporting plugins or dashboards.

    Args:
        dut_tg_port_map (dict):
            Mapping of DUT host objects → port/interface dictionaries.
            This defines which DUTs and ports to poll.
        duration_sec (int):
            Total time in seconds for which polling will run.
        interval_sec (int):
            Time interval in seconds between consecutive polling iterations.
        db_reporter:
            Reporter instance that collects and aggregates metrics for persistence or export.

    Returns:
        None
    """
    label_templates = {
        "portstat": {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_PORT_ID: None},
        "psu": {
            METRIC_LABEL_DEVICE_ID: None,
            METRIC_LABEL_DEVICE_PSU_ID: None,
            METRIC_LABEL_DEVICE_PSU_MODEL: None,
            METRIC_LABEL_DEVICE_PSU_SERIAL: None,
            METRIC_LABEL_DEVICE_PSU_HW_REV: None,
        },
        "queue": {
            METRIC_LABEL_DEVICE_ID: None,
            METRIC_LABEL_DEVICE_PORT_ID: None,
            METRIC_LABEL_DEVICE_QUEUE_ID: None,
            METRIC_LABEL_DEVICE_QUEUE_CAST: "unicast",
        },
        "temp": {METRIC_LABEL_DEVICE_ID: None, METRIC_LABEL_DEVICE_SENSOR_ID: None},
    }

    metrics = {
        "portstat": DevicePortMetrics(reporter=db_reporter),
        "psu": DevicePSUMetrics(reporter=db_reporter),
        "queue": DeviceQueueMetrics(reporter=db_reporter),
        "temp": DeviceTemperatureMetrics(reporter=db_reporter),
    }

    # --------------------------------------------------------------------------
    # Telemetry Configurations:
    # Each entry defines how raw JSON output from DUT maps to labels + metrics.
    # --------------------------------------------------------------------------
    configs = {
        # -----------------
        # Queue Watermarks:
        # "show queue watermark unicast --json"
        # Records the per-queue buffer usage (watermark in bytes).
        "queue": dict(
            metric_obj=metrics["queue"],
            label_template=label_templates["queue"],
            label_map={
                METRIC_LABEL_DEVICE_PORT_ID: "Port",  # Port ID from record
                METRIC_LABEL_DEVICE_QUEUE_ID: "queue_id",  # Queue ID from record
                METRIC_LABEL_DEVICE_QUEUE_CAST: lambda r, _: "unicast",  # Constant label
            },
            field_map={
                "watermark_bytes": "watermark_byte",  # Actual watermark value
            },
        ),
        # -----------------
        # PSU Metrics:
        # "show platform psu --json"
        # Records voltage, current, power, and status/LED for each power supply.
        "psu": dict(
            metric_obj=metrics["psu"],
            label_template=label_templates["psu"],
            label_map={
                METRIC_LABEL_DEVICE_PSU_ID: "name",  # PSU slot name
                METRIC_LABEL_DEVICE_PSU_MODEL: "model",  # PSU model
                METRIC_LABEL_DEVICE_PSU_SERIAL: "serial",  # Serial number
                METRIC_LABEL_DEVICE_PSU_HW_REV: "revision",  # Hardware revision
            },
            field_map={
                "voltage": "voltage",  # PSU voltage reading
                "current": "current",  # Current (Amps)
                "power": "power",  # Power (Watts)
                "status": lambda r: r.get("status", {}).get("value", 0),  # Operational status (OK/Fail)
                "led": lambda r: r.get("led", {}).get("value", 0),  # LED state (color/status)
            },
        ),
        # -----------------
        # Temperature Metrics:
        # "show platform temperature --json"
        # Records temperature values and thresholds per temperature sensor.
        "temp": dict(
            metric_obj=metrics["temp"],
            label_template=label_templates["temp"],
            label_map={
                METRIC_LABEL_DEVICE_SENSOR_ID: "Sensor",  # Sensor identifier
            },
            field_map={
                "reading": "Temperature",  # Current temperature
                "high_th": "High_TH",  # High threshold
                "low_th": "Low_TH",  # Low threshold
                "crit_high_th": "Crit_High_TH",  # Critical high threshold
                "crit_low_th": "Crit_Low_TH",  # Critical low threshold
                "warning": "Warning",  # Warning indicator
            },
        ),
        # -----------------
        # Port Stats:
        # "portstat -i PORTS -j"
        # Records per-port throughput, utilization, error, and drop counters.
        "portstat": dict(
            metric_obj=metrics["portstat"],
            label_template=label_templates["portstat"],
            label_map={
                METRIC_LABEL_DEVICE_PORT_ID: lambda _, k: k,  # Key is the port name
            },
            field_map={
                "rx_bps": "RX_BPS",  # RX throughput (bps)
                "tx_bps": "TX_BPS",  # TX throughput (bps)
                "rx_util": "RX_UTIL",  # RX utilization (% of line rate)
                "tx_util": "TX_UTIL",  # TX utilization (% of line rate)
                "rx_ok": "RX_OK",  # Successful RX packets
                "tx_ok": "TX_OK",  # Successful TX packets
                "rx_err": "RX_ERR",  # RX errors
                "tx_err": "TX_ERR",  # TX errors
                "rx_drop": "RX_DRP",  # Dropped RX packets
                "tx_drop": "TX_DRP",  # Dropped TX packets
                "rx_overrun": "RX_OVR",  # RX buffer overruns
                "tx_overrun": "TX_OVR",  # TX buffer overruns
            },
        ),
    }

    end_time = time.time() + duration_sec
    logger.info(f"Started polling every {interval_sec: .2f}s for {duration_sec}s")

    while time.time() < end_time:
        poll_start = time.time()
        results = get_dut_stats(dut_tg_port_map)

        for duthostname, outputs in results.items():
            logger.info(f"Stats from {duthostname}: {outputs}")
            for stat_type, cfg in configs.items():
                record_metrics(
                    cfg["metric_obj"],
                    outputs.get(stat_type),
                    duthostname,
                    cfg["label_template"],
                    cfg["label_map"],
                    cfg["field_map"],
                )

        time.sleep(max(0, interval_sec - (time.time() - poll_start)))

    logger.info(f"Finished polling after {duration_sec}s.")
