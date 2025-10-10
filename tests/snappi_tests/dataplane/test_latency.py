from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
from tests.common.telemetry import (
    UNIT_SECONDS,
)
from tests.common.telemetry.constants import (
    METRIC_LABEL_TG_TRAFFIC_RATE,
    METRIC_LABEL_TG_FRAME_BYTES,
    METRIC_LABEL_TG_RFC2889_ENABLED,
)

from tests.common.telemetry.metrics import GaugeMetric
from copy import deepcopy
from itertools import product


logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("tgen")]

# Test Parameters
ROUTE_RANGES = {"IPv6": [["777:777:777::1", 64, 5000]], "IPv4": [["100.1.1.1", 24, 5000]]}

latency_param_values = {
    "ip_version": ["IPv6"],
    "test_duration": [60],
    "rfc2889_enabled": [True, False],
    "frame_size": [64, 128, 256, 512, 1024, 4096, 8192],
    "traffic_rate": [10, 25, 50, 75, 100],
    "num_iterations": [1],
}

oversubscription_param_values = {
    "ip_version": ["IPv6"],
    "test_duration": [60],
    "rfc2889_enabled": [True, False],
    "frame_size": [64, 128, 256, 512, 1024, 4096, 8192],
    "traffic_rate": [10, 25, 50, 75, 100],
    "num_iterations": [1],
    "rx_port_index": [3],
    "tx_port_count": [2],
}

# Create combinations of parameters as tuples
oversubscription_param_names = ",".join(oversubscription_param_values.keys())
oversubscription_param_product = list(product(*oversubscription_param_values.values()))
latency_param_names = ",".join(latency_param_values.keys())
latency_param_product = list(product(*latency_param_values.values()))

oversubscription_percentage = 10
DATA_FLOW_DURATION_SEC = 60


@pytest.mark.parametrize(latency_param_names, latency_param_product)
def test_latency_measurement(
    request,
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_config,
    db_reporter,
    ip_version,
    test_duration,
    frame_size,
    traffic_rate,
    num_iterations,
    rfc2889_enabled,
):
    """
    Test Function: Latency Measurement Test

    This function measures and reports network latency metrics for defined traffic flows using a traffic generator.

    Test Warmup:
    1. Sends the same traffic as the main test for 1 minute to warm up the testbed.
    2. Clears all relevant counters on the traffic generator before measurements start.

    Description:
    - Configures the traffic generator according to given test parameters (traffic pattern, rate, frame size, etc.).
    - Generates traffic and captures latency data for each configured flow.
    - Reports the measured latency for each traffic item in the test.

    Parameters:
    - Depends on the test scenario; typical parameters include
        - traffic_rate,rfc2889_enabled, frame_size, ip_version, duration_sec.

    Steps:
    1. Set up traffic on the traffic generator according to test case settings.
    2. Measure and collect latency statistics.
    3. Report latency results for each traffic flow.

    Returns:
    None. Latency results are reported/logged as part of the test process.
    """

    logger.info(
        f"Testing {ip_version} traffic at {traffic_rate}% line rate for {test_duration} seconds "
        f"with frame size {frame_size} bytes | Frame Ordering: {rfc2889_enabled}, Iterations: {num_iterations}"
    )
    snappi_config, snappi_obj_handles, snappi_extra_params, snappi_ports, tx_ports, rx_ports = setup_snappi_test(
        duthosts,
        get_snappi_ports,
        create_snappi_config,
        ip_version,
        ROUTE_RANGES,
        port_selector="half_split",
    )
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": traffic_rate,
            "frame_size": frame_size,
            "flow_name": "latency_measurement",
            "tx_names": snappi_obj_handles["Tx"]["network_group"] + snappi_obj_handles["Rx"]["network_group"],
            "rx_names": snappi_obj_handles["Rx"]["network_group"] + snappi_obj_handles["Tx"]["network_group"],
            "mesh_type": "mesh",
            "latency": True,
        }
    ]

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    snappi_api.set_config(snappi_config)
    ixnet = snappi_api._ixnetwork
    ixnet_traffic_params = {"BiDirectional": True, "SrcDestMesh": "fullMesh"}
    ixnet.Traffic.TrafficItem.find().update(**ixnet_traffic_params)
    ixnet.Traffic.FrameOrderingMode = "RFC2889" if rfc2889_enabled else "none"
    start_stop(snappi_api, operation="start", op_type="protocols", waittime=3)
    start_stop(snappi_api, operation="start", op_type="traffic")

    logger.info(
        f"RFC2889_enabled: {rfc2889_enabled}, " f"Fetching Stats — Frame Size: {frame_size}, " f"Rate: {traffic_rate}"
    )
    poll_latency_metrics(
        ixnet, test_duration, db_reporter, duthosts, ip_version, traffic_rate, frame_size, rfc2889_enabled
    )
    start_stop(snappi_api, operation="stop", op_type="traffic")


@pytest.mark.parametrize(oversubscription_param_names, oversubscription_param_product)
def test_latency_oversubscription(
    request,
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_config,
    db_reporter,
    ip_version,
    test_duration,
    frame_size,
    traffic_rate,
    num_iterations,
    rfc2889_enabled,
    rx_port_index,
    tx_port_count,
):
    """
    Test Function: Latency Oversubscription Test

    This test verifies latency performance under oversubscribed traffic conditions on a traffic generator.

    Test Warmup:
    1. Run the same traffic that each test is testing for 1 minute to warm up the testbed.
    2. Clean up the traffic generator counters.

    Test Case Description:
    - Generate traffic from multiple TX ports to a single RX port on the traffic generator.
    - The number of TX ports used defines the oversubscription ratio: 1 (1:1), 2 (2:1), 4 (4:1), or 8 (8:1).
    - The RX port index defaults to the last port if not specified.
    - Traffic rate is fixed at 100% line rate.
    - The test measures and reports latency for each traffic flow item.

    Parameters:
    - rx_port_index (int, optional): Index of RX port (default last port).
    - tx_port_count (int): Number of TX ports to use.
    - traffic_rate (float): Traffic sending rate, fixed to 100%.

    Steps:
    1. Configure traffic generator to send traffic based on the tx_port_count and traffic_rate.
    2. Measure latency for each traffic flow.
    3. Report latency results.

    """
    logger.info("XXX" * 50)
    logger.info(
        f"Testing {ip_version} traffic at {traffic_rate}% line rate for {test_duration} seconds "
        f"with frame size {frame_size} bytes | Frame Ordering: {rfc2889_enabled},"
        f"Iterations: {num_iterations}, tx_port_count: {tx_port_count}, rx_port_index: {rx_port_index}"
    )
    snappi_config, snappi_obj_handles, snappi_extra_params, snappi_ports, tx_ports, rx_ports = setup_snappi_test(
        duthosts,
        get_snappi_ports,
        create_snappi_config,
        ip_version,
        ROUTE_RANGES,
        port_selector="oversubscription",
        tx_port_count=tx_port_count,
        rx_port_index=rx_port_index,
    )

    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": traffic_rate,
            "frame_size": frame_size,
            "flow_name": "latency_oversubscription",
            "tx_names": snappi_obj_handles["Tx"]["network_group"] + snappi_obj_handles["Rx"]["network_group"],
            "rx_names": snappi_obj_handles["Rx"]["network_group"] + snappi_obj_handles["Tx"]["network_group"],
            "mesh_type": "mesh",
            "latency": True,
        }
    ]
    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    snappi_api.set_config(snappi_config)
    ixnet = snappi_api._ixnetwork
    ixnet_traffic_params = {"BiDirectional": False, "SrcDestMesh": "fullMesh"}

    ixnet.Traffic.TrafficItem.find().update(**ixnet_traffic_params)
    ixnet.Traffic.FrameOrderingMode = "RFC2889" if rfc2889_enabled else "none"
    start_stop(snappi_api, operation="start", op_type="protocols", waittime=3)
    start_stop(snappi_api, operation="start", op_type="traffic")

    logger.info(
        f"RFC2889_enabled: {rfc2889_enabled}, " f"Fetching Stats — Frame Size: {frame_size}, " f"Rate: {traffic_rate}"
    )

    poll_latency_metrics(
        ixnet,
        test_duration,
        db_reporter,
        duthosts,
        ip_version,
        traffic_rate,
        frame_size,
        rfc2889_enabled,
        tx_port_count,
    )
    start_stop(snappi_api, operation="stop", op_type="traffic")


def get_ports(port_list, tx_port_count=1, rx_port_index=None):
    """
    Select TX and RX ports for oversubscription scenarios.

    Determines which ports to use as TX (transmit) and RX (receive)
    ports on the traffic generator, based on the total list of available
    ports, the number of TX ports desired, and an optional RX port index.

    If `rx_port_index` is not specified, the last port in `port_list` is
    selected as RX by default and the first `tx_port_count` ports are used as TX.
    The function validates that `tx_port_count` is one of the supported
    oversubscription values: 1 (1:1), 2 (2:1), 4 (4:1), or 8 (8:1).

    Args:
        port_list (list): List of available port objects or indices.
        tx_port_count (int, optional): Number of TX ports to use (default: 1).
            Must be one of [1, 2, 4, 8].
        rx_port_index (int, optional): Index of RX port in `port_list`.
            If None, use the last port.

    Returns:
        tuple: (tx_ports, rx_port)
            tx_ports (list): List of selected TX port(s).
            rx_port: Selected RX port.

    Raises:
        ValueError: If tx_port_count is not in the allowed list or
            if indices are out of range.

    Example:
        port_list = [0, 1, 2, 3]
        tx_ports, rx_port = get_ports(port_list, tx_port_count=2)
        # tx_ports = [0, 1], rx_port = 3
    """
    # Validate tx_port_count allowed values
    if tx_port_count not in [2**i for i in range(10)]:
        raise ValueError("tx_port_count must be a power of 2 less than 1024")

    total_ports = len(port_list)
    if total_ports < 2:
        raise ValueError("At least two ports are required (1 RX and >=1 TX)")

    # Validate or assign rx_port_index
    if rx_port_index is None:
        return port_list[:-1], [port_list[-1]]
    elif not (0 <= rx_port_index < total_ports):
        raise ValueError(f"rx_port_index {rx_port_index} is out of range for port_list of length {total_ports}")

    # Gather all indices except rx_port_index for TX candidates
    tx_candidate_indices = [i for i in range(total_ports) if i != rx_port_index]

    # Validate tx_port_count does not exceed available TX ports
    if tx_port_count > len(tx_candidate_indices):
        raise ValueError(f"tx_port_count={tx_port_count} exceeds available TX ports={len(tx_candidate_indices)}")

    # Select first tx_port_count TX ports from tx_candidate_indices
    tx_ports = [port_list[i] for i in tx_candidate_indices[:tx_port_count]]

    return tx_ports, [port_list[rx_port_index]]


def setup_snappi_test(
    duthosts,
    get_snappi_ports,
    create_snappi_config,
    ip_version,
    route_ranges,
    port_selector,
    tx_port_count=1,
    rx_port_index=None,
    protocol_type="bgp",
    is_rdma=False,
):
    """
    Set up a Snappi test configuration for traffic generation and protocol simulation.

    Args:
        duthosts: Device(s) under test - used to query port and protocol information.
        get_snappi_ports: Callable to obtain all candidate Snappi ports for the given DUTs and IP version.
        create_snappi_config: Callable to create and return a Snappi config and handles.
        ip_version (str): 'ipv4' or 'ipv6', selects address family for test and route range.
        route_ranges (dict): Dict keyed by IP version, specifying route ranges for protocol config.
        port_selector (str): Determines how to split/assign TX and RX ports: 'half_split'
                            splits ports list in half, 'oversubscription' uses helper logic.
        tx_port_count (int, optional): How many ports to use for transmit side default 1). Used for 'oversubscription'.
        rx_port_index (int, optional): Index or selection logic for RX port in 'oversubscription' case.
        protocol_type (str, optional): Protocol to configure on test ports ('bgp', etc).
        is_rdma (bool, optional): If True, configure extra params for RDMA flows.

    Returns:
        tuple: (
            snappi_config,        # The full test config ready for use with Snappi API
            snappi_obj_handles,   # Handles/objects useful for later reference (flows, ports, etc)
            snappi_extra_params,  # Extra parameters used for config and protocol state
            snappi_ports,         # List of selected candidate ports
            tx_ports,             # Selected TX ports (list)
            rx_ports              # Selected RX ports (list)
        )

    Raises:
        ValueError: If port_selector is not recognized.

    Notes:
        - Supports multiple deployment topologies based on port_selector.
        - This function is intended for building parametrized traffic/protocol
        tests for pytest or framework-based workflows.
        - Protocol configuration (BGP, RDMA, etc.)
        is embedded into snappi_extra_params for use downstream by the test or config factory.
    """

    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports, ip_version)
    if port_selector == "half_split":
        port_distrbution = (slice(0, len(snappi_ports) // 2), slice(len(snappi_ports) // 2, None))
        tx_ports, rx_ports = snappi_ports[port_distrbution[0]], snappi_ports[port_distrbution[1]]

    elif port_selector == "oversubscription":
        tx_ports, rx_ports = get_ports(snappi_ports, tx_port_count, rx_port_index)
    else:
        raise ValueError(f"Unknown port_selector: {port_selector}")

    snappi_extra_params.protocol_config = {
        "Tx": {
            "route_ranges": route_ranges[ip_version],
            "protocol_type": protocol_type,
            "ports": tx_ports,
            "subnet_type": ip_version,
            "is_rdma": is_rdma,
        },
        "Rx": {
            "route_ranges": route_ranges[ip_version],
            "protocol_type": protocol_type,
            "ports": rx_ports,
            "subnet_type": ip_version,
            "is_rdma": is_rdma,
        },
    }
    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    return snappi_config, snappi_obj_handles, snappi_extra_params, snappi_ports, tx_ports, rx_ports


def poll_latency_metrics(
    ixnet,
    duration_sec,
    db_reporter,
    duthosts,
    ip_version,
    traffic_rate,
    frame_size,
    rfc2889_enabled,
    tx_port_count=None,
):
    latency_average_ns = GaugeMetric("test.latency.l3.avg.ns", "Avg Latency", UNIT_SECONDS, db_reporter)
    latency_minimum_ns = GaugeMetric("test.latency.l3.min.ns", "Min Latency", UNIT_SECONDS, db_reporter)
    latency_maximum_ns = GaugeMetric("test.latency.l3.max.ns", "Max Latency", UNIT_SECONDS, db_reporter)
    test_labels = {
        "tg.ip_version": ip_version,
        METRIC_LABEL_TG_TRAFFIC_RATE: traffic_rate,
        METRIC_LABEL_TG_FRAME_BYTES: frame_size,
        METRIC_LABEL_TG_RFC2889_ENABLED: rfc2889_enabled,
        "test.params.duration.sec": duration_sec,
        "test.params.route_count": ROUTE_RANGES[ip_version][0][2],
        "test.params.route_prefix_length": ROUTE_RANGES[ip_version][0][1],
        **({"test.params.oversubscription_ratio": tx_port_count} if tx_port_count is not None else {}),
    }

    flwStats = StatViewAssistant(ixnet, "Flow Statistics")
    selected_columns = [
        "Source/Dest Port Pair",
        "Tx Frames",
        "Rx Frames",
        "Loss %",
        "Store-Forward Avg Latency (ns)",
        "Store-Forward Max Latency (ns)",
        "Store-Forward Min Latency (ns)",
    ]
    end_time = time.time() + duration_sec
    interval_sec = 30
    logger.info(f"Started polling Flow Statistics every {interval_sec:.2f}s for {duration_sec}s")

    while time.time() < end_time:
        logger.info("Polling Stats")
        poll_start = time.time()
        flow_df = pd.DataFrame(flwStats.Rows.RawData, columns=flwStats.ColumnHeaders)
        logger.info("\nFlow Statistics:\n" + tabulate(flow_df[selected_columns], headers="keys", tablefmt="psql"))
        for _, row in flow_df.iterrows():
            labels_copy = deepcopy(test_labels)
            labels_copy["test.tx_port"] = row["Tx Port"]
            labels_copy["test.rx_port"] = row["Rx Port"]
            latency_average_ns.record(row["Store-Forward Avg Latency (ns)"], labels_copy)
            latency_maximum_ns.record(row["Store-Forward Max Latency (ns)"], labels_copy)
            latency_minimum_ns.record(row["Store-Forward Min Latency (ns)"], labels_copy)
        elapsed = time.time() - poll_start
        time.sleep(max(0, interval_sec - elapsed))
    db_reporter.report()
