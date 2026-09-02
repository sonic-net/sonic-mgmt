from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
from tests.common.telemetry.metrics import GaugeMetric
from tests.common.telemetry.constants import (
    METRIC_LABEL_TG_FRAME_BYTES,
    METRIC_LABEL_TG_RFC2889_ENABLED,
    UNIT_PERCENT,
)

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("nut")]

test_results = pd.DataFrame(
    columns=[
        "Frame Ordering",
        "Frame Size",
        "Line Rate (%)",
        "Tx Frames",
        "Rx Frames",
        "Loss %",
        "Status",
        "Duration (s)",
    ]
)

ROUTE_RANGES = {"IPv6": [[["777:777:777::1", 64, 16]]], "IPv4": [[["100.1.1.1", 24, 16]]]}


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_bytes", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("rfc2889_enabled", [True, False])
def test_packet_drop_threshold(
    request,
    duthosts,
    snappi_api,  # noqa F811
    get_snappi_ports,
    fanout_graph_facts_multidut,  # noqa F811
    set_primary_chassis,
    create_snappi_config,
    rfc2889_enabled,
    frame_bytes,
    ip_version,
    db_reporter,
):
    """
    Test to measure latency introduced by the switch under fully loaded conditions.
    """
    no_loss_max_rate = GaugeMetric("no_loss_max_rate", "No Loss Max Rate", UNIT_PERCENT, db_reporter)
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports, ip_version, protocol_type="bgp")
    port_distrbution = (slice(0, len(snappi_ports) // 2), slice(len(snappi_ports) // 2, None))
    tx_ports, rx_ports = snappi_ports[port_distrbution[0]], snappi_ports[port_distrbution[1]]
    ranges = ROUTE_RANGES[ip_version]*(len(snappi_ports))
    snappi_extra_params.protocol_config = {
        "Tx": {
            "route_ranges": ranges,
            "network_group": False,
            "protocol_type": "bgp",
            "ports": tx_ports,
            "subnet_type": ip_version,
            "is_rdma": False,
        },
        "Rx": {
            "route_ranges": ranges,
            "network_group": False,
            "protocol_type": "bgp",
            "ports": rx_ports,
            "subnet_type": ip_version,
            "is_rdma": False,
        },
    }

    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    frame_rate = 100  # Start with 100% line rate
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": frame_rate,
            "frame_size": frame_bytes,
            "is_rdma": False,
            "flow_name": "packet_drop_threshold",
            "tx_names": snappi_obj_handles["Tx"]["ip"] + snappi_obj_handles["Rx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["ip"] + snappi_obj_handles["Tx"]["ip"],
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
    ixnet.Traffic.FrameOrderingMode = "RFC2889" if rfc2889_enabled else "none"
    start_stop(snappi_api, operation="start", op_type="traffic")
    start_stop(snappi_api, operation="stop", op_type="traffic")
    # ***************************************************************************

    req = snappi_api.config_update().flows
    req.property_names = [req.RATE]
    update_flow = snappi_config.flows[0]
    req.flows.append(update_flow)
    best_rate = 100
    """ Uses binary search to determine the max line rate without loss. """
    if not boundary_check(snappi_api, snappi_config, frame_bytes, best_rate, rfc2889_enabled):
        low, high, best_rate = 1, 100, 1
        while high - low > 0.1:  # Stop when precision is within 0.5%
            mid = round((low + high) / 2, 2)
            logger.info("=" * 50)
            logger.info(f"Testing {mid}% Line Rate   Range: {low}% - {high}%")
            logger.info("=" * 50)
            update_flow.rate.percentage = mid
            snappi_api.update_flows(req)

            if boundary_check(snappi_api, snappi_config, frame_bytes, mid, rfc2889_enabled):
                best_rate, low = mid, mid
            else:
                high = mid  # Decrease rate if loss

        logger.info(
            f"Final Maximum Line Rate Without Loss for FrameOrderingMode: {rfc2889_enabled}, "
            f"Frame Size: {frame_bytes} is: {best_rate}%"
        )
    """
    max_line_rate = test_results[
        (test_results['Frame Ordering'] == rfc2889_enabled) &
        (test_results['Frame Size'] == frame_bytes) &
        (test_results['Loss %'] == 0.0)
    ]['Line Rate (%)'].max()
    """
    no_loss_max_rate.record(
        best_rate, {
                    "tg.ip_version": ip_version,
                    METRIC_LABEL_TG_FRAME_BYTES: frame_bytes,
                    METRIC_LABEL_TG_RFC2889_ENABLED: rfc2889_enabled
                }
    )
    db_reporter.report()
    for ordering_mode, group in test_results.groupby("Frame Ordering"):
        summary = f"""
        Summary for Frame Ordering Mode: {ordering_mode}
        {"=" * 100}
        {tabulate(group, headers="keys", tablefmt="psql", showindex=False)}
        {"=" * 100}
        """
        logger.info(summary.strip())


def boundary_check(snappi_api, snappi_config, frame_bytes, line_rate, rfc2889_enabled):
    """Tests if the given line rate results in frame loss."""
    logger.info(f"Updating percentLineRate to: {line_rate}")

    # ***************************************************************************
    # Using RestPy Code
    ixnet = snappi_api._ixnetwork
    ixnet.Traffic.StartStatelessTrafficBlocking()
    wait_with_message("Running traffic for", 10)
    start_stop(snappi_api, operation="stop", op_type="traffic")
    df = get_stats(snappi_api, "Traffic Item Statistics", columns=None, return_type="df")

    # Select only necessary columns and convert them to numeric
    df = df[["name", "frames_tx", "frames_rx", "loss"]]
    df[["loss"]] = pd.to_numeric(df["loss"], errors="coerce")

    # Check if loss occurred (Loss % > 0)
    df["Status"] = (df["loss"] == 0).map({True: "PASS", False: "FAIL"})
    # Print the DataFrame for results
    logger.info(
        f"Dumping Frame Size/Rate: {frame_bytes}/{line_rate} RFC2889 Enabled: {rfc2889_enabled} Traffic Item Stats:\n"
        f"{tabulate(df, headers='keys', tablefmt='psql', showindex=False)}"
    )
    loss = df["loss"].max()  # Get max loss in case of multiple traffic items

    # Create a DataFrame for the current test result directly
    global test_results
    result_df = pd.DataFrame(
        [
            {
                "Frame Ordering": rfc2889_enabled,
                "Frame Size": frame_bytes,
                "Line Rate (%)": line_rate,
                "Tx Frames": df["frames_tx"].sum(),
                "Rx Frames": df["frames_rx"].sum(),
                "Loss %": df["loss"].max(),
                "Status": df["Status"].iloc[0],
                "Duration (s)": 30,
            }
        ]
    )

    # Append the new result to the global test_results DataFrame
    test_results = pd.concat([test_results, result_df], ignore_index=True)

    return loss == 0  # True if no loss, False if loss occurs
