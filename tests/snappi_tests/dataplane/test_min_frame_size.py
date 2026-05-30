from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
from tests.common.telemetry.metrics import GaugeMetric

from tests.common.telemetry.constants import (
    METRIC_LABEL_TG_FRAME_BYTES,
    METRIC_LABEL_TG_RFC2889_ENABLED,
)

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("nut")]

test_results = pd.DataFrame(
    columns=[
        "IP Version",
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

LINE_RATE_PERCENT = 100
FRAME_SIZE_STEP = 64
START_FRAME = 64
END_FRAME = 9100


@pytest.mark.parametrize("ip_version", ["IPv6", "IPv4"])
@pytest.mark.parametrize("rfc2889_enabled", [True, False])
def test_min_frame_size_no_loss(
    request,
    duthosts,
    snappi_api,  # noqa: F811
    get_snappi_ports,  # noqa: F811
    fanout_graph_facts_multidut,  # noqa: F811
    set_primary_chassis,  # noqa: F811
    create_snappi_config,  # noqa: F811
    rfc2889_enabled,
    ip_version,
    db_reporter,
):
    """Find the smallest 64-byte-aligned frame size at 100% line rate that has zero packet loss.

    The candidate space is range(START_FRAME, END_FRAME+1, FRAME_SIZE_STEP), so the
    result is always a multiple of FRAME_SIZE_STEP (64 bytes). The largest size is
    verified first; if it cannot pass, the test fails rather than silently reporting
    the maximum as the answer.
    """
    frame_ordering_mode = "RFC2889" if rfc2889_enabled else "none"
    no_loss_min_frame = GaugeMetric("no_loss_min_frame", "No Loss Minimum Frame Size", "bytes", db_reporter)

    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports, ip_version, protocol_type="bgp")
    port_distribution = (slice(0, len(snappi_ports) // 2), slice(len(snappi_ports) // 2, None))
    tx_ports, rx_ports = snappi_ports[port_distribution[0]], snappi_ports[port_distribution[1]]

    # Tx and Rx advertise the same prefixes intentionally: traffic is bidirectional
    # (mesh) and both endpoints need symmetric reachability for the same prefix set.
    ranges = ROUTE_RANGES[ip_version] * len(snappi_ports)
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
    frame_sizes = list(range(START_FRAME, END_FRAME + 1, FRAME_SIZE_STEP))

    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": LINE_RATE_PERCENT,
            "frame_size": frame_sizes[-1],
            "is_rdma": False,
            "flow_name": "min_frame_size_no_loss",
            "tx_names": snappi_obj_handles["Tx"]["ip"] + snappi_obj_handles["Rx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["ip"] + snappi_obj_handles["Tx"]["ip"],
            "mesh_type": "mesh",
        }
    ]

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    snappi_api.set_config(snappi_config)
    start_stop(snappi_api, operation="start", op_type="protocols")
    global test_results
    try:
        # Ixia/IxNetwork-specific: SNAPPI does not expose BiDirectional/SrcDestMesh or
        # FrameOrderingMode, so reach into the RestPy session to set them directly.
        ixnet = getattr(snappi_api, "_ixnetwork", None)
        pytest_assert(ixnet is not None,
                      "This test requires an Ixia/IxNetwork backend (snappi_api._ixnetwork)")
        ixnet_traffic_params = {"BiDirectional": True, "SrcDestMesh": "fullMesh"}
        ixnet.Traffic.TrafficItem.find().update(**ixnet_traffic_params)
        ixnet.Traffic.FrameOrderingMode = frame_ordering_mode

        # after changing frame ordering mode,
        # need to generate traffic again to make sure the config is applied to traffic item
        start_stop(snappi_api, operation="start", op_type="traffic")

        # Verify the largest frame size passes before searching; otherwise the
        # binary-search default would silently report END_FRAME as the answer.
        logger.info(
                    "=" * 50 + "\n"
                    f"Sanity check {ip_version}: max frame size {frame_sizes[-1]} bytes "
                    f"at {LINE_RATE_PERCENT}% line rate\n"
                    "=" * 50
                )
        result = boundary_check(snappi_api, snappi_config, frame_sizes[-1], LINE_RATE_PERCENT, rfc2889_enabled)
        result["IP Version"] = ip_version
        pytest_assert(
            result["no_loss"],
            f"Maximum frame size {frame_sizes[-1]} bytes drops packets at "
            f"{LINE_RATE_PERCENT}% line rate (FrameOrderingMode={frame_ordering_mode}) - "
            f"cannot determine a no-loss minimum.",
        )
        row_data = {k: v for k, v in result.items() if k != "no_loss"}
        test_results = pd.concat(
                                [test_results, pd.DataFrame([row_data])],
                                ignore_index=True
                                )

        req = snappi_api.config_update().flows
        req.property_names = [req.SIZE]
        update_flow = snappi_config.flows[0]
        req.flows.append(update_flow)

        def _passes(frame_size):
            global test_results
            update_flow.size.fixed = frame_size
            snappi_api.update_flows(req)
            result = boundary_check(snappi_api, snappi_config, frame_size, LINE_RATE_PERCENT, rfc2889_enabled)
            result["IP Version"] = ip_version
            row_data = {k: v for k, v in result.items() if k != "no_loss"}
            test_results = pd.concat(
                [test_results, pd.DataFrame([row_data])],
                ignore_index=True
            )
            return result["no_loss"]

        # Standard "leftmost True" binary search over indices: find the smallest
        # index i where _passes(frame_sizes[i]) is True.
        low, high = 0, len(frame_sizes) - 1
        best_idx = high  # already verified above
        while low <= high:
            mid = (low + high) // 2
            mid_size = frame_sizes[mid]
            logger.info("=" * 50)
            logger.info(f"Testing {ip_version} Frame Size: {mid_size} bytes at {LINE_RATE_PERCENT}% Line Rate")
            logger.info("=" * 50)
            if _passes(mid_size):
                best_idx = mid
                high = mid - 1
            else:
                low = mid + 1

        best_frame_size = frame_sizes[best_idx]
        logger.info(
            f"Final Smallest Frame Size Without Loss for FrameOrderingMode {ip_version}: "
            f"{frame_ordering_mode!r} is: {best_frame_size} bytes"
        )

        no_loss_min_frame.record(
            best_frame_size,
            {
                "tg.ip_version": ip_version,
                METRIC_LABEL_TG_FRAME_BYTES: best_frame_size,
                METRIC_LABEL_TG_RFC2889_ENABLED: rfc2889_enabled,
            },
        )
        db_reporter.report()
        for ordering_mode, group in test_results.groupby("Frame Ordering"):
            summary = f"""
            Summary for {ip_version} Frame Ordering Mode: {ordering_mode}
            {"=" * 100}
            {tabulate(group, headers="keys", tablefmt="psql", showindex=False)}
            {"=" * 100}
            """
            logger.info(summary.strip())

    finally:
        start_stop(snappi_api, operation="stop", op_type="protocols")
