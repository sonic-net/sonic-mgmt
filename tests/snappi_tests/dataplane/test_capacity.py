from tests.snappi_tests.dataplane.imports import *    # noqa F403
from snappi_tests.dataplane.files.helper import *        # noqa F403

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("tgen")]

# Test Parameters
traffic_run_duration = 10  # Configurable traffic run duration
frame_sizes = [66, 86, 128, 256, 512, 1024, 2048, 4096, 8192]  # Frame Sizes
frame_ordering = ["RFC2889", "none"]
test_results = pd.DataFrame(
    columns=[
        "Frame Ordering",
        "Frame Size",
        "Line Rate (%)",
        "Tx Frames",
        "Rx Frames",
        "Frames Delta",
        "Loss %",
        "Status",
        "Duration (s)",
    ]
)


@pytest.fixture(scope="session", autouse=True)
def session_teardown(request):
    yield
    request.session.ixnet_session.remove()
    logger.info("\n=== Custom session teardown in Test Script ===")


def test_packet_drop_threshold(
    request,
    snappi_api,  # noqa F811
    conn_graph_facts,  # noqa F811
    fanout_graph_facts,  # noqa F811
    duthosts,
    set_primary_chassis,
    get_snappi_ports,
):
    """
    Test to measure latency introduced by the switch under fully loaded conditions.
    """
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports)

    session_assistant = SessionAssistant(
        IpAddress=snappi_api._address,
        RestPort=snappi_api._port,
        UserName=snappi_api._username,
        Password=snappi_api._password,
        SessionName="PacketDropThreshold",
    )
    logger.info(f"Starting IxNetwork Session Id {session_assistant.Session}")
    ixnet = session_assistant.Ixnetwork
    request.session.ixnet_session = session_assistant.Session
    logger.info("Session and ixnetwork initialized.")

    for ch in snappi_api._ixnet_specific_config.chassis_chains:
        ixnet.Locations.add(Hostname=ch.primary, ChainTopology="star")
        for se in ch.secondary:
            ixnet.Locations.add(Hostname=se.location, PrimaryDevice=ch.primary)

    port_distribution = (
        slice(0, len(snappi_ports) // 2),
        slice(len(snappi_ports) // 2, None)
    )
    config = IxNetConfigParams(traffic_type="ipv6")
    setup_ixnetwork_config(ixnet, snappi_ports, port_distribution, config)
    hls = ixnet.Traffic.TrafficItem.find().HighLevelStream.find()
    frame_size_hljson_template = [
        {
            "xpath": f"/traffic/trafficItem[1]/highLevelStream[{index+1}]",
            "frameSize": {"xpath": f"/traffic/trafficItem[1]/highLevelStream[{index+1}]/frameSize"},
        }
        for index in range(len(hls))
    ]
    for ordering in frame_ordering:
        ixnet.Traffic.FrameOrderingMode = ordering
        ixnet.Traffic.TrafficItem.find().Generate()
        ixnet.Traffic.Apply()
        logger.info(f"FrameOrderingMode: {ordering}")
        for frame_size in frame_sizes:
            logger.info(f"Finding Packet Drop Threshold for FrameOrderingMode: {ordering} Frame Size: {frame_size}")
            hljson = [
                {
                    **hl,
                    "frameSize": {
                        **hl["frameSize"],
                        "fixedSize": frame_size
                    }
                }
                for hl in frame_size_hljson_template
            ]
            ixnet.ResourceManager.ImportConfig(json.dumps(hljson), False)
            """ Uses binary search to determine the max line rate without loss. """
            if boundary_check(ixnet, hls, 100):
                continue

            low, high, best_rate = 1, 100, 1
            while high - low > 0.1:  # Stop when precision is within 0.5%
                mid = round((low + high) / 2, 2)
                logger.info("=" * 50)
                logger.info(f"Testing {mid}% Line Rate   Range: {low}% - {high}%")
                logger.info("=" * 50)
                if boundary_check(ixnet, hls, mid):
                    best_rate, low = mid, mid
                else:
                    high = mid  # Decrease rate if loss

            logger.info(
                f"Final Maximum Line Rate Without Loss for FrameOrderingMode: {ordering}, "
                f"Frame Size: {frame_size}, is: {best_rate}%"
            )

    for ordering_mode, group in test_results.groupby("Frame Ordering"):
        summary = f"""
        Summary for Frame Ordering Mode: {ordering_mode}
        {"=" * 100}
        {tabulate(group, headers="keys", tablefmt="psql", showindex=False)}
        {"=" * 100}
        """
        logger.info(summary.strip())


def boundary_check(ixnet, hls, line_rate):
    """Tests if the given line rate results in frame loss."""
    logger.info(f"Updating percentLineRate to: {line_rate}")
    frame_size = hls.FrameSize.FixedSize
    frame_rate_hljson = [
        {
            "xpath": f"/traffic/trafficItem[1]/highLevelStream[{index + 1}]",
            "frameRate": {
                "xpath": f"/traffic/trafficItem[1]/highLevelStream[{index + 1}]/frameRate",
                "rate": line_rate,
            },
        }
        for index in range(len(hls))
    ]
    ixnet.ResourceManager.ImportConfig(json.dumps(frame_rate_hljson), False)
    start_traffic(ixnet)
    wait_with_message("Running traffic for", traffic_run_duration)
    stop_traffic(ixnet)
    wait_with_message("Waiting for stats to settle", 5)

    # Fetch traffic stats inline using Pandas
    view = StatViewAssistant(ixnet, "Traffic Item Statistics")
    df = pd.DataFrame(view.Rows.RawData, columns=view.ColumnHeaders)

    # Select only necessary columns and convert them to numeric
    df = df[["Traffic Item", "Tx Frames", "Rx Frames", "Frames Delta", "Loss %"]]
    df[["Loss %"]] = pd.to_numeric(df["Loss %"], errors="coerce")

    # Check if loss occurred (Loss % > 0)
    df["Status"] = (df["Loss %"] == 0).map({True: "PASS", False: "FAIL"})
    # Print the DataFrame for results
    logger.info(
        f'Dumping Frame Size/Rate: {frame_size}/{line_rate} Traffic Item Stats:\n'
        f'{tabulate(df, headers="keys", tablefmt="psql", showindex=False)}'
    )

    loss = df["Loss %"].max()  # Get max loss in case of multiple traffic items
    ixnet.ClearStats()

    # Create a DataFrame for the current test result directly
    global test_results
    result_df = pd.DataFrame(
        [
            {
                "Frame Ordering": ixnet.Traffic.FrameOrderingMode,
                "Frame Size": hls.FrameSize.FixedSize,
                "Line Rate (%)": line_rate,
                "Tx Frames": df["Tx Frames"].sum(),
                "Rx Frames": df["Rx Frames"].sum(),
                "Frames Delta": df["Frames Delta"].sum(),
                "Loss %": df["Loss %"].max(),
                "Status": df["Status"].iloc[0],
                "Duration (s)": traffic_run_duration,
            }
        ]
    )

    # Append the new result to the global test_results DataFrame
    test_results = pd.concat([test_results, result_df], ignore_index=True)
    return loss == 0  # True if no loss, False if loss occurs
