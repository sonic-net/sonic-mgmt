from tests.snappi_tests.dataplane.imports import *

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("tgen")]

import pytest
import snappi
import numpy as np
import matplotlib.pyplot as plt
import os
import json

# Test Parameters
traffic_run_duration = 10  # Configurable traffic run duration
frame_sizes = [66, 86, 128, 256, 512, 1024, 2048, 4096, 8192]  # Frame Sizes
# frame_sizes             = [2048,128]           #Frame Sizes
test_results = pd.DataFrame(
    columns=[
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


def boundary_check(ixnet, hls, line_rate):
    """Tests if the given line rate results in frame loss."""
    logger.info(f"Updating percentLineRate to: {line_rate}")
    frame_size = hls.FrameSize.FixedSize
    hls.FrameRate.update(Type="percentLineRate", Rate=line_rate)

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
        f'Dumping Frame Size/Rate: {frame_size}/{line_rate} Traffic Item Stats:\n{tabulate(df, headers="keys", tablefmt="psql",showindex=False)}'
    )  # .transpose()

    loss = df["Loss %"].max()  # Get max loss in case of multiple traffic items
    ixnet.ClearStats()

    # Create a DataFrame for the current test result directly
    global test_results
    result_df = pd.DataFrame(
        [
            {
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


pytestmark = [pytest.mark.topology("tgen")]


def test_packet_drop_threshold(
    request,
    snappi_api,  # noqa F811
    setup_snappi_port_configs,
    conn_graph_facts,  # noqa F811
    fanout_graph_facts,  # noqa F811
    duthosts,
    get_snappi_ports,
    setup_and_teardown,
):
    """
    Test to measure latency introduced by the switch under fully loaded conditions.
    """
    ixnet, session_assistant = setup_and_teardown
    for frame_size in frame_sizes:
        logger.info(f"Finding Packet Drop Threshold for Frame Size: {frame_size}")
        hls = ixnet.Traffic.TrafficItem.find().HighLevelStream.find()
        hls.FrameSize.update(FixedSize=frame_size)
        """ Uses binary search to determine the max line rate without loss. """
        if boundary_check(ixnet, hls, 100):
            logger.info("\n" + "=" * 150)
            logger.info("TEST SUMMARY")
            logger.info("=" * 150)
            logger.info(
                f'Dumping TEST Summary Stats:\n{tabulate(test_results, headers="keys", tablefmt="psql",showindex=False)}'
            )
            logger.info("=" * 150)
            continue

        low, high, best_rate = 1, 100, 1
        while high - low > 5.0:  # Stop when precision is within 0.5%
            mid = round((low + high) / 2, 2)
            logger.info("=" * 50)
            logger.info(f"Testing {mid}% Line Rate   Range: {low}% - {high}%")
            logger.info("=" * 50)
            if boundary_check(ixnet, hls, mid):
                best_rate, low = mid, mid
            else:
                high = mid  # Decrease rate if loss

        logger.info(f"Final Maximum Line Rate Without Loss: {best_rate}%")
        logger.info("\n" + "=" * 100)
        logger.info("TEST SUMMARY")
        logger.info("=" * 70)
        logger.info(
            f'Dumping TEST Summary Stats:\n{tabulate(test_results, headers="keys", tablefmt="psql",showindex=False)}'
        )  # .transpose()
        logger.info("=" * 100)


def wait_with_message(message, duration):
    """Displays a countdown while waiting."""
    for remaining in range(duration, 0, -1):
        logger.info(f"{message} {remaining} seconds remaining.")
        # sys.stdout.flush()
        time.sleep(1)
    logger.info("")  # Ensure line break after countdown.


def start_traffic(ixnet):
    """Starts the traffic and ensures frames are being transmitted."""
    logger.info("\tStarting traffic...")
    ixnet.Traffic.StartStatelessTrafficBlocking()
    ti = StatViewAssistant(ixnet, "Traffic Item Statistics")

    if not ti.CheckCondition("Tx Frames", StatViewAssistant.GREATER_THAN, 0):
        raise Exception("Traffic did not start properly.")
    logger.info("\tTraffic started successfully.")


def stop_traffic(ixnet, timeout=30, interval=3):
    """Stops traffic and ensures it is fully stopped within the timeout period."""
    logger.info("\tStopping traffic...")
    ixnet.Traffic.StopStatelessTrafficBlocking()

    for _ in range(0, timeout, interval):
        if not ixnet.Traffic.IsTrafficRunning:
            logger.info("\tTraffic successfully stopped.")
            return
        time.sleep(interval)

    raise TimeoutError("\tTraffic did not stop within the timeout period.")


@pytest.fixture(scope="function", autouse=True)
def setup_and_teardown(request, snappi_api, setup_snappi_port_configs):
    """
    Fixture to initialize and cleanup resources for the test.
    """
    # Setup: Initialize session_assistant and ixnet
    session_assistant = SessionAssistant(
        IpAddress=snappi_api._address,
        RestPort=snappi_api._port,
        UserName=snappi_api._username,
        Password=snappi_api._password,
        SessionName="LatencyMeasurement",
        ClearConfig=True,
    )
    ixnet = session_assistant.Ixnetwork
    request.session.ixnet_session = session_assistant.Session
    # ixnet.Locations.add(Hostname="10.36.84.31", ChainTopology="star")
    # ixnet.Locations.add(Hostname="10.36.84.34", PrimaryDevice="10.36.84.31")

    logger.info(f"Starting IxNetwork Session Id {session_assistant.Session}")
    logger.info("Session and ixnetwork initialized.")
    port_config_list = setup_snappi_port_configs
    logger.info("Connect the virtual ports to test ports")
    port_list = [
        {"xpath": f"/vport[{i+1}]", "location": port['location'], "name": f"Port-{i:02d}"}
        for i, port in enumerate(port_config_list)
    ]
    # Import configuration and assign ports
    ixnet.ResourceManager.ImportConfig(json.dumps(port_list), False)

    ixnet.AssignPorts(True)

    # Assign IP addresses and gateways
    def assign_addresses(ipv4_device, ips, gateways):
        ipv4_device.Address.ValueList(ips)
        ipv4_device.GatewayIp.ValueList(gateways)

    vports, half_ports = ixnet.Vport.find(), len(port_config_list) // 2
    logger.info("Creating IxNetwork Topology")
    ipv4_w = (
        ixnet.Topology.add(Vports=vports[:half_ports])
        .DeviceGroup.add(Name="Device West", Multiplier="1")
        .Ethernet.add()
        .Ipv4.add(Name=f"Ipv4 West")
    )
    ipv4_e = (
        ixnet.Topology.add(Vports=vports[half_ports:])
        .DeviceGroup.add(Name="Device East", Multiplier="1")
        .Ethernet.add()
        .Ipv4.add(Name=f"Ipv4 East")
    )

    ip, gw = map(list, zip(*[[pc['ipAddress'], pc['ipGateway']] for pc in port_config_list]))

    assign_addresses(ipv4_w, ip[:half_ports], gw[:half_ports])
    assign_addresses(ipv4_e, ip[half_ports:], gw[half_ports:])

    logger.info("Create Traffic Item")
    ixnet.Traffic.FrameOrderingMode = "RFC2889"
    trafficItem = ixnet.Traffic.TrafficItem.add(
        Name="TestTraffic",
        BiDirectional=True,
        SrcDestMesh="fullMesh",
        TrafficType="ipv4",
    )
    logger.info("Add endpoint flow group")
    trafficItem.EndpointSet.add(
        Sources=ixnet.Topology.find(), Destinations=ixnet.Topology.find()
    )
    logger.info("Configuring config elements")
    configElement = trafficItem.ConfigElement.find()[0]
    configElement.FrameRate.update(Rate=100, Type="percentLineRate")
    configElement.TransmissionControl.update(Duration=20, Type="continous")
    configElement.FrameRateDistribution.PortDistribution = "applyRateToAll"
    configElement.FrameSize.FixedSize = 512
    tracking = trafficItem.Tracking.find()[0]
    tracking.TrackBy = ["sourceDestPortPair0"]

    logger.info("Start All Protocols")
    ixnet.StartAllProtocols(Arg1="sync")
    try:
        logger.info("Verify protocol sessions")
        protocolsSummary = StatViewAssistant(ixnet, "Protocols Summary")
        protocolsSummary.CheckCondition(
            "Sessions Not Started", StatViewAssistant.EQUAL, 0, 180
        )
        protocolsSummary.CheckCondition(
            "Sessions Down", StatViewAssistant.EQUAL, 0, 180
        )
    except Exception as e:
        logger.info("ERROR:Protocols session are down.")
        raise Exception(str(e))

    ixnet.Traffic.TrafficItem.find().Generate()
    ixnet.Traffic.Apply()

    yield ixnet, session_assistant
