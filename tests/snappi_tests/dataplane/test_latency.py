from tests.snappi_tests.dataplane.imports import *

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

pytestmark = [pytest.mark.topology("tgen")]


@pytest.mark.parametrize(
    "frame_size_rate, num_iterations",
    [(size_rate, num_iterations) for size_rate in frame_sizes_rate],
)
def test_latency_measurement(
    request,
    snappi_api,  # noqa F811
    setup_snappi_port_configs,
    conn_graph_facts,  # noqa F811
    fanout_graph_facts,  # noqa F811
    duthosts,
    get_snappi_ports,
    setup_and_teardown,
    frame_size_rate,
    num_iterations,
):
    """
    Test to measure latency introduced by the switch under fully loaded conditions.
    """

    ixnet, session_assistant = setup_and_teardown

    tiStatistics = StatViewAssistant(ixnet, "Traffic Item Statistics")
    # Create the DataFrame
    tdf = pd.DataFrame(tiStatistics.Rows.RawData, columns=tiStatistics.ColumnHeaders)
    # Ensure 'Store-Forward Avg Latency (ns)' column is numeric
    tdf["Store-Forward Avg Latency (ns)"] = pd.to_numeric(
        tdf["Store-Forward Avg Latency (ns)"], errors="coerce"
    )
    # Compute RTT as 2 * Avg Latency
    tdf["RTT (ns)"] = tdf["Store-Forward Avg Latency (ns)"] * 2

    flowStatistics = StatViewAssistant(ixnet, "Flow Statistics")
    binStatistics = StatViewAssistant(ixnet, "Bin Statistics")

    # Number of iterations (adjust as needed)
    selected_columns = [
        "Iteration",
        "Frame Size",
        "Tx Port",
        "Rx Port",
        "Tx Frames",
        "Rx Frames",
        "Frames Delta",
        "Loss %",
        "Store-Forward Avg Latency (ns)",
        "Store-Forward Min Latency (ns)",
        "Store-Forward Max Latency (ns)",
    ]
    flow_stat_column = flowStatistics.ColumnHeaders
    bin_stat_column = binStatistics.ColumnHeaders

    def fetch_and_wait(iteration):
        """Fetch stats, log data, and wait for 10 seconds."""
        logger.info(
            f"Fetching Stats Frame Size: {frame_size_rate[0]} and Rate: {frame_size_rate[1]} Iteration: {iteration}"
        )

        # Flow Statistics
        flow_df = pd.DataFrame(flowStatistics.Rows.RawData, columns=flow_stat_column)
        flow_df["Iteration"] = iteration
        flow_df["Frame Size"] = frame_size_rate[0]
        flow_selected = flow_df[selected_columns].copy()
        logger.info(
            f'Dumping Frame Size: {frame_size_rate[0]} at Rate: {frame_size_rate[1]} Flow Stats Iteration {iteration}:\n{tabulate(flow_selected, headers="keys", tablefmt="psql")}'
        )

        # Bin Statistics
        bin_df = pd.DataFrame(binStatistics.Rows.RawData, columns=bin_stat_column)
        bin_df.insert(0, "Frame Size", frame_size_rate[0])
        bin_df.insert(0, "Iteration", iteration)
        bin_df.drop("Rx Port", axis=1, inplace=True)
        logger.info(
            f'Dumping Frame Size/Rate: {frame_size_rate[0]}/{frame_size_rate[1]} Latency Bin Stats Iteration {iteration}:\n{tabulate(bin_df, headers="keys", tablefmt="psql",showindex=False)}'
        )  # .transpose()

        time.sleep(20)  # Wait 10 seconds before the next iteration
        return flow_selected, bin_df

    # Execute the iterations using list comprehension
    all_iterations, bin_all_iterations = zip(
        *(fetch_and_wait(i) for i in range(1, num_iterations + 1))
    )
    logger.info("DUMPING STATS AFTER TRAFFIC STOP")
    startStopTraffic(ixnet, "stop")
    # Check stats after traffic stops
    flow_df = pd.DataFrame(flowStatistics.Rows.RawData, columns=flow_stat_column)
    flow_selected = flow_df[
        ["Tx Port", "Rx Port", "Tx Frames", "Rx Frames", "Frames Delta", "Loss %"]
    ].copy()
    logger.info(
        f'Dumping Frame Size: {frame_size_rate[0]} at Rate: {frame_size_rate[1]} Flow Stats :\n{tabulate(flow_selected, headers="keys", tablefmt="psql",showindex=False)}'
    )

    trafficStatistics = StatViewAssistant(ixnet, "Traffic Item Statistics")
    traffic_df = pd.DataFrame(
        trafficStatistics.Rows.RawData, columns=trafficStatistics.ColumnHeaders
    )
    traffic_selected = traffic_df[
        ["Traffic Item", "Tx Frames", "Rx Frames", "Frames Delta", "Loss %"]
    ].copy()
    logger.info(
        f'Dumping Frame Size/Rate: {frame_size_rate[0]}/{frame_size_rate[1]} Traffic Item Stats:\n{tabulate(traffic_selected, headers="keys", tablefmt="psql",showindex=False)}'
    )  # .transpose()

    selected_columns = [
        "Iteration",
        "Pair Key",
        "Tx Port",
        "Rx Port",
        "Loss %",
        "Store-Forward Avg Latency (ns)",
        "Store-Forward Min Latency (ns)",
        "Store-Forward Max Latency (ns)",
    ]

    # Concatenate all iterations into one DataFrame
    multi_iteration_df = pd.concat(all_iterations, ignore_index=True)

    multi_iteration_bin_df = pd.concat(bin_all_iterations, ignore_index=True)
    # Generate Pair Key for bidirectional matching (Tx Port and Rx Port as a set)
    multi_iteration_df["Pair Key"] = multi_iteration_df.apply(
        lambda row: frozenset([row["Tx Port"], row["Rx Port"]]), axis=1
    )

    # Display the DataFrame for multiple iterations
    logger.info(
        "Dumping all Iteration Flow Stats.\n{}".format(
            tabulate(
                multi_iteration_df[selected_columns], headers="keys", tablefmt="psql"
            )
        )
    )
    logger.info(
        "Dumping all Iteration Latency Bin Stats.\n{}".format(
            tabulate(multi_iteration_bin_df, headers="keys", tablefmt="psql")
        )
    )

    # Ensure 'Store-Forward Avg Latency (ns)' is numeric
    multi_iteration_df["Store-Forward Avg Latency (ns)"] = pd.to_numeric(
        multi_iteration_df["Store-Forward Avg Latency (ns)"], errors="coerce"
    )
    # Group by 'Pair Key' to calculate the average latency across all iterations for each pair
    avg_latency_df = (
        multi_iteration_df.groupby("Pair Key")["Store-Forward Avg Latency (ns)"]
        .mean()
        .reset_index()
    )
    # Sort by the average RTT in nanoseconds
    avg_latency_df_sorted = avg_latency_df.sort_values(
        by="Store-Forward Avg Latency (ns)", ascending=True
    )
    # Display the result
    logger.info(
        "Displaying Result\n{}".format(
            tabulate(
                avg_latency_df_sorted, headers="keys", tablefmt="psql", showindex=False
            )
        )
    )

    pivot_df = multi_iteration_df.pivot_table(
        index="Tx Port",
        columns="Rx Port",
        values="Store-Forward Avg Latency (ns)",
        aggfunc="mean",
    )
    logger.info(
        "Displaying Pivot\n{}".format(
            tabulate(pivot_df, headers="keys", tablefmt="psql", showindex=False)
        )
    )
    generate_heatmap(pivot_df, frame_size_rate)


@pytest.fixture(scope="function", autouse=True)
def setup_and_teardown(request, snappi_api, setup_snappi_port_configs):
    """
    Fixture to initialize and cleanup resources for the test.
    """
    # Setup: Initialize session_assistant and ixnet
    testplatform = TestPlatform(
        ip_address=snappi_api._address, rest_port=snappi_api._port
    )
    testplatform.Authenticate(snappi_api._username, snappi_api._password)
    ixnet_session = testplatform.Sessions.find(Name="LatencyMeasurement")
    session_assistant = SessionAssistant(
        IpAddress=snappi_api._address,
        RestPort=snappi_api._port,
        UserName=snappi_api._username,
        Password=snappi_api._password,
        SessionName="LatencyMeasurement",
    )
    ixnet = session_assistant.Ixnetwork
    request.session.ixnet_session = session_assistant.Session
    # ixnet.Locations.add(Hostname='10.36.84.31', ChainTopology="star")
    # ixnet.Locations.add(Hostname='10.36.84.34',PrimaryDevice='10.36.84.31')

    frame_size, rate = request.getfixturevalue("frame_size_rate")

    if not ixnet_session:
        logger.info(f"Starting IxNetwork Session Id {session_assistant.Session}")
        logger.info("Session and ixnetwork initialized.")
        port_config_list = setup_snappi_port_configs

        logger.info("Connect the virtual ports to test ports")
        port_list = [
            {
                "xpath": f"/vport[{i+1}]",
                "location": port["location"],
                "name": f'{port["location"].split("/")[-1]}-{port["peer_port"].replace("Ethernet","Eth")}',
            }
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

        ip, gw = map(
            list, zip(*[[pc["ipAddress"], pc["ipGateway"]] for pc in port_config_list])
        )
        assign_addresses(ipv4_w, ip[:half_ports], gw[:half_ports])
        assign_addresses(ipv4_e, ip[half_ports:], gw[half_ports:])

        def createTrafficItem():
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
            configElement.FrameRate.update(Rate=rate, Type="percentLineRate")
            configElement.TransmissionControl.update(Duration=20, Type="continous")
            configElement.FrameRateDistribution.PortDistribution = "applyRateToAll"
            configElement.FrameSize.FixedSize = frame_size
            tracking = trafficItem.Tracking.find()[0]
            tracking.TrackBy = ["sourceDestPortPair0"]
            lbin = tracking.LatencyBin.find()
            lbin.NumberOfBins = 5
            lbin.Enabled = True
            lbin.BinLimits = [0.6, 0.8, 1, 1.2, 2147483647.0]

        logger.info("Creating Traffic")
        createTrafficItem()

        # Yielding the resources so that they can be used in the test function
        startStopTraffic(ixnet, "start")
        logger.info("Creating Traffic Flow Latency Bin Filtering View...")
        binView = ixnet.Statistics.View.add(
            Caption="Bin Statistics", Visible=True, Type="layer23TrafficFlow"
        )
        # Configure the Layer23 Traffic Flow Filter
        fdd = binView.Layer23TrafficFlowFilter.find()
        fdd.update(
            AggregatedAcrossPorts=False,
            PortFilterIds=binView.AvailablePortFilter.find(),
            TrafficItemFilterId=binView.AvailableTrafficItemFilter.find()[0],
            EgressLatencyBinDisplayOption="showLatencyBinStats",
        )
        fdd.EnumerationFilter.add(
            SortDirection="ascending",
            TrackingFilterId=binView.AvailableTrackingFilter.find()[0],
        )
        """
        #Available Stats
        stats = ["Tx Frames", "Rx Frames", "Rx Frames per Bin", "Frames Delta", "Loss %",
            "Tx Frame Rate", "Rx Frame Rate", "Rx Frame Rate per Bin",
            "Tx L1 Rate (Gbps)","Rx L1 Rate (Gbps)","Rx Bytes per Bin","Rx Bytes",
            "Tx Rate (Gbps)","Rx Rate (Gbps)","Rx Rate (Gbps) per Bin",
            "Store-Forward Avg Latency (ns) per Bin","Store-Forward Avg Latency (ns)",
            "Store-Forward Min Latency (ns)", "Store-Forward Min Latency (ns) per Bin",
            "Store-Forward Max Latency (ns)", "Store-Forward Max Latency (ns) per Bin",
            "First TimeStamp per Bin", "First TimeStamp", "Last TimeStamp per Bin","Last TimeStamp"]

        """
        # Enable all available stats
        # [setattr(stat, "Enabled", True) for stat in binView.Statistic.find()]
        [
            setattr(stat, "Enabled", True)
            for stat in binView.Statistic.find()
            if "Store-Forward Avg Latency (ns)" in stat.Caption
        ]
        binView.Enabled = True

    else:
        logger.info(f"Using Existing IxNetwork Session Id: {session_assistant.Session}")
        startStopTraffic(ixnet, "stop")
        ixnet.Traffic.TrafficItem.find(
            Name="TestTraffic"
        ).ConfigElement.find().FrameSize.FixedSize = frame_size
        ixnet.Traffic.TrafficItem.find(
            Name="TestTraffic"
        ).ConfigElement.find().FrameRate.Rate = rate
        startStopTraffic(ixnet, "start")

    yield ixnet, session_assistant


@pytest.fixture(scope="session", autouse=True)
def session_teardown(request):
    yield
    request.session.ixnet_session.remove()
    logger.info("\n=== Custom session teardown in Test Script ===")


def startStopTraffic(ixnet, oper):
    if oper == "start":
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
        # Start the traffic
        ixnet.Traffic.TrafficItem.find()[0].Generate()
        logger.info("Start Traffic")
        ixnet.Traffic.Apply()
        ixnet.Traffic.StartStatelessTrafficBlocking()
        ti = StatViewAssistant(ixnet, "Traffic Item Statistics")
        try:
            ti.CheckCondition("Tx Frames", StatViewAssistant.GREATER_THAN, 0)
        except Exception:
            raise Exception("Traffic did not start properly.")

    else:
        ixnet.Traffic.StopStatelessTrafficBlocking()
        attempts = 0
        while ixnet.Traffic.IsTrafficRunning and attempts < 10:
            time.sleep(3)
            attempts += 1
        if attempts >= 10:
            raise Exception("Traffic did not stop after 30 seconds.")
        logger.info("\t\tTraffic stopped.")

        ixnet.StopAllProtocols(Arg1="sync")
        try:
            logger.info("Verify protocol sessions")
            protocolsSummary = StatViewAssistant(ixnet, "Protocols Summary")
            protocolsSummary.CheckCondition(
                "Sessions Down", StatViewAssistant.EQUAL, 0, 180
            )
            protocolsSummary.CheckCondition(
                "Sessions Up", StatViewAssistant.EQUAL, 0, 180
            )
        except Exception as e:
            logger.info("ERROR:Protocols session are down.")
            logger.info(protocolsSummary)
            raise Exception(str(e))


def generate_heatmap(pivot_df, frame_size_rate):
    """Generate and save a heatmap with enhanced readability."""

    # Convert ns to µs (microseconds)
    pivot_df = pivot_df / 1000  # Since 1 ns = 0.001 µs
    # Define a custom colormap from green (low) to red (high)
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "green_to_red_purple", ["green", "yellow", "purple", "red"]
    )
    # Determine dynamic figure size based on data shape
    num_tx_ports, num_rx_ports = pivot_df.shape
    fig_width = max(12, num_rx_ports * 0.5)
    fig_height = max(12, num_tx_ports * 0.5)
    # Create figure
    plt.figure(figsize=(fig_width, fig_height))

    # Generate heatmap
    sns.heatmap(
        pivot_df,
        annot=True,
        cmap=cmap,
        fmt=".1f",
        linewidths=0.5,
        cbar_kws={"label": "Latency (µs)"},
    )

    # Set axis labels and title
    plt.xlabel("Rx Port", fontsize=14)
    plt.ylabel("Tx Port", fontsize=14)
    plt.xticks(rotation=45, ha="right", fontsize=12)  # Rotate x-axis labels
    plt.yticks(fontsize=12)
    plt.title("Store-Forward Avg Latency Heatmap (µs)", fontsize=16)

    # Save and show the heatmap
    plt.tight_layout()
    filename = f"{os.path.dirname(__file__)}/heatmap_framesize{frame_size_rate[0]}_rate{frame_size_rate[1]}.png"
    plt.savefig(filename, dpi=300)
    plt.show()
    plt.close()

    logger.info(f"Heatmap saved as {filename}")
