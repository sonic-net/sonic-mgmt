from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
from tests.common.telemetry.constants import UNIT_PERCENT, METRIC_LABEL_TG_FRAME_BYTES
from tests.common.telemetry.metrics import GaugeMetric
from tests.common.telemetry.metrics.device import DevicePortMetrics
from tests.common.telemetry import METRIC_LABEL_DEVICE_ID, METRIC_LABEL_DEVICE_PORT_ID
from functools import wraps

pytestmark = [pytest.mark.topology("nut-single-dut")]
logger = logging.getLogger(__name__)

COLUMNS_SHOW = ["Tx Port", "Rx Port", "Host", "Interface", "CRC", "Tx Frames", "Rx Frames", "RX_ERR", "Loss %"]
fcs_config = {
    "zero": {"Auto": False, "SingleValue": 0},
    "random": {"Auto": False, "ValueType": "nonRepeatableRandom", "RandomMask": "0xFFFFFFFF"},
}


def parametrize_common(func):
    @pytest.mark.parametrize("subnet_type", ["IPv6"])
    @pytest.mark.parametrize("test_duration_sec", [60])
    @pytest.mark.parametrize("tx_port_count", ["max"])
    @pytest.mark.parametrize("frame_size", [128, 256, 1024, 1518, 4096, 8192])
    @pytest.mark.parametrize("fcs_error_type", ["zero", "random"])
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


@parametrize_common
def test_line_rate_fcs_error(
    duthosts,
    request,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_config,
    subnet_type,
    tbinfo,
    frame_size,
    test_duration_sec,
    tx_port_count,
    fcs_error_type,
    db_reporter,
):
    """
    Tests line-rate traffic with FCS errors injected.
    Validates that RX ports receive zero frames and RX_ERR counters equal TX frames.
    """

    logger.info("Starting test_line_rate_fcs_error_traffic_test.")
    good_bad_crc_map, tx_ports, rx_ports = setup_base_config_plus_test_scenario(
        request,
        "line_rate_fcs_error",
        snappi_api,
        duthosts,
        get_snappi_ports,
        get_duthost_bgp_details,
        tx_port_count,
        subnet_type,
        frame_size,
        100,
        test_duration_sec,
        fcs_error_type,
    )

    start_stop(snappi_api, operation="start", op_type="traffic")

    wait_for(
        lambda: is_traffic_stopped(snappi_api),
        "Waiting for traffic stop.",
        interval_seconds=1,
        timeout_seconds=test_duration_sec + 20,
    )
    flow_df, df_counters, df = get_merged_counters(snappi_api, tx_ports + rx_ports)
    df["CRC"] = "badCrc"

    checks = [
        {"mask": df["Rx Frames"] != 0, "fail_msg": "RX port(s) received unexpected frames."},
        {"mask": df["RX_ERR"] != df["Tx Frames"], "fail_msg": "Mismatch: RX_ERR != Tgen TX frames on some ports."},
    ]

    logger.info(
        "Traffic counters post-test:\n"
        + tabulate(df[COLUMNS_SHOW], headers="keys", tablefmt="fancy_grid", showindex=False)
    )
    push_metrics(
        db_reporter, df, subnet_type, frame_size, test_duration_sec, tx_port_count, len(tx_ports), fcs_error_type
    )

    if not validate_and_log(df, checks):
        pytest.fail("FCS line-rate traffic test failed. See logs for details.")
    logger.info("test_line_rate_fcs_error_traffic_test completed successfully.")


@parametrize_common
def test_fcs_error_isolation_one_to_one_parallel(
    request,
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_config,
    subnet_type,
    tbinfo,
    frame_size,
    test_duration_sec,
    tx_port_count,
    fcs_error_type,
    db_reporter,
):
    """
    Tests parallel pairs of flows with alternating good/bad FCS.
    Validates bad-FCS flows get full loss and RX_ERR matches bad TX.
    """

    logger.info("Starting test_fcs_error_isolation_1_to_1_parallel.")

    good_bad_crc_map, tx_ports, rx_ports = setup_base_config_plus_test_scenario(
        request,
        "fcs_error_isolation_one_to_one_parallel",
        snappi_api,
        duthosts,
        get_snappi_ports,
        get_duthost_bgp_details,
        tx_port_count,
        subnet_type,
        frame_size,
        50,
        test_duration_sec,
        fcs_error_type,
    )

    ixnet = snappi_api._ixnetwork
    logger.info("Starting traffic with FCS error injection.")
    ixnet.Traffic.StartStatelessTrafficBlocking()
    wait_for(lambda: is_traffic_stopped(snappi_api), "Waiting for traffic stop.", 1, test_duration_sec + 20)

    flow_df, df_counters, df = get_merged_counters(snappi_api, tx_ports + rx_ports)
    df["CRC"] = (
        df.set_index(["Tx Port", "Rx Port"])
        .index.map({pair: crc for crc, pairs in good_bad_crc_map.items() for pair in pairs})
        .fillna("unknown")
        .values
    )

    rate_by_rx_crc = df.groupby(["Rx Port", "CRC"])["Rx Frames"].sum().unstack(fill_value=0)
    total_bad_tx = df.query("CRC == 'badCrc'")["Tx Frames"].sum()
    total_bad_rxerr = df.query("CRC == 'badCrc'")["RX_ERR"].sum()

    logger.info(
        "Traffic counters post-test:\n"
        + tabulate(df[COLUMNS_SHOW], headers="keys", tablefmt="fancy_grid", showindex=False)
    )

    checks = [
        {"mask": (rate_by_rx_crc.get("badCrc", pd.Series(0)) > 0), "fail_msg": "RX port(s) received bad-FCS frames."},
        {"mask": (total_bad_rxerr != total_bad_tx), "fail_msg": "RX_ERR not matches Tgen TX bad-FCS frames."},
        {
            "mask": (df["CRC"].eq("badCrc") & (df["Loss %"] != 100.0)),
            "fail_msg": "Bad-FCS flows did not have 100% loss.",
        },
        {"mask": (df["CRC"].eq("goodCrc") & (df["Loss %"] > 0.0)), "fail_msg": "Good-FCS flows showed packet loss."},
    ]

    push_metrics(
        db_reporter, df, subnet_type, frame_size, test_duration_sec, tx_port_count, len(tx_ports), fcs_error_type
    )
    if not validate_and_log(df, checks):
        pytest.fail("FCS isolation one-to-one parallel test failed. See logs for details.")
    logger.info("test_fcs_error_isolation_one_to_one_parallel_traffic_test completed successfully.")


@parametrize_common
def test_fcs_error_isolation_mixed_traffic_on_a_single_port_traffic(
    request,
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_config,
    subnet_type,
    tbinfo,
    frame_size,
    test_duration_sec,
    tx_port_count,
    fcs_error_type,
    db_reporter,
):
    """
    Tests mixed good/bad FCS traffic sharing the same RX port.
    Ensures no bad-FCS frames are received and ingress RX_ERR matches bad TX frames.
    """

    logger.info("Starting test_fcs_error_isolation_mixed_traffic_on_a_single_port_traffic_test.")

    good_bad_crc_map, tx_ports, rx_ports = setup_base_config_plus_test_scenario(
        request,
        "fcs_error_isolation_mixed_traffic_on_a_single_port",
        snappi_api,
        duthosts,
        get_snappi_ports,
        get_duthost_bgp_details,
        tx_port_count,
        subnet_type,
        frame_size,
        50,
        test_duration_sec,
        fcs_error_type,
    )

    ixnet = snappi_api._ixnetwork
    ixnet.Traffic.StartStatelessTrafficBlocking()
    wait_for(lambda: is_traffic_stopped(snappi_api), "Waiting for traffic stop.", 1, test_duration_sec + 20)

    flow_df, df_counters, df = get_merged_counters(snappi_api, tx_ports + rx_ports)
    df["CRC"] = (
        df.set_index(["Tx Port", "Rx Port"])
        .index.map({pair: crc for crc, pairs in good_bad_crc_map.items() for pair in pairs})
        .fillna("unknown")
        .values
    )

    crc_group = df.groupby(["Rx Port", "CRC"])["Rx Frames"].sum().unstack(fill_value=0)
    flow_bad = crc_group.get("badCrc", 0)
    total_bad_tx = df.query("CRC == 'badCrc'")["Tx Frames"].sum()
    total_rx_err = df["RX_ERR"].sum()

    logger.info(
        "Traffic counters post-test:\n"
        + tabulate(df[COLUMNS_SHOW], headers="keys", tablefmt="fancy_grid", showindex=False)
    )

    push_metrics(
        db_reporter, df, subnet_type, frame_size, test_duration_sec, tx_port_count, len(tx_ports), fcs_error_type
    )

    checks = [
        {"mask": flow_bad > 0, "fail_msg": "RX port(s) received bad-FCS frames."},
        {
            "mask": total_bad_tx != total_rx_err,
            "fail_msg": ("Mismatch: ingress RX error counters vs bad-FCS Tgen TX frames."),
        },
    ]

    if not validate_and_log(df, checks):
        pytest.fail("FCS isolation mixed-port test failed. See logs for details.")
    logger.info("test_fcs_error_isolation_mixed_traffic_on_a_single_port_traffic_test completed successfully.")


def setup_base_config_plus_test_scenario(
    request,
    scenario,
    snappi_api,
    duthosts,
    get_snappi_ports,
    get_duthost_bgp_details,
    tx_port_count,
    subnet_type,
    frame_size,
    frame_rate,
    test_duration,
    fcs_error_type,
):
    """
    Setup protocol config, port pairs, traffic flows, and FCS error injection.
    Returns a map of CRC types to TX-RX pairs, and lists of tx_ports and rx_ports.
    """
    logger.info("Setting up base configuration and test scenario.")
    snappi_params = SnappiTestParams()
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports, subnet_type)
    if scenario == "line_rate_fcs_error":
        tx_ports = snappi_ports[:-1] if tx_port_count == "max" else snappi_ports[:tx_port_count]
        rx_ports = snappi_ports[-1:] if tx_port_count == "max" else snappi_ports[tx_port_count:tx_port_count + 1]
    else:
        tx_count = 2 * (len(snappi_ports) // 3) if tx_port_count == "max" else 2 * tx_port_count
        rx_count = len(snappi_ports) - tx_count if tx_port_count == "max" else tx_port_count

        tx_ports = snappi_ports[:tx_count]
        rx_ports = snappi_ports[tx_count:tx_count + rx_count]

    base_proto = {"network_group": False, "protocol_type": "bgp", "subnet_type": subnet_type}
    snappi_params.protocol_config = {
        "Tx": {**base_proto, "ports": tx_ports},
        "Rx": {**base_proto, "ports": rx_ports},
    }

    create_cfg_fn = request.getfixturevalue("create_snappi_config")
    snappi_config, handle_map = create_cfg_fn(snappi_params)

    tx_names = handle_map["Tx"]["ip"]
    rx_names = handle_map["Rx"]["ip"]

    if scenario == "line_rate_fcs_error":
        tx_rx_pairs = [(tx_names, rx_names)]
    else:
        # Build TX-RX pairs: every 2 TX ports map to 1 RX port
        tx_rx_pairs = [
            (tx_names[i * 2:(i * 2) + 2], [rx_names[i]]) for i in range(min(len(tx_names) // 2, len(rx_names)))
        ]
    # Configure traffic flows
    snappi_params.traffic_flow_config = [
        {
            "line_rate": frame_rate,
            "frame_size": frame_size,
            "flow_name": f"traffic_fcs_{tx_grp[0]}_to_{rx_grp[0]}",
            "tx_names": tx_grp,
            "rx_names": rx_grp,
            "mesh_type": "mesh",
            "traffic_duration_fixed_seconds": test_duration,
        }
        for tx_grp, rx_grp in tx_rx_pairs
    ]

    snappi_config = create_traffic_items(snappi_config, snappi_params)
    snappi_api.set_config(snappi_config)
    start_stop(snappi_api, operation="start", op_type="protocols")

    good_bad_crc_map = {"goodCrc": [], "badCrc": []}

    ixnet = snappi_api._ixnetwork
    traffic_items = ixnet.Traffic.find().TrafficItem.find()

    if scenario == "line_rate_fcs_error":
        fcs_field = traffic_items.ConfigElement.find().Stack.find(StackTypeId="ethernet.fcs")[-1].Field.find()
        fcs_field.update(**fcs_config.get(fcs_error_type, fcs_config["random"]))

    else:
        logger.info("Generating traffic items in IxNetwork API.")
        traffic_items.Generate()
        for ti in traffic_items:
            for idx, hl in enumerate(ti.HighLevelStream.find()):
                crc_type = "badCrc" if idx % 2 else "goodCrc"
                if crc_type == "badCrc":
                    fcs_field = hl.Stack.find(StackTypeId="ethernet.fcs")[-1].Field.find()
                    fcs_update_args = {"Auto": False}
                    if fcs_error_type == "zero":
                        fcs_update_args.update(SingleValue=0)
                    else:  # random
                        fcs_update_args.update(ValueType="nonRepeatableRandom", RandomMask="0xFFFFFFFF")
                    fcs_field.update(**fcs_update_args)
                good_bad_crc_map[crc_type].append((hl.TxPortName, hl.RxPortNames[0]))

        ixnet.Traffic.Apply()

    logger.info("Clearing all switch counters on DUTs.")
    [duthost.command("sudo sonic-clear counters") for duthost in duthosts]
    logger.info("Base configuration and test scenario setup complete.")
    return good_bad_crc_map, tx_ports, rx_ports


def push_metrics(
    db_reporter, df, ip_version, frame_bytes, duration_sec, tx_port_count, tx_port_count_after_calc, fcs_error_type
):
    """
    Push traffic generator and device under test (DUT) port-level telemetry metrics to the database.

    This function calculates utilization metrics for transmitted and received frames,
    separates metrics for good and bad Frame Check Sequence (FCS) traffic,
    and records detailed port-level counters such as error counts, drops, and overruns.

    Args:
        db_reporter: The database reporter instance used to record metrics.
        df (pd.DataFrame): DataFrame containing aggregated traffic and DUT statistics.
        ip_version (str): IP protocol version used in the test (e.g., 'IPv6').
        frame_bytes (int): Frame size in bytes used in the traffic test.
        duration_sec (int): Duration of the traffic test in seconds.
        tx_port_count (int or str): Number of TX ports configured (may be 'max' string).
        tx_port_count_after_calc (int): The calculated effective number of TX ports used.
        fcs_error_type (str): Type of FCS error injected ('zero' or 'random').

    Returns:
        None

    Side Effects:
        Records multiple gauge metrics on transmitted and received traffic utilization,
        error, drop, and overrun counters at per-host and per-port granularity.
        Finally, it commits all the recorded data via `db_reporter.report()`.
    """

    # Define fixed labels that apply to all reported metrics in this test run
    test_labels = {
        "tg.ip_version": ip_version,
        METRIC_LABEL_TG_FRAME_BYTES: frame_bytes,
        "tg.fcs_error_type": fcs_error_type,
        "test.params.duration.sec": duration_sec,
        "tg.tx_port_count": tx_port_count_after_calc,
        "test.params.tx.port.count": tx_port_count,
    }

    # Calculate bits per frame (used for utilization calculations)
    bits_per_frame = frame_bytes * 8

    # Calculate TX and RX utilization percentages for each flow
    tx_util = (df["Tx Frames"] * bits_per_frame) / (duration_sec * 1e9) * 100
    rx_util = (df["Rx Frames"] * bits_per_frame) / (duration_sec * 1e9) * 100

    # Initialize metric recording objects for each utilization type
    tx_good = GaugeMetric("tg.tx.good.util", "Good-FCS TX utilization", UNIT_PERCENT, db_reporter)
    rx_good = GaugeMetric("tg.rx.good.util", "Good-FCS RX utilization", UNIT_PERCENT, db_reporter)
    tx_bad = GaugeMetric("tg.tx.bad.util", "Bad-FCS TX utilization", UNIT_PERCENT, db_reporter)
    rx_bad = GaugeMetric("tg.rx.bad.util", "Bad-FCS RX utilization", UNIT_PERCENT, db_reporter)

    logger.info("Pushing telemetry metrics for each host and port.")

    # Group data by Host to report metrics individually per device under test
    for host, group in df.groupby("Host"):
        # Iterate through each port row in the group
        for idx, row in group.iterrows():
            # Prepare combined labels for metric reporting (test params + device info)
            labels = {
                **deepcopy(test_labels),
                METRIC_LABEL_DEVICE_ID: host,
                METRIC_LABEL_DEVICE_PORT_ID: row["Interface"],
            }

            # Record usage metrics depending on CRC status (good or bad)
            if row["CRC"] == "badCrc":
                tx_bad.record(tx_util[idx], labels)
                rx_bad.record(rx_util[idx], labels)
            else:
                tx_good.record(tx_util[idx], labels)
                rx_good.record(rx_util[idx], labels)

            # Instantiate port-level metrics recorder for the given port labels
            port_metrics = DevicePortMetrics(reporter=db_reporter, labels=labels)

            # Report detailed counters only if the data is present in the row
            for metric, col in [
                (port_metrics.rx_bps, "RX_BPS"),
                (port_metrics.tx_bps, "TX_BPS"),
                (port_metrics.rx_util, "RX_UTIL"),
                (port_metrics.tx_util, "TX_UTIL"),
                (port_metrics.rx_ok, "RX_OK"),
                (port_metrics.tx_ok, "TX_OK"),
                (port_metrics.rx_err, "RX_ERR"),
                (port_metrics.tx_err, "RX_ERR"),
                (port_metrics.rx_drop, "RX_DRP"),
                (port_metrics.tx_drop, "TX_DRP"),
                (port_metrics.rx_overrun, "RX_OVR"),
                (port_metrics.tx_overrun, "TX_OVR"),
            ]:
                if col in row:
                    metric.record(row[col])

    # Commit all recorded metrics to the database
    db_reporter.report()
    logger.info("Metrics push complete.")


def get_merged_counters(snappi_api, tgen_ports):
    """
    Retrieve and merge flow statistics from the traffic generator (IxNetwork)
    with port-level counters from the Device Under Test (DUT).

    This function:
    - Builds mappings between DUT ports and traffic generator ports.
    - Queries DUTs for port statistics using CLI commands.
    - Retrieves flow-level statistics from IxNetwork.
    - Cleans and converts relevant fields to appropriate numeric types.
    - Maps traffic generator ports to DUT hosts and interfaces.
    - Merges flow and DUT counters into a single pandas DataFrame keyed by host/interface.

    Args:
        snappi_api: Snappi API session object with IxNetwork access.
        tgen_ports (list of dict): List of traffic generator port info dictionaries,
            each containing 'duthost', 'peer_port', and 'port_id' keys.

    Returns:
        pd.DataFrame: A merged DataFrame with detailed metrics from both DUT counters
                      and traffic generator flow statistics, indexed by Host and Interface.
    """
    # Build DUT → TG mapping
    dut_tg_port_map = collections.defaultdict(dict)
    for intf in tgen_ports:
        dut_tg_port_map[intf["duthost"]][intf["peer_port"]] = f"Port_{intf['port_id']}"

    # Reverse TG → (Host, Interface) mapping
    port_to_host_if = {
        port: (host.hostname, iface) for host, ifmap in dut_tg_port_map.items() for iface, port in ifmap.items()
    }

    logger.info("Collecting port statistics from DUT via CLI commands ('portstat').")
    # Collect DUT counters via portstat
    df_counters = pd.DataFrame(
        [
            {"Host": host.hostname, "Interface": iface, **stats}
            for host, ifaces in {
                h: json.loads("".join(h.command(f"sudo portstat -i {','.join(ports.keys())} -j")["stdout_lines"]))
                for h, ports in dut_tg_port_map.items()
            }.items()
            for iface, stats in ifaces.items()
        ]
    )
    df_counters = df_counters.replace({",": "", "%": ""}, regex=True)
    num_cols = ["RX_ERR", "RX_OK", "TX_OK"]
    df_counters[num_cols] = df_counters[num_cols].apply(pd.to_numeric, errors="coerce")

    logger.info("Retrieving flow statistics from IxNetwork Traffic API.")
    # Use IxNetwork StatViewAssistant to acquire current 'Flow Statistics'
    flow_stats = StatViewAssistant(snappi_api._ixnetwork, "Flow Statistics")
    flow_df = pd.DataFrame(flow_stats.Rows.RawData, columns=flow_stats.ColumnHeaders)
    flow_df = flow_df.replace({",": "", "%": ""}, regex=True)
    flow_df[["Tx Frames", "Rx Frames"]] = flow_df[["Tx Frames", "Rx Frames"]].astype(int)
    flow_df["Loss %"] = flow_df["Loss %"].astype(float)

    # Map Tx Port strings to DUT Host and Interface tuples
    mapped = flow_df["Tx Port"].map(port_to_host_if).tolist()
    flow_df[["Host", "Interface"]] = pd.DataFrame(mapped, index=flow_df.index)

    # Merge the DUT port counters with IxNetwork flow stats on Host and Interface
    merged_df = flow_df.merge(df_counters, on=["Host", "Interface"], how="left")
    logger.info("Successfully merged flow and DUT port counters.")

    return flow_df, df_counters, merged_df


def validate_and_log(df, checks):
    """
    Apply validation checks on the DataFrame and log any failing rows.

    Args:
        df (pd.DataFrame): The DataFrame containing test metrics.
        checks (list of dict): Each dict must have:
            - 'mask': A boolean Series or bool indicating failing condition.
            - 'fail_msg': Error message to log if condition is met.

    Returns:
        bool: True if all checks pass (no failures), False if any fail.

    This function handles alignment issues with boolean masks by reindexing
    masks to match the DataFrame's index, which prevents IndexingError.
    It logs a formatted table of all rows that violate each check condition.
    """
    test_pass = True  # Flag to track overall test pass/fail status

    for check in checks:
        mask = check["mask"]  # Boolean Series or bool marking failing rows
        # Ensure boolean mask aligns with DataFrame index to avoid pandas indexing errors
        if isinstance(mask, pd.Series):
            mask_aligned = mask.reindex(df.index, fill_value=False)
            # Select only columns of interest for logging failing rows
            failing_rows = df.loc[mask_aligned, COLUMNS_SHOW]
        else:
            # If mask is a single bool True, consider all rows failing (log entire df),
            # Otherwise, no failures
            failing_rows = df.loc[df.index] if mask else pd.DataFrame()

        if not failing_rows.empty or (isinstance(mask, bool) and mask):
            logger.error(check["fail_msg"])  # Log the failure message
            if not failing_rows.empty:
                # Log a nice formatted table of the failing rows for easier debugging
                logger.error("\n" + tabulate(failing_rows, headers="keys", tablefmt="fancy_grid", showindex=False))
            test_pass = False  # At least one check failed

    return test_pass
