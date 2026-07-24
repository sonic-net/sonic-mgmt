from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
from tests.common.telemetry.constants import UNIT_PERCENT, METRIC_LABEL_TG_FRAME_BYTES
from tests.common.telemetry.metrics import GaugeMetric
from tests.common.telemetry.metrics.device import DevicePortMetrics
from tests.common.telemetry import METRIC_LABEL_DEVICE_ID, METRIC_LABEL_DEVICE_PORT_ID
from functools import wraps

pytestmark = [pytest.mark.topology("nut-single-dut")]
logger = logging.getLogger(__name__)

COLUMNS_SHOW = ["CRC", "fcs_error_type", "Tx Port", "Rx Port", "Host", "Interface",
                "Tx Frames", "Rx Frames", "RX_ERR", "Loss %"]

# Test scenario identifiers (used to drive port selection, flow building and FCS injection).
SCENARIO_LINE_RATE = "line_rate_fcs_error"
SCENARIO_ONE_TO_ONE = "fcs_error_isolation_one_to_one_parallel"
SCENARIO_MIXED = "fcs_error_isolation_mixed_traffic_on_a_single_port"

# IxNetwork "Flow Statistics" columns that may hold the per-flow traffic-item name.
TRAFFIC_ITEM_NAME_COLUMNS = ["Traffic Item", "Flow Group", "Traffic Item Name"]


def parametrize_common(func):
    @pytest.mark.parametrize("subnet_type", ["IPv4"])
    @pytest.mark.parametrize("test_duration_sec", [60])
    @pytest.mark.parametrize("tx_port_count", ["max"])
    @pytest.mark.parametrize("frame_size", [1518])
    @pytest.mark.parametrize("fcs_error_type", ["zero", "random"])
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Verification: Each verify_* returns a list of failure strings (empty = pass) so every
# violated condition is reported at once.
# ---------------------------------------------------------------------------
def verify_line_rate(df):
    """All frames are bad: RX receives nothing and every byte is counted as an RX error."""
    failures = []
    rx_total = int(df["Rx Frames"].sum())
    if rx_total != 0:
        failures.append(f"RX received {rx_total} frames, expected 0.")

    mismatched = df.loc[df["RX_ERR"] != df["Tx Frames"], "Interface"].tolist()
    if mismatched:
        failures.append(f"RX_ERR != TX frame count on interface(s): {mismatched}")
    return failures


def verify_isolation(df):
    """Bad-FCS traffic is fully dropped at ingress; good-FCS traffic passes cleanly.

    Works for both one-to-one (pure-bad ports) and mixed (good+bad per port): RX_ERR
    is summed per distinct ingress port so a port with two flow rows isn't double-counted.
    """
    failures = []
    bad = df[df["CRC"] == "badCrc"]
    good = df[df["CRC"] == "goodCrc"]

    rx_bad = int(bad["Rx Frames"].sum())
    if rx_bad != 0:
        failures.append(f"RX received {rx_bad} bad-FCS frames, expected 0.")

    if not (bad["Loss %"] == 100.0).all():
        failures.append("Some bad-FCS flows did not have 100% loss.")

    if (good["Loss %"] > 0.0).any():
        failures.append("Some good-FCS flows showed packet loss.")

    total_bad_tx = int(bad["Tx Frames"].sum())
    total_rx_err = int(df.drop_duplicates(["Host", "Interface"])["RX_ERR"].sum())
    if total_bad_tx != total_rx_err:
        failures.append(f"Ingress RX_ERR ({total_rx_err}) != bad-FCS TX frames ({total_bad_tx}).")
    return failures


def assert_no_failures(scenario, failures):
    """Fail the test (listing every violated condition) unless `failures` is empty."""
    pytest_assert(not failures, f"FCS '{scenario}' verification failed: \n - " + "\n  - ".join(failures))


def add_leading_columns(df, crc, fcs_error_type):
    """Place CRC as the 1st column and fcs_error_type as the 2nd column of `df`.

    `crc` may be a scalar (e.g. "badCrc") or a per-row array. Returns the same df.
    """
    if "CRC" in df.columns:
        df = df.drop(columns="CRC")
    df.insert(0, "CRC", crc)
    df.insert(1, "fcs_error_type", fcs_error_type)
    return df


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
        SCENARIO_LINE_RATE,
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
    df = get_merged_counters(snappi_api, tx_ports + rx_ports)
    df = add_leading_columns(df, "badCrc", fcs_error_type)

    logger.info(
        "Traffic counters post-test:\n"
        + tabulate(df[COLUMNS_SHOW], headers="keys", tablefmt="fancy_grid", showindex=False)
    )
    push_metrics(
        db_reporter, df, subnet_type, frame_size, test_duration_sec, tx_port_count, len(tx_ports), fcs_error_type
    )

    assert_no_failures(SCENARIO_LINE_RATE, verify_line_rate(df))
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
        SCENARIO_ONE_TO_ONE,
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

    ixnet = snappi_api._ixnetwork
    logger.info("Starting traffic with FCS error injection.")
    ixnet.Traffic.StartStatelessTrafficBlocking()
    wait_for(lambda: is_traffic_stopped(snappi_api), "Waiting for traffic stop.", 1, test_duration_sec + 20)

    df = get_merged_counters(snappi_api, tx_ports + rx_ports)
    # good/bad live on different TX ports -> classify by (Tx Port, Rx Port).
    crc_values = (
        df.set_index(["Tx Port", "Rx Port"])
        .index.map({pair: crc for crc, pairs in good_bad_crc_map.items() for pair in pairs})
        .fillna("unknown")
        .values
    )
    df = add_leading_columns(df, crc_values, fcs_error_type)

    logger.info(
        "Traffic counters post-test:\n"
        + tabulate(df[COLUMNS_SHOW], headers="keys", tablefmt="fancy_grid", showindex=False)
    )
    push_metrics(
        db_reporter, df, subnet_type, frame_size, test_duration_sec, tx_port_count, len(tx_ports), fcs_error_type
    )

    assert_no_failures(SCENARIO_ONE_TO_ONE, verify_isolation(df))
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
        SCENARIO_MIXED,
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

    df = get_merged_counters(snappi_api, tx_ports + rx_ports)
    # Good and bad flows share the same (Tx Port, Rx Port) pair in this scenario, so the
    # CRC type must be resolved from the per-flow traffic-item name, not the port pair.
    name_to_crc = {name: crc for crc, names in good_bad_crc_map.items() for name in names}
    name_col = next((c for c in TRAFFIC_ITEM_NAME_COLUMNS if c in df.columns), None)
    if name_col is None:
        pytest.fail("Could not locate the traffic-item name column in flow statistics.")
    crc_values = df[name_col].map(name_to_crc).fillna("unknown").values
    df = add_leading_columns(df, crc_values, fcs_error_type)

    logger.info(
        "Traffic counters post-test:\n"
        + tabulate(df[COLUMNS_SHOW], headers="keys", tablefmt="fancy_grid", showindex=False)
    )
    push_metrics(
        db_reporter, df, subnet_type, frame_size, test_duration_sec, tx_port_count, len(tx_ports), fcs_error_type
    )

    assert_no_failures(SCENARIO_MIXED, verify_isolation(df))
    logger.info("test_fcs_error_isolation_mixed_traffic_on_a_single_port_traffic_test completed successfully.")


def inject_fcs_error(obj, fcs_error_type):
    """
    Corrupt the FCS of an IxNetwork traffic object (ConfigElement or HighLevelStream).

    "zero" forces the ethernet.fcs field to a fixed 0 value; "random" randomizes the
    frame payload and marks the CRC as bad.
    """
    if fcs_error_type == "zero":
        obj.Stack.find(StackTypeId="ethernet.fcs")[-1].Field.find().update(Auto=False, SingleValue=0)
    elif fcs_error_type == "random":
        obj.FramePayload.find().Type = "random"
        obj.Crc = "badCrc"


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
    if scenario == SCENARIO_LINE_RATE:
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

    mixed_scenario = scenario == SCENARIO_MIXED

    if scenario == SCENARIO_LINE_RATE:
        tx_rx_pairs = [(tx_names, rx_names)]
    else:
        # Build TX-RX pairs: every 2 TX ports map to 1 RX port
        tx_rx_pairs = [
            (tx_names[i * 2:(i * 2) + 2], [rx_names[i]]) for i in range(min(len(tx_names) // 2, len(rx_names)))
        ]

    good_bad_crc_map = {"goodCrc": [], "badCrc": []}

    if mixed_scenario:
        # Mixed-traffic on a single port (section 4.2.2): each TX port carries BOTH a
        # good-FCS and a bad-FCS flow to the same RX port simultaneously, each at
        # `frame_rate` (50%) line rate. The crc map is keyed by flow name because the
        # good and bad flows share the same (Tx Port, Rx Port) pair.
        snappi_params.traffic_flow_config = []
        for tx_grp, rx_grp in tx_rx_pairs:
            for tx in tx_grp:
                for crc in ("goodCrc", "badCrc"):
                    flow_name = f"fcs_{crc}_{tx}_to_{rx_grp[0]}"
                    snappi_params.traffic_flow_config.append(
                        {
                            "line_rate": frame_rate,
                            "frame_size": frame_size,
                            "flow_name": flow_name,
                            "tx_names": [tx],
                            "rx_names": rx_grp,
                            "mesh_type": "one_to_one",
                            "traffic_duration_fixed_seconds": test_duration,
                        }
                    )
                    good_bad_crc_map[crc].append(flow_name)
    else:
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

    ixnet = snappi_api._ixnetwork
    traffic_items = ixnet.Traffic.find().TrafficItem.find()

    if scenario == SCENARIO_LINE_RATE:
        inject_fcs_error(traffic_items.ConfigElement.find(), fcs_error_type)

    elif mixed_scenario:
        # Inject FCS errors per traffic-item: only the bad-FCS flows are corrupted.
        logger.info("Generating traffic items in IxNetwork API.")
        traffic_items.Generate()
        bad_names = set(good_bad_crc_map["badCrc"])
        for ti in traffic_items:
            if ti.Name not in bad_names:
                continue
            for hl in ti.HighLevelStream.find():
                inject_fcs_error(hl, fcs_error_type)
        ixnet.Traffic.Apply()

    else:
        logger.info("Generating traffic items in IxNetwork API.")
        traffic_items.Generate()
        for ti in traffic_items:
            for idx, hl in enumerate(ti.HighLevelStream.find()):
                is_bad = bool(idx % 2)
                if is_bad:
                    inject_fcs_error(hl, fcs_error_type)
                crc_type = "badCrc" if is_bad else "goodCrc"
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
            # test_labels holds only scalars, so a shallow copy is sufficient and avoids
            # a per-row deepcopy.
            labels = {
                **test_labels,
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
                (port_metrics.tx_err, "TX_ERR"),
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

    return merged_df
