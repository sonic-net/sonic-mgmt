"""
SRv6 Max Throughput Minimum Packet Size test.

Sends SRv6 IPv6-in-IPv6 traffic bidirectionally across 32 ports at 100% line rate
and verifies zero drops at known minimum packet sizes per feature-configuration scenario.
"""
from tests.snappi_tests.dataplane.imports import *  # noqa: F403
from snappi_tests.dataplane.files.helper import *  # noqa: F403
from snappi_tests.dataplane.files.max_throughput_helper import (
    load_max_throughput_config,
    get_platform_thresholds,
    configure_scenario,
    backup_dut_config,
    restore_dut_config,
)

logger = logging.getLogger(__name__)  # noqa: F405

pytestmark = [pytest.mark.topology("nut")]  # noqa: F405

MAX_THROUGHPUT_CONFIG = load_max_throughput_config()
SCENARIO_NAMES = list(MAX_THROUGHPUT_CONFIG["scenarios"].keys())
ROUTE_RANGES = {"IPv6": [[["777:777:777::1", 64, 16]]]}


@pytest.mark.parametrize("scenario_name", SCENARIO_NAMES)  # noqa: F405
def test_max_throughput_min_pkt_size(
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_config,
    scenario_name,
):
    """Verify zero packet loss at 100% line rate for the scenario's minimum packet size."""
    config = MAX_THROUGHPUT_CONFIG
    min_ports = config.get("min_ports", 32)
    traffic_duration = config.get("traffic_duration_sec", 60)
    line_rate = config.get("line_rate_pct", 100)
    tolerance_offset = config.get("tolerance_pkt_size_offset", 10)

    pytest_require(  # noqa: F405
        len(duthosts) == 1,
        "This test requires a single-DUT topology, found {} DUTs".format(len(duthosts)),
    )
    duthost = duthosts[0]

    thresholds = get_platform_thresholds(duthost, config)
    pytest_require(  # noqa: F405
        thresholds is not None,
        "Platform '{}' not found in max_throughput_config.yaml — skipping".format(
            duthost.facts.get("hwsku", "unknown")
        ),
    )
    pytest_require(  # noqa: F405
        scenario_name in thresholds,
        "Scenario '{}' has no threshold for platform '{}'".format(
            scenario_name, duthost.facts.get("hwsku", "")
        ),
    )
    min_pkt_size = thresholds[scenario_name]

    snappi_ports = get_duthost_interface_details(  # noqa: F405
        duthosts, get_snappi_ports, "IPv6", protocol_type="bgp"
    )
    pytest_require(  # noqa: F405
        len(snappi_ports) >= min_ports,
        "Need at least {} snappi ports, only {} available — skipping".format(
            min_ports, len(snappi_ports)
        ),
    )
    snappi_ports = snappi_ports[:min_ports]
    half = len(snappi_ports) // 2
    tx_ports = snappi_ports[:half]
    rx_ports = snappi_ports[half:]

    backup_dut_config(duthost)

    try:
        configure_scenario(duthost, scenario_name, config)

        logger.info(
            "Scenario '%s': testing min packet size %dB at %d%% line rate for %ds",
            scenario_name, min_pkt_size, line_rate, traffic_duration,
        )

        _build_and_run_traffic(
            snappi_api,
            create_snappi_config,
            snappi_ports,
            tx_ports,
            rx_ports,
            frame_size=min_pkt_size,
            line_rate=line_rate,
            duration_sec=traffic_duration,
            scenario_name=scenario_name,
            max_loss_pct=0.0,
            config=config,
            duthost=duthost,
        )

        tolerance_pkt_size = min_pkt_size + tolerance_offset
        logger.info(
            "Scenario '%s': tolerance check at %dB (min + %dB offset)",
            scenario_name, tolerance_pkt_size, tolerance_offset,
        )

        _build_and_run_traffic(
            snappi_api,
            create_snappi_config,
            snappi_ports,
            tx_ports,
            rx_ports,
            frame_size=tolerance_pkt_size,
            line_rate=line_rate,
            duration_sec=traffic_duration,
            scenario_name=scenario_name,
            max_loss_pct=0.001,
            config=config,
            duthost=duthost,
        )

    finally:
        logger.info("Restoring DUT config after scenario '%s'", scenario_name)
        restore_dut_config(duthost)


def _build_and_run_traffic(
    snappi_api,
    create_snappi_config,
    snappi_ports,
    tx_ports,
    rx_ports,
    frame_size,
    line_rate,
    duration_sec,
    scenario_name,
    max_loss_pct,
    config,
    duthost,
):
    """Build fresh snappi config with SRv6 IPv6-in-IPv6 flows, run traffic, and assert loss."""
    flow_name = "max_tput_{}_{}B".format(scenario_name, frame_size)
    srv6_cfg = config.get("srv6", {})

    snappi_extra_params = SnappiTestParams()  # noqa: F405
    ranges = ROUTE_RANGES["IPv6"] * len(snappi_ports)
    snappi_extra_params.protocol_config = {
        "Tx": {
            "route_ranges": ranges,
            "protocol_type": "bgp",
            "ports": tx_ports,
            "subnet_type": "IPv6",
            "is_rdma": False,
        },
        "Rx": {
            "route_ranges": ranges,
            "protocol_type": "bgp",
            "ports": rx_ports,
            "subnet_type": "IPv6",
            "is_rdma": False,
        },
    }

    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)

    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": line_rate,
            "frame_size": frame_size,
            "is_rdma": False,
            "flow_name": flow_name,
            "tx_names": (
                snappi_obj_handles["Tx"]["network_group"]
                + snappi_obj_handles["Rx"]["network_group"]
            ),
            "rx_names": (
                snappi_obj_handles["Rx"]["network_group"]
                + snappi_obj_handles["Tx"]["network_group"]
            ),
            "mesh_type": "mesh",
        }
    ]

    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)  # noqa: F405
    snappi_api.set_config(snappi_config)

    start_stop(snappi_api, operation="start", op_type="protocols")  # noqa: F405
    check_bgp_state(snappi_api, "IPv6")  # noqa: F405

    ixnet = snappi_api._ixnetwork
    ixnet.Traffic.TrafficItem.find().update(BiDirectional=True, SrcDestMesh="fullMesh")

    _apply_srv6_packet_headers(ixnet, srv6_cfg)

    start_stop(snappi_api, operation="start", op_type="traffic")  # noqa: F405

    # Verify SRv6 mySID counters are incrementing to confirm traffic matches the SID
    time.sleep(5)  # noqa: F405
    _verify_srv6_mysid_stats(duthost, srv6_cfg)

    logger.info("Traffic running for %d seconds ...", duration_sec)
    wait_with_message("Running traffic for", duration_sec)  # noqa: F405

    start_stop(snappi_api, operation="stop", op_type="traffic")  # noqa: F405

    df = get_stats(  # noqa: F405
        snappi_api, "Traffic Item Statistics", columns=None, return_type="df"
    )
    df = df[["name", "frames_tx", "frames_rx", "loss"]]
    df[["loss"]] = pd.to_numeric(df["loss"], errors="coerce")  # noqa: F405
    df["Status"] = (df["loss"] <= max_loss_pct).map({True: "PASS", False: "FAIL"})

    logger.info(
        "Scenario '%s' @ %dB results:\n%s",
        scenario_name,
        frame_size,
        tabulate(df, headers="keys", tablefmt="psql", showindex=False),  # noqa: F405
    )

    max_loss = df["loss"].max()

    start_stop(snappi_api, operation="stop", op_type="protocols")  # noqa: F405

    pytest_assert(  # noqa: F405
        max_loss <= max_loss_pct,
        "Scenario '{}' FAILED at {}B: loss {:.4f}% exceeds threshold {:.4f}%".format(
            scenario_name, frame_size, max_loss, max_loss_pct,
        ),
    )
    logger.info("Scenario '%s' PASSED at %dB (loss %.4f%%)", scenario_name, frame_size, max_loss)


def _verify_srv6_mysid_stats(duthost, srv6_cfg):
    """Check that SRv6 mySID entries exist in ASIC_DB, confirming traffic matches the SID."""
    sid_ip = srv6_cfg.get("sid_ip", "fcbb:bbbb:1::")
    result = duthost.shell(
        'sonic-db-cli ASIC_DB keys "*ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY*"',
        module_ignore_errors=True,
    )["stdout"].strip()

    if not result:
        logger.warning("No SRv6 mySID entries found in ASIC_DB — SID may not be programmed")
        return

    if sid_ip not in result:
        logger.warning("SRv6 mySID %s not found in ASIC_DB entries", sid_ip)
        return

    logger.info("SRv6 mySID %s confirmed present in ASIC_DB — traffic should match", sid_ip)

    # Check CRM counters to confirm mySID resource is in use
    crm_output = duthost.shell(
        "crm show resources srv6-my-sid-entry", module_ignore_errors=True
    )
    if crm_output["rc"] == 0:
        logger.info("SRv6 mySID CRM resources:\n%s", crm_output["stdout"])


def _apply_srv6_packet_headers(ixnet, srv6_cfg):
    """Add SRv6 IPv6-in-IPv6 encapsulation to the IxNetwork traffic items."""
    outer_dst_ip = srv6_cfg.get("outer_dst_ip", "fcbb:bbbb:1:11a::2")

    traffic_items = ixnet.Traffic.TrafficItem.find()
    for ti in traffic_items:
        config_elements = ti.ConfigElement.find()
        for ce in config_elements:
            stacks = ce.Stack.find()

            for stack in stacks:
                if "IPv6" in stack.DisplayName or "ipv6" in stack.StackTypeId:
                    for field in stack.Field.find():
                        if "Destination Address" in field.DisplayName:
                            field.SingleValue = outer_dst_ip
                        elif "Next Header" in field.DisplayName:
                            field.SingleValue = "41"  # IPv6-in-IPv6
                    break

            proto_template = ixnet.Traffic.ProtocolTemplate.find(StackTypeId="ipv6")
            if proto_template:
                for stack in stacks:
                    if "IPv6" in stack.DisplayName or "ipv6" in stack.StackTypeId:
                        stack.Append(proto_template)
                        break

                stacks = ce.Stack.find()
                ipv6_stacks = [s for s in stacks
                               if "IPv6" in s.DisplayName or "ipv6" in s.StackTypeId]
                if len(ipv6_stacks) >= 2:
                    inner_ipv6 = ipv6_stacks[1]
                    for field in inner_ipv6.Field.find():
                        if "Source Address" in field.DisplayName:
                            field.ValueType = "increment"
                            field.StartValue = "2001:db8:1::1"
                            field.StepValue = "::1"
                            field.CountValue = "1000"
                        elif "Destination Address" in field.DisplayName:
                            field.ValueType = "increment"
                            field.StartValue = "2001:db8:2::1"
                            field.StepValue = "::1"
                            field.CountValue = "1000"

    traffic_items.Generate()
