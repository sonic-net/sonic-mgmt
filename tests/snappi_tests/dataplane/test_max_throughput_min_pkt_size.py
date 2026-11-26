"""
SRv6 Max Throughput Minimum Packet Size test.

Sends SRv6 IPv6-in-IPv6 traffic bidirectionally across 32 ports at 100% line rate
and verifies zero drops at known minimum packet sizes per feature-configuration scenario.
"""
import ipaddress

from tests.snappi_tests.dataplane.imports import *  # noqa: F403
from snappi_tests.dataplane.files.helper import *  # noqa: F403
from snappi_tests.dataplane.files.max_throughput_helper import (
    _load_json_output,
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
    validate_srv6_stats = config["scenarios"][scenario_name].get(
        "usid_decap", False
    )

    snappi_extra_params = SnappiTestParams()  # noqa: F405
    ranges = _generate_unique_route_ranges("IPv6", len(snappi_ports))
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
            "tx_names": snappi_obj_handles["Tx"]["network_group"],
            "rx_names": snappi_obj_handles["Rx"]["network_group"],
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
    _clear_dut_counters(duthost)
    srv6_counters_before = (
        _get_srv6_mysid_counters(duthost, srv6_cfg)
        if validate_srv6_stats else None
    )

    start_stop(snappi_api, operation="start", op_type="traffic")  # noqa: F405

    time.sleep(5)  # noqa: F405
    if validate_srv6_stats:
        _verify_srv6_mysid_counter_delta(
            duthost, srv6_cfg, srv6_counters_before
        )

    logger.info("Traffic running for %d seconds ...", duration_sec)
    wait_with_message("Running traffic for", duration_sec)  # noqa: F405

    start_stop(snappi_api, operation="stop", op_type="traffic")  # noqa: F405
    _verify_no_dut_drops(duthost, snappi_ports)

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


def _generate_unique_route_ranges(ip_version, port_count):
    """Generate one unique advertised route prefix per Snappi port."""
    base_ip, prefix, route_count = ROUTE_RANGES[ip_version][0][0]
    ip_class = (
        ipaddress.IPv4Address
        if ip_version == "IPv4" else ipaddress.IPv6Address
    )
    base_ip = int(ip_class(base_ip))
    increment = route_count if ip_version == "IPv4" else 1 << 96
    return [
        [[str(ip_class(base_ip + count * increment)), prefix, route_count]]
        for count in range(port_count)
    ]


def _counter_to_int(value):
    """Convert SONiC CLI counter output to an integer."""
    if value in (None, "", "N/A"):
        return 0
    return int(str(value).replace(",", ""))


def _get_srv6_mysid_counters(duthost, srv6_cfg):
    """Read packet and byte counters for the configured SRv6 mySID."""
    sid_ip = srv6_cfg.get("sid_ip", "fcbb:bbbb:1::")
    sid_with_prefix = "{}/{}".format(
        sid_ip, srv6_cfg.get("sid_prefix_len", 48)
    )
    stats_list = duthost.show_and_parse("show srv6 stats")

    for stats in stats_list:
        mysid = stats.get("mysid", "")
        if (
            mysid in (sid_ip, sid_with_prefix) or
            mysid.startswith("{}/".format(sid_ip))
        ):
            return {
                "packets": _counter_to_int(stats.get("packets")),
                "bytes": _counter_to_int(stats.get("bytes")),
            }

    pytest_assert(  # noqa: F405
        False,
        "SRv6 mySID {} not found in 'show srv6 stats': {}".format(
            sid_ip, stats_list
        ),
    )


def _verify_srv6_mysid_counter_delta(duthost, srv6_cfg, before):
    """Verify SRv6 mySID counters increment while traffic is running."""
    after = _get_srv6_mysid_counters(duthost, srv6_cfg)
    pytest_assert(  # noqa: F405
        after["packets"] > before["packets"] and
        after["bytes"] > before["bytes"],
        "SRv6 mySID counters did not increment. Before: {}, after: {}".format(
            before, after
        ),
    )
    logger.info(
        "SRv6 mySID counters incremented. Before: %s, after: %s",
        before,
        after,
    )


def _get_dut_ports(snappi_ports):
    """Return unique DUT front-panel ports used by the Snappi test."""
    return sorted({port["peer_port"] for port in snappi_ports})


def _clear_dut_counters(duthost):
    """Clear DUT port and queue counters before traffic starts."""
    duthost.shell("sonic-clear counters")
    duthost.shell("sonic-clear queuecounters")


def _verify_no_port_drops(duthost, dut_ports):
    """Verify no RX/TX drops on DUT ports used by the test."""
    output = duthost.shell(
        "portstat -i {} -j".format(",".join(dut_ports))
    )["stdout"]
    stats = _load_json_output(output)
    drops = []

    for port in dut_ports:
        port_stats = stats.get(port, {})
        pytest_assert(  # noqa: F405
            port_stats,
            "No portstat counters found for {}".format(port),
        )
        for counter in ("RX_DRP", "TX_DRP"):
            value = _counter_to_int(port_stats.get(counter))
            if value:
                drops.append("{} {}={}".format(port, counter, value))

    pytest_assert(  # noqa: F405
        not drops,
        "Unexpected DUT port drops: {}".format(", ".join(drops)),
    )


def _verify_no_queue_drops(duthost, dut_ports):
    """Verify no queue drops on DUT ports used by the test."""
    drops = []
    output = duthost.shell("show queue counters --all -j")["stdout"]
    queue_stats = _load_json_output(output)

    for port in dut_ports:
        port_queues = queue_stats.get(port, {})
        pytest_assert(  # noqa: F405
            port_queues,
            "No queue counters found for {}".format(port),
        )

        for queue, queue_stats in port_queues.items():
            if not isinstance(queue_stats, dict):
                continue
            drop_packets = _counter_to_int(queue_stats.get("droppacket"))
            if drop_packets:
                drops.append(
                    "{} {} droppacket={}".format(port, queue, drop_packets)
                )

    pytest_assert(  # noqa: F405
        not drops,
        "Unexpected DUT queue drops: {}".format(", ".join(drops)),
    )


def _verify_no_dut_drops(duthost, snappi_ports):
    """Verify DUT port and queue counters did not record drops."""
    dut_ports = _get_dut_ports(snappi_ports)
    _verify_no_port_drops(duthost, dut_ports)
    _verify_no_queue_drops(duthost, dut_ports)


def _apply_srv6_packet_headers(ixnet, srv6_cfg):
    """Add SRv6 IPv6-in-IPv6 encapsulation to the IxNetwork traffic items."""
    outer_dst_ip = srv6_cfg.get("outer_dst_ip", "fcbb:bbbb:1:11a::2")

    traffic_items = ixnet.Traffic.TrafficItem.find()
    configured_elements = 0
    for ti in traffic_items:
        config_elements = ti.ConfigElement.find()
        for ce in config_elements:
            stacks = ce.Stack.find()
            ipv6_stacks = [
                s for s in stacks
                if "IPv6" in s.DisplayName or "ipv6" in s.StackTypeId
            ]
            pytest_assert(  # noqa: F405
                ipv6_stacks, "Traffic item has no outer IPv6 stack"
            )

            outer_ipv6 = ipv6_stacks[0]
            outer_dst_set = False
            outer_next_header_set = False
            for field in outer_ipv6.Field.find():
                if "Destination Address" in field.DisplayName:
                    field.SingleValue = outer_dst_ip
                    outer_dst_set = True
                elif "Next Header" in field.DisplayName:
                    field.SingleValue = "41"  # IPv6-in-IPv6
                    outer_next_header_set = True
            pytest_assert(  # noqa: F405
                outer_dst_set, "Outer IPv6 destination field was not found"
            )
            pytest_assert(  # noqa: F405
                outer_next_header_set,
                "Outer IPv6 next-header field was not found",
            )

            proto_template = ixnet.Traffic.ProtocolTemplate.find(
                StackTypeId="ipv6"
            )
            pytest_assert(  # noqa: F405
                proto_template,
                "IxNetwork IPv6 protocol template was not found",
            )
            if len(ipv6_stacks) < 2:
                outer_ipv6.Append(proto_template)
                stacks = ce.Stack.find()
                ipv6_stacks = [
                    s for s in stacks
                    if "IPv6" in s.DisplayName or "ipv6" in s.StackTypeId
                ]

            pytest_assert(
                len(ipv6_stacks) >= 2,
                "Traffic item has no inner IPv6 stack after SRv6 header "
                "configuration",
            )  # noqa: F405
            inner_ipv6 = ipv6_stacks[1]
            inner_src_set = False
            inner_dst_set = False
            for field in inner_ipv6.Field.find():
                if "Source Address" in field.DisplayName:
                    field.ValueType = "increment"
                    field.StartValue = "2001:db8:1::1"
                    field.StepValue = "::1"
                    field.CountValue = "1000"
                    inner_src_set = True
                elif "Destination Address" in field.DisplayName:
                    field.ValueType = "increment"
                    field.StartValue = "2001:db8:2::1"
                    field.StepValue = "::1"
                    field.CountValue = "1000"
                    inner_dst_set = True

            pytest_assert(  # noqa: F405
                inner_src_set, "Inner IPv6 source field was not found"
            )
            pytest_assert(  # noqa: F405
                inner_dst_set, "Inner IPv6 destination field was not found"
            )
            configured_elements += 1

    pytest_assert(  # noqa: F405
        configured_elements > 0,
        "No SRv6 traffic config elements were updated",
    )
    traffic_items.Generate()
