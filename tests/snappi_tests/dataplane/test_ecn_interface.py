"""
ECN interference tests.

Reference test plan:
    docs/testplan/snappi/switch-ecn-interference-tests.md

Both tests use a 2 Tx -> 1 Rx topology so the two equal-rate flows oversubscribe
a single egress port and drive ECN-CE marking.  ECN marking is observed on the
egress side by tracking the 2 ECN bits of the IP header (offset 126, width 2)
and drilling the Traffic Item view down on those bits, producing a per-codepoint
"User Defined Statistics" view.

The tests take a ``lossy_prio`` pair as a parameter:

    * the FIRST priority of the pair is ECN enabled  (queue under test / queue A)
    * the SECOND priority is left NON-ECN enabled     (queue B)

test_cross_queue_interface
    Verify ECN marking isolation *between* queues.  Queue A (ECN) traffic and
    queue B (non-ECN) traffic congest the same egress port simultaneously.
    Queue A packets must get CE marked; queue B packets must NOT be CE marked
    (they are handled by their own WRED config -- dropped/trimmed).

test_mixed_ecn_codepoint
    Verify ECN marking isolation *between codepoints* within the queue under
    test.  Each Tx port sends 4 separate traffic items -- one per ECN codepoint
    (Non-ECT, ECT(0), ECT(1), CE) -- at 24% line rate each, for 8 traffic items
    in total across the 2 Tx ports.  Under congestion the ECT(0)/ECT(1) packets
    must be CE marked, the CE packets stay CE and the Non-ECT packets must never
    be CE marked.
"""
import random
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_interface_details, create_snappi_config, \
    set_primary_chassis, create_traffic_items, start_stop, wait_with_message, get_stats, \
    _normalize_stat_rows, print_ud_statistics, _rx_rate, _traffic_item, \
    _ti_row_index, _drill_down_egress, _ud_rows_by_codepoint, _drill_and_get, _dscp_values  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import (
    enable_ecn,
    stop_pfcwd,
    disable_packet_aging,
)  # noqa: F401

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"
FRAME_SIZE = 1024
LINE_RATE = 70  # % line rate per stream (cross-queue test default)
# For the mixed-codepoint test each Tx port sends 4 traffic items (one per ECN
# codepoint) at 24% line rate each so the 4 together oversubscribe the shared
# egress port when both Tx ports run.
MIXED_CODEPOINT_LINE_RATE = 24
FLOW_DURATION = 1000  # seconds; flows are stopped explicitly by the test

# ECN codepoint values as seen on the 2 tracked egress bits (offset 126, width 2)
ECN_NON_ECT = 0  # 00
ECN_ECT1 = 1  # 01
ECN_ECT0 = 2  # 10
ECN_CE = 3  # 11

# Ordered ECN codepoint names and their tracked-bit values.  One traffic item
# per name is created per Tx port for the mixed-codepoint test.
CODEPOINTS = ["non_ect", "ect0", "ect1", "ce"]
CODEPOINT_VALUE = {
    "non_ect": ECN_NON_ECT,
    "ect0": ECN_ECT0,
    "ect1": ECN_ECT1,
    "ce": ECN_CE,
}

# Drill-down option matching the 2 ECN bits configured for egress tracking.
DRILL_DOWN_OPTION = "Custom: (2 bits at offset 126)"

TI_COLUMNS = ["frames_tx", "frames_rx", "loss", "frames_tx_rate", "frames_rx_rate"]
SELECTED_UD_COLS = [
    "Egress Tracking",
    "Tx Frames",
    "Rx Frames",
    "Frames Delta",
    "Loss %",
    "Tx Frame Rate",
    "Rx Frame Rate",
]


@pytest.fixture(scope="module")
def port_groups(duthosts, get_snappi_ports):
    """Group the discovered snappi ports into 3-port groups (2 Tx + 1 Rx)."""
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(len(snappi_ports) >= 3,
                  "Need at least 3 snappi ports (2 Tx + 1 Rx) for the test")
    pg = [snappi_ports[i:i + 3] for i in range(0, len(snappi_ports), 3)]
    # Drop a trailing incomplete group if the port count is not a multiple of 3.
    return [g for g in pg if len(g) == 3]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _configure_interference(snappi_api, create_snappi_config, snappi_ports,  # noqa F811
                            subnet_type, ecn_prio, non_ecn_prio, mode):  # noqa F811
    """Build a 2 Tx -> 1 Rx oversubscription scenario with egress ECN tracking.

    ``mode`` selects how the two flows are built:

        "cross_queue"     - flow A on ``ecn_prio`` (ECN) + flow B on
                            ``non_ecn_prio`` (non-ECN), both ECT(1).
        "mixed_codepoint" - both flows on ``ecn_prio`` carrying an even mix of
                            all 4 ECN codepoints.

    Generates and applies the traffic but does NOT start it.  Returns
    ``(ixnet, config_facts)``.
    """
    pytest_assert(len(snappi_ports) >= 3, "Not enough ports for the test, need at least 3 ports")
    tx_ports = snappi_ports[:2]
    rx_ports = [snappi_ports[2]]
    egress_duthost = rx_ports[0]["duthost"]

    config_facts = egress_duthost.config_facts(
        host=egress_duthost.hostname, source="running"
    )["ansible_facts"]
    pytest_assert("DSCP_TO_TC_MAP" in config_facts, "DSCP_TO_TC_MAP is not configured on the DUT")
    for prio in (ecn_prio, non_ecn_prio):
        pytest_assert(
            str(prio) in config_facts["DSCP_TO_TC_MAP"]["AZURE"].values(),
            "Lossy priority {} is not mapped to any DSCP in DSCP_TO_TC_MAP".format(prio),
        )

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(egress_duthost, rx_ports[0]["asic_value"])
    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(egress_duthost)
    # Enable ECN only on the first priority of the pair; the second is left
    # non-ECN so its packets are handled by WRED (dropped/trimmed) not marked.
    pytest_assert(enable_ecn(host_ans=egress_duthost, prio=ecn_prio),
                  "Unable to enable ecn on priority {}".format(ecn_prio))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": tx_ports,
               "subnet_type": subnet_type, "is_rdma": True},
        "Rx": {"protocol_type": "ip", "ports": rx_ports,
               "subnet_type": subnet_type, "is_rdma": True},
    }
    config, handles = create_snappi_config(snappi_extra_params)

    rx_names = handles["Rx"]["ip"]
    tx1_name = [handles["Tx"]["ip"][0]]
    tx2_name = [handles["Tx"]["ip"][1]]

    common = {
        "line_rate": LINE_RATE,
        "frame_size": FRAME_SIZE,
        "is_rdma": True,
        "rx_names": rx_names,
        "traffic_duration_fixed_seconds": FLOW_DURATION,
    }

    if mode == "cross_queue":
        ecn_dscp = random.choice(_dscp_values(config_facts, ecn_prio))
        non_ecn_dscp = random.choice(_dscp_values(config_facts, non_ecn_prio))
        snappi_extra_params.traffic_flow_config = [
            dict(common, flow_name="Queue_A_ECN", tx_names=tx1_name,
                 prio=ecn_prio, dscp_value=ecn_dscp, ecn_value="ect1"),
            # Non-ECN queue: only the DSCP value is configured, the ECN field is
            # left untouched (ecn_value=None) so nothing marks these packets.
            dict(common, flow_name="Queue_B_NON_ECN", tx_names=tx2_name,
                 prio=non_ecn_prio, dscp_value=non_ecn_dscp, ecn_value=None),
        ]
    elif mode == "mixed_codepoint":
        ecn_dscp = random.choice(_dscp_values(config_facts, ecn_prio))
        # Each Tx port gets 4 traffic items -- one per ECN codepoint -- at 24%
        # line rate each (8 traffic items total across the 2 Tx ports).
        mixed_common = dict(common, line_rate=MIXED_CODEPOINT_LINE_RATE)
        snappi_extra_params.traffic_flow_config = []
        for port_idx, tx_name in ((1, tx1_name), (2, tx2_name)):
            for cp in CODEPOINTS:
                snappi_extra_params.traffic_flow_config.append(
                    dict(mixed_common,
                         flow_name="Mixed_P{}_{}".format(port_idx, cp),
                         tx_names=tx_name, prio=ecn_prio,
                         dscp_value=ecn_dscp, ecn_value=cp),
                )
    else:
        pytest_assert(False, "Unknown interference mode: {}".format(mode))

    config = create_traffic_items(config, snappi_extra_params)
    snappi_api.set_config(config)

    logger.info("Starting All protocols")
    start_stop(snappi_api, operation="start", op_type="protocols")
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)

    ixnet = snappi_api._ixnetwork
    trafficItem = ixnet.Traffic.TrafficItem.find()
    trafficItem.EgressEnabled = "True"
    eg = trafficItem.EgressTracking.find()
    eg.Encapsulation = "Any: Use Custom Settings"
    eg.Offset = "Custom"
    eg.CustomOffsetBits = 126
    eg.CustomWidthBits = 2
    logger.info("PASS: Egress tracking configured on the 2 ECN bits")

    logger.info("Generating Traffic Item(s)")
    trafficItem.Generate()
    logger.info("Applying Traffic")
    ixnet.Traffic.Apply()
    ixnet.Globals.Statistics.Advanced.Timestamp.TimestampPrecision = 9
    return ixnet, config_facts


# ---------------------------------------------------------------------------
# Cross-queue interference
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossy_prio", [(0, 2)])
def test_cross_queue_interface(
        duthosts,
        snappi_api,  # noqa: F811
        get_snappi_ports,  # noqa: F811
        set_primary_chassis,  # noqa: F811
        create_snappi_config,  # noqa: F811
        subnet_type,
        lossy_prio,
        port_groups,
        fanout_graph_facts_multidut,
):
    """Verify ECN marking isolation between queues.

    ``lossy_prio`` is a (ecn_prio, non_ecn_prio) pair: the first priority is ECN
    enabled (queue A), the second is non-ECN (queue B).  Queue A traffic and
    queue B traffic congest the same egress port together.  Queue A packets must
    be CE marked while queue B packets must remain unmarked.
    """
    ecn_prio, non_ecn_prio = lossy_prio
    for snappi_ports in port_groups:
        logger.info("\nSnappi ports used for the test:")
        for port in snappi_ports:
            logger.info("{}: {}".format(port["peer_port"], port["location"]))
        logger.info("ECN priority (queue A): {}, non-ECN priority (queue B): {}"
                    .format(ecn_prio, non_ecn_prio))

        ixnet, _ = _configure_interference(
            snappi_api, create_snappi_config, snappi_ports,
            subnet_type, ecn_prio, non_ecn_prio, mode="cross_queue",
        )

        ti_a = _traffic_item(ixnet, "Queue_A_ECN")
        ti_b = _traffic_item(ixnet, "Queue_B_NON_ECN")

        # --- Phase 1: queue A only -> 1:1, no congestion, no ECN marking ---
        logger.info("Starting queue A (ECN) flow only -- no oversubscription expected")
        ti_a.StartStatelessTrafficBlocking()
        wait_with_message("For queue A flow to stabilize:", 20)
        get_stats(snappi_api, "Traffic Item Statistics", TI_COLUMNS, "print")
        logger.info("Drill down on Queue_A_ECN flow")
        _drill_down_egress(ixnet, _ti_row_index(ixnet, "Queue_A_ECN"))

        cp_a = _ud_rows_by_codepoint(ixnet)
        pytest_assert(_rx_rate(cp_a, ECN_CE) == 0,
                      "No packets should be ECN-CE marked before oversubscription")
        logger.info("PASS: No ECN marking on queue A without congestion")

        # --- Phase 2: add queue B -> cross-queue congestion -> queue A marked ---
        logger.info("Starting queue B (non-ECN) flow to create cross-queue congestion")
        ti_b.StartStatelessTrafficBlocking()
        wait_with_message("For cross-queue congestion / ECN marking:", 30)
        get_stats(snappi_api, "Traffic Item Statistics", TI_COLUMNS, "print")

        # Queue A (ECN enabled) must be CE marked.
        logger.info("Drill down on Queue_A_ECN flow")
        _drill_down_egress(ixnet, _ti_row_index(ixnet, "Queue_A_ECN"))
        cp_a = _ud_rows_by_codepoint(ixnet)
        pytest_assert(_rx_rate(cp_a, ECN_CE) > 0,
                      "FAIL: queue A (ECN) packets are not CE marked under congestion")
        logger.info("PASS: queue A (ECN) packets are CE marked under congestion")

        # Queue B (non-ECN) must NOT be CE marked -- WRED handles it (drop/trim).
        logger.info("Drill down on Queue_B_NON_ECN flow")
        _drill_down_egress(ixnet, _ti_row_index(ixnet, "Queue_B_NON_ECN"))
        cp_b = _ud_rows_by_codepoint(ixnet)
        qb_non_ce = sum(_rx_rate(cp_b, c) for c in (ECN_NON_ECT, ECN_ECT1, ECN_ECT0))
        pytest_assert(_rx_rate(cp_b, ECN_CE) == 0,
                      "FAIL: queue B (non-ECN) packets were CE marked; queues are not isolated")
        pytest_assert(qb_non_ce > 0,
                      "FAIL: queue B should still egress (uncmarked) packets")
        logger.info("PASS: queue B (non-ECN) packets are not CE marked -- queues isolated")
        ixnet.Traffic.StopStatelessTrafficBlocking()


# ---------------------------------------------------------------------------
# Mixed ECN codepoint
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossy_prio", [(0, 2)])
def test_mixed_ecn_codepoint(
        duthosts,
        snappi_api,  # noqa: F811
        get_snappi_ports,  # noqa: F811
        set_primary_chassis,  # noqa: F811
        create_snappi_config,  # noqa: F811
        subnet_type,
        lossy_prio,
        port_groups,
        fanout_graph_facts_multidut,
):
    """Verify ECN marking isolation between codepoints within one queue.

    Both Tx ports use the first (ECN enabled) priority of the ``lossy_prio``
    pair.  Each Tx port sends 4 separate traffic items -- one per ECN codepoint
    (Non-ECT, ECT(0), ECT(1), CE) at 24% line rate each -- for 8 traffic items
    in total.  The 4 codepoint flows of the first port are drilled down and
    verified: under congestion ECT(0)/ECT(1) packets must be CE marked, CE
    packets stay CE and Non-ECT packets must never be CE marked.
    """
    ecn_prio, non_ecn_prio = lossy_prio
    for snappi_ports in port_groups:
        logger.info("\nSnappi ports used for the test:")
        for port in snappi_ports:
            logger.info("{}: {}".format(port["peer_port"], port["location"]))
        logger.info("Queue under test (ECN priority): {}".format(ecn_prio))

        ixnet, _ = _configure_interference(
            snappi_api, create_snappi_config, snappi_ports,
            subnet_type, ecn_prio, non_ecn_prio, mode="mixed_codepoint",
        )

        # The 4 codepoint traffic items of each Tx port.
        first_port_flows = ["Mixed_P1_{}".format(cp) for cp in CODEPOINTS]
        second_port_flows = ["Mixed_P2_{}".format(cp) for cp in CODEPOINTS]

        # --- Phase 1: first port only -> no congestion -> codepoints unchanged ---
        logger.info("Starting the 4 codepoint flows of the first port only "
                    "-- no oversubscription expected")
        for name in first_port_flows:
            _traffic_item(ixnet, name).StartStatelessTrafficBlocking()
        wait_with_message("For first port flows to stabilize:", 20)
        get_stats(snappi_api, "Traffic Item Statistics", TI_COLUMNS, "print")

        base_ce = {}
        for cp in CODEPOINTS:
            name = "Mixed_P1_{}".format(cp)
            cp_map = _drill_and_get(ixnet, name)
            base_ce[cp] = _rx_rate(cp_map, ECN_CE)
        logger.info("PASS: all codepoints preserved without congestion")

        # --- Phase 2: both ports -> congestion -> ECT marked, Non-ECT/CE intact ---
        logger.info("Starting the 4 codepoint flows of the second port to create "
                    "oversubscription")
        for name in second_port_flows:
            _traffic_item(ixnet, name).StartStatelessTrafficBlocking()
        wait_with_message("For ECN marking to start:", 30)
        get_stats(snappi_api, "Traffic Item Statistics", TI_COLUMNS, "print")

        cong = {cp: _drill_and_get(ixnet, "Mixed_P1_{}".format(cp))
                for cp in CODEPOINTS}

        # ECT(0)/ECT(1) packets are converted to CE, so a CE row appears where
        # there was none without congestion.
        pytest_assert(_rx_rate(cong["ect0"], ECN_CE) > base_ce["ect0"],
                      "FAIL: ECT(0) packets were not CE marked under congestion")
        pytest_assert(_rx_rate(cong["ect1"], ECN_CE) > base_ce["ect1"],
                      "FAIL: ECT(1) packets were not CE marked under congestion")
        # CE packets pass through with the CE codepoint unchanged.
        pytest_assert(_rx_rate(cong["ce"], ECN_CE) > 0,
                      "FAIL: CE packets did not pass through as CE under congestion")
        # Non-ECT packets must never be CE marked -- they still egress as Non-ECT.
        pytest_assert(_rx_rate(cong["non_ect"], ECN_CE) == 0,
                      "FAIL: Non-ECT packets were CE marked -- must never happen")
        pytest_assert(_rx_rate(cong["non_ect"], ECN_NON_ECT) > 0,
                      "FAIL: Non-ECT packets disappeared -- they must never be CE marked")
        logger.info("PASS: ECT(0)/ECT(1) marked to CE, CE stays CE, Non-ECT unaffected")

        ixnet.Traffic.StopStatelessTrafficBlocking()
