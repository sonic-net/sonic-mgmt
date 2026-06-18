"""
ECN marking response-time tests (enter time + exit time).

Topology per port-group: 2 Tx ports -> 1 Rx (egress) port, so two equal-rate
flows can oversubscribe a single egress port and drive ECN-CE marking.

Egress tracking is configured on the 2 ECN bits of the IP header (offset 126,
width 2). After a drill-down on those 2 bits the "User Defined Statistics" view
breaks the egress traffic out by CE value; Row 3 (Rows[2]) is the ECN-CE marked
row (CE bits == 3).

Two measurements:

- ECN marking ENTER time (test_ecn_response_entry_time):
    1. Start the first flow only -- no oversubscription, no ECN marking.
    2. Start the second flow -- oversubscription begins and ECN marking starts.
    3. first_marked_ts  = First TimeStamp of the ECN-CE row (Row 3 of UD stats).
       first_pkt_flow2  = First TimeStamp of the second stream.
       ENTER time       = first_marked_ts - first_pkt_flow2.

- ECN marking EXIT time (test_ecn_response_exit_time, existing logic):
    1. Run both flows oversubscribed so packets are ECN-CE marked.
    2. Stop the first stream so the egress buffer drains and marking stops.
       last_ts_flow1 = Last TimeStamp of the stopped flow.
       egress_3      = Last TimeStamp of the ECN-CE row (Row 3 of UD stats).
       EXIT time     = egress_3 - last_ts_flow1.
"""
import random
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_interface_details, create_snappi_config, \
    get_snappi_stats, set_primary_chassis, create_traffic_items, start_stop, wait_with_message, \
    get_stats, _normalize_stat_rows, print_ud_statistics, dutconfig_checkpoint  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import (
    enable_ecn,
    stop_pfcwd,
    disable_packet_aging,
)  # noqa: F401

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"

# Row index of the ECN-CE marked entry in the drilled-down User Defined
# Statistics view (CE bits == 3). 1-indexed this is "Row 3".
ECN_CE_ROW = 2

# Drill-down option matching the 2 ECN bits configured below (offset 126, 2 bits).
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
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(len(snappi_ports) % 3 == 0,
                  "Number of ports should be a multiple of 3 to create port groups of 3 ports each")
    pg = []
    for i in range(0, len(snappi_ports), 3):
        pg.append(snappi_ports[i:i + 3])
    return pg[:-1] if len(snappi_ports) % 3 != 0 else pg


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _configure_oversub(snappi_api,
                       create_snappi_config,  # noqa: F811
                       snappi_ports,
                       subnet_type,
                       lossy_prio):
    """Build a 2:1 oversubscription scenario (2 Tx -> 1 Rx) with egress ECN/CE
    tracking. Generates and applies the traffic but does NOT start it.

    Returns (ixnet, trafficItem).
    """
    pytest_assert(len(snappi_ports) >= 3, "Not enough ports for the test, Need at least 3 ports")
    tx_ports = snappi_ports[:2]
    rx_ports = [snappi_ports[2]]
    egress_duthost = rx_ports[0]["duthost"]

    config_facts = egress_duthost.config_facts(
        host=egress_duthost.hostname, source="running"
    )["ansible_facts"]
    pytest_assert("DSCP_TO_TC_MAP" in config_facts, "DSCP_TO_TC_MAP is not configured on the DUT")
    pytest_assert(
        str(lossy_prio) in config_facts["DSCP_TO_TC_MAP"]["AZURE"].values(),
        "Lossy priority {} is not mapped to any DSCP in DSCP_TO_TC_MAP".format(lossy_prio),
    )
    dscp_values = [int(dscp) for dscp, tc in config_facts["DSCP_TO_TC_MAP"]["AZURE"].items()
                   if int(tc) == lossy_prio]

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(egress_duthost, rx_ports[0]["asic_value"])
    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(egress_duthost)
    pytest_assert(enable_ecn(host_ans=egress_duthost, prio=lossy_prio), "Unable to enable ecn")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": tx_ports,
               "subnet_type": subnet_type, "is_rdma": True},
        "Rx": {"protocol_type": "ip", "ports": rx_ports,
               "subnet_type": subnet_type, "is_rdma": True},
    }
    config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": 99,
            "frame_size": 1024,
            "is_rdma": True,
            "flow_name": "Traffic Flow",
            "tx_names": snappi_obj_handles["Tx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["ip"],
            "traffic_duration_fixed_seconds": 1000,
            "prio": lossy_prio,
            "dscp_value": random.choice(dscp_values),
        },
    ]
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
    logger.info("PASS: Egress tracking configured successfully")

    logger.info("Generating Traffic Item")
    trafficItem.Generate()
    logger.info("Applying Traffic")
    ixnet.Traffic.Apply()
    return ixnet, trafficItem


def _drill_down_egress(ixnet):
    """Drill down the Traffic Item view on the 2 egress ECN bits, producing the
    per-CE-value 'User Defined Statistics' view."""
    tiview = ixnet.Statistics.View.find(Caption="Traffic Item Statistics")[0]
    pytest_assert(len(tiview) == 1, "No statistics rows found in Traffic Item Statistics view")
    drill_down = tiview.DrillDown.find()
    drill_down.TargetRowIndex = 0
    drill_down.TargetDrillDownOption = DRILL_DOWN_OPTION
    drill_down.DoDrillDown()
    wait_with_message("For drill down operation to complete:", 30)
    logger.info("Drill Down Finished")


def _ts_seconds(timestamp_str):
    """Parse the seconds.milliseconds field out of an IxNetwork 'HH:MM:SS.sss'
    timestamp string (same convention as the original response-time test)."""
    return float(timestamp_str.split(":")[-1])


# ---------------------------------------------------------------------------
# ECN marking ENTER time
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossy_prio", [0])
def test_ecn_response_entry_time(
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
    """Measure the ECN marking ENTER time.

    Start the first flow alone (no oversubscription -> no ECN marking), then
    start the second flow to create oversubscription. The enter time is the
    delta between the first ECN-CE marked packet (Row 3 of the User Defined
    Statistics) and the first packet transmitted by the second stream.
    """
    for snappi_ports in port_groups:
        logger.info("\n")
        logger.info("Snappi ports used for the test:")
        for port in snappi_ports:
            logger.info("{}: {}".format(port["peer_port"], port["location"]))

        ixnet, trafficItem = _configure_oversub(
            snappi_api, create_snappi_config, snappi_ports, subnet_type, lossy_prio
        )
        ixnet.Globals.Statistics.Advanced.Timestamp.TimestampPrecision = 9
        streams = trafficItem.HighLevelStream.find()
        pytest_assert(len(streams) >= 2,
                      "Expected 2 high level streams (one per Tx port) for oversubscription")
        stream1, stream2 = streams[0], streams[1]

        # --- Phase 1: first flow only -> no oversubscription, no ECN marking ---
        logger.info("Starting first stream only (no oversubscription expected)")
        stream1.StartStatelessTrafficBlocking()
        wait_with_message("For first stream to stabilize:", 20)
        get_stats(snappi_api, "Traffic Item Statistics", TI_COLUMNS, "print")
        TI_Statistics = StatViewAssistant(ixnet, "Traffic Item Statistics")
        pytest_assert(int(float(TI_Statistics.Rows[0]["Loss %"])) == 0,
                      "No loss expected with a single (non-oversubscribed) flow")

        _drill_down_egress(ixnet)
        UD_Statistics = StatViewAssistant(ixnet, "User Defined Statistics")
        print_ud_statistics(SELECTED_UD_COLS, UD_Statistics)
        if len(_normalize_stat_rows(UD_Statistics.Rows)) > ECN_CE_ROW:
            pytest_assert(int(float(UD_Statistics.Rows[ECN_CE_ROW]["Rx Frame Rate"])) == 0,
                          "No packets should be ECN-CE (bit=3) marked before oversubscription")
        logger.info("PASS: No ECN marking observed with a single flow")

        # --- Phase 2: start second flow -> oversubscription -> ECN marking ---
        logger.info("Starting second stream to create oversubscription")
        stream2.StartStatelessTrafficBlocking()
        wait_with_message("For ECN marking to start:", 30)

        _drill_down_egress(ixnet)
        UD_Statistics = StatViewAssistant(ixnet, "User Defined Statistics")
        print_ud_statistics(SELECTED_UD_COLS, UD_Statistics)
        pytest_assert(int(float(UD_Statistics.Rows[ECN_CE_ROW]["Rx Frame Rate"])) > 0,
                      "FAIL: Packets are not received with ECN - CE bit set to 3 after oversubscription")
        logger.info("PASS: Packets are received with ECN - CE bit set to 3.")

        # First ECN-CE marked packet timestamp (Row 3 of User Defined Statistics)
        first_marked_ts = _ts_seconds(UD_Statistics.Rows[ECN_CE_ROW]["First TimeStamp"])
        logger.info("First TimeStamp of ECN-CE row (Row 3, UD Statistics): {}".format(
            UD_Statistics.Rows[ECN_CE_ROW]["First TimeStamp"]))

        # First packet timestamp of the second stream (the flow that triggered marking).
        # Flow Statistics rows follow the high level stream order, so Rows[1] is stream2.
        flow_Statistics = StatViewAssistant(ixnet, "Flow Statistics")
        first_pkt_flow2_ts = _ts_seconds(flow_Statistics.Rows[1]["First TimeStamp"])
        logger.info("First TimeStamp of 2nd flow (Row 2, Flow Statistics): {}".format(
            flow_Statistics.Rows[1]["First TimeStamp"]))
        ECN_ENTER_TIME = round((first_marked_ts - first_pkt_flow2_ts) * 1000000, 6)
        logger.info("\n")
        logger.info("ECN Marking Enter Time is: {} microseconds".format(ECN_ENTER_TIME))
        logger.info("\n")
        pytest_assert(ECN_ENTER_TIME >= 0,
                      "ECN enter time should be non-negative (first marked packet must follow "
                      "the second stream's first packet)")

        # Stop Traffic
        trafficItem.StopStatelessTrafficBlocking()


# ---------------------------------------------------------------------------
# ECN marking EXIT time
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossy_prio", [0])
def test_ecn_response_exit_time(
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
    """Measure the ECN marking EXIT time.

    Run both flows oversubscribed so packets are ECN-CE marked, then stop the
    first stream so the egress buffer drains and marking stops. The exit time is
    the delta between the last ECN-CE marked packet (Row 3 of the User Defined
    Statistics) and the last packet of the stopped flow.
    """
    for snappi_ports in port_groups:
        logger.info("\n")
        logger.info("Snappi ports used for the test:")
        for port in snappi_ports:
            logger.info("{}: {}".format(port["peer_port"], port["location"]))

        ixnet, trafficItem = _configure_oversub(
            snappi_api, create_snappi_config, snappi_ports, subnet_type, lossy_prio
        )
        ixnet.Globals.Statistics.Advanced.Timestamp.TimestampPrecision = 9
        # Start both flows together -> oversubscription -> ECN marking.
        logger.info("Starting Traffic")
        ixnet.Traffic.StartStatelessTrafficBlocking()
        time.sleep(30)
        get_stats(snappi_api, "Traffic Item Statistics", TI_COLUMNS, "print")
        TI_Statistics = StatViewAssistant(ixnet, "Traffic Item Statistics")
        pytest_assert(int(float(TI_Statistics.Rows[0]["Loss %"])) > 0,
                      "Loss must be observed when oversubscribed traffic is running")

        _drill_down_egress(ixnet)

        # Stop one of the high level streams and note down its respective time stamp.
        stream1 = trafficItem.HighLevelStream.find()[0]
        UD_Statistics = StatViewAssistant(ixnet, "User Defined Statistics")
        pytest_assert(int(float(UD_Statistics.Rows[ECN_CE_ROW]["Rx Frame Rate"])) > 0,
                      "FAIL: Packets are not received with ECN - CE bit set to 3")
        print_ud_statistics(SELECTED_UD_COLS, UD_Statistics)
        logger.info("PASS: Packets are received with ECN - CE bit set to 3.")

        stream1.StopStatelessTrafficBlocking()
        logger.info("Stream 1 stopped")
        wait_with_message("For egress port buffer to drain:", 10)
        UD_Statistics = StatViewAssistant(ixnet, "User Defined Statistics")
        print_ud_statistics(SELECTED_UD_COLS, UD_Statistics)

        # Last timestamp of the stopped flow (Flow Statistics Row 0 == stream1).
        flow_Statistics = StatViewAssistant(ixnet, "Flow Statistics")
        last_time_stamp_flow_1 = _ts_seconds(flow_Statistics.Rows[0]["Last TimeStamp"])
        logger.info("Last TimeStamp of stopped flow (Row 1, Flow Statistics): {}".format(
            flow_Statistics.Rows[0]["Last TimeStamp"]))
        # After stopping the flow, egress tracking Row 3 should stop receiving marked packets.
        UD_Statistics = StatViewAssistant(ixnet, "User Defined Statistics")
        pytest_assert(int(float(UD_Statistics.Rows[ECN_CE_ROW]["Rx Frame Rate"])) == 0,
                      "FAIL: Packets are still received with ECN - CE bit set to 3 after stopping the stream")
        logger.info("PASS: Packets are not received with ECN - CE bit set to 3 after stopping the stream")

        egress_3 = _ts_seconds(UD_Statistics.Rows[ECN_CE_ROW]["Last TimeStamp"])
        logger.info("Last TimeStamp of ECN-CE row (Row 3, UD Statistics): {}".format(
            UD_Statistics.Rows[ECN_CE_ROW]["Last TimeStamp"]))
        ECN_EXIT_TIME = round((egress_3 - last_time_stamp_flow_1) * 1000, 3)
        logger.info("\n")
        logger.info("ECN Marking Exit Response Time is: {} milliseconds".format(ECN_EXIT_TIME))
        logger.info("\n")

        # Stop Traffic
        trafficItem.StopStatelessTrafficBlocking()
