# flake8: noqa: F403, F401, F405
from snappi_tests.rocev2.files.helper import *

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 10  # seconds

def test_rocev2_basic_dp_traffic_no_congestion(
                                    request,
                                    snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts_multidut,
                                    get_snappi_ports,
                                    duthosts
                                ):
    """
    NOTE:
        ECN thresholds should be configured higher than the PFC threshold.
        Otherwise, tail drops may occur before PFC is triggered, and no PFC frames will be generated.

    1. Configure DUT with 2 lossless queues 3 and 4 mapping to DSCP value 3 and 4
       queue 6 mapping to DSCP 48, enable PFC and ECN-marking.
    2. Configure 1:1 test traffic between rank 0-2 & 1-3, 1 rank (endpoint) per port.
    3. Configure constant rate test traffic (RoCEv2 AI traffic) for 2 lossless and 4 lossy queues: 6 QPs per rank pair.
    4. DSCP value 0-5 on rank0 q1-6
    5. DSCP value 0-5 on rank1 q1-6
    6. DSCP for ACK/NAK/CNP value 48
    7. 4K IB MTU, 1MB message size (256 packets in burst per message)
    8. ECN-CE bit value 00 (non-ECT)
    9. Verify that PFC is triggered on queue 3 (and 4 if not disabled)
       ACKs are sent on queue 3 (and 4 if not disabled)
       And that there is no ECN marking and no CNPs on queue 3 (and 4 if not disabled).

    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 4, "Need minimum of 4 ports")

    tconfig, plist, sports = snappi_dut_base_config(request, duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]
    lossless_queue = random.choice([3, 4])
    lossy_queue = 5

    COMMON_CFG = {
                "mtu": 9100,
                "qp_configs": [{"message_size_unit": "mb", "message_size": 1, "dscp": priority_to_dscp[lossless_queue]}],
                "cnp": {"ip_dscp": 48, "ecn_value": "non_ect"},
                "dcqcn_settings": {"enable_dcqcn": False},
                "connection_type": {
                    "choice": "reliable_connection",
                    "reliable_connection": {
                        "ack": {"ip_dscp": priority_to_dscp[lossy_queue], "ecn_value": "non_ect"},
                        "nak": {"ip_dscp": priority_to_dscp[lossy_queue], "ecn_value": "non_ect"},
                        "enable_retransmission_timeout": True,
                        "retransmission_timeout_value": 40,
                    },
                },
            }

    pairs = list(zip(port_ids[:len(port_ids)//2], port_ids[len(port_ids)//2:]))
    topology = {
                port: {"peers": [peer], **COMMON_CFG}
                for tx, rx in pairs
                for port, peer in ((tx, rx), (rx, tx))
            }
    logger.info(f"Test Topology: {topology}")

    rocev2_flow_df,port_stats_df=run_rocev2_step(
        api=snappi_api,
        base_config=tconfig,
        port_config_list=plist,
        topology=topology,
        traffic_duration=TRAFFIC_DURATION,
        duthosts=duthosts,
    )

    dut_queue_df = queue_counters(snappi_dut_port_map, queue_ids=[f"UC{lossless_queue}", f"UC{lossy_queue}"], queue_cols=["totalpacket"])
    merged_df = rocev2_flow_df.merge(dut_queue_df, left_on="port_tx", right_on="snappi_port",how="left")


    dsps = [priority_to_dscp[q] for q in [lossless_queue]]
    # pfc_cols = [f"`Rx_Pause_Priority_Group_{q}_Frames`" for q in [lossless_queue]]
    pfc_cols = [f"Rx Pause Priority Group 0 Frames"]
    checks = [
        make_check("message_fail != 0 or frame_delta != 0",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "message_tx", "message_complete_rx", "message_fail", "frame_delta"],
                "All messages complete, no loss",
                "message_fail=0 & frame_delta=0 required" ),
        make_check("nak_tx != 0 or nak_rx != 0 or frame_sequence_error != 0",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                "No NAK/sequence errors",
                "nak_tx=0 & nak_rx=0 & frame_sequence_error=0 required" ),
        make_check(f"avg_latency > {LATENCY_PROFILES['ai']['avg_latency_max']}",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "avg_latency", "max_latency"],
                "Latency within spec",
                f"avg_latency > {LATENCY_PROFILES['ai']['avg_latency_max']} is a failure" ),
        make_check(f"ip_dscp in {dsps} and ack_tx == 0",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "ack_tx", "ack_rx"], f"ACK on DSCPs {dsps}",
                f"ack_tx > 0 required for DSCPs {dsps}"),
        make_check(f"ip_dscp in {dsps} and ecn_ce_rx != 0",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "ecn_ce_rx"], f"ECN-CE on DSCPs {dsps}",
                f"ecn_ce_rx == 0 required for DSCPs {dsps}"),
        make_check(f"ip_dscp in {dsps} and cnp_tx != 0 and cnp_rx != 0",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "cnp_tx", "cnp_rx"], f"CNP on DSCPs {dsps}",
                f"cnp_tx == 0 and cnp_rx == 0 required for DSCPs {dsps}"),
        make_check(" or ".join(f"`{col}` != 0" for col in pfc_cols),
                ["Port Name"]+pfc_cols, f"PFC on queues {lossless_queue}",
                "PFC frames expected on at least one of the lossless queues",
                override_df=port_stats_df),
        make_check(f"ack_tx != `UC5 totalpacket` or ack_rx != ack_tx",
                ["flow_name", "port_tx", "port_rx","ip_dscp", "ack_tx", "ack_rx", "UC5 totalpacket"], f"ACK on Snappi and DUT should match.",
                f"ack_tx == UC5 totalpacket and ack_rx == ack_tx"),
    ]
    assert_queries(merged_df, checks)
    logger.info("*** TC1 PASSED ***")
