# flake8: noqa: F403, F401, F405
from snappi_tests.rocev2.files.helper import *
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_rocev2_basic_dp_traffic_no_congestion(
                                                request,
                                                snappi_api,
                                                conn_graph_facts,
                                                fanout_graph_facts_multidut,
                                                get_snappi_ports,
                                                duthosts,
                                                tbinfo,
                                                multidut_port_info,
                                            ):
    """
    Test basic RoCEv2 datapath functionality with no congestion (i.e., no PFC, no ECN, no DCBX, etc.).
    Verify that all traffic is lossless and that there are no RoCEv2 errors (NAKs, sequence errors, CNPs).

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph for multiple duts
        get_snappi_ports (pytest fixture): list of snappi port and duthost information
        duthosts (pytest fixture): list of DUTs
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    snappi_port_list = get_snappi_ports
    pytest_require(
                    len(snappi_port_list) >= 4,
                    "Need Minimum of 4 ports defined in ansible/files/*links.csv file"
                )
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(request,
                                                                            duthosts,
                                                                            snappi_port_list,
                                                                            snappi_api
                                                                            )
    port_ids = [port_config.id for port_config in port_config_list]
    pairs = list(zip(port_ids[:len(port_ids)//2], port_ids[len(port_ids)//2:]))
    topology = {
                **{tx: {"peers": [rx], "mtu": 5000} for tx, rx in pairs},
                **{rx: {"peers": [], "mtu": 5000} for tx, rx in pairs}
               }
    testbed_config = configure_rocev2_topology(testbed_config, port_config_list, topology)  # noqa: F405
    logger.info(f"Test Topology: {topology}")

    snappi_api.set_config(testbed_config)
    # Remove  below code once the bug is fixed
    rocev2s = snappi_api._ixnetwork.Topology.find().DeviceGroup.find().Ethernet.find().Ipv4.find().Rocev2.find()
    [rocev2.update(QpCount=0) for rocev2 in rocev2s if rocev2.PeerIPList == []]

    # Protocols: start → stop → start
    start_stop(snappi_api, operation="start", op_type="protocols")

    # Remove  below code once the bug is fixed
    start_stop(snappi_api, operation="stop", op_type="protocols")
    start_stop(snappi_api, operation="start", op_type="protocols")

    # Traffic: start → wait → stop
    start_stop(snappi_api, operation="start", op_type="traffic")
    wait_with_message("Waiting for traffic to finish...", 30)
    start_stop(snappi_api, operation="stop", op_type="traffic")

    streams = snappi_api._ixnetwork.Traffic.find().RoceV2Traffic.find().RoceV2Stream.find()
    dscp_by_qp = {s.Name: int(s.IpDscp) for s in streams}
    df = get_stats(snappi_api, stat_name="per_qp", return_type='df')
    df.insert(df.columns.get_loc('port_rx') + 1, 'ip_dscp', df['flow_name'].map(dscp_by_qp))
    logger.info(f"Traffic Stats: \n{tabulate(df, headers='keys', tablefmt='psql')}")
    ps_df = get_stats(snappi_api, stat_name="Port Statistics", return_type='df')

    # Convert PFC column once (fixed your syntax error)
    col = "Rx Pause Priority Group 3 Frames"
    ps_df[col] = pd.to_numeric(ps_df[col], errors="coerce")

    # Define checks as (mask, columns, description)
    CHECKS = [
                (
                    df["frame_delta"].ne(0),
                    ["ip_dscp", "frame_delta"],
                    "No loss",
                    "frame_delta must be 0 for all flows (no loss allowed)",
                ),
                (
                    df[["nak_tx", "nak_rx", "frame_sequence_error"]].ne(0),
                    ["ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                    "No NAK/sequence error",
                    "nak_tx, nak_rx, frame_sequence_error must all be 0",
                ),
                (
                    df[["cnp_tx", "cnp_rx"]].ne(0),
                    ["ip_dscp", "cnp_tx", "cnp_rx"],
                    "No CNP (both tx/rx zero)",
                    "cnp_tx and cnp_rx must be 0 for all flows",
                ),
                (
                    ps_df["Rx Pause Priority Group 3 Frames"].ne(0),
                    ["Rx Pause Priority Group 3 Frames"],
                    "No PFC queue 3",
                    "Rx Pause Priority Group 3 Frames must be 0 (no PFC on queue 3)",
                    dict(context_df=ps_df, context_cols=("Port Name",)),
                ),
                (
                    (df["ip_dscp"] == priority_to_dscp[6]) & (df["ack_tx"] == 0),
                    ["ip_dscp", "ack_tx", "ack_rx"],
                    "ACK queue 6",
                    "for ip_dscp=DSCP(queue 6), ack_tx must be > 0 (ACK must exist on queue 6)",
                ),
                (
                    (df["ip_dscp"].isin([priority_to_dscp[3], priority_to_dscp[4]]))
                    & (df["ecn_ce_rx"] != 0),
                    ["ip_dscp", "ecn_ce_rx"],
                    "No ECN-CE queue 3/4",
                    "for ip_dscp of queues 3/4, ecn_ce_rx must be 0 (no ECN-CE)",
                ),
                (
                    (df["ip_dscp"] == priority_to_dscp[6])
                    & df[["cnp_tx", "cnp_rx"]].ne(0).any(axis=1),
                    ["ip_dscp", "cnp_tx", "cnp_rx"],
                    "No CNP queue 6",
                    "for ip_dscp=DSCP(queue 6), cnp_tx/cnp_rx must be 0 (no CNP on queue 6)",
                ),
    ]

    run_assertions(df, CHECKS)  # noqa: F405
    logger.info("All assertions passed for RoCEv2 basic datapath test with no congestion.")
