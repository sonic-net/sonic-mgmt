from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config, \
    dutconfig_checkpoint, wait_for  # noqa: F401
from snappi_tests.dataplane.files.helper import (
    configure_acl_for_route_withdrawl, start_stop, get_stats, check_bgp_state,
    build_bgp_convergence_config, run_bgp_convergence_event,
    assert_rx_ports_receiving, check_learned_routes_in_dut, select_random_t0_t1_port,
)

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)
TIMEOUT = 20
METRIC_DESCRIPTION = "convergence time for port down/Route withdrawl event"

# Route ranges advertised by the Rx (BT0) snappi ports, keyed by IP version.
# Each entry is ((network, prefix_len, count), (network, prefix_len, count)).
ROUTE_RANGES = {
    "IPv6": [
        (
            ("777:777:777::1", 64, 5000),
            ("666:666:666::1", 64, 5000),
        )
    ],
    "IPv4": [
        (
            ("100.1.1.1", 24, 5000),
            ("200.1.1.1", 24, 5000),
        )
    ],
}


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10, 25, 50, 75, 100])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("max_convergence_ms", [4000])
def test_bgp_t0_port_shutdown(
    duthosts,
    dutconfig_checkpoint,   # noqa: F811, F401
    snappi_api,
    get_snappi_ports,
    conn_graph_facts,
    fanout_graph_facts_multidut,
    set_primary_chassis,   # noqa: F811, F401
    create_snappi_config,  # noqa: F811, F401
    ip_version,
    db_reporter,
    tbinfo,
    frame_rate,
    frame_size,
    max_convergence_ms
):
    """
    Measure BGP dataplane convergence after a single Rx port goes down via a
    physical port shutdown (``t0_port_shutdown``).
    """
    event_type = "t0_port_shutdown"
    snappi_extra_params = SnappiTestParams()
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = build_bgp_convergence_config(
        duthosts,
        get_snappi_ports,
        create_snappi_config,
        snappi_extra_params,
        ip_version,
        frame_rate,
        frame_size,
        route_ranges=ROUTE_RANGES,
        port_split="half",
    )

    logger.info("Starting Single Port Flap (Down) Test")
    # Flap a randomly selected T0 DUT's port that connects to the T1 (from links.csv)
    # instead of the default snappi-facing Rx port.
    snappi_extra_params.FLAP_DETAILS = select_random_t0_t1_port(duthosts, conn_graph_facts, dut_type="t0")
    flap_dut_obj = next(
        (dut for dut in duthosts if dut.hostname == snappi_extra_params.FLAP_DETAILS["device_name"]),
        None
    )
    port = snappi_extra_params.FLAP_DETAILS["port_name"]
    device = snappi_extra_params.FLAP_DETAILS["device_name"]

    def disrupt():
        check_bgp_state(snappi_api, ip_version)
        check_learned_routes_in_dut(duthosts, ip_version, rx_ports, ROUTE_RANGES)
        start_stop(snappi_api, operation="start", op_type="traffic")
        flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
        pytest_assert(int(flow_stats[0].loss) == 0, f"Loss Observed in {flow_stats[0].name} before link Flap")
        assert_rx_ports_receiving(snappi_api)
        logger.info("All ports Tx and Rx rates are within 0.05% of average rates")
        logger.info("Shutting down {} port of {} dut !!".format(port, device))
        flap_dut_obj.command("sudo config interface shutdown {}\n".format(port))
        wait_for(lambda: is_traffic_converged(snappi_api), "Traffic to Converge", interval_seconds=5, timeout_seconds=180)

    run_bgp_convergence_event(
        snappi_api, snappi_config, db_reporter, snappi_extra_params,
        ip_version, event_type, METRIC_DESCRIPTION,
        disrupt=disrupt,
        delta_zero_msg="Delta Frames is 0 after flap, which means no packet drop occurred",
        not_converged_msg="Traffic did not converge after link down",
        max_convergence_ms=max_convergence_ms,
    )


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10, 25, 50, 75, 100])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("max_convergence_ms", [4000])
def test_bgp_route_withdrawal(
    duthosts,
    dutconfig_checkpoint,    # noqa: F811, F401
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,   # noqa: F811, F401
    create_snappi_config,  # noqa: F811, F401
    ip_version,
    db_reporter,
    tbinfo,
    frame_rate,
    frame_size,
    max_convergence_ms,
):
    """
    Measure BGP dataplane convergence after a single Rx port's routes are
    withdrawn (``route_withdrawal``).
    """
    event_type = "route_withdrawal"
    snappi_extra_params = SnappiTestParams()
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = build_bgp_convergence_config(
        duthosts,
        get_snappi_ports,
        create_snappi_config,
        snappi_extra_params,
        ip_version,
        frame_rate,
        frame_size,
        route_ranges=ROUTE_RANGES,
        port_split="half",
    )

    logger.info("Starting Single Port (Route Withdraw) Test")
    dut_obj = rx_ports[0]['duthost']
    table_name = "AI_ACL_TABLE"

    def disrupt():
        check_bgp_state(snappi_api, ip_version)
        check_learned_routes_in_dut(duthosts, ip_version, rx_ports, ROUTE_RANGES)
        start_stop(snappi_api, operation="start", op_type="traffic")
        # Unless we configure acl on the DUT, the packets will not drop on route withdraw
        logger.info("Configuring ACL for packet drop on one of the BGP peer")
        destination_ip_list = [list(item) for item in ROUTE_RANGES[ip_version][0]]
        acl_dict = configure_acl_for_route_withdrawl(destination_ip_list, table_name)
        dut_obj.command("sudo config acl add table {} l3v6".format(json.dumps(acl_dict)))
        dut_obj.command(
            "sudo config acl add table {} L3v6 -p {} -s egress".format(table_name, rx_ports[1]['peer_port'])
        )
        with open("/tmp/ai_acl.json", 'w') as fp:
            json.dump(acl_dict, fp, indent=4)
        dut_obj.copy(src="/tmp/ai_acl.json", dest="/home/admin/ai_acl.json")
        start_time = time.time()
        dut_obj.command("sudo chmod 666 /home/admin/ai_acl.json")
        dut_obj.command("sudo config acl update full \"/home/admin/ai_acl.json\"")
        logger.info('Withdrawing Routes from {}'.format(snappi_obj_handles["Rx"]["network_group"][1]))
        cs = snappi_api.control_state()
        cs.protocol.route.state = cs.protocol.route.WITHDRAW
        cs.protocol.route.names = [snappi_obj_handles["Rx"]["network_group"][1]]
        snappi_api.set_control_state(cs)
        end_time = time.time()
        wait_for(lambda: is_traffic_converged(snappi_api), "Traffic to Converge", interval_seconds=5, timeout_seconds=180)
        logger.info('Time taken to apply acl and route withdraw on snappi port: {} (s)'.
                    format(end_time - start_time))

    run_bgp_convergence_event(
        snappi_api, snappi_config, db_reporter, snappi_extra_params,
        ip_version, event_type, METRIC_DESCRIPTION,
        disrupt=disrupt,
        delta_zero_msg="Delta Frames is 0 after applying acl and route withdraw, "
                       "which means no packet drop occurred",
        not_converged_msg="Traffic did not converge after route withdraw",
        max_convergence_ms=max_convergence_ms,
    )
