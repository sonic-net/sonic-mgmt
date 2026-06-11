from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config  # noqa: F401
from snappi_tests.dataplane.files.helper import (
    configure_acl_for_route_withdrawl, start_stop, get_stats, check_bgp_state,
    build_bgp_convergence_config, run_bgp_convergence_event,
    assert_rx_ports_receiving, ROUTE_RANGES,
)

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)
TIMEOUT = 20
METRIC_DESCRIPTION = "convergence time for port up/Route Injection event"


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("event_type", ["t0_port_startup", "route_injection"])
def test_bgp_sessions(
    duthosts,
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
    event_type
):
    """
    Measure BGP dataplane convergence after a single Rx port comes back up via
    a physical port startup (``t0_port_startup``) or a BGP route injection
    (``route_injection``).
    """
    snappi_extra_params = SnappiTestParams()
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = build_bgp_convergence_config(
        duthosts,
        get_snappi_ports,
        create_snappi_config,
        snappi_extra_params,
        ip_version,
        frame_rate,
        frame_size,
        port_split="half",
    )
    get_convergence_for_single_session_flap(
        duthosts,
        snappi_api,
        snappi_config,
        tx_ports,
        rx_ports,
        ip_version,
        snappi_obj_handles,
        event_type,
        db_reporter,
        snappi_extra_params
    )


def get_convergence_for_single_session_flap(
    duthosts,
    snappi_api,
    snappi_config,
    tx_ports,
    rx_ports,
    ip_version,
    snappi_obj_handles,
    event_type,
    db_reporter,
    snappi_extra_params
):
    """
    Get the packet loss duration
    """
    if event_type == "t0_port_startup":
        logger.info("Starting Single Port Flap (Up) Test")
        flap_dut_obj = next(
            (dut for dut in duthosts if dut.hostname == snappi_extra_params.FLAP_DETAILS["device_name"]),
            None
        )
        port = snappi_extra_params.FLAP_DETAILS["port_name"]
        device = snappi_extra_params.FLAP_DETAILS["device_name"]

        def disrupt():
            check_bgp_state(snappi_api, ip_version)
            logger.info("Shutting down {} port of {} dut before starting traffic ".format(port, device))
            flap_dut_obj.command("sudo config interface shutdown {}\n".format(port))
            start_stop(snappi_api, operation="start", op_type="traffic")
            wait(20, "For traffic to stabilize")
            flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
            pytest_assert(int(flow_stats[0].loss) == 0, f"Loss Observed in {flow_stats[0].name} before link Flap Up")
            logger.info("Starting Up {} port of {} dut !!".format(port, device))
            flap_dut_obj.command("sudo config interface startup {}\n".format(port))
            wait(20, "For statistics to be collected")
            assert_rx_ports_receiving(snappi_api)

        def cleanup():
            logger.info("Starting up {} port of {} dut !!".format(port, device))
            flap_dut_obj.command("sudo config interface startup {}\n".format(port))

        run_bgp_convergence_event(
            snappi_api, snappi_config, db_reporter, snappi_extra_params,
            ip_version, event_type, METRIC_DESCRIPTION,
            disrupt=disrupt, cleanup=cleanup,
            delta_zero_msg="Delta Frames is 0 after flap, which means no packet drop occurred",
            not_converged_msg="Traffic did not converge after link down",
        )
    elif event_type == "route_injection":
        logger.info("Starting Single Port (Route Injection) Test")
        dut_obj = rx_ports[0]['duthost']
        table_name = "AI_ACL_TABLE"

        def disrupt():
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
            dut_obj.command("sudo chmod 666 /home/admin/ai_acl.json")
            dut_obj.command("sudo config acl update full \"/home/admin/ai_acl.json\"")
            logger.info('Withdrawing Routes from {}'.format(snappi_obj_handles["Rx"]["network_group"][1]))
            cs = snappi_api.control_state()
            cs.protocol.route.state = cs.protocol.route.WITHDRAW
            cs.protocol.route.names = [snappi_obj_handles["Rx"]["network_group"][1]]
            snappi_api.set_control_state(cs)
            wait(30, "For routes to be withdrawn")
            start_stop(snappi_api, operation="start", op_type="traffic")
            # Route Injection
            start_time = time.time()
            logger.info("Removing acl table {}".format(table_name))
            dut_obj.command("sudo config acl remove table {}".format(table_name))
            logger.info('Injecting Routes from {}'.format(snappi_obj_handles["Rx"]["network_group"][1]))
            cs = snappi_api.control_state()
            cs.protocol.route.state = cs.protocol.route.ADVERTISE
            cs.protocol.route.names = [snappi_obj_handles["Rx"]["network_group"][1]]
            snappi_api.set_control_state(cs)
            end_time = time.time()
            wait(30, "For routes to be Advertised")
            logger.info('Time taken to apply acl and route Injection on snappi port: {} (s)'.
                        format(end_time - start_time))

        def cleanup():
            logger.info("Removing acl table {}".format(table_name))
            dut_obj.command("sudo config acl remove table {}".format(table_name))

        run_bgp_convergence_event(
            snappi_api, snappi_config, db_reporter, snappi_extra_params,
            ip_version, event_type, METRIC_DESCRIPTION,
            disrupt=disrupt, cleanup=cleanup,
            delta_zero_msg="Delta Frames is 0 after removing applied acl and route Injection, "
                           "which means no packet drop occurred",
            not_converged_msg="Traffic did not converge after route injection",
        )
