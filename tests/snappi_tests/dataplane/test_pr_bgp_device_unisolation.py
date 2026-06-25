from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config, \
    dutconfig_checkpoint  # noqa: F401
from snappi_tests.dataplane.files.helper import (
    start_stop, get_stats, check_bgp_state, get_all_port_names,
    all_ports_startup, all_ports_shutdown, build_bgp_convergence_config,
    run_bgp_convergence_event, check_learned_routes_in_dut, select_unisolation_device,
)

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)
TIMEOUT = 20
METRIC_DESCRIPTION = "convergence time-port up/Route Injection event"

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


def _build_unisolation_config(
    duthosts,
    get_snappi_ports,
    create_snappi_config,  # noqa: F811, F401
    snappi_extra_params,
    ip_version,
    frame_rate,
    frame_size,
):
    """
    Build the interleaved Tx/Rx BGP convergence config shared by the three
    device-unisolation tests and pick the T1 unisolation device.
    """
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = build_bgp_convergence_config(
        duthosts,
        get_snappi_ports,
        create_snappi_config,
        snappi_extra_params,
        ip_version,
        frame_rate,
        frame_size,
        route_ranges=ROUTE_RANGES,
        port_split="interleave",
    )
    snappi_extra_params.unisolation_device = select_unisolation_device(duthosts, dut_type="t1")
    return snappi_config, snappi_obj_handles, tx_ports, rx_ports


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10, 100])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("max_convergence_ms", [4000])
def test_bgp_config_reload(
    duthosts,
    dutconfig_checkpoint,  # noqa: F811, F401
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
    max_convergence_ms
):
    """
    Measure BGP dataplane convergence after a ``config reload`` on the T1 DUT.
    """
    event_type = "config_reload"
    snappi_extra_params = SnappiTestParams()
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = _build_unisolation_config(
        duthosts, get_snappi_ports, create_snappi_config, snappi_extra_params,
        ip_version, frame_rate, frame_size,
    )
    dut_obj = snappi_extra_params.unisolation_device

    def disrupt():
        check_bgp_state(snappi_api, ip_version)
        check_learned_routes_in_dut(duthosts, ip_version, rx_ports, ROUTE_RANGES)
        logger.info("Starting {} test".format(event_type))
        start_stop(snappi_api, operation="start", op_type="traffic")
        flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
        pytest_assert(int(flow_stats[0].loss) == 0, "Loss Observed in {} before {} on DUT {}".
                      format(flow_stats[0].name, event_type, dut_obj.hostname))
        logger.info("No Loss observed before {} on DUT {}".format(event_type, dut_obj.hostname))
        logger.info("Reloading config on DUT {}".format(dut_obj.hostname))
        reload_output = dut_obj.command("sudo config reload -f -y \n")['stderr']
        if 'Error' in reload_output:
            reload_output = dut_obj.command("sudo config reload -y \n")['stderr']
            pytest_assert('Error' not in reload_output,
                          'Error while reloading config in {} !!!!!'.format(dut_obj.hostname))

    def cleanup():
        logger.info("Finally Block Execution...")
        all_ports_startup(dut_obj)

    run_bgp_convergence_event(
        snappi_api, snappi_config, db_reporter, snappi_extra_params,
        ip_version, event_type, METRIC_DESCRIPTION,
        disrupt=disrupt, cleanup=cleanup, cleanup_first=True,
        convergence="rate_within", converge_timeout=300,
        rate_varying_msg="Total Tx Rx Rates are varying by more than 0.1 percent after {} on DUT {}".
        format(event_type, dut_obj.hostname),
        max_convergence_ms=max_convergence_ms
    )


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10, 100])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("max_convergence_ms", [4000])
def test_bgp_all_ports_startup(
    duthosts,
    dutconfig_checkpoint,   # noqa: F811, F401
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
    Measure BGP dataplane convergence after a bulk port startup on the T1 DUT
    (all ports shut down before traffic, then started back up).
    """
    event_type = "all_ports_startup"
    snappi_extra_params = SnappiTestParams()
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = _build_unisolation_config(
        duthosts, get_snappi_ports, create_snappi_config, snappi_extra_params,
        ip_version, frame_rate, frame_size,
    )
    dut_obj = snappi_extra_params.unisolation_device

    def disrupt():
        check_bgp_state(snappi_api, ip_version)
        check_learned_routes_in_dut(duthosts, ip_version, rx_ports, ROUTE_RANGES)
        logger.info("Starting {} test".format(event_type))
        logger.info('Interface List : {} '.format(get_all_port_names(dut_obj)))
        # Shutdown all ports on DUT before traffic start
        all_ports_shutdown(dut_obj)
        start_stop(snappi_api, operation="start", op_type="traffic")
        # Startup all ports on DUT after traffic start
        all_ports_startup(dut_obj)

    def cleanup():
        logger.info("Finally Block Execution...")
        all_ports_startup(dut_obj)

    run_bgp_convergence_event(
        snappi_api, snappi_config, db_reporter, snappi_extra_params,
        ip_version, event_type, METRIC_DESCRIPTION,
        disrupt=disrupt, cleanup=cleanup, cleanup_first=True,
        convergence="rate_within", converge_timeout=300,
        rate_varying_msg="Total Tx Rx Rates are varying by more than 0.1 percent after {} on DUT {}".
        format(event_type, dut_obj.hostname),
        max_convergence_ms=max_convergence_ms
    )


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10, 100])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("max_convergence_ms", [4000])
def test_bgp_container_restart(
    duthosts,
    dutconfig_checkpoint,  # noqa: F811, F401
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
    max_convergence_ms
):
    """
    Measure BGP dataplane convergence after a ``bgp`` container restart on the
    T1 DUT.
    """
    event_type = "bgp_container_restart"
    snappi_extra_params = SnappiTestParams()
    snappi_config, snappi_obj_handles, tx_ports, rx_ports = _build_unisolation_config(
        duthosts, get_snappi_ports, create_snappi_config, snappi_extra_params,
        ip_version, frame_rate, frame_size,
    )
    dut_obj = snappi_extra_params.unisolation_device

    def disrupt():
        check_bgp_state(snappi_api, ip_version)
        check_learned_routes_in_dut(duthosts, ip_version, rx_ports, ROUTE_RANGES)
        logger.info("Starting {} test".format(event_type))
        start_stop(snappi_api, operation="start", op_type="traffic")
        flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
        pytest_assert(int(flow_stats[0].loss) == 0, "Loss Observed in {} before {} on DUT {}".
                      format(flow_stats[0].name, event_type, dut_obj.hostname))
        logger.info("No Loss observed before {} on DUT {}".format(event_type, dut_obj.hostname))
        logger.info("Restarting bgp container on DUT {}".format(dut_obj.hostname))
        restart_output = dut_obj.command("sudo systemctl restart bgp \n")['stderr']
        pytest_assert('Error' not in restart_output,
                      'Error while restarting bgp container in {} !!!!!'.format(dut_obj.hostname))

    def cleanup():
        logger.info("Finally Block Execution...")
        all_ports_startup(dut_obj)

    run_bgp_convergence_event(
        snappi_api, snappi_config, db_reporter, snappi_extra_params,
        ip_version, event_type, METRIC_DESCRIPTION,
        disrupt=disrupt, cleanup=cleanup, cleanup_first=True,
        convergence="rate_within", converge_timeout=300,
        rate_varying_msg="Total Tx Rx Rates are varying by more than 0.1 percent after {} on DUT {}".
        format(event_type, dut_obj.hostname),
    )
