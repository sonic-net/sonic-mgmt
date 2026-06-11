import logging
from tests.snappi_tests.dataplane.imports import pytest, pytest_assert, SnappiTestParams  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config  # noqa: F401
from snappi_tests.dataplane.files.helper import (
    start_stop, get_stats, check_bgp_state, get_all_port_names,
    all_ports_startup, all_ports_shutdown, build_bgp_convergence_config,
    run_bgp_convergence_event,
)

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)
TIMEOUT = 20
METRIC_DESCRIPTION = "convergence time-port up/Route Injection event"


@pytest.mark.parametrize("ip_version", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10, 100])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 4096, 8192])
@pytest.mark.parametrize("event_type", ["config_reload", "all_ports_startup", "bgp_container_restart"])
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
    Measure BGP dataplane convergence after a device-level disruption on the T1
    DUT: a config reload, a bulk port startup, or a BGP container restart.
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
        port_split="interleave",
    )
    snappi_extra_params.unisolation_device = next(
        (dut for dut in duthosts if 't1' in dut.hostname), None
    )
    pytest_assert(
        snappi_extra_params.unisolation_device is not None,
        "Failing test as unable to find the unisolation device hostname that contains t1"
    )
    run_convergence_test_for_device_unisolation(
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


def run_convergence_test_for_device_unisolation(
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
    dut_obj = snappi_extra_params.unisolation_device

    def disrupt():
        check_bgp_state(snappi_api, ip_version)
        logger.info("Starting {} test".format(event_type))
        if 'all_ports_startup' not in event_type:
            start_stop(snappi_api, operation="start", op_type="traffic")
            flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
            pytest_assert(int(flow_stats[0].loss) == 0, "Loss Observed in {} before {} on DUT {}".
                          format(flow_stats[0].name, event_type, dut_obj.hostname))
            logger.info("No Loss observed before {} on DUT {}".format(event_type, dut_obj.hostname))
            if event_type == "config_reload":
                logger.info("Reloading config on DUT {}".format(dut_obj.hostname))
                reload_output = dut_obj.command("sudo config reload -f -y \n")['stderr']
                if 'Error' in reload_output:
                    reload_output = dut_obj.command("sudo config reload -y \n")['stderr']
                    pytest_assert('Error' not in reload_output,
                                  'Error while reloading config in {} !!!!!'.format(dut_obj.hostname))
            elif event_type == "bgp_container_restart":
                logger.info("Restarting bgp container on DUT {}".format(dut_obj.hostname))
                restart_output = dut_obj.command("sudo systemctl restart bgp \n")['stderr']
                pytest_assert('Error' not in restart_output,
                              'Error while restarting bgp container in {} !!!!!'.format(dut_obj.hostname))
        elif event_type == "all_ports_startup":
            logger.info('Interface List : {} '.format(get_all_port_names(dut_obj)))
            # Shutdown all ports on DUT before traffic start
            all_ports_shutdown(dut_obj)
            start_stop(snappi_api, operation="start", op_type="traffic")
            # Startup all ports on DUT after traffic start
            all_ports_startup(dut_obj)
        else:
            pytest.fail("Unsupported event type: {}".format(event_type))

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
