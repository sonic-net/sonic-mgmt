from tests.common.telemetry import (
    UNIT_SECONDS,       # noqa: F401, F403, F405, E402
)
from tests.common.telemetry.constants import (
    METRIC_LABEL_TG_TRAFFIC_RATE,
    METRIC_LABEL_TG_FRAME_BYTES,
)
from tests.snappi_tests.dataplane.imports import *   # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import set_primary_chassis, create_snappi_config, create_traffic_items, \
    get_duthost_interface_details, configure_acl_for_route_withdrawl, start_stop, \
    get_stats, check_bgp_state, is_traffic_converged, wait_for, get_all_port_names, \
    all_ports_startup, all_ports_shutdown   # noqa: F401, F403, F405, E402
METRIC_LABEL_TEST_PARAMS_EVENT_TYPE: Final[str] = "test.params.event_type"
METRIC_LABEL_TEST_PARAMS_ROUTE_SCALE: Final[str] = "test.params.route_scale"
METRIC_LABEL_TEST_PARAMS_PREFIX_LENGTH: Final[str] = "test.params.prefix_length"
METRIC_LABEL_TG_IP_VERSION: Final[str] = "tg.ip_version"
METRIC_NAME_BGP_CONVERGENCE_DATAPLANE_UPDATE_TIME_MS: Final[str] = "bgp.convergence.dataplane.update.time.ms"
pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)
TIMEOUT = 20
# Mention the details of the port that needs to be flapped and the corresponding BT0 device
ROUTE_RANGES = {
    "IPv6": [
        (
            ("777:777:777::1", 64, 5000),
            ("666:666:666::1", 64, 5000)
        )
    ],
    "IPv4": [
        (
            ("100.1.1.1", 24, 5000),
            ("200.1.1.1", 24, 5000)
        )
    ],
}


@pytest.mark.parametrize("subnet_type", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [10])
@pytest.mark.parametrize("frame_size", [64, 128, 256, 512, 1024, 1518])
@pytest.mark.parametrize("event_type", ["config_reload", "all_ports_startup", "bgp_container_restart"])
@pytest.mark.parametrize("unisolation_device_hostname", ['sonic-s6100-dut3'])
def test_bgp_sessions(
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,   # noqa: F811, F401
    create_snappi_config,  # noqa: F811, F401
    subnet_type,
    db_reporter,
    tbinfo,
    frame_rate,
    frame_size,
    event_type,
    unisolation_device_hostname
):
    """
    Test to check if packets get dropped on injecting fec errors
    Note: fanout_per_port is the number of fanouts per fron panel port
          Example: For running the test on 400g fanout mode of a 800g port,
          fanout_per_port is 2
    """
    snappi_extra_params = SnappiTestParams()
    pytest_assert(
        subnet_type in ROUTE_RANGES, "Failing test as no route ranges are provided for {}".format(subnet_type)
    )
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports, subnet_type, protocol_type="bgp")
    tx_ports = snappi_ports[::2]
    rx_ports = snappi_ports[1::2]

    for dut in duthosts:
        if dut.hostname == unisolation_device_hostname:
            snappi_extra_params.unisolation_device = dut
            break
    pytest_assert(
        hasattr(snappi_extra_params, 'unisolation_device'),
        "Failing test as unable to find the unisolation device hostname: {}".format(unisolation_device_hostname)
    )
    snappi_extra_params.protocol_config = {
        "Tx": {
            "protocol_type": "bgp",
            "ports": tx_ports,
            "subnet_type": subnet_type,
            "is_rdma": False,
        },
        "Rx": {
            "route_ranges": ROUTE_RANGES[subnet_type] * len(rx_ports),
            "protocol_type": "bgp",
            "ports": rx_ports,
            "subnet_type": subnet_type,
            "is_rdma": False,
        },
    }
    snappi_config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": frame_rate,
            "frame_size": frame_size,
            "is_rdma": False,
            "flow_name": "bgp_traffic",
            "tx_names": snappi_obj_handles["Tx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["network_group"],
        },
    ]
    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    get_convergence_for_device_unisolation(
        duthosts,
        snappi_api,
        snappi_config,
        tx_ports,
        rx_ports,
        subnet_type,
        snappi_obj_handles,
        event_type,
        db_reporter,
        snappi_extra_params
    )


def get_convergence_for_device_unisolation(
    duthosts,
    snappi_api,
    snappi_config,
    tx_ports,
    rx_ports,
    subnet_type,
    snappi_obj_handles,
    event_type,
    db_reporter,
    snappi_extra_params
):
    """
    Get the packet loss duration
    """
    convergence_dataplane_time = GaugeMetric(METRIC_NAME_BGP_CONVERGENCE_DATAPLANE_UPDATE_TIME_MS,
                                             "convergence time for port up/Route Injection event",
                                             UNIT_SECONDS,
                                             db_reporter)
    dut_obj = snappi_extra_params.unisolation_device
    snappi_api.set_config(snappi_config)
    start_stop(snappi_api, operation="start", op_type="protocols")
    check_bgp_state(snappi_api, subnet_type)
    logger.info('\n')
    logger.info("-------------------------------------")
    logger.info("Starting {} test".format(event_type))
    logger.info("-------------------------------------")
    logger.info('\n')
    try:
        if 'all_ports_startup' not in event_type:
            start_stop(snappi_api, operation="start", op_type="traffic")
            flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
            pytest_assert(int(flow_stats[0].loss) == 0, "Loss Observed in {} before {} on DUT {}".
                          format(flow_stats[0].name, event_type, dut_obj.hostname))
            logger.info("No Loss observed before {} on DUT {}".format(event_type, dut_obj.hostname))
            if event_type == "config_reload":
                # Reload config on DUT
                logger.info("Reloading config on DUT {}".format(dut_obj.hostname))
                reload_output = dut_obj.command("sudo config reload -f -y \n")['stderr']
                if 'Error' in reload_output:
                    reload_output = dut_obj.command("sudo config reload -y \n")['stderr']
                    pytest_assert('Error' not in reload_output['stderr'],
                                  'Error while reloading config in {} !!!!!'
                                  .format(dut_obj.hostname))

            elif event_type == "bgp_container_restart":
                # Restart BGP container
                logger.info("Restarting bgp container on DUT {}".format(dut_obj.hostname))
                dut_obj.command("sudo systemctl restart bgp \n")
                pytest_assert('Error' not in dut_obj.command("sudo systemctl restart bgp \n")['stderr'],
                              'Error while restarting bgp container in {} !!!!!'
                              .format(dut_obj.hostname))

        elif event_type == "all_ports_startup":
            logger.info('Interface List : {} '.format(get_all_port_names(dut_obj)))
            # Shutdown all ports on DUT before traffic start
            all_ports_shutdown(dut_obj)
            # start traffic
            start_stop(snappi_api, operation="start", op_type="traffic")
            # Startup all ports on DUT after traffic start
            all_ports_startup(dut_obj)
        else:
            pytest.fail("Unsupported event type: {}".format(event_type))

        wait_for(
            lambda: is_traffic_converged(snappi_api),
            "Traffic to Converge",
            interval_seconds=10,
            timeout_seconds=300
        )
        flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
        frame_rate_difference = abs(int(flow_stats[0].frames_tx_rate) - int(flow_stats[0].frames_rx_rate))
        logger.info("Frames Tx Rate : {}".format(flow_stats[0].frames_tx_rate))
        logger.info("Frames Rx Rate : {}".format(flow_stats[0].frames_rx_rate))
        logger.info("Frame Rate Difference : {}".format(frame_rate_difference))
        pytest_assert(
            frame_rate_difference <= (0.001 * int(flow_stats[0].frames_tx_rate)),
            "Total Tx Rx Rates are varying by more than 0.1 percent after {} on DUT {}".format(event_type, dut_obj.hostname)
        )
        delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
        logger.info('Traffic has converged after {} on DUT {}'.format(event_type, dut_obj.hostname))
        pkt_loss_duration = 1000 * (delta_frames / flow_stats[0].frames_tx_rate)
        logger.info("Delta Frames : {}".format(delta_frames))
        logger.info('--------------------------   Convergence Numbers   ----------------------------------')
        logger.info("Convergence Time for {} : {} (ms)".format(event_type, pkt_loss_duration))
        logger.info('--------------------------------------------------------------------------------------')
        start_stop(snappi_api, operation="stop", op_type="traffic")
        test_labels = {
            METRIC_LABEL_TEST_PARAMS_EVENT_TYPE: event_type,
            METRIC_LABEL_TEST_PARAMS_ROUTE_SCALE: ROUTE_RANGES[subnet_type][0][0][-1],
            METRIC_LABEL_TG_TRAFFIC_RATE: snappi_extra_params.traffic_flow_config[0]['line_rate'],
            METRIC_LABEL_TG_FRAME_BYTES: snappi_extra_params.traffic_flow_config[0]['frame_size'],
            METRIC_LABEL_TG_IP_VERSION: subnet_type,
        }
        convergence_dataplane_time.record(pkt_loss_duration, test_labels)
        db_reporter.report()
    except Exception as e:
        logger.error("Error during packet loss duration calculation: {}".format(e))
        pytest.fail("Test failed due to exception: {}".format(e))
    finally:
        logger.info("Finally Block Execution...")
        all_ports_startup(dut_obj)
        start_stop(snappi_api, operation="stop", op_type="protocols", waittime=1)
        start_stop(snappi_api, operation="stop", op_type="traffic", waittime=1)
