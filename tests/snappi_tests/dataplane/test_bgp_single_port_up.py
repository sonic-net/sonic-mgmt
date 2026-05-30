from tests.common.telemetry import UNIT_SECONDS       # noqa: F401, F403, F405, E402
from tests.common.telemetry.constants import METRIC_LABEL_TG_TRAFFIC_RATE, \
    METRIC_LABEL_TG_FRAME_BYTES  # noqa: F401, F403, F405, E402
from tests.snappi_tests.dataplane.imports import *  # noqa F403
from snappi_tests.dataplane.files.helper import *  # noqa F403
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
    snappi_extra_params = SnappiTestParams()
    pytest_assert(
        ip_version in ROUTE_RANGES, "Failing test as no route ranges are provided for {}".format(ip_version)
    )
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports, ip_version)
    port_distrbution = (slice(0, len(snappi_ports) // 2), slice(len(snappi_ports) // 2, None))
    tx_ports, rx_ports = snappi_ports[port_distrbution[0]], snappi_ports[port_distrbution[1]]
    snappi_extra_params.FLAP_DETAILS = {
        "device_name": rx_ports[0]['peer_device'],
        "port_name": rx_ports[0]['peer_port'],
    }
    snappi_extra_params.protocol_config = {
        "Tx": {
            "protocol_type": "bgp",
            "ports": tx_ports,
            "subnet_type": ip_version,
            "is_rdma": False,
        },
        "Rx": {
            "route_ranges": ROUTE_RANGES[ip_version] * len(rx_ports),
            "protocol_type": "bgp",
            "ports": rx_ports,
            "subnet_type": ip_version,
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
    convergence_dataplane_time = GaugeMetric(METRIC_NAME_BGP_CONVERGENCE_DATAPLANE_UPDATE_TIME_MS,
                                             "convergence time for port up/Route Injection event",
                                             UNIT_SECONDS,
                                             db_reporter)
    if event_type == "t0_port_startup":
        logger.info("Starting Single Port Flap (Up) Test")
        snappi_api.set_config(snappi_config)
        flap_dut_obj = next(
            (dut for dut in duthosts if dut.hostname == snappi_extra_params.FLAP_DETAILS["device_name"]),
            None
        )
        try:
            start_stop(snappi_api, operation="start", op_type="protocols")
            check_bgp_state(snappi_api, ip_version)
            logger.info(
                "Shutting down {} port of {} dut before starting traffic ".format(
                    snappi_extra_params.FLAP_DETAILS["port_name"],
                    snappi_extra_params.FLAP_DETAILS["device_name"],
                )
            )
            flap_dut_obj.command(
                "sudo config interface shutdown {}\n".format(
                    snappi_extra_params.FLAP_DETAILS["port_name"]
                )
            )
            start_stop(snappi_api, operation="start", op_type="traffic")
            wait(20, "For traffic to stabilize")
            flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
            pytest_assert(int(flow_stats[0].loss) == 0, f"Loss Observed in {flow_stats[0].name} before link Flap Up")
            logger.info(
                "Starting Up {} port of {} dut !!".format(
                    snappi_extra_params.FLAP_DETAILS["port_name"],
                    snappi_extra_params.FLAP_DETAILS["device_name"],
                )
            )
            flap_dut_obj.command(
                "sudo config interface startup {}\n".format(
                    snappi_extra_params.FLAP_DETAILS["port_name"]
                )
            )
            # calculate pld
            wait(20, "For statistics to be collected")
            tmp['port_num'] = tmp['Port'].str.extract(r'(\d+)').astype(int)
            tmp = tmp.sort_values('port_num')
            mid = len(tmp) // 2
            second_half_ports = tmp.iloc[mid:, :]
            # Check if 'Rx Frame Rate' values for Rx ports are greater than atleast 1000
            # to ensure all Rx ports are receiving traffic
            all_close = (second_half_ports['Rx Frame Rate'] > 1000).all()
            pytest_assert(all_close, "Not all Rx ports are having frame rate atleast 1000")
            flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
            delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
            pkt_loss_duration = 1000 * (delta_frames / flow_stats[0].frames_tx_rate)
            logger.info("Delta Frames : {}".format(delta_frames))
            pytest_assert(int(delta_frames) != 0, "Delta Frames is 0 after flap, which means no packet drop occurred")
            pytest_assert(is_traffic_converged(snappi_api), "Traffic did not converge after link down")
            logger.info('Traffic has converged back after link flap Up')
            logger.info('--------------------------   Convergence Numbers   ----------------------------------')
            logger.info("Convergence Time for Single Port Flap Up: {} (ms)".format(pkt_loss_duration))
            logger.info('--------------------------------------------------------------------------------------')
            start_stop(snappi_api, operation="stop", op_type="traffic")
            test_labels = {
                METRIC_LABEL_TEST_PARAMS_EVENT_TYPE: event_type,
                METRIC_LABEL_TEST_PARAMS_ROUTE_SCALE: ROUTE_RANGES[ip_version][0][0][-1],
                METRIC_LABEL_TG_TRAFFIC_RATE: snappi_extra_params.traffic_flow_config[0]['line_rate'],
                METRIC_LABEL_TG_FRAME_BYTES: snappi_extra_params.traffic_flow_config[0]['frame_size'],
                METRIC_LABEL_TG_IP_VERSION: ip_version,
            }
            convergence_dataplane_time.record(pkt_loss_duration, test_labels)
            db_reporter.report()
        except Exception as e:
            logger.error("Error during packet loss duration calculation: {}".format(e))
            pytest.fail("Test failed due to exception: {}".format(e))
        finally:
            start_stop(snappi_api, operation="stop", op_type="protocols", waittime=1)
            start_stop(snappi_api, operation="stop", op_type="traffic", waittime=1)
            logger.info(
                "Starting up {} port of {} dut !!".format(
                    snappi_extra_params.FLAP_DETAILS["port_name"],
                    snappi_extra_params.FLAP_DETAILS["device_name"],
                )
            )
            flap_dut_obj.command(
                "sudo config interface startup {}\n".format(snappi_extra_params.FLAP_DETAILS["port_name"])
            )
    elif event_type == "route_injection":
        logger.info("Starting Single Port (Route Injection) Test")
        dut_obj = rx_ports[0]['duthost']
        table_name = "AI_ACL_TABLE"
        try:
            snappi_api.set_config(snappi_config)
            start_stop(snappi_api, operation="start", op_type="protocols")
            logger.info('\n')
            # Unless we configure acl on the DUT, the packets will not drop on route withdraw
            logger.info("Configuring ACL for packet drop on one of the BGP peer")
            destination_ip_list = [list(item) for item in ROUTE_RANGES[ip_version][0]]
            acl_dict = configure_acl_for_route_withdrawl(destination_ip_list, table_name)
            dut_obj.command("sudo config acl add table {} l3v6".format(json.dumps(acl_dict)))
            logger.info("sudo config acl add table {} l3v6".format(table_name))
            cmd = "sudo config acl add table {} L3v6 -p {} -s egress".format(table_name, rx_ports[1]['peer_port'])
            dut_obj.command(cmd)
            logger.info("sudo config acl add table {} L3v6 -p {} -s egress".
                        format(table_name, rx_ports[1]['peer_port']))
            with open("/tmp/ai_acl.json", 'w') as fp:
                json.dump(acl_dict, fp, indent=4)
            dut_obj.copy(src="/tmp/ai_acl.json", dest="/home/admin/ai_acl.json")
            dut_obj.command("sudo chmod 666 /home/admin/ai_acl.json")
            dut_obj.command("sudo config acl update full \"/home/admin/ai_acl.json\"")
            """ Withdrawing routes from a BGP peer from snappi port """
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
            flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
            delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
            pkt_loss_duration = 1000 * (delta_frames / flow_stats[0].frames_tx_rate)
            logger.info("Delta Frames : {}".format(delta_frames))
            pytest_assert(int(delta_frames) != 0, "Delta Frames is 0 after removing applied acl and route Injection,\
                        which means no packet drop occurred")
            logger.info("PACKET LOSS DURATION After Route Injection (ms): {}".format(pkt_loss_duration))
            pytest_assert(is_traffic_converged(snappi_api), "Traffic did not converge after route injection")
            dut_obj.command("sudo config acl remove table {}".format(table_name))
            logger.info('\n')
            logger.info('--------------------------   Convergence Numbers   ----------------------------------')
            logger.info('Convergence Time for Single Route Injection : {} (ms)'.format(pkt_loss_duration))
            logger.info('Time taken to apply acl and route Injection on snappi port: {} (s)'.
                        format(end_time - start_time))
            logger.info('--------------------------------------------------------------------------------------')
            start_stop(snappi_api, operation="stop", op_type="traffic")
            # Create metrics
            test_labels = {
                METRIC_LABEL_TEST_PARAMS_EVENT_TYPE: event_type,
                METRIC_LABEL_TEST_PARAMS_ROUTE_SCALE: ROUTE_RANGES[ip_version][0][0][-1],
                METRIC_LABEL_TG_TRAFFIC_RATE: snappi_extra_params.traffic_flow_config[0]['line_rate'],
                METRIC_LABEL_TG_FRAME_BYTES: snappi_extra_params.traffic_flow_config[0]['frame_size'],
                METRIC_LABEL_TG_IP_VERSION: ip_version,
            }
            convergence_dataplane_time.record(pkt_loss_duration, test_labels)
            db_reporter.report()
        except Exception as e:
            logger.error("Error during packet loss duration calculation: {}".format(e))
            pytest.fail("Test failed due to exception: {}".format(e))
        finally:
            start_stop(snappi_api, operation="stop", op_type="protocols", waittime=1)
            start_stop(snappi_api, operation="stop", op_type="traffic", waittime=1)
            logger.info("Removing acl table {}".format(table_name))
            dut_obj.command("sudo config acl remove table {}".format(table_name))
