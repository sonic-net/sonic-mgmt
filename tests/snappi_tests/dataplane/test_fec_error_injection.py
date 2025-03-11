from tests.snappi_tests.dataplane.imports import *  # noqa: F401
from tests.common.snappi_tests.snappi_helpers import (
    wait_for_arp,
    fetch_snappi_flow_metrics,
)  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import (
    snappi_api_serv_ip,
    snappi_api_serv_port,
    snappi_api,
    get_snappi_ports,
    is_snappi_multidut,
    get_snappi_ports_single_dut,
    get_snappi_ports_multi_dut,
    snappi_dut_base_config,
)  # noqa: F401
from snappi_tests.dataplane.files.helper import (
    setup_snappi_port_configs,
    get_ti_stats,
    get_fanout_port_groups,
    create_snappi_config,
)

pytestmark = [pytest.mark.topology("tgen")]
logger = logging.getLogger(__name__)

fanout_per_port = 8
ErrorTypes = [
    "codeWords",
    "laneMarkers",
    "minConsecutiveUncorrectableWithLossOfLink",
    "maxConsecutiveUncorrectableWithoutLossOfLink",
]


@pytest.mark.parametrize("fanout_per_port", [2])
@pytest.mark.parametrize("error_type", ErrorTypes)
def test_fec_error_injection(
    duthost,
    snappi_api,
    get_snappi_ports,
    setup_snappi_port_configs,
    fanout_graph_facts_multidut,
    fanout_per_port,
    error_type,
):
    """
    Test to check if packets get dropped on injecting fec errors
    Note: fanout_per_port is the number of fanouts per fron panel port
          Example: For running the test on 400g fanout mode of a 800g port,
          fanout_per_port is 2
    Note: Not supported for speed mode 8x100G
    """
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_snappi_ports
    snappi_ports = setup_snappi_port_configs
    fanout_port_group_list = get_fanout_port_groups(snappi_ports, fanout_per_port)
    for iteration, fanout_port_group in enumerate(fanout_port_group_list):
        logger.info("|----------------------------------------|")
        logger.info("\t\tIteration: {} \n".format(iteration + 1))
        logger.info("Using Fanout Ports :-")
        logger.info("\n")
        for port in fanout_port_group:
            logger.info(
                port["peer_port"]
                + " : "
                + port["location"]
                + " : "
                + port["snappi_speed_type"]
            )
        logger.info("|----------------------------------------|\n")
        snappi_config = create_snappi_config(snappi_api, fanout_port_group)
        snappi_api.set_config(snappi_config)
        ixnet = snappi_api._ixnetwork
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)
        logger.info("\n")
        tx_ports = []
        ixnet_ports = ixnet.Vport.find()
        for port in ixnet_ports:
            port_name = port.Name
            if "Tx" in port_name:
                tx_ports.append(port)
        logger.info(
            "Setting FEC Error Type to : {} on Snappi ports :-".format(error_type)
        )
        for port in tx_ports:
            port.L1Config.FecErrorInsertion.ErrorType = error_type
            logger.info(port.Name)
            if error_type == "codeWords":
                port.L1Config.FecErrorInsertion.PerCodeword = 16
            port.L1Config.FecErrorInsertion.Continuous = True
        wait(10, "To apply fec setting on the port")
        logger.info("Starting Traffic ...")
        ts = snappi_api.control_state()
        ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
        snappi_api.set_control_state(ts)
        wait(10, "For traffic to start")
        try:
            logger.info("Starting FEC Error Insertion")
            [port.StartFecErrorInsertion() for port in tx_ports]
            wait(15, "For error insertion to start")
            logger.info(
                "Dumping Traffic Item statistics :\n {}".format(
                    tabulate(get_ti_stats(ixnet), headers="keys", tablefmt="psql")
                )
            )
            for snappi_port in tx_ports:
                for port in fanout_port_group:
                    if port["location"] == snappi_port.Location:
                        if (
                            error_type == "minConsecutiveUncorrectableWithLossOfLink"
                            or error_type == "codeWords"
                            or error_type == "laneMarkers"
                        ):
                            pytest_assert(
                                duthost.links_status_down(port["peer_port"]) is True,
                                "FAIL: {} is still up after injecting FEC Error".format(
                                    port["peer_port"]
                                ),
                            )
                            logger.info(
                                "PASS: {} Went down after injecting FEC Error: {}".format(
                                    port["peer_port"], error_type
                                )
                            )
                        elif (
                            error_type == "maxConsecutiveUncorrectableWithoutLossOfLink"
                        ):
                            pytest_assert(
                                duthost.links_status_down(port["peer_port"]) is False,
                                "FAIL: {} went down after injecting FEC Error".format(
                                    port["peer_port"]
                                ),
                            )
                            logger.info(
                                "PASS: {} didn't go down after injecting FEC Error: {}".format(
                                    port["peer_port"], error_type
                                )
                            )
            flow_metrics = fetch_snappi_flow_metrics(snappi_api, ["IPv4 Traffic"])[0]
            pytest_assert(
                flow_metrics.frames_tx > 0 and int(flow_metrics.loss) > 0,
                "FAIL: Rx Port did not drop packets after starting FEC Error Insertion",
            )
            logger.info(
                "PASS : Snappi Rx Port observed packet drop after starting FEC Error Insertion"
            )
            logger.info("Stopping FEC Error Insertion")
            [port.StopFecErrorInsertion() for port in tx_ports]
            wait(20, "For error insertion to stop")
            for snappi_port in tx_ports:
                for port in fanout_port_group:
                    if port["location"] == snappi_port.Location:
                        if (
                            error_type == "minConsecutiveUncorrectableWithLossOfLink"
                            or error_type == "codeWords"
                            or error_type == "laneMarkers"
                        ):
                            pytest_assert(
                                duthost.links_status_down(port["peer_port"]) is False,
                                "FAIL: {} is still down after stopping FEC Error".format(
                                    port["peer_port"]
                                ),
                            )
                            logger.info(
                                "PASS: {} is up after stopping FEC Error injection: {}".format(
                                    port["peer_port"], error_type
                                )
                            )
            ixnet.ClearStats()
            wait(10, "For clear stats operation to complete")
            logger.info(
                "Dumping Traffic Item statistics :\n {}".format(
                    tabulate(get_ti_stats(ixnet), headers="keys", tablefmt="psql")
                )
            )
            flow_metrics = fetch_snappi_flow_metrics(snappi_api, ["IPv4 Traffic"])[0]
            pytest_assert(
                int(flow_metrics.frames_rx_rate) > 0 and int(flow_metrics.loss) == 0,
                "FAIL: Rx Port did not resume receiving packets after stopping FEC Error Insertion",
            )
            logger.info(
                "PASS : Rx Port resumed receiving packets after stopping FEC Error Insertion"
            )
            logger.info("Stopping Traffic ...")
            ts = snappi_api.control_state()
            ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
            snappi_api.set_control_state(ts)
            wait(10, "For traffic to stop")
        finally:
            logger.info("....Finally Block")
            [port.StopFecErrorInsertion() for port in tx_ports]
