from tests.snappi_tests.dataplane.imports import pytest, SnappiTestParams, wait_for_arp, wait, pytest_assert
from snappi_tests.dataplane.files.helper import get_duthost_bgp_details, create_snappi_config, \
    get_fanout_port_groups, set_primary_chassis, create_traffic_items, start_stop, get_stats    # noqa: F401, F405
import logging
pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)  # noqa: F405

"""
    The following FEC ErrorTypes are the options available for AresOneM in 800G, 400G and 200G speed modes in IxNetwork
    with which the Ports go down when the error is injected or there is packet drop.
    example:
        For codeWords, laneMarkers, minConsecutiveUncorrectableWithLossOfLink link goes down and there is packet drop
        For maxConsecutiveUncorrectableWithoutLossOfLink link does not go down and there is packet drop

    # Note: Need atleast two front panel ports for this test

"""
ErrorTypes = [
    "codeWords",
    "laneMarkers",
    "minConsecutiveUncorrectableWithLossOfLink",
    "maxConsecutiveUncorrectableWithoutLossOfLink",
]
# Example If the speed of the fanout port is 400G on a 800G front panel port then the fanout_per_port is 2
# (because 2 400G fanouts per 800G fron panel port),
# if its 200G then fanout_per_port is 4, if its 100G then fanout_per_port is 8


@pytest.mark.parametrize("fanout_per_port", [2])
@pytest.mark.parametrize("error_type", ErrorTypes)
@pytest.mark.parametrize("subnet_type", ["IPv6"])
@pytest.mark.parametrize("frame_rate", [20])
@pytest.mark.parametrize("frame_size", [1024])
def test_fec_error_injection(
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,   # noqa: F811
    subnet_type,
    create_snappi_config,  # noqa: F811
    fanout_per_port,
    error_type,
    frame_rate,
    frame_size,
):
    """
    Test to check if packets get dropped on injecting fec errors
    Note: fanout_per_port is the number of fanouts per fron panel port
          Example: For running the test on 400g fanout mode of a 800g port,
          fanout_per_port is 2
    Note: Not supported for speed mode 8x100G
    """
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports, subnet_type)
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
        half_ports = int(len(fanout_port_group) / 2)
        Tx_ports = fanout_port_group[:half_ports]
        Rx_ports = fanout_port_group[half_ports:]
        logger.info('Tx Ports: {}'.format([port["peer_port"] for port in Tx_ports]))
        logger.info('Rx Ports: {}'.format([port["peer_port"] for port in Rx_ports]))
        logger.info("\n")
        snappi_extra_params.protocol_config = {
            "Tx": {
                "protocol_type": "bgp",
                "ports": Tx_ports,
                "subnet_type": subnet_type,
                "is_rdma": False,
            },
            "Rx": {
                "protocol_type": "bgp",
                "ports": Rx_ports,
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
                "flow_name": "Traffic Flow",
                "tx_names": snappi_obj_handles["Tx"]["ip"],
                "rx_names": snappi_obj_handles["Rx"]["ip"],
            },
        ]
        snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
        snappi_api.set_config(snappi_config)
        start_stop(snappi_api, operation="start", op_type="protocols")
        columns = ["frames_tx", "frames_rx", "loss", "frames_tx_rate", "frames_rx_rate"]
        ixnet = snappi_api._ixnetwork
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)
        logger.info("\n")
        tx_ports = []
        ixnet_ports = ixnet.Vport.find()
        for port in ixnet_ports:
            for snappi_port in Tx_ports:
                if str(port.Location) == str(snappi_port["location"]):
                    tx_ports.append(port)
        logger.info(
            "Setting FEC Error Type to : {} on Tx Snappi ports :-".format(error_type)
        )
        for port in tx_ports:
            port.L1Config.FecErrorInsertion.ErrorType = error_type
            for snappi_port in fanout_port_group:
                if port.Location == snappi_port["location"]:
                    logger.info('{} --- {}'.format(port.Name, snappi_port["peer_port"]))
            if error_type == "codeWords":
                port.L1Config.FecErrorInsertion.PerCodeword = 16
            port.L1Config.FecErrorInsertion.Continuous = True
        wait(10, "To apply fec setting on the port")
        start_stop(snappi_api, operation="start", op_type="traffic")
        try:
            logger.info("Starting FEC Error Insertion")
            [port.StartFecErrorInsertion() for port in tx_ports]
            wait(15, "For error insertion to start")
            get_stats(snappi_api, "Traffic Item Statistics", columns, 'print')
            for snappi_port in tx_ports:
                for port in fanout_port_group:
                    if port["location"] == snappi_port.Location:
                        if (
                            error_type == "minConsecutiveUncorrectableWithLossOfLink"
                            or error_type == "codeWords"
                            or error_type == "laneMarkers"
                        ):
                            pytest_assert(
                                port["duthost"].links_status_down(port["peer_port"]) is True,
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
                                port["duthost"].links_status_down(port["peer_port"]) is False,
                                "FAIL: {} went down after injecting FEC Error".format(
                                    port["peer_port"]
                                ),
                            )
                            logger.info(
                                "PASS: {} didn't go down after injecting FEC Error: {}".format(
                                    port["peer_port"], error_type
                                )
                            )
            flow_metrics = get_stats(snappi_api, "Traffic Item Statistics")[0]
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
                                port["duthost"].links_status_down(port["peer_port"]) is False,
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
            get_stats(snappi_api, "Traffic Item Statistics", columns, 'print')
            flow_metrics = get_stats(snappi_api, "Traffic Item Statistics")[0]
            pytest_assert(
                int(flow_metrics.frames_rx_rate) > 0 and int(flow_metrics.loss) == 0,
                "FAIL: Rx Port did not resume receiving packets after stopping FEC Error Insertion",
            )
            logger.info(
                "PASS : Rx Port resumed receiving packets after stopping FEC Error Insertion"
            )
            start_stop(snappi_api, operation="stop", op_type="traffic")
        finally:
            logger.info("....Finally Block, Stopping FEC Error Insertion....")
            [port.StopFecErrorInsertion() for port in tx_ports]
