from tests.snappi_tests.dataplane.imports import *  # noqa: F401
from tests.common.snappi_tests.common_helpers import (
    get_addrs_in_subnet,
    get_peer_snappi_chassis,
    get_other_hosts_from_ipv6_host,
)
from snappi_tests.dataplane.files.helper import (
    create_snappi_config,
    create_traffic_items,
    set_primary_chassis,
    create_snappi_l1config,
    get_duthost_bgp_details,
)  # noqa: F401


pytestmark = [pytest.mark.topology("tgen")]
logger = logging.getLogger(__name__)
TIMEOUT = 30
# Mention the details of the port that needs to be flapped and the corresponding BT0 device
FLAP_DETAILS = {"device_name": "sonic-s6100-dut1", "port_name": "Ethernet18"}
ROUTE_RANGES = {
    "IPv6": [["5000::1", 64, 2500], ["4000::1", 64, 2500]],
    "IPv4": [['100.1.1.1', 24, 2500], ['200.1.1.1', 24, 2500]]
}


@pytest.mark.parametrize("subnet_type", ["IPv6"])
def test_bgp_sessions(
    duthosts,
    snappi_api,
    get_snappi_ports,
    fanout_graph_facts_multidut,
    set_primary_chassis,
    create_snappi_l1config,
    subnet_type,
    tbinfo,
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
    snappi_ports = get_duthost_bgp_details(duthosts, get_snappi_ports, subnet_type)
    tx_ports = [snappi_ports[0]]
    rx_ports = snappi_ports[1:]
    snappi_config = create_snappi_l1config
    snappi_extra_params.protocol_config = {
        "Tx": {"network_group": False, "protocol_type": "bgp", "ports": tx_ports,
               "subnet_type": subnet_type, 'is_rdma': False},
        "Rx": {"network_group": True, "route_ranges": ROUTE_RANGES[subnet_type], "protocol_type": "bgp",
               "ports": rx_ports, "subnet_type": subnet_type, 'is_rdma': False},
    }
    snappi_config, snappi_obj_handles = create_snappi_config(snappi_config, snappi_extra_params)
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": 90,
            "frame_size": 1024,
            "is_rdma": False,
            "flow_name": "bgp_traffic",
            "tx_names": snappi_obj_handles["Tx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["network_group"],
        },
    ]
    snappi_config = create_traffic_items(snappi_config, snappi_extra_params)
    get_pkt_loss_duration(duthosts, snappi_api, snappi_config, tx_ports, rx_ports, subnet_type)


def check_bgp_state(snappi_api, type):
    req = snappi_api.metrics_request()
    if type == "bgpv4":
        req.bgpv4.peer_names = []
        bgpv4_metrics = snappi_api.get_metrics(req).bgpv4_metrics
        assert bgpv4_metrics[-1].session_state == "up", "BGP v4 Session State is not UP"
        logger.info("BGP v4 Session State is UP")
    elif type == "bgpv6":
        req.bgpv6.peer_names = []
        bgpv6_metrics = snappi_api.get_metrics(req).bgpv6_metrics
        assert bgpv6_metrics[-1].session_state == "up", "BGP v6 Session State is not UP"
        logger.info("BGP v6 Session State is UP")


def get_flow_stats(api):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    request = api.metrics_request()
    request.flow.flow_names = []
    return api.get_metrics(request).flow_metrics


def get_port_stats(api):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    request = api.metrics_request()
    return api.get_metrics(request).port_metrics


def get_pkt_loss_duration(duthosts, snappi_api, snappi_config, tx_ports, rx_ports, subnet_type):
    """
    Get the packet loss duration
    """
    # snappi_config.events.cp_events.enable = True
    # snappi_config.events.dp_events.enable = True
    # snappi_config.events.dp_events.rx_rate_threshold = 90/(len(rx_ports)-1)
    try:
        flap_dut_obj = next((dut for dut in duthosts if dut.hostname == FLAP_DETAILS["device_name"]), None)
        snappi_api.set_config(snappi_config)
        logger.info("Starting Protocol")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        if subnet_type == "IPv4":
            check_bgp_state(snappi_api, type="bgpv4")
        elif subnet_type == "IPv6":
            check_bgp_state(snappi_api, type="bgpv6")
        logger.info("Starting Traffic")
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Traffic To start")
        flow_stats = get_flow_stats(snappi_api)
        pytest_assert(int(flow_stats[0].loss) == 0, f"Loss Observed in {flow_stats[0].name} before link Flap")

        # flap one link from BT0 side
        logger.info(
            " Shutting down {} port of {} dut !!".format(FLAP_DETAILS["port_name"], FLAP_DETAILS["device_name"])
        )
        flap_dut_obj.command("sudo config interface shutdown {} \n".format(FLAP_DETAILS["port_name"]))
        # calculate pld
        wait(TIMEOUT, "For statistics to be collected")
        flow_stats = get_flow_stats(snappi_api)
        pytest_assert(
            int(flow_stats[0].frames_tx_rate) == int(flow_stats[0].frames_rx_rate),
            f"Tx Rx Rates are not equal after link flap",
        )
        delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / flow_stats[0].frames_tx_rate)
        logger.info("Delta Frames : {}".format(delta_frames))
        pytest_assert(int(delta_frames) != 0, "Delta Frames is 0 after flap, which means no packet drop occurred")
        logger.info("PACKET LOSS DURATION After Link Up (ms): {}".format(pkt_loss_duration))
        logger.info(" Starting up {} port of {} dut !!".format(FLAP_DETAILS["port_name"], FLAP_DETAILS["device_name"]))
        flap_dut_obj.command("sudo config interface startup {} \n".format(FLAP_DETAILS["port_name"]))
    except Exception as e:
        logger.error("Error during packet loss duration calculation: {}".format(e))
        pytest.fail("Test failed due to exception: {}".format(e))
    finally:
        logger.info(" Starting up {} port of {} dut !!".format(FLAP_DETAILS["port_name"], FLAP_DETAILS["device_name"]))
        flap_dut_obj.command("sudo config interface startup {} \n".format(FLAP_DETAILS["port_name"]))
