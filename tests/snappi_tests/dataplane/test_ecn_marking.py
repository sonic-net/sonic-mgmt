from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helperv2 import get_duthost_interface_details, create_snappi_config, \
    get_snappi_stats, set_primary_chassis, create_traffic_items, start_stop  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)


@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_ecn_marking(
    duthosts,
    snappi_api,                   # noqa: F811
    get_snappi_ports,             # noqa: F811
    set_primary_chassis,   # noqa: F811
    create_snappi_config,    # noqa: F811
    subnet_type,
    fanout_graph_facts_multidut,
):
    """
    Test to check if packets are getting ECN marked on congestion
    """
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports, subnet_type, protocol_type="IP")
    pytest_assert(len(snappi_ports) >= 3, "Not enough ports for the test, Need at least 3 ports")
    tx_ports = snappi_ports[:2]
    rx_ports = [snappi_ports[2]]
    snappi_ports = tx_ports + rx_ports
    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": tx_ports,
               "subnet_type": subnet_type, 'is_rdma': True},
        "Rx": {"protocol_type": "ip",
               "ports": rx_ports, "subnet_type": subnet_type, 'is_rdma': True},
    }
    config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    api = snappi_api
    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": 55,
            "frame_size": 1024,
            "is_rdma": True,
            "flow_name": "Traffic Flow",
            "tx_names": snappi_obj_handles["Tx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["ip"],
            "traffic_duration_fixed_seconds": 10,
        },
    ]
    config = create_traffic_items(config, snappi_extra_params)
    packet_capture_file = "ECN_capture"
    logger.info("Packet capture file: {}.pcapng".format(packet_capture_file))
    packet_capture_ports = ['Port_3']
    config_capture_pkt(
        testbed_config=config,
        port_names=packet_capture_ports,
        capture_type=packet_capture.IP_CAPTURE,
        capture_name=packet_capture_file,
    )
    api.set_config(config)
    logger.info("Starting All protocols")
    start_stop(snappi_api, operation="start", op_type="protocols")
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    # Starting Capture
    logger.info("Starting packet capture ...")
    cs = api.control_state()
    cs.port.capture.port_names = packet_capture_ports
    cs.port.capture.state = cs.port.capture.START
    api.set_control_state(cs)
    wait(5, "To start capture")
    # Starting Traffic
    logger.info("Starting transmit on all flows ...")
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    api.set_control_state(ts)
    wait(60, "For Fixed duration traffic to stop and stats to be generated")
    logger.info("\n")
    logger.info(
        tabulate(
            get_snappi_stats(
                api._ixnetwork,
                "Traffic Item Statistics",
                [
                    'Tx Frames',
                    'Rx Frames',
                    'Frames Delta',
                    'Loss %',
                    'Tx Frame Rate',
                    'Rx Frame Rate'
                ]
            ),
            headers="keys",
            tablefmt="psql"
        )
    )
    # Stopping Capture
    logger.info("Stopping packet capture ...")
    request = api.capture_request()
    request.port_name = packet_capture_ports[0]
    cs = api.control_state()
    cs.port.capture.state = cs.port.capture.STOP
    api.set_control_state(cs)
    wait(20, "To stop capture")
    logger.info(
        "Retrieving and saving packet capture to {}.pcapng".format(packet_capture_file)
    )
    wait(20, "To load capture")
    pcap_bytes = api.get_capture(request)
    with open(packet_capture_file + ".pcapng", "wb") as fid:
        fid.write(pcap_bytes.getvalue())
    # Analyzing captured packets for ECN markings
    ip_pkts = get_ipv4_pkts(packet_capture_file + ".pcapng")
    count = 0
    for pkt in ip_pkts:
        if is_ecn_marked(pkt):
            count += 1
    pytest_assert(count > 0, "No packets are ECN marked")
    logger.info("Total packets Captured: {}".format(len(ip_pkts)))
    logger.info("Total packets marked: {}".format(count))
    logger.info("Percentage of packets marked: {}".format(count / len(ip_pkts) * 100))
    # Check if the first packet is ECN marked
    pytest_assert(is_ecn_marked(ip_pkts[0]), "The first packet should be marked")
    # Check if the last packet is not ECN marked
    pytest_assert(
        not is_ecn_marked(ip_pkts[-1]), "The last packet should not be marked"
    )
