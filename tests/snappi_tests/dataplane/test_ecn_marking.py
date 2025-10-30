from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_vlan_details, create_snappi_config, \
    get_snappi_stats, set_primary_chassis, create_traffic_items  # noqa: F401, F403, F405, E402

pytestmark = [pytest.mark.topology("tgen")]
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
    Test to check if packets get dropped on injecting fec errors
    Note: fanout_per_port is the number of fanouts per fron panel port
          Example: For running the test on 400g fanout mode of a 800g port,
          fanout_per_port is 2
    """
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_duthost_vlan_details(duthosts, get_snappi_ports)
    pytest_assert(len(snappi_ports) >= 3, "Not enough ports for the test, Need at least 3 ports")
    tx_ports = snappi_ports[:2]
    rx_ports = [snappi_ports[2]]
    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "vlan", "ports": tx_ports,
               "subnet_type": subnet_type, 'is_rdma': True},
        "Rx": {"protocol_type": "vlan",
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
        },
    ]
    config = create_traffic_items(config, snappi_extra_params)
    api.set_config(config)
    packet_capture_file = "ECN_capture"
    logger.info("Packet capture file: {}.pcapng".format(packet_capture_file))
    packet_capture_ports = [config.ports[-1].name]
    config_capture_pkt(
        testbed_config=config,
        port_names=packet_capture_ports,
        capture_type=packet_capture.IP_CAPTURE,
        capture_name=packet_capture_file,
    )

    ixnetwork = api._ixnetwork
    ixnetwork.Vport.find(Name=packet_capture_ports[0]).Capture.HardwareEnabled = True
    ixnetwork.Vport.find(Name=packet_capture_ports[0]).Capture.SoftwareEnabled = True
    ixnetwork.Vport.find(Name=packet_capture_ports[0]).Capture.CaptureMode = (
        "captureContinuousMode"
    )
    ixnet_ports = ixnetwork.Vport.find()
    for port in ixnet_ports:
        port.Type = "aresOneMFcoe"
        port.L1Config.AresOneM.Fcoe.PfcQueueGroups = [
            pfcQueueValueDict[key] for key in pfcQueueValueDict
        ]
    logger.info("Starting All protocols")
    ixnetwork.StartAllProtocols()
    wait(10, "For Protocols To start")
    trafficItem = ixnetwork.Traffic.TrafficItem.find()
    for ti in trafficItem:
        ti.ConfigElement.find()[0].TransmissionControl.Type = "fixedDuration"
        ti.ConfigElement.find()[0].TransmissionControl.Duration = 5
    logger.info("Starting packet capture ...")
    cs = api.control_state()
    cs.port.capture.port_names = packet_capture_ports
    cs.port.capture.state = cs.port.capture.START
    api.set_control_state(cs)
    wait(5, "To start capture")

    logger.info("Starting transmit on all flows ...")
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    api.set_control_state(ts)
    wait(10, "To send traffic")
    logger.info("\n")
    logger.info(
        tabulate(
            get_snappi_stats(
                ixnetwork,
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
    logger.info("Stopping transmit on all flows ...")
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
    api.set_control_state(ts)
    wait(20, "To stop traffic")
    logger.info("Stopping packet capture ...")
    request = api.capture_request()
    request.port_name = packet_capture_ports[0]
    wait(20, "To stop capture")
    cs = api.control_state()
    cs.port.capture.state = cs.port.capture.STOP
    api.set_control_state(cs)
    logger.info(
        "Retrieving and saving packet capture to {}.pcapng".format(packet_capture_file)
    )
    wait(20, "To load capture")
    pcap_bytes = api.get_capture(request)
    with open(packet_capture_file + ".pcapng", "wb") as fid:
        fid.write(pcap_bytes.getvalue())

    # packet_capture_file = "Rx_0 - Data"
    ip_pkts = get_ipv4_pkts(packet_capture_file + ".pcapng")
    count = 0
    for pkt in ip_pkts:
        if is_ecn_marked(pkt):
            count += 1
    logger.info("Total packets Captured: {}".format(len(ip_pkts)))
    logger.info("Total packets marked: {}".format(count))
    logger.info("Percentage of packets marked: {}".format(count / len(ip_pkts) * 100))
    # Check if the first packet is ECN marked
    pytest_assert(is_ecn_marked(ip_pkts[0]), "The first packet should be marked")
    # Check if the last packet is not ECN marked
    pytest_assert(
        not is_ecn_marked(ip_pkts[-1]), "The last packet should not be marked"
    )
