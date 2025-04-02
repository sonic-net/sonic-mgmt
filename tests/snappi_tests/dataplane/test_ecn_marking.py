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
    create_traffic_items,
)
from tests.common.snappi_tests.read_pcap import get_ipv4_pkts
from tests.common.snappi_tests.common_helpers import packet_capture, config_capture_pkt
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict

pytestmark = [pytest.mark.topology("tgen")]
logger = logging.getLogger(__name__)


def test_ecn_marking(
    duthost,
    snappi_api,                   # noqa: F811
    get_snappi_ports,             # noqa: F811
    setup_snappi_port_configs,    # noqa: F811
    fanout_graph_facts_multidut,
):
    """
    Test to check if packets get dropped on injecting fec errors
    Note: fanout_per_port is the number of fanouts per fron panel port
          Example: For running the test on 400g fanout mode of a 800g port,
          fanout_per_port is 2
    """
    snappi_extra_params = SnappiTestParams()
    snappi_ports = get_snappi_ports
    snappi_ports = setup_snappi_port_configs
    tx_ports = setup_snappi_port_configs[1:3]
    rx_ports = [setup_snappi_port_configs[3]]
    config, tx_names, rx_names = create_snappi_config(
        snappi_api, tx_ports, rx_ports, is_rdma=True
    )
    api = snappi_api
    for tx_name in tx_names:
        config = create_traffic_items(
            config, tx_name, rx_names[0], line_rate=55, is_rdma=True
        )
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
    logger.info(
        "Dumping Traffic Item statistics :\n {}".format(
            tabulate(get_ti_stats(ixnetwork), headers="keys", tablefmt="psql")
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
    wait(20, "ecc ")
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
    # Check if the first packet is ECN marked
    pytest_assert(is_ecn_marked(ip_pkts[0]), "The first packet should be marked")
    # Check if the last packet is not ECN marked
    pytest_assert(
        not is_ecn_marked(ip_pkts[-1]), "The last packet should not be marked"
    )
