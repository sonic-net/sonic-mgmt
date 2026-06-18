import random
import time
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_interface_details, create_snappi_config, \
    get_snappi_stats, set_primary_chassis, create_traffic_items, start_stop, wait_with_message, \
    dutconfig_checkpoint, _block_egress, _unblock_egress, _get_original_scheduler  # noqa: F401, F403, F405
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import (
    enable_ecn,
    disable_packet_aging,
    config_capture_pkt,
)

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"
FRAME_SIZE = 1024


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def port_groups(duthosts, get_snappi_ports):
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(
        len(snappi_ports) >= 2,
        "Need at least 2 snappi ports for the test",
    )
    return [snappi_ports[i: i + 2] for i in range(0, len(snappi_ports) - 1, 2)]


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossless_prio", [0])
def test_ecn_marking_lossless_queue(
    duthosts,
    snappi_api,
    get_snappi_ports,
    set_primary_chassis,  # noqa: F811
    create_snappi_config,  # noqa: F811
    subnet_type,
    lossless_prio,
    port_groups,
    fanout_graph_facts_multidut,
):
    """ECN marking at egress using lossless queue scheduler blocking.

    Blocks the egress queue with a near-zero-rate scheduler so packets
    accumulate past kmax, then verifies:
    - >95% packet loss while the queue is blocked.
    - The first packet released from the full buffer is ECN-marked.
    - The last captured packet (queue nearly empty) is not ECN-marked.
    """
    snappi_extra_params = SnappiTestParams()

    for snappi_ports in port_groups:
        logger.info("Snappi ports: Tx=%s  Rx=%s",
                    snappi_ports[0]["peer_port"], snappi_ports[1]["peer_port"])

        tx_ports = [snappi_ports[0]]
        rx_ports = [snappi_ports[1]]
        egress_duthost = rx_ports[0]["duthost"]
        egress_port = rx_ports[0]["peer_port"]

        # --- DUT config sanity ---
        config_facts = egress_duthost.config_facts(
            host=egress_duthost.hostname, source="running"
        )["ansible_facts"]
        pytest_assert(
            "DSCP_TO_TC_MAP" in config_facts,
            "DSCP_TO_TC_MAP is not configured on the DUT",
        )
        pytest_assert(
            str(lossless_prio) in config_facts["DSCP_TO_TC_MAP"]["AZURE"].values(),
            f"Lossless priority {lossless_prio} is not mapped to any DSCP in DSCP_TO_TC_MAP",
        )
        dscp_values = [
            int(dscp)
            for dscp, tc in config_facts["DSCP_TO_TC_MAP"]["AZURE"].items()
            if int(tc) == lossless_prio
        ]

        # --- ECN setup ---
        disable_packet_aging(egress_duthost)
        pytest_assert(
            enable_ecn(host_ans=egress_duthost, prio=lossless_prio),
            "Unable to enable ECN on DUT",
        )

        # --- Block egress; send 2x kmax packets so the buffer fills well past kmax ---
        original_scheduler = _get_original_scheduler(egress_duthost, egress_port, lossless_prio)
        _block_egress(egress_duthost, egress_port, lossless_prio)

        wred_profile = config_facts.get("WRED_PROFILE", {}).get("AZURE_LOSSLESS", {})
        pytest_assert(wred_profile, "WRED profile AZURE_LOSSLESS not found in config_facts")
        kmax = int(wred_profile["green_max_threshold"])
        fixed_packet_count = 2 * (kmax // FRAME_SIZE)

        # --- Build snappi config ---
        snappi_extra_params.protocol_config = {
            "Tx": {
                "protocol_type": "ip",
                "ports": tx_ports,
                "subnet_type": subnet_type,
                "is_rdma": True,
            },
            "Rx": {
                "protocol_type": "ip",
                "ports": rx_ports,
                "subnet_type": subnet_type,
                "is_rdma": True,
            },
        }
        config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
        snappi_extra_params.traffic_flow_config = [
            {
                "line_rate": 100,
                "frame_size": FRAME_SIZE,
                "is_rdma": True,
                "flow_name": "ECN_scheduler_block",
                "tx_names": snappi_obj_handles["Tx"]["ip"],
                "rx_names": snappi_obj_handles["Rx"]["ip"],
                "traffic_duration_fixed_packets": fixed_packet_count,
                "prio": lossless_prio,
                "dscp_value": random.choice(dscp_values),
            }
        ]
        config = create_traffic_items(config, snappi_extra_params)

        pcap_file = "ECN_lossless_queue"
        pcap_ports = ["Port_2"]
        config_capture_pkt(
            testbed_config=config,
            port_names=pcap_ports,
            capture_type=packet_capture.IP_CAPTURE,
            capture_name=pcap_file,
        )
        snappi_api.set_config(config)

        # --- Start protocols and traffic ---
        start_stop(snappi_api, operation="start", op_type="protocols")
        wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)

        ixnet = snappi_api._ixnetwork
        traffic_item = ixnet.Traffic.TrafficItem.find()
        rx_vport = ixnet.Vport.find(Name=pcap_ports[0])
        rx_vport.Capture.ControlSliceSize = 32
        rx_vport.Capture.SliceSize = 32

        cs = snappi_api.control_state()
        cs.port.capture.port_names = pcap_ports
        cs.port.capture.state = cs.port.capture.START
        snappi_api.set_control_state(cs)
        wait(5, "To start capture")

        ts = snappi_api.control_state()
        ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
        snappi_api.set_control_state(ts)
        wait(30, "For traffic to fill the queue")

        get_stats(
            snappi_api, "Traffic Item Statistics",
            ["frames_tx", "frames_rx", "loss", "frames_tx_rate", "frames_rx_rate"],
            "print",
        )

        # --- Verify blocking loss ---
        ti_stats = StatViewAssistant(ixnet, "Traffic Item Statistics")
        pytest_assert(
            int(float(ti_stats.Rows[0]["Loss %"])) > 95,
            "Loss must be observed when egress queue is blocked",
        )
        leaked_frame_count = int(ti_stats.Rows[0]["Rx Frames"])

        # --- Unblock egress so buffered packets drain ---
        _unblock_egress(egress_duthost, egress_port, lossless_prio, original_scheduler)

        # --- Stop capture and retrieve pcap ---
        cap_req = snappi_api.capture_request()
        cap_req.port_name = pcap_ports[0]
        cs = snappi_api.control_state()
        cs.port.capture.state = cs.port.capture.STOP
        snappi_api.set_control_state(cs)
        wait(20, "To stop capture")

        pcap_bytes = snappi_api.get_capture(cap_req)
        pcap_path = f"{pcap_file}.pcapng"
        with open(pcap_path, "wb") as fh:
            fh.write(pcap_bytes.getvalue())

        # --- ECN assertions ---
        ip_pkts = get_ipv4_pkts(pcap_path)
        logger.info("Total packets captured: %d", len(ip_pkts))
        pytest_assert(len(ip_pkts) > 0, "No IPv4 packets were captured")

        marked_count = sum(1 for pkt in ip_pkts if is_ecn_marked(pkt))
        pytest_assert(marked_count > 0, "No packets are ECN marked")
        logger.info("ECN marked: %d / %d (%.1f%%)",
                    marked_count, len(ip_pkts), marked_count / len(ip_pkts) * 100)

        pytest_assert(
            is_ecn_marked(ip_pkts[leaked_frame_count - 1]),
            "The first packet released from a full buffer should be ECN marked",
        )
        pytest_assert(
            not is_ecn_marked(ip_pkts[-1]),
            "The last captured packet (queue draining) should not be ECN marked",
        )

        traffic_item.StopStatelessTrafficBlocking()
