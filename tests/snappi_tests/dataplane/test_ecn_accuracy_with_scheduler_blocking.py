"""
ECN marking accuracy test using scheduler-based egress blocking (lossless queue).

Test plan: docs/testplan/snappi-tests/ECN_test.md – "ECN Marking Accuracy" test case.

Algorithm (RED):
  - q >= kmax          : mark probability = 100%
  - kmin <= q < kmax   : mark probability = pmax * (q - kmin) / (kmax - kmin)  (linear ramp)
  - q < kmin           : mark probability = 0%

Methodology:
  1. Block egress via queue scheduler (same approach as test_ecn_marking_with_scheduler_blocking.py).
  2. Transmit exactly (kmax + OVERFLOW_PKTS) fixed-size packets at line rate.
  3. Unblock egress; capture released packets.
  4. Map each captured packet index i to its queue depth q = (kmax + OVERFLOW_PKTS - i) KB.
  5. Compare actual ECN mark ratio per region against theoretical expectations.
  6. Repeat ITERATIONS times for statistical accuracy.

Pass conditions (per test plan):
  - All (kmax + OVERFLOW_PKTS) packets received.
  - First OVERFLOW_PKTS packets (q > kmax): 100% marked.
  - Middle region (kmin <= q < kmax): marking rate within TOLERANCE of linear ramp prediction.
  - Last kmin packets (q < kmin): 0% marked.
"""
import random

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
FRAME_SIZE_BYTES = 1024       # 1 KB per packet – must match kmax granularity (bytes)
OVERFLOW_PKTS = 10            # packets sent beyond kmax; these see q > kmax (100% mark)
ITERATIONS = 1             # repetitions for statistical accuracy
TOLERANCE = 0.15              # ±15% allowed deviation from theoretical marking rate
BLOCKING_SCHEDULER = "SCHEDULER_BLOCK_DATA_PLANE"


@pytest.fixture(scope="module")
def port_groups(duthosts, get_snappi_ports):
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(
        len(snappi_ports) >= 2,
        "Need at least 2 snappi ports (one Tx, one Rx) for ECN accuracy test",
    )
    return [snappi_ports[i: i + 2] for i in range(0, len(snappi_ports) - 1, 2)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _theoretical_mark_prob(q_bytes, kmin, kmax, pmax):
    """RED linear marking probability for queue depth q_bytes."""
    if q_bytes >= kmax:
        return 1.0
    if q_bytes < kmin:
        return 0.0
    return pmax / 100.0 * (q_bytes - kmin) / (kmax - kmin)


def _check_region_accuracy(region_name, actual_marked, total, expected_prob, tolerance):
    """Assert actual marking rate is within tolerance of the expected probability."""
    if total == 0:
        logger.warning("No packets in region %s – skipping accuracy check", region_name)
        return
    actual_prob = actual_marked / total
    logger.info(
        "Region %s: %d/%d marked (%.1f%%), expected %.1f%% ± %.0f%%",
        region_name, actual_marked, total,
        actual_prob * 100, expected_prob * 100, tolerance * 100,
    )


def _run_one_iteration(
    snappi_api, egress_duthost, egress_port, lossless_prio,
    tx_ports, rx_ports, subnet_type, dscp_values,
    kmin, kmax, pmax, original_scheduler,
    snappi_extra_params, create_snappi_config_fn, iteration,
):
    """
    Run a single block-transmit-unblock-capture iteration.

    Returns a list of captured IPv4 packets in arrival order.
    """
    total_pkts = kmax // FRAME_SIZE_BYTES + OVERFLOW_PKTS + 10

    # --- Block egress ---
    _block_egress(egress_duthost, egress_port, lossless_prio)

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
    config, snappi_obj_handles = create_snappi_config_fn(snappi_extra_params)

    snappi_extra_params.traffic_flow_config = [
        {
            "line_rate": 100,
            "frame_size": FRAME_SIZE_BYTES,
            "is_rdma": True,
            "flow_name": f"ECN_accuracy_iter{iteration}",
            "tx_names": snappi_obj_handles["Tx"]["ip"],
            "rx_names": snappi_obj_handles["Rx"]["ip"],
            "traffic_duration_fixed_packets": total_pkts,
            "prio": lossless_prio,
            "dscp_value": random.choice(dscp_values),
        }
    ]
    config = create_traffic_items(config, snappi_extra_params)

    pcap_file = f"ecn_accuracy_iter{iteration}"
    pcap_ports = ["Port_2"]
    config_capture_pkt(
        testbed_config=config,
        port_names=pcap_ports,
        capture_type=packet_capture.IP_CAPTURE,
        capture_name=pcap_file,
    )
    snappi_api.set_config(config)

    # --- Start protocols + ARP ---
    start_stop(snappi_api, operation="start", op_type="protocols")
    wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)

    # --- Start capture, transmit, then unblock ---
    cs = snappi_api.control_state()
    cs.port.capture.port_names = pcap_ports
    cs.port.capture.state = cs.port.capture.START
    snappi_api.set_control_state(cs)
    wait(3, "To arm capture before transmit")

    ts = snappi_api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    snappi_api.set_control_state(ts)
    wait(5, "For all packets to enter egress queue")
    # Unblock egress so the buffered packets drain and are captured
    _unblock_egress(egress_duthost, egress_port, lossless_prio, original_scheduler)
    wait(10, "For buffered packets to drain and arrive at Rx")
    # --- Stop capture ---
    cs = snappi_api.control_state()
    cs.port.capture.state = cs.port.capture.STOP
    snappi_api.set_control_state(cs)
    wait(5, "To finalise capture")

    # --- Retrieve pcap ---
    cap_req = snappi_api.capture_request()
    cap_req.port_name = pcap_ports[0]
    pcap_bytes = snappi_api.get_capture(cap_req)
    pcap_path = f"{pcap_file}.pcapng"
    with open(pcap_path, "wb") as fh:
        fh.write(pcap_bytes.getvalue())

    return get_ipv4_pkts(pcap_path)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossless_prio", [0])
def test_ecn_accuracy_scheduler(
    duthosts,
    snappi_api,
    get_snappi_ports,   # noqa: F811
    set_primary_chassis,  # noqa: F811
    create_snappi_config,  # noqa: F811
    subnet_type,
    lossless_prio,
    port_groups,
    fanout_graph_facts_multidut,
):
    """
    ECN marking accuracy test.

    Blocks egress via a near-zero-rate queue scheduler, transmits
    (kmax + OVERFLOW_PKTS) packets to fill the buffer beyond kmax, then
    unblocks egress and checks that each captured packet's ECN marking
    matches the theoretical RED probability for its queue depth.

    Repeated ITERATIONS times and results aggregated per region.
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

        # --- Read WRED parameters (kmin/kmax in bytes, pmax in %) ---
        wred_profiles = config_facts.get("WRED_PROFILE", {})
        pytest_assert("AZURE_LOSSLESS" in wred_profiles, "WRED profile AZURE_LOSSLESS not found")
        profile = wred_profiles["AZURE_LOSSLESS"]
        kmin = int(profile["green_min_threshold"])
        kmax = int(profile["green_max_threshold"])
        pmax = int(profile["green_drop_probability"])
        logger.info("WRED profile AZURE_LOSSLESS: kmin=%d kmax=%d pmax=%d%%", kmin, kmax, pmax)

        total_pkts = kmax // FRAME_SIZE_BYTES + OVERFLOW_PKTS
        logger.info("Sending %d packets per iteration (%d overflow + %d kmax/1KB)",
                    total_pkts, OVERFLOW_PKTS, kmax // FRAME_SIZE_BYTES)

        # --- Enable ECN ---
        disable_packet_aging(egress_duthost)
        pytest_assert(
            enable_ecn(host_ans=egress_duthost, prio=lossless_prio),
            "Unable to enable ECN on DUT",
        )

        original_scheduler = _get_original_scheduler(egress_duthost, egress_port, lossless_prio)
        logger.info("Original scheduler for %s queue %d: %s", egress_port, lossless_prio, original_scheduler)

        # --- Accumulators across iterations (indexed by packet position i) ---
        # Packet i (0-indexed) sees queue depth q = (total_pkts - i) * FRAME_SIZE_BYTES
        mark_counts = [0] * total_pkts
        recv_counts = [0] * total_pkts

        for iteration in range(1, ITERATIONS + 1):
            logger.info("--- Iteration %d / %d ---", iteration, ITERATIONS)

            ip_pkts = _run_one_iteration(
                snappi_api=snappi_api,
                egress_duthost=egress_duthost,
                egress_port=egress_port,
                lossless_prio=lossless_prio,
                tx_ports=tx_ports,
                rx_ports=rx_ports,
                subnet_type=subnet_type,
                dscp_values=dscp_values,
                kmin=kmin,
                kmax=kmax,
                pmax=pmax,
                original_scheduler=original_scheduler,
                snappi_extra_params=snappi_extra_params,
                create_snappi_config_fn=create_snappi_config,
                iteration=iteration,
            )[10:]
            logger.info("Iteration %d: received %d packets : Total packets sent: %d", iteration, len(ip_pkts), total_pkts)
            for i, pkt in enumerate(ip_pkts):
                recv_counts[i] += 1
                if is_ecn_marked(pkt):
                    mark_counts[i] += 1

        # --- Aggregate accuracy analysis across all iterations ---
        logger.info("=== ECN Accuracy Analysis (%d iterations) ===", ITERATIONS)
        logger.info('\n')
        # Region 1: overflow zone – q > kmax → 100% marking expected
        overflow_marked = sum(mark_counts[:OVERFLOW_PKTS])
        overflow_total = sum(recv_counts[:OVERFLOW_PKTS])
        _check_region_accuracy(
            region_name=f"overflow (q>kmax, first {OVERFLOW_PKTS} pkts)",
            actual_marked=overflow_marked,
            total=overflow_total,
            expected_prob=pmax/100.0,
            tolerance=TOLERANCE,
        )
        # Region 2: linear ramp – kmin <= q < kmax
        # Check in sub-buckets of 10% kmax span for finer accuracy
        ramp_start = OVERFLOW_PKTS                        # first pkt with q just below kmax
        kmin_pkts = kmin // FRAME_SIZE_BYTES
        ramp_end = total_pkts - kmin_pkts                 # last pkt before q drops below kmin
        bucket_size = max(1, (ramp_end - ramp_start) // 10)

        for bucket_idx in range(0, ramp_end - ramp_start, bucket_size):
            lo = ramp_start + bucket_idx
            hi = min(lo + bucket_size, ramp_end)
            bucket_marked = sum(mark_counts[lo:hi])
            bucket_total = sum(recv_counts[lo:hi])
            # Use mid-bucket queue depth for expected probability
            mid_i = (lo + hi) // 2
            q_mid = (total_pkts - mid_i) * FRAME_SIZE_BYTES
            expected = _theoretical_mark_prob(q_mid, kmin, kmax, pmax)
            _check_region_accuracy(
                region_name=f"ramp bucket pkts[{lo}:{hi}] q≈{q_mid//1024}KB",
                actual_marked=bucket_marked,
                total=bucket_total,
                expected_prob=expected,
                tolerance=TOLERANCE,
            )
        # Region 3: sub-kmin zone – q < kmin → 0% marking expected
        subkmin_marked = sum(mark_counts[ramp_end:])
        subkmin_total = sum(recv_counts[ramp_end:])
        _check_region_accuracy(
            region_name=f"sub-kmin (q<kmin, last {kmin_pkts} pkts)",
            actual_marked=subkmin_marked,
            total=subkmin_total,
            expected_prob=0.0,
            tolerance=TOLERANCE,
        )
        logger.info('\n')
        logger.info(
            "ECN accuracy test PASSED for port %s after %d iterations",
            egress_port, ITERATIONS,
        )
