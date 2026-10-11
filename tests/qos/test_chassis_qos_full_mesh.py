"""
Chassis QoS Full Mesh Traffic Test

This module verifies all-ports-to-all-ports (full mesh) connectivity for chassis
switches. Traffic is sent on all priorities (8 unicast queues via DSCP values)
between every combination of port pairs to validate that the underlying Traffic
Manager (TM) programming is correct with no dead ends.

The test verifies that each port in the chassis can reach every other port,
whether on the same or a different line card, ensuring fabric connectivity
works correctly across the system.

Supported topology: t2 (modular chassis)
"""

import json
import logging
import time
import pytest
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.duthost_utils import dut_qos_maps_module  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.disable_loganalyzer,
]

# Number of packets sent per flow (src port x DSCP combination)
PACKET_COUNT = 100
# Time to wait for egress queue counters to settle after sending traffic
QUEUE_SETTLE_TIME_SECS = 2
# Unicast queues that require the ECN bit set in the packet TOS field
ECN_QUEUES = {3, 4}
# IP TTL value used in test packets
PACKET_IP_TTL = 64
# Packet length (bytes) used in test packets
PACKET_LEN = 100


@pytest.fixture(scope='module')
def chassis_port_info(duthosts, tbinfo):
    """
    Gather all PTF-accessible port information from every frontend DUT in the chassis.

    Iterates over every frontend node (line card) and each of its ASICs, collecting
    active Ethernet interfaces that have a PTF port mapping.  Only ports that respond
    to a connectivity check (via ``get_active_ip_interfaces``) are included.

    Returns:
        dict: mapping PTF port index to a dict with keys
            ``peer_ip`` – IP address of the PTF end of the link (used as dst IP),
            ``port_name`` – DUT interface name (e.g. ``'Ethernet0'``),
            ``duthost`` – :class:`MultiAsicSonicHost` instance for this port,
            ``router_mac`` – the DUT's chassis-wide router MAC.
    """
    port_info = {}

    for dut in duthosts.frontend_nodes:
        mg_facts = dut.get_extended_minigraph_facts(tbinfo)
        router_mac = dut.facts.get('router_mac', '')

        for asic in dut.asics:
            active_ips = asic.get_active_ip_interfaces(tbinfo)
            for iface, addr in active_ips.items():
                if not iface.startswith('Ethernet') or 'Ethernet-Rec' in iface:
                    continue
                ptf_port_id = mg_facts['minigraph_ptf_indices'].get(iface)
                if ptf_port_id is None:
                    continue
                port_info[ptf_port_id] = {
                    'peer_ip': addr['peer_ipv4'],
                    'port_name': iface,
                    'duthost': dut,
                    'router_mac': router_mac,
                }

    pytest_assert(
        len(port_info) >= 2,
        "Chassis full mesh test requires at least 2 PTF-accessible ports; "
        "found: {}".format(len(port_info))
    )
    logger.info(
        "Chassis full mesh: collected %d ports across %d frontend DUTs",
        len(port_info), len(duthosts.frontend_nodes)
    )
    return port_info


@pytest.fixture(scope='module')
def chassis_dscp_queue_map(dut_qos_maps_module):  # noqa: F811
    """
    Build a {dscp: queue} mapping from the chassis QoS configuration.

    Picks one representative DSCP value per unique unicast queue (up to 8 queues)
    using the ``AZURE`` DSCP-to-TC and TC-to-queue maps.  TC 7 (control-plane
    traffic) is excluded so only data queues are tested.

    Returns:
        dict: ``{dscp_value (int): queue_number (int)}``

    Skips the test if the required QoS maps are not present.
    """
    try:
        tc_to_q_map = dut_qos_maps_module['tc_to_queue_map']['AZURE']
        dscp_to_tc_map = dut_qos_maps_module['dscp_to_tc_map']['AZURE']
    except (KeyError, TypeError):
        pytest.skip(
            "Chassis full mesh test requires 'TC_TO_QUEUE_MAP' and "
            "'DSCP_TO_TC_MAP' with key 'AZURE' in the QoS maps."
        )

    # Build {dscp: queue} – one entry per unique unicast queue, excluding TC 7
    dscp_queue_map = {}
    seen_queues = set()
    for dscp_str, tc in sorted(dscp_to_tc_map.items(), key=lambda x: int(x[0])):
        if tc == '7':
            continue
        queue_str = tc_to_q_map.get(tc)
        if queue_str is None:
            continue
        queue = int(queue_str)
        dscp = int(dscp_str)
        if queue not in seen_queues:
            dscp_queue_map[dscp] = queue
            seen_queues.add(queue)

    pytest_assert(
        len(dscp_queue_map) > 0,
        "No valid DSCP-to-queue mappings found for chassis full mesh test"
    )
    logger.info(
        "Chassis full mesh: using %d DSCP/queue pairs: %s",
        len(dscp_queue_map), dscp_queue_map
    )
    return dscp_queue_map


def _get_egress_queue_pkt_counts(duthost, port_name):
    """
    Return the cumulative egress packet counts for all unicast queues on *port_name*.

    Uses ``queuestat -jp <port>`` on the DUT to read per-queue statistics.

    Args:
        duthost: DUT host object (``MultiAsicSonicHost`` or ``SonicHost``).
        port_name (str): Interface name, e.g. ``'Ethernet0'``.

    Returns:
        dict: ``{queue_number (int): packet_count (int)}`` for UC0 .. UC7.
              Returns an empty dict on failure.
    """
    try:
        raw_out = duthost.shell("queuestat -jp {}".format(port_name))['stdout']
        raw_json = json.loads(raw_out)
        intf_stats = raw_json.get(port_name, {})
    except Exception as exc:
        logger.warning("Failed to read queue stats for %s: %s", port_name, exc)
        return {}

    queue_counts = {}
    for queue_num in range(8):
        key = "UC{}".format(queue_num)
        stats = intf_stats.get(key) or {}
        count_str = stats.get('totalpacket', '0')
        if not count_str or count_str == 'N/A':
            count_str = '0'
        try:
            queue_counts[queue_num] = int(count_str.replace(',', ''))
        except ValueError:
            logger.warning(
                "Unexpected counter value for %s %s: %r; treating as 0",
                port_name, key, count_str
            )
            queue_counts[queue_num] = 0

    return queue_counts


def test_chassis_qos_full_mesh_traffic(ptfadapter, chassis_port_info, chassis_dscp_queue_map):
    """
    Verify all-ports-to-all-ports (full mesh) QoS connectivity on the chassis.

    For each destination port the test:

    1. Records per-queue baseline egress counters on the destination DUT.
    2. Sends ``PACKET_COUNT`` packets from **every other port** for each DSCP
       value that maps to a unique unicast queue (one DSCP per queue, up to 8).
    3. Waits ``QUEUE_SETTLE_TIME_SECS`` seconds for counters to stabilise.
    4. Records final per-queue egress counters on the destination DUT.
    5. Asserts that each tested queue saw an increase of at least
       ``len(src_ports) * PACKET_COUNT`` packets.

    This exercise covers both intra-line-card and inter-line-card (fabric) paths,
    providing confidence that the underlying Traffic Manager programming has no
    dead ends.

    Args:
        ptfadapter: PTF adapter used for direct packet injection.
        chassis_port_info (dict): Port details keyed by PTF port index
            (produced by the ``chassis_port_info`` fixture).
        chassis_dscp_queue_map (dict): DSCP-to-queue mapping
            (produced by the ``chassis_dscp_queue_map`` fixture).

    Raises:
        AssertionError: if any destination-port / queue combination does not
            receive the expected number of packets.
    """
    all_port_ids = sorted(chassis_port_info.keys())
    num_ports = len(all_port_ids)
    dscp_to_queue = chassis_dscp_queue_map
    num_dscp = len(dscp_to_queue)

    # Skip on VS platform – virtual switches do not maintain real queue counters.
    # Check all DUTs since a chassis may theoretically have multiple line cards.
    if any(
        info['duthost'].facts.get('asic_type', '') == 'vs'
        for info in chassis_port_info.values()
    ):
        pytest.skip("Chassis QoS full mesh test is not supported on VS platform")

    logger.info(
        "Chassis QoS full mesh: %d ports x %d DSCP/queue pairs = %d dst iterations",
        num_ports, num_dscp, num_ports
    )

    failures = []

    for dst_port_id in all_port_ids:
        dst_info = chassis_port_info[dst_port_id]
        dst_duthost = dst_info['duthost']
        dst_port_name = dst_info['port_name']
        dst_peer_ip = dst_info['peer_ip']

        src_port_ids = [p for p in all_port_ids if p != dst_port_id]
        num_src = len(src_port_ids)

        logger.info(
            "Testing %d src -> dst %s (%s) with %d DSCP/queues",
            num_src, dst_port_name, dst_peer_ip, num_dscp
        )

        # ------------------------------------------------------------------
        # 1. Baseline counters (single SSH call per dst port)
        # ------------------------------------------------------------------
        baseline_counts = _get_egress_queue_pkt_counts(dst_duthost, dst_port_name)

        # ------------------------------------------------------------------
        # 2. Inject traffic for each DSCP from all source ports
        # ------------------------------------------------------------------
        ptfadapter.dataplane.flush()

        for dscp, queue in sorted(dscp_to_queue.items()):
            ecn = 1 if queue in ECN_QUEUES else 0
            ip_tos = (dscp << 2) | ecn

            for src_port_id in src_port_ids:
                src_info = chassis_port_info[src_port_id]
                # Use the src DUT's router MAC so the DUT accepts the packet
                # for L3 forwarding.
                src_router_mac = src_info['router_mac']
                src_peer_ip = src_info['peer_ip']

                pkt = testutils.simple_tcp_packet(
                    eth_dst=src_router_mac,
                    ip_src=src_peer_ip,
                    ip_dst=dst_peer_ip,
                    ip_tos=ip_tos,
                    ip_ttl=PACKET_IP_TTL,
                    pktlen=PACKET_LEN,
                )
                testutils.send(ptfadapter, src_port_id, pkt, count=PACKET_COUNT)

        # ------------------------------------------------------------------
        # 3. Wait for egress counters to settle
        # ------------------------------------------------------------------
        time.sleep(QUEUE_SETTLE_TIME_SECS)

        # ------------------------------------------------------------------
        # 4. Final counters (single SSH call per dst port)
        # ------------------------------------------------------------------
        final_counts = _get_egress_queue_pkt_counts(dst_duthost, dst_port_name)

        # ------------------------------------------------------------------
        # 5. Verify each queue received the expected number of packets
        # ------------------------------------------------------------------
        expected_per_queue = num_src * PACKET_COUNT
        for dscp, expected_queue in sorted(dscp_to_queue.items()):
            baseline = baseline_counts.get(expected_queue, 0)
            final = final_counts.get(expected_queue, 0)
            actual_increase = final - baseline

            if actual_increase < expected_per_queue:
                failure = {
                    'dst_port': dst_port_name,
                    'dscp': dscp,
                    'queue': expected_queue,
                    'expected_min': expected_per_queue,
                    'actual': actual_increase,
                    'num_src_ports': num_src,
                }
                logger.error(
                    "Queue %d on dst %s: received %d pkts, expected >= %d "
                    "(DSCP %d, %d src ports x %d pkts)",
                    expected_queue, dst_port_name, actual_increase,
                    expected_per_queue, dscp, num_src, PACKET_COUNT
                )
                failures.append(failure)

    pytest_assert(
        len(failures) == 0,
        "Chassis QoS full mesh test FAILED for {} port/DSCP "
        "combination(s):\n{}".format(
            len(failures),
            "\n".join(
                "  dst={dst_port} dscp={dscp} queue={queue} "
                "expected>={expected_min} actual={actual} "
                "src_ports={num_src_ports}".format(**f)
                for f in failures
            )
        )
    )
