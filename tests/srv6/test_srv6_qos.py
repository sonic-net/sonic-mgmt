"""
Test cases for validating DSCP to queue mapping for IPv6-in-IPv6 SRv6 packets in SONiC.

For each DSCP value defined in the DSCP_TO_TC map (CONFIG_DB), the test injects an
IPv6-in-IPv6 SRv6 packet (with and without SRH) into the DUT.  The DUT applies the
SRv6 uN action (DIP shift) and forwards the packet out of the egress port.  The
test verifies that the packet egresses on the queue selected by the
DSCP_TO_TC -> TC_TO_QUEUE mapping using the outer-IPv6 DSCP value.
"""
import json
import logging
import random
import ast
import pytest
import ptf.testutils as testutils
import ptf.packet as packet

from ptf.mask import Mask
from tabulate import tabulate
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import (
    get_dscp_to_queue_value,
    wait_until,
)
from tests.srv6.srv6_utils import (
    get_neighbor_mac,
    verify_asic_db_sid_entry_exist,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox", "broadcom", "vpp"),
    pytest.mark.topology("t0", "t1"),
]

DEFAULT_PKT_COUNT = 10
LOCATOR_NAME = "loc_qos"
LOCATOR_PREFIX = "fcbb:bbbb:1::"
LOCATOR_SID_PREFIX = "fcbb:bbbb:1::/48"
NEXTHOP_PREFIX = "fcbb:bbbb:2::/48"
# Outer SRv6 DIP - encodes a uN shift towards 'fcbb:bbbb:2::' (next uSID slot)
SRV6_OUTER_DIP = "fcbb:bbbb:1:2::"
SRV6_SHIFTED_DIP = "fcbb:bbbb:2::"
# Inner IPv6 packet endpoints (only used as packet payload; not routed)
INNER_SRC_IPV6 = "2000::1"
INNER_DST_IPV6 = "3000::2"
COUNTER_STABILIZATION_TIME = 10  # seconds to wait for queue counters to update


@pytest.fixture(scope="module", autouse=True)
def checkpoint(duthost):
    create_checkpoint(duthost)
    yield
    try:
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def _get_bgp_ipv6_neighbors(duthost):
    """
    Return a mapping {neighbor_hostname: neighbor_ipv6} for all IPv6 BGP
    neighbors of the given DUT/ASIC handle.

    `show ipv6 bgp sum` lines look like:
        <neighbor-ipv6>  4   <asn>  ...  <state/PfxRcd>  <neighbor-hostname>
    The neighbor hostname is typically the last column.
    """
    mapping = {}
    output = duthost.command("show ipv6 bgp sum")["stdout"]
    for line in output.split("\n"):
        tokens = line.split()
        if len(tokens) < 2:
            continue
        candidate_ip = tokens[0]
        # An IPv6 address always contains ':'
        if ":" not in candidate_ip:
            continue
        neighbor_name = tokens[-1]
        mapping[neighbor_name] = candidate_ip
    return mapping


def _portchannel_for_intf(dut_mg_facts, intf):
    """Return the portchannel name owning `intf` if any, otherwise `intf`."""
    for pc_name, pc_info in dut_mg_facts.get("minigraph_portchannels", {}).items():
        if intf in pc_info.get("members", []):
            return pc_name
    return intf


def _select_egress_port(dut, dut_mg_facts, ports_map):
    """
    Pick an egress DUT port whose LLDP neighbor has an IPv6 BGP address
    configured, so that we can install a static IPv6 route via that
    neighbor's address as the SRv6 nexthop.

    Returns:
        tuple: (egress_intf, egress_neighbor, egress_neighbor_ip, egress_dut_port)

        `egress_dut_port` is the portchannel name when the egress interface
        is a portchannel member, otherwise the physical interface name.
    """
    bgp_ipv6_neighbors = _get_bgp_ipv6_neighbors(dut)
    if not bgp_ipv6_neighbors:
        pytest.skip(f"No IPv6 BGP neighbors found for {dut}")

    lldp_table = dut.command("show lldp table")["stdout"].split("\n")[3:]
    for line in lldp_table:
        entry = line.split()
        if len(entry) < 2:
            continue
        intf, neighbor = entry[0], entry[1]
        if intf not in ports_map:
            continue
        if neighbor not in bgp_ipv6_neighbors:
            continue
        egress_dut_port = _portchannel_for_intf(dut_mg_facts, intf)
        return intf, neighbor, bgp_ipv6_neighbors[neighbor], egress_dut_port

    pytest.skip(f"No LLDP neighbor with IPv6 BGP address found on {dut}")


def _select_ingress_port(dut, dut_mg_facts, ports_map, egress_dut_port):
    """
    Pick an ingress DUT port: any operationally-up port that maps to PTF and
    belongs to a different L3 interface than the egress.

    Returns:
        tuple: (ingress_intf, ingress_ptf_port)
    """
    intf_status = dut.show_interface(command="status")["ansible_facts"]["int_status"]
    for intf, info in intf_status.items():
        if intf not in ports_map:
            continue
        if (info.get("oper_state") or "").lower() != "up":
            continue
        if _portchannel_for_intf(dut_mg_facts, intf) == egress_dut_port:
            continue
        return intf, ports_map[intf]

    pytest.skip(
        f"No operationally-up DUT port (different from egress {egress_dut_port}) found on {dut}"
    )


@pytest.fixture(scope="module")
def srv6_qos_module_setup(rand_selected_dut, enum_frontend_asic_index, tbinfo):
    """
    Module-scoped setup: select ingress/egress DUT ports and resolve QoS maps.

    These values do not change between test parametrizations, so caching them
    at module scope avoids repeating the (relatively slow) port-selection and
    CONFIG_DB lookups for every test case.

    Returns a dict with:
        - dut_mac, ingress_dut_port, ptf_src_port
        - egress_dut_port, egress_ptf_ports
        - neighbor_ip
        - sonic_db_cli  (CLI prefix targeting the right ASIC namespace)
        - dscp_to_tc_map, tc_to_queue_map (resolved from PORT_QOS_MAP)
        - dscp_values (sorted DSCP keys present in dscp_to_tc_map)
    """
    duthost = rand_selected_dut
    asic_index = enum_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_handle = duthost.asic_instance(asic_index)
        dut_mac = dut_handle.get_router_mac()
    else:
        cli_options = ""
        dut_handle = duthost
        dut_mac = duthost.facts["router_mac"]

    sonic_db_cli = "sonic-db-cli" + cli_options

    dut_mg_facts = dut_handle.get_extended_minigraph_facts(tbinfo)
    ports_map = dut_mg_facts["minigraph_ptf_indices"]
    if len(ports_map) == 0:
        pytest.skip(f"No PTF ports found for {dut_handle}")

    egress_intf, egress_neighbor, neighbor_ip, egress_dut_port = \
        _select_egress_port(dut_handle, dut_mg_facts, ports_map)

    pc_members = (
        dut_mg_facts.get("minigraph_portchannels", {})
        .get(egress_dut_port, {})
        .get("members")
    )
    if pc_members:
        egress_ptf_ports = [ports_map[m] for m in pc_members if m in ports_map]
    else:
        egress_ptf_ports = [ports_map[egress_intf]]

    ingress_dut_port, ptf_src_port = \
        _select_ingress_port(dut_handle, dut_mg_facts, ports_map, egress_dut_port)

    logger.info(
        f"SRv6 QoS test: ingress DUT port {ingress_dut_port} (PTF port {ptf_src_port}); "
        f"egress {egress_intf} (L3 {egress_dut_port}, neighbor {egress_neighbor} @ {neighbor_ip})"
    )

    # Look up the QoS map names that are bound to the egress port via
    # PORT_QOS_MAP, then fetch the corresponding maps from CONFIG_DB.  Field
    # values may be of the form "AZURE" or "[DSCP_TO_TC_MAP|AZURE]"; we
    # normalise both.
    def _qos_map_name(field):
        raw = duthost.command(
            f"{sonic_db_cli} CONFIG_DB HGET 'PORT_QOS_MAP|{egress_dut_port}' '{field}'")["stdout"].strip()
        if not raw:
            return None
        return raw.split("|")[-1].strip("[]")

    dscp_to_tc_name = _qos_map_name("dscp_to_tc_map")
    tc_to_queue_name = _qos_map_name("tc_to_queue_map")
    pytest_assert(
        dscp_to_tc_name and tc_to_queue_name,
        f"PORT_QOS_MAP for egress port {egress_dut_port} does not reference dscp_to_tc_map "
        "and/or tc_to_queue_map",
    )

    def _hgetall(table, key):
        raw = duthost.command(f"{sonic_db_cli} CONFIG_DB HGETALL '{table}|{key}'")["stdout"].strip()
        return ast.literal_eval(raw)

    dscp_to_tc_map = _hgetall("DSCP_TO_TC_MAP", dscp_to_tc_name)
    tc_to_queue_map = _hgetall("TC_TO_QUEUE_MAP", tc_to_queue_name)
    pytest_assert(
        dscp_to_tc_map and tc_to_queue_map,
        f"DSCP_TO_TC_MAP|{dscp_to_tc_name} or TC_TO_QUEUE_MAP|{tc_to_queue_name} is empty in CONFIG_DB",
    )

    dscp_values = sorted(int(d) for d in dscp_to_tc_map.keys())
    logger.info(f"Resolved DSCP values for test: {dscp_values}")

    return {
        "dut_mac": dut_mac,
        "ingress_dut_port": ingress_dut_port,
        "ptf_src_port": ptf_src_port,
        "egress_dut_port": egress_dut_port,
        "egress_ptf_ports": egress_ptf_ports,
        "neighbor_ip": neighbor_ip,
        "sonic_db_cli": sonic_db_cli,
        "dscp_to_tc_map": dscp_to_tc_map,
        "tc_to_queue_map": tc_to_queue_map,
        "dscp_values": dscp_values,
    }


@pytest.fixture(scope="function", params=["pipe", None], ids=["decap_dscp_pipe", "decap_dscp_unset"])
def srv6_qos_setup(request, rand_selected_dut, srv6_qos_module_setup):
    """
    Function-scoped setup: configure the SRv6 uN locator, SID and static route
    on the DUT.  Reuses the module-scoped port/QoS lookup from
    `srv6_qos_module_setup`.

    Parametrized on `decap_dscp_mode`:
      * "pipe"  - explicitly configure ``decap_dscp_mode pipe`` on the SID.
      * ``None`` - do not configure ``decap_dscp_mode`` at all (default value
        is expected to be ``pipe`` and behavior should be identical).
    """
    decap_dscp_mode = request.param
    duthost = rand_selected_dut

    sonic_db_cli = srv6_qos_module_setup["sonic_db_cli"]
    egress_dut_port = srv6_qos_module_setup["egress_dut_port"]
    neighbor_ip = srv6_qos_module_setup["neighbor_ip"]

    # Configure SRv6 locator + uN SID + static route towards next uSID slot
    duthost.command(
        sonic_db_cli + f" CONFIG_DB HSET SRV6_MY_LOCATORS\\|{LOCATOR_NAME} prefix {LOCATOR_PREFIX} func_len 0"
    )
    sid_fields = "action uN"
    if decap_dscp_mode is not None:
        sid_fields += f" decap_dscp_mode {decap_dscp_mode}"
    duthost.command(
        sonic_db_cli + f" CONFIG_DB HSET SRV6_MY_SIDS\\|{LOCATOR_NAME}\\|{LOCATOR_SID_PREFIX} {sid_fields}"
    )
    duthost.command(
        sonic_db_cli + f" CONFIG_DB HSET STATIC_ROUTE\\|default\\|{NEXTHOP_PREFIX} nexthop "
        f"{neighbor_ip} ifname {egress_dut_port}"
    )
    duthost.command("config save -y")

    pytest_assert(
        wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli),
        "SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB",
    )
    pytest_assert(
        wait_until(60, 5, 0, get_neighbor_mac, duthost, neighbor_ip),
        f"Failed to resolve neighbor MAC for {neighbor_ip}",
    )

    return srv6_qos_module_setup


def _build_srv6_packet(dut_mac, ptf_src_mac, dscp, with_srh):
    """
    Build an IPv6-in-IPv6 SRv6 packet with the requested outer DSCP value.
    The encoded uN action will shift the DIP from fcbb:bbbb:1:2:: to fcbb:bbbb:2::
    on the egress side.

    Args:
        dut_mac (str): destination MAC for the outer Ethernet frame (DUT mac)
        ptf_src_mac (str): source MAC for the outer Ethernet frame
        dscp (int): outer-IPv6 DSCP value to set
        with_srh (bool): whether to include an SRH header

    Returns:
        PTF packet
    """
    # Traffic Class field carries DSCP in the upper 6 bits (TC = DSCP << 2)
    tc = (dscp & 0x3F) << 2
    # Build the inner IPv6/UDP frame using PTF helpers, then strip the outer
    # Ethernet header so it can be embedded as the SRv6 payload.
    inner_eth = testutils.simple_udpv6_packet(
        eth_dst=dut_mac,
        eth_src=ptf_src_mac,
        ipv6_src=INNER_SRC_IPV6,
        ipv6_dst=INNER_DST_IPV6,
    )
    inner_pkt = inner_eth["IPv6"]

    if with_srh:
        return testutils.simple_ipv6_sr_packet(
            eth_dst=dut_mac,
            eth_src=ptf_src_mac,
            ipv6_src="1000:1000::1",
            ipv6_dst=SRV6_OUTER_DIP,
            ipv6_tc=tc,
            ipv6_hlim=2,
            srh_seg_left=1,
            srh_nh=41,  # IPv6 next-header
            inner_frame=inner_pkt,
        )

    return testutils.simple_ipv6ip_packet(
        eth_dst=dut_mac,
        eth_src=ptf_src_mac,
        ipv6_src="1000:1000::1",
        ipv6_dst=SRV6_OUTER_DIP,
        ipv6_tc=tc,
        ipv6_hlim=2,
        inner_frame=inner_pkt,
    )


def _build_expected_packet(pkt):
    """
    Build the expected egress packet after the SRv6 uN DIP shift.

    The DUT shifts the outer IPv6 destination from `fcbb:bbbb:1:2::` to
    `fcbb:bbbb:2::` and decrements the hop limit by one.  The outer Ethernet
    addresses are rewritten by the DUT (we don't care about the exact values).
    """
    exp = pkt.copy()
    exp["IPv6"].dst = SRV6_SHIFTED_DIP
    exp["IPv6"].hlim -= 1
    masked = Mask(exp)
    masked.set_do_not_care_packet(packet.Ether, "dst")
    masked.set_do_not_care_packet(packet.Ether, "src")
    masked.set_do_not_care_packet(packet.IPv6, "fl")
    return masked


def _get_queue_count(duthost, port, queue):
    raw_out = duthost.shell(f"queuestat -jp {port}")['stdout']
    intf_stats = json.loads(raw_out).get(port, {})
    pkt_str = intf_stats.get(f"UC{queue}", {}).get("totalpacket", "0")
    if pkt_str in ("N/A", None):
        pkt_str = "0"
    return int(pkt_str.replace(',', ''))


@pytest.mark.parametrize("with_srh", [True, False], ids=["with_srh", "without_srh"])
def test_srv6_dscp_to_queue_mapping(
    ptfadapter, rand_selected_dut, srv6_qos_setup, with_srh
):
    """
    Validate DSCP-to-queue mapping for IPv6-in-IPv6 SRv6 packets.

    For every DSCP value in the DSCP_TO_TC map, send DEFAULT_PKT_COUNT SRv6
    packets with that DSCP set on the outer IPv6 header, then verify that
    the corresponding egress queue counter on the DUT increments by the
    expected amount.
    """
    duthost = rand_selected_dut
    egress_dut_port = srv6_qos_setup["egress_dut_port"]
    egress_ptf_ports = srv6_qos_setup["egress_ptf_ports"]
    dut_mac = srv6_qos_setup["dut_mac"]
    dscp_to_tc_map = srv6_qos_setup["dscp_to_tc_map"]
    tc_to_queue_map = srv6_qos_setup["tc_to_queue_map"]
    dscp_values = list(srv6_qos_setup["dscp_values"])

    ptf_src_port = srv6_qos_setup["ptf_src_port"]
    ptf_src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port).decode("utf-8")

    output_table = []
    failed = False

    logger.info(f"Validating DSCP-to-queue mapping for DSCPs: {dscp_values}")

    # Randomize order to detect any state-leak between iterations
    random.shuffle(dscp_values)

    for dscp in dscp_values:
        expected_queue = get_dscp_to_queue_value(dscp, dscp_to_tc_map, tc_to_queue_map)
        if expected_queue is None:
            logger.info(f"No queue mapping for DSCP {dscp} - skipping")
            output_table.append([dscp, "N/A", "N/A", "SKIPPED"])
            continue

        pkt = _build_srv6_packet(dut_mac, ptf_src_mac, dscp, with_srh)
        logger.info(f"Test packet for DSCP {dscp}: {pkt}")
        exp_pkt = _build_expected_packet(pkt)

        duthost.command("queuestat -c")
        cleared = wait_until(
            COUNTER_STABILIZATION_TIME, 1, 0,
            lambda: _get_queue_count(duthost, egress_dut_port, expected_queue) == 0,
        )
        if not cleared:
            logger.error(
                f"DSCP {dscp}: queue {expected_queue} counter did not clear after queuestat -c"
            )
            output_table.append(
                [dscp, expected_queue, 0, "FAILURE - QUEUE COUNTER NOT CLEARED"]
            )
            failed = True
            continue

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_src_port, pkt, count=DEFAULT_PKT_COUNT)

        # Verify that at least one of the SRv6-shifted packets is captured
        # on one of the egress PTF ports.
        try:
            rx_port_index, received_pkt = testutils.verify_packet_any_port(
                ptfadapter, exp_pkt, ports=egress_ptf_ports
            )
            logger.info(f"DSCP {dscp}: captured packet:\n{packet.Ether(received_pkt)}")
            logger.info(
                f"DSCP {dscp}: captured expected SRv6 packet on PTF port "
                f"{egress_ptf_ports[rx_port_index]}"
            )
        except AssertionError as detail:
            logger.error(
                f"DSCP {dscp}: did not capture expected SRv6 packet on egress "
                f"PTF ports {egress_ptf_ports}: {detail}"
            )
            output_table.append(
                [dscp, expected_queue, 0, "FAILURE - PACKET NOT CAPTURED"]
            )
            failed = True
            continue

        counter_populated = wait_until(
            COUNTER_STABILIZATION_TIME, 1, 0,
            lambda: _get_queue_count(duthost, egress_dut_port, expected_queue) >= DEFAULT_PKT_COUNT,
        )
        queue_count = _get_queue_count(duthost, egress_dut_port, expected_queue)
        if not counter_populated:
            logger.error(
                f"FAILURE: DSCP {dscp} - queue {expected_queue} count {queue_count} "
                f"< expected {DEFAULT_PKT_COUNT} (timed out waiting for counter)"
            )
            output_table.append(
                [dscp, expected_queue, queue_count, "FAILURE - QUEUE COUNTER TIMEOUT"]
            )
            failed = True
            continue

    logger.info(
        f"SRv6 DSCP-to-queue mapping results (with_srh={with_srh}):\n"
        f"{tabulate(output_table, headers=['DSCP', 'Expected Queue', 'Egress Queue Count', 'Result'])}"
    )

    pytest_assert(not failed, "SRv6 DSCP-to-queue mapping test failed - see results table")
