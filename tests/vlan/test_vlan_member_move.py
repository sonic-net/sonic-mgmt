import logging

import pytest
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.vlan_hardening import ignore_expected_loganalyzer_exceptions  # noqa: F401
from tests.common.helpers.vlan_hardening import (
    borrow_ports,
    get_config_facts,
    get_vlan_members,
    pick_free_vlan_id,
    ptf_indices_for_ports,
    restore_borrowed_port,
    state_db_vlan_member_tagging_mode,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Candidate ranges for the two test VLANs, each probed via pick_free_vlan_id()
# so a leftover VLAN from an aborted prior run can't collide with this test.
VLAN_N_RANGE = range(1011, 1021)
VLAN_M_RANGE = range(1021, 1030)


def build_broadcast_icmp_packet(src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                                src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):
    # Build an untagged broadcast ICMP packet to test VLAN flooding without FDB learning.
    return testutils.simple_icmp_packet(pktlen=100,
                                        eth_dst=dst_mac,
                                        eth_src=src_mac,
                                        dl_vlan_enable=False,
                                        ip_src=src_ip,
                                        ip_dst=dst_ip,
                                        ip_ttl=ttl)


def get_vlan_memberships(duthost, port):
    # Return all current VLAN memberships for `port` as (vlan_id_str, tagging_mode) tuples.
    cfg_facts = get_config_facts(duthost)
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    memberships = []
    for vlan, members in vlan_members.items():
        if port in members:
            memberships.append((vlan[len('Vlan'):], members[port].get('tagging_mode')))
    return memberships


def get_port_pvid(duthost, port):
    # Return a port's PVID from its untagged VLAN_MEMBER entry, or None if it has none.
    for vlan_id, tagging_mode in get_vlan_memberships(duthost, port):
        if tagging_mode == "untagged":
            return int(vlan_id)
    return None


def setup_move_topology(duthost, vlan_n, vlan_m, ports):
    # Set up three borrowed ports across two VLANs and return their original state for restoration.
    p, n_peer, m_peer = ports

    saved_state = {}
    for port in ports:
        saved_state[port] = get_vlan_memberships(duthost, port)

    for port in ports:
        for vlan_id, _ in saved_state[port]:
            duthost.shell("config vlan member del {} {}".format(vlan_id, port))

    duthost.shell("config vlan add {}".format(vlan_n))
    duthost.shell("config vlan add {}".format(vlan_m))

    duthost.shell("config vlan member add {} {} --untagged".format(vlan_n, p))
    duthost.shell("config vlan member add {} {} --untagged".format(vlan_n, n_peer))
    duthost.shell("config vlan member add {} {} --untagged".format(vlan_m, m_peer))

    return saved_state


def teardown_move_topology(duthost, enum_frontend_asic_index, vlan_n, vlan_m, ports, saved_state, borrowed):
    # Best-effort cleanup: remove test VLANs, restore port VLAN state, and rejoin PortChannels independently.
    config_facts = get_config_facts(duthost)
    for vlan_id in (vlan_n, vlan_m):
        members = get_vlan_members(config_facts, "Vlan{}".format(vlan_id))
        for port in ports:
            if port in members:
                duthost.shell("config vlan member del {} {}".format(vlan_id, port),
                              module_ignore_errors=True)

    duthost.shell("config vlan del {}".format(vlan_n), module_ignore_errors=True)
    duthost.shell("config vlan del {}".format(vlan_m), module_ignore_errors=True)

    for port in ports:
        for vlan_id, tagging_mode in saved_state.get(port, []):
            cmd = "config vlan member add {} {}".format(vlan_id, port)
            if tagging_mode == "untagged":
                cmd += " --untagged"
            duthost.shell(cmd, module_ignore_errors=True)

    for descriptor in borrowed:
        restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)


def move_port(duthost, port, from_vlan, to_vlan):
    # Move `port` from untagged `from_vlan` to untagged `to_vlan` via back-to-back del/add.
    duthost.shell("config vlan member del {} {}".format(from_vlan, port))
    duthost.shell("config vlan member add {} {} --untagged".format(to_vlan, port))


def _borrow_move_topology_ports(duthost, tbinfo, enum_frontend_asic_index):
    # Borrow three topology-aware test ports before setup; partial PortChannel changes roll back internally.
    borrowed = borrow_ports(duthost, tbinfo, enum_frontend_asic_index, 3)
    if len(borrowed) < 3:
        pytest.skip("Not enough usable ports available to run this test "
                    "(3 needed, {} found).".format(len(borrowed)))
    return borrowed, tuple(b["port"] for b in borrowed)


def test_vlan_member_move(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    # Verify moving an untagged port updates CONFIG_DB consistently, including PVID and memberships.
    duthost = duthosts[rand_one_dut_hostname]
    borrowed, (p, n_peer, m_peer) = _borrow_move_topology_ports(duthost, tbinfo, enum_frontend_asic_index)
    ports = (p, n_peer, m_peer)

    config_facts = get_config_facts(duthost)
    vlan_n = pick_free_vlan_id(config_facts, VLAN_N_RANGE)
    vlan_m = pick_free_vlan_id(config_facts, VLAN_M_RANGE)

    saved_state = {}
    try:
        saved_state = setup_move_topology(duthost, vlan_n, vlan_m, ports)

        move_port(duthost, p, vlan_n, vlan_m)

        config_facts = get_config_facts(duthost)
        vlan_members = config_facts.get('VLAN_MEMBER', {})

        # 1. no Vlan<N>|<P> entry remains
        n_members = vlan_members.get("Vlan{}".format(vlan_n), {})
        pytest_assert(p not in n_members,
                      "Port {} still has a VLAN_MEMBER entry under VLAN {} after the move".format(p, vlan_n))

        # 2. a Vlan<M>|<P> entry exists with tagging_mode == "untagged"
        m_members = vlan_members.get("Vlan{}".format(vlan_m), {})
        pytest_assert(p in m_members,
                      "Port {} has no VLAN_MEMBER entry under VLAN {} after the move".format(p, vlan_m))
        pytest_assert(m_members[p].get("tagging_mode") == "untagged",
                      "Port {} is a member of VLAN {} but not untagged: {}".format(p, vlan_m, m_members[p]))

        # 3. P's PVID (per the untagged-membership oracle) is now M
        pvid = get_port_pvid(duthost, p)
        pytest_assert(pvid == vlan_m,
                      "Expected PVID {} for port {} after the move, got {}".format(vlan_m, p, pvid))

        # 4. VLAN N itself still exists (just without P) - no incidental VLAN-N teardown
        vlans = config_facts.get('VLAN', {})
        pytest_assert("Vlan{}".format(vlan_n) in vlans,
                      "VLAN {} was unexpectedly removed as a side effect of the port move".format(vlan_n))

        # 5. no stale/duplicate membership left under N for P
        pytest_assert(p not in vlan_members.get("Vlan{}".format(vlan_n), {}),
                      "Stale VLAN_MEMBER entry for port {} left under VLAN {}".format(p, vlan_n))
    finally:
        teardown_move_topology(duthost, enum_frontend_asic_index, vlan_n, vlan_m, ports, saved_state, borrowed)


def test_vlan_member_move_forwarding(ptfadapter, duthosts, rand_one_dut_hostname,
                                     tbinfo, enum_frontend_asic_index, ptfhost):
    # Verify a moved untagged port stops receiving from the old VLAN and starts receiving from the new one.
    duthost = duthosts[rand_one_dut_hostname]
    borrowed, (p, n_peer, m_peer) = _borrow_move_topology_ports(duthost, tbinfo, enum_frontend_asic_index)
    ports = (p, n_peer, m_peer)

    config_facts = get_config_facts(duthost)
    vlan_n = pick_free_vlan_id(config_facts, VLAN_N_RANGE)
    vlan_m = pick_free_vlan_id(config_facts, VLAN_M_RANGE)

    ptf_indices = ptf_indices_for_ports(duthost, ptfhost, tbinfo, enum_frontend_asic_index, ports)
    if any(port not in ptf_indices for port in ports):
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)
        pytest.skip("Borrowed ports {} have no PTF dataplane index on this topology; "
                    "cannot inject traffic.".format(ports))
    p_idx, n_peer_idx, m_peer_idx = (ptf_indices[port] for port in ports)
    asic = duthost.asic_instance(enum_frontend_asic_index)

    saved_state = {}
    try:
        saved_state = setup_move_topology(duthost, vlan_n, vlan_m, ports)

        pkt = build_broadcast_icmp_packet()

        # Baseline: P is still an untagged member of VLAN_N
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, n_peer_idx, pkt)
        testutils.verify_packets_any(ptfadapter, pkt, ports=[p_idx], timeout=5)

        move_port(duthost, p, vlan_n, vlan_m)

        # Wait for STATE_DB to reflect the move before sending traffic, since CONFIG_DB updates first.
        vlan_n_key, vlan_m_key = "Vlan{}".format(vlan_n), "Vlan{}".format(vlan_m)
        pytest_assert(
            wait_until(10, 1, 0, lambda: (
                state_db_vlan_member_tagging_mode(asic, vlan_n_key, p) is None and
                state_db_vlan_member_tagging_mode(asic, vlan_m_key, p) == "untagged")),
            "STATE_DB VLAN_MEMBER_TABLE did not reflect the move of {} from {} to {} within 10s -- "
            "control plane (vlanmgrd) never applied the change".format(p, vlan_n_key, vlan_m_key))

        # After the move: P is no longer a member of VLAN_N, so n_peer's broadcast must NOT
        # reach P any more - old membership is gone in hardware, not just in CONFIG_DB.
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, n_peer_idx, pkt)
        testutils.verify_no_packet_any(ptfadapter, pkt, ports=[p_idx], timeout=5)

        # P is now an untagged member of VLAN_M - broadcast from m_peer must reach P - new
        # membership is live in hardware.
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, m_peer_idx, pkt)
        testutils.verify_packets_any(ptfadapter, pkt, ports=[p_idx], timeout=5)
    finally:
        teardown_move_topology(duthost, enum_frontend_asic_index, vlan_n, vlan_m, ports, saved_state, borrowed)
