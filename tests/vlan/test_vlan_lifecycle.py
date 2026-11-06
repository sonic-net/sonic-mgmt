import logging

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.portchannel_to_vlan import build_icmp_packet
from tests.common.helpers.vlan_hardening import ignore_expected_loganalyzer_exceptions  # noqa: F401
from tests.common.helpers.vlan_hardening import (
    borrow_port,
    borrow_ports,
    get_config_facts,
    get_vlan_members,
    pick_free_vlan_id,
    ptf_indices_for_ports,
    release_prior_membership,
    restore_borrowed_port,
    verify_flood_to_all_ports,
)

logger = logging.getLogger(__name__)

# Topology-agnostic: borrow helpers handle t0/non-t0, and tests skip when ports or PTF wiring are unavailable.
pytestmark = [
    pytest.mark.topology('any')
]

# Give each test an exclusive 10-ID range to prevent leftovers from colliding across tests.
VLAN_CREATE_RANGE = range(2101, 2111)               # test_vlan_create
VLAN_DELETE_RANGE = range(2111, 2121)               # test_vlan_delete
VLAN_REJECT_RANGE = range(2121, 2131)               # test_vlan_delete_with_members_rejected
VLAN_BATCH_RANGE = range(2131, 2141)                # test_vlan_mixed_membership_batch_add
VLAN_DELETE_MEMBER_RANGE = range(2141, 2151)        # test_vlan_delete_member
VLAN_ADD_UNTAGGED_RANGE = range(2151, 2161)         # test_vlan_add_untagged_member
VLAN_ADD_TAGGED_RANGE = range(2161, 2171)           # test_vlan_add_tagged_member


def test_vlan_create(duthosts, rand_one_dut_hostname):
    # Create a VLAN and verify it appears in CONFIG_DB with the expected name.
    duthost = duthosts[rand_one_dut_hostname]
    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_CREATE_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))

        config_facts = get_config_facts(duthost)
        pytest_assert(vlan_name in config_facts.get('VLAN', {}),
                      "{} was not created in CONFIG_DB VLAN table".format(vlan_name))
    finally:
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)


def test_vlan_delete(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    # Create a VLAN, add/remove an untagged member, verify cleanup, and restore the borrowed port.
    duthost = duthosts[rand_one_dut_hostname]

    borrowed = borrow_port(duthost, tbinfo, enum_frontend_asic_index)
    if borrowed is None:
        pytest.skip("No usable port found on this DUT/topology; cannot safely borrow a port for this test.")
    port = borrowed["port"]

    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_DELETE_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))
        # Release the borrowed port's existing membership before adding it to the new VLAN.
        release_prior_membership(duthost, borrowed)
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, port))

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port in vlan_members,
                      "{} was not added as a member of {}".format(port, vlan_name))
        pytest_assert(
            vlan_members[port].get('tagging_mode') == 'untagged',
            "{} was not added as an untagged member of {}".format(port, vlan_name))

        duthost.shell("config vlan member del {} {}".format(vlan_id, port))
        duthost.shell("config vlan del {}".format(vlan_id))

        config_facts = get_config_facts(duthost)
        pytest_assert(vlan_name not in config_facts.get('VLAN', {}),
                      "{} still present in CONFIG_DB VLAN table after delete".format(vlan_name))
        remaining_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port not in remaining_members,
                      "{} still has a VLAN_MEMBER entry under {} after delete".format(port, vlan_name))
    finally:
        # Best-effort cleanup: remove leftover VLAN state, then restore the borrowed port.
        duthost.shell("config vlan member del {} {}".format(vlan_id, port), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        restore_borrowed_port(duthost, enum_frontend_asic_index, borrowed)


def test_vlan_delete_with_members_rejected(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    # Verify deleting a VLAN with members is rejected and leaves the VLAN and member intact.
    duthost = duthosts[rand_one_dut_hostname]

    borrowed = borrow_port(duthost, tbinfo, enum_frontend_asic_index)
    if borrowed is None:
        pytest.skip("No usable port found on this DUT/topology; cannot safely borrow a port for this test.")
    port = borrowed["port"]

    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_REJECT_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))
        release_prior_membership(duthost, borrowed)
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, port))

        # Allow the expected CLI failure and assert its return code/stderr instead.
        result = duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        pytest_assert(result.get('rc', 0) != 0,
                      "Deleting {} while it still has member {} unexpectedly succeeded "
                      "(rc=0): {}".format(vlan_name, port, result))

        config_facts = get_config_facts(duthost)
        pytest_assert(vlan_name in config_facts.get('VLAN', {}),
                      "{} was removed from CONFIG_DB despite the delete being rejected".format(vlan_name))
        vlan_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port in vlan_members,
                      "VLAN_MEMBER entry for {} under {} was removed despite the delete being "
                      "rejected".format(port, vlan_name))
    finally:
        duthost.shell("config vlan member del {} {}".format(vlan_id, port), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        restore_borrowed_port(duthost, enum_frontend_asic_index, borrowed)


def test_vlan_mixed_membership_batch_add(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    # Add three VLAN members back-to-back and verify their tagging modes.
    duthost = duthosts[rand_one_dut_hostname]

    borrowed = borrow_ports(duthost, tbinfo, enum_frontend_asic_index, 3)
    if len(borrowed) < 3:
        pytest.skip("Need at least 3 distinct usable ports on this DUT to run this test; "
                    "found {}.".format(len(borrowed)))

    port_a, port_b, port_c = (b["port"] for b in borrowed)

    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_BATCH_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))

        for descriptor in borrowed:
            release_prior_membership(duthost, descriptor)

        duthost.shell("config vlan member add {} {}".format(vlan_id, port_a))
        duthost.shell("config vlan member add {} {}".format(vlan_id, port_b))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, port_c))

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_name)

        for port, expected_mode in ((port_a, 'tagged'), (port_b, 'tagged'), (port_c, 'untagged')):
            pytest_assert(port in vlan_members,
                          "{} was not added as a member of {}".format(port, vlan_name))
            pytest_assert(
                vlan_members[port].get('tagging_mode') == expected_mode,
                "{} expected tagging_mode {} in {}, got {}".format(
                    port, expected_mode, vlan_name, vlan_members[port].get('tagging_mode')))
    finally:
        for port in (port_a, port_b, port_c):
            duthost.shell("config vlan member del {} {}".format(vlan_id, port), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)


def test_vlan_delete_member(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    # Remove a VLAN member and verify the VLAN remains in CONFIG_DB.
    duthost = duthosts[rand_one_dut_hostname]

    borrowed = borrow_port(duthost, tbinfo, enum_frontend_asic_index)
    if borrowed is None:
        pytest.skip("No usable port found on this DUT/topology; cannot safely borrow a port for this test.")
    port = borrowed["port"]

    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_DELETE_MEMBER_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))
        release_prior_membership(duthost, borrowed)
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, port))

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port in vlan_members,
                      "{} was not added as a member of {}".format(port, vlan_name))

        duthost.shell("config vlan member del {} {}".format(vlan_id, port))

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port not in vlan_members,
                      "VLAN_MEMBER entry for {} under {} still present after member delete".format(
                          port, vlan_name))
        pytest_assert(vlan_name in config_facts.get('VLAN', {}),
                      "{} was unexpectedly removed after only its member was deleted".format(vlan_name))
    finally:
        duthost.shell("config vlan member del {} {}".format(vlan_id, port), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        restore_borrowed_port(duthost, enum_frontend_asic_index, borrowed)


def test_vlan_add_untagged_member(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index,
                                  ptfadapter, ptfhost):
    # Verify an untagged VLAN member and broadcast flooding to all other VLAN members.
    duthost = duthosts[rand_one_dut_hostname]

    borrowed = borrow_ports(duthost, tbinfo, enum_frontend_asic_index, 3)
    if len(borrowed) < 3:
        pytest.skip("Need at least 3 distinct usable ports on this DUT to run this test; "
                    "found {}.".format(len(borrowed)))
    port, peer_a, peer_b = (b["port"] for b in borrowed)

    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_ADD_UNTAGGED_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))
        for descriptor in borrowed:
            release_prior_membership(duthost, descriptor)

        # Peers join first so they are established members the new port's
        # frame can flood to.
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, peer_a))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, peer_b))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, port))

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port in vlan_members,
                      "{} was not added as a member of {}".format(port, vlan_name))
        pytest_assert(
            vlan_members[port].get('tagging_mode') == 'untagged',
            "{} was not added as an untagged member of {}".format(port, vlan_name))

        ptf_indices = ptf_indices_for_ports(duthost, ptfhost, tbinfo, enum_frontend_asic_index,
                                            [port, peer_a, peer_b])
        if any(p not in ptf_indices for p in (port, peer_a, peer_b)):
            pytest.skip("Borrowed ports {} have no PTF dataplane index on this "
                        "topology; cannot inject traffic.".format((port, peer_a, peer_b)))

        pkt = build_icmp_packet(vlan_id=0)
        peer_ptf_indices = [ptf_indices[peer_a], ptf_indices[peer_b]]
        logger.info("Sending untagged broadcast ICMP into new member %s (ptf idx %d), expecting "
                    "delivery on ALL existing members %s (ptf idx %s)",
                    port, ptf_indices[port], (peer_a, peer_b), peer_ptf_indices)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_indices[port], pkt)
        verify_flood_to_all_ports(ptfadapter, pkt, peer_ptf_indices)
    finally:
        for p in (port, peer_a, peer_b):
            duthost.shell("config vlan member del {} {}".format(vlan_id, p), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)


def test_vlan_add_tagged_member(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index,
                                ptfadapter, ptfhost):
    # Verify a tagged VLAN member and tagged broadcast flooding to all other VLAN members.
    duthost = duthosts[rand_one_dut_hostname]

    borrowed = borrow_ports(duthost, tbinfo, enum_frontend_asic_index, 3)
    if len(borrowed) < 3:
        pytest.skip("Need at least 3 distinct usable ports on this DUT to run this test; "
                    "found {}.".format(len(borrowed)))
    port, peer_a, peer_b = (b["port"] for b in borrowed)

    vlan_id = pick_free_vlan_id(get_config_facts(duthost), VLAN_ADD_TAGGED_RANGE)
    vlan_name = "Vlan{}".format(vlan_id)

    try:
        duthost.shell("config vlan add {}".format(vlan_id))
        for descriptor in borrowed:
            release_prior_membership(duthost, descriptor)

        # Peers join first, also tagged, so they are established members
        # the new port's frame can flood to.
        duthost.shell("config vlan member add {} {}".format(vlan_id, peer_a))
        duthost.shell("config vlan member add {} {}".format(vlan_id, peer_b))
        duthost.shell("config vlan member add {} {}".format(vlan_id, port))

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_name)
        pytest_assert(port in vlan_members,
                      "{} was not added as a member of {}".format(port, vlan_name))
        pytest_assert(
            vlan_members[port].get('tagging_mode') == 'tagged',
            "{} was not added as a tagged member of {}".format(port, vlan_name))

        ptf_indices = ptf_indices_for_ports(duthost, ptfhost, tbinfo, enum_frontend_asic_index,
                                            [port, peer_a, peer_b])
        if any(p not in ptf_indices for p in (port, peer_a, peer_b)):
            pytest.skip("Borrowed ports {} have no PTF dataplane index on this "
                        "topology; cannot inject traffic.".format((port, peer_a, peer_b)))

        pkt = build_icmp_packet(vlan_id=vlan_id)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

        peer_ptf_indices = [ptf_indices[peer_a], ptf_indices[peer_b]]
        logger.info("Sending VLAN-tagged(%d) broadcast ICMP into new member %s (ptf idx %d), expecting "
                    "still-tagged delivery on ALL existing members %s (ptf idx %s)",
                    vlan_id, port, ptf_indices[port], (peer_a, peer_b), peer_ptf_indices)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_indices[port], pkt)
        verify_flood_to_all_ports(ptfadapter, exp_pkt, peer_ptf_indices)
    finally:
        for p in (port, peer_a, peer_b):
            duthost.shell("config vlan member del {} {}".format(vlan_id, p), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)
