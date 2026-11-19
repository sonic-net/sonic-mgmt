"""
L2 hardening: VLAN member add/delete forwarding-plane tests.
"""
import logging

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

from tests.common.gu_utils import apply_patch, expect_op_success, generate_tmpfile, delete_tmpfile, create_path
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.portchannel_to_vlan import build_icmp_packet
from tests.common.utilities import wait_until
from tests.common.helpers.vlan_hardening import ignore_expected_loganalyzer_exceptions  # noqa: F401
from tests.common.helpers.vlan_hardening import (
    borrow_ports,
    get_config_facts,
    get_vlan_members,
    pick_free_vlan_id,
    ptf_indices_for_ports,
    release_prior_membership,
    restore_borrowed_port,
    state_db_vlan_member_tagging_mode,
    verify_flood_to_all_ports,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Candidate range for the temporary test VLAN, probed via pick_free_vlan_id()
# so a leftover VLAN from an aborted prior run can't collide with this test.
TEST_VLAN_ID_RANGE = range(1030, 1040)


def _borrow_test_ports(duthost, tbinfo, enum_frontend_asic_index, ptfhost, count=3, min_count=None):
    # Borrow and map up to `count` PTF-wired ports, proceeding with at least `min_count` or skipping.
    if min_count is None:
        min_count = count
    borrowed = borrow_ports(duthost, tbinfo, enum_frontend_asic_index, count)
    if len(borrowed) < min_count:
        pytest.skip("Not enough usable ports to run this test: found {}, need at least {}".format(
            len(borrowed), min_count))
    if len(borrowed) < count:
        logger.warning(
            "Only found %d of %d requested usable ports on this DUT/topology; proceeding with "
            "reduced coverage (e.g. flood verification may only reach %d peer(s) instead of the "
            "full set).", len(borrowed), count, len(borrowed) - 1)

    ports = [b["port"] for b in borrowed]
    for descriptor in borrowed:
        release_prior_membership(duthost, descriptor)

    ptf_indices = ptf_indices_for_ports(duthost, ptfhost, tbinfo, enum_frontend_asic_index, ports)
    if any(p not in ptf_indices for p in ports):
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)
        pytest.skip("Borrowed ports {} have no PTF dataplane index on this topology; "
                    "cannot inject traffic.".format(ports))

    return borrowed, ports, ptf_indices


def setup_test_vlan(duthost, asic, vlan_id, ports, untagged):
    # Create the test VLAN and add `ports` as members, tagged or untagged.
    duthost.shell("config vlan add {}".format(vlan_id))
    vlan_key = "Vlan{}".format(vlan_id)
    expected_mode = 'untagged' if untagged else 'tagged'
    for port in ports:
        flag = " --untagged" if untagged else ""
        duthost.shell("config vlan member add {} {}{}".format(vlan_id, port, flag))
        pytest_assert(
            wait_until(10, 1, 0,
                       lambda p=port: state_db_vlan_member_tagging_mode(asic, vlan_key, p) == expected_mode),
            "STATE_DB VLAN_MEMBER_TABLE|{}|{} tagging_mode did not become {!r} after member add "
            "(currently {!r}) -- control plane (vlanmgrd) never applied the change".format(
                vlan_key, port, expected_mode, state_db_vlan_member_tagging_mode(asic, vlan_key, port)))


def teardown_test_vlan(duthost, vlan_id, ports):
    # Best-effort cleanup: remove test VLAN members, then delete the VLAN.
    for port in ports:
        duthost.shell("config vlan member del {} {}".format(vlan_id, port), module_ignore_errors=True)
    duthost.shell("config vlan del {}".format(vlan_id), module_ignore_errors=True)


def _setup_untagged_forwarding_baseline(duthost, asic, vlan_id, ptf_indices, test_ports):
    # Create a test VLAN, add untagged members, verify flooding, and return state; supports reduced peer coverage.
    p_port, *peer_ports = test_ports

    setup_test_vlan(duthost, asic, vlan_id, test_ports, untagged=True)

    config_facts = get_config_facts(duthost)
    vlan_key = "Vlan{}".format(vlan_id)
    vlan_members = get_vlan_members(config_facts, vlan_key)
    pytest_assert(p_port in vlan_members,
                  "{} was not added as a member of {} in CONFIG_DB".format(p_port, vlan_key))
    pytest_assert(vlan_members[p_port]['tagging_mode'] == 'untagged',
                  "{} member of {} has tagging_mode {!r}, expected 'untagged'".format(
                      p_port, vlan_key, vlan_members[p_port]['tagging_mode']))

    p_idx = ptf_indices[p_port]
    peer_idxs = [ptf_indices[peer] for peer in peer_ports]

    pkt = build_icmp_packet(vlan_id=0)
    return p_port, peer_ports, p_idx, peer_idxs, pkt


def test_untagged_member_forwarding(duthosts, rand_one_dut_hostname, ptfadapter, ptfhost, tbinfo,
                                    enum_frontend_asic_index):
    # Verify untagged VLAN member config and broadcast flooding to ALL peers in one test.
    duthost = duthosts[rand_one_dut_hostname]
    borrowed, test_ports, ptf_indices = _borrow_test_ports(
        duthost, tbinfo, enum_frontend_asic_index, ptfhost, count=3)
    vlan_id = pick_free_vlan_id(get_config_facts(duthost), TEST_VLAN_ID_RANGE)
    asic = duthost.asic_instance(enum_frontend_asic_index)

    try:
        p_port, peer_ports, p_idx, peer_idxs, pkt = _setup_untagged_forwarding_baseline(
            duthost, asic, vlan_id, ptf_indices, test_ports)

        logger.info("Sending untagged broadcast ICMP from %s (ptf idx %d), expecting delivery on ALL of %s "
                    "(ptf idx %s)", p_port, p_idx, peer_ports, peer_idxs)
        logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, p_idx, pkt)
        verify_flood_to_all_ports(ptfadapter, pkt, peer_idxs)
    finally:
        teardown_test_vlan(duthost, vlan_id, test_ports)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)


def test_tagged_member_forwarding(duthosts, rand_one_dut_hostname, ptfadapter, ptfhost, tbinfo,
                                  enum_frontend_asic_index):
    # Verify tagged VLAN member config and tagged broadcast flooding to ALL peers, including VLAN ID on egress.
    duthost = duthosts[rand_one_dut_hostname]
    borrowed, test_ports, ptf_indices = _borrow_test_ports(
        duthost, tbinfo, enum_frontend_asic_index, ptfhost, count=3)
    p_port, peer1, peer2 = test_ports
    peer_ports = [peer1, peer2]
    vlan_id = pick_free_vlan_id(get_config_facts(duthost), TEST_VLAN_ID_RANGE)
    asic = duthost.asic_instance(enum_frontend_asic_index)

    try:
        setup_test_vlan(duthost, asic, vlan_id, test_ports, untagged=False)

        config_facts = get_config_facts(duthost)
        vlan_key = "Vlan{}".format(vlan_id)
        vlan_members = get_vlan_members(config_facts, vlan_key)
        pytest_assert(p_port in vlan_members,
                      "{} was not added as a member of {} in CONFIG_DB".format(p_port, vlan_key))
        pytest_assert(vlan_members[p_port]['tagging_mode'] == 'tagged',
                      "{} member of {} has tagging_mode {!r}, expected 'tagged'".format(
                          p_port, vlan_key, vlan_members[p_port]['tagging_mode']))

        p_idx = ptf_indices[p_port]
        peer_idxs = [ptf_indices[peer] for peer in peer_ports]

        pkt = build_icmp_packet(vlan_id=vlan_id)

        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

        logger.info("Sending tagged(%d) broadcast ICMP from %s (ptf idx %d), expecting still-tagged "
                    "delivery on ALL of %s (ptf idx %s)", vlan_id, p_port, p_idx, peer_ports, peer_idxs)
        logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, p_idx, pkt)
        verify_flood_to_all_ports(ptfadapter, exp_pkt, peer_idxs)
    finally:
        teardown_test_vlan(duthost, vlan_id, test_ports)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)


def test_delete_member_stops_forwarding(duthosts, rand_one_dut_hostname, ptfadapter, ptfhost, tbinfo,
                                        enum_frontend_asic_index):
    # Verify deleting an untagged VLAN member stops previously working broadcast forwarding.
    duthost = duthosts[rand_one_dut_hostname]
    borrowed, test_ports, ptf_indices = _borrow_test_ports(
        duthost, tbinfo, enum_frontend_asic_index, ptfhost, count=3)
    vlan_id = pick_free_vlan_id(get_config_facts(duthost), TEST_VLAN_ID_RANGE)
    asic = duthost.asic_instance(enum_frontend_asic_index)

    try:
        p_port, peer_ports, p_idx, peer_idxs, pkt = _setup_untagged_forwarding_baseline(
            duthost, asic, vlan_id, ptf_indices, test_ports)

        logger.info("Baseline: sending untagged broadcast ICMP from %s (ptf idx %d), expecting delivery on ALL "
                    "of %s", p_port, p_idx, peer_ports)
        logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, p_idx, pkt)
        verify_flood_to_all_ports(ptfadapter, pkt, peer_idxs)
        logger.info("Baseline forwarding confirmed for %s", p_port)

        logger.info("Deleting %s from Vlan%d", p_port, vlan_id)
        vlan_key = "Vlan{}".format(vlan_id)
        duthost.shell("config vlan member del {} {}".format(vlan_id, p_port))
        pytest_assert(
            wait_until(10, 1, 0, lambda: state_db_vlan_member_tagging_mode(asic, vlan_key, p_port) is None),
            "STATE_DB VLAN_MEMBER_TABLE|{}|{} still present {}s after 'config vlan member del' -- "
            "control plane (vlanmgrd) never applied the removal".format(vlan_key, p_port, 10))

        logger.info("Re-sending identical untagged broadcast ICMP from %s (ptf idx %d) after member deletion; "
                    "expecting ZERO delivery on %s", p_port, p_idx, peer_ports)
        logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, p_idx, pkt)
        testutils.verify_no_packet_any(ptfadapter, pkt, peer_idxs)
        logger.info("Confirmed zero delivery to %s after removing %s from the VLAN", peer_ports, p_port)
    finally:
        teardown_test_vlan(duthost, vlan_id, test_ports)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)


def test_untagged_to_tagged_member_update(duthosts, rand_one_dut_hostname, ptfadapter, ptfhost, tbinfo,
                                          enum_frontend_asic_index):
    # Verify a single config change updates a VLAN member from untagged to tagged in config and forwarding.
    duthost = duthosts[rand_one_dut_hostname]
    # Prefer 3 ports for full flood coverage, but allow 2 since one peer still tests tagging-mode changes.
    borrowed, test_ports, ptf_indices = _borrow_test_ports(
        duthost, tbinfo, enum_frontend_asic_index, ptfhost, count=3, min_count=2)
    vlan_id = pick_free_vlan_id(get_config_facts(duthost), TEST_VLAN_ID_RANGE)
    tmpfile = generate_tmpfile(duthost)
    asic = duthost.asic_instance(enum_frontend_asic_index)

    try:
        p_port, peer_ports, p_idx, peer_idxs, untagged_pkt = _setup_untagged_forwarding_baseline(
            duthost, asic, vlan_id, ptf_indices, test_ports)
        vlan_key = "Vlan{}".format(vlan_id)

        logger.info("Baseline: sending untagged broadcast ICMP from %s (ptf idx %d), expecting delivery on ALL "
                    "of %s", p_port, p_idx, peer_ports)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, p_idx, untagged_pkt)
        verify_flood_to_all_ports(ptfadapter, untagged_pkt, peer_idxs)
        logger.info("Baseline untagged forwarding confirmed for %s", p_port)

        logger.info("Updating %s's tagging_mode under %s from untagged to tagged via a single "
                    "'config apply-patch' JSON patch", p_port, vlan_key)
        json_patch = [
            {
                "op": "replace",
                "path": create_path(["VLAN_MEMBER", "{}|{}".format(vlan_key, p_port), "tagging_mode"]),
                "value": "tagged",
            }
        ]
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        config_facts = get_config_facts(duthost)
        vlan_members = get_vlan_members(config_facts, vlan_key)
        pytest_assert(p_port in vlan_members,
                      "{} disappeared from {} in CONFIG_DB after the tagging_mode patch".format(p_port, vlan_key))
        pytest_assert(vlan_members[p_port]['tagging_mode'] == 'tagged',
                      "{} member of {} has tagging_mode {!r} after the patch, expected 'tagged'".format(
                          p_port, vlan_key, vlan_members[p_port]['tagging_mode']))

        # Confirm vlanmgrd processed the tagging-mode update in STATE_DB before checking dataplane behavior.
        pytest_assert(
            wait_until(10, 1, 0, lambda: state_db_vlan_member_tagging_mode(asic, vlan_key, p_port) == 'tagged'),
            "STATE_DB VLAN_MEMBER_TABLE|{}|{} tagging_mode did not become 'tagged' after the patch "
            "(currently {!r}) -- control plane (vlanmgrd) never applied the change".format(
                vlan_key, p_port, state_db_vlan_member_tagging_mode(asic, vlan_key, p_port)))

        logger.info("Re-sending the same untagged broadcast ICMP from %s (ptf idx %d) now that it is a "
                    "tagged member; expecting ZERO delivery on %s", p_port, p_idx, peer_ports)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, p_idx, untagged_pkt)
        testutils.verify_no_packet_any(ptfadapter, untagged_pkt, peer_idxs)
        logger.info("Confirmed %s no longer forwards untagged traffic as an access member", p_port)

        tagged_pkt = build_icmp_packet(vlan_id=vlan_id)
        logger.info("Sending VLAN-tagged(%d) broadcast ICMP from %s (ptf idx %d); expecting untagged "
                    "delivery on ALL of %s (still-untagged peers strip the tag on egress)",
                    vlan_id, p_port, p_idx, peer_ports)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, p_idx, tagged_pkt)
        verify_flood_to_all_ports(ptfadapter, untagged_pkt, peer_idxs)
        logger.info("Confirmed VLAN-tagged traffic from %s now forwards correctly as a tagged member", p_port)
    finally:
        delete_tmpfile(duthost, tmpfile)
        teardown_test_vlan(duthost, vlan_id, test_ports)
        for descriptor in borrowed:
            restore_borrowed_port(duthost, enum_frontend_asic_index, descriptor)
