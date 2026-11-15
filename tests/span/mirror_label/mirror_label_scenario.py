'''
Scenario shared by the label persistence and warm reboot tests: three ERSPAN sessions, an ACL rule, port mirroring
and the checks that must hold before and after a restart of the DUT.

Test plan: docs/testplan/Mirror-session-label-test-plan.md

Sessions lbl_persist_01 .. lbl_persist_03, each with its own destination and (except one) its own label.
They are created from the highest number to the lowest, while orchagent replays them from CONFIG_DB in key
(alphabetical) order, i.e. from the lowest number to the highest. A label that is restored together with its
session, and not just through the order of re-creation, shows up as a correct label <-> destination pair after
the restart. Only ERSPAN sessions are used.
'''

import logging

import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from mirror_label_helpers import (
    ACL_RULE_SRC_IP,
    SESSION_PREFIX,
    acl_rule_mirror_session,
    assert_label_in_all_layers,
    assert_no_label,
    asic_db_label_by_dst,
    collect_gre_by_dst,
    create_erspan_session,
    erspan_dst_ip,
    wait_sessions_active,
)

logger = logging.getLogger(__name__)

NUM_SESSIONS = 3          # three mirror sessions fit every supported platform (some HW holds no more)
UNLABELED_NUMBER = 2
ACL_NUMBER = 3            # mirrored by the ACL rule
PORT_MIRROR_NUMBER = 1    # mirrors the ingress of the source port
TRAFFIC_DST_IP = "30.0.0.10"


def session(number):
    '''Return (name, label or None, destination IP) of session number 1..NUM_SESSIONS.'''
    name = "{}persist_{:02d}".format(SESSION_PREFIX, number)
    label = None if number == UNLABELED_NUMBER else "P{:02d}".format(number)
    return name, label, erspan_dst_ip(number - 1)


def initial_labels():
    '''Return {session number: label or None} as created.'''
    return {number: session(number)[1] for number in range(1, NUM_SESSIONS + 1)}


def create_sessions(duthost, src_port_name):
    '''Create the sessions from the highest number to the lowest; the lowest one mirrors the source port.'''
    for number in range(NUM_SESSIONS, 0, -1):
        name, label, dst = session(number)
        port_args = {"src_port": src_port_name, "direction": "rx"} if number == PORT_MIRROR_NUMBER else {}
        create_erspan_session(duthost, name, dst, label=label, **port_args)


def make_packet(duthost, ptfadapter, src_index):
    '''A packet that matches the ACL rule and enters the source port.'''
    return testutils.simple_ip_packet(eth_src=ptfadapter.dataplane.get_mac(0, src_index),
                                      eth_dst=duthost.facts["router_mac"],
                                      ip_src=ACL_RULE_SRC_IP, ip_dst=TRAFFIC_DST_IP)


def mirrored_destinations():
    '''Return (destination mirrored by the ACL, destination mirrored by the port, the other destinations).'''
    dst_acl, dst_port = session(ACL_NUMBER)[2], session(PORT_MIRROR_NUMBER)[2]
    others = [session(n)[2] for n in range(1, NUM_SESSIONS + 1) if n not in (ACL_NUMBER, PORT_MIRROR_NUMBER)]
    return dst_acl, dst_port, others


def check_mirror_traffic(duthost, ptfadapter, label_ports, route):
    '''
    One packet matching the ACL rule enters the source port: the ACL mirrors it to the ACL session and the
    port mirror of the port-mirror session copies it too; every other session mirrors nothing. Every copy
    goes to its own destination, exactly once. The port mirror also copies background packets of the PTF
    host, so only frames that carry the test packet (its source IP) are counted.
    '''
    src = label_ports["src"]
    dst_acl, dst_port, others = mirrored_destinations()
    pkt = make_packet(duthost, ptfadapter, src["index"])
    ptfadapter.dataplane.flush()
    # frames still queued on the PTF port before the test packet is sent (leftovers of earlier traffic)
    leftovers = collect_gre_by_dst(ptfadapter, route["ptf_index"], timeout=1)
    if leftovers:
        logger.warning("ERSPAN frames present BEFORE sending the test packet: %s", leftovers)
    testutils.send(ptfadapter, src["index"], pkt)
    frames = []
    counts = collect_gre_by_dst(ptfadapter, route["ptf_index"], timeout=3, details=frames,
                                inner_ip_src=ACL_RULE_SRC_IP)
    logger.info("Mirrored frames by outer destination: %s; frames (t, dst, ip id): %s", counts, frames)
    pytest_assert(counts.get(dst_acl) == 1,
                  "Expected one copy for the ACL session ({}), got {}".format(dst_acl, counts))
    pytest_assert(counts.get(dst_port) == 1,
                  "Expected one copy for the port-mirror session ({}), got {}".format(dst_port, counts))
    pytest_assert(not any(dst in counts for dst in others),
                  "Other sessions must mirror nothing, got {}".format(counts))


def assert_state(duthost, asic, expected, ptfadapter, label_ports, route):
    '''
    expected: {session number: label or None}. Every session is active and carries its own label in every
    layer, the label <-> destination pairs in ASIC_DB are right, the ACL is bound to the ACL session and
    mirrored traffic is as expected.
    '''
    wait_sessions_active(asic, [session(n)[0] for n in range(1, NUM_SESSIONS + 1)])
    for number, label in expected.items():
        name = session(number)[0]
        if label is None:
            assert_no_label(duthost, asic, name)
        else:
            assert_label_in_all_layers(duthost, asic, name, label)
    expected_by_dst = {session(n)[2]: label for n, label in expected.items()}
    actual_by_dst = asic_db_label_by_dst(asic)
    pytest_assert(actual_by_dst == expected_by_dst,
                  "ASIC_DB label per destination differs.\nexpected: {}\nactual:   {}".format(
                      expected_by_dst, actual_by_dst))
    acl_name = session(ACL_NUMBER)[0]
    pytest_assert(acl_rule_mirror_session(asic) == acl_name,
                  "ACL rule points to {!r}, expected {}".format(acl_rule_mirror_session(asic), acl_name))
    check_mirror_traffic(duthost, ptfadapter, label_ports, route)
