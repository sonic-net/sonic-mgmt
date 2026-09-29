"""
gRIBI agent (gribid) tests: routes programmed over gRIBI reach orchagent's
ZeroMQ route channel, the ASIC, and APPL_STATE_DB, and every route's
FIB_PROGRAMMED reflects orchagent's answer.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.gribi.helper import (GRIBI_SERVICE, asic_next_hops, final_status, gribi_listening, nh_op, nhg_op,
                                restart_gribi, route_op, state_protocol)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
]

# Benchmarking and documentation ranges, so no BGP route shares the prefix.
PREFIX_V4 = "198.18.10.0/24"
PREFIX_V6 = "2001:db8:20::/64"
PREFIX_UNRESOLVED = "198.18.11.0/24"
PREFIX_VRF = "198.18.12.0/24"
UNRESOLVED_NH = "192.0.2.1"


def programmed(duthost, prefix, want_nhs, vrf=None):
    return (state_protocol(duthost, prefix, vrf) == "gribi"
            and asic_next_hops(duthost, prefix) == sorted(want_nhs))


def removed(duthost, prefix, vrf=None):
    return state_protocol(duthost, prefix, vrf) is None and asic_next_hops(duthost, prefix) is None


def delete_route(client, prefix, nhg_id, nh_indexes, ni="DEFAULT"):
    ops = [route_op(1, prefix, nhg_id, ni=ni, op="DELETE"), nhg_op(2, nhg_id, [], ni=ni, op="DELETE")]
    ops += [nh_op(3 + i, idx, ni=ni, op="DELETE") for i, idx in enumerate(nh_indexes)]
    return client.modify(ops)


def test_gribi_service_is_served(gribi_client):
    pytest_assert(GRIBI_SERVICE in gribi_client.services(), "gRIBI is not served")


def test_ipv4_ecmp_add_replace_delete(gribi_dut, gribi_client, uplinks_v4):
    (_, _, nh_a), (_, _, nh_b) = uplinks_v4[0], uplinks_v4[1]
    try:
        statuses, errors = gribi_client.modify([
            nh_op(1, 101, nh_a), nh_op(2, 102, nh_b),
            nhg_op(3, 100, [(101, 1), (102, 1)]),
            route_op(4, PREFIX_V4, 100),
        ])
        pytest_assert(final_status(statuses, 4) == "FIB_PROGRAMMED",
                      "add: {} {}".format(statuses.get(4), errors.get(4)))
        pytest_assert(wait_until(15, 1, 0, programmed, gribi_dut, PREFIX_V4, [nh_a, nh_b]),
                      "{} not programmed over {} and {}".format(PREFIX_V4, nh_a, nh_b))

        # Replacing the group re-sends every route that uses it.
        statuses, errors = gribi_client.modify([nhg_op(1, 100, [(101, 1)], op="REPLACE")])
        pytest_assert(final_status(statuses, 1) == "FIB_PROGRAMMED",
                      "replace: {} {}".format(statuses.get(1), errors.get(1)))
        pytest_assert(wait_until(15, 1, 0, programmed, gribi_dut, PREFIX_V4, [nh_a]),
                      "{} still uses more than {} after the group shrank".format(PREFIX_V4, nh_a))
    finally:
        statuses, errors = delete_route(gribi_client, PREFIX_V4, 100, [101, 102])
    pytest_assert(final_status(statuses, 1) == "FIB_PROGRAMMED",
                  "delete: {} {}".format(statuses.get(1), errors.get(1)))
    pytest_assert(wait_until(15, 1, 0, removed, gribi_dut, PREFIX_V4), "{} not removed".format(PREFIX_V4))


def test_ipv6_add_delete(gribi_dut, gribi_client, uplinks_v6):
    nh = uplinks_v6[0][2]
    try:
        statuses, errors = gribi_client.modify([
            nh_op(1, 201, nh), nhg_op(2, 200, [(201, 1)]), route_op(3, PREFIX_V6, 200),
        ])
        pytest_assert(final_status(statuses, 3) == "FIB_PROGRAMMED",
                      "add: {} {}".format(statuses.get(3), errors.get(3)))
        pytest_assert(wait_until(15, 1, 0, programmed, gribi_dut, PREFIX_V6, [nh]),
                      "{} not programmed over {}".format(PREFIX_V6, nh))
    finally:
        delete_route(gribi_client, PREFIX_V6, 200, [201])
    pytest_assert(wait_until(15, 1, 0, removed, gribi_dut, PREFIX_V6), "{} not removed".format(PREFIX_V6))


def test_unresolved_next_hop_is_fib_failed(gribi_dut, gribi_client):
    try:
        statuses, errors = gribi_client.modify([
            nh_op(1, 301, UNRESOLVED_NH), nhg_op(2, 300, [(301, 1)]), route_op(3, PREFIX_UNRESOLVED, 300),
        ])
        pytest_assert(final_status(statuses, 3) == "FIB_FAILED",
                      "route over {}: {}".format(UNRESOLVED_NH, statuses.get(3)))
        pytest_assert(UNRESOLVED_NH in errors.get(3, ""), "error does not name the next hop: {}".format(errors))
        pytest_assert(asic_next_hops(gribi_dut, PREFIX_UNRESOLVED) is None,
                      "{} reached the ASIC over an unresolved next hop".format(PREFIX_UNRESOLVED))
    finally:
        delete_route(gribi_client, PREFIX_UNRESOLVED, 300, [301])


def test_route_in_vrf(gribi_dut, gribi_client, gribi_vrf):
    vrf, _, peer = gribi_vrf
    try:
        statuses, errors = gribi_client.modify([
            nh_op(1, 401, peer, ni=vrf), nhg_op(2, 400, [(401, 1)], ni=vrf), route_op(3, PREFIX_VRF, 400, ni=vrf),
        ])
        pytest_assert(final_status(statuses, 3) == "FIB_PROGRAMMED",
                      "add in {}: {} {}".format(vrf, statuses.get(3), errors.get(3)))
        pytest_assert(wait_until(15, 1, 0, programmed, gribi_dut, PREFIX_VRF, [peer], vrf),
                      "{} not programmed in {} over {}".format(PREFIX_VRF, vrf, peer))
    finally:
        delete_route(gribi_client, PREFIX_VRF, 400, [401], ni=vrf)
    pytest_assert(wait_until(15, 1, 0, removed, gribi_dut, PREFIX_VRF, vrf),
                  "{} not removed from {}".format(PREFIX_VRF, vrf))


def test_feature_disable_stops_gribi(gribi_dut):
    try:
        gribi_dut.shell("sudo config feature state gribi disabled")
        pytest_assert(wait_until(30, 2, 0, lambda: not gribi_listening(gribi_dut)),
                      "gRIBI still listening with the feature disabled")
    finally:
        gribi_dut.shell("sudo config feature state gribi enabled")
        restart_gribi(gribi_dut)
