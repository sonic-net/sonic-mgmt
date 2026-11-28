# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
MSTP on the three-bridge l2-topo.

MSTP elects a root per instance and either forms a single region across all
three bridges or is deliberately mismatched so that exactly one leg becomes a
boundary.

Every BPDU here is addressed to 01:80:C2:00:00:00, which PVST uses only on the
native VLAN. If these fail while PVST passes, read the topology gates first.

"""
import logging
import time

import pytest

from .l2topo import (FORWARDING, IEEE_BPDU_MAC, MST, assert_boundary_legs, capture_end, forwarding_legs,
                     is_blocked, leg_states, wait_for_value, wait_until)

from .conftest import MST_REGION, MST_REVISION, make_t1_root

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]

MODE = MST
CIST = 0
MSTI_1 = 1
MSTI_2 = 2


@pytest.fixture(scope="class")
def regioned(mstp):
    """One region across all three bridges, with an instance per VLAN where the
        build allows it. Cases needing two trees stand down where only the CIST can
        be reached, rather than collapsing onto it and passing without testing
        anything.
    """
    topo = mstp
    usable = [CIST]
    # Both conditions have to hold: the build must be able to create an
    # instance, and the topology must have a second VLAN to map to it. An
    # instance is only distinguishable from the CIST by the VLANs it owns.
    if len(topo.vlans) >= 2 and topo.t0_1.msti_supported():
        v1, v2 = topo.vlans[0], topo.vlans[1]
        for node in topo.all_nodes():
            node.mst_map_vlan(MSTI_1, v1)
            node.mst_map_vlan(MSTI_2, v2)
        make_t1_root(topo, MODE, [MSTI_1, MSTI_2])
        usable += [MSTI_1, MSTI_2]
    elif len(topo.vlans) < 2:
        logger.warning(
            "this topology has %d VLAN, so there is nothing to map to a second "
            "instance; the multi instance cases will stand down", len(topo.vlans))
    else:
        logger.warning(
            "this build cannot create an MST instance beyond the CIST, so the "
            "multi instance cases will stand down")
    topo.usable_instances = usable
    yield topo
    if len(usable) > 1:
        for node in topo.all_nodes():
            node.mst_unmap_vlan(MSTI_1, topo.vlans[0])
            node.mst_unmap_vlan(MSTI_2, topo.vlans[1])


def _need_mstis(topo):
    if len(getattr(topo, "usable_instances", [CIST])) < 3:
        pytest.skip(
            "this build has no MST instance beyond the CIST: mapping a VLAN and "
            "setting a priority both refuse with \"instance does not exist\", and "
            "there is no create command, so a second tree cannot be built to "
            "compare against")


def _blocked_legs(topo, scope):
    return sorted(leg.role for leg in topo.legs
                  if any(is_blocked(st) for st in leg_states(leg, MODE, scope)))


def _instances_split_by_priority(topo):
    """On a triangle with one leg per pair of bridges, path diversity comes from
            priority: give instance 2 a different root and the switch under test has
            to reach it over a different port, while instance 1 stays exactly as it
            was. This is how MSTP spreads VLANs over links.
    """
    sut, new_root = topo.t0_1, topo.t0_2
    for scope in (MSTI_1, MSTI_2):
        assert topo.converge(MODE, scope), "instance {} never settled: {}".format(
            scope, topo.port_states(MODE, scope))
    assert topo.t1.is_self_root(MODE, MSTI_1) and topo.t1.is_self_root(MODE, MSTI_2), (
        "the t1 is not root of both instances to begin with: {} {}".format(
            topo.t1.bridge_data(MODE, MSTI_1), topo.t1.bridge_data(MODE, MSTI_2)))
    before_1 = topo.port_states(MODE, MSTI_1)
    root_port_1 = sut.root_port(MODE, MSTI_1)
    blocked_1 = _blocked_legs(topo, MSTI_1)

    new_root.set_bridge_priority(MODE, MSTI_2, 4096)
    try:
        ok = wait_until(150, 3, lambda: new_root.is_self_root(MODE, MSTI_2),
                        "{} becomes root of instance {}".format(new_root.name, MSTI_2))
        assert ok, "{} did not become root of instance {} at priority 4096: {}".format(
            new_root.name, MSTI_2, new_root.bridge_data(MODE, MSTI_2))
        assert topo.converge(MODE, MSTI_2, timeout=180), "instance {} never settled: {}".format(
            MSTI_2, topo.port_states(MODE, MSTI_2))
        root_port_2 = sut.root_port(MODE, MSTI_2)
        blocked_2 = _blocked_legs(topo, MSTI_2)
        logger.info("%s root port: instance %d %s, instance %d %s; blocked legs %s and %s",
                    sut.name, MSTI_1, root_port_1, MSTI_2, root_port_2, blocked_1, blocked_2)
        assert root_port_2 not in ("", "Root", root_port_1), (
            "{} reaches the root of instance {} over {}, the same port as instance {} "
            "({}); the instances are not using different links".format(
                sut.name, MSTI_2, root_port_2, MSTI_1, root_port_1))
        assert blocked_2 != blocked_1, (
            "both instances block the same legs ({}); a different root has to give up "
            "a different leg".format(blocked_1))
        assert topo.port_states(MODE, MSTI_1) == before_1, (
            "instance {} changed while only instance {} was reconfigured.\n"
            "before: {}\nafter:  {}".format(
                MSTI_1, MSTI_2, before_1, topo.port_states(MODE, MSTI_1)))
    finally:
        new_root.set_bridge_priority(MODE, MSTI_2, 32768)
        topo.converge(MODE, MSTI_2, timeout=180)


@pytest.mark.usefixtures("regioned")
class TestMstpL2Topo(object):

    def test_all_three_bridges_form_one_region(self, topo):
        """Region name, revision and VLAN map have to agree, or there is no region."""
        configs = {}
        for node in topo.all_nodes():
            # Read once per poll, so the value reported is the one checked.
            ok, seen = wait_for_value(60, 3, lambda n=node: (
                lambda cfg: (bool(cfg.get("name")), cfg))(n.region_config()))
            assert ok, "{} never published an MST region config".format(node.name)
            configs[node.name] = seen

        names = {c.get("name") for c in configs.values()}
        revisions = {c.get("revision") for c in configs.values()}
        assert names == {MST_REGION}, \
            "bridges disagree on region name: {}".format(configs)
        assert len(revisions) == 1, \
            "bridges disagree on revision: {}".format(configs)

        # Agreement on the map is what the digest encodes, so check it converged.
        assert topo.converge(MODE, CIST), \
            "the CIST never settled: {}".format(topo.port_states(MODE, CIST))

        # One region has one regional root, and every bridge has to name it.
        # This is what the daemon publishes, not a read-back of the config.
        def _regional_roots():
            return {n.name: n.bridge_data(MODE, CIST).get("regional_root_address", "")
                    for n in topo.all_nodes()}
        ok, seen = wait_for_value(60, 3, lambda: (
            all(_regional_roots().values()) and len(set(_regional_roots().values())) == 1,
            _regional_roots()))
        assert ok, "bridges disagree on the regional root, or one does not publish it: {}".format(seen)

    def test_the_cist_and_regional_roots_are_reported_consistently(self, topo):
        """All three bridges have to name the same root, on every instance."""
        for scope in topo.usable_instances:
            topo.converge(MODE, scope)
            roots = {n.name: n.root_bridge_id(MODE, scope) for n in topo.all_nodes()}
            distinct = {r for r in roots.values() if r}
            assert len(distinct) == 1, (
                "bridges disagree on the root for instance {}: {}".format(scope, roots))
            assert topo.t1.is_self_root(MODE, scope), (
                "the t1 is not the root for instance {}: {}".format(
                    scope, topo.t1.bridge_data(MODE, scope)))

    def test_different_instances_select_different_links(self, topo):
        """Instance level path diversity. Costing one member of the parallel pair up
                for one instance has to move that instance and leave the other where it
                was.
        """
        _need_mstis(topo)
        if not topo.has_parallel_pair:
            _instances_split_by_priority(topo)
            return
        leg_a, leg_b = topo.parallel_legs
        sut = topo.t0_1
        for scope in (MSTI_1, MSTI_2):
            topo.converge(MODE, scope)
        baseline = sut.root_port(MODE, MSTI_1)

        sut.set_port_cost(MODE, MSTI_2, leg_a.b_port, 20000)
        try:
            ok, seen = wait_for_value(120, 3, lambda: (
                sut.root_port(MODE, MSTI_2) not in ("", baseline),
                sut.root_port(MODE, MSTI_2)))
            assert ok, (
                "instance {} stayed on {} after {} was costed up for it alone; the "
                "instances are not selecting links independently".format(
                    MSTI_2, seen, leg_a.b_port))
            assert sut.root_port(MODE, MSTI_1) == baseline, (
                "instance {} moved from {} to {} when only instance {} was "
                "reconfigured".format(MSTI_1, baseline, sut.root_port(MODE, MSTI_1), MSTI_2))
        finally:
            sut.set_port_cost(MODE, MSTI_2, leg_a.b_port, 200)
            topo.converge(MODE, MSTI_2)

    def test_a_deliberate_mismatch_makes_exactly_one_boundary(self, topo):
        """The boundary case, and the reason three bridges are the minimum. Moving
                one bridge to a different region turns its legs into boundaries while
                CIST connectivity across the triangle survives.
        """
        odd = topo.t0_2
        boundary_legs = [leg for leg in topo.legs
                         if odd in (leg.a, leg.b)]
        assert boundary_legs, "the odd bridge has no legs"

        odd.set_region("other-region", MST_REVISION + 1)
        try:
            ok = wait_until(120, 3,
                            lambda: odd.region_config().get("name") == "other-region",
                            "region change applied")
            assert ok, "{} did not take the new region name: {}".format(
                odd.name, odd.region_config())

            # CIST has to keep the triangle connected across the boundary.
            assert topo.converge(MODE, CIST, timeout=180), (
                "the CIST did not settle after the region split: {}".format(
                    topo.port_states(MODE, CIST)))
            states = [odd.port_state(MODE, CIST, port) for port in odd.ports.values()]
            assert FORWARDING in states, (
                "{} has no forwarding CIST port after being moved out of the region; "
                "the boundary cut it off instead of making it a boundary. States: {}"
                .format(odd.name, dict(zip(odd.ports.values(), states))))

            # The bridges still in the region have to stay in it.
            for node in (topo.t1, topo.t0_1):
                assert node.region_config().get("name") == MST_REGION, (
                    "{} left the region when only {} was reconfigured".format(
                        node.name, odd.name))
            # And the daemon has to report the boundary where it is.
            assert_boundary_legs(topo, odd)
        finally:
            odd.set_region(MST_REGION, MST_REVISION)
            topo.converge(MODE, CIST, timeout=180)

    def test_hop_count_decrements_across_the_region(self, topo):
        """Inside a region the CIST uses hop count, not message age. Each bridge away
                from the regional root sees one fewer hop, which needs more than two
                bridges to observe.
        """
        topo.converge(MODE, CIST)
        counts = {}
        for node in topo.all_nodes():
            data = node.bridge_data(MODE, CIST)
            value = data.get("remaining_hops") or data.get("hop_count") or data.get("max_hops")
            counts[node.name] = value
        present = {k: v for k, v in counts.items() if v not in (None, "")}
        if not present:
            pytest.skip("this build publishes no hop count field on {}; "
                        "bridge row was {}".format(
                            MST, topo.t1.bridge_data(MODE, CIST)))
        root_hops = present.get(topo.t1.name)
        downstream = [int(v) for k, v in present.items() if k != topo.t1.name]
        assert root_hops is not None and downstream, \
            "not enough hop count data to compare: {}".format(present)
        assert all(d < int(root_hops) for d in downstream), (
            "hop count did not decrement away from the regional root: {}".format(present))

    @pytest.mark.usefixtures("restore_legs")
    def test_root_fails_over_per_instance(self, topo):
        """Each instance has to reroute on its own when the preferred uplink goes."""
        scope = topo.usable_instances[-1]
        topo.converge(MODE, scope)
        uplink = topo.leg("uplink-b")
        # The shut leg's own rows change the moment it goes down, so they are
        # left out: the reroute has to show on the other ports.
        shut = {"{}:{}".format(n.name, p) for n, _e, p in uplink.ends()}

        def _others():
            return {k: v for k, v in topo.port_states(MODE, scope).items() if k not in shut}

        before = _others()
        survivors = sorted(leg.role for leg in topo.legs if leg is not uplink)

        uplink.set_up(False)
        try:
            ok = wait_until(180, 2, lambda: _others() != before,
                            "instance {} reroutes".format(scope))
            assert ok, (
                "instance {} did not reroute after the t0 uplink failed; the other "
                "ports are unchanged at {}".format(scope, before))
            assert topo.converge(MODE, scope, timeout=180), (
                "instance {} never settled after the failover: {}".format(
                    scope, topo.port_states(MODE, scope)))
            # Failover means the two legs that are left carry the instance.
            ok, seen = wait_for_value(120, 3, lambda: (
                sorted(lg.role for lg in forwarding_legs(topo, MODE, scope)) == survivors,
                sorted(lg.role for lg in forwarding_legs(topo, MODE, scope))))
            assert ok, (
                "instance {} is not forwarding on both remaining legs after the "
                "failover: forwarding {}, expected {}".format(scope, seen, survivors))
        finally:
            uplink.set_up(True)
            topo.converge(MODE, scope, timeout=180)

    @pytest.mark.usefixtures("restore_legs")
    def test_a_topology_change_is_scoped_to_the_affected_instance(self, topo):
        """A change on one instance must not disturb the other's tree."""
        _need_mstis(topo)
        disturbed, control = MSTI_1, MSTI_2
        for scope in (disturbed, control):
            topo.converge(MODE, scope)
        control_before = topo.port_states(MODE, control)

        topo.t0_2.set_bridge_priority(MODE, disturbed, 4096)
        try:
            ok = wait_until(150, 3, lambda: topo.t0_2.is_self_root(MODE, disturbed),
                            "instance {} moves its root".format(disturbed))
            assert ok, "instance {} did not move its root to {}: {}".format(
                disturbed, topo.t0_2.name, topo.t0_2.bridge_data(MODE, disturbed))
            control_after = topo.port_states(MODE, control)
            assert control_after == control_before, (
                "instance {} changed while only instance {} was reconfigured.\n"
                "before: {}\nafter:  {}".format(control, disturbed,
                                                control_before, control_after))
        finally:
            topo.t0_2.set_bridge_priority(MODE, disturbed, 32768)
            topo.converge(MODE, disturbed)

    def test_every_leg_carries_ieee_bpdus(self, topo):
        """MSTP BPDUs are addressed to 01:80:C2:00:00:00 on every leg. A leg that
                carries PVST but not this is a bridged leg, not a protocol fault.
        """
        for leg in topo.legs:
            node, eth = capture_end(leg)
            assert node is not None, "leg {} has no capturable end".format(leg.role)
            cap = node.capture_bpdus(eth, seconds=10)
            assert cap["ieee"], (
                "leg {} carried no frame addressed to {} in 10s, watched at {}. "
                "PVST frames seen: {}.".format(
                    leg.role, IEEE_BPDU_MAC, node.name, cap["pvst"]))
            logger.info("leg %-10s ieee=%d", leg.role, cap["ieee"])

    def test_convergence_time_is_measured_per_instance(self, topo, convergence_log):
        """Recorded per instance rather than held to a threshold."""
        uplink = topo.leg("uplink-b")
        scopes = topo.usable_instances
        for scope in scopes:
            topo.converge(MODE, scope)
        before = {s: topo.port_states(MODE, s) for s in scopes}

        uplink.set_up(False)
        start = time.time()
        try:
            # Every instance is timed from the same link event, polled together.
            times = topo.settle_times(MODE, before, start, timeout=180)
            for scope in scopes:
                assert scope in times, (
                    "instance {} never reconverged in 180s: {}".format(
                        scope, topo.port_states(MODE, scope)))
                convergence_log.append({"mode": MODE, "scope": scope,
                                        "event": "uplink-b down",
                                        "seconds": round(times[scope], 2)})
                logger.info("MSTP instance %s reconverged in %.2fs", scope, times[scope])
        finally:
            uplink.set_up(True)
            for scope in scopes:
                topo.converge(MODE, scope, timeout=180)
