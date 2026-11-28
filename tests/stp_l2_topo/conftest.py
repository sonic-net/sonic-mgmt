# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
The l2-topo suite: three SONiC bridges in a triangle, on the `t0-l2tri` topology.

A PTF test injects frames at one switch. It cannot run a spanning tree of its
own, so it cannot check that independent bridges agree on a root, that a leg
blocks because another bridge won, or that traffic follows the elected tree.
Those cases need three bridges and live here.

The topology is read, not restated: the topo file declares the legs, the
testbed declares the DUTs. The bridges take fixed roles by position in the
`dut` list: switch under test, expected root, and its peer.

"""
import logging
import shlex

import pytest

from tests.common.helpers.assertions import pytest_require as require

from .l2topo import MST, PVST, Topology, wait_until

logger = logging.getLogger(__name__)

MST_REGION = "sonic-l2-topo"
MST_REVISION = 1

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    pytest.mark.disable_loganalyzer,
]


def pytest_addoption(parser):
    parser.addoption("--allow-storm", action="store_true",
                     help="run the control case that deliberately creates a broadcast "
                          "storm, which is what shows the loop test can fail")
    parser.addoption("--keep-mode", action="store_true",
                     help="leave the STP mode enabled after the run, for hand debugging")


# Created by the suite on every bridge when ports are enrolled, and carried on
# every leg, tagged.
SECOND_VLAN = 1100

# The t1 is the root by configuration. The virtual bridges get random MACs at
# deployment, so without this the root is a draw.
T1_PRIORITY = 8192


def _runner(host):
    """An ansible host as the (command, timeout) -> (rc, out, err) callable the
        driver wants. Failures are returned, not raised; the driver decides which
        ones matter.
    """
    def run(cmd, timeout=60):
        # host.shell has no timeout of its own, so a hung command would block the run.
        # timeout(1) kills it and returns 124.
        res = host.shell("timeout {} bash -c {}".format(int(timeout), shlex.quote(cmd)),
                         module_ignore_errors=True, verbose=False)
        return res.get("rc", 1), res.get("stdout", ""), res.get("stderr", "")
    return run


@pytest.fixture(scope="session")
def l2_vlan(duthosts, tbinfo):
    """The VLAN the triangle runs in, taken from the first DUT's minigraph."""
    mg = duthosts[0].get_extended_minigraph_facts(tbinfo)
    vlans = mg.get("minigraph_vlans") or {}
    require(vlans, "no VLAN in the minigraph; the l2-topo needs one")
    name = sorted(vlans)[0]
    return int(name.replace("Vlan", ""))


@pytest.fixture(scope="session")
def topo(duthosts, tbinfo, l2_vlan):
    # Every bridge has to be in duthosts: the legs are built from all of them.
    require(len(duthosts) >= 3,
            "the l2-topo needs three bridges; this run has {} ({} on the testbed); "
            "pass all of them with -d".format(len(duthosts), len(tbinfo["duts"])))
    # A second VLAN on the legs only, so MST has something to map to a second
    # instance and PVST has a second tree. Without it the multi-instance and
    # per-VLAN cases can only skip.
    vlans = [l2_vlan, SECOND_VLAN]
    t = Topology.from_duthosts(
        duthosts, tbinfo, vlans=vlans,
        runners={h.hostname: _runner(h) for h in duthosts})
    logger.info("l2-topo on %s, VLANs %s", tbinfo["conf-name"], vlans)
    for leg in t.legs:
        logger.info("  %s", leg)
    # The minigraph leaves ports without a neighbour shut, and the legs have none.
    _legs_up(t)
    yield t
    for node in t.all_nodes():
        for port in node.ports.values():
            node.exec("config vlan member del {} {}".format(SECOND_VLAN, port))
        node.exec("config vlan del {}".format(SECOND_VLAN))


def _leg_ends(topo):
    return [(leg.a, leg.a_eth) for leg in topo.legs] + [(leg.b, leg.b_eth) for leg in topo.legs]


def _legs_up(topo):
    ends = _leg_ends(topo)
    for node, port in ends:
        node.link_set(port, True)
    if not wait_until(60, 2, lambda: all(n.link_is_up(p) for n, p in ends), "legs up"):
        pytest.fail("legs did not come up: {}".format(", ".join(
            "{}:{}".format(n.name, p) for n, p in ends if not n.link_is_up(p))),
            pytrace=False)


def _legs_down(topo):
    for node, port in _leg_ends(topo):
        node.link_set(port, False)


@pytest.fixture(scope="session")
def containers_up(topo):
    """Every bridge answers. Stops short of CONFIG_DB so the topology gates can
        run against an image that is not a working SONiC yet.
    """
    down = [n.name for n in topo.all_nodes() if not n.is_running()]
    if down:
        pytest.fail("bridges not reachable: {}".format(", ".join(down)), pytrace=False)
    return topo


@pytest.fixture(scope="session")
def nodes_up(containers_up):
    """Every bridge is up and its CONFIG_DB answers."""
    for node in containers_up.all_nodes():
        if not wait_until(120, 3, node.config_db_ready, "{} CONFIG_DB".format(node.name)):
            pytest.fail("{} is reachable but its CONFIG_DB never answered".format(
                node.name), pytrace=False)
    return containers_up


@pytest.fixture(scope="session")
def stp_image(nodes_up):
    """The image has to contain the spanning tree daemons. They are excluded from
        the virtual build by default, and an absent stpd looks like a crashed one.
        A skip here is a packaging answer, not a protocol one.
    """
    missing = [n.name for n in nodes_up.all_nodes() if not n.stp_available()]
    if missing:
        pytest.skip(
            "no spanning tree daemons on {}; the image was built without "
            "INCLUDE_STP=y.".format(", ".join(missing)))
    for node in nodes_up.all_nodes():
        if not node.enable_stp_feature():
            pytest.fail("{}: stpd and stpmgrd did not start".format(node.name),
                        pytrace=False)
    return nodes_up


def make_t1_root(topo, mode, scopes):
    for scope in scopes:
        topo.t1.set_bridge_priority(mode, scope, T1_PRIORITY)


def _bring_up(topo, mode, request):
    # The framework config-reloads between modules, which puts the feature
    # back to the image default, so the daemons have to be checked here and
    # not only once per session.
    for node in topo.all_nodes():
        assert node.enable_stp_feature(), "{}: stpd and stpmgrd did not start".format(node.name)
    # The region goes in with the mode so a re-apply carries it too. A bridge
    # without its region is in a region of its own, and every leg reads as a
    # boundary.
    region = MST_REGION if mode == MST else None
    revision = MST_REVISION if mode == MST else None
    assert topo.set_mode(mode, region=region, revision=revision), (
        "no bridge published a {} tree after two attempts at applying the "
        "configuration".format(mode))
    make_t1_root(topo, mode, [0] if mode == MST else list(topo.vlans))
    # The legs come up only once every bridge runs spanning tree, so the
    # triangle is never a loop with nothing to break it.
    _legs_up(topo)
    yield topo
    if not request.config.getoption("--keep-mode"):
        # Three bridges with spanning tree off and every leg up are a loop, and
        # a broadcast circulates through them and out of every other port they
        # have until something breaks it. Take the legs down first.
        _legs_down(topo)
        for node in topo.all_nodes():
            node.disable_stp()


@pytest.fixture(scope="class")
def pvst(stp_image, request):
    for t in _bring_up(stp_image, PVST, request):
        yield t


@pytest.fixture(scope="class")
def mstp(stp_image, request):
    for t in _bring_up(stp_image, MST, request):
        yield t


@pytest.fixture
def restore_legs(topo):
    """Put every leg back up after a test that failed one."""
    yield
    for leg in topo.legs:
        leg.set_up(True)


@pytest.fixture(scope="session")
def convergence_log():
    """Convergence numbers are recorded rather than asserted against a threshold."""
    records = []
    yield records
    for r in records:
        logger.info("convergence: %s", r)
