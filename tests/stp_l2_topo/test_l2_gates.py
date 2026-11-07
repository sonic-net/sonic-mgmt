# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
The topology gates. Nothing in the protocol suites means anything until these
pass: BPDUs confirmed on all three legs, an image that contains the spanning
tree daemon, and legs that carry the IEEE reserved group address.

"""
import logging
import re

import pytest

from .l2topo import IEEE_BPDU_MAC, PVST_BPDU_MAC, wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]


def _frame(dst_mac, src_mac="02:00:00:00:99:01"):
    """A config BPDU addressed to `dst_mac`, padded to the 60 byte minimum. The
        payload is a real BPDU so the frame takes the path a BPDU takes, including
        the LLC length check.
    """
    bid = "8000" + src_mac.replace(":", "")
    bpdu = ("0000" "00" "00" "00" + bid + "00000000" + bid + "8001"
            "0000" "1400" "0200" "0f00")
    llc = "424203"
    body = llc + bpdu
    frame = (dst_mac.replace(":", "") + src_mac.replace(":", "")
             + "{:04x}".format(len(body) // 2) + body)
    return frame + "00" * max(0, 60 - len(frame) // 2)


class TestTopologyGates(object):
    """These need the topology, not spanning tree, so they run on any image."""

    def test_all_bridges_are_running(self, containers_up):
        for node in containers_up.all_nodes():
            assert node.is_running(), "{} is not running".format(node.name)

    def test_every_leg_is_wired_end_to_end(self, containers_up):
        """Both ends of every leg exist and carry the port names the manifest claims."""
        for leg in containers_up.legs:
            for node, eth, port in leg.ends():
                assert eth in node.ports, "{} has no {} ({})".format(node.name, eth, leg.role)
                assert node.ports[eth] == port, (
                    "{}:{} maps to {} but the manifest says {}".format(
                        node.name, eth, node.ports[eth], port))
                assert node.link_is_up(eth), "{}:{} is down on leg {}".format(
                    node.name, eth, leg.role)

    @pytest.mark.parametrize("dst,label", [(IEEE_BPDU_MAC, "IEEE"), (PVST_BPDU_MAC, "PVST")])
    def test_legs_carry_the_reserved_group_address(self, containers_up, dst, label):
        """Both BPDU addresses cross every leg untouched. A bridged leg would pass
                this only while its own STP was off, so this asserts the property rather
                than the wiring.
        """
        import time
        for leg in containers_up.legs:
            (a, a_eth, a_port), (b, b_eth, b_port) = leg.ends()
            cap = "/tmp/l2gate.{}.{}".format(leg.role, dst.replace(":", ""))

            # Start the capture on the far end, backgrounded and bounded by
            # `timeout` there, so frames can be sent while it listens.
            b.exec("nohup sudo timeout 20 tcpdump -i {} -nn -e -l -c 1 "
                   "'ether dst {}' > {} 2>/dev/null & disown".format(b_eth, dst, cap))
            time.sleep(3)   # let tcpdump attach before anything is sent
            for _ in range(5):
                a.inject(a_eth, _frame(dst))
                time.sleep(0.4)
            time.sleep(2)
            out = b.exec("cat {} 2>/dev/null; rm -f {}".format(cap, cap))
            arrived = dst in out.lower()
            logger.info("leg %-10s %s %s:%s -> %s:%s  %s",
                        leg.role, label, a.name, a_eth, b.name, b_eth,
                        "arrived" if arrived else "NOT SEEN")

            assert arrived, (
                "a {} frame sent on {}:{} never reached {}:{} across leg {}. "
                "The leg is not transparent to that address.".format(
                    label, a.name, a_eth, b.name, b_eth, leg.role))


class TestImageGates(object):
    """These need the image to be able to run spanning tree."""

    def test_config_db_answers_on_every_bridge(self, nodes_up):
        for node in nodes_up.all_nodes():
            assert node.config_db_ready(), \
                "{} CONFIG_DB is not answering".format(node.name)

    def test_image_carries_the_stp_daemons(self, nodes_up):
        """The daemons are excluded from the virtual build by default. On a
                single-container image they are binaries rather than an `stp` docker.
        """
        missing = [n.name for n in nodes_up.all_nodes() if not n.stp_available()]
        assert not missing, (
            "the image does not carry the spanning tree daemons (missing on {}). "
            "Build it with INCLUDE_STP=y.".format(", ".join(missing)))

    def test_stp_daemons_start(self, stp_image):
        for node in stp_image.all_nodes():
            assert node.stp_daemons_running(), (
                "{}: stpd or stpmgrd is not RUNNING under supervisord".format(node.name))

    def test_bpdus_are_seen_on_every_leg(self, pvst):
        """Every leg carries real BPDUs from an independent protocol instance, so a
                silent leg means the topology is wrong, not the protocol.
        """
        stp_image = pvst
        silent = []
        for leg in stp_image.legs:
            (a, a_eth, _), _ = leg.ends()
            seen = wait_until(60, 5,
                              lambda n=a, e=a_eth: (lambda c: c if c["ieee"] or c["pvst"] else None)(
                                  n.capture_bpdus(e, seconds=6)),
                              "BPDUs on {}".format(leg.role))
            if not seen:
                silent.append(leg.role)
            else:
                logger.info("leg %-10s ieee=%d pvst=%d", leg.role, seen["ieee"], seen["pvst"])
        assert not silent, "no BPDUs on leg(s): {}".format(", ".join(silent))

    def test_only_the_three_bridges_speak_on_any_leg(self, pvst):
        """Three bridges, and no fourth. Anything in the path running its own
                spanning tree joins the election and looks like a protocol bug.
        """
        stp_image = pvst
        # bridge_mac(), not the manifest field: a hardware node leaves the
        # manifest blank, and an empty string here makes the switch under test
        # its own stranger.
        known = {n.bridge_mac() for n in stp_image.all_nodes()}
        assert all(known), "a bridge did not report its MAC: {}".format(sorted(known))
        strangers = {}
        for leg in stp_image.legs:
            (a, a_eth, _), _ = leg.ends()
            cap = a.capture_bpdus(a_eth, seconds=10)
            for line in cap["lines"]:
                m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5}) > ", line.lower())
                if not m:
                    continue
                src_mac = m.group(1)
                # Per port MACs derive from the bridge MAC, so compare on the
                # vendor and node bytes rather than the last.
                if not any(src_mac[:14] == k[:14] for k in known):
                    strangers.setdefault(leg.role, set()).add(src_mac)
        assert not strangers, (
            "BPDUs from a bridge that is not one of the three appeared on {}. "
            "Known bridge MACs are {}. Something in the path is running its own "
            "spanning tree.".format(
                {k: sorted(v) for k, v in strangers.items()}, sorted(known)))
