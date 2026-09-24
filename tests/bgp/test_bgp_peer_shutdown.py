"""Check if BGP session is shutdown correctly."""

import logging
import os
import time

import pytest
from scapy.all import sniff, IP, IPv6
from scapy.contrib import bgp
from scapy.layers.l2 import CookedLinux

from tests.bgp.bgp_helpers import capture_bgp_packages_to_file, fetch_and_delete_pcap_file
from tests.common.helpers.bgp import BGPNeighbor
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until
from tests.common.utilities import is_ipv6_only_topology

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'lrh', 'urh', 'm1', 'lt2', 'ft2', 'c0', 'lma', 'uma'),
]

TEST_ITERATIONS = 5
BGP_DOWN_LOG_TMPL = "/tmp/bgp_down.pcap"
WAIT_TIMEOUT = 120
NEIGHBOR_ASN0 = 61000
NEIGHBOR_PORT0 = 11000
# How long after the teardown the peer's notification may arrive. The capture
# is started before the teardown, so the pcap also holds notifications from
# earlier resets of the same session; bounding the validated set to this window
# is what keeps those out of it.
NOTIFICATION_WINDOW = 30


@pytest.fixture
def common_setup_teardown(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    is_dualtor,
    is_quagga,
    ptfhost,
    setup_interfaces,
    tbinfo,
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    conn0 = setup_interfaces[0]
    conn0_ns = (
        DEFAULT_NAMESPACE
        if "namespace" not in list(conn0.keys())
        else conn0["namespace"]
    )

    dut_asn = mg_facts["minigraph_bgp_asn"]
    is_v6_topo = is_ipv6_only_topology(tbinfo)

    confed_asn = duthost.get_bgp_confed_asn()
    use_vtysh = False

    dut_type = ""
    for k, v in list(mg_facts["minigraph_devices"].items()):
        if k == duthost.hostname:
            dut_type = v["type"]

    if dut_type in ["ToRRouter", "SpineRouter", "BackEndToRRouter", "LowerSpineRouter"]:
        neigh_type = "LeafRouter"
    elif dut_type == "UpperSpineRouter" and confed_asn is not None:
        # On confederation-based UT2 topologies the UpperSpineRouter peers with
        # AZNGHub neighbors using the confederation ASN, not the per-DUT ASN.
        neigh_type = "AZNGHub"
        dut_asn = int(confed_asn)
    elif dut_type in ["UpperSpineRouter", "FabricSpineRouter"]:
        neigh_type = "LowerSpineRouter"
        if dut_type == "FabricSpineRouter" and confed_asn is not None:
            # For FT2, we need to use vtysh to configure BGP neigh if BGP confed is enabled
            use_vtysh = True
    elif dut_type in ["LowerRegionalHub"]:
        neigh_type = "SpineRouter"  # or "UpperSpineRouter"
        if confed_asn is not None:
            use_vtysh = True
    elif dut_type in ["UpperRegionalHub"]:
        neigh_type = "LowerRegionalHub"
        if confed_asn is not None:
            use_vtysh = True
    elif dut_type in ["LowerMgmtAggregator"]:
        neigh_type = "MgmtSpineRouter"
        if confed_asn is not None:
            use_vtysh = True
    elif dut_type in ["UpperMgmtAggregator"]:
        neigh_type = "LowerMgmtAggregator"
        if confed_asn is not None:
            use_vtysh = True
    else:
        neigh_type = "ToRRouter"
    logging.info(
        "pseudoswitch0 neigh_addr {} ns {} dut_asn {} local_addr {} neigh_type {}".format(
            conn0["neighbor_addr"].split("/")[0],
            conn0_ns,
            dut_asn,
            conn0["local_addr"].split("/")[0],
            neigh_type,
        )
    )

    bgp_neighbor = (
        BGPNeighbor(
            duthost,
            ptfhost,
            "pseudoswitch0",
            conn0["neighbor_addr"].split("/")[0],
            NEIGHBOR_ASN0,
            conn0["local_addr"].split("/")[0],
            dut_asn,
            NEIGHBOR_PORT0,
            neigh_type,
            conn0_ns,
            is_multihop=is_quagga or is_dualtor,
            is_passive=False,
            is_ipv6_only=is_v6_topo,
            confed_asn=confed_asn,
            use_vtysh=use_vtysh
        )
    )

    yield bgp_neighbor, use_vtysh


@pytest.fixture
def constants(is_quagga, setup_interfaces, pytestconfig):
    class _C(object):
        """Dummy class to save test constants."""
        def __init__(self):
            self.sleep_interval = None
            self.log_dir = None

        pass

    _constants = _C()
    if is_quagga:
        _constants.sleep_interval = 40
    else:
        _constants.sleep_interval = 5

    log_file = pytestconfig.getoption("log_file", None)
    if log_file:
        _constants.log_dir = os.path.dirname(os.path.abspath(log_file))
    else:
        _constants.log_dir = None

    return _constants


def _get_bgp_neighbors(duthost, neighbor):
    """Return bgp_neighbors dict for the ASIC where the pseudo-neighbor session lives."""
    asichost = duthost.asic_instance_from_namespace(neighbor.namespace)
    return asichost.bgp_facts()['ansible_facts']['bgp_neighbors']


def is_neighbor_session_established(duthost, neighbor):
    bgp_neighbors = _get_bgp_neighbors(duthost, neighbor)
    return (neighbor.ip in bgp_neighbors
            and bgp_neighbors[neighbor.ip]["state"] == "established")


def bgp_notification_packets(pcap_file, is_v6_topo, src_ip=None, dst_ip=None,
                             start_time=None, end_time=None):
    """Get the incoming bgp notification packets belonging to the teardown under test.

    When tcpdump captures on the 'any' interface with LINUX_SLL link type,
    each packet has a CookedLinux header with a pkttype field indicating
    direction. Filter out outgoing packets (pkttype == 4, 'sent-by-us')
    so only incoming notifications are validated.

    The capture is started before the teardown is triggered, so the pcap can also
    hold notifications from earlier resets of the same session and notifications
    exchanged with the other bgp neighbors of the dut. ``src_ip``/``dst_ip`` and
    ``start_time``/``end_time`` narrow the result to the notifications produced by
    the operation under test. They default to None, which keeps the previous
    unfiltered behaviour.
    """
    ip_ver = IPv6 if is_v6_topo else IP

    def _notification_under_test(p):
        if not (ip_ver in p and bgp.BGPHeader in p and p[bgp.BGPHeader].type == 3):
            return False
        if CookedLinux in p and p[CookedLinux].pkttype == 4:
            return False
        if src_ip is not None and p[ip_ver].src != src_ip:
            return False
        if dst_ip is not None and p[ip_ver].dst != dst_ip:
            return False
        if start_time is not None and float(p.time) < start_time:
            return False
        if end_time is not None and float(p.time) > end_time:
            return False
        return True

    packets = sniff(offline=pcap_file, lfilter=_notification_under_test)
    return packets


def match_bgp_notification(packet, action):
    """Check if the bgp notification packet matches.

    Only the notification content is checked here; which packets are relevant is
    decided by bgp_notification_packets().
    """
    bgp_fields = packet[bgp.BGPNotification].fields
    if action == "cease":
        # error_code 6: Cease, error_subcode 3: Peer De-configured. References: RFC 4271
        return (bgp_fields["error_code"] == 6 and
                bgp_fields["error_subcode"] == 3)
    else:
        return False


def is_neighbor_session_down(duthost, neighbor):
    bgp_neighbors = _get_bgp_neighbors(duthost, neighbor)
    return (neighbor.ip in bgp_neighbors
            and bgp_neighbors[neighbor.ip]["admin"] == "down"
            and bgp_neighbors[neighbor.ip]["state"] == "idle")


def _flush_route(duthost, neighbor, prefix):
    asichost = duthost.asic_instance_from_namespace(neighbor.namespace)
    asichost.shell("{} route flush {}".format(asichost.ip_cmd, prefix), module_ignore_errors=True)


def is_neighbor_removed(duthost, neighbor):
    """Return True once the peer no longer shows up in bgp_facts (FRR has finished clearing it)."""
    bgp_neighbors = _get_bgp_neighbors(duthost, neighbor)
    return neighbor.ip not in bgp_neighbors


def _dump_establish_failure_diagnostics(duthost, neighbor):
    """Best-effort diagnostic dump for a failed-to-establish session, so the
    evidence lands directly in the pytest log even if the elastictest run's
    other artifacts (syslog, pcaps) aren't retrievable afterward.
    """
    try:
        asichost = duthost.asic_instance_from_namespace(neighbor.namespace)
        vtysh_cmd = duthost.get_vtysh_cmd_for_namespace(
            "vtysh -c 'show bgp neighbor {}'".format(neighbor.ip),
            neighbor.namespace
        )
        bgp_nbr_state = duthost.shell(
            vtysh_cmd, module_ignore_errors=True)['stdout']
        logging.warning(
            "bgp neighbor state on failure:\n%s", bgp_nbr_state)

        sock_state = asichost.shell(
            "ss -tn '( dst {}:179 )'".format(neighbor.ip),
            module_ignore_errors=True)['stdout']
        logging.warning("socket state on failure:\n%s", sock_state)

        exabgp_status = neighbor.ptfhost.shell(
            "supervisorctl status exabgp-{}".format(neighbor.name),
            module_ignore_errors=True)['stdout']
        logging.warning("exabgp status on failure:\n%s", exabgp_status)
    except Exception as e:
        logging.warning(
            "Failed to collect establish-failure diagnostics: %s", repr(e))


def test_bgp_peer_shutdown(
    common_setup_teardown,
    constants,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    request,
    tbinfo
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    n0, _ = common_setup_teardown
    is_v6_topo = is_ipv6_only_topology(tbinfo)
    announced_route = {"prefix": "fc00:10::/64", "nexthop": n0.ip} if is_v6_topo else \
                      {"prefix": "10.10.100.0/27", "nexthop": n0.ip}

    for _ in range(TEST_ITERATIONS):
        try:
            n0.start_session()
            # ensure new session is ready
            if not wait_until(
                WAIT_TIMEOUT,
                5,
                20,
                lambda: is_neighbor_session_established(duthost, n0),
            ):
                _dump_establish_failure_diagnostics(duthost, n0)
                pytest.fail("Could not establish bgp sessions")

            n0.announce_route(announced_route)
            time.sleep(constants.sleep_interval)
            announced_route_on_dut_before_shutdown = duthost.get_route(announced_route["prefix"], n0.namespace)
            if not announced_route_on_dut_before_shutdown:
                pytest.fail("announce route %s from n0 to dut failed" % announced_route["prefix"])

            # tear down BGP session on n0
            bgp_pcap = BGP_DOWN_LOG_TMPL
            with capture_bgp_packages_to_file(duthost, "any", bgp_pcap, n0.namespace):
                # Taken inside the capture context: the context sleeps for
                # TCPDUMP_WAIT_TIMEOUT before yielding, so an epoch read before it
                # would sit well before the teardown and would not bound the pcap.
                teardown_epoch = float(duthost.shell("date +%s.%6N")['stdout'])
                n0.teardown_session()
                if not wait_until(
                    WAIT_TIMEOUT,
                    5,
                    20,
                    lambda: is_neighbor_session_down(duthost, n0),
                ):
                    pytest.fail("Could not tear down bgp session")

            local_pcap_filename = fetch_and_delete_pcap_file(bgp_pcap, constants.log_dir, duthost, request)
            bpg_notifications = bgp_notification_packets(
                local_pcap_filename,
                is_v6_topo,
                src_ip=n0.ip,
                dst_ip=n0.peer_ip,
                start_time=teardown_epoch,
                end_time=teardown_epoch + NOTIFICATION_WINDOW,
            )

            matched_notifications = []
            for bgp_packet in bpg_notifications:
                logging.debug(
                    "bgp notification packet, capture time %s, packet details:\n%s",
                    bgp_packet.time,
                    bgp_packet.show(dump=True),
                )

                if match_bgp_notification(bgp_packet, "cease"):
                    matched_notifications.append(bgp_packet)
                else:
                    # The peer may reset the session for its own reasons inside the
                    # window; that is not the transition under test.
                    logging.warning(
                        "ignoring notification from %s at %s that is not cease/peer de-configured",
                        n0.ip,
                        bgp_packet.time,
                    )

            if not matched_notifications:
                pytest.fail(
                    "No cease/peer de-configured notification from %s in the %ds after the "
                    "teardown at epoch %.6f; %d notification(s) from the test peer were in "
                    "the window" % (n0.ip, NOTIFICATION_WINDOW, teardown_epoch, len(bpg_notifications))
                )

            announced_route_on_dut_after_shutdown = duthost.get_route(announced_route["prefix"], n0.namespace)
            if announced_route_on_dut_after_shutdown:
                pytest.fail("route %s still exists in DUT after BGP shutdown" % announced_route["prefix"])
        finally:
            n0.stop_session()
            _flush_route(duthost, n0, announced_route["prefix"])
            # Ensure FRR has fully cleared the old peer before the next
            # iteration recreates it, to avoid a recreate-during-clearing
            # race that can delay re-establishment past WAIT_TIMEOUT.
            if not wait_until(30, 2, 0, is_neighbor_removed, duthost, n0):
                pytest.fail(
                    "BGP neighbor %s was not fully removed after "
                    "stop_session" % n0.ip)
