import contextlib
import ipaddress
import logging
import pytest
import tempfile
import time

from datetime import datetime

from scapy.all import IP
from scapy.all import IPv6
from scapy.all import sniff
from scapy.contrib import bgp

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]
BGP_LOG_TMPL = "/tmp/bgp_neighbor_%s.pcap"


@contextlib.contextmanager
def log_bgp_updates(duthost, iface, save_path):
    """Capture bgp packets to file."""

    def _is_tcpdump_running(duthost, cmd):
        check_cmd = "ps u -C tcpdump | grep '%s'" % cmd
        if cmd in duthost.shell(check_cmd)['stdout']:
            return True
        return False

    if iface == "any":
        # Scapy doesn't support LINUX_SLL2 (Linux cooked v2), and tcpdump on Bullseye
        # defaults to writing in that format when listening on any interface. Therefore,
        # have it use LINUX_SLL (Linux cooked) instead.
        start_pcap = "tcpdump -y LINUX_SLL -i %s -w %s port 179" % (iface, save_path)
    else:
        start_pcap = "tcpdump -i %s -w %s port 179" % (iface, save_path)
    # for multi-asic dut, add 'ip netns exec asicx' to the beggining of tcpdump cmd
    stop_pcap_cmd = "sudo pkill -SIGINT -f '%s'" % start_pcap
    start_pcap_cmd = "nohup {} &".format(start_pcap)
    duthost.file(path=save_path, state="absent")
    duthost.shell(start_pcap_cmd)
    # wait until tcpdump process created
    if not wait_until(20, 5, 2, lambda: _is_tcpdump_running(duthost, start_pcap),):
        pytest.fail("Could not start tcpdump")

    try:
        yield
    finally:
        duthost.shell(stop_pcap_cmd, module_ignore_errors=True)


@pytest.fixture(params=["ipv4", "ipv6"])
def ip_version(request):
    return request.param


@pytest.fixture
def select_bgp_neighbor(ip_version, duthost):
    config_facts = duthost.get_running_config_facts()

    for bgp_neighbor, neighbor_details in list(config_facts["BGP_NEIGHBOR"].items()):
        bgp_neighbor_addr = ipaddress.ip_address(bgp_neighbor)
        is_ipv4_neighbor = isinstance(bgp_neighbor_addr, ipaddress.IPv4Address)
        if ip_version == "ipv4" and is_ipv4_neighbor:
            break
        elif ip_version == "ipv6" and not is_ipv4_neighbor:
            break
    else:
        raise ValueError("Failed to find")

    return bgp_neighbor, neighbor_details


@pytest.fixture(autouse=True)
def restore_bgp_sessions(duthost):
    yield

    duthost.shell("config bgp startup all")


def test_dualtor_bgp_update_delay(duthost, ip_version, select_bgp_neighbor):
    """
    This testcase aims to validate that, for a dualtor T0, after startup BGP sessions,
    it should always sleep for 10 seconds delay before sending out any BGP updates.
    And the BGP updates come from T1s should comes earlier than the BGP update to the T1s,
    so the T0 could always have default route ready before T1 learns any route from T0.
    """

    def verify_bgp_session(duthost, bgp_neighbor, admin, state):
        bgp_facts = duthost.bgp_facts()["ansible_facts"]["bgp_neighbors"]
        return bgp_neighbor in bgp_facts and bgp_facts[bgp_neighbor]["admin"] == admin \
            and bgp_facts[bgp_neighbor]["state"] == state

    def bgp_update_packets(pcap_file):
        """Get bgp update packets from pcap file."""
        packets = sniff(
            offline=pcap_file,
            lfilter=lambda p: ip_packet in p and bgp.BGPHeader in p and p[bgp.BGPHeader].type == 2
        )
        return packets

    bgp_neighbor, bgp_details = select_bgp_neighbor
    local_address = bgp_details["local_addr"]
    ip_packet = IP if ip_version == "ipv4" else IPv6

    logging.info("shutdown BGP %s", bgp_neighbor)
    duthost.shell("config bgp shutdown neighbor %s" % bgp_neighbor)
    pytest_assert(
        wait_until(10, 2, 2, verify_bgp_session, duthost, bgp_neighbor, "down", "idle"),
        "Could not shutdown neighbor %s" % bgp_neighbor
    )

    logging.info("startup BGP %s", bgp_neighbor)
    bgp_pcap = BGP_LOG_TMPL % bgp_neighbor
    with log_bgp_updates(duthost, "any", bgp_pcap):
        startup_ret = duthost.shell("config bgp startup neighbor %s" % bgp_neighbor)
        pytest_assert(
            wait_until(10, 2, 2, verify_bgp_session, duthost, bgp_neighbor, "up", "established"),
            "Could not startup neighbor %s" % bgp_neighbor
        )

        time.sleep(20)

    bgp_startup_time = datetime.strptime(startup_ret['end'], "%Y-%m-%d %H:%M:%S.%f")
    logging.debug("BGP neighbor is started at %s", bgp_startup_time)

    with tempfile.NamedTemporaryFile() as tmp_pcap:
        duthost.fetch(src=bgp_pcap, dest=tmp_pcap.name, flat=True)
        duthost.file(path=bgp_pcap, state="absent")
        bgp_updates = bgp_update_packets(tmp_pcap.name)

    first_update_to_peer = None
    first_update_from_peer = None
    for bgp_update in bgp_updates:
        if bgp_update[ip_packet].src == bgp_neighbor and bgp_update[ip_packet].dst == local_address:
            # update from peer
            if first_update_from_peer is None:
                first_update_from_peer = bgp_update
        elif bgp_update[ip_packet].src == local_address and bgp_update[ip_packet].dst == bgp_neighbor:
            # update to peer
            if first_update_to_peer is None:
                first_update_to_peer = bgp_update

    pytest_assert(
        first_update_from_peer is not None,
        "Could not find any BGP updates from %s" % bgp_neighbor
    )
    pytest_assert(
        first_update_to_peer is not None,
        "Could not find any BGP updates to %s" % bgp_neighbor
    )

    first_update_to_peer_time = datetime.fromtimestamp(float(first_update_to_peer.time))
    first_update_from_peer_time = datetime.fromtimestamp(float(first_update_from_peer.time))
    logging.debug("The BGP update to peer is sent at %s", first_update_to_peer_time)
    logging.debug("The BGP update from peer is received at %s", first_update_from_peer_time)
    pytest_assert(
        (first_update_to_peer_time - bgp_startup_time).total_seconds() >= 10,
        "There should be at least 10 seconds of delay between startup BGP session and the first out BGP update"
    )
    pytest_assert(
        first_update_to_peer_time > first_update_from_peer_time,
        "Dualtor T0 should receive BGP update from peer first"
    )
