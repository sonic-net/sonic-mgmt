"""Check if BGP session is shutdown correctly."""

import logging
import os
import time

import pytest
from scapy.all import sniff, IP
from scapy.contrib import bgp

from tests.bgp.bgp_helpers import capture_bgp_packages_to_file, fetch_and_delete_pcap_file
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.bgp import BGPNeighbor
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until, delete_running_config

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
]

TEST_ITERATIONS = 5
BGP_DOWN_LOG_TMPL = "/tmp/bgp_down.pcap"
WAIT_TIMEOUT = 120
NEIGHBOR_ASN0 = 61000
NEIGHBOR_PORT0 = 11000


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

    dut_type = ""
    for k, v in list(mg_facts["minigraph_devices"].items()):
        if k == duthost.hostname:
            dut_type = v["type"]

    if dut_type in ["ToRRouter", "SpineRouter", "BackEndToRRouter"]:
        neigh_type = "LeafRouter"
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
        )
    )

    yield bgp_neighbor

    # Cleanup suppress-fib-pending config
    delete_tacacs_json = [
        {"DEVICE_METADATA": {"localhost": {"suppress-fib-pending": "disabled"}}}
    ]
    delete_running_config(delete_tacacs_json, duthost)


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


def is_neighbor_session_established(duthost, neighbor):
    # handle both multi-asic and single-asic
    bgp_facts = duthost.bgp_facts(num_npus=duthost.sonichost.num_asics())["ansible_facts"]
    return (neighbor.ip in bgp_facts["bgp_neighbors"]
            and bgp_facts["bgp_neighbors"][neighbor.ip]["state"] == "established")


def bgp_notification_packets(pcap_file):
    """Get bgp notification packets from pcap file."""
    packets = sniff(
        offline=pcap_file,
        lfilter=lambda p: IP in p and bgp.BGPHeader in p and p[bgp.BGPHeader].type == 3,
    )
    return packets


def match_bgp_notification(packet, src_ip, dst_ip, action, bgp_session_down_time):
    """Check if the bgp notification packet matches."""
    if not (packet[IP].src == src_ip and packet[IP].dst == dst_ip):
        return False

    bgp_fields = packet[bgp.BGPNotification].fields
    if action == "cease":
        # error_code 6: Cease, error_subcode 3: Peer De-configured. References: RFC 4271
        return (bgp_fields["error_code"] == 6 and
                bgp_fields["error_subcode"] == 3 and
                float(packet.time) < bgp_session_down_time)
    else:
        return False


def is_neighbor_session_down(duthost, neighbor):
    # handle both multi-asic and single-asic
    bgp_neighbors = duthost.bgp_facts(num_npus=duthost.sonichost.num_asics())["ansible_facts"]["bgp_neighbors"]
    return (neighbor.ip in bgp_neighbors and
            bgp_neighbors[neighbor.ip]["admin"] == "down" and
            bgp_neighbors[neighbor.ip]["state"] == "idle")


def get_bgp_down_timestamp(duthost, namespace, peer_ip, timestamp_before_teardown):
    # get the bgp session down timestamp from syslog in the format of seconds (with ms precision) since the Unix Epoch
    cmd = (
        "grep \"[b]gp{}#bgpcfgd: Peer 'default|{}' admin state is set to 'down'\" /var/log/syslog | tail -1"
    ).format(namespace.split("asic")[1] if namespace else "", peer_ip)

    bgp_down_msg_list = duthost.shell(cmd)['stdout'].split()
    if not bgp_down_msg_list:
        pytest.fail("Could not find the BGP session down message in syslog")

    try:
        timestamp = " ".join(bgp_down_msg_list[1:4])
        timestamp_in_sec = float(duthost.shell("date -d \"{}\" +%s.%6N".format(timestamp))['stdout'])
    except RunAnsibleModuleFail:
        timestamp = " ".join(bgp_down_msg_list[0:3])
        timestamp_in_sec = float(duthost.shell("date -d \"{}\" +%s.%6N".format(timestamp))['stdout'])
    except Exception as e:
        logging.error("Error when parsing syslog message timestamp: {}".format(repr(e)))
        pytest.fail("Failed to parse syslog message timestamp")

    if timestamp_in_sec < timestamp_before_teardown:
        pytest.fail("Could not find the BGP session down time")

    return timestamp_in_sec


def test_bgp_peer_shutdown(
    common_setup_teardown,
    constants,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    request,
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    n0 = common_setup_teardown
    announced_route = {"prefix": "10.10.100.0/27", "nexthop": n0.ip}

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
                pytest.fail("Could not establish bgp sessions")

            n0.announce_route(announced_route)
            time.sleep(constants.sleep_interval)
            announced_route_on_dut_before_shutdown = duthost.get_route(announced_route["prefix"], n0.namespace)
            if not announced_route_on_dut_before_shutdown:
                pytest.fail("announce route %s from n0 to dut failed" % announced_route["prefix"])

            timestamp_before_teardown = time.time()
            # tear down BGP session on n0
            bgp_pcap = BGP_DOWN_LOG_TMPL
            with capture_bgp_packages_to_file(duthost, "any", bgp_pcap, n0.namespace):
                n0.teardown_session()
                if not wait_until(
                    WAIT_TIMEOUT,
                    5,
                    20,
                    lambda: is_neighbor_session_down(duthost, n0),
                ):
                    pytest.fail("Could not tear down bgp session")

            local_pcap_filename = fetch_and_delete_pcap_file(bgp_pcap, constants.log_dir, duthost, request)
            bpg_notifications = bgp_notification_packets(local_pcap_filename)
            for bgp_packet in bpg_notifications:
                logging.debug(
                    "bgp notification packet, capture time %s, packet details:\n%s",
                    bgp_packet.time,
                    bgp_packet.show(dump=True),
                )

                bgp_session_down_time = get_bgp_down_timestamp(duthost, n0.namespace, n0.ip, timestamp_before_teardown)
                if not match_bgp_notification(bgp_packet, n0.ip, n0.peer_ip, "cease", bgp_session_down_time):
                    pytest.fail("BGP notification packet does not match expected values")

            announced_route_on_dut_after_shutdown = duthost.get_route(announced_route["prefix"], n0.namespace)
            if announced_route_on_dut_after_shutdown:
                pytest.fail("route %s still exists in DUT after BGP shutdown" % announced_route["prefix"])
        finally:
            n0.stop_session()
            duthost.shell("ip route flush %s" % announced_route["prefix"])
