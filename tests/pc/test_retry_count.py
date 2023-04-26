import pytest

import time
import logging
import ipaddress
import sys
from collections import Counter

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.ptf_runner import ptf_runner
from tests.common.config_reload import config_reload
from scapy.all import *
import scapy.contrib.lacp

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1")
]

class LACPRetryCount(Packet):
    name = "LACPRetryCount"
    fields_desc = [
        ByteField("version", 0xf1),
        ByteField("actor_type", 1),
        ByteField("actor_length", 20),
        ShortField("actor_system_priority", 0),
        MACField("actor_system", None),
        ShortField("actor_key", 0),
        ShortField("actor_port_priority", 0),
        ShortField("actor_port_number", 0),
        ByteField("actor_state", 0),
        XStrFixedLenField("actor_reserved", "", 3),
        ByteField("partner_type", 2),
        ByteField("partner_length", 20),
        ShortField("partner_system_priority", 0),
        MACField("partner_system", None),
        ShortField("partner_key", 0),
        ShortField("partner_port_priority", 0),
        ShortField("partner_port_number", 0),
        ByteField("partner_state", 0),
        XStrFixedLenField("partner_reserved", "", 3),
        ByteField("collector_type", 3),
        ByteField("collector_length", 16),
        ShortField("collector_max_delay", 0),
        XStrFixedLenField("collector_reserved", "", 12),
        ConditionalField(ByteField("actor_retry_count_type", 0x80), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("actor_retry_count_length", 4), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("actor_retry_count", 0), lambda pkt:pkt.version == 0xf1),
        ConditionalField(XStrFixedLenField("actor_retry_count_reserved", "", 1), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("partner_retry_count_type", 0x81), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("partner_retry_count_length", 4), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("partner_retry_count", 0), lambda pkt:pkt.version == 0xf1),
        ConditionalField(XStrFixedLenField("partner_retry_count_reserved", "", 1), lambda pkt:pkt.version == 0xf1),
        ByteField("terminator_type", 0),
        ByteField("terminator_length", 0),
        ConditionalField(XStrFixedLenField("reserved", "", 42), lambda pkt:pkt.version == 0xf1),
        ConditionalField(XStrFixedLenField("reserved", "", 50), lambda pkt:pkt.version != 0xf1),
    ]

split_layers(scapy.contrib.lacp.SlowProtocol, scapy.contrib.lacp.LACP, subtype=1)
bind_layers(scapy.contrib.lacp.SlowProtocol, LACPRetryCount, subtype=1)

@pytest.fixture(scope="module")
def configure_higher_retry_count_on_neighbors(request, nbrhosts):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Only supported with sonic neighbor")

    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("sudo config portchannel retry-count set PortChannel1 5")

    # Wait for retry count info to be updated
    time.sleep(5)

    yield

    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("sudo config portchannel retry-count set PortChannel1 3")

    # Wait for retry count info to be updated
    time.sleep(60)

@pytest.fixture(scope="module")
def configure_higher_retry_count(request, duthost):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Only supported with sonic neighbor")

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    for port_channel in list(cfg_facts["PORTCHANNEL"].keys()):
        duthost.shell("sudo config portchannel retry-count set {} 5".format(port_channel))

    # Wait for retry count info to be updated
    time.sleep(5)

    yield

    for port_channel in list(cfg_facts["PORTCHANNEL"].keys()):
        duthost.shell("sudo config portchannel retry-count set {} 3".format(port_channel))

    # Wait for retry count info to be updated
    time.sleep(60)

def test_peer_lag_member_retry_count(duthost, nbrhosts, configure_higher_retry_count_on_neighbors):
    """
    Test that DUT sees new retry count when peers update retry count.
    """
    for nbr in list(nbrhosts.keys()):
        port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
        pytest_assert(port_channel_status["runner"]["retry_count"] == 5, "retry count on neighbor is incorrect")

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    for port_channel in port_channels:
        port_channel_status = duthost.get_port_channel_status(port_channel)
        number_of_lag_member = len(cfg_facts["PORTCHANNEL_MEMBER"][port_channel])
        pytest_assert("ports" in port_channel_status and number_of_lag_member == len(port_channel_status["ports"]),
                      "get port status error")
        for _, status in list(port_channel_status["ports"].items()):
            pytest_assert(status["runner"]["selected"], "status of lag member error")
            pytest_assert(status["runner"]["partner_retry_count"] == 5, "partner retry count is incorrect")

def test_retry_count(duthost, nbrhosts, configure_higher_retry_count):
    """
    Test that peers see new retry count when DUT updates retry count.
    """
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    for port_channel in port_channels:
        port_channel_status = duthost.get_port_channel_status(port_channel)
        pytest_assert(port_channel_status["runner"]["retry_count"] == 5, "retry count on DUT is incorrect")

    for nbr in list(nbrhosts.keys()):
        port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
        for _, status in list(port_channel_status["ports"].items()):
            pytest_assert(status["runner"]["selected"], "status of lag member error")
            pytest_assert(status["runner"]["partner_retry_count"] == 5, "partner retry count is incorrect")

def log_lacpdu_packets(duthost, iface, save_path):
    """Capture LACPDU packets to file."""
    start_pcap = "tcpdump -i %s -w %s ether proto 0x8809" % (iface, save_path)
    stop_pcap = "sudo pkill -f '{}'".format(start_pcap)
    start_pcap = "sudo nohup {} &".format(start_pcap)
    duthost.shell(start_pcap)

    time.sleep(30)

    duthost.shell(stop_pcap, module_ignore_errors=True)

def test_peer_lag_member_retry_count_packet_version(duthost, nbrhosts, configure_higher_retry_count_on_neighbors):
    """
    Test that peers and DUT use new LACPDU version when peers use a non-standard retry count
    """

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    for port_channel in port_channels:
        port_channel_status = duthost.get_port_channel_status(port_channel)
        for port, status in list(port_channel_status["ports"].items()):
            log_lacpdu_packets(duthost, port, "lacpdu.pcap")
            lacpduPackets = None
            with tempfile.NamedTemporaryFile() as tmp_pcap:
                duthost.fetch(src="lacpdu.pcap", dest=tmp_pcap.name, flat=True)
                duthost.file(path="lacpdu.pcap", state="absent")
                lacpduPackets = rdpcap(tmp_pcap.name)
            sendVersionVerified = False
            receiveVersionVerified = False
            for pkt in lacpduPackets:
                if pkt["LACPRetryCount"].version == 0xf1:
                    if pkt["LACPRetryCount"].actor_system == status["runner"]["actor_lacpdu_info"]["system"]:
                        sendVersionVerified = True
                    elif pkt["LACPRetryCount"].actor_system == status["runner"]["partner_lacpdu_info"]["system"]:
                        receiveVersionVerified = True
            pytest_assert(sendVersionVerified, "unable to verify that LACPDU packets sent were the right version")
            pytest_assert(receiveVersionVerified, "unable to verify that LACPDU packets received were the right version")

def test_retry_count_packet_version(duthost, nbrhosts, configure_higher_retry_count):
    """
    Test that peers and DUT use new LACPDU version when DUT uses a non-standard retry count
    """
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    for port_channel in port_channels:
        port_channel_status = duthost.get_port_channel_status(port_channel)
        for port, status in list(port_channel_status["ports"].items()):
            log_lacpdu_packets(duthost, port, "lacpdu.pcap")
            lacpduPackets = None
            with tempfile.NamedTemporaryFile() as tmp_pcap:
                duthost.fetch(src="lacpdu.pcap", dest=tmp_pcap.name, flat=True)
                duthost.file(path="lacpdu.pcap", state="absent")
                lacpduPackets = rdpcap(tmp_pcap.name)
            sendVersionVerified = False
            receiveVersionVerified = False
            for pkt in lacpduPackets:
                if pkt["LACPRetryCount"].version == 0xf1:
                    if pkt["LACPRetryCount"].actor_system == status["runner"]["actor_lacpdu_info"]["system"]:
                        sendVersionVerified = True
                    elif pkt["LACPRetryCount"].actor_system == status["runner"]["partner_lacpdu_info"]["system"]:
                        receiveVersionVerified = True
            pytest_assert(sendVersionVerified, "unable to verify that LACPDU packets sent were the right version")
            pytest_assert(receiveVersionVerified, "unable to verify that LACPDU packets received were the right version")
